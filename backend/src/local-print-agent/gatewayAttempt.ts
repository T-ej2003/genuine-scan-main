import { createHash, randomUUID } from "crypto";
import { promises as fs } from "fs";
import path from "path";
import { dispatchJournalRoot } from "./dispatchJournal";

type Claim = { printJobId: string; printItemId: string; testJobId?: string };
type Context = { gatewayId: string; backendUrl: string; connectionType: "NETWORK_DIRECT" | "NETWORK_IPP" };
type Failure = Claim & Context & { state: "PRE_DISPATCH_FAILURE"; reason: string };
const key = (item: string) => createHash("sha256").update(item).digest("hex");
const itemKey = (claim: Claim) => claim.testJobId ? `diagnostic:${claim.testJobId}` : claim.printItemId;
const uncertain = () => Object.assign(new Error("Gateway dispatch evidence requires reconciliation; automatic replay refused."), { errorCode: "dispatch_reconciliation_required" });
const reservationAbsent = async (claim: Claim) => {
  try { await fs.lstat(path.join(dispatchJournalRoot(), `${key(itemKey(claim))}.json`)); return false; }
  catch (error: any) { if (error.code === "ENOENT") return true; throw uncertain(); }
};

// The preparation guard is distinct from a physical-dispatch reservation. Its
// exclusive creation serializes validation/failure reporting across processes.
// Abandoned or malformed guards never authorize dispatch or imply an idle job.
export const executeGatewayAttempt = async (context: Context, claim: Claim,
  execute: (reserve: (action: () => Promise<void>) => Promise<void>) => Promise<void>,
  report: (failure: Failure) => Promise<void>) => {
  if (!itemKey(claim) || (!claim.testJobId && !claim.printJobId)) throw uncertain();
  const root = dispatchJournalRoot();
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  const file = path.join(root, `${key(itemKey(claim))}.gateway-attempt.json`);
  let handle;
  try { handle = await fs.open(file, "wx", 0o600); } catch { throw uncertain(); }
  let reservationStarted = false;
  let reserved = false;
  const write = async (record: object) => {
    await handle.truncate(0);
    await handle.write(JSON.stringify(record), 0, "utf8");
    await handle.sync();
  };
  try {
    await write({ ...context, ...claim, state: "PREPARING" });
    if (!await reservationAbsent(claim)) throw uncertain();
    try {
      await execute(async action => {
        reservationStarted = true;
        await action();
        reserved = true;
      });
    } catch (error: any) {
      // A thrown filesystem error is not proof of absence. Under our exclusive
      // preparation guard, only an accessible, absent reservation permits FAIL.
      if (reserved || error?.errorCode === "dispatch_reconciliation_required" || !await reservationAbsent(claim)) throw error;
      const failure: Failure = { ...context, ...claim, state: "PRE_DISPATCH_FAILURE",
        reason: String(error?.message || "Gateway preparation failed").slice(0, 500) };
      await write(failure); // durable failure outbox before an unreliable HTTP call
      try { await report(failure); await write({ ...failure, state: "PRE_DISPATCH_REPORTED" }); }
      catch { Object.assign(error, { failureReportingPending: true }); }
      Object.assign(error, { failureClassification: "PRE_DISPATCH_FAILURE", reservationStarted });
      throw error;
    }
  } finally { await handle.close(); }
};

// Lost failure acknowledgements retry only the authoritative FAIL operation,
// never payload rendering or physical transport. The SQL transition is idempotent.
export const flushGatewayPreDispatchFailures = async (context: Context, report: (failure: Failure) => Promise<void>) => {
  let files: string[];
  try { files = await fs.readdir(dispatchJournalRoot()); } catch (error: any) { if (error.code === "ENOENT") return; throw error; }
  for (const name of files.filter(name => /^[a-f0-9]{64}\.gateway-attempt\.json$/.test(name))) {
    const file = path.join(dispatchJournalRoot(), name);
    let failure: Failure;
    try { failure = JSON.parse(await fs.readFile(file, "utf8")); } catch { continue; }
    if (failure.state !== "PRE_DISPATCH_FAILURE" || failure.gatewayId !== context.gatewayId || failure.backendUrl !== context.backendUrl) continue;
    if (name !== `${key(itemKey(failure))}.gateway-attempt.json` || !await reservationAbsent(failure)) throw uncertain();
    try {
      await report(failure);
      const temp = `${file}.${randomUUID()}.tmp`;
      const handle = await fs.open(temp, "wx", 0o600);
      try { await handle.writeFile(JSON.stringify({ ...failure, state: "PRE_DISPATCH_REPORTED" })); await handle.sync(); }
      finally { await handle.close(); }
      await fs.rename(temp, file);
    } catch {
      // Keep a valid pending outbox on disk. A backend outage must not cause a
      // physical retry, nor prevent separately claimed work from being handled.
      console.warn("Gateway pre-dispatch failure report remains pending", { journalKey: name });
    }
  }
};
