import { createHash } from "crypto";
import { constants, promises as fs } from "fs";
import os from "os";
import path from "path";

export const dispatchJournalRoot = () => process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR || path.join(os.homedir(), ".mscqr", "dispatch-journal");
export const inspectDispatchJournal = async () => {
  const root = dispatchJournalRoot();
  let names: string[];
  try { names = (await fs.readdir(root)).sort(); }
  catch (error: unknown) {
    if (fileErrorCode(error) === "ENOENT") return { count: 0, sha256: createHash("sha256").update("[]").digest("hex"), entries: [] };
    throw error;
  }
  if (!(await fs.lstat(root)).isDirectory()) throw dispatchReconciliationError();
  if (names.length > 10_000) throw dispatchReconciliationError();
  let bytes = 0;
  const entries: { name: string; sha256: string; printJobId: string; printItemId: string; attemptId: string | null; state: string; gatewayId?: string }[] = [];
  for (const name of names) {
    if (!/^[a-f0-9]{64}(\.gateway-attempt)?\.json$/.test(name)) throw dispatchReconciliationError();
    const file = path.join(root, name);
    const stat = await fs.lstat(file);
    if (!stat.isFile() || stat.size > 1_048_576 || (bytes += stat.size) > 1_073_741_824) throw dispatchReconciliationError();
    const content = await fs.readFile(file);
    const after = await fs.lstat(file);
    if (content.length !== stat.size || !after.isFile() || after.size !== stat.size ||
        after.mtimeMs !== stat.mtimeMs || after.ino !== stat.ino) throw dispatchReconciliationError();
    let record: any;
    try { record = JSON.parse(content.toString("utf8")); } catch { throw dispatchReconciliationError(); }
    if (![2, 3].includes(record?.journalVersion) ||
        !["ATTEMPT_RESERVED", "PREPARING", "PRE_DISPATCH_FAILURE", "PRE_DISPATCH_REPORTED"].includes(record?.state) ||
        typeof record.printJobId !== "string" || typeof record.printItemId !== "string" ||
        (record.journalVersion === 3 && typeof record.attemptId !== "string") ||
        name !== `${dispatchReservationKey(record.testJobId ? `diagnostic:${record.testJobId}` : record.printJobId,
          record.testJobId ? `diagnostic:${record.testJobId}` : record.printItemId,
          record.journalVersion === 3 ? record.attemptId : undefined)}${name.endsWith(".gateway-attempt.json") ? ".gateway-attempt" : ""}.json`)
      throw dispatchReconciliationError();
    const gatewayId = process.env.PRINT_GATEWAY_ID;
    entries.push({ name, sha256: createHash("sha256").update(content).digest("hex"),
      printJobId: record.printJobId, printItemId: record.printItemId,
      attemptId: typeof record.attemptId === "string" ? record.attemptId : null, state: record.state,
      ...(gatewayId && (name.endsWith(".gateway-attempt.json") ? record.gatewayId : record.printerId) === gatewayId ? { gatewayId } : {}) });
  }
  return { count: entries.length, sha256: createHash("sha256").update(JSON.stringify(entries.map(({ name, sha256 }) => [name, sha256]))).digest("hex"), entries };
};
export const dispatchReservationKey = (job: string, item: string, attemptId?: string) =>
  createHash('sha256').update(JSON.stringify(attemptId ? ['v3',job,item,attemptId] : ['v2',job,item])).digest('hex');
export const legacyDispatchKey = (item: string) => createHash('sha256').update(item).digest('hex');
export const dispatchReconciliationError = () => Object.assign(new Error('Prior dispatch evidence requires reconciliation; automatic replay refused.'),{errorCode:'dispatch_reconciliation_required'});
const fileErrorCode = (error: unknown) => error && typeof error === 'object' && 'code' in error ? error.code : undefined;

const syncDirectory = async (directory: string) => {
  const handle = await fs.open(directory, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
};

// Existing governed reissue moves a PrintItem into a newly authorized PrintJob.
// The authenticated server delivery binds both IDs. Retain old evidence while
// allowing that explicit reissue; a redelivery of the same job stays blocked.
// Older item-only markers are ambiguous and always fail closed. They are never
// deleted or inferred to authorize a replacement from mutable file contents.
export const priorDispatchExists = async (input: {printJobId:string;printItemId:string;attemptId?:string}) => {
  try {await fs.lstat(path.join(dispatchJournalRoot(),`${dispatchReservationKey(input.printJobId,input.printItemId)}.json`));return true;}
  catch(error:unknown){if(fileErrorCode(error)!=='ENOENT')throw dispatchReconciliationError();}
  if (input.attemptId) {
    try {await fs.lstat(path.join(dispatchJournalRoot(),`${dispatchReservationKey(input.printJobId,input.printItemId,input.attemptId)}.json`));return true;}
    catch(error:unknown){if(fileErrorCode(error)!=='ENOENT')throw dispatchReconciliationError();}
  }
  try {
    await fs.lstat(path.join(dispatchJournalRoot(),`${legacyDispatchKey(input.printItemId)}.json`));
    return true;
  } catch(error:unknown){if(fileErrorCode(error)==='ENOENT')return false;throw dispatchReconciliationError();}
};

// A reservation is deliberately never automatically removed, including when
// the process dies before it can establish whether the printer received bytes.
// Reissue must use a newly governed job, not delete this evidence.
export const reserveAutomaticDispatch = async (input: {
  printJobId: string; printItemId: string; printerId: string; payloadHash: string; attemptId?: string;
}): Promise<boolean> => {
  if (!input.printJobId || !input.printItemId || !input.printerId || !input.payloadHash) {
    throw new Error("Automatic dispatch identity is incomplete.");
  }
  const root = dispatchJournalRoot();
  let rootExists = true;
  try { await fs.lstat(root); } catch (error: unknown) {
    if (fileErrorCode(error) !== 'ENOENT') throw error;
    rootExists = false;
  }
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  if (!rootExists && process.platform !== 'win32') {
    // mkdir may have created several ancestors. Persist each new name before
    // relying on a reservation file inside the new journal directory.
    let directory = root;
    while (path.dirname(directory) !== directory) {
      await syncDirectory(path.dirname(directory));
      directory = path.dirname(directory);
    }
  }
  if(await priorDispatchExists(input))return false;
  const key = dispatchReservationKey(input.printJobId,input.printItemId,input.attemptId);
  let handle;
  try {
    // POSIX synchronizes the new file and its parent directory below. Node 24
    // does not expose O_SYNC in fs.constants on Windows; keep exclusive create
    // and FlushFileBuffers via handle.sync there. Windows directory fsync is
    // unsupported, so a power-loss claim for its namespace is not inferred.
    handle = await fs.open(path.join(root, `${key}.json`),
      process.platform === 'win32' ? 'wx' :
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_SYNC, 0o600);
  } catch (error: unknown) {
    if (fileErrorCode(error) === "EEXIST") return false;
    throw error;
  }
  const durabilityErrors: unknown[] = [];
  try {
    await handle.writeFile(JSON.stringify({ ...input, journalVersion:input.attemptId ? 3 : 2, state: "ATTEMPT_RESERVED", reservedAt: new Date().toISOString() }));
    await handle.sync();
    if (process.platform !== 'win32') await syncDirectory(root);
  } catch (error) {
    durabilityErrors.push(error);
  }
  try { await handle.close(); } catch (error) { durabilityErrors.push(error); }
  if (durabilityErrors.length) {
    // Creation already succeeded. Failed write, sync or close may leave a
    // durable or partial marker; never convert it into a retryable failure.
    throw Object.assign(new Error("Dispatch reservation could not be verified; reconciliation required."), {
      errorCode: "dispatch_reconciliation_required",
      cause: durabilityErrors.length === 1 ? durabilityErrors[0] : new AggregateError(durabilityErrors),
    });
  }
  return true;
};
