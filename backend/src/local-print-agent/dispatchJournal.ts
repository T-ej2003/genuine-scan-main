import { createHash } from "crypto";
import { promises as fs } from "fs";
import os from "os";
import path from "path";

export const dispatchJournalRoot = () => process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR || path.join(os.homedir(), ".mscqr", "dispatch-journal");
export const dispatchReservationKey = (job: string, item: string) => createHash('sha256').update(JSON.stringify(['v2',job,item])).digest('hex');
export const legacyDispatchKey = (item: string) => createHash('sha256').update(item).digest('hex');
export const dispatchReconciliationError = () => Object.assign(new Error('Prior dispatch evidence requires reconciliation; automatic replay refused.'),{errorCode:'dispatch_reconciliation_required'});

// Existing governed reissue moves a PrintItem into a newly authorized PrintJob.
// The authenticated server delivery binds both IDs. Retain old evidence while
// allowing that explicit reissue; a redelivery of the same job stays blocked.
// Older item-only markers are ambiguous and always fail closed. They are never
// deleted or inferred to authorize a replacement from mutable file contents.
export const priorDispatchExists = async (input: {printJobId:string;printItemId:string}) => {
  try {await fs.lstat(path.join(dispatchJournalRoot(),`${dispatchReservationKey(input.printJobId,input.printItemId)}.json`));return true;}
  catch(error:any){if(error.code!=='ENOENT')throw dispatchReconciliationError();}
  try {
    await fs.lstat(path.join(dispatchJournalRoot(),`${legacyDispatchKey(input.printItemId)}.json`));
    return true;
  } catch(error:any){if(error.code==='ENOENT')return false;throw dispatchReconciliationError();}
};

// A reservation is deliberately never automatically removed, including when
// the process dies before it can establish whether the printer received bytes.
// Reissue must use a newly governed job, not delete this evidence.
export const reserveAutomaticDispatch = async (input: {
  printJobId: string; printItemId: string; printerId: string; payloadHash: string;
}): Promise<boolean> => {
  if (!input.printJobId || !input.printItemId || !input.printerId || !input.payloadHash) {
    throw new Error("Automatic dispatch identity is incomplete.");
  }
  const root = dispatchJournalRoot();
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  if(await priorDispatchExists(input))return false;
  const key = dispatchReservationKey(input.printJobId,input.printItemId);
  let handle;
  try {
    handle = await fs.open(path.join(root, `${key}.json`), "wx", 0o600);
  } catch (error: any) {
    if (error?.code === "EEXIST") return false;
    throw error;
  }
  try {
    await handle.writeFile(JSON.stringify({ ...input, journalVersion:2, state: "ATTEMPT_RESERVED", reservedAt: new Date().toISOString() }));
    await handle.sync();
  } catch (error) {
    // Creation already succeeded. A failed write/fsync may leave a durable or
    // partial reservation; callers must not convert it into a retryable FAIL.
    throw Object.assign(new Error("Dispatch reservation could not be verified; reconciliation required."), {
      errorCode: "dispatch_reconciliation_required", cause: error,
    });
  } finally {
    try { await handle.close(); } catch (cause) {
      throw Object.assign(new Error("Dispatch reservation close failed; reconciliation required."), {
        errorCode: "dispatch_reconciliation_required", cause,
      });
    }
  }
  return true;
};
