import { createHash } from "crypto";
import { constants, promises as fs } from "fs";
import os from "os";
import path from "path";

export const dispatchJournalRoot = () => process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR || path.join(os.homedir(), ".mscqr", "dispatch-journal");
export const dispatchReservationKey = (job: string, item: string) => createHash('sha256').update(JSON.stringify(['v2',job,item])).digest('hex');
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
export const priorDispatchExists = async (input: {printJobId:string;printItemId:string}) => {
  try {await fs.lstat(path.join(dispatchJournalRoot(),`${dispatchReservationKey(input.printJobId,input.printItemId)}.json`));return true;}
  catch(error:unknown){if(fileErrorCode(error)!=='ENOENT')throw dispatchReconciliationError();}
  try {
    await fs.lstat(path.join(dispatchJournalRoot(),`${legacyDispatchKey(input.printItemId)}.json`));
    return true;
  } catch(error:unknown){if(fileErrorCode(error)==='ENOENT')return false;throw dispatchReconciliationError();}
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
  const key = dispatchReservationKey(input.printJobId,input.printItemId);
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
    await handle.writeFile(JSON.stringify({ ...input, journalVersion:2, state: "ATTEMPT_RESERVED", reservedAt: new Date().toISOString() }));
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
