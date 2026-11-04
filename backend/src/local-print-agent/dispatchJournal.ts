import { createHash } from "crypto";
import { promises as fs } from "fs";
import os from "os";
import path from "path";

// A reservation is deliberately never automatically removed, including when
// the process dies before it can establish whether the printer received bytes.
// Reissue must use a new governed print item, not delete this evidence.
export const reserveAutomaticDispatch = async (input: {
  printJobId: string; printItemId: string; printerId: string; payloadHash: string;
}): Promise<boolean> => {
  if (!input.printJobId || !input.printItemId || !input.printerId || !input.payloadHash) {
    throw new Error("Automatic dispatch identity is incomplete.");
  }
  const root = process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR || path.join(os.homedir(), ".mscqr", "dispatch-journal");
  await fs.mkdir(root, { recursive: true, mode: 0o700 });
  const key = createHash("sha256").update(input.printItemId).digest("hex");
  let handle;
  try {
    handle = await fs.open(path.join(root, `${key}.json`), "wx", 0o600);
  } catch (error: any) {
    if (error?.code === "EEXIST") return false;
    throw error;
  }
  try {
    await handle.writeFile(JSON.stringify({ ...input, state: "ATTEMPT_RESERVED", reservedAt: new Date().toISOString() }));
    await handle.sync();
  } finally { await handle.close(); }
  return true;
};
