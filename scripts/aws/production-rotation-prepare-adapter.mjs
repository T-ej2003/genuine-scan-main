import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;

const hashFile = (filePath) => createHash("sha256").update(readFileSync(filePath)).digest("hex");

const lastJsonLine = (output) => {
  const lines = String(output || "").trim().split("\n").reverse();
  for (const line of lines) {
    try { return JSON.parse(line); } catch { /* coordinator diagnostics are not evidence */ }
  }
  throw new Error("Rotation coordinator did not return machine-readable prepare evidence.");
};

/**
 * Production adapter for the reviewed coordinator. The coordinator owns the
 * secret/state transaction; this boundary supplies only aggregate inventory
 * evidence and returns redacted persisted-state metadata.
 */
export function createProductionRotationPrepareAdapter({ run, coordinator, configFile, stateFile, fixtureFile } = {}) {
  if (typeof run !== "function" || typeof coordinator !== "string" || !configFile || !stateFile || !fixtureFile) {
    throw new Error("Production rotation prepare adapter is incomplete.");
  }
  return {
    async run({ inventory, rotationId } = {}) {
      if (!inventory || typeof inventory !== "object" || !SHA256.test(inventory.evidenceSha256 || "")) throw new Error("Rotation prepare requires hash-bound bounded inventory evidence.");
      if (!/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "")) throw new Error("Rotation prepare rotation ID is invalid.");
      const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-inventory-"));
      const inventoryFile = path.join(temporaryDirectory, "inventory.json");
      try {
        writeFileSync(inventoryFile, `${JSON.stringify(inventory)}\n`, { mode: 0o600 });
        const output = await run([
          "node", coordinator, "--prepare",
          "--config", configFile,
          "--state-file", stateFile,
          "--fixture-file", fixtureFile,
          "--inventory-evidence-file", inventoryFile,
        ]);
        const response = lastJsonLine(output);
        const persistedRotationId = String(response.rotationId || "");
        if (persistedRotationId !== rotationId || response.phase !== "overlap-deploy-required") throw new Error("Rotation coordinator did not persist the expected prepared phase.");
        const rotationStateSha256 = hashFile(stateFile);
        if (!SHA256.test(rotationStateSha256)) throw new Error("Persisted rotation state hash is invalid.");
        return {
          valid: true,
          prepared: true,
          rotationId: persistedRotationId,
          rotationStateSha256,
          inventoryEvidenceSha256: inventory.evidenceSha256,
          evidenceRef: `rotation-state:${persistedRotationId}`,
          evidenceSha256: createHash("sha256").update(`${persistedRotationId}:${rotationStateSha256}:${inventory.evidenceSha256}`).digest("hex"),
          mutationCount: 1,
        };
      } finally {
        rmSync(temporaryDirectory, { recursive: true, force: true });
      }
    },
  };
}
