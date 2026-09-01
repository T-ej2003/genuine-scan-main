import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { rotationBindingsToPostPrepareTaskBindings } from "./production-cutover-runtime-bootstrap.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;

const assertCoordinatorOutput = (filePath, repositoryRoot, label) => {
  ensureStageBPrivateDirectory({ directory: path.dirname(filePath), repositoryRoot, label: `${label} directory` });
  assertStageBArtifactPath({ artifactPath: filePath, repositoryRoot, label });
  if (lstatSync(filePath, { throwIfNoEntry: false })) readStageBPrivateFileBytes({ filePath, repositoryRoot, label });
};

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
export function createProductionRotationPrepareAdapter({ run, coordinator, configFile, configSha256, stateFile, fixtureFile, runtimeProofFile, repositoryRoot = process.cwd() } = {}) {
  if (typeof run !== "function" || typeof coordinator !== "string" || !configFile || !stateFile || !fixtureFile) {
    throw new Error("Production rotation prepare adapter is incomplete.");
  }
  const verifyOverlap = {
    async run({ execProof, rotationId, rotationStateSha256, rotationFixtureSha256 } = {}) {
      if (!runtimeProofFile || execProof?.valid !== true || !execProof.proof || !SHA256.test(rotationStateSha256 || "") || !SHA256.test(rotationFixtureSha256 || "")) throw new Error("Overlap coordinator verification inputs are incomplete.");
      const config = readBoundStageBPrivateJson({ filePath: configFile, expectedSha256: configSha256, repositoryRoot, label: "Production cutover runtime config" });
      if (config.rotationId !== rotationId) throw new Error("Overlap coordinator verification rotation changed.");
      const stateBefore = readStageBPrivateFileBytes({ filePath: stateFile, repositoryRoot, label: "Persisted rotation state" });
      const fixture = readStageBPrivateFileBytes({ filePath: fixtureFile, repositoryRoot, label: "Persisted rotation fixture" });
      if (fixture.sha256 !== rotationFixtureSha256) throw new Error("Overlap coordinator continuation artifacts changed.");
      const existing = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(stateBefore.bytes));
      const preparedStateSha256 = existing.phase === "overlap-deploy-required"
        ? stateBefore.sha256
        : existing.verification?.preparedStateSha256;
      if (!SHA256.test(preparedStateSha256 || "") || preparedStateSha256 !== rotationStateSha256) throw new Error("Rotation state is not bound to the prepared predecessor.");
      if (existing.phase === "verified") {
        if (existing.verification?.preparedStateSha256 !== rotationStateSha256 || !existing.overlapRuntime || !existing.overlapReadyAt || !existing.cleanupEligibleAt) throw new Error("Verified rotation state is not bound to the prepared predecessor.");
        return { terminalState: "VERIFIED_OVERLAP", rotationId, rotationStateSha256: stateBefore.sha256, overlapReadyAt: existing.overlapReadyAt, cleanupEligibleAt: existing.cleanupEligibleAt, resumed: true };
      }
      if (existing.phase !== "overlap-deploy-required" && existing.phase !== "overlap-ready") throw new Error("Overlap coordinator continuation phase is unsupported.");
      if (existing.phase === "overlap-ready" && (!existing.overlapRuntime || !existing.overlapReadyAt || !existing.cleanupEligibleAt)) throw new Error("Overlap-ready successor state is incomplete.");
      const existingProof = lstatSync(runtimeProofFile, { throwIfNoEntry: false });
      if (existingProof) {
        const captured = readStageBPrivateFileBytes({ filePath: runtimeProofFile, repositoryRoot, label: "Overlap runtime proof" });
        const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
        if (JSON.stringify(value) !== JSON.stringify(execProof.proof)) throw new Error("Persisted overlap runtime proof conflicts with this verifier attempt.");
      } else writeStageBPrivateFileAtomic({ filePath: runtimeProofFile, bytes: Buffer.from(`${JSON.stringify(execProof.proof, null, 2)}\n`), repositoryRoot, label: "Overlap runtime proof" });
      const response = lastJsonLine(await run(["node", coordinator, "--verify", "--config", configFile, "--config-sha256", configSha256, "--state-file", stateFile, "--runtime-verification-file", runtimeProofFile]));
      const stateAfter = readStageBPrivateFileBytes({ filePath: stateFile, repositoryRoot, label: "Verified rotation state" });
      const state = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(stateAfter.bytes));
      if (response.phase !== "verified" || state.phase !== "verified" || state.rotationId !== rotationId || !state.overlapRuntime || !state.overlapReadyAt || !state.cleanupEligibleAt) throw new Error("Rotation coordinator did not persist VERIFIED_OVERLAP.");
      return { terminalState: "VERIFIED_OVERLAP", rotationId, rotationStateSha256: stateAfter.sha256, overlapReadyAt: state.overlapReadyAt, cleanupEligibleAt: state.cleanupEligibleAt, resumed: false };
    },
  };
  return {
    async run({ inventory, rotationId } = {}) {
      if (!inventory || typeof inventory !== "object" || !SHA256.test(inventory.evidenceSha256 || "")) throw new Error("Rotation prepare requires hash-bound bounded inventory evidence.");
      if (!/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "")) throw new Error("Rotation prepare rotation ID is invalid.");
      const config = readBoundStageBPrivateJson({ filePath: configFile, expectedSha256: configSha256, repositoryRoot, label: "Production cutover runtime config" });
      assertCoordinatorOutput(stateFile, repositoryRoot, "Persisted rotation state");
      assertCoordinatorOutput(fixtureFile, repositoryRoot, "Persisted rotation fixture");
      const temporaryDirectory = mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-inventory-"));
      const inventoryFile = path.join(temporaryDirectory, "inventory.json");
      try {
        writeFileSync(inventoryFile, `${JSON.stringify(inventory)}\n`, { mode: 0o600 });
        const output = await run([
          "node", coordinator, "--prepare",
          "--config", configFile,
          "--config-sha256", configSha256,
          "--state-file", stateFile,
          "--fixture-file", fixtureFile,
          "--inventory-evidence-file", inventoryFile,
        ]);
        const response = lastJsonLine(output);
        const persistedRotationId = String(response.rotationId || "");
        if (persistedRotationId !== rotationId || response.phase !== "overlap-deploy-required") throw new Error("Rotation coordinator did not persist the expected prepared phase.");
        const persistedState = readStageBPrivateFileBytes({ filePath: stateFile, repositoryRoot, label: "Persisted rotation state" });
        const persistedFixture = readStageBPrivateFileBytes({ filePath: fixtureFile, repositoryRoot, label: "Persisted rotation fixture" });
        const state = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(persistedState.bytes));
        if (state.rotationId !== persistedRotationId || state.phase !== response.phase) throw new Error("Persisted rotation state does not match coordinator readback.");
        const rotationStateSha256 = persistedState.sha256;
        return {
          valid: true,
          prepared: true,
          rotationId: persistedRotationId,
          rotationStateSha256,
          rotationFixtureSha256: persistedFixture.sha256,
          inventoryEvidenceSha256: inventory.evidenceSha256,
          evidenceRef: `rotation-state:${persistedRotationId}`,
          evidenceSha256: createHash("sha256").update(`${persistedRotationId}:${rotationStateSha256}:${persistedFixture.sha256}:${inventory.evidenceSha256}`).digest("hex"),
          overlapSecretBindings: rotationBindingsToPostPrepareTaskBindings(config),
          mutationCount: 1,
        };
      } finally {
        rmSync(temporaryDirectory, { recursive: true, force: true });
      }
    },
    async revalidate({ rotationId, rotationStateSha256 } = {}) {
      if (!/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "") || !SHA256.test(rotationStateSha256 || "")) throw new Error("Rotation post-prepare identity is invalid.");
      const config = readBoundStageBPrivateJson({ filePath: configFile, expectedSha256: configSha256, repositoryRoot, label: "Production cutover runtime config" });
      if (config.rotationId !== rotationId) throw new Error("Rotation post-prepare config identity changed.");
      const persistedState = readStageBPrivateFileBytes({ filePath: stateFile, repositoryRoot, label: "Persisted rotation state" });
      if (persistedState.sha256 !== rotationStateSha256) throw new Error("Persisted rotation state changed before ECS registration.");
      const response = lastJsonLine(await run(["node", coordinator, "--status", "--config", configFile, "--config-sha256", configSha256, "--state-file", stateFile]));
      if (response.mode !== "status" || response.phase !== "overlap-deploy-required" || !response.records || typeof response.records !== "object") throw new Error("Live rotation state no longer authenticates the prepared overlap.");
      return { valid: true, rotationId, rotationStateSha256, phase: response.phase };
    },
    verifyOverlap,
  };
}
