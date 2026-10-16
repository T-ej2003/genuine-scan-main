import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalJson, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { authenticateCompletedInventoryAdoptionEvidence } from "./production-completed-inventory-adoption.mjs";
import { readBoundStageBPrivateJson, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const hash = value => createHash("sha256").update(value).digest("hex");
const equal = (a, b) => canonicalJson(a) === canonicalJson(b);

export function deriveRotationSuccessorState({ predecessorState, predecessorStateSha256, config }) {
  if (!predecessorState || !config || !SHA.test(config.sourceSha || "") || !SHA.test(config.completedInventoryPredecessorSourceSha || "")
      || config.sourceSha === config.completedInventoryPredecessorSourceSha
      || config.rotationSuccessor?.predecessorStateSha256 !== predecessorStateSha256
      || config.rotationSuccessor?.predecessorSourceSha !== config.completedInventoryPredecessorSourceSha
      || predecessorState.sourceSha !== config.completedInventoryPredecessorSourceSha
      || predecessorState.overlapDeploymentSha !== predecessorState.sourceSha
      || predecessorState.rotationId !== config.rotationId || predecessorState.phase !== "overlap-deploy-required"
      || predecessorState.inventoryEvidenceSha256 !== config.rotationSuccessor?.inventoryEvidenceSha256
      || !SHA256.test(predecessorStateSha256 || "") || !SHA256.test(config.rotationSuccessor?.predecessorFixtureSha256 || "")) {
    throw new Error("Rotation successor predecessor state or identity is invalid.");
  }
  return { ...predecessorState, sourceSha: config.sourceSha, overlapDeploymentSha: config.sourceSha };
}

export async function authenticateRotationSuccessor({ config, configSha256, predecessorState, predecessorStateSha256, predecessorFixtureSha256, state, fixtureSha256, inventoryEvidence, evidence, proveDescendant, verifySignature, now = new Date() }) {
  if (!SHA256.test(configSha256 || "") || !config?.rotationSuccessor || !SHA256.test(predecessorStateSha256 || "")
      || config.rotationSuccessor.predecessorFixtureSha256 !== predecessorFixtureSha256
      || fixtureSha256 !== predecessorFixtureSha256 || !SHA256.test(fixtureSha256 || "")
      || proveDescendant?.({ ancestorSha: config.completedInventoryPredecessorSourceSha, descendantSha: config.sourceSha }) !== true) throw new Error("Rotation successor source or fixture lineage is invalid.");
  const adopted = await authenticateCompletedInventoryAdoptionEvidence(inventoryEvidence, { config, configSha256, proveDescendant, now }, verifySignature);
  if (adopted.schemaVersion !== 3 || adopted.sourceSha !== config.completedInventoryPredecessorSourceSha
      || adopted.inventorySha256 !== config.rotationSuccessor.inventoryEvidenceSha256) throw new Error("Rotation successor inventory completion is not authenticated.");
  const derived = deriveRotationSuccessorState({ predecessorState, predecessorStateSha256, config });
  const expectedPayload = {
    kind: "PRODUCTION_ROTATION_SOURCE_SUCCESSOR", schemaVersion: 1,
    predecessorSourceSha: predecessorState.sourceSha, successorSourceSha: config.sourceSha,
    rotationId: config.rotationId, ticket: config.ticket, configSha256,
    predecessorStateSha256, predecessorFixtureSha256,
    inventoryAdoptionSha256: hash(canonicalJson(inventoryEvidence)),
    successorStateSha256: hash(canonicalJson(derived)),
  };
  if (!evidence || !equal(evidence.payload, expectedPayload) || !/^[A-Za-z0-9+/]+={0,2}$/.test(evidence.signatureBase64 || "")
      || typeof verifySignature !== "function"
      || !await verifySignature({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(expectedPayload)), signature: Buffer.from(evidence.signatureBase64, "base64") })) throw new Error("Rotation successor signature or immutable predecessor is invalid.");
  if (!equal(state, { ...derived, successorProvenance: evidence })) throw new Error("Rotation successor state differs from its authenticated predecessor.");
  return { state, evidence, predecessorStateSha256, predecessorFixtureSha256 };
}

export async function signRotationSuccessor({ config, configSha256, predecessorState, predecessorStateSha256, predecessorFixtureSha256, inventoryEvidence, proveDescendant, verifySignature, sign, now = new Date() }) {
  const derived = deriveRotationSuccessorState({ predecessorState, predecessorStateSha256, config });
  if (typeof sign !== "function" || !SHA256.test(configSha256 || "") || !SHA256.test(predecessorFixtureSha256 || "")) throw new Error("Rotation successor signer input is incomplete.");
  await authenticateCompletedInventoryAdoptionEvidence(inventoryEvidence, { config, configSha256, proveDescendant, now }, verifySignature);
  const payload = {
    kind: "PRODUCTION_ROTATION_SOURCE_SUCCESSOR", schemaVersion: 1,
    predecessorSourceSha: predecessorState.sourceSha, successorSourceSha: config.sourceSha,
    rotationId: config.rotationId, ticket: config.ticket, configSha256,
    predecessorStateSha256, predecessorFixtureSha256,
    inventoryAdoptionSha256: hash(canonicalJson(inventoryEvidence)),
    successorStateSha256: hash(canonicalJson(derived)),
  };
  const signatureBase64 = await sign({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(payload)) });
  const evidence = { payload, signatureBase64 };
  const state = { ...derived, successorProvenance: evidence };
  await authenticateRotationSuccessor({ config, configSha256, predecessorState, predecessorStateSha256, predecessorFixtureSha256, state, fixtureSha256: predecessorFixtureSha256, inventoryEvidence, evidence, proveDescendant, verifySignature, now });
  return { state, evidence };
}

export async function authenticatePreparedRotationSuccessor({ config, configSha256, repositoryRoot = process.cwd(), runAws, now = new Date() }) {
  if (!config.rotationSuccessor) return null;
  if (typeof runAws !== "function") throw new Error("Rotation successor requires a credential-bound KMS verifier.");
  const predecessor = config.rotationSuccessor;
  const originalConfig = readBoundStageBPrivateJson({ filePath: predecessor.predecessorConfigFile, expectedSha256: predecessor.predecessorConfigSha256, repositoryRoot, label: "Original rotation config" });
  const predecessorState = readBoundStageBPrivateJson({ filePath: predecessor.predecessorStateFile, expectedSha256: predecessor.predecessorStateSha256, repositoryRoot, label: "Original rotation state" });
  const originalFixture = readStageBPrivateFileBytes({ filePath: predecessor.predecessorFixtureFile, repositoryRoot, label: "Original rotation fixture" });
  const fixture = readStageBPrivateFileBytes({ filePath: config.rotationFixtureFile, repositoryRoot, label: "Successor rotation fixture" });
  const state = JSON.parse(readStageBPrivateFileBytes({ filePath: config.rotationStateFile, repositoryRoot, label: "Successor rotation state" }).bytes);
  const evidence = JSON.parse(readStageBPrivateFileBytes({ filePath: path.join(path.dirname(config.rotationStateFile), "rotation-successor-evidence.json"), repositoryRoot, label: "Rotation successor evidence" }).bytes);
  const inventoryEvidence = JSON.parse(readStageBPrivateFileBytes({ filePath: path.join(path.dirname(config.rotationStateFile), "inventory-completed-adoption-evidence.json"), repositoryRoot, label: "Completed inventory adoption" }).bytes);
  if (originalConfig.sourceSha !== predecessor.predecessorSourceSha || originalConfig.rotationId !== config.rotationId
      || originalConfig.rotationStateFile !== predecessor.predecessorStateFile || originalConfig.rotationFixtureFile !== predecessor.predecessorFixtureFile
      || !fixture.bytes.equals(originalFixture.bytes)) throw new Error("Rotation successor original material changed.");
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-verify-"));
  fs.chmodSync(temporary, 0o700);
  const messageFile = path.join(temporary, "message");
  try {
    const verifySignature = ({ keyId, message, signature }) => {
      fs.writeFileSync(messageFile, message, { mode: 0o600 });
      return JSON.parse(runAws(["kms", "verify", "--key-id", keyId, "--message", `fileb://${messageFile}`, "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", "RSASSA_PSS_SHA_256", "--output", "json", "--no-cli-pager"])).SignatureValid === true;
    };
    const proveDescendant = ({ ancestorSha, descendantSha }) => {
      try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: repositoryRoot, stdio: "ignore" }); return true; } catch { return false; }
    };
    return await authenticateRotationSuccessor({ config, configSha256, predecessorState, predecessorStateSha256: predecessor.predecessorStateSha256,
      predecessorFixtureSha256: originalFixture.sha256, state, fixtureSha256: fixture.sha256, inventoryEvidence, evidence, proveDescendant, verifySignature, now });
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}
