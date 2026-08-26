import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { normalizeProductionRotationState, PRODUCTION_ROTATION_LEGACY_STATE_VERSION, PRODUCTION_ROTATION_STATE_VERSION } from "../../backend/scripts/security/production-rotation-grace-contract.mjs";

const MODES = new Set(["rotation-overlap", "rotation-cleanup"]);
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TASK_DEFINITION = /^arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/;
const FINGERPRINT = /^[a-f0-9]{16}$/;
const VERSION_ID = /^[A-Za-z0-9+=/:._-]{7,256}$/;
const ISO = (value) => {
  const time = Date.parse(String(value || ""));
  return Number.isFinite(time) ? time : null;
};
const fail = (message) => { throw new Error(message); };
const required = (value, name) => {
  const normalized = String(value || "").trim();
  if (!normalized) fail(`${name} is required`);
  return normalized;
};
const assert = (condition, message) => { if (!condition) fail(message); };

const containsSensitiveStateKey = (value) => {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsSensitiveStateKey);
  return Object.entries(value).some(([key, child]) =>
    /(value|token|secret|fixture|password|credential|private(?:key|material))/i.test(key) || containsSensitiveStateKey(child));
};

const assertCommon = ({ state, mode, sourceSha, rotationId, deploymentSha, taskDefinitionArn, expectedCurrentTaskDefinitionArn, imageDigest, stateSha256, rawState }) => {
  assert(MODES.has(mode), `unsupported rotation release mode: ${mode}`);
  assert(SHA.test(sourceSha), "source SHA must be a full protected-main SHA");
  assert(SHA.test(deploymentSha), "rotation deployment SHA must be a full SHA");
  assert(DIGEST.test(imageDigest), "rotation image digest must be immutable");
  assert(TASK_DEFINITION.test(taskDefinitionArn), "rotation task definition ARN is invalid");
  assert(TASK_DEFINITION.test(expectedCurrentTaskDefinitionArn), "expected current task definition ARN is invalid");
  assert(taskDefinitionArn !== expectedCurrentTaskDefinitionArn, "rotation target and expected current task definitions must differ");
  assert(typeof state === "object" && state !== null && !Array.isArray(state), "rotation state must be an object");
  assert(!containsSensitiveStateKey(state), "rotation state must contain metadata only, not secrets or fixtures");
  assert([PRODUCTION_ROTATION_LEGACY_STATE_VERSION, PRODUCTION_ROTATION_STATE_VERSION].includes(state.stateVersion), "rotation stateVersion is unsupported");
  assert(state.rotationId === rotationId, "rotation state rotationId does not match release input");
  assert(state.sourceSha === sourceSha, "rotation state source SHA does not match release target");
  assert(FINGERPRINT.test(state.jwt?.oldFingerprint) && FINGERPRINT.test(state.jwt?.newFingerprint), "rotation JWT fingerprints are invalid");
  assert(FINGERPRINT.test(state.qr?.oldPublicFingerprint) && FINGERPRINT.test(state.qr?.newPublicFingerprint), "rotation QR fingerprints are invalid");
  for (const [name, value] of Object.entries(state.pending || {})) assert(VERSION_ID.test(value), `${name} pending version ID is invalid`);
  assert(typeof state.overlapDeploymentSha === "string" && SHA.test(state.overlapDeploymentSha), "rotation overlap deployment SHA is invalid");
};

export function validateRotationTransition({ mode, sourceSha, rotationId, deploymentSha, taskDefinitionArn, expectedCurrentTaskDefinitionArn, imageDigest, stateSha256, rawState, now = Date.now() }) {
  assert((typeof rawState === "string" || Buffer.isBuffer(rawState)) && stateSha256 === createHash("sha256").update(rawState).digest("hex"), "rotation state SHA-256 does not match release input");
  let state;
  try { state = JSON.parse(Buffer.isBuffer(rawState) ? new TextDecoder("utf-8", { fatal: true }).decode(rawState) : rawState); } catch { fail("rotation state bytes are not valid UTF-8 JSON"); }
  assertCommon({ mode, state, sourceSha, rotationId, deploymentSha, taskDefinitionArn, expectedCurrentTaskDefinitionArn, imageDigest, stateSha256, rawState });
  const nowMs = typeof now === "function" ? now() : now;
  assert(Number.isFinite(nowMs), "transition validation clock is invalid");
  assert(ISO(state.preparedAt) !== null && ISO(state.preparedAt) <= nowMs, "rotation preparedAt is invalid");

  if (mode === "rotation-overlap") {
    assert(state.phase === "overlap-deploy-required", "overlap requires phase overlap-deploy-required");
    if (state.stateVersion === PRODUCTION_ROTATION_STATE_VERSION) state = normalizeProductionRotationState(state).state;
    assert(state.overlapDeploymentSha === deploymentSha, "overlap deployment SHA does not match prepared state");
    assert(ISO(state.overlapPreparedAt) !== null && ISO(state.overlapPreparedAt) <= nowMs, "overlapPreparedAt is invalid");
    assert(!state.cleanupRuntime && !state.cleanupCompletedAt && !state.cleanupDeploymentSha, "overlap state already contains cleanup proof");
  } else {
    state = normalizeProductionRotationState(state).state;
    assert(state.phase === "cleanup-deploy-required", "cleanup requires phase cleanup-deploy-required");
    assert(state.cleanupDeploymentSha === deploymentSha, "cleanup deployment SHA does not match persisted state");
    assert(ISO(state.cleanupEligibleAt) !== null && ISO(state.cleanupEligibleAt) <= nowMs, "cleanup grace window has not elapsed");
    assert(ISO(state.retirementTimestamp) !== null && ISO(state.retirementTimestamp) <= nowMs, "retirement timestamp is invalid");
    assert(state.overlapRuntime && state.verifiedAt, "cleanup requires persisted overlap runtime verification");
    assert(!state.cleanupRuntime && !state.cleanupCompletedAt && !state.cleanupEvidenceRef, "cleanup state already contains final runtime proof");
  }

  return {
    mode,
    phase: state.phase,
    rotationId: state.rotationId,
    sourceSha,
    deploymentSha,
    taskDefinitionArn,
    expectedCurrentTaskDefinitionArn,
    imageDigest,
    stateSha256,
  };
}

const parseArgs = (argv) => {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--") || index + 1 >= argv.length) fail(`invalid argument: ${arg}`);
    values.set(arg.slice(2), argv[++index]);
  }
  return values;
};

const main = () => {
  const values = parseArgs(process.argv.slice(2));
  const mode = required(values.get("mode"), "--mode");
  const stateFile = required(values.get("state-file"), "--state-file");
  const rawState = readFileSync(stateFile);
  const result = validateRotationTransition({
    mode,
    rawState,
    sourceSha: required(values.get("source-sha"), "--source-sha"),
    rotationId: required(values.get("rotation-id"), "--rotation-id"),
    deploymentSha: required(values.get("deployment-sha"), "--deployment-sha"),
    taskDefinitionArn: required(values.get("task-definition"), "--task-definition"),
    expectedCurrentTaskDefinitionArn: required(values.get("expected-current-task-definition"), "--expected-current-task-definition"),
    imageDigest: required(values.get("image-digest"), "--image-digest"),
    stateSha256: required(values.get("state-sha256"), "--state-sha256"),
  });
  console.log(JSON.stringify({ ...result, transitionReady: true }));
};

if (process.argv[1] && import.meta.url.endsWith(process.argv[1])) {
  try { main(); } catch (error) { console.error(`Production rotation transition validation failed: ${error.message || error}`); process.exit(1); }
}
