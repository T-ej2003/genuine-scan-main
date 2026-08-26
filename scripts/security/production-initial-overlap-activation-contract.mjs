#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP = "PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP";
export const PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS = 2_592_000;

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const FINGERPRINT = /^[a-f0-9]{16}$/;
const TASK_DEFINITION = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/;
const TASK = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9-]+$/;
const DEPLOYMENT = /^ecs-svc\/[1-9][0-9]*$/;
const SERVICE = "mscqr-backend-servi-euw2";
const CLUSTER = "mscqr-prod-euw2-main";
const REQUIRED_RUNTIME_CHECKS = Object.freeze([
  "jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected",
  "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected",
  "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify", "serviceHealthy",
]);
const CLEANUP_FIELDS = Object.freeze(["retirementTimestamp", "cleanupDeploymentSha", "cleanupRuntime", "cleanupCompletedAt", "cleanupEvidenceRef"]);

const fail = (message) => { throw new Error(message); };
const iso = (value) => {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : null;
};
const containsSensitiveStateKey = (value) => {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some(containsSensitiveStateKey);
  return Object.entries(value).some(([key, child]) => /(value|token|secret|fixture|password|credential|private(?:key|material))/i.test(key) || containsSensitiveStateKey(child));
};

export function validateProductionInitialActivationDuringAuthenticatedOverlap({ state, rawState, stateSha256, expected, now = Date.now() } = {}) {
  if (!state || typeof state !== "object" || Array.isArray(state) || containsSensitiveStateKey(state)) fail("Initial-overlap rotation state must be redacted metadata.");
  if (!Buffer.isBuffer(rawState) || !SHA256.test(stateSha256 || "") || createHash("sha256").update(rawState).digest("hex") !== stateSha256) fail("Initial-overlap rotation state bytes do not match their SHA-256.");
  if (!expected || !SHA40.test(expected.sourceSha || "") || typeof expected.rotationId !== "string" || !expected.rotationId || !TASK_DEFINITION.test(expected.taskDefinitionArn || "") || !DIGEST.test(expected.imageDigest || "") || !SHA40.test(expected.deploymentSha || "")) fail("Initial-overlap expected identity is incomplete.");
  if (state.stateVersion !== 3 || state.sourceSha !== expected.sourceSha || state.rotationId !== expected.rotationId || state.overlapDeploymentSha !== expected.deploymentSha) fail("Initial-overlap rotation identity does not match the authorized release.");
  if (state.phase !== "verified") fail("Initial activation requires OVERLAP_RUNTIME_VERIFIED state.");
  if (!FINGERPRINT.test(state.jwt?.oldFingerprint || "") || !FINGERPRINT.test(state.jwt?.newFingerprint || "") || state.jwt.oldFingerprint === state.jwt.newFingerprint) fail("Current and previous JWT material identities are invalid.");
  if (!FINGERPRINT.test(state.qr?.oldPublicFingerprint || "") || !FINGERPRINT.test(state.qr?.newPublicFingerprint || "") || state.qr.oldPublicFingerprint === state.qr.newPublicFingerprint || typeof state.qr?.oldKeyVersion !== "string" || typeof state.qr?.newKeyVersion !== "string" || !state.qr.oldKeyVersion || !state.qr.newKeyVersion || state.qr.oldKeyVersion === state.qr.newKeyVersion) fail("Current and previous QR material identities are invalid.");

  const proof = state.overlapRuntime;
  if (!proof || typeof proof !== "object" || Array.isArray(proof) || proof.phase !== "overlap" || proof.rotationId !== state.rotationId || proof.deploymentSha !== state.overlapDeploymentSha) fail("Authenticated overlap runtime proof is missing or mismatched.");
  if (proof.targetService !== SERVICE || proof.targetCluster !== CLUSTER || proof.targetTaskDefinitionArn !== expected.taskDefinitionArn || proof.targetImageDigest !== expected.imageDigest || !TASK.test(proof.targetTaskArn || "") || proof.selectedTaskArn !== proof.targetTaskArn || !DEPLOYMENT.test(proof.targetDeploymentId || "")) fail("Overlap runtime proof is not bound to the exact ECS deployment.");
  if (proof.expectedReleaseSha !== expected.sourceSha || proof.expectedReleaseGitSha !== expected.sourceSha || proof.healthReleaseGitSha !== expected.sourceSha || proof.healthHttpStatus !== 200) fail("Overlap runtime health is not bound to protected source.");
  for (const name of REQUIRED_RUNTIME_CHECKS) if (proof[name] !== true) fail(`Overlap runtime proof is missing ${name}.`);
  if (state.verification?.runtimeInvocationRef !== proof.runtimeInvocationRef) fail("Rotation verification does not bind the runtime invocation.");
  for (const name of REQUIRED_RUNTIME_CHECKS.filter((name) => !name.startsWith("artifact") && name !== "healthHttpStatus")) if (state.verification?.[name] !== true) fail(`Rotation verification is missing ${name}.`);

  const observedAt = iso(proof.observedAt);
  const healthObservedAt = iso(proof.healthObservedAt);
  const verifiedAt = iso(state.verifiedAt);
  const cleanupEligibleAt = iso(state.cleanupEligibleAt);
  const nowMs = typeof now === "function" ? now() : now;
  if ([observedAt, healthObservedAt, verifiedAt, cleanupEligibleAt, nowMs].some((value) => !Number.isFinite(value)) || healthObservedAt > observedAt || observedAt > verifiedAt || verifiedAt > nowMs || state.overlapReadyAt !== proof.observedAt) fail("Initial-overlap runtime timeline is invalid.");
  if (cleanupEligibleAt !== observedAt + PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS * 1000) fail("Rotation cleanup eligibility does not preserve the 30-day grace period.");
  if (state.cleanupWindowComplete === true || CLEANUP_FIELDS.some((field) => state[field] !== undefined && state[field] !== null)) fail("Initial overlap must not claim rotation cleanup or retirement.");

  return Object.freeze({
    contract: PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP,
    sourceSha: state.sourceSha,
    rotationId: state.rotationId,
    taskDefinitionArn: proof.targetTaskDefinitionArn,
    deploymentId: proof.targetDeploymentId,
    taskArn: proof.targetTaskArn,
    imageDigest: proof.targetImageDigest,
    cleanupEligibleAt: state.cleanupEligibleAt,
    minimumGraceSeconds: PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
    cleanupPending: true,
  });
}

const required = (values, name) => {
  const value = values.get(name);
  if (!value) fail(`${name} is required.`);
  return value;
};

export function runCli(argv = process.argv.slice(2)) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || values.has(key)) fail(`Invalid or duplicate argument: ${key || "<missing>"}`);
    values.set(key, value);
  }
  const stateFile = required(values, "--state-file");
  const rawState = readFileSync(stateFile);
  const result = validateProductionInitialActivationDuringAuthenticatedOverlap({
    state: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawState)),
    rawState,
    stateSha256: required(values, "--state-sha256"),
    expected: {
      sourceSha: required(values, "--source-sha"),
      rotationId: required(values, "--rotation-id"),
      deploymentSha: required(values, "--deployment-sha"),
      taskDefinitionArn: required(values, "--task-definition"),
      imageDigest: required(values, "--image-digest"),
    },
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli();
