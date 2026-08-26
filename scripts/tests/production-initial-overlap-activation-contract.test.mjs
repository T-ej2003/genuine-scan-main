import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import {
  PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP,
  PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
  validateProductionInitialActivationDuringAuthenticatedOverlap,
} from "../security/production-initial-overlap-activation-contract.mjs";
import { validateOnboardingContract, validateRotationClosedContract } from "../security/production-onboarding-contract.mjs";

const sourceSha = "a".repeat(40);
const imageDigest = `sha256:${"b".repeat(64)}`;
const rotationId = "rotation-initial-activation-1";
const deploymentSha = "c".repeat(40);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:51";
const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/0123456789abcdef0123456789abcdef";
const observedAt = "2026-08-26T12:00:00.000Z";
const cleanupEligibleAt = "2026-09-25T12:00:00.000Z";
const now = Date.parse("2026-08-26T12:01:00.000Z");
const cleanupEligibleAtMs = Date.parse(cleanupEligibleAt);
const runtimeChecks = {
  jwtCurrentRuntimeVerify: true, jwtPreviousRuntimeVerify: true, jwtInvalidRuntimeRejected: true,
  qrCurrentRuntimeVerify: true, qrPreviousRuntimeVerify: true, qrTamperMatchingKeyTest: true, qrUnknownKeyRejected: true,
  artifactCurrentRuntimeVerify: true, artifactHistoricalRuntimeVerify: true, serviceHealthy: true,
};
const state = (phase = "verified", extra = {}) => ({
  stateVersion: 3,
  rotationId,
  sourceSha,
  phase,
  overlapDeploymentSha: deploymentSha,
  preparedAt: "2026-08-26T11:00:00.000Z",
  overlapPreparedAt: "2026-08-26T11:10:00.000Z",
  overlapReadyAt: observedAt,
  verifiedAt: "2026-08-26T12:00:30.000Z",
  cleanupEligibleAt,
  jwt: { oldFingerprint: "1".repeat(16), newFingerprint: "2".repeat(16) },
  qr: { oldPrivateFingerprint: "3".repeat(16), oldPublicFingerprint: "4".repeat(16), newPrivateFingerprint: "5".repeat(16), newPublicFingerprint: "6".repeat(16), oldKeyVersion: "qr-old", newKeyVersion: "qr-new" },
  pending: { jwtVersionId: "jwt-version-1", qrPrivateVersionId: "qr-private-1", qrPublicVersionId: "qr-public-1" },
  overlapRuntime: {
    rotationId, phase: "overlap", deploymentSha, runtimeInvocationRef: "runtime-proof-1", observedAt,
    healthObservedAt: "2026-08-26T11:59:59.000Z", healthHttpStatus: 200, healthReleaseGitSha: sourceSha,
    expectedReleaseGitSha: sourceSha, expectedReleaseSha: sourceSha,
    targetTaskArn: taskArn, selectedTaskArn: taskArn, targetTaskDefinitionArn: taskDefinitionArn,
    targetImageDigest: imageDigest, targetService: "mscqr-backend-servi-euw2", targetCluster: "mscqr-prod-euw2-main",
    targetDeploymentId: "ecs-svc/123456789", ...runtimeChecks,
  },
  verification: { runtimeInvocationRef: "runtime-proof-1", ...Object.fromEntries(Object.entries(runtimeChecks).filter(([name]) => !name.startsWith("artifact"))) },
  ...extra,
});
const expected = { sourceSha, rotationId, deploymentSha, taskDefinitionArn, imageDigest };
const validate = (value, expectedOverrides = {}, clock = now) => {
  const rawState = Buffer.from(JSON.stringify(value));
  return validateProductionInitialActivationDuringAuthenticatedOverlap({ state: value, rawState, stateSha256: createHash("sha256").update(rawState).digest("hex"), expected: { ...expected, ...expectedOverrides }, now: clock });
};

test("verified overlap authorizes initial activation without claiming rotation closure", () => {
  const result = validate(state());
  assert.equal(result.contract, PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP);
  assert.equal(result.minimumGraceSeconds, 2_592_000);
  assert.equal(PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS, 2_592_000);
  assert.equal(result.cleanupEligibleAt, cleanupEligibleAt);
  assert.equal(result.cleanupPending, true);
  assert.throws(() => validateRotationClosedContract(state(), () => now), /cleanup|grace/i);
});

test("prepared or deployed-only rotation cannot authorize initial activation", () => {
  assert.throws(() => validate(state("prepared")), /OVERLAP_RUNTIME_VERIFIED/);
  assert.throws(() => validate(state("overlap-deploy-required")), /OVERLAP_RUNTIME_VERIFIED/);
  assert.throws(() => validate(state("overlap-ready")), /OVERLAP_RUNTIME_VERIFIED/);
  assert.throws(() => validate(state("grace-wait")), /OVERLAP_RUNTIME_VERIFIED/);
});

test("authenticated overlap expires exactly when cleanup becomes eligible", () => {
  assert.doesNotThrow(() => validate(state(), {}, cleanupEligibleAtMs - 1));
  assert.throws(() => validate(state(), {}, cleanupEligibleAtMs), /expired/);
  assert.throws(() => validate(state(), {}, cleanupEligibleAtMs + 1), /expired/);

  const finalCleanup = {
    cleanupEligibleAt,
    previousSlotsRetired: true,
    pendingSlotsRetired: true,
    cleanupDeploymentAfterRetirement: true,
    cleanupRuntimeVerified: true,
    oldJwtRejected: true,
    oldQrRejected: true,
    freshFinalRotationEvidence: true,
  };
  assert.equal(validateRotationClosedContract(finalCleanup, () => cleanupEligibleAtMs), true);
});

test("cleanup deadline remains anchored to the canonical overlap observation", () => {
  for (const delta of [-1, 1]) {
    const value = state();
    value.cleanupEligibleAt = new Date(cleanupEligibleAtMs + delta).toISOString();
    assert.throws(() => validate(value), /30-day grace period/);
  }

  const shiftedObservation = state();
  shiftedObservation.overlapRuntime.observedAt = new Date(Date.parse(observedAt) + 1).toISOString();
  shiftedObservation.overlapReadyAt = shiftedObservation.overlapRuntime.observedAt;
  assert.throws(() => validate(shiftedObservation), /30-day grace period/);

  const ambiguousTimestamp = state();
  ambiguousTimestamp.cleanupEligibleAt = "2026-09-25 12:00:00";
  assert.throws(() => validate(ambiguousTimestamp), /timeline/);

  const offsetTimestamp = state();
  offsetTimestamp.cleanupEligibleAt = "2026-09-25T13:00:00.000+01:00";
  assert.throws(() => validate(offsetTimestamp), /timeline/);

  for (const invalidClock of [Number.NaN, Number.POSITIVE_INFINITY, cleanupEligibleAtMs - 0.5]) {
    assert.throws(() => validate(state(), {}, invalidClock), /timeline/);
  }
});

test("identity, runtime, health, signing, and cleanup inconsistencies fail closed", () => {
  const mutations = [
    ["wrong source", (value) => { value.sourceSha = "f".repeat(40); }],
    ["wrong rotation", (value) => { value.rotationId = "rotation-wrong"; }],
    ["malformed deployment", (value) => { value.overlapRuntime.targetDeploymentId = "external/987654321"; }],
    ["wrong task definition", (value) => { value.overlapRuntime.targetTaskDefinitionArn = taskDefinitionArn.replace(/:51$/, ":52"); }],
    ["wrong image", (value) => { value.overlapRuntime.targetImageDigest = `sha256:${"e".repeat(64)}`; }],
    ["unhealthy", (value) => { value.overlapRuntime.serviceHealthy = false; }],
    ["missing signing", (value) => { value.overlapRuntime.artifactHistoricalRuntimeVerify = false; }],
    ["material alias", (value) => { value.jwt.newFingerprint = value.jwt.oldFingerprint; }],
    ["forged grace", (value) => { value.cleanupEligibleAt = "2026-08-27T12:00:00.000Z"; }],
    ["false cleanup", (value) => { value.cleanupWindowComplete = true; }],
    ["early retirement", (value) => { value.retirementTimestamp = "2026-08-26T12:00:31.000Z"; }],
    ["future verification", (value) => { value.verifiedAt = "2026-08-26T13:00:00.000Z"; }],
    ["sensitive material", (value) => { value.secretValue = "not-persistable"; }],
  ];
  for (const [name, mutate] of mutations) {
    const value = structuredClone(state()); mutate(value);
    assert.throws(() => validate(value), undefined, name);
  }
});

test("state byte tampering and expected identity drift fail closed", () => {
  const value = state();
  const rawState = Buffer.from(JSON.stringify(value));
  assert.throws(() => validateProductionInitialActivationDuringAuthenticatedOverlap({ state: value, rawState, stateSha256: "0".repeat(64), expected, now }), /bytes/);
  for (const [name, replacement] of [["sourceSha", "f".repeat(40)], ["rotationId", "rotation-other"], ["deploymentSha", "d".repeat(40)], ["taskDefinitionArn", taskDefinitionArn.replace(/:51$/, ":52")], ["imageDigest", `sha256:${"e".repeat(64)}`]]) {
    assert.throws(() => validate(value, { [name]: replacement }), undefined, name);
  }
});

test("verified overlap plus strict onboarding permits readiness while security failures remain blocking", () => {
  validate(state());
  const runtimeNames = ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "cookieCurrentSealOnly", "cookiePreviousOpenDuringOverlap", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify"];
  const acceptanceNames = ["superAdminLogin", "mfa", "authMe", "refresh", "dashboardStats", "qrStats", "tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "dbReady", "redisReady", "objectStorageReady", "stageANetworkingReady"];
  const onboarding = { valid: true, evidenceRef: "onboarding:test", evidenceSha256: "7".repeat(64), sourceSha, imageDigest, taskDefinitionArn, taskArn, rotationId, rotationStateSha256: "8".repeat(64), taskMarker: true, ecsExecProof: true, serviceStable: true, targetTaskDefinitionMatch: true, targetImageDigestMatch: true, health: { serviceHealthy: true, healthReleaseGitSha: sourceSha }, rotationPhase: "verified", runtime: Object.fromEntries(runtimeNames.map((name) => [name, true])), acceptance: Object.fromEntries(acceptanceNames.map((name) => [name, true])) };
  assert.equal(validateOnboardingContract(onboarding), true);
  for (const name of ["dbReady", "tenantIsolation", "superAdminLogin"]) assert.throws(() => validateOnboardingContract({ ...onboarding, acceptance: { ...onboarding.acceptance, [name]: false } }), new RegExp(name));
  assert.throws(() => validateOnboardingContract({ ...onboarding, health: { ...onboarding.health, serviceHealthy: false } }), /health/);
});

test("Release Gate uses the shared overlap contract and preserves the normal checksum-bound RLS transaction", () => {
  const workflow = readFileSync(".github/workflows/release-gate.yml", "utf8");
  yaml.load(workflow);
  const lifecycle = workflow.indexOf("Validate production release lifecycle mode");
  const rls = workflow.indexOf("Apply and verify checksum-bound production RLS package");
  const activation = workflow.indexOf("Activate exact Stage-B backend candidate");
  assert.match(workflow.slice(lifecycle, rls), /production-initial-overlap-activation-contract\.mjs/);
  assert.match(workflow.slice(lifecycle, rls), /check:rotation-evidence-freshness/);
  assert(rls > lifecycle && activation > rls);
  assert.match(workflow, /--expected-current-task-definition[\s\S]*--expected-current-deployment-id/);
  assert.match(workflow.slice(rls, activation), /production-normal-backend-activation\.mjs[\s\S]*--mode verify[\s\S]*apply-production-full-rls-release\.mjs/);
  assert.match(workflow, /Authenticated-overlap runtime image does not match the protected release image authorization/);
  assert.doesNotMatch(workflow, /minimumGraceSeconds\s*=|cleanupWindowComplete\s*=|--confirm-cleanup/);
});

test("production closure selects exactly one rotation lifecycle contract", () => {
  const script = readFileSync("scripts/check-production-activation-rotation.mjs", "utf8");
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  assert.match(packageJson.scripts["stage-b:deployment-closure:production"], /check-production-activation-rotation/);
  assert.match(script, /check-rotation-evidence-freshness/);
  assert.match(script, /production-initial-overlap-activation-contract/);
  assert.match(script, /values\.every/);
  assert.match(script, /values\.some/);
});

test("production closure consumes the exact verified-overlap state bytes", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "mscqr-initial-overlap-"));
  try {
    const stateFile = path.join(directory, "state.json");
    const observed = Date.now() - 120_000;
    const value = state("verified", {
      overlapReadyAt: new Date(observed).toISOString(),
      verifiedAt: new Date(observed + 60_000).toISOString(),
      cleanupEligibleAt: new Date(observed + PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS * 1000).toISOString(),
    });
    value.overlapRuntime.observedAt = value.overlapReadyAt;
    value.overlapRuntime.healthObservedAt = new Date(observed - 1_000).toISOString();
    const rawState = Buffer.from(JSON.stringify(value));
    writeFileSync(stateFile, rawState, { mode: 0o600 });
    const output = execFileSync(process.execPath, ["scripts/check-production-activation-rotation.mjs"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PRODUCTION_INITIAL_OVERLAP_STATE_FILE: stateFile,
        PRODUCTION_INITIAL_OVERLAP_STATE_SHA256: createHash("sha256").update(rawState).digest("hex"),
        PRODUCTION_INITIAL_OVERLAP_SOURCE_SHA: sourceSha,
        PRODUCTION_INITIAL_OVERLAP_ROTATION_ID: rotationId,
        PRODUCTION_INITIAL_OVERLAP_DEPLOYMENT_SHA: deploymentSha,
        PRODUCTION_INITIAL_OVERLAP_TASK_DEFINITION: taskDefinitionArn,
        PRODUCTION_INITIAL_OVERLAP_IMAGE_DIGEST: imageDigest,
      },
    });
    assert.match(output, new RegExp(PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
