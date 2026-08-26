import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import {
  PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP,
  PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
  validateProductionInitialActivationDuringAuthenticatedOverlap,
} from "../security/production-initial-overlap-activation-contract.mjs";
import { canonicalProductionEcsClusterArn, PRODUCTION_ECS_CLUSTER_NAME, STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { validateOnboardingContract, validateRotationClosedContract } from "../security/production-onboarding-contract.mjs";
import { verify as persistVerifiedOverlap, writeState } from "../../backend/scripts/security/rotate-production-signing-material.mjs";

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
  minimumGraceSeconds: PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
  jwt: { oldFingerprint: "1".repeat(16), newFingerprint: "2".repeat(16) },
  qr: { oldPrivateFingerprint: "3".repeat(16), oldPublicFingerprint: "4".repeat(16), newPrivateFingerprint: "5".repeat(16), newPublicFingerprint: "6".repeat(16), oldKeyVersion: "qr-old", newKeyVersion: "qr-new" },
  pending: { jwtVersionId: "jwt-version-1", qrPrivateVersionId: "qr-private-1", qrPublicVersionId: "qr-public-1" },
  overlapRuntime: {
    rotationId, phase: "overlap", deploymentSha, runtimeInvocationRef: "runtime-proof-1", observedAt,
    healthObservedAt: "2026-08-26T11:59:59.000Z", healthHttpStatus: 200, healthReleaseGitSha: sourceSha,
    expectedReleaseGitSha: sourceSha, expectedReleaseSha: sourceSha,
    targetTaskArn: taskArn, selectedTaskArn: taskArn, targetTaskDefinitionArn: taskDefinitionArn,
    targetImageDigest: imageDigest, targetService: "mscqr-backend-servi-euw2", targetCluster: STAGE_B.clusterArn,
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

test("production cluster name and ARN canonicalize to one persisted identity", () => {
  assert.equal(canonicalProductionEcsClusterArn(PRODUCTION_ECS_CLUSTER_NAME), STAGE_B.clusterArn);
  assert.equal(canonicalProductionEcsClusterArn(STAGE_B.clusterArn), STAGE_B.clusterArn);
  assert.doesNotThrow(() => validate(state()));
  const authenticatedShortName = state(); authenticatedShortName.overlapRuntime.targetCluster = PRODUCTION_ECS_CLUSTER_NAME;
  assert.doesNotThrow(() => validate(authenticatedShortName));
  for (const value of [
    "another-cluster",
    "arn:aws:ecs:eu-west-2:000000000000:cluster/mscqr-prod-euw2-main",
    "arn:aws:ecs:us-east-1:368992683803:cluster/mscqr-prod-euw2-main",
    "arn:aws:ecs:eu-west-2:368992683803:cluster/another-cluster",
    "cluster/mscqr-prod-euw2-main",
  ]) {
    assert.throws(() => canonicalProductionEcsClusterArn(value));
    const proofState = state(); proofState.overlapRuntime.targetCluster = value;
    assert.throws(() => validate(proofState), /exact ECS deployment/);
  }
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
    assert.throws(() => validate(value), /reviewed grace period/);
  }

  const shiftedObservation = state();
  shiftedObservation.overlapRuntime.observedAt = new Date(Date.parse(observedAt) + 1).toISOString();
  shiftedObservation.overlapReadyAt = shiftedObservation.overlapRuntime.observedAt;
  assert.throws(() => validate(shiftedObservation), /reviewed grace period/);

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

test("reviewed grace is at least 30 days and remains bound to its original deadline", () => {
  for (const minimumGraceSeconds of [2_592_000, 2_592_001, 3_000_000]) {
    const value = state();
    value.minimumGraceSeconds = minimumGraceSeconds;
    value.cleanupEligibleAt = new Date(Date.parse(value.overlapRuntime.observedAt) + minimumGraceSeconds * 1000).toISOString();
    const deadline = Date.parse(value.cleanupEligibleAt);
    assert.doesNotThrow(() => validate(value, {}, deadline - 1));
    assert.throws(() => validate(value, {}, deadline), /expired/);
    assert.throws(() => validate(value, {}, deadline + 1), /expired/);
  }
  for (const minimumGraceSeconds of [2_591_999, 0, -1, Number.MAX_SAFE_INTEGER]) {
    const value = state(); value.minimumGraceSeconds = minimumGraceSeconds;
    assert.throws(() => validate(value));
  }
  const extended = state(); extended.minimumGraceSeconds += 1; assert.throws(() => validate(extended), /reviewed grace/);
  const shortened = state(); shortened.minimumGraceSeconds -= 1; assert.throws(() => validate(shortened), /at least/);
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
  for (const rotationId of ["short", "rotation\ninjected", "rotation id spaces"]) assert.throws(() => validate(value, { rotationId }), /identity/);
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
  const parsed = yaml.load(workflow);
  const resolveSteps = parsed.jobs["resolve-deploy-target"].steps;
  const deploySteps = parsed.jobs["deploy-production-ecs"].steps;
  const resolveLifecycle = resolveSteps.find(({ name }) => name === "Validate production release lifecycle mode");
  const reconstruct = deploySteps.find(({ name }) => name === "Reconstruct activation rotation contract on deployment runner");
  const rlsStep = deploySteps.find(({ name }) => name === "Apply and verify checksum-bound production RLS package");
  const activationStep = deploySteps.find(({ name }) => name === "Activate exact Stage-B backend candidate");
  assert(resolveLifecycle && reconstruct && rlsStep && activationStep);
  assert.doesNotMatch(resolveLifecycle.run, /GITHUB_ENV|PRODUCTION_INITIAL_OVERLAP_STATE_FILE/);
  assert.match(reconstruct.env.ROTATION_STATE_JSON, /inputs\.rotation_state_json/);
  assert.match(reconstruct.env.SOURCE_SHA, /needs\.resolve-deploy-target\.outputs\.deploy_sha/);
  assert.match(reconstruct.run, /RUNNER_TEMP\/initial-overlap-rotation-state\.json/);
  assert.match(reconstruct.run, /PRODUCTION_ACTIVATION_ROTATION_CONTRACT=AUTHENTICATED_OVERLAP/);
  assert.match(reconstruct.run, /PRODUCTION_ACTIVATION_ROTATION_CONTRACT=STRICT_FINAL_ROTATION/);
  assert(deploySteps.indexOf(reconstruct) < deploySteps.indexOf(rlsStep));
  assert(deploySteps.indexOf(rlsStep) < deploySteps.indexOf(activationStep));
  const lifecycle = workflow.indexOf("Validate production release lifecycle mode");
  const rls = workflow.indexOf("Apply and verify checksum-bound production RLS package");
  const activation = workflow.indexOf("Activate exact Stage-B backend candidate");
  assert.match(workflow.slice(lifecycle, rls), /production-initial-overlap-activation-contract\.mjs/);
  assert.match(workflow.slice(lifecycle, rls), /check:rotation-evidence-freshness/);
  assert.match(workflow.slice(workflow.indexOf(reconstruct.name), rls), /PRODUCTION_INITIAL_OVERLAP_STATE_FILE=.*GITHUB_ENV/s);
  assert(rls > lifecycle && activation > rls);
  assert.match(workflow, /--expected-current-task-definition[\s\S]*--expected-current-deployment-id/);
  assert.match(workflow.slice(rls, activation), /production-normal-backend-activation\.mjs[\s\S]*--mode verify[\s\S]*apply-production-full-rls-release\.mjs/);
  assert.equal(workflow.match(/node scripts\/check-production-activation-rotation\.mjs/g)?.length, 2);
  assert.match(workflow, /Authenticated-overlap runtime image does not match the protected release image authorization/);
  assert.doesNotMatch(workflow, /minimumGraceSeconds\s*=|cleanupWindowComplete\s*=|--confirm-cleanup/);
});

test("production closure selects exactly one rotation lifecycle contract", () => {
  const script = readFileSync("scripts/check-production-activation-rotation.mjs", "utf8");
  const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
  assert.match(packageJson.scripts["stage-b:deployment-closure:production"], /check-production-activation-rotation/);
  assert.match(script, /check-rotation-evidence-freshness/);
  assert.match(script, /production-initial-overlap-activation-contract/);
  assert.match(script, /STRICT_FINAL_ROTATION/);
  assert.match(script, /AUTHENTICATED_OVERLAP/);
  assert.match(script, /must be selected explicitly/);
});

test("production closure rejects missing or contradictory lifecycle selection", () => {
  assert.throws(
    () => execFileSync(process.execPath, ["scripts/check-production-activation-rotation.mjs"], { env: { PATH: process.env.PATH }, stdio: "pipe" }),
    /Production activation rotation contract must be selected explicitly/,
  );
  assert.throws(
    () => execFileSync(process.execPath, ["scripts/check-production-activation-rotation.mjs"], {
      env: {
        PATH: process.env.PATH,
        PRODUCTION_ACTIVATION_ROTATION_CONTRACT: "STRICT_FINAL_ROTATION",
        PRODUCTION_INITIAL_OVERLAP_STATE_FILE: "/job-a/state.json",
      },
      stdio: "pipe",
    }),
    /Strict final rotation cannot consume initial-overlap bindings/,
  );
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
        PRODUCTION_ACTIVATION_ROTATION_CONTRACT: "AUTHENTICATED_OVERLAP",
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

test("real producer-consumer disk rehearsal accepts the documented cluster ARN and reviewed longer grace", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "mscqr-overlap-roundtrip-"));
  try {
    const bin = path.join(directory, "bin"); mkdirSync(bin);
    const proofFile = path.join(directory, "runtime-proof.json");
    const fixtureFile = path.join(directory, "fixture.json"); writeFileSync(fixtureFile, "{}\n", { mode: 0o600 });
    const observed = new Date(Date.now() - 120_000).toISOString();
    const healthObserved = new Date(Date.parse(observed) - 1_000).toISOString();
    const deploymentId = "ecs-svc/123456789";
    const awsFixture = {
      caller: { Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-ecs-exec-verifier/rehearsal" },
      service: { services: [{ serviceName: "mscqr-backend-servi-euw2", enableExecuteCommand: true, deployments: [{ id: deploymentId, status: "PRIMARY", taskDefinition: taskDefinitionArn }] }], failures: [] },
      cluster: { clusters: [{ clusterArn: STAGE_B.clusterArn, clusterName: PRODUCTION_ECS_CLUSTER_NAME, status: "ACTIVE" }], failures: [] },
      taskDefinition: { taskDefinition: { taskDefinitionArn, containerDefinitions: [{ name: "backend", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageDigest}`, environment: [{ name: "RELEASE_GIT_SHA", value: sourceSha }] }] } },
      listed: { taskArns: [taskArn] },
      described: { tasks: [{ taskArn, clusterArn: STAGE_B.clusterArn, taskDefinitionArn, lastStatus: "RUNNING", healthStatus: "HEALTHY", group: "service:mscqr-backend-servi-euw2", startedBy: deploymentId, containers: [{ name: "backend", imageDigest }], tags: [{ key: "MSCQRExecTarget", value: "production-backend" }], managedAgents: [{ name: "ExecuteCommandAgent", lastStatus: "RUNNING" }] }], failures: [] },
    };
    const aws = path.join(bin, "aws");
    writeFileSync(aws, `#!/usr/bin/env node
const fixture = JSON.parse(process.env.FAKE_AWS_FIXTURE);
const args = process.argv.slice(2); const key = args[0] + " " + args[1];
const clusterAt = args.indexOf("--cluster"); if (clusterAt >= 0 && args[clusterAt + 1] !== process.env.FAKE_CLUSTER_ARN) process.exit(9);
const responses = { "sts get-caller-identity": fixture.caller, "ecs describe-services": fixture.service, "ecs describe-clusters": fixture.cluster, "ecs describe-task-definition": fixture.taskDefinition, "ecs list-tasks": fixture.listed, "ecs describe-tasks": fixture.described };
if (!responses[key]) process.exit(8); process.stdout.write(JSON.stringify(responses[key]));
`, { mode: 0o700 }); chmodSync(aws, 0o700);
    const python = path.join(bin, "python3");
    writeFileSync(python, "#!/bin/sh\nprintf 'MSCQR_PROOF_BEGIN\\n%s\\nMSCQR_PROOF_END\\n' \"$FAKE_RUNTIME_PROOF\"\n", { mode: 0o700 }); chmodSync(python, 0o700);
    const proof = { rotationId, phase: "overlap", deploymentSha, runtimeInvocationRef: "runtime-proof-roundtrip", observedAt: observed, healthObservedAt: healthObserved, healthHttpStatus: 200, healthReleaseGitSha: sourceSha, expectedReleaseGitSha: sourceSha, ...runtimeChecks };
    const runVerifier = (cluster, output) => execFileSync(process.execPath, [
      "scripts/aws/verify-production-rotation-via-ecs-exec.mjs",
      "--cluster", cluster, "--service", "mscqr-backend-servi-euw2", "--task-definition", taskDefinitionArn,
      "--image-digest", imageDigest, "--release-sha", sourceSha, "--deployment-sha", deploymentSha,
      "--rotation-id", rotationId, "--invocation-ref", "runtime-proof-roundtrip", "--phase", "overlap",
      "--fixture-file", fixtureFile, "--health-url", "https://www.mscqr.com/api/health", "--proof-output", output,
    ], { env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FAKE_AWS_FIXTURE: JSON.stringify(awsFixture), FAKE_CLUSTER_ARN: STAGE_B.clusterArn, FAKE_RUNTIME_PROOF: JSON.stringify(proof) } });
    runVerifier(STAGE_B.clusterArn, proofFile);
    assert.equal(JSON.parse(readFileSync(proofFile, "utf8")).targetCluster, STAGE_B.clusterArn);
    const shortNameProofFile = path.join(directory, "runtime-proof-short-name.json");
    runVerifier(PRODUCTION_ECS_CLUSTER_NAME, shortNameProofFile);
    assert.equal(JSON.parse(readFileSync(shortNameProofFile, "utf8")).targetCluster, STAGE_B.clusterArn);

    const stateFile = path.join(directory, "state.json");
    const longerGrace = PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS + 1;
    writeState(stateFile, { ...state("overlap-deploy-required"), minimumGraceSeconds: longerGrace, cleanupEligibleAt: undefined, overlapReadyAt: undefined, verifiedAt: undefined, overlapRuntime: undefined, verification: undefined });
    const coordinatorConfig = { rotationId, sourceSha, overlapDeploymentSha: deploymentSha, minimumGraceSeconds: longerGrace };
    await persistVerifiedOverlap({ config: coordinatorConfig, values: new Map([["state-file", stateFile], ["runtime-verification-file", proofFile]]), clock: () => Date.parse(observed) + 60_000 });
    const persistedBytes = readFileSync(stateFile);
    const persisted = JSON.parse(persistedBytes);
    assert.equal(persisted.minimumGraceSeconds, longerGrace);
    assert.equal(persisted.overlapRuntime.targetCluster, STAGE_B.clusterArn);
    assert.equal(persisted.cleanupEligibleAt, new Date(Date.parse(observed) + longerGrace * 1000).toISOString());
    const roundTripFields = [
      "sourceSha", "rotationId", "phase", "overlapDeploymentSha", "overlapReadyAt", "verifiedAt", "cleanupEligibleAt", "minimumGraceSeconds",
      "jwt.oldFingerprint", "jwt.newFingerprint", "qr.oldPublicFingerprint", "qr.newPublicFingerprint", "qr.oldKeyVersion", "qr.newKeyVersion",
      "overlapRuntime.phase", "overlapRuntime.rotationId", "overlapRuntime.deploymentSha", "overlapRuntime.targetService", "overlapRuntime.targetCluster",
      "overlapRuntime.targetTaskDefinitionArn", "overlapRuntime.targetImageDigest", "overlapRuntime.targetTaskArn", "overlapRuntime.selectedTaskArn",
      "overlapRuntime.targetDeploymentId", "overlapRuntime.observedAt", "overlapRuntime.healthObservedAt", "overlapRuntime.expectedReleaseSha",
      "overlapRuntime.expectedReleaseGitSha", "overlapRuntime.healthReleaseGitSha", "overlapRuntime.runtimeInvocationRef", "verification.runtimeInvocationRef",
      ...Object.keys(runtimeChecks).map((name) => `overlapRuntime.${name}`),
    ];
    const at = (object, field) => field.split(".").reduce((value, key) => value?.[key], object);
    for (const field of roundTripFields) assert.notEqual(at(persisted, field), undefined, `real producer omitted ${field}`);
    const stateSha256 = createHash("sha256").update(persistedBytes).digest("hex");
    const activationArgs = ["--state-file", stateFile, "--state-sha256", stateSha256, "--source-sha", sourceSha, "--rotation-id", rotationId, "--deployment-sha", deploymentSha, "--task-definition", taskDefinitionArn, "--image-digest", imageDigest];
    assert.match(execFileSync(process.execPath, ["scripts/security/production-initial-overlap-activation-contract.mjs", ...activationArgs], { encoding: "utf8" }), /PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP/);
    const workflow = yaml.load(readFileSync(".github/workflows/release-gate.yml", "utf8"));
    const reconstruction = workflow.jobs["deploy-production-ecs"].steps.find(({ name }) => name === "Reconstruct activation rotation contract on deployment runner");
    assert(reconstruction);
    const jobA = path.join(directory, "job-a"); mkdirSync(jobA);
    writeFileSync(path.join(jobA, "state.json"), persistedBytes, { mode: 0o600 });
    writeFileSync(path.join(jobA, "github-env"), "PRODUCTION_INITIAL_OVERLAP_STATE_FILE=/job-a/state.json\n");
    rmSync(jobA, { recursive: true, force: true });
    assert.equal(existsSync(jobA), false);

    const jobB = path.join(directory, "job-b"); mkdirSync(jobB);
    const runReconstruction = (overrides = {}, target = jobB) => {
      mkdirSync(target, { recursive: true });
      const githubEnv = path.join(target, "github-env");
      const environment = {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        RUNNER_TEMP: target,
        GITHUB_ENV: githubEnv,
        SOURCE_SHA: sourceSha,
        ROTATION_ID: rotationId,
        ROTATION_STATE_JSON: persistedBytes.toString("utf8"),
        ROTATION_STATE_SHA256: stateSha256,
        ROTATION_TASK_DEFINITION_ARN: taskDefinitionArn,
        ROTATION_IMAGE_DIGEST: imageDigest,
        ROTATION_DEPLOYMENT_SHA: deploymentSha,
        ...overrides,
      };
      execFileSync("bash", ["-c", reconstruction.run], { cwd: process.cwd(), env: environment, stdio: "pipe" });
      return Object.fromEntries(readFileSync(githubEnv, "utf8").trim().split("\n").map((line) => {
        const separator = line.indexOf("=");
        return [line.slice(0, separator), line.slice(separator + 1)];
      }));
    };
    const jobBEnvironment = runReconstruction();
    assert.equal(jobBEnvironment.PRODUCTION_ACTIVATION_ROTATION_CONTRACT, "AUTHENTICATED_OVERLAP");
    assert.match(jobBEnvironment.PRODUCTION_INITIAL_OVERLAP_STATE_FILE, new RegExp(`^${jobB.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/`));
    assert.equal(existsSync(jobBEnvironment.PRODUCTION_INITIAL_OVERLAP_STATE_FILE), true);
    assert.match(execFileSync(process.execPath, ["scripts/check-production-activation-rotation.mjs"], { encoding: "utf8", env: { PATH: process.env.PATH, ...jobBEnvironment } }), /PRODUCTION_INITIAL_ACTIVATION_DURING_AUTHENTICATED_OVERLAP/);

    const reject = (name, overrides) => assert.throws(() => runReconstruction(overrides, path.join(directory, `reject-${name}`)), undefined, name);
    reject("missing-job-output", { SOURCE_SHA: "" });
    reject("tampered-job-output", { SOURCE_SHA: "f".repeat(40) });
    reject("missing-state-source", { ROTATION_STATE_JSON: "", PRODUCTION_INITIAL_OVERLAP_STATE_FILE: "/job-a/state.json" });
    reject("state-hash", { ROTATION_STATE_SHA256: "0".repeat(64) });
    reject("rotation-id", { ROTATION_ID: "rotation-other" });
    reject("deployment", { ROTATION_DEPLOYMENT_SHA: "d".repeat(40) });
    reject("task-definition", { ROTATION_TASK_DEFINITION_ARN: taskDefinitionArn.replace(/:51$/, ":52") });
    reject("image", { ROTATION_IMAGE_DIGEST: `sha256:${"e".repeat(64)}` });
    const expired = structuredClone(persisted);
    expired.overlapRuntime.observedAt = "2026-07-01T00:00:00.000Z";
    expired.overlapRuntime.healthObservedAt = "2026-06-30T23:59:59.000Z";
    expired.overlapReadyAt = expired.overlapRuntime.observedAt;
    expired.verifiedAt = "2026-07-01T00:01:00.000Z";
    expired.cleanupEligibleAt = new Date(Date.parse(expired.overlapReadyAt) + expired.minimumGraceSeconds * 1000).toISOString();
    const expiredJson = JSON.stringify(expired);
    reject("expired", { ROTATION_STATE_JSON: expiredJson, ROTATION_STATE_SHA256: createHash("sha256").update(expiredJson).digest("hex") });

    const onboardingFile = path.join(directory, "onboarding.json");
    const runtimeNames = ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "cookieCurrentSealOnly", "cookiePreviousOpenDuringOverlap", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify"];
    const acceptanceNames = ["superAdminLogin", "mfa", "authMe", "refresh", "dashboardStats", "qrStats", "tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "dbReady", "redisReady", "objectStorageReady", "stageANetworkingReady"];
    writeFileSync(onboardingFile, JSON.stringify({ valid: true, evidenceRef: "onboarding:roundtrip", evidenceSha256: "7".repeat(64), sourceSha, imageDigest, taskDefinitionArn, taskArn, rotationId, rotationStateSha256: stateSha256, taskMarker: true, ecsExecProof: true, serviceStable: true, targetTaskDefinitionMatch: true, targetImageDigestMatch: true, health: { serviceHealthy: true, healthReleaseGitSha: sourceSha }, rotationPhase: persisted.phase, runtime: Object.fromEntries(runtimeNames.map((name) => [name, true])), acceptance: Object.fromEntries(acceptanceNames.map((name) => [name, true])) }), { mode: 0o600 });
    assert.equal(validateOnboardingContract(JSON.parse(readFileSync(onboardingFile, "utf8"))), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
