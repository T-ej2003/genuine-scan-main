import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { validateRotationTransition } from "../security/check-production-rotation-transition.mjs";

const read = (path) => readFileSync(path, "utf8");
const template = read("infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-rotation-candidate.json");
const terraform = read("infra/aws/terraform/production-green-stage-b/main.tf");
const variables = read("infra/aws/terraform/production-green-stage-b/variables.tf");
const qr = read("backend/src/services/qrTokenService.ts");
const jwt = read("backend/src/utils/secretConfig.ts");
const coordinator = read("backend/scripts/security/rotate-production-signing-material.mjs");
const runtimeVerifier = read("backend/src/security/productionRotationRuntime.ts");
const runtimeCommand = read("backend/scripts/security/verify-production-rotation-runtime.mjs");
const artifact = read("backend/src/services/artifactSigningService.ts");
const compliance = read("backend/src/services/compliancePackService.ts");
const immutableAudit = read("backend/src/services/immutableAuditExportService.ts");
const qualityGate = read(".github/workflows/quality-gate.yml");
const deploymentAudit = read(".github/workflows/deployment-audit.yml");
const releaseCandidateGate = read(".github/workflows/release-candidate-gate.yml");
const releaseGate = read(".github/workflows/release-gate.yml");
const releaseTrain = read(".github/workflows/release-train.yml");
const runbook = read("documents/SECURITY_KEY_ROTATION_RUNBOOK.md");
const dockerfile = read("backend/Dockerfile");
const backendPackage = JSON.parse(read("backend/package.json"));

test("rotation task template is dual-slot and Ed25519-only", () => {
  for (const placeholder of [
    "{{JWT_SECRET_CURRENT}}",
    "{{JWT_SECRET_PREVIOUS}}",
    "{{QR_SIGN_PRIVATE_KEY_CURRENT}}",
    "{{QR_SIGN_PUBLIC_KEY_CURRENT}}",
    "{{QR_SIGN_ACTIVE_KEY_VERSION}}",
    "{{QR_SIGN_PUBLIC_KEY_PREVIOUS}}",
    "{{QR_SIGN_PREVIOUS_KEY_VERSION}}",
    "{{ARTIFACT_SIGN_PRIVATE_KEY_CURRENT}}",
    "{{ARTIFACT_SIGN_PUBLIC_KEY_CURRENT}}",
    "{{ARTIFACT_SIGN_ACTIVE_KEY_VERSION}}",
    "{{ARTIFACT_SIGN_PUBLIC_KEYS_JSON}}",
  ]) assert.ok(template.includes(placeholder), `missing rotation placeholder: ${placeholder}`);
  assert.doesNotMatch(template, /QR_SIGN_HMAC/);
  assert.match(artifact, /Ed25519/);
  assert.doesNotMatch(compliance, /QR_SIGN_(PRIVATE_KEY|HMAC)/);
  assert.doesNotMatch(immutableAudit, /QR_SIGN_(PRIVATE_KEY|HMAC)/);
  assert.match(template, /"containerPort": 4000/);
  assert.match(template, /"protocol": "tcp"/);
});

test("cleanup task mode removes every retired previous binding while overlap keeps them", () => {
  const secrets = JSON.parse(template).containerDefinitions[0].secrets.map(({ name }) => name);
  const retiredPrevious = ["JWT_SECRET_PREVIOUS", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"];
  const current = ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION"];
  assert.deepEqual(secrets.filter((name) => retiredPrevious.includes(name)), retiredPrevious);
  assert.deepEqual(secrets.filter((name) => current.includes(name)), current);
  assert.match(terraform, /production_rotation_cleanup_enabled/);
  assert.match(terraform, /contains\(\["JWT_SECRET_PREVIOUS", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"\]/);
  assert.deepEqual(secrets.filter((name) => !retiredPrevious.includes(name)).filter((name) => current.includes(name)), current);
});

test("runtime contracts issue current and verify only current plus one previous slot", () => {
  assert.match(jwt, /currentKeys: \["JWT_SECRET_CURRENT"\]/);
  assert.match(jwt, /previousKeys: \["JWT_SECRET_PREVIOUS"\]/);
  assert.match(qr, /readPreviousPublicKey/);
  assert.match(qr, /keys\.push\(\{ version: previousVersion/);
  assert.match(qr, /if \(!matchedKey\) throw new QrTokenVerificationError/);
  assert.match(qr, /requestedKeyVersion !== signingProfile\.keyVersion/);
  assert.match(qr, /QR_SIGN_PRIVATE_KEY_PREVIOUS/);
});

test("Terraform rotation mode is opt-in and references exact Secrets Manager JSON keys", () => {
  assert.match(terraform, /production_rotation_enabled/);
  assert.match(terraform, /production_rotation_secret_value_from/);
  assert.match(variables, /Production rotation task definitions require exact Secrets Manager JSON-key valueFrom references/);
  assert.match(variables, /current and previous secret references\/version references must be distinct/);
});

test("Stage B candidate definitions keep both rotation modes type-compatible", () => {
  assert.match(terraform, /candidate_definitions = merge\(/);
  assert.match(terraform, /\{ backend = local\.backend_definition_for_mode \}/);
  assert.match(terraform, /if kind != "backend"/);
  assert.doesNotMatch(terraform, /kind == "backend" \? local\.backend_definition_for_mode/);
});

test("rotation task secret entries remain ECS valueFrom objects", () => {
  const rotation = JSON.parse(template).containerDefinitions[0];
  assert.equal(rotation.environment.find(({ name }) => name === "ROTATION_RUNTIME_TMP_DIR")?.value, "/app/uploads");
  assert.equal(rotation.secrets.some(({ name, value }) => name === "ROTATION_RUNTIME_TMP_DIR" || value !== undefined), false);
  assert.equal(rotation.secrets.every(({ valueFrom }) => typeof valueFrom === "string" && valueFrom.length > 0), true);
});

test("overlap secret set is bounded into the backend execution role", () => {
  const overlapSecrets = ["jwt_current", "jwt_previous", "qr_private_current", "qr_public_current", "qr_current_version", "qr_public_previous", "qr_previous_version", "artifact_private_current", "artifact_public_current", "artifact_active_version", "artifact_public_keys_json"];
  const templateNames = new Set(JSON.parse(template).containerDefinitions[0].secrets.map(({ name }) => name));
  for (const name of ["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION", "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"]) assert.equal(templateNames.has(name), true, name);
  assert.match(terraform, /overlap_rotation_secret_arns = var\.production_rotation_enabled/);
  assert.match(terraform, /backend_execution_secret_arns = var\.production_rotation_enabled/);
  assert.match(terraform, /trimsuffix\(value, ":value::"\)/);
  assert.match(terraform, /alltrue\(\[for arn in local\.overlap_rotation_secret_arns : contains\(local\.backend_execution_secret_arns, arn\) && !strcontains\(arn, "\*"\)\]\)/);
  const executionPolicy = terraform.match(/resource "aws_iam_role_policy" "execution"[\s\S]*?(?=\nresource )/)?.[0] || "";
  assert.match(executionPolicy, /secretsmanager:GetSecretValue/);
  assert.match(executionPolicy, /local\.backend_execution_secret_arns/);
  const secretStatement = executionPolicy.match(/Sid\s*=\s*"ReadOnlyExactInjectedSecrets"[\s\S]*?\n      \}/)?.[0] || "";
  assert.doesNotMatch(secretStatement, /Resource\s*=\s*["']\*["']/);
  assert.doesNotMatch(secretStatement, /mscqr\/prod\/\*/);
  assert.doesNotMatch(secretStatement, /kms:Decrypt/);
});

test("coordinator exposes explicit resumable phases and no implicit cleanup", () => {
  for (const mode of ["--prepare", "--verify", "--cleanup", "--status"]) assert.match(coordinator, new RegExp(mode.slice(2)));
  assert.match(coordinator, /exactly one of --prepare, --verify, --cleanup, or --status/);
  assert.match(coordinator, /--config-sha256 must be an exact SHA-256/);
  assert.match(coordinator, /rotation config changed after approval/);
  assert.match(coordinator, /--confirm-cleanup is required for cleanup/);
  assert.match(coordinator, /config\.qr\.previousKeyVersion/);
  assert.match(coordinator, /deploymentRequired: true/);
  for (const phase of ["prepared", "overlap-deploy-required", "overlap-ready", "verified", "grace-wait", "retirement-started", "retirement-complete", "cleanup-deploy-required", "cleanup-runtime-verified", "cleaned"]) assert.match(coordinator, new RegExp(phase));
  assert.match(coordinator, /minimumGraceSeconds/);
  assert.match(coordinator, /retirementTimestamp/);
  assert.match(coordinator, /cleanup deployment must occur after retirement writes/);
  assert.match(coordinator, /qrPublicPending/);
  assert.doesNotMatch(coordinator, /console\.log\([^\n]*SecretString/);
});

test("runtime verification is deployment-side and uses the application verification stack", () => {
  assert.match(runtimeVerifier, /verifyJwtWithCurrentOrPrevious/);
  assert.match(runtimeVerifier, /verifyQrToken/);
  assert.match(runtimeVerifier, /verifyProductionRotationCleanupRuntime/);
  assert.match(runtimeCommand, /ROTATION_RUNTIME_PHASE/);
  assert.match(runtimeCommand, /ROTATION_DEPLOYMENT_SHA/);
  assert.match(runtimeCommand, /--health-url/);
  assert.match(runtimeCommand, /protocol !== "https:"/);
  assert.match(runtimeCommand, /--expected-release-sha/);
  assert.match(runtimeVerifier, /currentJwtToken/);
  assert.match(runtimeVerifier, /previousJwtToken/);
  assert.match(runtimeVerifier, /signUnknownKidFixture/);
  assert.match(runtimeVerifier, /payload\.kid = "unknown-runtime-key"/);
  assert.match(runtimeVerifier, /cryptoSign\(null/);
  assert.match(runtimeVerifier, /signArtifactPayload/);
  assert.match(runtimeVerifier, /verifyArtifactPayload/);
  assert.doesNotMatch(runtimeVerifier, /const currentToken = jwt\.sign/);
  assert.doesNotMatch(runtimeVerifier, /const previousToken = jwt\.sign/);
  assert.doesNotMatch(runtimeCommand, /console\.log\([^\n]*Token/);
});

test("deployed-task verifier command matches the image filesystem and parser contract", () => {
  assert.match(dockerfile, /WORKDIR \/app/);
  assert.equal(backendPackage.scripts["security:verify-production-rotation-runtime"], "node scripts/security/verify-production-rotation-runtime.mjs");
  for (const value of ["ROTATION_RUNTIME_PHASE", "ROTATION_ID", "ROTATION_DEPLOYMENT_SHA", "ROTATION_RUNTIME_INVOCATION_REF", "--fixture-file", "--proof-output", "--health-url", "--expected-release-sha"]) {
    assert.match(runbook, new RegExp(value.replaceAll("-", "\\-")), `runbook is missing ${value}`);
  }
  assert.match(runbook, /verify-production-rotation-via-ecs-exec\.sh/);
  assert.match(runbook, /--task-definition/);
  assert.match(runbook, /--image-digest/);
  assert.doesNotMatch(runbook, /npm --prefix backend run security:verify-production-rotation-runtime/);
  assert.doesNotMatch(runtimeCommand, /--verification-out/);
});

test("Stage B image classification keeps the evidence schema non-image and unknown paths fail closed", async () => {
  const { classifyStageBImageReusePath, imageImpactReportFor } = await import("../aws/validate-stage-b-image-reuse.mjs");
  const schema = ".security/rotation-evidence.schema.json";
  assert.deepEqual(classifyStageBImageReusePath(schema), { file: schema, category: "toolingOnly", imageAffecting: false });
  assert.deepEqual(imageImpactReportFor({ imageReleaseSha: "a".repeat(40), toolingSha: "b".repeat(40), toolingInputTreeSha256: "c".repeat(64), changedFiles: [schema] }).imageAffectingFiles, []);
  assert.equal(classifyStageBImageReusePath("backend/src/app.ts").imageAffecting, true);
  assert.equal(classifyStageBImageReusePath("frontend/src/App.tsx").category, "unknown");
  assert.throws(() => imageImpactReportFor({ imageReleaseSha: "a".repeat(40), toolingSha: "b".repeat(40), toolingInputTreeSha256: "c".repeat(64), changedFiles: ["unknown/runtime.bin"] }), /unclassified/);
});

test("pre-rotation pushes use source validation while explicit production runs stay strict", () => {
  const securityStep = qualityGate.slice(qualityGate.indexOf("- name: Security and release guardrails"));
  assert.match(securityStep, /GITHUB_EVENT_NAME.*schedule/);
  assert.match(securityStep, /GITHUB_EVENT_NAME.*workflow_dispatch/);
  assert.match(securityStep, /verify:ci:security:source/);
  assert.match(securityStep, /verify:ci:security\n/);
  assert.doesNotMatch(securityStep, /GITHUB_REF.*refs\/heads\/main/);

  const deploymentStep = deploymentAudit.slice(deploymentAudit.indexOf("- name: Run full release validation"));
  assert.match(deploymentStep, /GITHUB_EVENT_NAME.*workflow_dispatch/);
  assert.match(deploymentStep, /verify:release:source/);
  assert.match(deploymentStep, /verify:release\n/);

  const releaseCandidateStep = releaseCandidateGate.slice(releaseCandidateGate.indexOf("- name: Release-candidate validation contract"));
  assert.match(releaseCandidateStep, /GITHUB_EVENT_NAME.*workflow_dispatch/);
  assert.match(releaseCandidateStep, /refs\/heads\/release-candidate/);
  assert.match(releaseCandidateStep, /refs\/tags/);
  assert.match(releaseCandidateStep, /verify:ci:release-candidate:source/);
  assert.match(releaseCandidateStep, /verify:ci:release-candidate\n/);

  const mode = ({ ref, event }) => event === "schedule" || event === "workflow_dispatch" || ref.startsWith("refs/heads/release-candidate/") || ref.startsWith("refs/tags/") ? "strict" : "source";
  assert.equal(mode({ ref: "refs/pull/256/merge", event: "pull_request" }), "source");
  assert.equal(mode({ ref: "refs/heads/codex/rotation-fix", event: "push" }), "source");
  assert.equal(mode({ ref: "refs/heads/main", event: "push" }), "source");
  assert.equal(mode({ ref: "refs/heads/main", event: "schedule" }), "strict");
  assert.equal(mode({ ref: "refs/heads/codex/rotation-fix", event: "workflow_dispatch" }), "strict");
  assert.equal(mode({ ref: "refs/heads/release-candidate/v1", event: "push" }), "strict");

  const packageJson = JSON.parse(read("package.json"));
  assert.match(packageJson.scripts["verify:guardrails"], /check:rotation-evidence-freshness/);
  assert.match(packageJson.scripts["verify:guardrails:source"], /check:rotation-evidence-contract/);
  assert.doesNotMatch(packageJson.scripts["verify:guardrails:source"], /check:rotation-evidence-freshness/);
});

test("release gate keeps normal strictness and admits only governed transition modes", () => {
  const lifecycleStep = releaseGate.indexOf("- name: Validate production release lifecycle mode");
  const deployJob = releaseGate.indexOf("  deploy-production-ecs:");
  const upstreamSanity = releaseGate.indexOf("node scripts/github/check-required-workflow-gates.mjs");
  assert.ok(lifecycleStep > upstreamSanity, "lifecycle validation must follow upstream gate sanity");
  assert.ok(lifecycleStep < deployJob, "lifecycle validation must precede the deploy job");
  assert.match(releaseGate.slice(lifecycleStep, deployJob), /normal\)[\s\S]*npm run check:rotation-evidence-freshness/);
  assert.match(releaseGate.slice(lifecycleStep, deployJob), /security:check-production-rotation-transition/);
  assert.doesNotMatch(releaseGate.slice(lifecycleStep, deployJob), /continue-on-error/);
  assert.match(releaseGate, /release_mode:[\s\S]*rotation-overlap[\s\S]*rotation-cleanup/);
  assert.match(releaseGate, /default: normal/);
  assert.doesNotMatch(releaseGate, /expert_override/);
  assert.doesNotMatch(releaseTrain, /expert_override/);
  assert.match(releaseGate, /TARGET_EVENTS: \$\{\{ inputs\.release_mode == 'normal' && 'push,workflow_dispatch' \|\| 'push' \}\}/);
  assert.match(releaseGate, /inputs\.release_mode == 'rotation-overlap' \|\| inputs\.release_mode == 'rotation-cleanup'[\s\S]*run-production-cutover\.mjs/);
  assert.match(releaseGate, /ENABLE_EXECUTE_COMMAND: "true"/);
  assert.match(releaseGate, /inputs\.release_mode == 'normal'[\s\S]*Publish immutable ECS images/);
  assert.match(releaseGate, /deploy-production-ecs:[\s\S]*needs: resolve-deploy-target/);
  const packageJson = JSON.parse(read("package.json"));
  assert.match(packageJson.scripts["check:rotation-evidence-freshness"], /check-rotation-evidence-freshness/);
  assert.match(packageJson.scripts["security:check-production-rotation-transition"], /check-production-rotation-transition/);
});

test("rotation transitions use the reviewed candidate family while normal releases keep the backend family", () => {
  const normalFamily = "mscqr-backend";
  const rotationFamily = "mscqr-production-rls-green-backend-candidate";
  assert.ok(releaseGate.includes(`BACKEND_TASK_DEFINITION: ${normalFamily}`));
  assert.ok(releaseGate.includes(`ROTATION_BACKEND_TASK_DEFINITION_FAMILY: ${rotationFamily}`));
  assert.ok(releaseGate.includes("EXPECTED_FAMILY: ${{ env.ROTATION_BACKEND_TASK_DEFINITION_FAMILY }}"));
  assert.ok(releaseGate.includes("--task-definition \"$EXISTING_TASK_DEFINITION_ARN\""));
  assert.doesNotMatch(releaseGate.slice(releaseGate.indexOf("- name: Deploy rotation transition backend ECS service")), /EXPECTED_FAMILY: \$\{\{ env\.BACKEND_TASK_DEFINITION \}\}/);
});

const sourceSha = "a".repeat(40);
const deploymentSha = "b".repeat(40);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
const expectedCurrentTaskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const imageDigest = `sha256:${"c".repeat(64)}`;
const makeState = (phase, extra = {}) => ({
  stateVersion: 3,
  rotationId: "rotation-gate-test",
  sourceSha,
  phase,
  overlapDeploymentSha: deploymentSha,
  preparedAt: "2026-08-11T00:00:00.000Z",
  overlapPreparedAt: "2026-08-11T00:01:00.000Z",
  jwt: { oldFingerprint: "1".repeat(16), newFingerprint: "2".repeat(16) },
  qr: { oldPublicFingerprint: "3".repeat(16), newPublicFingerprint: "4".repeat(16) },
  pending: { jwtVersionId: "jwt-version-1", qrPrivateVersionId: "qr-private-1", qrPublicVersionId: "qr-public-1" },
  ...extra,
});
const transitionArgs = (mode, state, overrides = {}) => {
  const rawState = JSON.stringify(state);
  return {
    mode,
    state,
    rawState,
    sourceSha,
    rotationId: "rotation-gate-test",
    deploymentSha,
    taskDefinitionArn,
    expectedCurrentTaskDefinitionArn,
    imageDigest,
    stateSha256: createHash("sha256").update(rawState).digest("hex"),
    now: Date.parse("2026-08-11T02:00:00.000Z"),
    ...overrides,
  };
};

test("rotation overlap and cleanup transitions validate state without final freshness", async () => {
  const overlapState = makeState("overlap-deploy-required");
  assert.equal(validateRotationTransition(transitionArgs("rotation-overlap", overlapState)).phase, "overlap-deploy-required");

  const cleanupState = makeState("cleanup-deploy-required", {
    cleanupDeploymentSha: deploymentSha,
    cleanupEligibleAt: "2026-08-11T01:00:00.000Z",
    retirementTimestamp: "2026-08-11T01:10:00.000Z",
    verifiedAt: "2026-08-11T00:30:00.000Z",
    overlapRuntime: { phase: "overlap", deploymentSha: deploymentSha },
  });
  assert.equal(validateRotationTransition(transitionArgs("rotation-cleanup", cleanupState)).phase, "cleanup-deploy-required");
});

test("rotation transition validator fails closed for missing, foreign, premature, or closed state", async () => {
  const overlapState = makeState("overlap-deploy-required");
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-bypass", overlapState)), /unsupported rotation release mode/);
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-overlap", makeState("overlap-deploy-required", { jwtCurrentToken: "redacted" }))), /metadata only/);
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-overlap", makeState("prepared"))), /overlap-deploy-required/);
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-overlap", overlapState, { sourceSha: "d".repeat(40) })), /source SHA/);
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-overlap", overlapState, { rotationId: "foreign-rotation" })), /rotationId/);
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-overlap", makeState("cleaned"))), /overlap-deploy-required/);
  const beforeGrace = makeState("cleanup-deploy-required", { cleanupDeploymentSha: deploymentSha, cleanupEligibleAt: "2026-08-11T03:00:00.000Z", retirementTimestamp: "2026-08-11T01:10:00.000Z", verifiedAt: "2026-08-11T00:30:00.000Z", overlapRuntime: {} });
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-cleanup", beforeGrace)), /grace window/);
  const retirementIncomplete = makeState("retirement-complete", { cleanupDeploymentSha: deploymentSha, cleanupEligibleAt: "2026-08-11T01:00:00.000Z", retirementTimestamp: "2026-08-11T01:10:00.000Z", verifiedAt: "2026-08-11T00:30:00.000Z", overlapRuntime: {} });
  assert.throws(() => validateRotationTransition(transitionArgs("rotation-cleanup", retirementIncomplete)), /cleanup-deploy-required/);
});

test("runbook uses only the coordinator's supported runtime proof flags", () => {
  assert.match(runbook, /--runtime-verification-file \/secure\/operator\/overlap-runtime\.json/);
  assert.doesNotMatch(runbook, /--verification-out/);
  for (const flag of ["--prepare", "--verify", "--config", "--state-file", "--fixture-file", "--runtime-verification-file"]) {
    assert.match(runbook, new RegExp(flag.replaceAll("-", "\\-")), `runbook is missing ${flag}`);
  }
  assert.match(coordinator, /runtime-verification-file/);
  assert.match(coordinator, /cleanup-deployment-sha/);
  assert.match(coordinator, /cleanup-runtime-file/);
  for (const env of ["ROTATION_RUNTIME_PHASE", "ROTATION_ID", "ROTATION_DEPLOYMENT_SHA", "ROTATION_RUNTIME_INVOCATION_REF"]) assert.match(runbook, new RegExp(env));
  for (const mode of ["rotation-overlap", "rotation-cleanup"]) assert.match(runbook, new RegExp(`release_mode=${mode}`));
  assert.match(runbook, /gh workflow run release-gate\.yml/);
  assert.doesNotMatch(runbook, /# Deploy\/restart[\s\S]*scripts\/aws\/deploy-ecs-service\.sh/);
});
