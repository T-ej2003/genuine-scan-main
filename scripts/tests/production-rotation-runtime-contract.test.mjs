import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

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

test("coordinator exposes explicit resumable phases and no implicit cleanup", () => {
  for (const mode of ["--prepare", "--verify", "--cleanup", "--status"]) assert.match(coordinator, new RegExp(mode.slice(2)));
  assert.match(coordinator, /exactly one of --prepare, --verify, --cleanup, or --status/);
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

test("release gate independently enforces strict freshness before deployment", () => {
  const strictStep = releaseGate.indexOf("- name: Strict production rotation freshness");
  const deployJob = releaseGate.indexOf("  deploy-production-ecs:");
  const upstreamSanity = releaseGate.indexOf("node scripts/github/check-required-workflow-gates.mjs");
  assert.ok(strictStep > upstreamSanity, "strict freshness must follow upstream gate sanity");
  assert.ok(strictStep < deployJob, "strict freshness must precede the deploy job");
  assert.match(releaseGate.slice(strictStep, deployJob), /npm run check:rotation-evidence-freshness/);
  assert.doesNotMatch(releaseGate.slice(strictStep, deployJob), /continue-on-error|if:/);
  assert.match(releaseGate, /TARGET_EVENTS: push,workflow_dispatch/);
  assert.match(releaseGate, /deploy-production-ecs:[\s\S]*needs: resolve-deploy-target/);
  assert.match(JSON.parse(read("package.json")).scripts["check:rotation-evidence-freshness"], /check-rotation-evidence-freshness/);
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
});
