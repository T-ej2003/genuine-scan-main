import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("rotation-overlap has one governed production entrypoint", () => {
  const workflow = readFileSync(".github/workflows/release-gate.yml", "utf8");
  const deploy = readFileSync("scripts/aws/deploy-ecs-service.sh", "utf8");
  const orchestrator = readFileSync("scripts/aws/production-cutover-control-plane.mjs", "utf8");
  assert.match(workflow, /run-production-cutover\.mjs[\s\S]*--mode rotation-overlap/);
  assert.match(workflow, /run-production-cutover\.mjs[\s\S]*--mode rotation-overlap[\s\S]*--transition-mode "\$\{\{ inputs\.release_mode \}\}"/);
  const overlapBlock = workflow.slice(workflow.indexOf("Deploy rotation transition backend ECS service"), workflow.indexOf("Verify backend health"));
  assert.doesNotMatch(overlapBlock, /deploy-ecs-service\.sh/);
  assert.match(deploy, /must be invoked by run-production-cutover\.mjs/);
  for (const required of ["runStageAControlPlane", "verifyArtifactSigningDomain", "registerOverlapTaskDefinition", "produceRuntimeRotationInventory", "buildOverlapReadinessEvidence", "runGovernedOverlapDeployment", "runProductionCutoverOverlapControlPlane", "produceOnboardingEvidence"]) assert.match(orchestrator, new RegExp(required));
  assert.match(readFileSync("scripts/aws/run-production-cutover.mjs", "utf8"), /runProductionCutoverOverlapControlPlane/);
  assert.doesNotMatch(readFileSync("scripts/aws/run-production-cutover.mjs", "utf8"), /runGovernedOverlapDeployment/);
  assert.match(workflow, /rotation_fixture_sha256/);
  assert.match(workflow, /Upload overlap deployment receipt/);
  assert.match(workflow, /production-overlap-deployment-receipt/);
  const verifier = readFileSync("scripts/aws/verify-production-cutover-overlap.mjs", "utf8");
  assert.match(verifier, /runPostOverlapVerification/);
  assert.doesNotMatch(verifier, /runGovernedOverlapDeployment|update-service|register-task-definition/);
});

test("prepare-overlap uses the shared control plane and cannot fall through to overlap deployment", () => {
  const cli = readFileSync("scripts/aws/run-production-cutover.mjs", "utf8");
  const controlPlane = readFileSync("scripts/aws/production-cutover-control-plane.mjs", "utf8");
  assert.match(cli, /"prepare-overlap"/);
  assert.match(cli, /PRODUCTION_CUTOVER_MODE\.PREPARE_OVERLAP/);
  assert.match(controlPlane, /mode === PRODUCTION_CUTOVER_MODE\.PREPARE_OVERLAP/);
  assert.ok(controlPlane.indexOf("mode === PRODUCTION_CUTOVER_MODE.PREPARE_OVERLAP") < controlPlane.indexOf("runGovernedOverlapDeployment({ readiness: readinessEvidence"));
  assert.match(cli, /preparedForOverlapAuthorization: true/);
  assert.match(cli, /ecsUpdateServiceCount: 0/);
  assert.doesNotMatch(cli.slice(cli.indexOf('mode === "prepare-overlap"'), cli.indexOf(': { readyForOnboarding')), /runProductionCutoverOverlapControlPlane/);
});

test("runtime inventory and ECS Exec are bounded by shared production target logic", () => {
  const inventory = readFileSync("scripts/aws/production-runtime-inventory-adapter.mjs", "utf8");
  const verifier = readFileSync("scripts/aws/verify-production-rotation-via-ecs-exec.mjs", "utf8");
  assert.doesNotMatch(inventory, /process\.env\.DATABASE_URL|--command.*process\.env/);
  assert.match(inventory, /DescribeTasks|describeTasks/);
  assert.match(inventory, /includeTags: true/);
  assert.match(verifier, /selectAndRevalidateExactTarget/);
  assert.match(verifier, /--include.*TAGS/);
});

test("strict onboarding cannot delegate acceptance to optional smoke skips", () => {
  const strict = readFileSync("scripts/security/production-strict-onboarding.mjs", "utf8");
  assert.match(strict, /Mandatory onboarding probe is unavailable/);
  assert.match(strict, /Mandatory onboarding check failed/);
  assert.match(strict, /assertNoOnboardingEvidenceLeak/);
  assert.doesNotMatch(strict, /SKIP|ALLOW_STAGING_SMOKE_DEGRADED_ON_PR/);
});
