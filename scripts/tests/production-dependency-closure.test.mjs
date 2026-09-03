import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { CAPABILITY_GRAPH_PATH, discoverAwsCliActions } from "../aws/generate-production-green-stage-b-capability-graph.mjs";
import { assertChangedAwsCallClosure, assertNoUnknownRollbackDependency, assertRollbackSemanticBoundary, buildProductionDependencyClosure } from "../aws/verify-production-dependency-closure.mjs";

const graph = () => JSON.parse(fs.readFileSync(CAPABILITY_GRAPH_PATH, "utf8"));

test("complete production dependency closure is exact across modes and failure paths", () => {
  const report = buildProductionDependencyClosure();
  assert.equal(report.status, "PASS");
  const stageAAdditions = report.newAwsCalls.filter(({ sourceFile, capabilityId }) => sourceFile.includes("stage-a-production-artifacts") || capabilityId === "stage-a-artifacts-recovery-root-sign" || capabilityId?.startsWith("stage-a-artifacts-recovery-release-lock-") || capabilityId?.startsWith("stage-a-artifacts-reconciliation-terraform-")).map(({ sourceFile, action, capabilityId }) => [sourceFile, action, capabilityId]);
  assert.deepEqual(stageAAdditions, [
    ["scripts/aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-reconciliation-release-identify"],
    ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:GetObject", "stage-a-artifacts-journal-read"],
    ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:PutObject", "stage-a-artifacts-journal-conditional-create"],
    ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:GetObject", "stage-a-artifacts-recovery-root-journal-read"],
    ["scripts/aws/production-stage-a-production-artifacts-journal.mjs", "s3:PutObject", "stage-a-artifacts-recovery-root-journal-conditional-create"],
    ["scripts/aws/production-root-attestation-signer.mjs", "kms:Sign", "stage-a-artifacts-recovery-root-sign"],
    ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetBucketPolicy", "stage-a-artifacts-reconciliation-release-read-policy"],
    ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-reconciliation-release-identify"],
    ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetBucketLocation", "stage-a-artifacts-reconciliation-terraform-read-bucket-location"],
    ["scripts/aws/production-stage-a-control-plane.mjs", "s3:GetObject", "stage-a-artifacts-reconciliation-terraform-read-state"],
    ["scripts/aws/production-stage-a-control-plane.mjs", "s3:PutObject", "stage-a-artifacts-reconciliation-terraform-write-state"],
    ["scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "s3:GetObject", "stage-a-artifacts-reconciliation-terraform-read-lock"],
    ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketLifecycleConfiguration", "stage-a-artifacts-recovery-root-read-lifecycle"],
    ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketPolicy", "stage-a-artifacts-recovery-release-read-policy"],
    ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:GetBucketVersioning", "stage-a-artifacts-recovery-root-read-versioning"],
    ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "s3:PutBucketPolicy", "stage-a-artifacts-recovery-root-put-policy"],
    ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "sts:GetCallerIdentity", "stage-a-artifacts-recovery-root-identify"],
    ["scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs", "s3:PutObject", "stage-a-artifacts-recovery-release-lock-acquire"],
    ["scripts/aws/production-stage-a-root-drop-orphan-recovery.mjs", "s3:DeleteObject", "stage-a-artifacts-recovery-release-lock-release"],
  ]);
  assert.equal(report.newAwsCalls.length, 42 + stageAAdditions.length); // 42 reviewed baseline calls plus the exact Stage-A recovery graph above
  assert.deepEqual(report.newAwsCalls.filter(({ capabilityId }) => capabilityId?.startsWith("stage-a-artifacts-recovery-release-lock-")).map(({ action, resources, identity }) => [action, resources, identity]), [
    ["s3:PutObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate.tflock"], "RELEASE_DEPLOYER"],
    ["s3:DeleteObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate.tflock"], "RELEASE_DEPLOYER"],
  ]);
  assert.deepEqual(report.newAwsCalls.filter(({ capabilityId }) => capabilityId?.startsWith("stage-a-artifacts-recovery-release-lock-")).map(({ reachableMode }) => reachableMode), [
    ["STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY", "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"],
    ["STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY", "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"],
  ]);
  const reconciliationBackend = report.newAwsCalls.filter(({ capabilityId }) => capabilityId?.startsWith("stage-a-artifacts-reconciliation-terraform-"));
  assert.deepEqual(reconciliationBackend.map(({ action, resources, identity, reachableMode }) => [action, resources, identity, reachableMode]), [
    ["s3:GetBucketLocation", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2"], "RELEASE_DEPLOYER", ["STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"]],
    ["s3:GetObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate"], "RELEASE_DEPLOYER", ["STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"]],
    ["s3:PutObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate"], "RELEASE_DEPLOYER", ["STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"]],
    ["s3:GetObject", ["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate.tflock"], "RELEASE_DEPLOYER", ["STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"]],
  ]);
  assert.equal(graph().capabilities.find(({ id }) => id === "stage-a-artifacts-reconciliation-terraform-write-state")?.mutation, true);
  const stageAStateReads = graph().capabilities.filter(({ action, resources }) => action === "s3:GetObject" && resources.includes("arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate"));
  assert.deepEqual(stageAStateReads.map(({ id, phase }) => [id, phase]), [
    ["manifest-collect-stage-a-prerequisite-state", "release-direct-read-preflight"],
    ["stage-a-artifacts-reconciliation-terraform-read-state", "stage-a-production-artifacts-state-reconciliation"],
  ]);
  const reconciliationMode = report.newAwsCalls.filter(({ reachableMode }) => reachableMode.includes("STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION"));
  const backendResources = new Set(["arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2", "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate", "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate.tflock"]);
  assert.equal(reconciliationMode.filter(({ resources }) => resources.some((resource) => backendResources.has(resource))).length, 6);
  assert.equal(reconciliationMode.some(({ action }) => action === "s3:ListBucket"), false);
  assert.equal(graph().capabilities.some(({ id }) => /^stage-a-artifacts-reconciliation-terraform-(?:acquire|release)-lock$/.test(id)), false);
  const controlPlaneSource = fs.readFileSync("scripts/aws/production-stage-a-control-plane.mjs", "utf8");
  assert.match(controlPlaneSource, /"plan", "-refresh-only", "-input=false", "-lock=true"/);
  assert.match(controlPlaneSource, /backendLockHeld \? \["-lock=false"\] : \[\]/);
  assert.deepEqual(report.newAwsCalls.filter(({ sourceFile }) => sourceFile.endsWith("production-stage-a-production-artifacts-journal.mjs")).map(({ action, capabilityId, identity }) => [action, capabilityId, identity]), [
    ["s3:GetObject", "stage-a-artifacts-journal-read", "RELEASE_DEPLOYER"],
    ["s3:PutObject", "stage-a-artifacts-journal-conditional-create", "RELEASE_DEPLOYER"],
    ["s3:GetObject", "stage-a-artifacts-recovery-root-journal-read", "ROOT_OPERATOR"],
    ["s3:PutObject", "stage-a-artifacts-recovery-root-journal-conditional-create", "ROOT_OPERATOR"],
  ]);
  assert.deepEqual(new Set(Object.values(report.modes)), new Set(["PASS"]));
  assert.deepEqual(new Set(Object.keys(report.runtimeModeClosure)), new Set(Object.keys(report.modes)));
  for (const { capabilityId, reachableMode } of report.newAwsCalls) for (const mode of reachableMode) assert.notEqual(report.modes[mode], undefined, `${capabilityId} is reachable from undeclared ${mode}`);
  assert.equal(report.runtimeDependencies.some(({ id }) => id === "ecs-final-candidate-runtime-consumability"), true);
  assert.deepEqual(new Set(Object.keys(report.runtimeModeClosure)), new Set(["NORMAL", "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME", "STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY", "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", "ROTATION_OVERLAP", "ROTATION_CLEANUP", "ROLLBACK_RECONCILIATION", "POST_DEPLOY_VERIFY"]));
  assert.equal(report.newAwsCalls.filter(({ capabilityId, reachableMode }) => capabilityId?.startsWith("stage-a-artifacts-recovery-") && !reachableMode.includes("STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY")).length, 0);
  assert.equal(report.newAwsCalls.filter(({ capabilityId, reachableMode }) => (capabilityId?.startsWith("stage-a-artifacts-journal-") || capabilityId?.startsWith("stage-a-artifacts-reconciliation-")) && !reachableMode.includes("STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION")).length, 0);
  const rootVerifierModes = report.newAwsCalls.filter(({ capabilityId }) => ["release-root-attestation-verify", "release-root-attestation-describe-key", "release-root-attestation-read-key-policy", "release-root-attestation-read-key-tags"].includes(capabilityId));
  assert.equal(rootVerifierModes.length, 4);
  for (const { reachableMode } of rootVerifierModes) assert.deepEqual(reachableMode, ["STAGE_A_PRODUCTION_ARTIFACTS_POLICY_RECOVERY", "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME"]);
  for (const sourceFile of ["scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs", "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs", "scripts/aws/authorize-production-stage-a-production-artifacts-reconciliation.mjs"]) assert.match(fs.readFileSync(sourceFile, "utf8"), /createRootAttestationKmsVerifier/);
  assert.deepEqual(report.newAwsCalls.find(({ capabilityId }) => capabilityId === "manifest-backend-health-recovery-describe-images")?.reachableMode, ["BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME"]);
  assert.deepEqual(report.pathClosure, { forward: "PASS", rollback: "PASS", reconciliation: "PASS" });
  assert.deepEqual(new Set(Object.values(report.counters)), new Set([0]));
});

test("unknown AWS calls and incomplete exact call classifications fail CI", () => {
  const calls = discoverAwsCliActions();
  const current = graph();
  assert.throws(() => assertChangedAwsCallClosure([...calls, { sourceFile: "scripts/aws/production-ecs-rollback-viability.mjs", action: "ecs:DeleteService" }], current), /Unknown production AWS call/);
  assert.throws(() => assertChangedAwsCallClosure(calls.filter(({ sourceFile, action }) => !(sourceFile.endsWith("production-ecs-rollback-viability.mjs") && action === "ecs:DescribeServiceRevisions")), current), /Changed production AWS calls/);
  for (const change of [
    (capability) => { capability.identity = "ADMINISTRATOR"; },
    (capability) => { capability.resources = ["*"]; },
    (capability) => { capability.probeIds = []; },
  ]) {
    const changed = structuredClone(current);
    change(changed.capabilities.find(({ id }) => id === "manifest-backend-health-recovery-describe-service-revisions"));
    assert.throws(() => assertChangedAwsCallClosure(calls, changed), /lacks exact IAM\/capability\/preflight closure/);
  }
});

test("documented ECS response shape is represented by the real service-revision boundary", () => {
  const source = fs.readFileSync("scripts/aws/production-ecs-rollback-viability.mjs", "utf8");
  assert.match(source, /targetServiceRevision\?\.arn/);
  assert.match(source, /rollback\?\.serviceRevisionArn/);
  assert.match(source, /sourceServiceRevisions/);
  assert.match(source, /describe-service-revisions/);
  assert.match(source, /serviceRevisions/);
  assert.match(source, /revision\?\.taskDefinition/);
  assert.doesNotMatch(source, /targetServiceRevision\?\.taskDefinition/);
  assert.equal(assertRollbackSemanticBoundary(source), true);
  assert.throws(() => assertRollbackSemanticBoundary(source.replaceAll("deployment?.rollback?.serviceRevisionArn", "deployment?.targetServiceRevision?.arn")), /semantic boundary|never derive/);
  assert.throws(() => assertRollbackSemanticBoundary(source.replace("attempt.startedBy === rollbackEcsServiceDeploymentId", "true")), /semantic boundary/);
  assert.throws(() => assertRollbackSemanticBoundary(`${source}\nconst failures = []; failures.length >= 2;`), /current deployment identity/);
});

test("unknown runtime dependencies fail CI", () => {
  const source = fs.readFileSync("scripts/aws/production-ecs-rollback-viability.mjs", "utf8");
  assert.equal(assertNoUnknownRollbackDependency(source), true);
  assert.throws(() => assertNoUnknownRollbackDependency(`${source}\nconst endpoint = process.env.ARBITRARY_ENDPOINT;`), /unclassified environment dependency/);
  assert.throws(() => assertNoUnknownRollbackDependency(`${source}\nimport client from "imagined-aws-client";`), /undeclared external Node dependency/);
});

test("rotation closure cannot borrow legacy backend recovery mutation authority", () => {
  const source = fs.readFileSync("scripts/aws/verify-production-dependency-closure.mjs", "utf8");
  for (const mode of ["ROTATION_OVERLAP", "ROTATION_CLEANUP"]) {
    const capabilityList = source.match(new RegExp(`${mode}: \\[([^\\n]+)\\]`))?.[1] || "";
    assert.match(capabilityList, /manifest-activate-exact-ecs-service/);
    assert.match(capabilityList, /manifest-rollback-exact-ecs-service/);
    assert.doesNotMatch(capabilityList, /manifest-backend-health-recovery-update-service/);
  }
});
