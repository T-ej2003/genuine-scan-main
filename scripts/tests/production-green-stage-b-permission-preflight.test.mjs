import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertApplyArtifacts, assertPermissionReport, parseCli as parseApplyCli, reserveStageBSharedApplyAttempt, runApply, showSavedPlan, stageBApplyArtifactSetIdentity, stageBApplyAttemptPath, stageBEffectiveOperatorHome } from "../apply-production-green-stage-b.mjs";
import { stageBApplyAttemptS3Key, stageBAttemptStepS3ObjectKey } from "../aws/stage-b-terraform-backend-contract.mjs";
import { buildRootAttestationKeyPolicy, ROOT_ATTESTATION_KEY_DESCRIPTION, ROOT_ATTESTATION_TAGS } from "../aws/production-root-attestation-key.mjs";
import { writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";
import {
  canonicalizeJson,
  assertPermissionReportPlanBinding,
  assertPermissionEvaluationBindings,
  assertTaskDefinitionRegistrationContexts,
  createStageBMutationManifest,
  deriveRequiredEvaluations,
  resolveStageBPermissionProfile,
  PERMISSION_REPORT_SIGNING_ALGORITHM,
  PERMISSION_REPORT_SIGNING_KEY_ARN,
  PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION,
  PERMISSION_REPORT_HASH_DOMAIN,
  PERMISSION_REPORT_BINDING_DOMAIN,
  PERMISSION_REPORT_BINDING_SCHEMA_VERSION,
  buildPermissionReportBinding,
  signedPermissionReportBindingSha256,
  serializePermissionReport,
  assertPermissionReportHashDomains,
  verifyPermissionReportSignature,
  PERMISSION_EVIDENCE_MAX_AGE_MS,
  sourcePolicyEvidence,
  sourcePolicyConditionKeyOrigins,
  REVIEWED_SIMULATION_CONTEXT_REGISTRY,
  assertReviewedSimulationContextRegistry,
  assertDiscoveredSimulationContextKeys,
  assertReleasePolicyEvidence,
  runCli,
  runPermissionPreflight as runPermissionPreflightRaw,
  signPermissionReport,
  simulatePrincipalPolicy,
  assertSimulationContextCardinality,
  validateSimulationResult,
  validateManifest,
} from "../aws/validate-production-green-stage-b-permissions.mjs";
import simulatorAllowed from "./fixtures/aws-iam-simulate-principal-policy-allowed.mjs";
import { assertStageBReleaseCallerArn } from "../plan-production-green-stage-b.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_BROKER_POLICY } from "../aws/stage-b-deployment-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES, STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS } from "../aws/stage-b-reference-audit-contract.mjs";
import { buildStageBProtectedMainCheckoutEvidence } from "../aws/stage-b-deployment-identity.mjs";
import { inspectStageBRefreshChecks, STAGE_B_EXPECTED_CHECK_ADDRESSES, STAGE_B_EXPECTED_RESOURCE_PRECONDITION_ADDRESSES, STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES } from "../aws/stage-b-refresh-contract.mjs";
import { generateImageEvidence, imageEvidenceSha256, signImageEvidence, IMAGE_EVIDENCE_MAX_AGE_MS } from "../aws/production-green-stage-b-image-evidence.mjs";
import { packageStageBBroker } from "../aws/package-production-green-stage-b-broker.mjs";
import { createStageBPlanApprovalReport, createStageBPlanCaptureReport } from "../aws/stage-b-plan-approval-contract.mjs";
import { buildStageBImagePublicationIdentity } from "../aws/stage-b-image-publication-identity.mjs";
import { buildEcsExecOperatorEvidence } from "../aws/production-ecs-exec-operator-contract.mjs";
import { deriveContractDigests, generateStageBTfvars } from "../aws/generate-production-green-stage-b-tfvars.mjs";
import { STAGE_A_STATE_IDENTITY_VERSION, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";

const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
const realForbiddenSimulations = JSON.parse(fs.readFileSync("scripts/tests/fixtures/aws-iam-simulate-principal-policy-stage-b-forbidden.json", "utf8"));
const initializedBackendMetadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8")).backend;
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const brokerPolicyArn = "arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime";
const brokerRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker";
const generatorArn = "arn:aws:iam::368992683803:root";
const policyEvidence = (() => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn, attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
})();
const runPermissionPreflight = (input) => {
  if (!input.savedPlanBytes) return runPermissionPreflightRaw({ policyEvidence, ecsExecVerifierEvidence: buildEcsExecOperatorEvidence(), ...input });
  if (input.planApprovalReport) return runPermissionPreflightRaw({ policyEvidence, ecsExecVerifierEvidence: buildEcsExecOperatorEvidence(), ...input });
  const selectedPlan = JSON.parse(input.planBytes);
  const planBound = input.planBound === true || selectedPlan.resource_changes.length >= 70;
  const savedPlanSha256 = crypto.createHash("sha256").update(input.savedPlanBytes).digest("hex");
  const planJsonSha256 = crypto.createHash("sha256").update(input.planBytes).digest("hex");
  const canonicalPlanJsonBytes = Buffer.from(`${canonicalizeJson(selectedPlan)}\n`);
  const hashes = { savedPlanSha256, planJsonSha256, canonicalPlanFileSha256: crypto.createHash("sha256").update(canonicalPlanJsonBytes).digest("hex"), logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(selectedPlan))).digest("hex") };
  const referenceAudit = planBound ? (() => {
    const retainedTaskDefinitions = selectedPlan.resource_changes.filter((change) => change.address?.includes("_retained[")).map((change, index) => {
      const key = change.address.match(/\[\"[a-f0-9]+-([^\"]+)\"\]$/)?.[1];
      const family = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).find(([address]) => address.match(/\[\"([^\"]+)\"\]$/)?.[1] === key)?.[1];
      return { terraformAddress: change.address, family, classification: "retained-no-op", oldTaskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 1}` };
    });
    const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, planJsonSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", auditedAt: input.now || new Date().toISOString(), retainedTaskDefinitions })}\n`);
    return { report: JSON.parse(bytes), bytes, sha256: crypto.createHash("sha256").update(bytes).digest("hex") };
  })() : undefined;
  const capture = createStageBPlanCaptureReport({ toolingSha: input.plan.variables.tooling_sha.value, toolingTreeSha256: "e".repeat(64), refreshReportSha256: "r".repeat(64), hashes, capturedAt: input.now || new Date().toISOString(), stageBLineage: "lineage", stageBSerial: 76, terraformVersion: "1.15.7", terraformFormatVersion: "1.2", classification: { noOp: selectedPlan.resource_changes.filter((change) => JSON.stringify(change.change?.actions) === JSON.stringify(["no-op"])).length, create: 12, update: 3, destroy: 0, replacement: 0, unclassified: 0 } });
  const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  const approval = createStageBPlanApprovalReport({ captureReportSha256: crypto.createHash("sha256").update(captureBytes).digest("hex"), referenceAuditPath: "/private/tmp/test-audit.json", referenceAuditSha256: referenceAudit?.sha256 || "a".repeat(64), referenceAuditCallerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", referenceAuditAt: input.now || new Date().toISOString(), toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: input.now || new Date().toISOString(), classification: capture.classification });
  let approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  return runPermissionPreflightRaw({ policyEvidence, ecsExecVerifierEvidence: buildEcsExecOperatorEvidence(), ...input, phase: input.phase || (planBound ? "plan-bound" : "initial"), canonicalPlanJsonBytes, planApprovalReport: approval, planApprovalReportBytes: approvalBytes, planApprovalReportSha256: crypto.createHash("sha256").update(approvalBytes).digest("hex"), referenceAudit: referenceAudit?.report, referenceAuditBytes: referenceAudit?.bytes });
};

function cliApprovalArgs(directory, selectedPlan = plan, selectedPlanBytes = planBytes, selectedSavedBytes = savedPlanBytes) {
  const canonicalBytes = Buffer.from(`${canonicalizeJson(selectedPlan)}\n`);
  const hashes = {
    savedPlanSha256: crypto.createHash("sha256").update(selectedSavedBytes).digest("hex"),
    planJsonSha256: crypto.createHash("sha256").update(selectedPlanBytes).digest("hex"),
    canonicalPlanFileSha256: crypto.createHash("sha256").update(canonicalBytes).digest("hex"),
    logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(selectedPlan))).digest("hex"),
  };
  const auditPath = path.join(directory, "approved.audit.json");
  const retainedTaskDefinitions = selectedPlan.resource_changes.filter((change) => change.address?.includes("_retained[")).map((change, index) => {
    const key = change.address.match(/\[\"[a-f0-9]+-([^\"]+)\"\]$/)?.[1];
    const family = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).find(([address]) => address.match(/\[\"([^\"]+)\"\]$/)?.[1] === key)?.[1];
    return { terraformAddress: change.address, family, classification: "retained-no-op", oldTaskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 1}` };
  });
  const audit = selectedPlan.variables?.stage_b_recovery_only?.value === true ? undefined : { schemaVersion: 1, planJsonSha256: hashes.planJsonSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", auditedAt: now, retainedTaskDefinitions };
  if (audit) writePrivate(auditPath, `${JSON.stringify(audit)}\n`);
  const capture = createStageBPlanCaptureReport({ toolingSha: selectedPlan.variables.tooling_sha.value, toolingTreeSha256: "e".repeat(64), refreshReportSha256: "r".repeat(64), hashes, capturedAt: now, stageBLineage: "lineage", stageBSerial: 76, terraformVersion: "1.15.7", terraformFormatVersion: "1.2", classification: { noOp: selectedPlan.resource_changes.filter((change) => JSON.stringify(change.change?.actions) === JSON.stringify(["no-op"])).length, create: 12, update: 3, destroy: 0, replacement: 0, unclassified: 0 } });
  const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  const auditBytes = audit ? fs.readFileSync(auditPath) : undefined;
  const approval = createStageBPlanApprovalReport({ captureReportSha256: crypto.createHash("sha256").update(captureBytes).digest("hex"), referenceAuditPath: auditPath, referenceAuditSha256: audit ? crypto.createHash("sha256").update(auditBytes).digest("hex") : "a".repeat(64), referenceAuditCallerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", referenceAuditAt: now, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: 76, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: now, classification: capture.classification });
  const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  const canonicalPath = path.join(directory, "approved.canonical.json"); const approvalPath = path.join(directory, "approved.plan.approval.json");
  writePrivate(canonicalPath, canonicalBytes); writePrivate(approvalPath, approvalBytes);
  return ["--canonical-plan-json", canonicalPath, "--plan-approval-report", approvalPath, "--plan-approval-report-sha256", crypto.createHash("sha256").update(approvalBytes).digest("hex"), ...(audit ? ["--reference-audit", auditPath] : [])];
}

test("apply wrapper binds terraform show to the Stage B root and supplied discovery environment", () => {
  const env = { HOME: "/reviewed/home", PATH: "/reviewed/bin", TF_DATA_DIR: "/private/tmp/reviewed-tf-data", TF_WORKSPACE: "default", TF_CLI_CONFIG_FILE: "/reviewed/.terraformrc" };
  const planPath = "/private/tmp/reviewed/stage-b.tfplan";
  let invocation;
  const result = showSavedPlan(planPath, {
    env,
    execFile: (command, args, options) => {
      invocation = { command, args, options };
      return Buffer.from("{}");
    },
  });
  assert.deepEqual(result, Buffer.from("{}"));
  assert.deepEqual(invocation, {
    command: "terraform",
    args: ["-chdir=infra/aws/terraform/production-green-stage-b", "show", "-json", planPath],
    options: { cwd: process.cwd(), env, encoding: null, stdio: ["ignore", "pipe", "pipe"] },
  });
});

const brokerFixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-permission-broker-fixture-"));
const brokerFixture = await packageStageBBroker({ outputPath: path.join(brokerFixtureRoot, "broker.zip"), toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), repositoryRoot: process.cwd() });
test.after(() => fs.rmSync(brokerFixtureRoot, { recursive: true, force: true }));
const contextValue = (mapping, key) => mapping.registerContext.find((entry) => entry.key === key).values[0];
const taskDefinitionAfter = (mapping) => ({
  family: mapping.family,
  cpu: contextValue(mapping, "ecs:task-cpu"),
  memory: contextValue(mapping, "ecs:task-memory"),
  requires_compatibilities: [contextValue(mapping, "ecs:compute-compatibility")],
  execution_role_arn: mapping.executionRoleArn,
  task_role_arn: mapping.taskRoleArn,
  tags: mapping.id === "backend" ? { Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform", MSCQRExecTarget: "production-backend" } : { Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform" },
  container_definitions: JSON.stringify([{ name: mapping.id, privileged: false }]),
});

test("permission report identity fields exactly bind the selected plan artifacts", () => {
  const planJsonBytes = fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
  const savedPlanBytes = Buffer.from("selected-saved-plan");
  const report = {
    planSha256: crypto.createHash("sha256").update(planJsonBytes).digest("hex"),
    savedPlanSha256: crypto.createHash("sha256").update(savedPlanBytes).digest("hex"),
    canonicalPlanJsonSha256: crypto.createHash("sha256").update(canonicalizeJson(JSON.parse(planJsonBytes))).digest("hex"),
    manifestSha256: crypto.createHash("sha256").update(canonicalizeJson(manifest)).digest("hex"),
  };
  assert.deepEqual(assertPermissionReportPlanBinding(report, { planJsonBytes, savedPlanBytes, manifest }), report);
  for (const field of Object.keys(report)) assert.throws(() => assertPermissionReportPlanBinding({ ...report, [field]: "0".repeat(64) }, { planJsonBytes, savedPlanBytes, manifest }), new RegExp(field));
});
const plan = {
  variables: {
    account_id: { value: "368992683803" },
    aws_region: { value: "eu-west-2" },
    tooling_sha: { value: "b".repeat(40) },
    image_release_sha: { value: "a".repeat(40) },
    canonical_image_evidence_sha256: { value: "c".repeat(64) },
  },
  resource_changes: [{
    address: 'aws_ecs_task_definition.candidate["read_only_canary"]',
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: taskDefinitionAfter(manifest.taskDefinitionMappings.find(({ id }) => id === "read-only-canary")) },
  }, {
    address: "aws_iam_policy.broker",
    type: "aws_iam_policy",
    change: { actions: ["update"], after: { name: "mscqr-production-rls-approval-broker-runtime" }, after_unknown: { policy: true } },
  }, {
    address: "aws_iam_role_policy_attachment.broker",
    type: "aws_iam_role_policy_attachment",
    change: { actions: ["no-op"], after: { role: "mscqr-production-rls-approval-broker", policy_arn: brokerPolicyArn } },
  }],
};
const planBytes = Buffer.from(JSON.stringify(plan));
const savedPlanBytes = Buffer.from("saved-binary-plan");
const productionPlanBytes = fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
const productionPlan = JSON.parse(productionPlanBytes);
const fixture = productionPlan;
const terraformConfiguration = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");

function freshImageRecoveryRegistrationPlan() {
  const value = structuredClone(productionPlan);
  const current = value.resource_changes.filter((change) => change.type === "aws_ecs_task_definition" && Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, change.address));
  for (const [index, change] of current.entries()) {
    const family = STAGE_B_TASK_DEFINITION_FAMILIES[change.address];
    const after = { ...structuredClone(change.change.after), network_mode: "awsvpc", volume: [], ipc_mode: null, pid_mode: null };
    const afterContainers = JSON.parse(after.container_definitions).map((container) => ({ ...container, image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr@sha256:${"a".repeat(64)}` }));
    after.container_definitions = JSON.stringify(afterContainers);
    const beforeContainers = afterContainers.map((container) => ({ ...container, image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr@sha256:${"b".repeat(64)}` }));
    const beforeArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:5`;
    const before = { ...structuredClone(after), arn: beforeArn, id: beforeArn, container_definitions: JSON.stringify(beforeContainers) };
    change.mode = "managed";
    change.change = { ...change.change, actions: ["create", "delete"], before, after, replace_paths: STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS };
    if (index > 0) value.resource_changes.push({
      address: change.address,
      deposed: `${String(index).padStart(7, "0")}a`,
      mode: "managed",
      type: "aws_ecs_task_definition",
      change: { actions: ["delete"], before: { family, arn: beforeArn, skip_destroy: true }, after: null },
    });
  }
  return value;
}

function importedBackendPlan() {
  const value = structuredClone(fixture);
  const change = value.resource_changes.find((item) => item.address === 'aws_ecs_task_definition.candidate["backend"]');
  const family = STAGE_B_TASK_DEFINITION_FAMILIES[change.address];
  const arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:9`;
  const before = structuredClone(change.change.after);
  const after = structuredClone(before);
  for (const state of [before, after]) {
    state.arn = arn;
    state.arn_without_revision = arn.replace(/:9$/, "");
    state.id = family;
    state.revision = 9;
    state.network_mode = "awsvpc";
    state.runtime_platform = [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }];
    state.volume = [];
  }
  before.skip_destroy = null;
  after.skip_destroy = true;
  change.change = { actions: ["update"], before, after, replace_paths: [], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} };
  return value;
}

test("imported backend normalization derives an explicit zero-AWS permission", () => {
  const imported = importedBackendPlan();
  assert.doesNotThrow(() => assertTaskDefinitionRegistrationContexts(imported, manifest, { terraformConfiguration }));
  const derived = deriveRequiredEvaluations(imported, manifest, { terraformConfiguration });
  assert.deepEqual(derived.zeroAwsMutationChanges, [{ address: 'aws_ecs_task_definition.candidate["backend"]', classification: "imported-backend-task-definition-metadata-normalization", requiredAwsActions: [] }]);
  assert.equal(derived.zeroAwsMutationChanges[0].requiredAwsActions.length, 0);
  assert.equal(derived.required.some((entry) => entry.resource === 'aws_ecs_task_definition.candidate["backend"]' && entry.action === "ecs:RegisterTaskDefinition"), false);
  assert.equal(derived.zeroAwsMutationChanges.some(({ requiredAwsActions }) => requiredAwsActions.includes("ecs:UpdateService")), false);
  const arbitrary = structuredClone(imported);
  arbitrary.resource_changes.find((item) => item.address === 'aws_ecs_task_definition.candidate["backend"]').change.after.cpu = "999";
  assert.throws(() => deriveRequiredEvaluations(arbitrary, manifest, { terraformConfiguration }), /unrelated field change|No permission manifest entry/);
});

test("imported backend normalization requires all other reviewed registration contexts", () => {
  const imported = importedBackendPlan();
  const backendAddress = 'aws_ecs_task_definition.candidate["backend"]';
  const workerAddress = 'aws_ecs_task_definition.candidate["worker"]';
  const missing = structuredClone(imported);
  missing.resource_changes = missing.resource_changes.filter(({ address }) => address !== workerAddress);
  assert.throws(() => assertTaskDefinitionRegistrationContexts(missing, manifest, { terraformConfiguration }), /exactly one reviewed task-definition registration/);

  const arbitrary = structuredClone(imported);
  const backend = arbitrary.resource_changes.find(({ address }) => address === backendAddress);
  backend.change.after.cpu = "999";
  assert.throws(() => assertTaskDefinitionRegistrationContexts(arbitrary, manifest, { terraformConfiguration }), /unrelated field change/);

  const replacement = structuredClone(imported);
  const replacementBackend = replacement.resource_changes.find(({ address }) => address === backendAddress);
  replacementBackend.change.actions = ["create", "delete"];
  replacementBackend.change.replace_paths = [["container_definitions"]];
  assert.throws(() => assertTaskDefinitionRegistrationContexts(replacement, manifest, { terraformConfiguration }), /exactly one reviewed task-definition registration|registration context|root-managed contract/);

  const extra = structuredClone(imported);
  extra.resource_changes.push({ address: "aws_ecs_task_definition.unbound", type: "aws_ecs_task_definition", change: { actions: ["update"], before: {}, after: {} } });
  assert.throws(() => assertTaskDefinitionRegistrationContexts(extra, manifest, { terraformConfiguration }), /unreviewed task-definition change/);
  const extraNoOp = structuredClone(imported);
  extraNoOp.resource_changes.push({ address: "aws_ecs_task_definition.unbound", type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: {}, after: {} } });
  assert.throws(() => assertTaskDefinitionRegistrationContexts(extraNoOp, manifest, { terraformConfiguration }), /unreviewed task-definition change/);
});

test("imported backend mutation manifest exactly binds the real 1/11/4 profile", () => {
  const imported = importedBackendPlan();
  for (const change of imported.resource_changes.filter(({ type, address }) => type === "aws_ecs_task_definition" && Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, address) && address !== 'aws_ecs_task_definition.candidate["backend"]')) {
    const family = STAGE_B_TASK_DEFINITION_FAMILIES[change.address];
    const after = { ...structuredClone(change.change.after), family, network_mode: "awsvpc", runtime_platform: [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }], volume: [], ipc_mode: null, pid_mode: null, container_definitions: JSON.stringify([{ name: "worker", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}`, privileged: false }]) };
    change.mode = "managed";
    change.change = {
      ...change.change,
      actions: ["create", "delete"],
      before: { ...after, arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:5`, id: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:5`, container_definitions: after.container_definitions.replace(`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`) },
      after,
      replace_paths: [["container_definitions"]],
    };
  }
  imported.resource_changes.push({ address: "aws_iam_role_policy.backend_ecs_exec", mode: "managed", type: "aws_iam_role_policy", change: { actions: ["create"], before: null, after: { role: "mscqr-production-rls-green-backend-task", name: "mscqr-production-rls-green-backend-ecs-exec" } } });
  const mutationManifest = createStageBMutationManifest(imported, manifest, {
    planProfile: "IMPORTED_BACKEND_METADATA_NORMALIZATION",
    planSha256: "1".repeat(64), savedPlanSha256: "2".repeat(64), canonicalPlanJsonSha256: "3".repeat(64), planApprovalReportSha256: "4".repeat(64), toolingSha: "5".repeat(40), terraformConfiguration,
  });
  const actionCounts = mutationManifest.resources.reduce((counts, { actions }) => ({ ...counts, [JSON.stringify(actions)]: (counts[JSON.stringify(actions)] || 0) + 1 }), {});
  assert.equal(actionCounts[JSON.stringify(["create"])], 1);
  assert.equal(actionCounts[JSON.stringify(["create", "delete"])], 11);
  assert.equal(actionCounts[JSON.stringify(["update"])], 4);
  const backend = mutationManifest.resources.find(({ address }) => address === 'aws_ecs_task_definition.candidate["backend"]');
  assert.equal(backend.expected_aws_mutation, false);
  assert.deepEqual(backend.required_permissions, []);
  assert.equal(mutationManifest.resources.filter(({ classification }) => classification === "stage-b-task-definition-registration").length, 11);
  assert.ok(/^[a-f0-9]{64}$/.test(mutationManifest.mutationManifestSha256));
  imported.resource_changes.find(({ type, address }) => type === "aws_ecs_task_definition" && address !== 'aws_ecs_task_definition.candidate["backend"]' && Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, address)).change.actions = ["delete", "create"];
  assert.throws(() => createStageBMutationManifest(imported, manifest, { planProfile: "IMPORTED_BACKEND_METADATA_NORMALIZATION", terraformConfiguration }), /exact create-before-delete actions/);
});
const now = "2026-08-01T12:00:00.000Z";
const clearCloudTrail = () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] });
const writePrivate = (filePath, bytes) => fs.writeFileSync(filePath, bytes, { mode: 0o600 });
const allowRequiredDenyForbidden = ({ evaluation }) => ({
  decision: evaluation.forbidden ? evaluation.expectedDecision : "allowed",
  matchedStatements: evaluation.expectedDecision === "explicitDeny" ? 1 : 0,
  missingContextValues: evaluation.expectedMissingContextValues,
});
const reportSignature = (report, overrides = {}) => {
  const { reportBytes = serializePermissionReport(report), ...fields } = overrides;
  const canonicalPayloadSha256 = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(report))).digest("hex");
  const reportFileSha256 = crypto.createHash("sha256").update(reportBytes).digest("hex");
  const bindingPayload = buildPermissionReportBinding({ report, canonicalPayloadSha256, reportFileSha256, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM });
  return Object.fromEntries(Object.entries({
  schemaVersion: PERMISSION_REPORT_SIGNATURE_SCHEMA_VERSION,
  hashDomain: PERMISSION_REPORT_HASH_DOMAIN,
  bindingDomain: PERMISSION_REPORT_BINDING_DOMAIN,
  bindingSchemaVersion: PERMISSION_REPORT_BINDING_SCHEMA_VERSION,
  evidenceKind: report.evidenceKind,
  phase: report.phase,
  purpose: report.purpose,
  accountId: "368992683803",
  region: "eu-west-2",
  keyId: PERMISSION_REPORT_SIGNING_KEY_ARN,
  keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN,
  signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM,
  canonicalPayloadSha256,
  reportFileSha256,
  signedBindingSha256: signedPermissionReportBindingSha256(bindingPayload),
  signatureBase64: "AQ==",
  signedAt: report.generatedAt,
  ...fields,
  }).filter(([, value]) => value !== undefined));
};
const writePermissionPair = (reportPath, signaturePath, report) => {
  const reportBytes = serializePermissionReport(report);
  writePrivate(reportPath, reportBytes);
  writePrivate(signaturePath, JSON.stringify(reportSignature(report, { reportBytes })));
};
const assertReport = (report, options = {}) => assertPermissionReport(report, { signatureArtifact: reportSignature(report), verifySignature: () => true, ...options });
const reportBinding = (report) => ({
  planSha256: report.planSha256,
  savedPlanSha256: report.savedPlanSha256,
  canonicalPlanJsonSha256: report.canonicalPlanJsonSha256,
  now,
});
const validReport = () => runPermissionPreflight({
  reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session",
  simulate: allowRequiredDenyForbidden,
  cloudTrail: clearCloudTrail,
});

test("manifest is source-controlled, exact-accounted, and has no wildcard PassRole", () => {
  assert.equal(validateManifest(manifest), true);
  assert.equal(manifest.taskDefinitionMappings.length, 12);
  assert.equal(new Set(manifest.taskDefinitionMappings.map((entry) => entry.address)).size, 12);
  assert.equal(manifest.taskDefinitionMappings.filter((entry) => entry.family === "mscqr-production-full-rls-green-read-only-canary").length, 1);
  assert.equal(REVIEWED_SIMULATION_CONTEXT_REGISTRY.length, 19);
  assert.equal(assertReviewedSimulationContextRegistry().length, 19);
  assert.ok(REVIEWED_SIMULATION_CONTEXT_REGISTRY.every(({ key, type, values }) => key && type && values.length > 0
    && (key === "s3:if-none-match" ? values.length === 1 && values[0] === "*" : !values.includes("*"))));
});

test("locked Stage A provider refresh contract is preflighted before any apply", () => {
  assert.doesNotThrow(() => validateManifest(manifest));
  const providerReads = deriveRequiredEvaluations(plan, manifest).required.filter(({ manifestId }) => manifestId.startsWith("refresh-stage-a-") || manifestId === "reference-audit-stage-a-root-drop-public-key");
  assert.ok(providerReads.some(({ action }) => action === "kms:GetKeyRotationStatus"));
  assert.ok(providerReads.some(({ action }) => action === "kms:GetPublicKey"));
  const missingRotation = structuredClone(manifest);
  missingRotation.required = missingRotation.required.filter((entry) => entry.id !== "refresh-stage-a-root-drop-key-rotation-status");
  assert.throws(() => validateManifest(missingRotation), /Stage A provider refresh contract is not covered.*kms:GetKeyRotationStatus/);
});

test("permission manifest declares the exact normal and recovery mutation matrix", () => {
  const profilesFor = (id) => manifest.required.find((entry) => entry.id === id)?.profiles;
  assert.deepEqual(profilesFor("update-broker-managed-policy"), ["NORMAL_STAGE_B_RELEASE", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"]);
  assert.deepEqual(profilesFor("prune-broker-managed-policy-versions"), ["NORMAL_STAGE_B_RELEASE", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"]);
  assert.deepEqual(profilesFor("update-reviewed-broker-alias"), ["NORMAL_STAGE_B_RELEASE", "RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"]);
  for (const entry of manifest.required.filter((candidate) => !candidate.plan)) assert.equal(entry.profiles, undefined);
});

test("checker approval publication is an exact separate capability and never a release preflight evaluation", () => {
  assert.deepEqual(manifest.checkerRequired, [{
    id: "publish-stage-b-approval", phase: "approval-publication", action: "secretsmanager:PutSecretValue",
    resources: [STAGE_B.approvalSecretArn], context: [{ key: "aws:RequestedRegion", type: "string", values: [STAGE_B.region] }],
    principal: STAGE_B.checkerRoleArn, evidence: manifest.checkerRequired[0].evidence,
  }]);
  assert.equal(deriveRequiredEvaluations(productionPlan, manifest).required.some(({ manifestId }) => manifestId === "publish-stage-b-approval"), false);
  assert.throws(() => validateManifest({ ...manifest, checkerRequired: [{ ...manifest.checkerRequired[0], resources: ["*"] }] }), /Checker approval publication capability is not exact/);
});

test("IAM census executes every independent evaluation after multiple simulator failures", () => {
  let calls = 0;
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "census-test",
    simulate: ({ evaluation }) => {
      calls += 1;
      if (calls === 1 || calls === 7 || calls === 19) throw new Error(`fixture failure ${calls}`);
      return allowRequiredDenyForbidden({ evaluation });
    },
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.iamEvaluationCensus.executed, report.iamEvaluationCensus.total);
  assert.equal(calls, report.iamEvaluationCensus.total);
  assert.ok(report.iamEvaluationCensus.invalid >= 3);
});

test("reviewed simulator registry fails closed on missing, extra, or malformed keys", () => {
  const missing = REVIEWED_SIMULATION_CONTEXT_REGISTRY.filter(({ key }) => key !== "aws:RequestedRegion");
  assert.throws(() => assertReviewedSimulationContextRegistry({ registry: missing }), /missing=aws:RequestedRegion/);
  const extra = [...REVIEWED_SIMULATION_CONTEXT_REGISTRY, { key: "new:ConditionKey", type: "string", values: ["reviewed"] }];
  assert.throws(() => assertReviewedSimulationContextRegistry({ registry: extra }), /extra=new:ConditionKey/);
  const malformed = REVIEWED_SIMULATION_CONTEXT_REGISTRY.map((entry) => entry.key === "aws:RequestedRegion" ? { ...entry, values: ["*"] } : entry);
  assert.throws(() => assertReviewedSimulationContextRegistry({ registry: malformed }), /wildcard/);
});

test("scalar simulator context values fail closed while list values remain multi-valued", () => {
  for (const type of ["string", "boolean", "numeric", "date", "ip", "binary"]) {
    assert.throws(() => assertSimulationContextCardinality([{ key: `test:${type}`, type, values: ["one", "two"] }]), /exactly one value/);
  }
  assert.doesNotThrow(() => assertSimulationContextCardinality([{ key: "test:list", type: "stringList", values: ["one", "two"] }, { key: "test:numeric-list", type: "numericList", values: ["one", "two"] }]));
  assert.doesNotThrow(() => assertSimulationContextCardinality([{ key: "test:numeric", type: "numeric", values: ["1"] }]));
});

test("IAM simulation rejects scalar multi-values before invoking AWS", () => {
  let invoked = false;
  assert.throws(() => simulatePrincipalPolicy({
    roleArn,
    evaluation: { id: "numeric-context", action: "iam:PassRole", resource: "arn:aws:iam::368992683803:role/example", context: [{ key: "ecs:task-cpu", type: "numeric", values: ["512", "1024"] }] },
    run: () => { invoked = true; return JSON.stringify(simulatorAllowed); },
  }), /exactly one value/);
  assert.equal(invoked, false);
});

test("GetContextKeysForPrincipalPolicy is discovery-only and cannot synthesize values", () => {
  const keys = REVIEWED_SIMULATION_CONTEXT_REGISTRY.map(({ key }) => key);
  assert.equal(assertDiscoveredSimulationContextKeys(keys), true);
  assert.throws(() => assertDiscoveredSimulationContextKeys([...keys, "new:ConditionKey"]), /extra=new:ConditionKey/);
  assert.throws(() => assertDiscoveredSimulationContextKeys(REVIEWED_SIMULATION_CONTEXT_REGISTRY), /malformed/);
  assert.throws(() => assertDiscoveredSimulationContextKeys([...keys, keys[0]]), /duplicate keys/);
});

test("preflight checks optional context-key discovery before any simulation", () => {
  const input = {
    reportGeneratorCallerArn: generatorArn,
    simulatedRoleArn: roleArn,
    plan,
    planBytes,
    savedPlanBytes,
    manifest,
    generatedAt: now,
    now,
    policyPublishedAt: now,
    cloudTrailSessionName: "test-session",
    cloudTrail: clearCloudTrail,
  };
  let simulations = 0;
  const report = runPermissionPreflight({
    ...input,
    discoverContextKeys: ({ roleArn: discoveredRoleArn }) => {
      assert.equal(discoveredRoleArn, roleArn);
      return REVIEWED_SIMULATION_CONTEXT_REGISTRY.map(({ key }) => key);
    },
    simulate: ({ evaluation }) => {
      simulations += 1;
      return allowRequiredDenyForbidden({ evaluation });
    },
  });
  assert.equal(report.status, "valid");
  assert.ok(simulations > 0);

  let blockedSimulation = false;
  const incompleteRegistry = REVIEWED_SIMULATION_CONTEXT_REGISTRY.filter(({ key }) => key !== "ecs:cluster");
  assert.throws(() => runPermissionPreflight({
    ...input,
    contextRegistry: incompleteRegistry,
    simulate: () => {
      blockedSimulation = true;
      throw new Error("simulation must not start");
    },
  }), /registry differs.*missing=ecs:cluster/);
  assert.equal(blockedSimulation, false);
});

test("Stage A live-evidence preflight covers exactly the five region-bound read actions", () => {
  const expected = [
    ["collect-stage-a-live-subnets", "ec2:DescribeSubnets"], ["collect-stage-a-live-route-tables", "ec2:DescribeRouteTables"], ["collect-stage-a-live-security-groups", "ec2:DescribeSecurityGroups"], ["collect-stage-a-live-cluster", "ecs:DescribeClusters"], ["collect-stage-a-live-database", "rds:DescribeDBInstances"],
  ];
  const derived = deriveRequiredEvaluations(plan, manifest).required.filter((item) => item.manifestId.startsWith("collect-stage-a-live-"));
  assert.deepEqual(derived.map((item) => [item.manifestId, item.action, item.resource, item.context]), expected.map(([id, action]) => [id, action, "*", derived.find((item) => item.manifestId === id).context ]).sort(([left], [right]) => left.localeCompare(right)));
  const missing = structuredClone(manifest); missing.required = missing.required.filter((entry) => entry.id !== "collect-stage-a-live-database");
  assert.throws(() => validateManifest(missing), /live-evidence permission mapping/);
});

test("Stage A live-evidence simulations fail closed for denied or wrong-region requests", () => {
  const evaluations = deriveRequiredEvaluations(plan, manifest).required.filter((item) => item.manifestId.startsWith("collect-stage-a-live-"));
  for (const item of evaluations) assert.equal(simulatePrincipalPolicy({ roleArn, evaluation: item, run: () => JSON.stringify({ EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: "*", EvalDecision: "allowed", MatchedStatements: [{}], MissingContextValues: [] }] }) }).decision, "allowed");
  assert.equal(runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session", simulate: ({ evaluation }) => evaluation.manifestId === evaluations[0].manifestId ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation }), cloudTrail: clearCloudTrail }).status, "invalid");
  const wrongRegion = structuredClone(manifest); wrongRegion.required.find((entry) => entry.id === evaluations[0].manifestId).context[0].values = ["us-east-1"];
  assert.throws(() => validateManifest(wrongRegion), /live-evidence permission mapping/);
});

test("Stage A checker source-role policy refresh is an exact preflight capability", () => {
  const sourceRole = "arn:aws:iam::368992683803:role/mscqr-production-independent-checker";
  const targetRole = "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker";
  const entry = manifest.required.find(({ id }) => id === "refresh-stage-a-checker-inline-policy");
  assert.deepEqual(entry, {
    id: "refresh-stage-a-checker-inline-policy",
    phase: "refresh",
    action: "iam:GetRolePolicy",
    resources: [sourceRole, targetRole],
    context: [],
    evidence: "locked hashicorp/aws provider refresh of the Stage A checker policy and exact source-role checker role-chain policy",
  });
  const evaluations = deriveRequiredEvaluations(plan, manifest).required.filter(({ manifestId }) => manifestId === entry.id);
  assert.deepEqual(evaluations.map(({ action, resource }) => [action, resource]), [
    ["iam:GetRolePolicy", sourceRole],
    ["iam:GetRolePolicy", targetRole],
  ]);
  const input = {
    reportGeneratorCallerArn: generatorArn,
    simulatedRoleArn: roleArn,
    plan,
    planBytes,
    savedPlanBytes,
    manifest,
    generatedAt: now,
    now,
    policyPublishedAt: now,
    cloudTrailSessionName: "checker-policy-preflight",
    cloudTrail: clearCloudTrail,
  };
  const missingSource = runPermissionPreflight({
    ...input,
    simulate: ({ evaluation }) => evaluation.action === "iam:GetRolePolicy" && evaluation.resource === sourceRole
      ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }
      : allowRequiredDenyForbidden({ evaluation }),
  });
  assert.equal(missingSource.status, "invalid");
  assert.equal(missingSource.requiredEvaluations.find(({ manifestId, resource }) => manifestId === entry.id && resource === sourceRole).decision, "implicitDeny");
  const exact = runPermissionPreflight({ ...input, simulate: allowRequiredDenyForbidden });
  assert.equal(exact.status, "valid");
  assert.equal(exact.requiredEvaluations.filter(({ manifestId }) => manifestId === entry.id).every(({ decision }) => decision === "allowed"), true);
});

test("Stage A checker trust update is an exact preflight capability", () => {
  const roleB = "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker";
  const entry = manifest.required.find(({ id }) => id === "apply-stage-a-checker-role-trust");
  assert.deepEqual(entry, {
    id: "apply-stage-a-checker-role-trust",
    phase: "apply",
    action: "iam:UpdateAssumeRolePolicy",
    resources: [roleB],
    context: [],
    evidence: "Exact Role B trust transition admitted by the Stage A semantic gate; Terraform changes only the obsolete second-hop-MFA trust to the exact Role A principal",
  });
  const evaluations = deriveRequiredEvaluations(plan, manifest).required.filter(({ manifestId }) => manifestId === entry.id);
  assert.deepEqual(evaluations.map(({ action, resource }) => [action, resource]), [["iam:UpdateAssumeRolePolicy", roleB]]);
  const input = {
    reportGeneratorCallerArn: generatorArn,
    simulatedRoleArn: roleArn,
    plan,
    planBytes,
    savedPlanBytes,
    manifest,
    generatedAt: now,
    now,
    policyPublishedAt: now,
    cloudTrailSessionName: "checker-trust-preflight",
    cloudTrail: clearCloudTrail,
  };
  const missing = runPermissionPreflight({
    ...input,
    simulate: ({ evaluation }) => evaluation.manifestId === entry.id
      ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }
      : allowRequiredDenyForbidden({ evaluation }),
  });
  assert.equal(missing.status, "invalid");
  assert.equal(missing.requiredEvaluations.find(({ manifestId }) => manifestId === entry.id).decision, "implicitDeny");
  const exact = runPermissionPreflight({ ...input, simulate: allowRequiredDenyForbidden });
  assert.equal(exact.status, "valid");
  assert.equal(exact.requiredEvaluations.find(({ manifestId }) => manifestId === entry.id).decision, "allowed");
});

test("Stage A checker publication policy update is an exact target-role preflight capability", () => {
  const targetRole = "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker";
  const sourceRole = "arn:aws:iam::368992683803:role/mscqr-production-independent-checker";
  const entry = manifest.required.find(({ id }) => id === "apply-stage-a-checker-publication-policy");
  assert.deepEqual(entry, {
    id: "apply-stage-a-checker-publication-policy",
    phase: "apply",
    action: "iam:PutRolePolicy",
    resources: [targetRole],
    context: [],
    evidence: "Exact Stage A checker publication inline policy on the RLS checker target role; Terraform separately proves the policy name, exact KMS signing statements, and exact Stage-B approval secret",
  });
  const evaluations = deriveRequiredEvaluations(plan, manifest).required.filter(({ manifestId }) => manifestId === entry.id);
  assert.deepEqual(evaluations.map(({ action, resource }) => [action, resource]), [["iam:PutRolePolicy", targetRole]]);
  const input = {
    reportGeneratorCallerArn: generatorArn,
    simulatedRoleArn: roleArn,
    plan,
    planBytes,
    savedPlanBytes,
    manifest,
    generatedAt: now,
    now,
    policyPublishedAt: now,
    cloudTrailSessionName: "checker-publication-preflight",
    cloudTrail: clearCloudTrail,
  };
  const missing = runPermissionPreflight({
    ...input,
    simulate: ({ evaluation }) => evaluation.manifestId === entry.id
      ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }
      : allowRequiredDenyForbidden({ evaluation }),
  });
  assert.equal(missing.status, "invalid");
  assert.equal(missing.requiredEvaluations.find(({ manifestId, resource }) => manifestId === entry.id && resource === targetRole).decision, "implicitDeny");
  const exact = runPermissionPreflight({ ...input, simulate: allowRequiredDenyForbidden });
  assert.equal(exact.status, "valid");
  assert.equal(exact.requiredEvaluations.find(({ manifestId, resource }) => manifestId === entry.id && resource === targetRole).decision, "allowed");
  assert.equal(evaluations.some(({ resource }) => resource === sourceRole), false);
});

test("backend ECS Exec inline policy creation is an exact target-role preflight capability", () => {
  const targetRole = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task";
  const entry = manifest.required.find(({ id }) => id === "create-stage-b-backend-ecs-exec-inline-policy");
  assert.equal(entry.action, "iam:PutRolePolicy");
  assert.deepEqual(entry.resources, [targetRole]);
  const exactPlan = structuredClone(plan);
  exactPlan.resource_changes.push({ address: "aws_iam_role_policy.backend_ecs_exec", type: "aws_iam_role_policy", change: { actions: ["create"], before: null, after: {} } });
  assert.deepEqual(deriveRequiredEvaluations(exactPlan, manifest).required.filter(({ manifestId }) => manifestId === entry.id).map(({ action, resource }) => [action, resource]), [["iam:PutRolePolicy", targetRole]]);
  for (const id of ["backend-ecs-exec-put-role-policy-unrelated-role", "backend-ecs-exec-put-role-policy-wildcard", "backend-ecs-exec-delete-role-policy", "backend-ecs-exec-attach-role-policy", "backend-ecs-exec-update-trust", "backend-ecs-exec-permissions-boundary"]) {
    assert.equal(manifest.forbidden.find((item) => item.id === id)?.expectedDecision, "implicitDeny", id);
  }
});

test("Stage A live-evidence policy source contains no mutation permission", () => {
  const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json", "utf8"));
  const statement = policy.Statement.find((item) => item.Sid === "ReadStageALivePrerequisites");
  assert.deepEqual(statement, { Sid: "ReadStageALivePrerequisites", Effect: "Allow", Action: ["ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "ecs:DescribeClusters", "rds:DescribeDBInstances"], Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } });
  for (const action of ["ec2:CreateSubnet", "ecs:UpdateService", "rds:ModifyDBInstance"]) {
    const evaluation = { id: `unrelated-${action}`, action, resource: "*", context: [{ key: "aws:RequestedRegion", type: "string", values: ["eu-west-2"] }], expectedDecision: "implicitDeny", expectedMissingContextValues: [] };
    Object.defineProperty(evaluation, "forbidden", { value: true });
    assert.equal(validateSimulationResult(evaluation, { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }).decision, "implicitDeny");
  }
});

test("runtime wrapper ECS reads simulate with the actual DescribeTasks Resource * shape", () => {
  const runtimeIds = [
    "reference-audit-ecs-services",
    "reference-audit-ecs-tasks",
    "reference-audit-ecs-service-details",
    "reference-audit-ecs-task-details",
    "reference-audit-ecs-task-definitions",
  ];
  const evaluations = deriveRequiredEvaluations(plan, manifest).required.filter(({ manifestId }) => runtimeIds.includes(manifestId));
  assert.equal(evaluations.length, runtimeIds.length);
  const byAction = new Map(evaluations.map((item) => [item.action, item]));
  assert.equal(byAction.get("ecs:ListTasks").resource, "*");
  assert.equal(byAction.get("ecs:DescribeTasks").resource, "*");
  assert.equal(byAction.get("ecs:DescribeTaskDefinition").resource, "*");
  assert.match(byAction.get("ecs:DescribeServices").resource, /service\/mscqr-prod-euw2-main\/\*/);
  for (const item of evaluations) {
    let invocation;
    const result = simulatePrincipalPolicy({
      roleArn,
      evaluation: item,
      run: (args) => {
        invocation = args;
        return JSON.stringify({ EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: "*" === item.resource ? "*" : item.resource, EvalDecision: "allowed", MatchedStatements: [{}], MissingContextValues: [] }] });
      },
    });
    assert.equal(result.decision, "allowed");
    assert.equal(invocation[invocation.indexOf("--resource-arns") + 1], item.resource);
  }
  const describeTasks = byAction.get("ecs:DescribeTasks");
  assert.equal(describeTasks.context.find(({ key }) => key === "aws:RequestedRegion").values[0], "eu-west-2");
  assert.equal(describeTasks.context.find(({ key }) => key === "ecs:cluster").values[0], STAGE_B.clusterArn);
  const wrongRegion = { ...describeTasks, context: describeTasks.context.map((entry) => entry.key === "aws:RequestedRegion" ? { ...entry, values: ["us-east-1"] } : entry) };
  const denied = simulatePrincipalPolicy({
    roleArn,
    evaluation: wrongRegion,
    run: (args) => {
      assert.equal(args[args.indexOf("--context-entries") + 1], "ContextKeyName=aws:RequestedRegion,ContextKeyValues=us-east-1,ContextKeyType=string");
      return JSON.stringify({ EvaluationResults: [{ EvalActionName: wrongRegion.action, EvalResourceName: "*", EvalDecision: "implicitDeny", MatchedStatements: [], MissingContextValues: [] }] });
    },
  });
  assert.equal(denied.decision, "implicitDeny");
});

test("predeployment DescribeTaskDefinition allows only eu-west-2", () => {
  const sourceEvaluation = deriveRequiredEvaluations(plan, manifest).required.find(({ manifestId }) => manifestId === "describe-predeployment-inventory-task-definition");
  assert.equal(sourceEvaluation.action, "ecs:DescribeTaskDefinition");
  assert.equal(sourceEvaluation.resource, "*");
  const simulate = (evaluation, decision, missing = []) => simulatePrincipalPolicy({
    roleArn,
    evaluation,
    run: (args) => {
      const contextIndex = args.indexOf("--context-entries");
      if (decision === "allowed") assert.equal(args[contextIndex + 1], "ContextKeyName=aws:RequestedRegion,ContextKeyValues=eu-west-2,ContextKeyType=string");
      return JSON.stringify({ EvaluationResults: [{ EvalActionName: evaluation.action, EvalResourceName: evaluation.resource, EvalDecision: decision, MatchedStatements: decision === "allowed" ? [{}] : [], MissingContextValues: missing }] });
    },
  });
  assert.equal(simulate(sourceEvaluation, "allowed").decision, "allowed");
  const otherRegion = { ...sourceEvaluation, context: sourceEvaluation.context.map((entry) => entry.key === "aws:RequestedRegion" ? { ...entry, values: ["us-east-1"] } : entry) };
  const otherResult = simulatePrincipalPolicy({
    roleArn,
    evaluation: otherRegion,
    run: (args) => {
      assert.match(args[args.indexOf("--context-entries") + 1], /ContextKeyValues=us-east-1/);
      return JSON.stringify({ EvaluationResults: [{ EvalActionName: otherRegion.action, EvalResourceName: "*", EvalDecision: "implicitDeny", MatchedStatements: [], MissingContextValues: [] }] });
    },
  });
  assert.equal(otherResult.decision, "implicitDeny");
  const missingRegion = { ...sourceEvaluation, context: sourceEvaluation.context.filter((entry) => entry.key !== "aws:RequestedRegion"), expectedMissingContextValues: ["aws:RequestedRegion"], expectedDecision: "implicitDeny" };
  Object.defineProperty(missingRegion, "forbidden", { value: true });
  assert.equal(simulate(missingRegion, "implicitDeny", ["aws:RequestedRegion"]).decision, "implicitDeny");
});

const listBucketEvaluation = () => deriveRequiredEvaluations(plan, manifest).forbidden.find((item) => item.manifestId === "backend-list-bucket-not-required");
const deniedListBucketSimulation = ({ evaluation }) => evaluation.manifestId === "backend-list-bucket-not-required"
  ? { decision: evaluation.expectedDecision, matchedStatements: 0, missingContextValues: evaluation.expectedMissingContextValues }
  : allowRequiredDenyForbidden({ evaluation });

test("direct backend accepts the exact reviewed ListBucket denial context", () => {
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session", simulate: deniedListBucketSimulation, cloudTrail: clearCloudTrail });
  const result = report.forbiddenEvaluations.find((item) => item.manifestId === "backend-list-bucket-not-required");
  assert.equal(report.status, "valid");
  assert.deepEqual(result.missingContextValues, result.expectedMissingContextValues);
  assert.deepEqual({ decision: result.decision, matchedStatements: result.matchedStatements, validation: result.validation }, { decision: "implicitDeny", matchedStatements: 0, validation: "accepted" });
});

test("direct backend rejects missing context on its unneeded ListBucket proof", () => {
  const item = listBucketEvaluation();
  assert.throws(() => simulatePrincipalPolicy({ roleArn, evaluation: item, run: () => JSON.stringify({ EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: item.resource, EvalDecision: "implicitDeny", MatchedStatements: [], MissingContextValues: ["s3:prefix"] }] }) }), /unexpected MissingContextValues/);
});

test("unexpected missing context is rejected for forbidden and required evaluations", () => {
  const forbidden = structuredClone(listBucketEvaluation());
  forbidden.forbidden = true;
  forbidden.expectedMissingContextValues = [];
  forbidden.expectedDecision = "implicitDeny";
  assert.throws(() => validateSimulationResult(forbidden, { decision: "implicitDeny", matchedStatements: 0, missingContextValues: ["s3:prefix"] }), /unexpected MissingContextValues/);
  const required = deriveRequiredEvaluations(plan, manifest).required[0];
  assert.throws(() => validateSimulationResult(required, { decision: "allowed", matchedStatements: 1, missingContextValues: ["unexpected:key"] }), /Required evaluation/);
});

test("expected missing context is forbidden on required entries, supplied contexts, and duplicates", () => {
  const required = structuredClone(manifest);
  required.required[0].expectedMissingContextValues = ["s3:prefix"];
  assert.throws(() => validateManifest(required), /only for forbidden/);
  const supplied = structuredClone(manifest);
  supplied.forbidden.find((entry) => entry.id === "backend-list-bucket-not-required").expectedMissingContextValues = ["s3:prefix"];
  supplied.forbidden.find((entry) => entry.id === "backend-list-bucket-not-required").context = [{ key: "s3:prefix", type: "string", values: ["env:/"] }];
  assert.throws(() => validateManifest(supplied), /overlaps supplied/);
  const duplicate = structuredClone(manifest);
  duplicate.forbidden.find((entry) => entry.id === "backend-list-bucket-not-required").expectedMissingContextValues = ["s3:prefix", "s3:prefix"];
  assert.throws(() => validateManifest(duplicate), /duplicate/);
});

test("all 21 sanitized real AWS forbidden responses match the reviewed contracts", () => {
  const items = deriveRequiredEvaluations(plan, manifest).forbidden;
  assert.equal(realForbiddenSimulations.evaluations.length, 21);
  for (const fixture of realForbiddenSimulations.evaluations) {
    const item = items.find(({ manifestId }) => manifestId === fixture.manifestId);
    assert.ok(item, fixture.manifestId);
    const response = structuredClone(fixture.response);
    if (item.action.startsWith("s3:")) response.EvaluationResults[0].MissingContextValues = [];
    const result = simulatePrincipalPolicy({ roleArn, evaluation: item, conditionKeyOrigins: sourcePolicyConditionKeyOrigins(), run: () => JSON.stringify(response) });
    assert.equal(result.decision, item.expectedDecision);
    assert.deepEqual(result.missingContextValues, item.expectedMissingContextValues);
  }
});

test("filters unrelated role-wide MissingContextValues before action validation", () => {
  const item = deriveRequiredEvaluations(plan, manifest).forbidden.find(({ manifestId }) => manifestId === "backend-bucket-delete");
  const result = simulatePrincipalPolicy({
    roleArn,
    evaluation: item,
    conditionKeyOrigins: sourcePolicyConditionKeyOrigins(),
    run: () => JSON.stringify({
      EvaluationResults: [{
        EvalActionName: item.action,
        EvalResourceName: item.resource,
        EvalDecision: "implicitDeny",
        MatchedStatements: [],
        MissingContextValues: [
          "aws:RequestTag/Component",
          "aws:ResourceTag/MSCQRExecTarget",
          "ecs:cluster",
          "iam:PassedToService",
        ],
      }],
    }),
  });
  assert.deepEqual(result.missingContextValues, []);
});

test("forbidden context comparison rejects missing, additional, wrong, duplicate, and misplaced values", () => {
  const items = deriveRequiredEvaluations(plan, manifest).forbidden;
  const implicit = structuredClone(items.find(({ manifestId }) => manifestId === "backend-list-bucket-not-required"));
  implicit.forbidden = true;
  const explicit = structuredClone(items.find(({ manifestId }) => manifestId === "backend-state-delete"));
  explicit.forbidden = true;
  const exact = { decision: implicit.expectedDecision, matchedStatements: 0, missingContextValues: implicit.expectedMissingContextValues };
  assert.throws(() => validateSimulationResult({ ...implicit, expectedMissingContextValues: ["unexpected:key"] }, exact), /unexpected MissingContextValues/);
  assert.throws(() => validateSimulationResult(implicit, { ...exact, missingContextValues: [...exact.missingContextValues, "unexpected:key"] }), /unexpected MissingContextValues/);
  assert.throws(() => validateSimulationResult(implicit, { ...exact, missingContextValues: ["wrong:key", ...exact.missingContextValues.slice(1)] }), /unexpected MissingContextValues/);
  assert.throws(() => validateSimulationResult(implicit, { ...exact, missingContextValues: ["unexpected:key"] }), /unexpected MissingContextValues/);
  assert.throws(() => validateSimulationResult(explicit, { decision: explicit.expectedDecision, matchedStatements: 1, missingContextValues: ["aws:RequestedRegion"] }), /unexpected MissingContextValues/);
  assert.throws(() => validateSimulationResult(implicit, { ...exact, missingContextValues: ["unexpected:key", "unexpected:key"] }), /duplicate/);
  assert.throws(() => validateSimulationResult(implicit, { ...exact, decision: "allowed" }), /returned decision allowed/);
});

test("every reviewed missing-context key has a canonical policy statement origin", () => {
  const origins = sourcePolicyConditionKeyOrigins();
  const expectedKeys = [...origins.keys()].sort();
  assert.deepEqual([...origins.keys()].sort(), expectedKeys);
  assert.deepEqual([...new Set(REVIEWED_SIMULATION_CONTEXT_REGISTRY.map(({ key }) => key))].sort(), expectedKeys);
  const deleteBucket = deriveRequiredEvaluations(plan, manifest).forbidden.find(({ manifestId }) => manifestId === "backend-bucket-delete");
  assert.deepEqual(deleteBucket.context, []);
  assert.deepEqual(deleteBucket.expectedMissingContextValues, []);
  const passRole = deriveRequiredEvaluations(plan, manifest).forbidden.find(({ manifestId }) => manifestId === "pass-unrelated-role");
  assert.deepEqual(passRole.expectedMissingContextValues, []);
  for (const entry of deriveRequiredEvaluations(plan, manifest).forbidden.filter(({ action }) => action.startsWith("s3:"))) {
    assert.deepEqual(entry.expectedMissingContextValues, [], entry.manifestId);
  }
  for (const key of expectedKeys) assert.ok(origins.get(key).every(({ policy, sid, operator, sourcePath }) => policy && sid && operator && sourcePath), key);
  const missingOrigin = new Map(origins); missingOrigin.delete(expectedKeys[0]);
  assert.throws(() => validateManifest(manifest, { conditionKeyOrigins: missingOrigin }), /registry differs.*missing=/);
  const newCondition = new Map(origins); newCondition.set("new:ConditionKey", [{ policy: "fixture", sid: "NewCondition", operator: "StringEquals", sourcePath: "fixture.json" }]);
  assert.throws(() => validateManifest(manifest, { conditionKeyOrigins: newCondition }), /registry differs.*extra=/);
});

test("production-shaped plan requires and binds the exact account and region variables", () => {
  const bytes = fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json");
  const run = (selectedPlan) => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: selectedPlan, planBytes: Buffer.from(JSON.stringify(selectedPlan)), savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  for (const key of ["account_id", "aws_region"]) {
    const missing = structuredClone(productionPlan); delete missing.variables[key];
    assert.throws(() => run(missing), /Plan account or region is wrong/);
  }
  assert.throws(() => run({ ...productionPlan, variables: { ...productionPlan.variables, account_id: { value: "000000000000" } } }), /Plan account or region is wrong/);
  assert.throws(() => run({ ...productionPlan, variables: { ...productionPlan.variables, aws_region: { value: "us-east-1" } } }), /Plan account or region is wrong/);
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: bytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  assert.equal(report.status, "valid");
  assert.equal(report.requiredEvaluations.length, 257);
  assert.equal(report.forbiddenEvaluations.length, 38);
  for (const evaluation of report.requiredEvaluations) {
    for (const context of evaluation.context.filter(({ key }) => key === "aws:RequestedRegion")) assert.deepEqual(context.values, ["eu-west-2"]);
    if (evaluation.resource.startsWith("arn:aws:") && !evaluation.resource.startsWith("arn:aws:s3:::")) assert.ok(
      evaluation.resource === "*"
      || evaluation.resource.includes(":368992683803:")
      || evaluation.resource === "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
      evaluation.resource,
    );
  }
});

test("backend health recovery permissions fail the administrator preflight before ECS mutation", () => {
  for (const deniedId of [
    "backend-health-recovery-describe-images",
    "backend-health-recovery-describe-repositories",
    "backend-health-recovery-register-legacy-task-definition",
    "backend-health-recovery-update-service",
  ]) {
    const report = runPermissionPreflight({
      reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan,
      planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now,
      policyPublishedAt: now, cloudTrailSessionName: "backend-health-recovery-preflight",
      simulate: ({ evaluation }) => evaluation.manifestId === deniedId
        ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }
        : allowRequiredDenyForbidden({ evaluation }),
      cloudTrail: clearCloudTrail,
    });
    assert.equal(report.status, "invalid");
    assert.equal(report.deniedCount, 1);
    assert.equal(report.requiredEvaluations.find(({ manifestId }) => manifestId === deniedId).validation, "rejected");
  }
});

test("signed permission reports bind expected and actual missing context", () => {
  const report = validReport();
  assertReport(report, reportBinding(report));
  for (const field of ["expectedMissingContextValues", "missingContextValues"]) {
    const tampered = structuredClone(report);
    tampered.forbiddenEvaluations.find((item) => item.manifestId === "backend-list-bucket-not-required")[field] = ["s3:prefix"];
    assert.throws(() => assertReport(tampered, reportBinding(tampered)), /different expected missing context|unexpected MissingContextValues|inconsistent validation evidence/);
  }
  const tampered = structuredClone(report);
  tampered.forbiddenEvaluations[0].missingContextExactMatch = false;
  assert.throws(() => assertReport(tampered, reportBinding(tampered)), /inconsistent validation evidence/);
});

test("exact canary create derives Register, TagResource, and both PassRole evaluations", () => {
  const derived = deriveRequiredEvaluations(plan, manifest);
  const passRoles = derived.required.filter((item) => item.action === "iam:PassRole" && !item.manifestId.startsWith("rollback-exact"));
  assert.deepEqual(passRoles.map((item) => item.resource), [
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
  ]);
  assert.ok(derived.required.some((item) => item.action === "ecs:RegisterTaskDefinition"));
  assert.ok(derived.required.some((item) => item.action === "ecs:TagResource"));
});

test("exact broker managed-policy update derives version actions for the exact policy", () => {
  const derived = deriveRequiredEvaluations({ ...plan, resource_changes: [plan.resource_changes[1]] }, manifest);
  const brokerEvaluations = derived.required.filter((item) => ["update-broker-managed-policy", "prune-broker-managed-policy-versions"].includes(item.manifestId));
  assert.deepEqual(brokerEvaluations.map(({ action }) => action), ["iam:DeletePolicyVersion", "iam:CreatePolicyVersion"]);
  for (const item of brokerEvaluations) {
    assert.equal(item.context.some(({ key }) => key === "ecs:task-cpu"), false);
    assert.equal(item.context.some(({ key }) => key === "ecs:task-memory"), false);
  }
});

test("recovery alias-only permission profile covers only the approved alias mutation", () => {
  const recoveryPlan = {
    ...structuredClone(plan),
    variables: { ...plan.variables, stage_b_recovery_only: { value: true } },
    resource_changes: [
      ...Array.from({ length: 72 }, (_, index) => ({
        address: `aws_lambda_alias.noop[${index}]`,
        type: "aws_lambda_alias",
        change: { actions: ["no-op"] },
      })),
      {
        address: "aws_lambda_alias.reviewed",
        type: "aws_lambda_alias",
        change: { actions: ["update"], before: { function_version: "2" }, after: { function_version: "3" }, after_unknown: {} },
      },
    ],
  };
  const selectedPlanBytes = Buffer.from(JSON.stringify(recoveryPlan));
  const selectedSavedPlanBytes = Buffer.from("recovery-saved-plan");
  const selectedCanonicalPlanJsonBytes = Buffer.from(`${canonicalizeJson(recoveryPlan)}\n`);
  const planHashes = {
    savedPlanSha256: crypto.createHash("sha256").update(selectedSavedPlanBytes).digest("hex"),
    planJsonSha256: crypto.createHash("sha256").update(selectedPlanBytes).digest("hex"),
    canonicalPlanFileSha256: crypto.createHash("sha256").update(selectedCanonicalPlanJsonBytes).digest("hex"),
    logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(recoveryPlan))).digest("hex"),
  };
  const recoveryAttestationSha256 = "d".repeat(64);
  const refreshBindingReportSha256 = "e".repeat(64);
  const capture = createStageBPlanCaptureReport({
    toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), refreshReportSha256: "f".repeat(64), refreshBindingReportSha256,
    recoveryAttestationSha256, hashes: planHashes, capturedAt: now, stageBLineage: "lineage", stageBSerial: 76,
    terraformVersion: "1.15.7", terraformFormatVersion: "1.2", planProfile: "RECOVERY_ALIAS_ONLY",
    classification: { noOp: 72, create: 0, update: 1, destroy: 0, replacement: 0, unclassified: 0 },
    brokerEvidence: { brokerOperation: "recovery-alias-only", brokerUpdatePresent: false, brokerActions: ["no-op"], brokerResourceAddresses: ["aws_lambda_alias.reviewed"] },
  });
  const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  const approval = createStageBPlanApprovalReport({
    captureReportSha256: crypto.createHash("sha256").update(captureBytes).digest("hex"), referenceAuditPath: "/private/tmp/recovery-audit.json", referenceAuditSha256: "a".repeat(64),
    referenceAuditCallerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", referenceAuditAt: now,
    toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, refreshBindingReportSha256,
    recoveryAttestationSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes: planHashes,
    logicalCanonicalPlanJsonSha256: planHashes.logicalCanonicalPlanJsonSha256, approvedAt: now,
    classification: capture.classification, planProfile: "RECOVERY_ALIAS_ONLY", brokerOperation: "recovery-alias-only",
    brokerUpdatePresent: false, brokerActions: ["no-op"], brokerResourceAddresses: ["aws_lambda_alias.reviewed"],
  });
  const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  const report = runPermissionPreflightRaw({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, manifest, plan: recoveryPlan, planBytes: selectedPlanBytes,
    canonicalPlanJsonBytes: selectedCanonicalPlanJsonBytes, savedPlanBytes: selectedSavedPlanBytes, planApprovalReport: approval,
    planApprovalReportBytes: approvalBytes, planApprovalReportSha256: crypto.createHash("sha256").update(approvalBytes).digest("hex"),
    generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "recovery-test", policyEvidence, ecsExecVerifierEvidence: buildEcsExecOperatorEvidence(), simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "valid");
  assert.equal(report.planProfile, "RECOVERY_ALIAS_ONLY");
  assert.equal(report.permissionProfile, "RECOVERY_ALIAS_ONLY");
  assert.doesNotThrow(() => assertPermissionEvaluationBindings(report, manifest, { plan: recoveryPlan, permissionProfile: "RECOVERY_ALIAS_ONLY" }));
  assert.doesNotThrow(() => assertPermissionReport(report, {
    signatureArtifact: reportSignature(report), verifySignature: () => true, plan: recoveryPlan,
    planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now,
  }));
  const planEvaluations = report.requiredEvaluations.filter(({ manifestId }) => manifest.required.find((entry) => entry.id === manifestId)?.plan);
  assert.deepEqual(planEvaluations.map(({ manifestId }) => manifestId), ["update-reviewed-broker-alias"]);
  assert.equal(planEvaluations[0].action, "lambda:UpdateAlias");
  assert.throws(() => assertPermissionEvaluationBindings({ ...report, requiredEvaluations: [...report.requiredEvaluations, { manifestId: "backend-register" }] }, manifest, { plan: recoveryPlan, permissionProfile: "RECOVERY_ALIAS_ONLY" }), /cannot contain ECS task-definition evaluations/);
});

test("permission profile selection fails closed across recovery and normal plan shapes", () => {
  const recoveryPlan = { ...structuredClone(plan), variables: { ...plan.variables, stage_b_recovery_only: { value: true } }, resource_changes: [{ address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: { actions: ["update"] } }] };
  assert.throws(() => deriveRequiredEvaluations({ ...recoveryPlan, resource_changes: [{ ...plan.resource_changes[1] }] }, manifest, { permissionProfile: "RECOVERY_ALIAS_ONLY" }), /No permission manifest entry/);
  assert.throws(() => deriveRequiredEvaluations({ ...recoveryPlan, resource_changes: [{ address: "aws_ecs_task_definition.candidate[\"backend\"]", type: "aws_ecs_task_definition", change: { actions: ["create"], after: {} } }] }, manifest, { permissionProfile: "RECOVERY_ALIAS_ONLY" }), /RECOVERY_ALIAS_ONLY rejects ECS/);
  assert.throws(() => deriveRequiredEvaluations({ ...recoveryPlan, resource_changes: [{ address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["update"], after: {} } }] }, manifest, { permissionProfile: "RECOVERY_ALIAS_ONLY" }), /No permission manifest entry/);
  assert.throws(() => deriveRequiredEvaluations({ ...recoveryPlan, resource_changes: [{ address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: { actions: ["update"] } }, { address: "aws_lambda_alias.other", type: "aws_lambda_alias", change: { actions: ["update"] } }] }, manifest, { permissionProfile: "RECOVERY_ALIAS_ONLY" }), /No permission manifest entry/);
  assert.throws(() => resolveStageBPermissionProfile({ plan: recoveryPlan, approvedPlanProfile: "BASELINE" }), /does not match/);
  assert.throws(() => resolveStageBPermissionProfile({ plan, approvedPlanProfile: "RECOVERY_ALIAS_ONLY" }), /does not match/);
  assert.throws(() => resolveStageBPermissionProfile({ plan, approvedPlanProfile: "UNKNOWN_PROFILE" }), /unsupported/);
  assert.equal(resolveStageBPermissionProfile({ plan, approvedPlanProfile: "BASELINE" }).permissionProfile, "NORMAL_STAGE_B_RELEASE");
});

test("broker managed-policy coverage fails for missing, wrong, wildcard, unrelated, create, delete, or replacement mappings", () => {
  const brokerChange = plan.resource_changes[1];
  const withoutBroker = structuredClone(manifest);
  withoutBroker.required = withoutBroker.required.filter((entry) => !entry.id.includes("broker-managed-policy"));
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [brokerChange] }, withoutBroker), /No permission manifest entry/);

  for (const mutate of [
    (broken) => { broken.required.find((entry) => entry.id === "update-broker-managed-policy").resources = ["arn:aws:iam::368992683803:policy/other"]; },
    (broken) => { broken.required.find((entry) => entry.id === "update-broker-managed-policy").resources = ["*"]; },
  ]) {
    const broken = structuredClone(manifest); mutate(broken);
    assert.throws(() => validateManifest(broken), /Broker managed-policy permission mapping is not exact/);
  }

  for (const actions of [["create"], ["delete"], ["delete", "create"]]) {
    assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [{ ...brokerChange, change: { ...brokerChange.change, actions } }] }, manifest), /No permission manifest entry/);
  }
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [{ ...brokerChange, address: "aws_iam_policy.other" }] }, manifest), /No permission manifest entry/);
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [{ address: "aws_iam_role_policy.broker", type: "aws_iam_role_policy", change: { actions: ["update"], after: { name: "stage-b-broker" } } }] }, manifest), /aws_iam_role_policy\.broker is forbidden/);
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [{ ...plan.resource_changes[2], change: { ...plan.resource_changes[2].change, actions: ["update"] } }] }, manifest), /attachment must be the exact imported no-op/);
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [{ ...plan.resource_changes[2], change: { ...plan.resource_changes[2].change, after: { role: "mscqr-production-unrelated-role", policy_arn: brokerPolicyArn } } }] }, manifest), /attachment must be the exact imported no-op/);
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [{ ...brokerChange, change: { ...brokerChange.change, after: { name: "mscqr-production-rls-approval-broker-runtime", policy: JSON.stringify({ Version: "2012-10-17", Statement: [] }) }, after_unknown: {} } }] }, manifest), /document differs/);
});

test("broker managed-policy simulation allows the exact update and rejects implicit or explicit deny", () => {
  const brokerPlan = { ...plan, resource_changes: [plan.resource_changes[1]] };
  const evaluate = (decision) => runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: brokerPlan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => !evaluation.forbidden && evaluation.action.startsWith("iam:") ? { decision, matchedStatements: 1, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation }),
    cloudTrail: clearCloudTrail,
  });
  assert.equal(evaluate("allowed").requiredEvaluations.find((item) => item.action === "iam:CreatePolicyVersion").decision, "allowed");
  for (const decision of ["implicitDeny", "explicitDeny"]) {
    const report = evaluate(decision);
    assert.equal(report.status, "invalid");
    assert.equal(report.requiredEvaluations.find((item) => item.action === "iam:CreatePolicyVersion").decision, decision);
  }
});

test("complete mocked preflight passes and binds the exact plan SHA", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "valid");
  assert.equal(report.planSha256, crypto.createHash("sha256").update(productionPlanBytes).digest("hex"));
  assert.equal(report.deniedCount, 0);
  assertReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now });
});

test("missing required PassRole fails closed", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => !evaluation.forbidden && evaluation.action === "iam:PassRole" ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation }),
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "invalid");
  assert.ok(report.requiredEvaluations.some((item) => item.action === "iam:PassRole" && item.decision === "implicitDeny"));
  assert.throws(() => assertReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /valid permission-preflight report/);
});

test("PassRole with the wrong service context is rejected by the manifest", () => {
  const broken = structuredClone(manifest);
  broken.taskDefinitionMappings[0].passRoleContext[0].values = ["lambda.amazonaws.com"];
  assert.throws(() => validateManifest(broken), /PassRole context/);
});

test("required and forbidden exact tuples cannot overlap, while different contexts remain distinct", () => {
  const broken = structuredClone(manifest);
  const unrelatedRole = broken.forbidden.find((entry) => entry.id === "pass-unrelated-role");
  unrelatedRole.resources = [manifest.taskDefinitionMappings[0].taskRoleArn];
  assert.throws(() => validateManifest(broken), /required\/forbidden overlap.*pass-unrelated-role.*rls-green-backend-task/);

  const differentContext = structuredClone(manifest);
  const differentContextEntry = differentContext.forbidden.find((entry) => entry.id === "pass-unrelated-role");
  differentContextEntry.resources = [manifest.taskDefinitionMappings[0].taskRoleArn];
  differentContextEntry.context[0].values = ["lambda.amazonaws.com"];
  assert.doesNotThrow(() => validateManifest(differentContext));
});

test("wrong role, account, region, missing context, and unreviewed plan actions fail closed", () => {
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: "arn:aws:iam::368992683803:role/unrelated", plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /simulated role/);
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: { ...plan, variables: { ...plan.variables, account_id: { value: "000000000000" } } }, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /account or region/);
  const broken = structuredClone(manifest); broken.taskDefinitionMappings[0].passRoleContext = [];
  assert.throws(() => validateManifest(broken), /PassRole context/);
  assert.throws(() => deriveRequiredEvaluations({ ...plan, resource_changes: [...plan.resource_changes, { address: "aws_ecs_service.unexpected", type: "aws_ecs_service", change: { actions: ["update"], after: {} } }] }, manifest), /No permission manifest entry/);
});

test("IAM simulation uses argv arrays and passes context explicitly", () => {
  let captured;
  const result = simulatePrincipalPolicy({
    roleArn,
    evaluation: { id: "lambda-fixture", action: simulatorAllowed.EvaluationResults[0].EvalActionName, resource: simulatorAllowed.EvaluationResults[0].EvalResourceName, context: [{ key: "aws:RequestedRegion", type: "string", values: ["eu-west-2"] }] },
    run: (args) => { captured = args; return JSON.stringify(simulatorAllowed); },
  });
  assert.equal(result.decision, "allowed");
  assert.ok(captured.includes("--action-names"));
  assert.ok(captured.includes("--context-entries"));
  assert.equal(captured.some((value) => value.includes(";") || value.includes("$(") || value.includes("`")), false);
});

test("forbidden allowed evaluation fails closed", () => {
  let calls = 0;
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => {
      calls += 1;
      return evaluation.id.startsWith("pass-unrelated-role") ? { decision: "allowed", matchedStatements: 1, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation });
    },
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "invalid");
  assert.equal(report.iamEvaluationCensus.invalid > 0, true);
  assert.match(report.iamEvaluationCensus.failures[0].error, /returned decision allowed/);
  assert.equal(calls, report.iamEvaluationCensus.total);
  assert.equal(report.iamEvaluationCensus.executed, report.iamEvaluationCensus.total);
});

test("wrong plan binding and stale reports are rejected", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.throws(() => assertReport(report, { planSha256: "0".repeat(64), savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /different plan/);
  const stale = { ...report, generatedAt: "2026-08-01T11:00:00.000Z" };
  assert.throws(() => assertPermissionReport(stale, { signatureArtifact: reportSignature(stale), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /expired/);
  const underHour = { ...report, generatedAt: new Date(Date.parse(now) - PERMISSION_EVIDENCE_MAX_AGE_MS + 1).toISOString() };
  assert.doesNotThrow(() => assertPermissionReport(underHour, { signatureArtifact: reportSignature(underHour), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }));
  const oneHourOld = { ...report, generatedAt: new Date(Date.parse(now) - PERMISSION_EVIDENCE_MAX_AGE_MS).toISOString() };
  assert.throws(() => assertPermissionReport(oneHourOld, { signatureArtifact: reportSignature(oneHourOld), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /expired/);
});

test("image provenance and permission evidence use independent freshness windows", () => {
  assert.notEqual(IMAGE_EVIDENCE_MAX_AGE_MS, PERMISSION_EVIDENCE_MAX_AGE_MS);
  assert.ok(IMAGE_EVIDENCE_MAX_AGE_MS > PERMISSION_EVIDENCE_MAX_AGE_MS);
});

test("permission preflight requires binary-plan bytes and the report carries both plan hashes", () => {
  assert.throws(() => runPermissionPreflightRaw({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, manifest, phase: "plan-bound", generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /Saved binary plan bytes/);
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, planBound: true, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  assert.match(report.savedPlanSha256, /^[a-f0-9]{64}$/);
  assert.match(report.canonicalPlanJsonSha256, /^[a-f0-9]{64}$/);
  const missingSavedHash = { ...report, savedPlanSha256: undefined };
  assert.throws(() => assertPermissionReport(missingSavedHash, { signatureArtifact: reportSignature(missingSavedHash), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /saved binary plan/);
});

test("CloudTrail denial supplements simulation and blocks preflight", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: () => ({ status: "unresolved-denial", eventsChecked: 1, unresolvedDenials: [{ eventName: "PassRole" }] }),
  });
  assert.equal(report.status, "invalid");
  assert.equal(report.deniedCount, 1);
  assert.throws(() => assertReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /valid permission-preflight report/);
});

test("AWS simulator accepts the hand-reviewed PascalCase CLI fixture", () => {
  const result = simulatePrincipalPolicy({
    roleArn,
    evaluation: { id: "lambda-fixture", action: simulatorAllowed.EvaluationResults[0].EvalActionName, resource: simulatorAllowed.EvaluationResults[0].EvalResourceName, context: [] },
    conditionKeyOrigins: sourcePolicyConditionKeyOrigins(),
    run: () => JSON.stringify(simulatorAllowed),
  });
  assert.deepEqual(result, { decision: "allowed", matchedStatements: 0, missingContextValues: [], organizationsAllowed: null, permissionsBoundaryAllowed: null });
});

test("AWS simulation preserves Organizations and permissions-boundary decisions", () => {
  const evaluation = deriveRequiredEvaluations(plan, manifest).required[0];
  const result = simulatePrincipalPolicy({ roleArn, evaluation, run: () => JSON.stringify({ EvaluationResults: [{ EvalActionName: evaluation.action, EvalResourceName: evaluation.resource, EvalDecision: "implicitDeny", MatchedStatements: [], MissingContextValues: [], OrganizationsDecisionDetail: { AllowedByOrganizations: false }, PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: false } }] }) });
  assert.equal(result.organizationsAllowed, false); assert.equal(result.permissionsBoundaryAllowed, false);
});

test("AWS simulator rejects camelCase-only and incomplete responses", () => {
  const item = { id: "lambda-fixture", action: "lambda:UpdateFunctionConfiguration", resource: simulatorAllowed.EvaluationResults[0].EvalResourceName, context: [] };
  for (const response of [
    { evaluationResults: [{ evalDecision: "allowed", matchedStatements: [] }] },
    { EvaluationResults: [] },
    { EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: item.resource, MatchedStatements: [], MissingContextValues: [] }] },
    { EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: item.resource, EvalDecision: "allowed", MatchedStatements: [], MissingContextValues: ["aws:ResourceTag/Environment"] }] },
    { EvaluationResults: [{ EvalActionName: "lambda:UpdateAlias", EvalResourceName: item.resource, EvalDecision: "allowed", MatchedStatements: [], MissingContextValues: [] }] },
  ]) assert.throws(() => simulatePrincipalPolicy({ roleArn, evaluation: item, run: () => JSON.stringify(response) }), /malformed|mismatch|unexpected/);
});

test("caller validation accepts only the exact STS assumed-role ARN", () => {
  assert.doesNotThrow(() => assertStageBReleaseCallerArn("arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session"));
  for (const invalid of [
    "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
    "arn:aws:iam::368992683803:root",
    "arn:aws:iam::368992683803:user/operator",
    "arn:aws:sts::000000000000:assumed-role/mscqr-production-release-deployer/session",
    "arn:aws:sts::368992683803:assumed-role/other/session",
    "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/",
    "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session/extra",
  ]) assert.throws(() => assertStageBReleaseCallerArn(invalid), /exact production release-deployer/);
});

test("all Lambda write manifest entries require the exact four resource-tag contexts", () => {
  const lambdaEntries = manifest.required.filter((entry) => ["lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode", "lambda:PublishVersion", "lambda:UpdateAlias"].includes(entry.action));
  assert.equal(lambdaEntries.length, 4);
  for (const entry of lambdaEntries) {
    assert.deepEqual(Object.fromEntries(entry.context.map(({ key, values }) => [key, values])), {
      "aws:RequestedRegion": ["eu-west-2"],
      "aws:ResourceTag/Environment": ["production"],
      "aws:ResourceTag/ManagedBy": ["Terraform"],
      "aws:ResourceTag/Component": ["full-rls-green-stage-b"],
    });
    for (const key of ["aws:ResourceTag/Environment", "aws:ResourceTag/ManagedBy", "aws:ResourceTag/Component"]) {
      const broken = structuredClone(manifest);
      broken.required.find((candidate) => candidate.id === entry.id).context = entry.context.filter((item) => item.key !== key);
      assert.throws(() => validateManifest(broken), (error) => error instanceof Error && error.message.includes(key));
    }
  }
});

test("the exact twelve task-definition creates expand to registration, tagging, and both PassRole evaluations", () => {
  const fullPlan = { ...plan, resource_changes: [...manifest.taskDefinitionMappings.map((mapping) => ({
    address: mapping.address,
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: taskDefinitionAfter(mapping) },
  })), plan.resource_changes[1]] };
  const derived = deriveRequiredEvaluations(fullPlan, manifest);
  assert.equal(derived.coveredChanges.length, 13);
  assert.equal(derived.required.filter((item) => item.action === "ecs:RegisterTaskDefinition").length, 14);
  assert.equal(derived.required.filter((item) => item.action === "ecs:TagResource").length, 13);
  assert.equal(derived.required.filter((item) => item.action === "iam:PassRole").length, 26);
});

test("task-definition registration context is complete and bound to each planned family", () => {
  const productionPlan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
  const registrations = deriveRequiredEvaluations(productionPlan, manifest).required.filter(({ action, manifestId }) => action === "ecs:RegisterTaskDefinition" && manifest.taskDefinitionMappings.some(({ id }) => manifestId === `${id}-register`));
  assert.equal(registrations.length, 12);
  for (const registration of registrations) {
    assert.deepEqual(registration.context.filter(({ key }) => key.startsWith("ecs:")).map(({ key, type, values }) => ({ key, type, values })), [
      { key: "ecs:cluster", type: "string", values: ["arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main"] },
      { key: "ecs:compute-compatibility", type: "stringList", values: ["FARGATE"] },
      { key: "ecs:privileged", type: "string", values: ["false"] },
      { key: "ecs:task-cpu", type: "numeric", values: [registration.manifestId === "worker-register" ? "512" : registration.manifestId === "read-only-canary-register" ? "256" : "1024"] },
      { key: "ecs:task-definition", type: "stringList", values: ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7", "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47"] },
      { key: "ecs:task-memory", type: "numeric", values: [registration.manifestId === "worker-register" ? "1024" : registration.manifestId === "read-only-canary-register" ? "512" : "2048"] },
    ]);
  }
});

test("operation context uses one ECS scalar per request and omits task scalars elsewhere", () => {
  const productionPlan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json"));
  const derived = deriveRequiredEvaluations(productionPlan, manifest).required;
  for (const item of derived.filter(({ action, manifestId }) => action === "ecs:RegisterTaskDefinition" && manifest.taskDefinitionMappings.some(({ id }) => manifestId === `${id}-register`))) {
    for (const context of item.context.filter(({ key }) => ["ecs:task-cpu", "ecs:task-memory"].includes(key))) assert.equal(context.values.length, 1);
  }
  for (const item of derived.filter(({ action }) => ["ecs:TagResource", "iam:PassRole"].includes(action))) {
    assert.equal(item.context.some(({ key }) => ["ecs:task-cpu", "ecs:task-memory"].includes(key)), false);
  }
});

test("missing or mismatched task registration context fails before simulation", () => {
  const productionPlan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
  for (const mutate of [
    (after) => { delete after.cpu; },
    (after) => { after.cpu = "512"; },
    (after) => { after.memory = "1024"; },
    (after) => { after.requires_compatibilities = ["EC2"]; },
    (after) => { after.container_definitions = JSON.stringify([{ privileged: true }]); },
    (after) => { after.tags.Environment = "staging"; },
    (after) => { after.family = "mscqr-production-unrelated"; },
  ]) {
    const candidate = structuredClone(productionPlan);
    mutate(candidate.resource_changes.find(({ address }) => address === manifest.taskDefinitionMappings[0].address).change.after);
    assert.throws(() => deriveRequiredEvaluations(candidate, manifest), /registration context|ecs:privileged|No permission manifest entry/);
  }
});

test("normal permission profile still requires every ECS registration context", () => {
  const productionPlan = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
  const report = { requiredEvaluations: [], forbiddenEvaluations: [], planCapabilities: { schemaVersion: 1, required: [], forbidden: [], mutationInstances: deriveRequiredEvaluations(productionPlan, manifest).coveredChanges } };
  assert.doesNotThrow(() => assertPermissionEvaluationBindings(report, manifest, { plan: productionPlan, permissionProfile: "NORMAL_STAGE_B_RELEASE" }));
  const missing = structuredClone(productionPlan);
  missing.resource_changes = missing.resource_changes.filter(({ address }) => address !== manifest.taskDefinitionMappings[0].address);
  assert.throws(() => assertPermissionEvaluationBindings(report, manifest, { plan: missing, permissionProfile: "NORMAL_STAGE_B_RELEASE" }), /exactly one reviewed task-definition registration/);
});

test("fresh-image recovery separates twelve registrations from eleven reviewed deposed cleanups", () => {
  const fresh = freshImageRecoveryRegistrationPlan();
  assert.doesNotThrow(() => assertTaskDefinitionRegistrationContexts(fresh, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration }));
  const derived = deriveRequiredEvaluations(fresh, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration });
  assert.doesNotThrow(() => assertPermissionEvaluationBindings({
    requiredEvaluations: [],
    forbiddenEvaluations: [],
    planCapabilities: { schemaVersion: 1, required: [], forbidden: [], mutationInstances: derived.coveredChanges, zeroAwsMutationChanges: derived.zeroAwsMutationChanges },
  }, manifest, { plan: fresh, permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration }));
  assert.throws(() => assertTaskDefinitionRegistrationContexts(fresh, manifest, { terraformConfiguration }), /unreviewed task-definition change/);

  const missingCleanup = structuredClone(fresh);
  missingCleanup.resource_changes = missingCleanup.resource_changes.filter((change) => !Object.hasOwn(change, "deposed") || change.address !== 'aws_ecs_task_definition.candidate["worker"]');
  assert.throws(() => assertTaskDefinitionRegistrationContexts(missingCleanup, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration }), /exact eleven reviewed deposed cleanups/);

  const duplicateCleanup = structuredClone(fresh);
  const cleanup = duplicateCleanup.resource_changes.find((change) => Object.hasOwn(change, "deposed"));
  duplicateCleanup.resource_changes.push({ ...structuredClone(cleanup), deposed: "deadbeef" });
  assert.throws(() => assertTaskDefinitionRegistrationContexts(duplicateCleanup, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration }), /exact eleven reviewed deposed cleanups/);

  const contextForCleanup = structuredClone(fresh);
  contextForCleanup.resource_changes.find((change) => Object.hasOwn(change, "deposed")).change.actions = ["create"];
  assert.throws(() => assertTaskDefinitionRegistrationContexts(contextForCleanup, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration }), /exact eleven reviewed deposed cleanups|exactly one reviewed task-definition registration|unreviewed task-definition change/);
});

test("fresh-image permissions accept twelve registrations after deposed residue is already reconciled", () => {
  const fresh = freshImageRecoveryRegistrationPlan();
  fresh.resource_changes = fresh.resource_changes.filter((change) => !Object.hasOwn(change, "deposed"));
  assert.doesNotThrow(() => assertTaskDefinitionRegistrationContexts(fresh, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration }));
  const derived = deriveRequiredEvaluations(fresh, manifest, { permissionProfile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", terraformConfiguration });
  assert.equal(derived.coveredChanges.filter((change) => change.classification === "PARTIAL_APPLY_RECOVERY_DEPOSED_TASK_DEFINITION_CLEANUP").length, 0);
});

test("manifest rejects missing, duplicate, and cross-family ECS registration context", () => {
  for (const mutate of [
    (mapping) => { mapping.registerContext = mapping.registerContext.filter(({ key }) => key !== "ecs:privileged"); },
    (mapping) => { mapping.registerContext = mapping.registerContext.filter(({ key }) => key !== "ecs:compute-compatibility"); },
    (mapping) => { mapping.registerContext = mapping.registerContext.filter(({ key }) => key !== "ecs:task-cpu"); },
    (mapping) => { mapping.registerContext = mapping.registerContext.filter(({ key }) => key !== "ecs:task-memory"); },
    (mapping) => { mapping.registerContext.push(structuredClone(mapping.registerContext[0])); },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "ecs:privileged").values = ["true"]; },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "ecs:task-cpu").values = ["512"]; },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "ecs:task-memory").values = ["1024"]; },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "ecs:compute-compatibility").values = ["EC2"]; },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "aws:RequestedRegion").values = ["eu-west-1"]; },
    (mapping) => { mapping.registerContext = mapping.registerContext.filter(({ key }) => key !== "aws:RequestTag/Environment"); },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "aws:TagKeys").values = ["Environment"]; },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "ecs:task-cpu").type = "boolean"; },
    (mapping) => { mapping.registerContext.find(({ key }) => key === "ecs:task-cpu").values = []; },
  ]) {
    const broken = structuredClone(manifest);
    mutate(broken.taskDefinitionMappings[0]);
    assert.throws(() => validateManifest(broken), /ECS registration context|duplicate context key|malformed context/);
  }
});

test("incomplete, duplicate, unknown, and mismatched task-definition mappings fail closed", () => {
  for (const mutate of [
    (broken) => broken.taskDefinitionMappings.pop(),
    (broken) => { broken.taskDefinitionMappings[1].address = broken.taskDefinitionMappings[0].address; },
    (broken) => { broken.taskDefinitionMappings[0].family = "unrelated"; },
    (broken) => { broken.taskDefinitionMappings.push({ ...broken.taskDefinitionMappings[0], id: "thirteenth", address: "aws_ecs_task_definition.extra" }); },
  ]) {
    const broken = structuredClone(manifest); mutate(broken);
    assert.throws(() => validateManifest(broken), /task-definition mapping|exact Stage B allowlist/);
  }
});

test("preflight separates approved generator identity from the simulated release role", () => {
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: roleArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /approved audit\/admin/);
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  assert.equal(report.reportGeneratorCallerArn, generatorArn);
  assert.equal(report.simulatedRoleArn, roleArn);
  assert.equal(report.applyRoleArn, roleArn);
  assert.equal(report.applyCallerArn, null);
  assert.match(report.manifestSha256, /^[a-f0-9]{64}$/);
});

test("permission evidence fails closed on stale versions, source drift, and detached policies", () => {
  const stale = structuredClone(policyEvidence); stale.policies[0].defaultVersionId = "legacy";
  assert.throws(() => assertReleasePolicyEvidence(stale), /source\/live identity/);
  const drifted = structuredClone(policyEvidence); drifted.policies[0].liveSha256 = "0".repeat(64);
  assert.throws(() => assertReleasePolicyEvidence(drifted), /source\/live identity/);
  const detached = structuredClone(policyEvidence); detached.policies[0].attached = false;
  assert.throws(() => assertReleasePolicyEvidence(detached), /source\/live identity/);
  const bounded = structuredClone(policyEvidence); bounded.permissionsBoundaryArn = "arn:aws:iam::368992683803:policy/boundary";
  assert.throws(() => assertReleasePolicyEvidence(bounded), /permissions boundary/);
  const extraAttachment = structuredClone(policyEvidence); extraAttachment.attachedPolicyArns.push("arn:aws:iam::aws:policy/AdministratorAccess");
  assert.throws(() => assertReleasePolicyEvidence(extraAttachment), /attachment set/);
});

test("preflight requires a manifest and rejects an unapproved generator", () => {
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /manifest is required/);
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: "arn:aws:iam::368992683803:user/operator", simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /approved audit\/admin/);
});

test("permission report signing uses the fixed KMS key and algorithm", () => {
  const report = validReport();
  let signed;
  const artifact = signPermissionReport(report, {
    now,
    sign: (input) => { signed = input; return "AQ=="; },
  });
  assert.equal(signed.keyArn, PERMISSION_REPORT_SIGNING_KEY_ARN);
  assert.equal(signed.signingAlgorithm, PERMISSION_REPORT_SIGNING_ALGORITHM);
  assert.deepEqual(artifact, reportSignature(report, { signedAt: now }));
  assert.doesNotThrow(() => assertReport(report, { ...reportBinding(report), signatureArtifact: artifact }));
});

test("permission report hash domains are explicit and whitespace-bound", () => {
  const report = validReport();
  const reportBytes = serializePermissionReport(report);
  const artifact = signPermissionReport(report, { now, reportBytes, sign: () => "AQ==" });
  const signatureBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`);
  const domains = assertPermissionReportHashDomains({ report, signatureArtifact: artifact, reportBytes, signatureBytes });
  assert.equal(artifact.hashDomain, "signedBindingSha256");
  assert.equal(artifact.canonicalPayloadSha256, domains.canonicalPayloadSha256);
  assert.equal(artifact.reportFileSha256, domains.reportFileSha256);
  assert.equal("reportSha256" in artifact, false);
  assert.notEqual(domains.canonicalPayloadSha256, domains.reportFileSha256);
  assert.throws(() => assertPermissionReportHashDomains({ report, signatureArtifact: artifact, reportBytes: Buffer.from(`${reportBytes} \n`), signatureBytes }), /different report bytes/);
  assert.throws(() => assertPermissionReportHashDomains({ report: { ...report, deniedCount: 1 }, signatureArtifact: artifact, reportBytes, signatureBytes }), /do not match/);
});

test("a substituted signature envelope or report cannot pass the bound pair", () => {
  const report = validReport();
  const reportBytes = serializePermissionReport(report);
  const artifact = signPermissionReport(report, { now, reportBytes, sign: () => "AQ==" });
  const signatureBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`);
  assert.throws(() => assertPermissionReportHashDomains({ report, signatureArtifact: { ...artifact, canonicalPayloadSha256: "0".repeat(64) }, reportBytes, signatureBytes }), /do not match|different canonical payload/);
  const substitutedReport = { ...report, deniedCount: 1 };
  const substitutedBytes = serializePermissionReport(substitutedReport);
  assert.throws(() => assertPermissionReportHashDomains({ report: substitutedReport, signatureArtifact: artifact, reportBytes: substitutedBytes, signatureBytes }), /different canonical payload/);
});

test("unsigned, modified, wrong-key, wrong-algorithm, wrong-hash, and stale reports fail signature verification", () => {
  const report = validReport();
  const artifact = reportSignature(report);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: undefined }), /signature/);
  assert.throws(() => assertPermissionReport({ ...report, status: "valid", deniedCount: 1 }, { ...reportBinding(report), signatureArtifact: artifact }), /different canonical payload/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/other" } }), /identity or algorithm/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256" } }), /identity or algorithm/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, canonicalPayloadSha256: "0".repeat(64) } }), /different canonical payload|different signed binding/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, signedAt: "2026-08-01T11:00:00.000Z" } }), /stale/);
});

test("versioned binding authenticates both report hash domains and evidence identity", () => {
  const report = validReport(); const reportBytes = serializePermissionReport(report); let artifactDigest; const artifact = signPermissionReport(report, { now, reportBytes, sign: ({ digest }) => { artifactDigest = digest.toString("hex"); return "AQ=="; } });
  assert.equal(artifactDigest, artifact.signedBindingSha256);
  const signatureBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`);
  assert.doesNotThrow(() => verifyPermissionReportSignature({ report, signatureArtifact: artifact, reportBytes, signatureBytes, now, verify: ({ digest }) => digest.toString("hex") === artifact.signedBindingSha256 }));
  assert.throws(() => verifyPermissionReportSignature({ report, signatureArtifact: artifact, reportBytes, signatureBytes, expectedSignatureFileSha256: "0".repeat(64), now, verify: () => true }), /signature file SHA256/);
  for (const mutation of [
    (value) => ({ ...value, reportFileSha256: "0".repeat(64) }),
    (value) => ({ ...value, canonicalPayloadSha256: "0".repeat(64) }),
    (value) => ({ ...value, signedBindingSha256: "0".repeat(64) }),
    (value) => ({ ...value, evidenceKind: "INITIAL_ADMIN_CAPABILITY" }),
    (value) => ({ ...value, phase: "initial" }),
    (value) => ({ ...value, purpose: "other-purpose" }),
    (value) => ({ ...value, accountId: "000000000000" }),
    (value) => ({ ...value, region: "us-east-1" }),
    (value) => ({ ...value, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/other", keyId: "arn:aws:kms:eu-west-2:368992683803:key/other" }),
    (value) => ({ ...value, signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256" }),
    (value) => ({ ...value, schemaVersion: 2 }),
    (value) => ({ ...value, hashDomain: "canonicalPayloadSha256" }),
  ]) assert.throws(() => verifyPermissionReportSignature({ report, signatureArtifact: mutation(artifact), reportBytes, signatureBytes: Buffer.from(`${JSON.stringify(mutation(artifact), null, 2)}\n`), now, verify: () => true }), /unsupported|different|binding|identity|algorithm/);
  assert.throws(() => verifyPermissionReportSignature({ report, signatureArtifact: artifact, reportBytes: Buffer.from(`${reportBytes} \n`), signatureBytes, now, verify: () => true }), /different report bytes/);
  const legacyArtifact = { ...artifact, schemaVersion: 2, hashDomain: "canonicalPayloadSha256" }; const legacyBytes = Buffer.from(`${JSON.stringify(legacyArtifact, null, 2)}\n`);
  assert.throws(() => verifyPermissionReportSignature({ report, signatureArtifact: legacyArtifact, reportBytes, signatureBytes: legacyBytes, now, verify: () => true }), /unsupported/);
});

test("production-default permission verification uses the release profile runner", () => {
  const report = validReport();
  const reportBytes = serializePermissionReport(report);
  const artifact = signPermissionReport(report, { now, reportBytes, sign: () => "AQ==" });
  const signatureBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`);
  const calls = [];
  const releaseRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
    profile: "mscqr-production-release-deployer",
    exec: (file, args, options) => {
      calls.push({ file, args, options });
      const operation = args[1]; const keyArn = "arn:aws:kms:eu-west-2:368992683803:key/11111111-2222-3333-4444-555555555555";
      return JSON.stringify(operation === "describe-key" ? { KeyMetadata: { Arn: keyArn, KeyId: keyArn.split("/").at(-1), Description: ROOT_ATTESTATION_KEY_DESCRIPTION, KeyUsage: "SIGN_VERIFY", KeySpec: "RSA_3072", KeyState: "Enabled", Enabled: true, KeyManager: "CUSTOMER", Origin: "AWS_KMS", MultiRegion: false } }
        : operation === "get-key-policy" ? { Policy: JSON.stringify(buildRootAttestationKeyPolicy()) }
          : operation === "list-resource-tags" ? { Tags: Object.entries(ROOT_ATTESTATION_TAGS).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) }
            : { SignatureValid: true });
    },
  });
  const previousProfile = process.env.AWS_PROFILE;
  process.env.AWS_PROFILE = "hostile-default-profile";
  try {
    assert.doesNotThrow(() => verifyPermissionReportSignature({ report, signatureArtifact: artifact, reportBytes, signatureBytes, now, run: releaseRun }));
  } finally {
    if (previousProfile === undefined) delete process.env.AWS_PROFILE;
    else process.env.AWS_PROFILE = previousProfile;
  }
  assert.equal(calls.length, 4);
  assert.equal(calls[0].file, "aws");
  assert.deepEqual(calls.map(({ args }) => args.slice(0, 2)), [["kms", "describe-key"], ["kms", "get-key-policy"], ["kms", "list-resource-tags"], ["kms", "verify"]]);
  assert.equal(calls.every(({ options }) => options.env.AWS_PROFILE === "mscqr-production-release-deployer"), true);
});

test("permission verification rejects an omitted trusted verifier instead of using ambient credentials", () => {
  const report = validReport();
  const reportBytes = serializePermissionReport(report);
  const artifact = signPermissionReport(report, { now, reportBytes, sign: () => "AQ==" });
  const signatureBytes = Buffer.from(`${JSON.stringify(artifact, null, 2)}\n`);
  assert.throws(() => verifyPermissionReportSignature({ report, signatureArtifact: artifact, reportBytes, signatureBytes, now }), /explicit trusted verifier or command runner/);
});

test("release-deployer cannot generate a report or sign through the CLI", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-signing-caller-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest));
  assert.throws(() => runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", path.join(directory, "report.json"), "--signature-output", path.join(directory, "signature.json"), "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...cliApprovalArgs(directory)], { getCaller: () => roleArn }), /Report generator caller/);
});

test("CLI passes its parsed manifest through the same preflight entrypoint", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-flow-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "report.signature.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest));
  let received;
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...cliApprovalArgs(directory)], { getCaller: () => generatorArn, collectPolicyEvidence: () => policyEvidence, runPreflight: (input) => { received = input.manifest; return { status: "valid", evidenceKind: "PLAN_BOUND_PERMISSION", phase: "plan-bound", generatedAt: now }; }, signReport: (report) => reportSignature(report) });
  assert.deepEqual(received, manifest);
  assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).status, "valid");
  assert.equal(JSON.parse(fs.readFileSync(signaturePath, "utf8")).canonicalPayloadSha256, reportSignature(JSON.parse(fs.readFileSync(outputPath, "utf8"))).canonicalPayloadSha256);
});

test("BASELINE CLI preflight requires reference audit before simulation", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-reference-audit-required-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest));
  const approvalArgs = cliApprovalArgs(directory).filter((argument, index, args) => argument !== "--reference-audit" && args[index - 1] !== "--reference-audit");
  let simulations = 0;
  assert.throws(() => runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", path.join(directory, "report.json"), "--signature-output", path.join(directory, "signature.json"), "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...approvalArgs], {
    getCaller: () => generatorArn,
    collectPolicyEvidence: () => policyEvidence,
    runPreflight: () => { simulations += 1; throw new Error("simulation must not start"); },
  }), /--reference-audit is required/);
  assert.equal(simulations, 0);
});

test("BASELINE CLI preflight rejects a nonexistent reference audit before simulation", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-reference-audit-missing-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest));
  const cliArgs = cliApprovalArgs(directory); const auditIndex = cliArgs.indexOf("--reference-audit"); cliArgs[auditIndex + 1] = path.join(directory, "missing-audit.json");
  let simulations = 0;
  assert.throws(() => runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", path.join(directory, "report.json"), "--signature-output", path.join(directory, "signature.json"), "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...cliArgs], {
    getCaller: () => generatorArn,
    collectPolicyEvidence: () => policyEvidence,
    runPreflight: () => { simulations += 1; throw new Error("simulation must not start"); },
  }), /reference audit.*regular.*file/i);
  assert.equal(simulations, 0);
});

test("invalid permission evidence is neither published nor signed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-invalid-preflight-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "report.signature.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest)); let signed = 0;
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...cliApprovalArgs(directory)], {
    getCaller: () => generatorArn, collectPolicyEvidence: () => policyEvidence,
    runPreflight: () => ({ status: "invalid", evidenceKind: "PLAN_BOUND_PERMISSION", phase: "plan-bound", generatedAt: now, deniedCount: 2 }), signReport: () => { signed += 1; },
  });
  assert.equal(signed, 0); assert.equal(fs.existsSync(outputPath), false); assert.equal(fs.existsSync(signaturePath), false); process.exitCode = 0;
});

test("a signing failure after report construction publishes no final artifact", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-signing-failure-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "signature.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest));
  assert.throws(() => runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...cliApprovalArgs(directory)], {
    getCaller: () => generatorArn, collectPolicyEvidence: () => policyEvidence,
    runPreflight: () => ({ status: "valid", evidenceKind: "PLAN_BOUND_PERMISSION", phase: "plan-bound", generatedAt: now }),
    signReport: () => { throw new Error("forced signing failure"); },
  }), /forced signing failure/);
  assert.equal(fs.existsSync(outputPath), false); assert.equal(fs.existsSync(signaturePath), false);
});

test("CLI and programmatic preflight paths produce the same deterministic report", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-equivalence-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "report.signature.json");
  writePrivate(planPath, planBytes); writePrivate(savedPath, savedPlanBytes); writePrivate(manifestPath, JSON.stringify(manifest));
  const direct = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, manifest, plan: productionPlan, planBytes: productionPlanBytes, savedPlanBytes, planBound: true, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  writePrivate(planPath, productionPlanBytes);
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test", ...cliApprovalArgs(directory, productionPlan, productionPlanBytes)], {
    getCaller: () => generatorArn,
    collectPolicyEvidence: () => policyEvidence,
    runPreflight: (input) => runPermissionPreflight({ ...input, generatedAt: now, now, simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }),
    signReport: (report) => reportSignature(report),
  });
  const cliReport = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  delete cliReport.planApprovalReportSha256;
  delete direct.planApprovalReportSha256;
  cliReport.planCapabilities.mutationManifest = { ...cliReport.planCapabilities.mutationManifest, planApprovalReportSha256: undefined, mutationManifestSha256: undefined };
  direct.planCapabilities.mutationManifest = { ...direct.planCapabilities.mutationManifest, planApprovalReportSha256: undefined, mutationManifestSha256: undefined };
  assert.deepEqual(cliReport, direct);
});

function wrapperFixture({ approvedPlan = plan, shownPlan, savedBytes = savedPlanBytes, approvedBytes } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-binding-"));
  const planPath = path.join(directory, "approved.tfplan");
  const planJsonPath = path.join(directory, "approved.plan.json");
  const canonicalPlanJsonPath = path.join(directory, "approved.plan.canonical.json");
  const planApprovalReportPath = path.join(directory, "approved.plan.approval.json");
  const auditPath = path.join(directory, "approved.audit.json");
  const permissionPath = path.join(directory, "approved.permission.json");
  const imageEvidencePath = path.join(directory, "approved.image-evidence.json");
  const imageEvidenceSignaturePath = path.join(directory, "approved.image-evidence.signature.json");
  const releaseSha = "a".repeat(40);
  const effectivePlan = structuredClone(approvedPlan);
  effectivePlan.variables = {
    ...effectivePlan.variables,
    tooling_sha: { value: "b".repeat(40) },
    image_release_sha: { value: releaseSha },
    backend_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}` },
    worker_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:${"b".repeat(64)}` },
    executor_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"c".repeat(64)}` },
    canary_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"d".repeat(64)}` },
    read_only_canary_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"d".repeat(64)}` },
  };
  const effectiveAddresses = new Set(effectivePlan.resource_changes.map((change) => change.address));
  for (const change of fixture.resource_changes) if (!effectiveAddresses.has(change.address)) effectivePlan.resource_changes.push(structuredClone(change));
  const planImageVariable = (address) => address.startsWith("aws_ecs_task_definition.executor[") ? "executor_image" : `${/\["([^"]+)"\]$/.exec(address)?.[1]}_image`;
  for (const [address, family] of Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)) {
    const mapping = manifest.taskDefinitionMappings.find((candidate) => candidate.address === address);
    const change = effectivePlan.resource_changes.find((candidate) => candidate.address === address);
    const after = { ...taskDefinitionAfter(mapping), family, container_definitions: JSON.stringify([{ image: effectivePlan.variables[planImageVariable(address)].value, privileged: false }]) };
    if (change) change.change.after = { ...after, ...change.change.after, container_definitions: after.container_definitions };
    else effectivePlan.resource_changes.push({ address, type: "aws_ecs_task_definition", change: { actions: ["create"], after } });
  }
  let effectiveShownPlan = structuredClone(shownPlan || effectivePlan);
  let effectiveApprovedBytes = approvedBytes || Buffer.from(JSON.stringify(effectivePlan));
  writePrivate(planPath, savedBytes);
  writePrivate(planJsonPath, effectiveApprovedBytes);
  let auditBytes = Buffer.from(JSON.stringify({ audit: true, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256: "c".repeat(64), broker: {
    aliasArn: STAGE_B.brokerAliasArn,
    aliasName: "reviewed",
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  } }));
  writePrivate(auditPath, auditBytes);
  const savedHash = crypto.createHash("sha256").update(savedBytes).digest("hex");
  let planHash = crypto.createHash("sha256").update(effectiveApprovedBytes).digest("hex");
  let canonicalHash = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(JSON.parse(JSON.stringify(effectiveShownPlan))))).digest("hex");
  const derivedEvaluations = deriveRequiredEvaluations(plan, manifest);
  const derivedEvaluationFor = (entry) => [...derivedEvaluations.required, ...derivedEvaluations.forbidden].find(({ manifestId }) => manifestId === entry.id);
  const requiredFixtureEntry = manifest.required.find((entry) => !entry.plan);
  const forbiddenFixtureEntry = manifest.forbidden.find((entry) => entry.id === "backend-list-bucket-not-required");
  const fixtureEvaluation = (entry, forbidden, decision, missingContextValues) => ({
    id: `${entry.id}:${entry.resources[0]}`,
    manifestId: entry.id,
    action: entry.action,
    resource: entry.resources[0],
    context: derivedEvaluationFor(entry).context,
    expectedMissingContextValues: entry.expectedMissingContextValues || [],
    ...(forbidden ? { expectedDecision: entry.expectedDecision } : {}),
    missingContextValues,
    missingContextExactMatch: true,
    decision,
    matchedStatements: forbidden ? 0 : 1,
    validation: forbidden ? "accepted" : "accepted",
  });
  const report = {
    schemaVersion: 1,
    evidenceKind: "PLAN_BOUND_PERMISSION",
    phase: "plan-bound",
  purpose: "saved-plan-authorization",
    planProfile: "BASELINE",
    permissionProfile: "NORMAL_STAGE_B_RELEASE",
    toolingSha: "b".repeat(40),
    imageReleaseSha: "a".repeat(40),
    canonicalImageEvidenceSha256: "c".repeat(64),
    reportGeneratorCallerArn: generatorArn,
    simulatedRoleArn: roleArn,
    applyRoleArn: roleArn,
    applyCallerArn: null,
    applyCallerArnPattern: "^arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/[^/]+$",
    manifestSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(manifest))).digest("hex"),
    planSha256: planHash,
    savedPlanSha256: savedHash,
    canonicalPlanJsonSha256: canonicalHash,
    generatedAt: new Date().toISOString(),
    requiredEvaluations: [fixtureEvaluation(requiredFixtureEntry, false, "allowed", [])],
    forbiddenEvaluations: [fixtureEvaluation(forbiddenFixtureEntry, true, forbiddenFixtureEntry.expectedDecision, forbiddenFixtureEntry.expectedMissingContextValues)],
    cloudTrail: { status: "clear", unresolvedDenials: [] },
    policyEvidence,
    requiredAllowedCount: 1,
    requiredDeniedCount: 0,
    forbiddenAllowedCount: 0,
    forbiddenDeniedCount: 1,
    deniedCount: 0,
    status: "valid",
  };
  const permissionSignaturePath = path.join(directory, "approved.permission.signature.json");
  writePermissionPair(permissionPath, permissionSignaturePath, report);
  const permissionReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(permissionPath)).digest("hex");
  const imageRecords = [
    ["backend", "mscqr-backend", "a".repeat(64), releaseSha],
    ["worker", "mscqr-worker", "b".repeat(64), releaseSha],
    ["rls-executor", "mscqr-backend", "c".repeat(64), `${releaseSha}-rls-executor`],
    ["rls-canary", "mscqr-backend", "d".repeat(64), `${releaseSha}-rls-canary`],
  ].map(([service, repository, digest, tag]) => ({ service, repository, image_uri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}:${tag}`, image_tag: tag, image_digest: `sha256:${digest}`, image_ref: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@sha256:${digest}` }));
  const imageArtifactBytes = Buffer.from(`${imageRecords.map((record) => JSON.stringify(record)).join("\n")}\n`);
  const imageArtifactSha256 = crypto.createHash("sha256").update(imageArtifactBytes).digest("hex");
  const imageObservedAt = new Date().toISOString();
  const publicationIdentity = buildStageBImagePublicationIdentity({ expectedPublicationSourceSha: releaseSha, expectedReleaseSha: releaseSha, artifactBytes: imageArtifactBytes, observed: { workflowRunId: "30760789616", workflowDatabaseId: "401", workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: "Production Green Stage B Images", event: "workflow_dispatch", workflowDefinitionSha: releaseSha, imageReleaseSha: releaseSha, headBranch: "main", conclusion: "success", artifactId: "501", artifactName: "production-green-stage-b-images", artifactExpired: false, artifactArchiveFilename: null }, observedAt: imageObservedAt });
  const imageRepositories = ["mscqr-backend", "mscqr-worker"].map((repository) => ({ repositoryName: repository, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, registryId: "368992683803", repositoryUri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}`, imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z", observedAt: imageObservedAt }));
  const imageEvidence = generateImageEvidence({ artifactBytes: imageArtifactBytes, publicationSourceSha: releaseSha, currentSourceSha: "b".repeat(40), imageReleaseSha: releaseSha, workflowRunId: "30760789616", artifactSha256: imageArtifactSha256, publicationIdentity, imageReuseEvidence: {}, verifierCallerArn: generatorArn, observedAt: imageObservedAt, repositories: imageRepositories, describe: (repository, tag) => ({ digest: `sha256:${imageRecords.find((record) => record.repository === repository && record.image_tag === tag).image_digest.slice(7)}`, imagePushedAt: "2026-08-02T18:26:34.000Z" }) });
  const canonicalImageEvidenceSha256 = imageEvidenceSha256(imageEvidence);
  effectivePlan.variables.canonical_image_evidence_sha256 = { value: canonicalImageEvidenceSha256 };
  const approvedPlanObject = approvedBytes ? JSON.parse(effectiveApprovedBytes) : effectivePlan;
  approvedPlanObject.variables.canonical_image_evidence_sha256 = { value: canonicalImageEvidenceSha256 };
  effectiveApprovedBytes = Buffer.from(JSON.stringify(approvedPlanObject));
  effectiveShownPlan.variables = { ...effectiveShownPlan.variables, canonical_image_evidence_sha256: { value: canonicalImageEvidenceSha256 } };
  writePrivate(planJsonPath, effectiveApprovedBytes);
  planHash = crypto.createHash("sha256").update(effectiveApprovedBytes).digest("hex");
  canonicalHash = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(JSON.parse(JSON.stringify(effectiveShownPlan))))).digest("hex");
  const retainedTaskDefinitions = effectivePlan.resource_changes.filter((change) => change.address?.includes("_retained[")).map((change, index) => {
    const key = change.address.match(/\["[a-f0-9]+-([^\"]+)"\]$/)[1];
    const family = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).find(([address]) => address.match(/\["([^\"]+)"\]$/)[1] === key)?.[1];
    return { terraformAddress: change.address, family, classification: "retained-no-op", oldTaskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 1}` };
  });
  auditBytes = Buffer.from(JSON.stringify({ audit: true, planJsonSha256: planHash, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256, retainedTaskDefinitions, broker: {
    aliasArn: STAGE_B.brokerAliasArn,
    aliasName: "reviewed",
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  } }));
  writePrivate(auditPath, auditBytes);
  report.canonicalImageEvidenceSha256 = canonicalImageEvidenceSha256;
  report.planSha256 = planHash;
  report.canonicalPlanJsonSha256 = canonicalHash;
  const projectCapabilities = (items) => items.map(({ id, action, resource, context, decision }) => ({ id, action, resource, context, decision }));
  report.planCapabilities = { schemaVersion: 1, required: projectCapabilities(report.requiredEvaluations), forbidden: projectCapabilities(report.forbiddenEvaluations), mutationInstances: deriveRequiredEvaluations(effectivePlan, manifest).coveredChanges };
  writePermissionPair(permissionPath, permissionSignaturePath, report);
  writePrivate(imageEvidencePath, `${JSON.stringify(imageEvidence, null, 2)}\n`);
  writePrivate(imageEvidenceSignaturePath, JSON.stringify(signImageEvidence(imageEvidence, { sign: () => "AQ==" })));
  const canonicalPlanJsonBytes = Buffer.from(`${canonicalizeJson(JSON.parse(effectiveApprovedBytes))}\n`);
  writePrivate(canonicalPlanJsonPath, canonicalPlanJsonBytes);
  const capture = createStageBPlanCaptureReport({ toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), refreshReportSha256: "r".repeat(64), hashes: { savedPlanSha256: savedHash, planJsonSha256: planHash, canonicalPlanFileSha256: crypto.createHash("sha256").update(canonicalPlanJsonBytes).digest("hex"), logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(effectivePlan))).digest("hex") }, capturedAt: new Date().toISOString(), stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 76, terraformVersion: "1.15.7", terraformFormatVersion: "1.2", classification: { noOp: effectivePlan.resource_changes.filter((change) => JSON.stringify(change.change?.actions) === JSON.stringify(["no-op"])).length, create: 12, update: 3, destroy: 0, replacement: 0, unclassified: 0 } });
  const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  const approval = createStageBPlanApprovalReport({ captureReportSha256: crypto.createHash("sha256").update(captureBytes).digest("hex"), referenceAuditPath: auditPath, referenceAuditSha256: crypto.createHash("sha256").update(auditBytes).digest("hex"), referenceAuditCallerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", referenceAuditAt: new Date().toISOString(), toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes: { savedPlanSha256: savedHash, planJsonSha256: planHash, canonicalPlanFileSha256: crypto.createHash("sha256").update(canonicalPlanJsonBytes).digest("hex"), logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(effectivePlan))).digest("hex") }, logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(effectivePlan))).digest("hex"), approvedAt: new Date().toISOString(), classification: capture.classification });
  let approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  writePrivate(planApprovalReportPath, approvalBytes);
  report.planApprovalReportSha256 = crypto.createHash("sha256").update(approvalBytes).digest("hex");
  writePermissionPair(permissionPath, permissionSignaturePath, report);
  const brokerPackagePath = path.join(directory, "broker.zip");
  fs.copyFileSync(brokerFixture.package.path, brokerPackagePath); fs.chmodSync(brokerPackagePath, 0o600);
  const brokerBytes = fs.readFileSync(brokerPackagePath);
  const brokerPackageManifestPath = `${brokerPackagePath}.manifest.json`;
  fs.copyFileSync(brokerFixture.manifest.path, brokerPackageManifestPath); fs.chmodSync(brokerPackageManifestPath, 0o600);
  const stageAStateBackupPath = path.join(directory, "stage-a-state.json");
  fs.writeFileSync(stageAStateBackupPath, JSON.stringify({ lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 35 }), { mode: 0o600 });
  const stageAInputPath = path.join(directory, "stage-a-prerequisites.json");
  const fixtureVpcId = ["vpc-", "0123456789abcdef0"].join("");
  const fixtureSecretArn = (suffix) => ["arn", "aws", "secretsmanager", "eu-west-2", STAGE_B.account, "secret", suffix].join(":");
  const stageAInput = {
    schemaVersion: 3, generator: "scripts/aws/generate-production-green-stage-a-prerequisites.mjs", toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 35, stageAStateSha256: stageAStateSemanticSha256(JSON.parse(fs.readFileSync(stageAStateBackupPath, "utf8"))),
    networkEvidence: { vpcId: fixtureVpcId, privateSubnets: STAGE_B.privateSubnetIds.map((subnetId, index) => ({ subnetId, availabilityZone: `eu-west-2${index ? "b" : "a"}`, cidrBlock: `10.0.${index}.0/24`, routeTableId: "rtb-12345678", natGatewayId: "nat-12345678" })), securityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((groupId) => ({ groupId, vpcId: fixtureVpcId })), ecsClusterArn: STAGE_B.clusterArn, databaseIdentifier: "mscqr-production-rls-green", rdsSubnetIds: STAGE_B.privateSubnetIds },
    accountId: STAGE_B.account, region: STAGE_B.region, vpcId: fixtureVpcId, privateSubnetIds: STAGE_B.privateSubnetIds, ecsClusterArn: STAGE_B.clusterArn, stageADatabaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, stageAExecutorSecurityGroupId: STAGE_B.executorSecurityGroupId, stageAExecutorTaskRoleArn: STAGE_B.executorRoleArn, stageABrokerRoleArn: STAGE_B.brokerRoleArn, stageAExecutorLogGroupName: "/ecs/mscqr-production/full-rls-green", stageAExecutorLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*", stageABrokerLogGroupName: "/aws/lambda/mscqr-production-rls-approval-broker", stageABrokerLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*", stageARuntimeSecretArns: Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, fixtureSecretArn(`mscqr/production/rls-green/phase2/database-url/${role}-abc123`)])), stageAExecutorNetworkingReady: true, approvalSecretArn: STAGE_B.approvalSecretArn, approvalKmsKeyArn: STAGE_B.approvalKmsKeyArn, receiptBucketArn: `arn:aws:s3:::${STAGE_B.receiptBucket}`, stageAReadOnlyCanaryDatabaseSecretArn: fixtureSecretArn("mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123"),
  };
  fs.writeFileSync(stageAInputPath, `${JSON.stringify(stageAInput)}\n`, { mode: 0o600 });
  const tfvarsPath = path.join(directory, "canonical.tfvars");
  const tfvarsValues = Object.fromEntries([
    ["backend_image", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "a".repeat(64)],
    ["worker_image", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:" + "b".repeat(64)],
    ["executor_image", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "c".repeat(64)],
    ["canary_image", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "d".repeat(64)],
    ["read_only_canary_image", "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:" + "d".repeat(64)],
  ]);
  const tfvarsBytes = Buffer.from(["broker_package_path = " + JSON.stringify(brokerPackagePath), ...Object.entries(tfvarsValues).map(([key, value]) => key + " = " + JSON.stringify(value)), ""].join("\n"));
  fs.writeFileSync(tfvarsPath, tfvarsBytes, { mode: 0o600 });
  const tfvarsBindingReport = {
    schemaVersion: 2, tfvarsSchemaVersion: 1, generator: "scripts/aws/generate-production-green-stage-b-tfvars.mjs",
    tfvarsFormat: "hcl", tfvarsFileName: path.basename(tfvarsPath), tfvarsExtension: ".tfvars",
    toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), imageReleaseSha: "a".repeat(40), imageEvidenceCanonicalSha256: canonicalImageEvidenceSha256,
    stageAInputPath, stageAInputSha256: crypto.createHash("sha256").update(fs.readFileSync(stageAInputPath)).digest("hex"), stageAStateBackupPath, stageAStateBackupSha256: stageAStateSemanticSha256(JSON.parse(fs.readFileSync(stageAStateBackupPath, "utf8"))), stageAStateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 35, stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stateSerial: 76, brokerPackagePath, brokerPackageManifestPath, brokerPackageManifestSha256: crypto.createHash("sha256").update(fs.readFileSync(brokerPackageManifestPath)).digest("hex"), brokerPackageManifestFormat: "stage-b-broker-zip-v2",
    brokerPackageRawSha256: crypto.createHash("sha256").update(brokerBytes).digest("hex"), brokerPackageBase64Sha256: crypto.createHash("sha256").update(brokerBytes).digest("base64"), recoveryMode: "NORMAL",
    tfvarsSha256: crypto.createHash("sha256").update(tfvarsBytes).digest("hex"),
    images: Object.fromEntries(Object.entries(tfvarsValues).map(([variable, imageReference]) => [variable === "read_only_canary_image" ? "readOnlyCanary" : variable.replace(/_image$/, ""), { terraformVariable: variable, service: variable === "worker_image" ? "worker" : variable === "executor_image" ? "rls-executor" : variable.includes("canary") ? "rls-canary" : "backend", repository: variable === "worker_image" ? "mscqr-worker" : "mscqr-backend", tag: "a".repeat(40), imageReference, digestLength: 71, digest: imageReference.slice(imageReference.indexOf("@") + 1), matchesEvidence: true }])),
  };
  const tfvarsBindingReportPath = path.join(directory, "canonical.binding.json");
  const stageBStateBackupPath = path.join(directory, "stage-b-state.json");
  const stageBStateBytes = Buffer.from(JSON.stringify({ lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 76, resources: [] }));
  fs.writeFileSync(stageBStateBackupPath, stageBStateBytes, { mode: 0o600 });
  tfvarsBindingReport.stateBackupSha256 = crypto.createHash("sha256").update(stageBStateBytes).digest("hex");
  fs.writeFileSync(tfvarsBindingReportPath, JSON.stringify(tfvarsBindingReport) + "\n", { mode: 0o600 });
  const tfvarsBindingReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(tfvarsBindingReportPath)).digest("hex");
  const refreshReportPath = path.join(directory, "refresh.json");
  const checks = [...STAGE_B_EXPECTED_CHECK_ADDRESSES, ...STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES, ...STAGE_B_EXPECTED_RESOURCE_PRECONDITION_ADDRESSES].map((address) => ({ address: address.startsWith("aws_") ? { kind: "resource", mode: "managed", type: address.split(".")[0], name: address.split(".")[1], to_display: address } : address, status: "pass", instances: [{ address: address.startsWith("aws_") ? { to_display: address } : address, status: "pass" }] }));
  const checkProof = inspectStageBRefreshChecks({ checks });
  const refreshReport = { schemaVersion: 1, status: "NO_CHANGES", deployablePlan: false, acquisitionStatus: "valid", terraformVersion: "1.15.7", terraformVersionSha256: crypto.createHash("sha256").update("1.15.7").digest("hex"), formatVersion: "1.2", planCommandExitCode: 0, showCommandExitCode: 0, refreshPlanPath: path.join(directory, ".stage-b-refresh", "refresh-only.tfplan"), refreshPlanSha256: "a".repeat(64), refreshPlanJsonSha256: "b".repeat(64), showStdoutSha256: "b".repeat(64), showStderrSha256: "c".repeat(64), toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), tfvarsSha256: tfvarsBindingReport.tfvarsSha256, bindingReportSha256: tfvarsBindingReportSha256, imageEvidenceSha256: canonicalImageEvidenceSha256, stageAStateSha256: tfvarsBindingReport.stageAStateBackupSha256, stageAStateLineage: tfvarsBindingReport.stageAStateLineage, stageAStateSerial: tfvarsBindingReport.stageAStateSerial, stageBStateSha256: tfvarsBindingReport.stateBackupSha256, stageBStateLineage: tfvarsBindingReport.stateLineage, stageBStateSerial: tfvarsBindingReport.stateSerial, backendMetadataSha256: "m".repeat(64), backendMetadataPath: path.join(directory, "terraform.tfstate"), backendMetadataMode: "0600", privateModeValidated: true, terraformDataDir: directory, workspace: "default", checkCount: checkProof.checkCount, infrastructureCheckCount: checkProof.infrastructureCheckCount, variableCheckCount: checkProof.variableCheckCount, resourcePreconditionCheckCount: checkProof.resourcePreconditionCheckCount, passedCheckCount: checkProof.passedCheckCount, failedCheckCount: checkProof.failedCheckCount, malformedCheckCount: checkProof.malformedCheckCount, missingCheckCount: checkProof.missingCheckCount, unknownCheckCount: checkProof.unknownCheckCount, duplicateCheckCount: checkProof.duplicateCheckCount, checkInventoryHash: checkProof.checkInventoryHash, emittedInstanceCount: checkProof.emittedInstanceCount, passedInstanceCount: checkProof.passedInstanceCount, failedInstanceCount: checkProof.failedInstanceCount, malformedInstanceCount: checkProof.malformedInstanceCount, duplicateInstanceCount: checkProof.duplicateInstanceCount, instanceInventoryHash: checkProof.instanceInventoryHash, failedChecks: [], checks: checkProof.checks, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] };
  fs.writeFileSync(refreshReportPath, `${JSON.stringify(refreshReport)}\n`, { mode: 0o600 });
  const actualRefreshReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(refreshReportPath)).digest("hex");
  approvalBytes = Buffer.from(`${JSON.stringify({ ...approval, refreshReportSha256: actualRefreshReportSha256 }, null, 2)}\n`);
  writePrivate(planApprovalReportPath, approvalBytes);
  report.planApprovalReportSha256 = crypto.createHash("sha256").update(approvalBytes).digest("hex");
  report.planCapabilities.mutationManifest = createStageBMutationManifest(JSON.parse(fs.readFileSync(planJsonPath, "utf8")), manifest, {
    planProfile: report.planProfile,
    planSha256: report.planSha256,
    savedPlanSha256: report.savedPlanSha256,
    canonicalPlanJsonSha256: report.canonicalPlanJsonSha256,
    planApprovalReportSha256: report.planApprovalReportSha256,
    toolingSha: report.toolingSha,
    terraformConfiguration: fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8"),
  });
  writePermissionPair(permissionPath, permissionSignaturePath, report);
  return { directory, planPath, planJsonPath, canonicalPlanJsonPath, planApprovalReportPath, planApprovalReportSha256: crypto.createHash("sha256").update(approvalBytes).digest("hex"), auditPath, permissionReportPath: permissionPath, permissionReportSignaturePath: permissionSignaturePath, permissionReportSha256: crypto.createHash("sha256").update(fs.readFileSync(permissionPath)).digest("hex"), permissionReportSignatureSha256: crypto.createHash("sha256").update(fs.readFileSync(permissionSignaturePath)).digest("hex"), imageEvidencePath, imageEvidenceSha256: canonicalImageEvidenceSha256, imageEvidenceSignaturePath, imageEvidenceWorkflowRunId: imageEvidence.workflowRunId, imageEvidenceArtifactSha256: imageEvidence.canonicalArtifactSha256, planHash, auditHash: crypto.createHash("sha256").update(auditBytes).digest("hex"), savedHash, canonicalHash, shownBytes: Buffer.from(JSON.stringify(effectiveShownPlan)), verifyImageEvidence: () => true, tfvarsPath, tfvarsBindingReportPath, tfvarsBindingReportSha256, refreshReportPath, refreshReportSha256: crypto.createHash("sha256").update(fs.readFileSync(refreshReportPath)).digest("hex"), stageBStateBackupPath, stageAInputPath, stageAStateBackupPath, brokerPackagePath, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), toolingTreeSha256: "e".repeat(64) };
}

const planBoundPermissionInput = (fixture) => {
  const currentNow = new Date().toISOString();
  const planBytes = fs.readFileSync(fixture.planJsonPath);
  const approvalReportBytes = fs.readFileSync(fixture.planApprovalReportPath);
  const referenceAuditBytes = fs.readFileSync(fixture.auditPath);
  return {
    reportGeneratorCallerArn: generatorArn,
    simulatedRoleArn: roleArn,
    manifest,
    plan: JSON.parse(planBytes),
    planBytes,
    canonicalPlanJsonBytes: fs.readFileSync(fixture.canonicalPlanJsonPath),
    savedPlanBytes: fs.readFileSync(fixture.planPath),
    planApprovalReport: JSON.parse(approvalReportBytes),
    planApprovalReportBytes: approvalReportBytes,
    planApprovalReportSha256: fixture.planApprovalReportSha256,
    referenceAudit: JSON.parse(referenceAuditBytes),
    referenceAuditBytes,
    generatedAt: currentNow,
    now: currentNow,
    policyPublishedAt: currentNow,
    cloudTrailSessionName: "test",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  };
};

const rebindPlanBoundPermissionInput = (input, plan, audit = input.referenceAudit, { bindAuditToPlan = true } = {}) => {
  const planBytes = Buffer.from(JSON.stringify(plan));
  const planJsonSha256 = crypto.createHash("sha256").update(planBytes).digest("hex");
  const canonicalPlanJsonBytes = Buffer.from(`${canonicalizeJson(plan)}\n`);
  const canonicalPlanFileSha256 = crypto.createHash("sha256").update(canonicalPlanJsonBytes).digest("hex");
  const logicalCanonicalPlanJsonSha256 = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(plan))).digest("hex");
  const boundAudit = { ...audit, ...(bindAuditToPlan ? { planJsonSha256 } : {}) };
  const referenceAuditBytes = Buffer.from(JSON.stringify(boundAudit));
  const approval = { ...input.planApprovalReport, planJsonSha256, canonicalPlanFileSha256, logicalCanonicalPlanJsonSha256, referenceAuditSha256: crypto.createHash("sha256").update(referenceAuditBytes).digest("hex") };
  const planApprovalReportBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  return { ...input, plan, planBytes, canonicalPlanJsonBytes, planApprovalReport: approval, planApprovalReportBytes, planApprovalReportSha256: crypto.createHash("sha256").update(planApprovalReportBytes).digest("hex"), referenceAudit: boundAudit, referenceAuditBytes };
};

test("plan-bound BASELINE permission preflight requires an exact structural reference audit", () => {
  const fixture = wrapperFixture();
  const valid = planBoundPermissionInput(fixture);
  assert.doesNotThrow(() => runPermissionPreflight(valid));
  assert.throws(() => runPermissionPreflight({ ...valid, referenceAudit: undefined, referenceAuditBytes: undefined }), /requires the bound reference audit/);
  assert.throws(() => runPermissionPreflight({ ...valid, referenceAudit: undefined }), /object and bytes/);
  assert.throws(() => runPermissionPreflight({ ...valid, referenceAuditBytes: undefined }), /object and bytes/);
  assert.throws(() => runPermissionPreflight({ ...valid, referenceAuditBytes: Buffer.from(`${JSON.stringify(valid.referenceAudit)}\n`) }), /reference-audit SHA256/);

  const mismatchedAudit = { ...valid.referenceAudit, planJsonSha256: "0".repeat(64) };
  assert.throws(() => runPermissionPreflight(rebindPlanBoundPermissionInput(valid, valid.plan, mismatchedAudit, { bindAuditToPlan: false })), /different plan JSON/);

  const missingAddress = structuredClone(valid.plan);
  missingAddress.resource_changes = missingAddress.resource_changes.filter((change) => change.address !== "aws_dynamodb_table.replay");
  assert.throws(() => runPermissionPreflight(rebindPlanBoundPermissionInput(valid, missingAddress)), /canonical address set|mutation census/);

  const arbitraryAddress = structuredClone(valid.plan);
  arbitraryAddress.resource_changes.push({ address: "aws_s3_bucket.unreviewed", type: "aws_s3_bucket", change: { actions: ["no-op"] } });
  assert.throws(() => runPermissionPreflight(rebindPlanBoundPermissionInput(valid, arbitraryAddress)), /canonical address set|mutation census/);

  const retainedAddress = 'aws_ecs_task_definition.candidate_retained["abcdef1-backend"]';
  const retainedPlan = structuredClone(valid.plan);
  retainedPlan.resource_changes.push({ address: retainedAddress, type: "aws_ecs_task_definition", change: { actions: ["no-op"] } });
  const retainedAudit = { ...valid.referenceAudit, retainedTaskDefinitions: [...valid.referenceAudit.retainedTaskDefinitions, { terraformAddress: retainedAddress, family: STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["backend"]'], classification: "retained-no-op", oldTaskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["backend"]']}:999999` }] };
  assert.doesNotThrow(() => runPermissionPreflight(rebindPlanBoundPermissionInput(valid, retainedPlan, retainedAudit)));
});

const wrapperArgs = (fixture, verifyOnly = false) => [
  ...(verifyOnly ? ["--verify-only"] : []),
  "--closure-mode", "production",
  "--plan", fixture.planPath, "--plan-json", fixture.planJsonPath, "--canonical-plan-json", fixture.canonicalPlanJsonPath, "--plan-approval-report", fixture.planApprovalReportPath, "--plan-approval-report-sha256", fixture.planApprovalReportSha256, "--reference-audit", fixture.auditPath,
  "--permission-report", fixture.permissionReportPath, "--permission-report-sha256", fixture.permissionReportSha256, "--permission-report-signature", fixture.permissionReportSignaturePath, "--permission-report-signature-sha256", fixture.permissionReportSignatureSha256,
  "--image-evidence", fixture.imageEvidencePath, "--image-evidence-sha256", fixture.imageEvidenceSha256, "--image-evidence-signature", fixture.imageEvidenceSignaturePath, "--image-evidence-workflow-run-id", fixture.imageEvidenceWorkflowRunId, "--image-evidence-artifact-sha256", fixture.imageEvidenceArtifactSha256,
  "--tooling-sha", "b".repeat(40), "--image-release-sha", "a".repeat(40), "--tfvars", fixture.tfvarsPath, "--tfvars-binding-report", fixture.tfvarsBindingReportPath, "--tfvars-binding-report-sha256", fixture.tfvarsBindingReportSha256, "--tooling-tree-sha256", fixture.toolingTreeSha256,
  "--refresh-report", fixture.refreshReportPath, "--refresh-report-sha256", fixture.refreshReportSha256,
  ...(fixture.refreshBindingReportPath ? ["--refresh-binding-report", fixture.refreshBindingReportPath, "--refresh-binding-report-sha256", fixture.refreshBindingReportSha256] : []),
  "--plan-sha256", fixture.planHash, "--audit-sha256", fixture.auditHash, "--saved-plan-sha256", fixture.savedHash, "--canonical-plan-json-sha256", fixture.canonicalHash,
];
const rebindApprovalAudit = (fixture, auditBytes) => {
  const approval = JSON.parse(fs.readFileSync(fixture.planApprovalReportPath));
  approval.referenceAuditSha256 = crypto.createHash("sha256").update(auditBytes).digest("hex");
  const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  writePrivate(fixture.planApprovalReportPath, approvalBytes);
  fixture.planApprovalReportSha256 = crypto.createHash("sha256").update(approvalBytes).digest("hex");
};

const createValidStageBApplyFixture = (options = {}) => ({
  ...wrapperFixture(options),
  sharedReservations: new Map(),
  protectedMainCheckout: buildStageBProtectedMainCheckoutEvidence({
    toolingSha: "b".repeat(40),
    currentHead: "b".repeat(40),
    originMainHead: "b".repeat(40),
    isAncestor: true,
    porcelainStatus: "",
    repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false },
    mode: "production",
  }),
});

const validApplyInput = (fixture) => ({
  argv: wrapperArgs(fixture, true),
  env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
  deps: {
    getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
    getProtectedMainCheckout: () => fixture.protectedMainCheckout,
    showPlan: () => fixture.shownBytes,
    validatePlan: () => {},
    verifyPermissionSignature: () => true,
    verifyImageEvidence: fixture.verifyImageEvidence,
    getBackendMetadata: () => structuredClone(initializedBackendMetadata),
    apply: () => { throw new Error("apply must not be reached"); },
  },
});

const validRealApplyInput = (fixture, checkoutReads = [fixture.protectedMainCheckout, fixture.protectedMainCheckout]) => {
  const reads = [...checkoutReads];
  const applyCalls = [];
  let checkoutReadCount = 0;
  return {
    argv: wrapperArgs(fixture),
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
    deps: {
      getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
      getProtectedMainCheckout: () => {
        const checkout = reads.shift();
        checkoutReadCount += 1;
        if (!checkout) throw new Error("Unexpected protected-main checkout read in test fixture.");
        return checkout;
      },
      showPlan: () => fixture.shownBytes,
      validatePlan: () => {},
      verifyPermissionSignature: () => true,
      verifyImageEvidence: fixture.verifyImageEvidence,
      getBackendMetadata: () => structuredClone(initializedBackendMetadata),
      getEffectiveOperatorHome: () => fixture.directory,
      reserveSharedApplyAttempt: ({ artifactSetIdentity, bytes }) => {
        if (fixture.sharedReservations.has(artifactSetIdentity)) throw new Error("shared reservation already exists");
        fixture.sharedReservations.set(artifactSetIdentity, Buffer.from(bytes));
        return { status: "reserved", key: stageBApplyAttemptS3Key(artifactSetIdentity) };
      },
      reserveApplyAttemptTransition: ({ attemptId, sequence, bytes }) => {
        fixture.sharedReservations.set(`${attemptId}/${sequence}`, Buffer.from(bytes));
        return { status: "reserved", key: stageBAttemptStepS3ObjectKey(attemptId, sequence) };
      },
      apply: (planPath) => {
        applyCalls.push(planPath);
        return { status: 0 };
      },
    },
    applyCalls,
    get checkoutReadCount() { return checkoutReadCount; },
  };
};

const changedPaths = (before, after, prefix = "") => {
  if (Object.is(before, after)) return [];
  if (before && after && typeof before === "object" && typeof after === "object" && !Array.isArray(before) && !Array.isArray(after)) {
    return [...new Set([...Object.keys(before), ...Object.keys(after)])].flatMap((key) => changedPaths(before[key], after[key], prefix ? `${prefix}.${key}` : key));
  }
  return [prefix];
};

const assertSingleFailureMutation = ({ baseline, mutated, changedFields }) => {
  assert.deepEqual(changedPaths(baseline, mutated).sort(), [...changedFields].sort());
};

test("missing permission report remains an artifact-gate failure", () => {
  const fixture = createValidStageBApplyFixture();
  fs.unlinkSync(fixture.permissionReportPath);
  assert.throws(() => runApply(validApplyInput(fixture)), (error) => error instanceof Error && error.message === "Permission-preflight report is missing.");
});

test("valid Stage B apply fixture reaches ready-to-apply before checkout mutation", () => {
  const fixture = createValidStageBApplyFixture();
  assert.equal(runApply(validApplyInput(fixture)).status, "ready-to-apply");
});

test("valid non-verify-only apply path calls the injected apply stub exactly once", () => {
  const fixture = createValidStageBApplyFixture();
  const input = validRealApplyInput(fixture);
  assert.equal(runApply(input).status, "applied-saved-plan");
  assert.equal(input.checkoutReadCount, 2);
  assert.deepEqual(input.applyCalls, [fixture.planPath]);
});

test("exact PARTIAL_APPLY_RECOVERY artifact set reaches the apply seam without ECS mutation authority", () => {
  const fixture = createValidStageBApplyFixture();
  const testNow = new Date().toISOString();
  const partialPlan = structuredClone(JSON.parse(fs.readFileSync(fixture.planJsonPath)));
  partialPlan.variables.stage_b_recovery_only = { value: false };
  for (const change of partialPlan.resource_changes) {
    if (change.address === 'aws_ecs_task_definition.candidate["backend"]' || change.address === "aws_iam_policy.broker" || change.address === "aws_iam_role_policy.backend_ecs_exec") change.change = { ...change.change, actions: ["no-op"] };
    else if (change.address === "aws_lambda_function.broker" || change.address === "aws_lambda_alias.reviewed") change.change = { ...change.change, actions: ["update"] };
    else if (Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, change.address)) {
      const family = STAGE_B_TASK_DEFINITION_FAMILIES[change.address];
      const before = { ...(change.change.before || change.change.after || {}), family, arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:9`, skip_destroy: true };
      change.change = { ...change.change, actions: ["delete"], before, after: null, after_unknown: {}, after_sensitive: {} };
      change.mode = "managed";
      change.deposed = "a".repeat(8);
    }
  }
  const partialPlanBytes = Buffer.from(`${JSON.stringify(partialPlan)}\n`);
  const partialCanonicalBytes = Buffer.from(`${canonicalizeJson(partialPlan)}\n`);
  const partialHashes = { savedPlanSha256: fixture.savedHash, planJsonSha256: crypto.createHash("sha256").update(partialPlanBytes).digest("hex"), canonicalPlanFileSha256: crypto.createHash("sha256").update(partialCanonicalBytes).digest("hex"), logicalCanonicalPlanJsonSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(partialPlan))).digest("hex") };
  const audit = { ...JSON.parse(fs.readFileSync(fixture.auditPath)), planJsonSha256: partialHashes.planJsonSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", auditedAt: testNow };
  const auditBytes = Buffer.from(`${JSON.stringify(audit)}\n`);
  const capture = createStageBPlanCaptureReport({ toolingSha: fixture.toolingSha, toolingTreeSha256: fixture.toolingTreeSha256, refreshReportSha256: fixture.refreshReportSha256, refreshBindingReportSha256: "r".repeat(64), hashes: partialHashes, capturedAt: testNow, stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 96, terraformVersion: "1.15.7", terraformFormatVersion: "1.2", classification: { noOp: partialPlan.resource_changes.filter(({ change }) => JSON.stringify(change.actions) === JSON.stringify(["no-op"])).length, create: 0, replacement: 0, update: 2, destroy: 11, unclassified: 0 }, planProfile: "PARTIAL_APPLY_RECOVERY", brokerEvidence: { brokerOperation: "partial-apply-recovery", brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: ["aws_lambda_alias.reviewed", "aws_lambda_function.broker"], brokerReferenceValidationPending: true } });
  const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  const approval = createStageBPlanApprovalReport({ captureReportSha256: crypto.createHash("sha256").update(captureBytes).digest("hex"), referenceAuditPath: fixture.auditPath, referenceAuditSha256: crypto.createHash("sha256").update(auditBytes).digest("hex"), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: testNow, toolingSha: fixture.toolingSha, toolingTreeSha256: fixture.toolingTreeSha256, refreshReportSha256: fixture.refreshReportSha256, refreshBindingReportSha256: capture.refreshBindingReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: 96, hashes: partialHashes, logicalCanonicalPlanJsonSha256: partialHashes.logicalCanonicalPlanJsonSha256, approvedAt: testNow, classification: capture.classification, planProfile: "PARTIAL_APPLY_RECOVERY", brokerOperation: capture.brokerOperation, brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: capture.brokerResourceAddresses });
  const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  writePrivate(fixture.planJsonPath, partialPlanBytes); writePrivate(fixture.canonicalPlanJsonPath, partialCanonicalBytes); writePrivate(fixture.auditPath, auditBytes); writePrivate(fixture.planApprovalReportPath, approvalBytes); fixture.planHash = partialHashes.planJsonSha256; fixture.canonicalHash = partialHashes.logicalCanonicalPlanJsonSha256; fixture.auditHash = crypto.createHash("sha256").update(auditBytes).digest("hex"); fixture.planApprovalReportSha256 = crypto.createHash("sha256").update(approvalBytes).digest("hex"); fixture.shownBytes = partialPlanBytes;
  const observationPath = path.join(fixture.directory, "observation.binding.json");
  const contract = deriveContractDigests();
  const binding = { ...JSON.parse(fs.readFileSync(fixture.tfvarsBindingReportPath)), stateSerial: 96, sourceContractSha256: contract.sourceContractSha256, migrationSetDigest: contract.migrationSetDigest, packageChecksumSha256: contract.packageChecksumSha256 };
  const stateBytes = Buffer.from(JSON.stringify({ lineage: binding.stateLineage, serial: 96, resources: [] })); fs.writeFileSync(path.join(fixture.directory, "stage-b-state.json"), stateBytes, { mode: 0o600 }); binding.stateBackupSha256 = crypto.createHash("sha256").update(stateBytes).digest("hex");
  const partialRecoveryState = {
    lineage: binding.stateLineage,
    serial: 96,
    resources: [
      { mode: "managed", type: "aws_ecs_task_definition", name: "candidate_retained", instances: ["backend", "worker", "canary"].map((kind) => ({ index_key: `b2b1017-${kind}`, attributes: { arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${STAGE_B_TASK_DEFINITION_FAMILIES[`aws_ecs_task_definition.candidate[\"${kind}\"]`]}:5`, family: STAGE_B_TASK_DEFINITION_FAMILIES[`aws_ecs_task_definition.candidate[\"${kind}\"]`], revision: 5, network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: 1024, memory: 2048, container_definitions: JSON.stringify([{ name: kind, image: "example" }]), volume: [] } })) },
      { mode: "managed", type: "aws_ecs_task_definition", name: "executor_retained", instances: ["admin-bootstrap", "admin-ownership", "capability-preflight", "role-provision", "role-verify", "rollback", "runtime-policy", "verification"].map((mode) => ({ index_key: `b2b1017-full-rls-${mode}`, attributes: { arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${STAGE_B_TASK_DEFINITION_FAMILIES[`aws_ecs_task_definition.executor[\"full-rls-${mode}\"]`]}:5`, family: STAGE_B_TASK_DEFINITION_FAMILIES[`aws_ecs_task_definition.executor[\"full-rls-${mode}\"]`], revision: 5, network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: 1024, memory: 2048, container_definitions: JSON.stringify([{ name: mode, image: "example" }]), volume: [] } })) },
      { type: "aws_iam_policy", name: "broker", instances: [{ attributes: { arn: STAGE_B_BROKER_POLICY.arn } }] },
      { type: "aws_iam_role_policy_attachment", name: "broker", instances: [{ attributes: { policy_arn: STAGE_B_BROKER_POLICY.arn, role: STAGE_B_BROKER_POLICY.roleName } }] },
    ],
  };
  writePrivate(fixture.stageBStateBackupPath, `${JSON.stringify(partialRecoveryState)}\n`);
  const partialStateSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.stageBStateBackupPath)).digest("hex");
  binding.stateBackupSha256 = partialStateSha256;
  const observationPackagePath = path.join(fixture.directory, "observation-broker.zip");
  fs.copyFileSync(fixture.brokerPackagePath, observationPackagePath); fs.chmodSync(observationPackagePath, 0o600); fs.copyFileSync(`${fixture.brokerPackagePath}.manifest.json`, `${observationPackagePath}.manifest.json`); fs.chmodSync(`${observationPackagePath}.manifest.json`, 0o600);
  const observationTfvarsPath = path.join(fixture.directory, "observation.tfvars");
  const observationGenerated = generateStageBTfvars({ imageEvidence: fixture.imageEvidencePath, imageEvidenceSignature: fixture.imageEvidenceSignaturePath, stateBackup: fixture.stageBStateBackupPath, stageAInput: fixture.stageAInputPath, stageAStateBackup: fixture.stageAStateBackupPath, brokerPackagePath: observationPackagePath, toolingSha: fixture.toolingSha, toolingTreeSha256: fixture.toolingTreeSha256, imageReleaseSha: fixture.imageReleaseSha, workflowRunId: fixture.imageEvidenceWorkflowRunId, canonicalArtifactSha256: fixture.imageEvidenceArtifactSha256, outputPath: observationTfvarsPath, bindingReportPath: observationPath, verifySignature: fixture.verifyImageEvidence });
  const observationBinding = observationGenerated.bindingReport;
  fixture.refreshBindingReportPath = observationPath; fixture.refreshBindingReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(observationPath)).digest("hex");
  capture.refreshBindingReportSha256 = fixture.refreshBindingReportSha256;
  const boundCaptureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  approval.captureReportSha256 = crypto.createHash("sha256").update(boundCaptureBytes).digest("hex");
  approval.refreshBindingReportSha256 = fixture.refreshBindingReportSha256;
  const refresh = JSON.parse(fs.readFileSync(fixture.refreshReportPath)); Object.assign(refresh, { status: "RESOURCE_DRIFT", resourceChanges: { nonNoOp: 1, changes: [{ address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", actions: ["update"] }] }, bindingReportSha256: fixture.refreshBindingReportSha256, tfvarsSha256: observationBinding.tfvarsSha256, stageBStateSerial: 96, stageBStateSha256: partialStateSha256, stateBackupSha256: partialStateSha256 });
  writePrivate(fixture.refreshReportPath, `${JSON.stringify(refresh)}\n`); fixture.refreshReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.refreshReportPath)).digest("hex");
  Object.assign(refresh, { bindingReportSha256: fixture.refreshBindingReportSha256, stageBStateSha256: partialStateSha256, stateBackupSha256: partialStateSha256 });
  writePrivate(fixture.refreshReportPath, `${JSON.stringify(refresh)}\n`);
  fixture.refreshReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.refreshReportPath)).digest("hex");
  const generatedPartial = generateStageBTfvars({ imageEvidence: fixture.imageEvidencePath, imageEvidenceSignature: fixture.imageEvidenceSignaturePath, stateBackup: fixture.stageBStateBackupPath, stageAInput: fixture.stageAInputPath, stageAStateBackup: fixture.stageAStateBackupPath, brokerPackagePath: fixture.brokerPackagePath, toolingSha: fixture.toolingSha, toolingTreeSha256: fixture.toolingTreeSha256, imageReleaseSha: fixture.imageReleaseSha, workflowRunId: fixture.imageEvidenceWorkflowRunId, canonicalArtifactSha256: fixture.imageEvidenceArtifactSha256, outputPath: fixture.tfvarsPath, bindingReportPath: fixture.tfvarsBindingReportPath, allowOverwrite: true, verifySignature: fixture.verifyImageEvidence, partialApplyRecovery: true, recovery: { refreshReportPath: fixture.refreshReportPath, observationBindingPath: observationPath } });
  assert.equal(generatedPartial.bindingReport.partialApplyRecovery, true);
  assert.equal(generatedPartial.bindingReport.recoveryRefreshReportSha256, fixture.refreshReportSha256);
  fixture.tfvarsBindingReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.tfvarsBindingReportPath)).digest("hex");
  approval.refreshReportSha256 = fixture.refreshReportSha256; const refreshedApprovalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`); writePrivate(fixture.planApprovalReportPath, refreshedApprovalBytes); fixture.planApprovalReportSha256 = crypto.createHash("sha256").update(refreshedApprovalBytes).digest("hex");
  const permissionInput = planBoundPermissionInput(fixture); const permission = runPermissionPreflight(permissionInput); writePermissionPair(fixture.permissionReportPath, fixture.permissionReportSignaturePath, permission); fixture.permissionReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportPath)).digest("hex"); fixture.permissionReportSignatureSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportSignaturePath)).digest("hex");
  const input = validRealApplyInput(fixture); let validationOptions; input.deps.validatePlan = (_plan, options) => { validationOptions = options; return { classifiedResources: partialPlan.resource_changes.filter((change) => change.change.actions[0] === "delete").map((change) => ({ address: change.address, deposed: change.deposed, actions: change.change.actions, classification: "partial-apply-deposed-task-definition-cleanup" })) }; }; let ecsRegistrations = 0; let ecsServiceUpdates = 0; input.deps.apply = (planPath) => { input.applyCalls.push(planPath); return { status: 0 }; };
  assert.equal(runApply(input).status, "applied-saved-plan"); assert.equal(input.applyCalls.length, 1); assert.equal(validationOptions.partialApplyRecovery, true); assert.equal(validationOptions.recoveryOnly, false); assert.equal(ecsRegistrations, 0); assert.equal(ecsServiceUpdates, 0);
});

test("apply attempt marker makes a second apply unreachable", () => {
  const fixture = createValidStageBApplyFixture();
  const first = validRealApplyInput(fixture);
  assert.equal(runApply(first).applyCalls, 1);
  const second = validRealApplyInput(fixture);
  assert.throws(() => runApply(second), /consumed|exist/i);
  assert.deepEqual(second.applyCalls, []);
});

test("shared reservation blocks the same artifact set across hosts, users, and local marker loss", () => {
  const fixture = createValidStageBApplyFixture();
  const first = validRealApplyInput(fixture);
  const result = runApply(first);
  fs.unlinkSync(result.applyAttemptPath);
  for (const environment of [
    { HOME: "/host-b/user-b", HOSTNAME: "host-b" },
    { HOME: "/runner/work", HOSTNAME: "github-runner", GITHUB_WORKSPACE: "/runner/work/repository" },
  ]) {
    const replay = validRealApplyInput(fixture);
    Object.assign(replay.env, environment);
    assert.throws(() => runApply(replay), /shared reservation already exists/);
    assert.deepEqual(replay.applyCalls, []);
  }
});

test("S3 reservation uses conditional create as the first authoritative gate and verifies its bytes", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-shared-reservation-"));
  const identity = "a".repeat(64); const bytes = Buffer.from("{\"attempt\":1}\n"); const calls = [];
  const result = reserveStageBSharedApplyAttempt({ artifactSetIdentity: identity, bytes, privateDirectory: directory, run: (args) => {
    calls.push(args);
    if (args[1] === "put-object") return { status: 0, stdout: "{}", stderr: "" };
    fs.writeFileSync(args.at(-1), bytes);
    return { status: 0, stdout: "{}", stderr: "" };
  } });
  assert.deepEqual(result, { status: "reserved", key: stageBApplyAttemptS3Key(identity) });
  assert.equal(calls[0].includes("--if-none-match"), true);
  assert.equal(calls[0][1], "put-object");
  assert.equal(calls[0][calls[0].indexOf("--if-none-match") + 1], "*");
  assert.equal(calls[0][calls[0].indexOf("--server-side-encryption") + 1], "AES256");
  assert.equal(calls[0][calls[0].indexOf("--key") + 1], stageBApplyAttemptS3Key(identity));
  assert.equal(calls[1][1], "get-object");
});

test("production command-runner string results are normalized before reservation decisions", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-shared-reservation-string-result-"));
  const identity = "c".repeat(64); const bytes = Buffer.from("{\"attempt\":1}\n");
  const result = reserveStageBSharedApplyAttempt({ artifactSetIdentity: identity, bytes, privateDirectory: directory, run: (args) => {
    if (args[1] === "get-object") fs.writeFileSync(args.at(-1), bytes);
    return "{}\n";
  } });
  assert.deepEqual(result, { status: "reserved", key: stageBApplyAttemptS3Key(identity) });
});

test("shared reservation 412, 409, outage, and readback mismatch fail closed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-shared-reservation-fail-"));
  const input = { artifactSetIdentity: "b".repeat(64), bytes: Buffer.from("{}\n"), privateDirectory: directory };
  for (const [stderr, pattern] of [
    ["PreconditionFailed (412)", /already exists/],
    ["ConditionalRequestConflict (409)", /concurrent conflict/],
    ["AccessDenied (403)", /could not be created/],
    ["ServiceUnavailable", /could not be created/],
  ]) assert.throws(() => reserveStageBSharedApplyAttempt({ ...input, run: () => ({ status: 1, stdout: "", stderr }) }), pattern);
  assert.throws(() => reserveStageBSharedApplyAttempt({ ...input, run: (args) => {
    if (args[1] === "put-object") return { status: 0, stdout: "{}", stderr: "" };
    fs.writeFileSync(args.at(-1), "different\n");
    return { status: 0, stdout: "{}", stderr: "" };
  } }), /readback verification failed/);
});

test("effective operator account fixes the attempt root across caller environment changes", () => {
  const original = { HOME: process.env.HOME, TMPDIR: process.env.TMPDIR, TMP: process.env.TMP, TEMP: process.env.TEMP, PWD: process.env.PWD };
  const originalCwd = process.cwd();
  const alternateCwd = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-attempt-cwd-"));
  try {
    Object.assign(process.env, { HOME: "/private/tmp/home-a", TMPDIR: "/private/tmp/tmp-a", TMP: "/private/tmp/tmp-a", TEMP: "/private/tmp/tmp-a", PWD: "/private/tmp/cwd-a" });
    const first = stageBEffectiveOperatorHome();
    process.chdir(alternateCwd);
    Object.assign(process.env, { HOME: "/private/tmp/home-b", TMPDIR: "/private/tmp/tmp-b", TMP: "/private/tmp/tmp-b", TEMP: "/private/tmp/tmp-b", PWD: "/private/tmp/cwd-b" });
    assert.equal(stageBEffectiveOperatorHome(), first);
    assert.equal(path.isAbsolute(first), true);
  } finally {
    process.chdir(originalCwd);
    for (const [key, value] of Object.entries(original)) value === undefined ? delete process.env[key] : process.env[key] = value;
  }
});

test("HOME, temporary-directory, and working-directory changes cannot relocate an artifact set", () => {
  const fixture = createValidStageBApplyFixture();
  const first = validRealApplyInput(fixture);
  Object.assign(first.env, { HOME: "/private/tmp/home-a", TMPDIR: "/private/tmp/tmp-a", PWD: "/private/tmp/cwd-a" });
  const marker = runApply(first).applyAttemptPath;
  const replay = validRealApplyInput(fixture);
  Object.assign(replay.env, { HOME: "/private/tmp/home-b", TMPDIR: "/private/tmp/tmp-b", PWD: "/private/tmp/cwd-b" });
  assert.throws(() => runApply(replay), /consumed|exist/i);
  assert.deepEqual(replay.applyCalls, []);
  assert.equal(marker.startsWith(path.join(fixture.directory, ".mscqr", "production-green-stage-b", "apply-attempts")), true);
});

test("caller-selected alternate apply-attempt paths cannot change the canonical reservation", () => {
  const fixture = createValidStageBApplyFixture();
  assert.equal(runApply(validRealApplyInput(fixture)).applyCalls, 1);
  for (const alternate of [path.join(fixture.directory, "alternate.json"), path.join(fixture.directory, "missing", "alternate.json"), "../escape.json", "/private/tmp/alternate.json"]) {
    const replay = validRealApplyInput(fixture);
    replay.argv.push("--apply-attempt", alternate);
    assert.throws(() => runApply(replay), /--apply-attempt is forbidden/);
    assert.deepEqual(replay.applyCalls, []);
  }
});

test("interrupted and successful applies leave the canonical artifact set permanently consumed", () => {
  for (const outcome of ["interrupted", "successful"]) {
    const fixture = createValidStageBApplyFixture();
    const first = validRealApplyInput(fixture);
    if (outcome === "interrupted") first.deps.apply = () => { throw new Error("simulated interruption"); };
    if (outcome === "interrupted") assert.throws(() => runApply(first), /simulated interruption/);
    else assert.equal(runApply(first).applyCalls, 1);
    const replay = validRealApplyInput(fixture);
    assert.throws(() => runApply(replay), /consumed|exist/i);
    assert.deepEqual(replay.applyCalls, []);
  }
});

test("mutation identity changes only with stable executable bindings", () => {
  const baseline = { protectedMainSha: "a".repeat(40), planSha256: "b".repeat(64), savedPlanSha256: "c".repeat(64), tfvarsSha256: "d".repeat(64), approvalSha256: "e".repeat(64), permissionEvidenceSha256: "f".repeat(64), mutationManifestSha256: "1".repeat(64), workspace: "default", backendIdentitySha256: "2".repeat(64) };
  const identity = stageBApplyArtifactSetIdentity(baseline);
  assert.equal(stageBApplyArtifactSetIdentity(structuredClone(baseline)), identity);
  for (const field of ["planSha256", "tfvarsSha256", "approvalSha256", "permissionEvidenceSha256", "mutationManifestSha256"]) assert.equal(stageBApplyArtifactSetIdentity({ ...baseline, [field]: "3".repeat(64) }), identity);
  for (const [field, value] of [["savedPlanSha256", "3".repeat(64)], ["protectedMainSha", "6".repeat(40)], ["backendIdentitySha256", "7".repeat(64)]]) {
    assert.notEqual(stageBApplyArtifactSetIdentity({ ...baseline, [field]: value }), identity);
  }
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-attempt-identity-"));
  const changed = stageBApplyArtifactSetIdentity({ ...baseline, savedPlanSha256: "3".repeat(64) });
  const firstPath = stageBApplyAttemptPath({ artifactSetIdentity: identity, effectiveOperatorHome: fixture });
  const changedPath = stageBApplyAttemptPath({ artifactSetIdentity: changed, effectiveOperatorHome: fixture });
  assert.equal(path.dirname(firstPath), path.dirname(changedPath));
  assert.notEqual(path.basename(firstPath), path.basename(changedPath));
});

test("RECOVERY_ALIAS_ONLY tfvars reserialization cannot mint another mutation right", () => {
  const stable = { planProfile: "RECOVERY_ALIAS_ONLY", savedPlanSha256: "a".repeat(64), tfvarsSha256: crypto.createHash("sha256").update("alias_version = 3\n").digest("hex"), protectedMainSha: "b".repeat(40), workspace: "default", backendIdentitySha256: "c".repeat(64) };
  const reserialized = { ...stable, tfvarsSha256: crypto.createHash("sha256").update("# same saved plan\nalias_version=3\n").digest("hex") };
  const identity = stageBApplyArtifactSetIdentity(stable);
  assert.equal(stageBApplyArtifactSetIdentity(reserialized), identity);
  assert.equal(stageBApplyAttemptS3Key(stageBApplyArtifactSetIdentity(reserialized)), stageBApplyAttemptS3Key(identity));
  const privateDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-recovery-tfvars-reserialization-"));
  assert.throws(() => reserveStageBSharedApplyAttempt({ artifactSetIdentity: stageBApplyArtifactSetIdentity(reserialized), bytes: Buffer.from("{}\n"), privateDirectory, run: () => ({ status: 1, stdout: "", stderr: "PreconditionFailed (412)" }) }), /already exists/);
});

test("renewed permission evidence cannot create a second mutation right", () => {
  const fixture = createValidStageBApplyFixture();
  const first = runApply(validRealApplyInput(fixture));
  const firstIdentity = first.executableAuditSha256;
  const report = JSON.parse(fs.readFileSync(fixture.permissionReportPath, "utf8"));
  report.generatedAt = new Date(Date.now() + 1_000).toISOString();
  writePermissionPair(fixture.permissionReportPath, fixture.permissionReportSignaturePath, report);
  fixture.permissionReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportPath)).digest("hex");
  fixture.permissionReportSignatureSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportSignaturePath)).digest("hex");
  fs.rmSync(path.join(fixture.directory, ".mscqr"), { recursive: true, force: true });
  const replay = validRealApplyInput(fixture);
  assert.throws(() => runApply(replay), /shared reservation already exists/);
  assert.equal([...fixture.sharedReservations.keys()][0], firstIdentity);
  assert.deepEqual(replay.applyCalls, []);
});

test("equivalent initialized-backend representations share one global reservation", () => {
  const fixture = createValidStageBApplyFixture();
  const equivalent = structuredClone(initializedBackendMetadata);
  equivalent.hash += 1;
  for (const [index, key] of Object.keys(equivalent.config).entries()) {
    if (["bucket", "key", "region", "encrypt", "use_lockfile"].includes(key)) continue;
    if (index % 2 === 0) delete equivalent.config[key];
    else equivalent.config[key] = "";
  }
  equivalent.config = Object.fromEntries(Object.entries(equivalent.config).reverse());
  const representationA = validApplyInput(fixture);
  const representationB = validApplyInput(fixture);
  representationB.deps.getBackendMetadata = () => structuredClone(equivalent);
  const identityA = runApply(representationA).executableAuditSha256;
  const identityB = runApply(representationB).executableAuditSha256;
  assert.equal(identityB, identityA);
  assert.equal(stageBApplyAttemptS3Key(identityB), stageBApplyAttemptS3Key(identityA));
  assert.equal(runApply(validRealApplyInput(fixture)).applyCalls, 1);
  fs.rmSync(path.join(fixture.directory, ".mscqr"), { recursive: true, force: true });
  const replay = validRealApplyInput(fixture);
  replay.deps.getBackendMetadata = () => structuredClone(equivalent);
  assert.throws(() => runApply(replay), /shared reservation already exists/);
  assert.deepEqual(replay.applyCalls, []);
});

test("effective operator lookup failure blocks Terraform spawn", () => {
  assert.throws(() => stageBEffectiveOperatorHome({ userInfo: () => { throw new Error("lookup unavailable"); } }), /could not resolve/);
  assert.throws(() => stageBEffectiveOperatorHome({ userInfo: () => ({ uid: -1, homedir: "relative" }) }), /missing or not absolute/);
  const fixture = createValidStageBApplyFixture();
  const input = validRealApplyInput(fixture);
  input.deps.getEffectiveOperatorHome = () => { throw new Error("operator lookup failed"); };
  assert.throws(() => runApply(input), /operator lookup failed/);
  assert.deepEqual(input.applyCalls, []);
});

test("exclusive apply-attempt reservation admits exactly one contender", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-apply-exclusive-"));
  const filePath = path.join(directory, "attempt.json");
  const reserve = () => writeStageBPrivateFileExclusive({ filePath, bytes: Buffer.from("{}\n"), repositoryRoot: process.cwd() });
  const results = await Promise.allSettled([Promise.resolve().then(reserve), Promise.resolve().then(reserve)]);
  assert.equal(results.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(results.filter(({ status }) => status === "rejected").length, 1);
});

test("canonical attempt path rejects symlink substitution and verify-only reserves nothing", () => {
  const fixture = createValidStageBApplyFixture();
  const readiness = runApply(validApplyInput(fixture));
  assert.equal(readiness.status, "ready-to-apply");
  assert.equal(readiness.reservationStatus, "not-authoritatively-readable");
  assert.equal(readiness.atomicReservationGate, "enforced-at-mutation-boundary");
  assert.equal(fixture.sharedReservations.size, 0);
  assert.equal(fs.existsSync(path.join(fixture.directory, ".mscqr")), false);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-attempt-outside-"));
  fs.symlinkSync(outside, path.join(fixture.directory, ".mscqr"));
  const input = validRealApplyInput(fixture);
  assert.throws(() => runApply(input), /non-symlink directory/);
  assert.deepEqual(input.applyCalls, []);
});

test("reservation failure occurs before Terraform spawn", () => {
  const fixture = createValidStageBApplyFixture();
  const input = validRealApplyInput(fixture);
  const events = [];
  input.deps.reserveSharedApplyAttempt = () => { events.push("shared-reserve"); throw new Error("reservation failed"); };
  input.deps.apply = () => { events.push("apply"); return { status: 0 }; };
  assert.throws(() => runApply(input), /reservation failed/);
  assert.deepEqual(events, ["shared-reserve"]);
});

test("local marker failure after shared reservation remains pre-Terraform and cannot be replayed implicitly", () => {
  const fixture = createValidStageBApplyFixture(); const input = validRealApplyInput(fixture); const events = [];
  input.deps.reserveApplyAttempt = () => { events.push("local-marker-failure"); throw new Error("local marker failure"); };
  input.deps.apply = () => { events.push("terraform"); return { status: 0 }; };
  assert.throws(() => runApply(input), /local marker failure/);
  assert.deepEqual(events, ["local-marker-failure"]);
  assert.deepEqual(input.applyCalls, []);
});

test("apply-intent persistence failure blocks Terraform before the spawn boundary", () => {
  const fixture = createValidStageBApplyFixture(); const input = validRealApplyInput(fixture); const events = [];
  input.deps.reserveApplyAttemptTransition = () => { events.push("intent-failure"); throw new Error("intent persistence failure"); };
  input.deps.apply = () => { events.push("terraform"); return { status: 0 }; };
  assert.throws(() => runApply(input), /intent persistence failure/);
  assert.deepEqual(events, ["intent-failure"]);
  assert.deepEqual(input.applyCalls, []);
});

test("spawn-uncertainty persistence failure blocks Terraform after durable pre-spawn intent", () => {
  const fixture = createValidStageBApplyFixture(); const input = validRealApplyInput(fixture); const events = [];
  input.deps.reserveApplyAttemptTransition = ({ sequence, attemptId }) => {
    events.push(`transition-${sequence}`);
    if (sequence === 2) throw new Error("spawn-uncertainty persistence failure");
    return { status: "reserved", key: stageBAttemptStepS3ObjectKey(attemptId, sequence) };
  };
  input.deps.apply = () => { events.push("terraform"); return { status: 0 }; };
  assert.throws(() => runApply(input), /spawn-uncertainty persistence failure/);
  assert.deepEqual(events, ["transition-1", "transition-2"]);
  assert.deepEqual(input.applyCalls, []);
});

test("a reconciliation claim occupying the canonical spawn slot blocks the original apply seam", () => {
  const fixture = createValidStageBApplyFixture(); const input = validRealApplyInput(fixture); const transitions = [];
  input.deps.reserveApplyAttemptTransition = ({ sequence, attemptId }) => {
    transitions.push(sequence);
    return sequence === 2
      ? { status: "occupied", key: stageBAttemptStepS3ObjectKey(attemptId, sequence) }
      : { status: "reserved", key: stageBAttemptStepS3ObjectKey(attemptId, sequence) };
  };
  input.deps.apply = () => { throw new Error("Terraform must remain unreachable"); };
  assert.throws(() => runApply(input), /apply-spawn uncertainty marker was not authenticated/);
  assert.deepEqual(transitions, [1, 2]);
  assert.deepEqual(input.applyCalls, []);
});

test("apply failure records a terminal failed result while thrown spawn ambiguity remains non-retryable", () => {
  const failedFixture = createValidStageBApplyFixture(); const failed = validRealApplyInput(failedFixture);
  failed.deps.apply = () => ({ status: 1 });
  assert.throws(() => runApply(failed), /Terraform apply failed/);
  const failedTransitions = [...failedFixture.sharedReservations.entries()].filter(([key]) => key.includes("/"));
  assert.equal(failedTransitions.length, 3);
  assert.equal(JSON.parse(failedTransitions[1][1]).status, "APPLY_SPAWN_UNCERTAIN");
  assert.equal(JSON.parse(failedTransitions[2][1]).status, "FAILED");

  const uncertainFixture = createValidStageBApplyFixture(); const uncertain = validRealApplyInput(uncertainFixture);
  uncertain.deps.apply = () => { throw new Error("spawn outcome unknown"); };
  assert.throws(() => runApply(uncertain), /spawn outcome unknown/);
  const uncertainTransitions = [...uncertainFixture.sharedReservations.entries()].filter(([key]) => key.includes("/"));
  assert.equal(uncertainTransitions.length, 3);
  assert.equal(JSON.parse(uncertainTransitions[1][1]).status, "APPLY_SPAWN_UNCERTAIN");
  assert.equal(JSON.parse(uncertainTransitions[2][1]).status, "UNKNOWN");
  assert.deepEqual(uncertain.applyCalls, []);
});

test("pre-existing local evidence blocks before consuming a shared reservation", () => {
  const fixture = createValidStageBApplyFixture(); runApply(validRealApplyInput(fixture)); fixture.sharedReservations.clear();
  const input = validRealApplyInput(fixture); let sharedCalls = 0;
  input.deps.reserveSharedApplyAttempt = () => { sharedCalls += 1; throw new Error("shared reservation must not be reached"); };
  assert.throws(() => runApply(input), /local apply-attempt evidence already exists/);
  assert.equal(sharedCalls, 0);
  assert.deepEqual(input.applyCalls, []);
});

test("shared reservation and readback precede local reservation and Terraform spawn", () => {
  const fixture = createValidStageBApplyFixture(); const input = validRealApplyInput(fixture); const events = [];
  input.deps.reserveSharedApplyAttempt = ({ artifactSetIdentity }) => { events.push("shared-reserved-and-verified"); return { status: "reserved", key: stageBApplyAttemptS3Key(artifactSetIdentity) }; };
  input.deps.reserveApplyAttempt = () => { events.push("local-evidence"); };
  input.deps.reserveApplyAttemptTransition = ({ sequence, attemptId }) => { events.push(`transition-${sequence}`); return { status: "reserved", key: stageBAttemptStepS3ObjectKey(attemptId, sequence) }; };
  input.deps.apply = () => { events.push("terraform"); return { status: 0 }; };
  runApply(input);
  assert.deepEqual(events, ["shared-reserved-and-verified", "local-evidence", "transition-1", "transition-2", "terraform", "transition-3"]);
});

test("apply rejects ambient Terraform CLI argument injection before artifacts or mutation", () => {
  const fixture = createValidStageBApplyFixture();
  const input = validRealApplyInput(fixture);
  input.env.TF_CLI_ARGS_apply = "-target=aws_ecs_task_definition.candidate[backend]";
  assert.throws(() => runApply(input), /refuses TF_CLI_ARGS/);
  assert.deepEqual(input.applyCalls, []);
});

test("apply rejects a signed permission report with a different mutation manifest", () => {
  const fixture = createValidStageBApplyFixture();
  const report = JSON.parse(fs.readFileSync(fixture.permissionReportPath, "utf8"));
  report.planCapabilities.mutationManifest.resources[0].actions = ["delete", "create"];
  writePermissionPair(fixture.permissionReportPath, fixture.permissionReportSignaturePath, report);
  fixture.permissionReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportPath)).digest("hex");
  fixture.permissionReportSignatureSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportSignaturePath)).digest("hex");
  const input = validRealApplyInput(fixture);
  assert.throws(() => runApply(input), /mutation manifest is incomplete or stale/);
  assert.deepEqual(input.applyCalls, []);
});

test("wrapper rejects permission context drift before the injected apply seam", () => {
  const fixture = createValidStageBApplyFixture();
  const report = JSON.parse(fs.readFileSync(fixture.permissionReportPath, "utf8"));
  report.requiredEvaluations[0].context = [{ key: "ecs:privileged", type: "string", values: ["false"] }];
  report.planCapabilities.required[0].context = report.requiredEvaluations[0].context;
  writePermissionPair(fixture.permissionReportPath, fixture.permissionReportSignaturePath, report);
  fixture.permissionReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportPath)).digest("hex");
  fixture.permissionReportSignatureSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.permissionReportSignaturePath)).digest("hex");
  const input = validRealApplyInput(fixture);
  assert.throws(() => runApply(input), /different context from the current reviewed registry/);
  assert.deepEqual(input.applyCalls, []);
});

test("wrapper rejects a backend config using another key before the apply seam", () => {
  const fixture = createValidStageBApplyFixture();
  const input = validRealApplyInput(fixture);
  input.deps.getBackendMetadata = () => ({ ...structuredClone(initializedBackendMetadata), config: { ...initializedBackendMetadata.config, key: "other.tfstate" } });
  assert.throws(() => runApply(input), /backend key/);
  assert.deepEqual(input.applyCalls, []);
});

test("wrapper verify-only and pre-apply reject redirected backend metadata", () => {
  for (const verifyOnly of [true, false]) {
    const fixture = createValidStageBApplyFixture();
    const input = verifyOnly ? validApplyInput(fixture) : validRealApplyInput(fixture);
    input.argv = wrapperArgs(fixture, verifyOnly);
    input.deps.getBackendMetadata = () => ({ ...structuredClone(initializedBackendMetadata), config: { ...initializedBackendMetadata.config, endpoints: { s3: "https://other.example" } } });
    assert.throws(() => runApply(input), /endpoints/);
    if (!verifyOnly) assert.deepEqual(input.applyCalls, []);
  }
});

test("production apply rejects every incomplete canonical tfvars provenance combination", () => {
  const fixture = createValidStageBApplyFixture();
  const required = [
    ["--tfvars", "--tfvars is required."],
    ["--tfvars-binding-report", "--tfvars-binding-report is required."],
    ["--tfvars-binding-report-sha256", "--tfvars-binding-report-sha256 is required."],
    ["--refresh-report", "--refresh-report is required."],
    ["--refresh-report-sha256", "--refresh-report-sha256 is required."],
    ["--tooling-tree-sha256", "--tooling-tree-sha256 is required."],
  ];
  for (const [option, message] of required) {
    const argv = wrapperArgs(fixture).filter((value, index, values) => values[index - 1] !== option && value !== option);
    assert.throws(() => parseApplyCli(argv), (error) => error instanceof Error && error.message === message, option);
  }
  assert.throws(() => parseApplyCli(wrapperArgs(fixture).filter((value, index, values) => values[index - 1] !== "--tfvars-binding-report-sha256" && value !== "--tfvars-binding-report-sha256")), /--tfvars-binding-report-sha256 is required/);
});

test("production apply rejects pull-request closure mode before artifact verification", () => {
  const fixture = createValidStageBApplyFixture();
  const argv = wrapperArgs(fixture).map((value, index, values) => index > 0 && values[index - 1] === "--closure-mode" ? "pull-request" : value);
  assert.throws(() => parseApplyCli(argv), (error) => error instanceof Error && error.message === "Stage B apply requires --closure-mode production.");
});

test("broker ZIP mutation blocks apply before the injected apply seam", () => {
  const fixture = createValidStageBApplyFixture();
  fs.appendFileSync(fixture.tfvarsPath.replace("canonical.tfvars", "broker.zip"), Buffer.from("mutation"));
  const input = validRealApplyInput(fixture);
  assert.throws(() => runApply(input), /broker package raw SHA256/);
  assert.deepEqual(input.applyCalls, []);
});

test("Stage-A binding-report serial mismatch blocks apply before the injected apply seam", () => {
  const fixture = createValidStageBApplyFixture();
  const bindingReport = JSON.parse(fs.readFileSync(fixture.tfvarsBindingReportPath, "utf8"));
  bindingReport.stageAStateSerial = 36;
  writePrivate(fixture.tfvarsBindingReportPath, `${JSON.stringify(bindingReport)}\n`);
  fixture.tfvarsBindingReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.tfvarsBindingReportPath)).digest("hex");
  const input = validRealApplyInput(fixture);
  assert.throws(() => runApply(input), /binding report Stage-A serial/);
  assert.deepEqual(input.applyCalls, []);
});

const protectedCheckoutCases = [
  { name: "HEAD differs from origin/main", changedFields: ["protectedMainCheckout.currentHead"], mutate: (fixture) => { fixture.protectedMainCheckout.currentHead = "c".repeat(40); }, errorMessage: "Stage B tooling HEAD does not match toolingSha." },
  { name: "plan tooling SHA differs from HEAD", changedFields: ["protectedMainCheckout.toolingSha"], mutate: (fixture) => { fixture.protectedMainCheckout.toolingSha = "c".repeat(40); }, errorMessage: "Stage B protected-main checkout tooling SHA does not match the approved plan tooling SHA." },
  { name: "tracked modification exists", changedFields: ["protectedMainCheckout.porcelainStatus"], mutate: (fixture) => { fixture.protectedMainCheckout.porcelainStatus = " M tracked"; }, errorMessage: "Stage B tooling checkout has tracked modifications." },
  { name: "staged modification exists", changedFields: ["protectedMainCheckout.porcelainStatus"], mutate: (fixture) => { fixture.protectedMainCheckout.porcelainStatus = "M  staged"; }, errorMessage: "Stage B tooling checkout has tracked modifications." },
  { name: "tracked deletion exists", changedFields: ["protectedMainCheckout.porcelainStatus"], mutate: (fixture) => { fixture.protectedMainCheckout.porcelainStatus = " D deleted"; }, errorMessage: "Stage B tooling checkout has tracked modifications." },
  { name: "untracked file exists", changedFields: ["protectedMainCheckout.porcelainStatus"], mutate: (fixture) => { fixture.protectedMainCheckout.porcelainStatus = "?? untracked"; }, errorMessage: "Stage B tooling checkout contains an untracked file." },
  { name: "commit is not merged into origin/main", changedFields: ["protectedMainCheckout.isAncestor"], mutate: (fixture) => { fixture.protectedMainCheckout.isAncestor = false; }, errorMessage: "Stage B tooling ancestry in origin/main could not be proven." },
  { name: "merge operation is in progress", changedFields: ["protectedMainCheckout.repositoryState.mergeInProgress"], mutate: (fixture) => { fixture.protectedMainCheckout.repositoryState.mergeInProgress = true; }, errorMessage: "Stage B tooling checkout has a merge in progress." },
  { name: "rebase operation is in progress", changedFields: ["protectedMainCheckout.repositoryState.rebaseInProgress"], mutate: (fixture) => { fixture.protectedMainCheckout.repositoryState.rebaseInProgress = true; }, errorMessage: "Stage B tooling checkout has a rebase in progress." },
  { name: "cherry-pick operation is in progress", changedFields: ["protectedMainCheckout.repositoryState.cherryPickInProgress"], mutate: (fixture) => { fixture.protectedMainCheckout.repositoryState.cherryPickInProgress = true; }, errorMessage: "Stage B tooling checkout has a cherry-pick in progress." },
  { name: "origin/main is missing", changedFields: ["protectedMainCheckout.originMainHead"], mutate: (fixture) => { fixture.protectedMainCheckout.originMainHead = undefined; }, errorMessage: "Stage B protected origin/main is unavailable." },
  { name: "ancestry cannot be proven", changedFields: ["protectedMainCheckout.isAncestor"], mutate: (fixture) => { fixture.protectedMainCheckout.isAncestor = undefined; }, errorMessage: "Stage B tooling ancestry in origin/main could not be proven." },
];

for (const { name, changedFields, mutate, errorMessage } of protectedCheckoutCases) {
  test(`protected checkout rejects ${name}`, () => {
    const baseline = createValidStageBApplyFixture();
    assert.equal(runApply(validApplyInput(baseline)).status, "ready-to-apply");
    const mutated = { ...baseline, protectedMainCheckout: structuredClone(baseline.protectedMainCheckout) };
    mutate(mutated);
    assertSingleFailureMutation({ baseline, mutated, changedFields });
    assert.throws(() => runApply(validApplyInput(mutated)), (error) => error instanceof Error && error.message === errorMessage, name);
  });
}

const secondCheckoutCases = [
  { name: "tracked modification", mutate: (checkout) => { checkout.porcelainStatus = " M drifted"; }, errorMessage: "Stage B tooling checkout has tracked modifications." },
  { name: "untracked file", mutate: (checkout) => { checkout.porcelainStatus = "?? drifted"; }, errorMessage: "Stage B tooling checkout contains an untracked file." },
  { name: "origin/main mismatch", mutate: (checkout) => { checkout.originMainHead = "c".repeat(40); }, errorMessage: "Stage B tooling SHA does not match origin/main." },
  { name: "HEAD differs from plan tooling SHA", mutate: (checkout) => { checkout.currentHead = "c".repeat(40); }, errorMessage: "Stage B tooling HEAD does not match toolingSha." },
  { name: "merge operation", mutate: (checkout) => { checkout.repositoryState.mergeInProgress = true; }, errorMessage: "Stage B tooling checkout has a merge in progress." },
  { name: "rebase operation", mutate: (checkout) => { checkout.repositoryState.rebaseInProgress = true; }, errorMessage: "Stage B tooling checkout has a rebase in progress." },
  { name: "cherry-pick operation", mutate: (checkout) => { checkout.repositoryState.cherryPickInProgress = true; }, errorMessage: "Stage B tooling checkout has a cherry-pick in progress." },
];

for (const { name, mutate, errorMessage } of secondCheckoutCases) {
  test(`non-verify-only apply rejects second-check ${name} drift`, () => {
    const fixture = createValidStageBApplyFixture();
    const secondCheckout = structuredClone(fixture.protectedMainCheckout);
    mutate(secondCheckout);
    const input = validRealApplyInput(fixture, [fixture.protectedMainCheckout, secondCheckout]);
    assert.throws(() => runApply(input), (error) => error instanceof Error && error.message === errorMessage, name);
    assert.equal(input.checkoutReadCount, 2);
    assert.deepEqual(input.applyCalls, []);
  });
}

test("exact binary plan and derived JSON reach the ready-to-apply boundary without applying", () => {
  const fixture = wrapperFixture();
  const result = runApply({
    argv: wrapperArgs(fixture, true),
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
    deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true, verifyImageEvidence: fixture.verifyImageEvidence, getBackendMetadata: () => structuredClone(initializedBackendMetadata), apply: () => { throw new Error("apply must not be reached"); } },
  });
  assert.equal(result.status, "ready-to-apply");
});

test("verify-only and apply reject failed refresh checks before any plan or apply seam", () => {
  const fixture = wrapperFixture();
  const refresh = JSON.parse(fs.readFileSync(fixture.refreshReportPath, "utf8"));
  refresh.checks[0].status = "fail";
  refresh.failedCheckCount = 1;
  refresh.passedCheckCount = refresh.checkCount - 1;
  refresh.failedChecks = [{ address: refresh.checks[0].address, status: "fail", message: "binding mismatch" }];
  writePrivate(fixture.refreshReportPath, `${JSON.stringify(refresh)}\n`);
  fixture.refreshReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(fixture.refreshReportPath)).digest("hex");
  for (const verifyOnly of [true, false]) {
    let applied = false;
    assert.throws(() => runApply({
      argv: wrapperArgs(fixture, verifyOnly),
      env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
      deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", currentHead: () => "b".repeat(40), showPlan: () => { throw new Error("plan seam must not be reached"); }, validatePlan: () => {}, verifyPermissionSignature: () => true, verifyImageEvidence: fixture.verifyImageEvidence, apply: () => { applied = true; } },
    }), /check or binding structure/);
    assert.equal(applied, false);
  }
});

test("apply wrapper rejects an unqualified broker target before apply", () => {
  const fixture = wrapperFixture();
  const audit = { ...JSON.parse(fs.readFileSync(fixture.auditPath)), broker: {
    aliasArn: STAGE_B.brokerFunctionArn,
    aliasName: "reviewed",
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  } };
  const auditBytes = Buffer.from(JSON.stringify(audit));
  writePrivate(fixture.auditPath, auditBytes);
  rebindApprovalAudit(fixture, auditBytes);
  assert.throws(() => assertApplyArtifacts({
    ...fixture,
    planSha256: fixture.planHash,
    auditSha256: crypto.createHash("sha256").update(auditBytes).digest("hex"),
    savedPlanSha256: fixture.savedHash,
    canonicalPlanJsonSha256: fixture.canonicalHash,
    permissionReportSha256: fixture.permissionReportSha256,
    callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
    showPlan: () => fixture.shownBytes,
    validatePlan: () => {},
    verifyPermissionSignature: () => true,
  }), (error) => error instanceof Error && error.message.includes("Difference: alias, qualifier"));
});

test("apply wrapper validates the canonical alias for any broker mutation regardless of ordering", () => {
  const brokerAddresses = ["aws_iam_policy.broker", "aws_lambda_function.broker", "aws_lambda_alias.reviewed"];
  const brokerChanges = productionPlan.resource_changes.filter((change) => brokerAddresses.includes(change.address));
  const planWithBrokerChanges = (order) => ({
    ...productionPlan,
    resource_changes: [
      ...productionPlan.resource_changes.filter((change) => !brokerAddresses.includes(change.address)),
      ...order.map((address) => brokerChanges.find((change) => change.address === address)),
    ],
  });
  const run = (approvedPlan, aliasArn) => {
    const fixture = wrapperFixture({ approvedPlan });
    const auditBytes = Buffer.from(JSON.stringify({ ...JSON.parse(fs.readFileSync(fixture.auditPath)), broker: {
      aliasArn,
      aliasName: "reviewed",
      aliasFunctionVersion: "2",
      configurationFunctionArn: STAGE_B.brokerAliasArn,
      configurationVersion: "2",
      resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
    } }));
    writePrivate(fixture.auditPath, auditBytes);
    rebindApprovalAudit(fixture, auditBytes);
    return () => assertApplyArtifacts({
      ...fixture,
      planSha256: fixture.planHash,
      auditSha256: crypto.createHash("sha256").update(auditBytes).digest("hex"),
      savedPlanSha256: fixture.savedHash,
      canonicalPlanJsonSha256: fixture.canonicalHash,
      permissionReportSha256: fixture.permissionReportSha256,
      callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
      showPlan: () => fixture.shownBytes,
      validatePlan: () => {},
      verifyPermissionSignature: () => true,
    });
  };
  const unqualified = STAGE_B.brokerFunctionArn;
  const orders = [
    brokerAddresses,
    [...brokerAddresses].reverse(),
    [brokerAddresses[1], brokerAddresses[2], brokerAddresses[0]],
  ];
  for (const order of orders) assert.throws(run(planWithBrokerChanges(order), unqualified), /Difference: alias, qualifier/);
});

test("verification-only and real apply paths reject an invalid report signature before apply", () => {
  const fixture = wrapperFixture();
  for (const verifyOnly of [true, false]) {
    assert.throws(() => runApply({
      argv: wrapperArgs(fixture, verifyOnly),
      env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
      deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => false, verifyImageEvidence: fixture.verifyImageEvidence, apply: () => { throw new Error("apply must not be reached"); } },
    }), /signature verification failed/);
  }
});

test("saved-plan binding rejects stale, changed, or semantically different binary plans", () => {
  const fixture = wrapperFixture({ shownPlan: { ...plan, resource_changes: [{ address: "unexpected", change: { actions: ["delete"] } }] } });
  assert.throws(() => assertApplyArtifacts({ ...fixture, planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }), /Permission report canonicalPlanJsonSha256|Saved binary Terraform plan/);
  const changed = wrapperFixture({ savedBytes: Buffer.from("changed-binary") });
  assert.throws(() => assertApplyArtifacts({ ...changed, planSha256: changed.planHash, auditSha256: changed.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: changed.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => changed.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }), /Saved Terraform plan SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, planSha256: "0".repeat(64), auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }), /Plan JSON SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: "", callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }), /Canonical plan JSON SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, permissionReportSha256: "0".repeat(64), planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }), /Permission-preflight report SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, permissionReportSignatureSha256: "0".repeat(64), planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }), /Permission-preflight report signature SHA256/);
});

test("canonical key ordering is ignored while semantic plan differences fail", () => {
  const source = wrapperFixture();
  const approvedPlan = JSON.parse(fs.readFileSync(source.planJsonPath, "utf8"));
  const reordered = Buffer.from(JSON.stringify({ resource_changes: approvedPlan.resource_changes, variables: approvedPlan.variables }));
  const fixture = wrapperFixture({ approvedBytes: reordered });
  assert.doesNotThrow(() => assertApplyArtifacts({ ...fixture, planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true }));
});

test("wrapper rejects a plan digest mismatch before invoking apply", () => {
  const fixture = wrapperFixture();
  const changedPlan = JSON.parse(fs.readFileSync(fixture.planJsonPath, "utf8"));
  changedPlan.variables.backend_image.value = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"f".repeat(64)}`;
  const changedBytes = Buffer.from(JSON.stringify(changedPlan));
  fs.writeFileSync(fixture.planJsonPath, changedBytes);
  fixture.planHash = crypto.createHash("sha256").update(changedBytes).digest("hex");
  for (const verifyOnly of [true, false]) {
    let applied = false;
    assert.throws(() => runApply({
      argv: wrapperArgs(fixture, verifyOnly),
      env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
      deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true, verifyImageEvidence: fixture.verifyImageEvidence, apply: () => { applied = true; } },
    }), /plan evidence planJsonSha256 does not match/);
    assert.equal(applied, false);
  }
});

test("apply wrapper rejects a non-STS caller during verification-only mode", () => {
  const fixture = wrapperFixture();
  assert.throws(() => runApply({
    argv: wrapperArgs(fixture, true),
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default", TF_DATA_DIR: fixture.directory },
    deps: { getCaller: () => roleArn, currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true, apply: () => { throw new Error("apply must not be reached"); } },
  }), /STS assumed-role/);
});
