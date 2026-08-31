import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { assertStageBNormalPlanCompleteness, assertStageBPlanApprovedBinding, assertStageBPlanApprovalReport, assertStageBPlanCaptureReport, createStageBPlanApprovalReport, createStageBPlanCaptureReport, stageBApprovalAuthorityMode, stageBPlanHashes, STAGE_B_BROKER_OPERATIONS, STAGE_B_LIVE_AUTHORITY, STAGE_B_PLAN_AUTHORITY, STAGE_B_PLAN_PROFILES, STAGE_B_RETAINED_TASK_DEFINITION_DESCRIPTORS } from "../aws/stage-b-plan-approval-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";
import { STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY } from "../aws/stage-b-deployment-contract.mjs";
import { approveCapturedStageBPlan, finalizeCapturedStageBPlanApproval, readStageBApprovalPlanArtifacts } from "../plan-production-green-stage-b.mjs";
import { writeStageBPrivateFileAtomic } from "../aws/stage-b-artifact-contract.mjs";
import { assertRecoveryOnlyPlan } from "../aws/stage-b-partial-apply-recovery-contract.mjs";
import { assertPermissionReportPlanBinding } from "../aws/validate-production-green-stage-b-permissions.mjs";

const fixture = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-approval-"));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const fixtureClassification = (() => {
  const counts = {};
  for (const change of fixture.resource_changes) counts[change.change.actions.join(",")] = (counts[change.change.actions.join(",")] || 0) + 1;
  return { noOp: counts["no-op"] || 0, create: counts.create || 0, update: counts.update || 0, destroy: counts.destroy || 0, replacement: 0, unclassified: 0 };
})();
const fixtureRetainedTaskDefinitions = fixture.resource_changes.filter((change) => change.address.includes("_retained[")).map((change, index) => {
  const key = change.address.match(/\["[a-f0-9]+-([^"]+)"\]$/)[1];
  const family = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).find(([address]) => address.match(/\["([^"]+)"\]$/)[1] === key)?.[1];
  return { terraformAddress: change.address, family, classification: "retained-no-op", oldTaskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 1}` };
});
const savedPlanBytes = Buffer.from("captured-binary-plan\n");
const planJsonBytes = Buffer.from(`${JSON.stringify(fixture)}\n`);
const canonicalPlanJsonBytes = Buffer.from(`${canonicalJson(fixture)}\n`);
const hashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes });
const capture = createStageBPlanCaptureReport({ toolingSha: "b".repeat(40), toolingTreeSha256: "c".repeat(64), refreshReportSha256: "d".repeat(64), hashes, capturedAt: "2026-08-05T14:00:00.000Z", stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 76, terraformVersion: fixture.terraform_version, terraformFormatVersion: fixture.format_version, classification: fixtureClassification, brokerEvidence: { brokerOperation: "update", brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: ["aws_iam_policy.broker", "aws_lambda_alias.reviewed", "aws_lambda_function.broker"], brokerReferenceValidationPending: true } });
const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
const audit = { schemaVersion: 1, planJsonSha256: hashes.planJsonSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", auditedAt: "2026-08-05T14:01:00.000Z", retainedTaskDefinitions: fixtureRetainedTaskDefinitions };
const auditBytes = Buffer.from(`${JSON.stringify(audit)}\n`);
const approval = createStageBPlanApprovalReport({ captureReportSha256: hash(captureBytes), referenceAuditPath: path.join(directory, "audit.json"), referenceAuditSha256: hash(auditBytes), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: "2026-08-05T14:02:00.000Z", classification: capture.classification, brokerOperation: capture.brokerOperation, brokerUpdatePresent: capture.brokerUpdatePresent, brokerActions: capture.brokerActions, brokerResourceAddresses: capture.brokerResourceAddresses });
const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
const plannerSource = fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8");
const approvalPathSource = plannerSource.slice(plannerSource.indexOf("export function approveCapturedStageBPlan"), plannerSource.indexOf("\n}\n\nif (process.argv[1]"));
const terraformConfiguration = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");

test.after(() => fs.rmSync(directory, { recursive: true, force: true }));

function outputDirectory(name) {
  const output = path.join(directory, name);
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  return output;
}

function finalizeOptions(approvalReportPath, overrides = {}) {
  return {
    approval,
    approvalReportPath,
    repositoryRoot: process.cwd(),
    captureReport: capture,
    captureReportBytes: captureBytes,
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    hashes,
    logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256,
    referenceAuditSha256: hash(auditBytes),
    trustedCallerArn: audit.callerArn,
    stageBLineage: capture.stageBLineage,
    stageBSerial: capture.stageBSerial,
    savedPlanPath: path.join(directory, "saved.tfplan"),
    planJsonPath: path.join(directory, "plan.json"),
    canonicalPlanJsonPath: path.join(directory, "canonical.json"),
    ...overrides,
  };
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
  let revision = 1;
  for (const current of value.resource_changes.filter((item) => Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, item.address) && item.address !== change.address)) {
    const currentAfter = structuredClone(current.change.after);
    const familyName = currentAfter.family;
    const key = current.address.match(/\["([^"]+)"\]$/)[1];
    const oldArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${familyName}:${revision++}`;
    const common = { ...currentAfter, network_mode: "awsvpc", volume: [], ipc_mode: "", pid_mode: "", skip_destroy: true };
    const beforeState = { ...structuredClone(common), arn: oldArn, arn_without_revision: oldArn.replace(/:\d+$/, ""), id: oldArn, revision: revision - 1 };
    const imageBefore = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${key}@sha256:${"b".repeat(64)}`;
    const imageAfter = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${key}@sha256:${"a".repeat(64)}`;
    beforeState.container_definitions = JSON.stringify([{ name: key, image: imageBefore, environment: [] }]);
    common.container_definitions = JSON.stringify([{ name: key, image: imageAfter, environment: [] }]);
    current.mode = "managed";
    current.change = { actions: ["create", "delete"], before: beforeState, after: common, replace_paths: [["container_definitions"]], before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} };
  }
  const backendPolicy = value.resource_changes.find((item) => item.address === STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.address);
  backendPolicy.change = { actions: ["create"], before: null, after: { name: STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.name, role: STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.role, policy: JSON.stringify(STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.document) }, before_unknown: {}, after_unknown: {}, before_sensitive: {}, after_sensitive: {} };
  return value;
}

function partialApplyRecoveryPlan() {
  const value = importedBackendPlan();
  for (const change of value.resource_changes) {
    if (change.address === 'aws_ecs_task_definition.candidate["backend"]' || change.address === "aws_iam_policy.broker" || change.address === STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.address) {
      change.change = { ...change.change, actions: ["no-op"] };
    } else if (Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, change.address)) {
      change.deposed = "a".repeat(8);
      change.change = { ...change.change, actions: ["delete"], after: null, after_unknown: {}, after_sensitive: {} };
    }
  }
  return value;
}

test("the imported backend profile passes the production approval path with zero AWS mutation", () => {
  const importedPlan = importedBackendPlan();
  const importedPlanJsonBytes = Buffer.from(`${JSON.stringify(importedPlan)}\n`);
  const importedCanonicalPlanJsonBytes = Buffer.from(`${canonicalJson(importedPlan)}\n`);
  const importedHashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes: importedPlanJsonBytes, canonicalPlanJsonBytes: importedCanonicalPlanJsonBytes });
  const importedAudit = { ...audit, planJsonSha256: importedHashes.planJsonSha256 };
  const importedAuditBytes = Buffer.from(`${JSON.stringify(importedAudit)}\n`);
  const importedClassification = { ...fixtureClassification, create: 1, replacement: 11, update: 4 };
  const importedCapture = createStageBPlanCaptureReport({ toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, hashes: importedHashes, capturedAt: capture.capturedAt, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, terraformVersion: capture.terraformVersion, terraformFormatVersion: capture.terraformFormatVersion, classification: importedClassification, planProfile: "IMPORTED_BACKEND_METADATA_NORMALIZATION", brokerEvidence: { brokerOperation: capture.brokerOperation, brokerUpdatePresent: capture.brokerUpdatePresent, brokerActions: capture.brokerActions, brokerResourceAddresses: capture.brokerResourceAddresses, brokerReferenceValidationPending: true } });
  const importedCaptureBytes = Buffer.from(`${JSON.stringify(importedCapture, null, 2)}\n`);
  const importedApproval = createStageBPlanApprovalReport({ captureReportSha256: hash(importedCaptureBytes), referenceAuditPath: importedAudit.referenceAuditPath, referenceAuditSha256: hash(importedAuditBytes), referenceAuditCallerArn: importedAudit.callerArn, referenceAuditAt: importedAudit.auditedAt, toolingSha: importedCapture.toolingSha, toolingTreeSha256: importedCapture.toolingTreeSha256, refreshReportSha256: importedCapture.refreshReportSha256, stageBLineage: importedCapture.stageBLineage, stageBSerial: importedCapture.stageBSerial, hashes: importedHashes, logicalCanonicalPlanJsonSha256: importedHashes.logicalCanonicalPlanJsonSha256, approvedAt: capture.capturedAt, classification: importedClassification, planProfile: "IMPORTED_BACKEND_METADATA_NORMALIZATION", brokerOperation: importedCapture.brokerOperation, brokerUpdatePresent: importedCapture.brokerUpdatePresent, brokerActions: importedCapture.brokerActions, brokerResourceAddresses: importedCapture.brokerResourceAddresses });
  const importedApprovalBytes = Buffer.from(`${JSON.stringify(importedApproval, null, 2)}\n`);
  assert.doesNotThrow(() => assertStageBNormalPlanCompleteness(importedPlan, { referenceAudit: importedAudit, strict: false, terraformConfiguration }));
  assert.doesNotThrow(() => assertStageBPlanApprovalReport(importedApproval, { approvalReportBytes: importedApprovalBytes, captureReport: importedCapture, captureReportBytes: importedCaptureBytes, referenceAudit: importedAudit, referenceAuditBytes: importedAuditBytes, hashes: importedHashes, logicalCanonicalPlanJsonSha256: importedHashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(importedAuditBytes), trustedCallerArn: importedAudit.callerArn, stageBLineage: importedCapture.stageBLineage, stageBSerial: importedCapture.stageBSerial, plan: importedPlan, terraformConfiguration }));
  assert.doesNotThrow(() => assertStageBPlanApprovedBinding(importedApproval, { approvalReportBytes: importedApprovalBytes, approvalReportSha256: hash(importedApprovalBytes), savedPlanBytes, planJsonBytes: importedPlanJsonBytes, canonicalPlanJsonBytes: importedCanonicalPlanJsonBytes, referenceAudit: importedAudit, referenceAuditBytes: importedAuditBytes, expectedToolingSha: importedCapture.toolingSha, expectedToolingTreeSha256: importedCapture.toolingTreeSha256, expectedRefreshReportSha256: importedCapture.refreshReportSha256, expectedStageBLineage: importedCapture.stageBLineage, expectedStageBSerial: importedCapture.stageBSerial, terraformConfiguration, now: new Date(capture.capturedAt) }));
});

test("partial-apply recovery binds the exact eleven cleanup entries and two Lambda updates through approval", () => {
  const partialPlan = partialApplyRecoveryPlan();
  const partialPlanJsonBytes = Buffer.from(`${JSON.stringify(partialPlan)}\n`);
  const partialCanonicalPlanJsonBytes = Buffer.from(`${canonicalJson(partialPlan)}\n`);
  const partialHashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes: partialPlanJsonBytes, canonicalPlanJsonBytes: partialCanonicalPlanJsonBytes });
  const partialAudit = { ...audit, planJsonSha256: partialHashes.planJsonSha256 };
  const partialAuditBytes = Buffer.from(`${JSON.stringify(partialAudit)}\n`);
  const partialClassification = { noOp: fixtureClassification.noOp + 2, create: 0, replacement: 0, update: 2, destroy: 11, unclassified: 0 };
  const partialCapture = createStageBPlanCaptureReport({ toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, refreshBindingReportSha256: "e".repeat(64), hashes: partialHashes, capturedAt: capture.capturedAt, stageBLineage: capture.stageBLineage, stageBSerial: 96, terraformVersion: capture.terraformVersion, terraformFormatVersion: capture.terraformFormatVersion, classification: partialClassification, planProfile: "PARTIAL_APPLY_RECOVERY", brokerEvidence: { brokerOperation: "partial-apply-recovery", brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: ["aws_lambda_alias.reviewed", "aws_lambda_function.broker"], brokerReferenceValidationPending: true } });
  const partialCaptureBytes = Buffer.from(`${JSON.stringify(partialCapture, null, 2)}\n`);
  const partialApproval = createStageBPlanApprovalReport({ captureReportSha256: hash(partialCaptureBytes), referenceAuditPath: partialAudit.referenceAuditPath, referenceAuditSha256: hash(partialAuditBytes), referenceAuditCallerArn: partialAudit.callerArn, referenceAuditAt: partialAudit.auditedAt, toolingSha: partialCapture.toolingSha, toolingTreeSha256: partialCapture.toolingTreeSha256, refreshReportSha256: partialCapture.refreshReportSha256, refreshBindingReportSha256: partialCapture.refreshBindingReportSha256, stageBLineage: partialCapture.stageBLineage, stageBSerial: partialCapture.stageBSerial, hashes: partialHashes, logicalCanonicalPlanJsonSha256: partialHashes.logicalCanonicalPlanJsonSha256, approvedAt: capture.capturedAt, classification: partialClassification, planProfile: "PARTIAL_APPLY_RECOVERY", brokerOperation: partialCapture.brokerOperation, brokerUpdatePresent: partialCapture.brokerUpdatePresent, brokerActions: partialCapture.brokerActions, brokerResourceAddresses: partialCapture.brokerResourceAddresses });
  const partialApprovalBytes = Buffer.from(`${JSON.stringify(partialApproval, null, 2)}\n`);
  const common = { approvalReportBytes: partialApprovalBytes, approvalReportSha256: hash(partialApprovalBytes), referenceAudit: partialAudit, referenceAuditBytes: partialAuditBytes, now: new Date(capture.capturedAt) };
  assert.doesNotThrow(() => assertStageBPlanApprovalReport(partialApproval, { ...common, captureReport: partialCapture, captureReportBytes: partialCaptureBytes, plan: partialPlan, hashes: partialHashes, logicalCanonicalPlanJsonSha256: partialHashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(partialAuditBytes), trustedCallerArn: partialAudit.callerArn, stageBLineage: partialCapture.stageBLineage, stageBSerial: partialCapture.stageBSerial, terraformConfiguration }));
  assert.doesNotThrow(() => assertStageBPlanApprovedBinding(partialApproval, { ...common, savedPlanBytes, planJsonBytes: partialPlanJsonBytes, canonicalPlanJsonBytes: partialCanonicalPlanJsonBytes, expectedToolingSha: partialCapture.toolingSha, expectedToolingTreeSha256: partialCapture.toolingTreeSha256, expectedRefreshReportSha256: partialCapture.refreshReportSha256, expectedStageBLineage: partialCapture.stageBLineage, expectedStageBSerial: partialCapture.stageBSerial, terraformConfiguration }));
  const mixedRecoveryApproval = { ...partialApproval, recoveryAttestationSha256: "a".repeat(64), recoveryPlan: true };
  const mixedRecoveryApprovalBytes = Buffer.from(`${JSON.stringify(mixedRecoveryApproval, null, 2)}\n`);
  assert.throws(() => assertStageBPlanApprovedBinding(mixedRecoveryApproval, { ...common, approvalReportBytes: mixedRecoveryApprovalBytes, approvalReportSha256: hash(mixedRecoveryApprovalBytes), savedPlanBytes, planJsonBytes: partialPlanJsonBytes, canonicalPlanJsonBytes: partialCanonicalPlanJsonBytes, expectedToolingSha: partialCapture.toolingSha, expectedToolingTreeSha256: partialCapture.toolingTreeSha256, expectedRefreshReportSha256: partialCapture.refreshReportSha256, expectedStageBLineage: partialCapture.stageBLineage, expectedStageBSerial: partialCapture.stageBSerial, terraformConfiguration }), /cannot carry RECOVERY_ALIAS_ONLY/);
});

test("approval-only propagates partial-apply recovery into the real approval validator seam", () => {
  const plan = partialApplyRecoveryPlan();
  const planJsonBytes = Buffer.from(`${JSON.stringify(plan)}\n`);
  const canonicalPlanJsonBytes = Buffer.from(`${canonicalJson(plan)}\n`);
  const approvalHashes = stageBPlanHashes({ savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes });
  const auditValue = { ...audit, planJsonSha256: approvalHashes.planJsonSha256 };
  const auditValueBytes = Buffer.from(`${JSON.stringify(auditValue)}\n`);
  const captureValue = createStageBPlanCaptureReport({ toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, refreshBindingReportSha256: "e".repeat(64), hashes: approvalHashes, capturedAt: capture.capturedAt, stageBLineage: capture.stageBLineage, stageBSerial: 96, terraformVersion: capture.terraformVersion, terraformFormatVersion: capture.terraformFormatVersion, classification: { noOp: fixtureClassification.noOp + 2, create: 0, replacement: 0, update: 2, destroy: 11, unclassified: 0 }, planProfile: "PARTIAL_APPLY_RECOVERY", brokerEvidence: { brokerOperation: "partial-apply-recovery", brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: ["aws_lambda_alias.reviewed", "aws_lambda_function.broker"], brokerReferenceValidationPending: true } });
  const captureValueBytes = Buffer.from(`${JSON.stringify(captureValue, null, 2)}\n`);
  const temp = outputDirectory("approval-only-partial");
  const savedPath = path.join(temp, "saved.tfplan"); const planPath = path.join(temp, "plan.json"); const canonicalPath = path.join(temp, "canonical.json"); const auditPath = path.join(temp, "audit.json"); const capturePath = path.join(temp, "capture.json"); const approvalPath = path.join(temp, "approval.json");
  for (const [filePath, bytes] of [[savedPath, savedPlanBytes], [planPath, planJsonBytes], [canonicalPath, canonicalPlanJsonBytes], [auditPath, auditValueBytes], [capturePath, captureValueBytes]]) fs.writeFileSync(filePath, bytes, { mode: 0o600 });
  let receivedOptions;
  const previousWorkspace = process.env.TF_WORKSPACE;
  process.env.TF_WORKSPACE = "default";
  const result = approveCapturedStageBPlan({
    tfvars: path.join(temp, "partial.tfvars"),
    cliOptions: ["--saved-plan", savedPath, "--plan-json", planPath, "--canonical-plan-json", canonicalPath, "--capture-report", capturePath, "--capture-report-sha256", hash(captureValueBytes), "--reference-audit", auditPath, "--reference-audit-sha256", hash(auditValueBytes), "--approval-report", approvalPath],
    protectedMainCheckout: { currentHead: capture.toolingSha },
    deps: {
      readPlanningInputs: () => ({ bindingReport: { stateLineage: captureValue.stageBLineage, stateSerial: captureValue.stageBSerial }, partialApplyRecovery: true, recoveryOnly: false }),
      getCallerArn: () => auditValue.callerArn,
      validatePlan: (_selectedPlan, options) => { receivedOptions = options; return { actionCounts: { "no-op": fixtureClassification.noOp + 2, update: 2, destroy: 11, create: 0, replacement: 0 }, unclassifiedResources: [] }; },
    },
  });
  if (previousWorkspace === undefined) delete process.env.TF_WORKSPACE; else process.env.TF_WORKSPACE = previousWorkspace;
  assert.equal(receivedOptions.partialApplyRecovery, true);
  assert.equal(result.status, "PLAN_APPROVED");
  assert.equal(JSON.parse(fs.readFileSync(approvalPath)).planProfile, "PARTIAL_APPLY_RECOVERY");
});

test("imported-backend profile rejects census and membership drift", () => {
  const rejects = (mutate) => {
    const candidate = importedBackendPlan();
    mutate(candidate);
    assert.throws(() => assertStageBNormalPlanCompleteness(candidate, { referenceAudit: audit, strict: false, terraformConfiguration }), /mutation census|unsupported|rotation|create-before-delete/);
  };
  const replacements = (candidate) => candidate.resource_changes.filter((item) => item.change.actions.join(",") === "create,delete");
  rejects((candidate) => { replacements(candidate)[0].change.actions = ["create"]; });
  rejects((candidate) => { replacements(candidate)[0].change.actions = ["no-op"]; });
  rejects((candidate) => { replacements(candidate)[0].change.replace_paths = [["cpu"]]; });
  rejects((candidate) => { const backend = candidate.resource_changes.find((item) => item.address === 'aws_ecs_task_definition.candidate["backend"]'); backend.change.actions = ["create", "delete"]; backend.change.replace_paths = [["container_definitions"]]; });
  rejects((candidate) => { const extra = candidate.resource_changes.find((item) => item.address === "aws_dynamodb_table.replay"); extra.change.actions = ["create"]; });
});

test("imported-backend approval rejects delete-before-create rollover ordering", () => {
  for (const index of [0, 5, 10]) {
    const candidate = importedBackendPlan();
    candidate.resource_changes.filter((item) => item.change.actions.join(",") === "create,delete")[index].change.actions = ["delete", "create"];
    assert.throws(() => assertStageBNormalPlanCompleteness(candidate, { referenceAudit: audit, strict: false, terraformConfiguration }), /create-before-delete/);
  }
});

test("approval imports PLAN_APPROVED from the canonical contract and keeps approval-only Terraform-free", () => {
  assert.match(plannerSource, /import \{[^}]*STAGE_B_PLAN_APPROVED[^}]*\} from "\.\/aws\/stage-b-plan-approval-contract\.mjs";/);
  assert.doesNotMatch(plannerSource, /(?:const|let|var)\s+STAGE_B_PLAN_APPROVED\s*=/);
  assert.doesNotMatch(approvalPathSource, /execFileSync\("terraform"[^)]*\bplan\b/);
  assert.doesNotMatch(approvalPathSource, /execFileSync\("terraform"[^)]*\bshow\b/);
  assert.doesNotMatch(approvalPathSource, /console\.(log|error|warn)\s*\(/);
});

test("approval finalization returns PLAN_APPROVED and constructs the complete result before publication", () => {
  const output = path.join(outputDirectory("result-before-publication"), "approval.json");
  let published = 0;
  const result = finalizeCapturedStageBPlanApproval(finalizeOptions(output, {
    publish: ({ filePath, report }) => {
      published += 1;
      assert.equal(filePath, output);
      assert.deepEqual(report, approval);
      assert.equal(fs.existsSync(output), false);
    },
  }));
  assert.equal(published, 1);
  assert.equal(result.status, "PLAN_APPROVED");
  assert.equal(result.state, "PLAN_APPROVED");
  assert.equal(result.approvedForApply, true);
  assert.equal(result.savedPlanSha256, hashes.savedPlanSha256);
  assert.equal(result.planJsonSha256, hashes.planJsonSha256);
  assert.equal(result.canonicalPlanFileSha256, hashes.canonicalPlanFileSha256);
  assert.equal(result.canonicalPlanJsonSha256, hashes.canonicalPlanFileSha256);
  assert.equal(result.logicalCanonicalPlanJsonSha256, hashes.logicalCanonicalPlanJsonSha256);
  assert.equal(fs.existsSync(output), false);
});

test("approval validation failure after object construction publishes no report", () => {
  const parent = outputDirectory("validation-failure");
  const output = path.join(parent, "approval.json");
  const invalidApproval = { ...approval, approvedForApply: false };
  assert.throws(() => finalizeCapturedStageBPlanApproval(finalizeOptions(output, { approval: invalidApproval })), /PLAN_CAPTURED|PLAN_APPROVED/);
  assert.equal(fs.existsSync(output), false);
  assert.deepEqual(fs.readdirSync(parent), []);
});

test("plan and approval evidence require canonical numeric serials", () => {
  assert.doesNotThrow(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: Number.MAX_SAFE_INTEGER }));
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: "76" }), /serial/);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: -1 }), /serial/);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: 76.5 }), /serial/);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, stageBSerial: Number.MAX_SAFE_INTEGER + 1 }), /serial/);
  assert.throws(() => assertStageBPlanApprovedBinding({ ...approval, stageBSerial: "76" }, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /serial/);
  assert.throws(() => assertStageBPlanApprovedBinding({ ...approval, stageBSerial: -1 }, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /serial/);
});

test("atomic publication failure removes temporary artifacts and final report", () => {
  const parent = outputDirectory("publication-failure");
  const output = path.join(parent, "approval.json");
  const failingFs = {
    ...fs,
    renameSync: (source, destination) => {
      if (path.basename(path.dirname(source)).startsWith(".stage-b-artifact-")) throw new Error("simulated approval publication failure");
      return fs.renameSync(source, destination);
    },
  };
  assert.throws(() => finalizeCapturedStageBPlanApproval(finalizeOptions(output, {
    publish: ({ filePath, report, repositoryRoot, label }) => writeStageBPrivateFileAtomic({ filePath, bytes: Buffer.from(`${JSON.stringify(report, null, 2)}\n`), repositoryRoot, label, fsOps: failingFs }),
  })), /simulated approval publication failure/);
  assert.equal(fs.existsSync(output), false);
  assert.deepEqual(fs.readdirSync(parent), []);
});

test("successful approval publishes one private regular report", () => {
  const parent = outputDirectory("successful-publication");
  const output = path.join(parent, "approval.json");
  const result = finalizeCapturedStageBPlanApproval(finalizeOptions(output));
  const stat = fs.lstatSync(output);
  assert.equal(result.state, "PLAN_APPROVED");
  assert.equal(result.approvedForApply, true);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(parent), ["approval.json"]);
});

test("approval-only loads all plan artifacts as raw bytes for hashing", () => {
  const paths = {
    savedPlanPath: path.join(directory, "saved.tfplan"),
    planJsonPath: path.join(directory, "plan.json"),
    canonicalPlanJsonPath: path.join(directory, "canonical.json"),
  };
  fs.writeFileSync(paths.savedPlanPath, savedPlanBytes);
  fs.writeFileSync(paths.planJsonPath, planJsonBytes);
  fs.writeFileSync(paths.canonicalPlanJsonPath, canonicalPlanJsonBytes);
  const loaded = readStageBApprovalPlanArtifacts(paths);
  assert.deepEqual(loaded.savedPlanBytes, savedPlanBytes);
  assert.deepEqual(loaded.planJsonBytes, planJsonBytes);
  assert.deepEqual(loaded.canonicalPlanJsonBytes, canonicalPlanJsonBytes);
  assert.deepEqual(stageBPlanHashes(loaded), hashes);
  assert.deepEqual(JSON.parse(loaded.planJsonBytes.toString("utf8")), fixture);
});

test("capture proves the one-plan structural boundary but is not deployable", () => {
  assert.equal(capture.brokerOperation, "update");
  assert.equal(capture.brokerReferenceValidationPending, true);
  assert.equal(approval.brokerReferenceValidationPending, false);
  assert.equal(approval.brokerReferenceValidationPassed, true);
  assert.doesNotThrow(() => assertStageBPlanCaptureReport(capture, { captureReportBytes: captureBytes, hashes, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }));
  assert.throws(() => assertStageBPlanApprovedBinding(capture, { approvalReportBytes: captureBytes, approvalReportSha256: hash(captureBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes }), /PLAN_APPROVED/);
});

test("approval binds exact captured artifacts and audit without another plan", () => {
  assert.equal(approval.brokerOperation, "update");
  assert.doesNotThrow(() => assertStageBPlanApprovalReport(approval, { approvalReportBytes: approvalBytes, captureReport: capture, captureReportBytes: captureBytes, referenceAudit: audit, referenceAuditBytes: auditBytes, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(auditBytes), trustedCallerArn: audit.callerArn, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }));
  assert.doesNotThrow(() => assertStageBPlanApprovedBinding(approval, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes, planJsonBytes, canonicalPlanJsonBytes, referenceAudit: audit, referenceAuditBytes: auditBytes, now: new Date("2026-08-05T14:02:00.000Z") }));
});

test("approval rejects every changed plan artifact and stale capture binding", () => {
  for (const [name, bytes] of [["binary", Buffer.from("changed\n")], ["plan json", Buffer.from(`${JSON.stringify({ ...fixture, terraform_version: "1.6.0" })}\n`)], ["canonical", Buffer.from(`${canonicalJson({ ...fixture, terraform_version: "1.6.0" })}\n`)]]) {
    const changed = { ...hashes, ...(name === "binary" ? { savedPlanSha256: hash(bytes) } : {}), ...(name === "plan json" ? { planJsonSha256: hash(bytes) } : {}), ...(name === "canonical" ? { canonicalPlanFileSha256: hash(bytes) } : {}) };
    assert.throws(() => assertStageBPlanApprovedBinding(approval, { approvalReportBytes: approvalBytes, approvalReportSha256: hash(approvalBytes), savedPlanBytes: changed.savedPlanSha256 === hashes.savedPlanSha256 ? savedPlanBytes : bytes, planJsonBytes: changed.planJsonSha256 === hashes.planJsonSha256 ? planJsonBytes : bytes, canonicalPlanJsonBytes: changed.canonicalPlanFileSha256 === hashes.canonicalPlanFileSha256 ? canonicalPlanJsonBytes : bytes }), /does not match|different/ , name);
  }
  const tamperedApproval = { ...approval, referenceAuditSha256: "0".repeat(64) }; const tamperedApprovalBytes = Buffer.from(`${JSON.stringify(tamperedApproval, null, 2)}\n`);
  assert.throws(() => assertStageBPlanApprovalReport(tamperedApproval, { approvalReportBytes: tamperedApprovalBytes, captureReport: capture, captureReportBytes: captureBytes, referenceAudit: audit, referenceAuditBytes: auditBytes, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(auditBytes), trustedCallerArn: audit.callerArn, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }), /reference-audit/);
});

test("approval is deterministic for unchanged captured artifacts", () => {
  const second = createStageBPlanApprovalReport({ captureReportSha256: hash(captureBytes), referenceAuditPath: approval.referenceAuditPath, referenceAuditSha256: hash(auditBytes), referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha, toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256, approvedAt: approval.approvedAt, classification: capture.classification, brokerOperation: capture.brokerOperation, brokerUpdatePresent: capture.brokerUpdatePresent, brokerActions: capture.brokerActions, brokerResourceAddresses: capture.brokerResourceAddresses });
  assert.deepEqual(second, approval);
});

test("plan profile and broker operation registries match the emitted Stage B universe", () => {
  assert.deepEqual(STAGE_B_PLAN_PROFILES, ["BASELINE", "IMPORTED_BACKEND_METADATA_NORMALIZATION", "ECS_TASK_DEFINITION_ROTATION", "RECOVERY_ALIAS_ONLY", "PARTIAL_APPLY_RECOVERY", "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY"]);
  assert.deepEqual(STAGE_B_BROKER_OPERATIONS, ["none", "initial-create", "update", "recovery-alias-only", "partial-apply-recovery", "fresh-image-partial-apply-recovery"]);
  assert.throws(() => createStageBPlanCaptureReport({ ...capture, planProfile: "UNREVIEWED" }), /unsupported/);
  assert.throws(() => createStageBPlanApprovalReport({ ...approval, planProfile: "UNREVIEWED" }), /unsupported/);
});

test("Stage B derives creation versus runtime authority from authenticated plan operation, never operator input", () => {
  assert.equal(stageBApprovalAuthorityMode(approval), STAGE_B_PLAN_AUTHORITY);
  assert.equal(stageBApprovalAuthorityMode({ brokerOperation: "initial-create" }), STAGE_B_PLAN_AUTHORITY);
  assert.equal(stageBApprovalAuthorityMode({ brokerOperation: "none" }), STAGE_B_LIVE_AUTHORITY);
  assert.throws(() => stageBApprovalAuthorityMode({ brokerOperation: "operator-selected" }), /canonical broker operation/);
});

test("normal approval uses canonical address completeness instead of a fixed no-op count", () => {
  const current = assertStageBNormalPlanCompleteness(fixture, { referenceAudit: audit, strict: false });
  assert.equal(current.classification.actionCounts["no-op"], 71);

  const retainedKeys = Object.keys(STAGE_B_RETAINED_TASK_DEFINITION_DESCRIPTORS).sort();
  assert.deepEqual(retainedKeys, [...new Set(fixtureRetainedTaskDefinitions.map((entry) => entry.terraformAddress.match(/_retained\["[a-f0-9]+-([^\"]+)"\]$/)[1]))].sort());
  assert.equal(retainedKeys.length, Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).length);
  assert.deepEqual([...new Set(retainedKeys.map((key) => STAGE_B_RETAINED_TASK_DEFINITION_DESCRIPTORS[key].kind))].sort(), ["candidate", "executor"]);
  assert.doesNotThrow(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: audit, strict: false }));

  const wrongKind = structuredClone(audit);
  wrongKind.retainedTaskDefinitions.find((entry) => entry.terraformAddress.endsWith('-backend"]')).terraformAddress = wrongKind.retainedTaskDefinitions.find((entry) => entry.terraformAddress.endsWith('-backend"]')).terraformAddress.replace("candidate_retained", "executor_retained");
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: wrongKind, strict: false }), /collection kind/);
  const wrongExecutorKind = structuredClone(audit);
  const executorEntry = wrongExecutorKind.retainedTaskDefinitions.find((entry) => entry.terraformAddress.includes("executor_retained"));
  executorEntry.terraformAddress = executorEntry.terraformAddress.replace("executor_retained", "candidate_retained");
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: wrongExecutorKind, strict: false }), /collection kind/);
  const wrongFamily = structuredClone(audit);
  wrongFamily.retainedTaskDefinitions[0].family = STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]'];
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: wrongFamily, strict: false }), /family/);
  const unknownKey = structuredClone(audit);
  unknownKey.retainedTaskDefinitions[0].terraformAddress = 'aws_ecs_task_definition.executor_retained["e689d4d-unreviewed"]';
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: unknownKey, strict: false }), /malformed|contract|collection kind/);
  const malformedCollection = structuredClone(audit);
  malformedCollection.retainedTaskDefinitions[0].terraformAddress = malformedCollection.retainedTaskDefinitions[0].terraformAddress.replace("candidate_retained", "candidate_history");
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: malformedCollection, strict: false }), /malformed/);

  const futurePlan = structuredClone(fixture);
  const futureAddress = 'aws_ecs_task_definition.executor_retained["f00ba4d-full-rls-verification"]';
  futurePlan.resource_changes.splice(futurePlan.resource_changes.findIndex((change) => change.address === "aws_dynamodb_table.replay"), 0, { address: futureAddress, type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: {}, after: {} } });
  const futureAudit = structuredClone(audit);
  futureAudit.retainedTaskDefinitions.push({ terraformAddress: futureAddress, family: "mscqr-production-full-rls-green-full-rls-verification", classification: "retained-no-op", oldTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-verification:99" });
  assert.equal(assertStageBNormalPlanCompleteness(futurePlan, { referenceAudit: futureAudit, strict: false }).classification.actionCounts["no-op"], 72);

  const rejects = (mutate, pattern) => {
    const candidate = structuredClone(fixture);
    mutate(candidate);
    assert.throws(() => assertStageBNormalPlanCompleteness(candidate, { referenceAudit: audit, strict: false }), pattern);
  };
  rejects((candidate) => { candidate.resource_changes.find((change) => change.address === 'aws_ecs_task_definition.candidate_retained["e689d4d-backend"]').address = "aws_s3_bucket.unreviewed"; }, /canonical resource universe|omits/);
  rejects((candidate) => { candidate.resource_changes.find((change) => change.address === 'aws_ecs_task_definition.candidate_retained["e689d4d-backend"]').change.actions = ["update"]; }, /retained task-definition is not an exact no-op/);
  rejects((candidate) => { candidate.resource_changes = candidate.resource_changes.filter((change) => change.address !== 'aws_ecs_task_definition.candidate_retained["e689d4d-backend"]'); }, /resource universe|omits/);
  rejects((candidate) => { candidate.resource_changes.find((change) => change.address === "aws_dynamodb_table.replay").change.actions = ["update"]; }, /unsupported|mutation census/);
  const duplicateAudit = structuredClone(audit);
  duplicateAudit.retainedTaskDefinitions.find((entry) => entry.terraformAddress === 'aws_ecs_task_definition.candidate_retained["760df83-backend"]').oldTaskDefinitionArn = duplicateAudit.retainedTaskDefinitions.find((entry) => entry.terraformAddress === 'aws_ecs_task_definition.candidate_retained["60b782b-backend"]').oldTaskDefinitionArn;
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: duplicateAudit, strict: false }), /family\/revision/);
  const unknownFamilyAudit = structuredClone(audit);
  unknownFamilyAudit.retainedTaskDefinitions[0].terraformAddress = 'aws_ecs_task_definition.executor_retained["e689d4d-unreviewed"]';
  assert.throws(() => assertStageBNormalPlanCompleteness(fixture, { referenceAudit: unknownFamilyAudit, strict: false }), /malformed|contract/);
});

test("RECOVERY_ALIAS_ONLY survives recovery classification, capture, approval, permission, and apply binding", () => {
  const recoveryPlan = {
    terraform_version: "1.15.7",
    format_version: "1.2",
    variables: { stage_b_recovery_only: { value: true } },
    resource_changes: [
      { address: "aws_iam_policy.broker", type: "aws_iam_policy", change: { actions: ["no-op"], before: {}, after: {}, after_unknown: {} } },
      { address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["no-op"], before: {}, after: {}, after_unknown: {} } },
      { address: "aws_ecs_task_definition.candidate[\"backend\"]", type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: {}, after: {}, after_unknown: {} } },
      { address: "aws_lambda_alias.reviewed", mode: "managed", module: null, type: "aws_lambda_alias", change: { actions: ["update"], before: { function_version: "2" }, after: { function_version: "3" }, after_unknown: { routing_config: [] } } },
    ],
  };
  const recoveryEvidence = {
    currentObservedEvidence: {
      protectedSourceSha: "a".repeat(40), terraformLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", refreshReportSha256: "d".repeat(64), terraformSerial: 76,
      terraformAddress: "aws_lambda_alias.reviewed", resourceMode: "managed", resourceModule: null, resourceType: "aws_lambda_alias", resourceName: "reviewed",
      functionName: "mscqr-production-rls-approval-broker", aliasName: "reviewed", stateVersion: "3", configuredDesiredVersion: "3", liveVersion: "2",
      changedAttributes: ["function_version"], routingConfigurationChanged: false, descriptionChanged: false, functionIdentityChanged: false, aliasIdentityChanged: false, additionalManagedResourceDrift: false,
    },
  };
  assert.deepEqual(assertRecoveryOnlyPlan(recoveryPlan, recoveryEvidence).profile, "RECOVERY_ALIAS_ONLY");
  const saved = Buffer.from("recovery-saved-plan\n");
  const planBytes = Buffer.from(`${JSON.stringify(recoveryPlan)}\n`);
  const canonicalBytes = Buffer.from(`${canonicalJson(recoveryPlan)}\n`);
  const recoveryHashes = stageBPlanHashes({ savedPlanBytes: saved, planJsonBytes: planBytes, canonicalPlanJsonBytes: canonicalBytes });
  const recoveryCapture = createStageBPlanCaptureReport({
    toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), refreshReportSha256: "d".repeat(64), refreshBindingReportSha256: "e".repeat(64), recoveryAttestationSha256: "c".repeat(64), hashes: recoveryHashes,
    capturedAt: "2026-08-09T00:00:00.000Z", stageBLineage: recoveryEvidence.currentObservedEvidence.terraformLineage, stageBSerial: 76,
    terraformVersion: recoveryPlan.terraform_version, terraformFormatVersion: recoveryPlan.format_version, planProfile: "RECOVERY_ALIAS_ONLY",
    classification: { noOp: 3, create: 0, update: 1, destroy: 0, replacement: 0, unclassified: 0 },
    brokerEvidence: { brokerOperation: "recovery-alias-only", brokerUpdatePresent: false, brokerActions: ["no-op"], brokerResourceAddresses: ["aws_lambda_alias.reviewed"], brokerReferenceValidationPending: false },
  });
  const recoveryCaptureBytes = Buffer.from(`${JSON.stringify(recoveryCapture, null, 2)}\n`);
  const recoveryAudit = { planJsonSha256: recoveryHashes.planJsonSha256, recoveryAttestationSha256: recoveryCapture.recoveryAttestationSha256, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/recovery", auditedAt: "2026-08-09T00:01:00.000Z" };
  const recoveryAuditBytes = Buffer.from(`${JSON.stringify(recoveryAudit)}\n`);
  const recoveryApproval = createStageBPlanApprovalReport({
    captureReportSha256: hash(recoveryCaptureBytes), referenceAuditPath: path.join(directory, "recovery-audit.json"), referenceAuditSha256: hash(recoveryAuditBytes),
    referenceAuditCallerArn: recoveryAudit.callerArn, referenceAuditAt: recoveryAudit.auditedAt, toolingSha: recoveryCapture.toolingSha, toolingTreeSha256: recoveryCapture.toolingTreeSha256,
    refreshReportSha256: recoveryCapture.refreshReportSha256, refreshBindingReportSha256: recoveryCapture.refreshBindingReportSha256, recoveryAttestationSha256: recoveryCapture.recoveryAttestationSha256, stageBLineage: recoveryCapture.stageBLineage,
    stageBSerial: recoveryCapture.stageBSerial, hashes: recoveryHashes, logicalCanonicalPlanJsonSha256: recoveryHashes.logicalCanonicalPlanJsonSha256, approvedAt: "2026-08-09T00:02:00.000Z",
    planProfile: recoveryCapture.planProfile, classification: recoveryCapture.classification, brokerOperation: recoveryCapture.brokerOperation, brokerUpdatePresent: recoveryCapture.brokerUpdatePresent,
    brokerActions: recoveryCapture.brokerActions, brokerResourceAddresses: recoveryCapture.brokerResourceAddresses,
  });
  const recoveryApprovalBytes = Buffer.from(`${JSON.stringify(recoveryApproval, null, 2)}\n`);
  assert.doesNotThrow(() => assertStageBPlanCaptureReport(recoveryCapture, { captureReportBytes: recoveryCaptureBytes, hashes: recoveryHashes, recoveryAttestationSha256: recoveryCapture.recoveryAttestationSha256, stageBLineage: recoveryCapture.stageBLineage, stageBSerial: recoveryCapture.stageBSerial }));
  assert.doesNotThrow(() => assertStageBPlanApprovalReport(recoveryApproval, { approvalReportBytes: recoveryApprovalBytes, captureReport: recoveryCapture, captureReportBytes: recoveryCaptureBytes, referenceAudit: recoveryAudit, referenceAuditBytes: recoveryAuditBytes, hashes: recoveryHashes, logicalCanonicalPlanJsonSha256: recoveryHashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(recoveryAuditBytes), trustedCallerArn: recoveryAudit.callerArn, stageBLineage: recoveryCapture.stageBLineage, stageBSerial: recoveryCapture.stageBSerial }));
  assert.doesNotThrow(() => assertStageBPlanApprovedBinding(recoveryApproval, { approvalReportBytes: recoveryApprovalBytes, approvalReportSha256: hash(recoveryApprovalBytes), savedPlanBytes: saved, planJsonBytes: planBytes, canonicalPlanJsonBytes: canonicalBytes, referenceAudit: recoveryAudit, referenceAuditBytes: recoveryAuditBytes, expectedRecoveryAttestationSha256: recoveryCapture.recoveryAttestationSha256, expectedStageBLineage: recoveryCapture.stageBLineage, expectedStageBSerial: recoveryCapture.stageBSerial, now: new Date("2026-08-09T00:02:00.000Z") }));
  const manifest = { recoveryOnly: true, reviewed: ["aws_lambda_alias.reviewed"] };
  const permission = { planSha256: recoveryHashes.planJsonSha256, savedPlanSha256: recoveryHashes.savedPlanSha256, canonicalPlanJsonSha256: recoveryHashes.logicalCanonicalPlanJsonSha256, manifestSha256: hash(Buffer.from(canonicalJson(manifest))), planApprovalReportSha256: hash(recoveryApprovalBytes) };
  assert.doesNotThrow(() => assertPermissionReportPlanBinding(permission, { planJsonBytes: planBytes, savedPlanBytes: saved, manifest, planApprovalReportSha256: hash(recoveryApprovalBytes) }));
  assert.equal(recoveryCapture.planProfile, "RECOVERY_ALIAS_ONLY");
  assert.equal(recoveryApproval.planProfile, "RECOVERY_ALIAS_ONLY");
  assert.equal(permission.planApprovalReportSha256, hash(recoveryApprovalBytes));

  const rejectCapture = (mutate) => { const candidate = structuredClone(recoveryCapture); mutate(candidate); const bytes = Buffer.from(`${JSON.stringify(candidate, null, 2)}\n`); assert.throws(() => assertStageBPlanCaptureReport(candidate, { captureReportBytes: bytes, hashes: recoveryHashes, recoveryAttestationSha256: recoveryCapture.recoveryAttestationSha256, stageBLineage: recoveryCapture.stageBLineage, stageBSerial: recoveryCapture.stageBSerial })); };
  rejectCapture((candidate) => { delete candidate.planProfile; });
  rejectCapture((candidate) => { candidate.brokerUpdatePresent = true; });
  rejectCapture((candidate) => { candidate.brokerResourceAddresses = ["aws_lambda_function.broker"]; });
  rejectCapture((candidate) => { candidate.brokerOperation = "unknown"; });
  rejectCapture((candidate) => { delete candidate.recoveryAttestationSha256; delete candidate.recoveryPlan; });
  const mismatchedApproval = { ...recoveryApproval, planProfile: "BASELINE" };
  assert.throws(() => assertStageBPlanApprovalReport(mismatchedApproval, { approvalReportBytes: Buffer.from(`${JSON.stringify(mismatchedApproval, null, 2)}\n`), captureReport: recoveryCapture, captureReportBytes: recoveryCaptureBytes, referenceAudit: recoveryAudit, referenceAuditBytes: recoveryAuditBytes, hashes: recoveryHashes, logicalCanonicalPlanJsonSha256: recoveryHashes.logicalCanonicalPlanJsonSha256, referenceAuditSha256: hash(recoveryAuditBytes), trustedCallerArn: recoveryAudit.callerArn, stageBLineage: recoveryCapture.stageBLineage, stageBSerial: recoveryCapture.stageBSerial }));
});
