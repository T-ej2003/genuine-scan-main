import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertApplyArtifacts, assertPermissionReport, parseCli as parseApplyCli, runApply } from "../apply-production-green-stage-b.mjs";
import {
  canonicalizeJson,
  assertPermissionReportPlanBinding,
  deriveRequiredEvaluations,
  PERMISSION_REPORT_SIGNING_ALGORITHM,
  PERMISSION_REPORT_SIGNING_KEY_ARN,
  PERMISSION_EVIDENCE_MAX_AGE_MS,
  sourcePolicyEvidence,
  assertReleasePolicyEvidence,
  runCli,
  runPermissionPreflight as runPermissionPreflightRaw,
  signPermissionReport,
  simulatePrincipalPolicy,
  validateSimulationResult,
  validateManifest,
} from "../aws/validate-production-green-stage-b-permissions.mjs";
import simulatorAllowed from "./fixtures/aws-iam-simulate-principal-policy-allowed.mjs";
import { assertStageBReleaseCallerArn } from "../plan-production-green-stage-b.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";
import { buildStageBProtectedMainCheckoutEvidence } from "../aws/stage-b-deployment-identity.mjs";
import { generateImageEvidence, imageEvidenceSha256, signImageEvidence, IMAGE_EVIDENCE_MAX_AGE_MS } from "../aws/production-green-stage-b-image-evidence.mjs";

const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
const initializedBackendMetadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8")).backend;
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const brokerPolicyArn = "arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime";
const brokerRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker";
const generatorArn = "arn:aws:iam::368992683803:root";
const policyEvidence = (() => {
  const policies = sourcePolicyEvidence().map((policy) => ({ ...policy, defaultVersionId: "v1", liveSha256: policy.sourceSha256, attached: true, matchesSource: true }));
  return { roleArn, attachedPolicyArns: policies.map(({ arn }) => arn).sort(), inlinePolicyNames: [], inlinePolicies: [], permissionsBoundaryArn: null, policies, status: "valid" };
})();
const runPermissionPreflight = (input) => runPermissionPreflightRaw({ policyEvidence, ...input });

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
    change: { actions: ["create"], after: { family: "mscqr-production-full-rls-green-read-only-canary" } },
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
const now = "2026-08-01T12:00:00.000Z";
const clearCloudTrail = () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] });
const allowRequiredDenyForbidden = ({ evaluation }) => ({ decision: evaluation.id.startsWith("backend-") || evaluation.id.startsWith("pass-unrelated-role") || evaluation.id.startsWith("pass-to-lambda") || evaluation.id.startsWith("invoke-broker") || evaluation.id.startsWith("execute-ecs-task") || evaluation.id.startsWith("update-ecs-service") || evaluation.id.startsWith("create-iam-role") || evaluation.id.startsWith("deregister-task-definition") ? "explicitDeny" : "allowed", matchedStatements: 1, missingContextValues: [] });
const reportSignature = (report, overrides = {}) => ({
  schemaVersion: 1,
  keyId: PERMISSION_REPORT_SIGNING_KEY_ARN,
  keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN,
  signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM,
  reportSha256: crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(report))).digest("hex"),
  signatureBase64: "AQ==",
  signedAt: report.generatedAt,
  ...overrides,
});
const assertReport = (report, options = {}) => assertPermissionReport(report, { signatureArtifact: reportSignature(report), verifySignature: () => true, ...options });
const reportBinding = (report) => ({
  planSha256: report.planSha256,
  savedPlanSha256: report.savedPlanSha256,
  canonicalPlanJsonSha256: report.canonicalPlanJsonSha256,
  now,
});
const validReport = () => runPermissionPreflight({
  reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session",
  simulate: allowRequiredDenyForbidden,
  cloudTrail: clearCloudTrail,
});

test("manifest is source-controlled, exact-accounted, and has no wildcard PassRole", () => {
  assert.equal(validateManifest(manifest), true);
  assert.equal(manifest.taskDefinitionMappings.length, 12);
  assert.equal(new Set(manifest.taskDefinitionMappings.map((entry) => entry.address)).size, 12);
  assert.equal(manifest.taskDefinitionMappings.filter((entry) => entry.family === "mscqr-production-full-rls-green-read-only-canary").length, 1);
});

test("Stage A live-evidence preflight covers exactly the five region-bound read actions", () => {
  const expected = [
    ["collect-stage-a-live-subnets", "ec2:DescribeSubnets"], ["collect-stage-a-live-route-tables", "ec2:DescribeRouteTables"], ["collect-stage-a-live-security-groups", "ec2:DescribeSecurityGroups"], ["collect-stage-a-live-cluster", "ecs:DescribeClusters"], ["collect-stage-a-live-database", "rds:DescribeDBInstances"],
  ];
  const derived = deriveRequiredEvaluations(plan, manifest).required.filter((item) => item.manifestId.startsWith("collect-stage-a-live-"));
  assert.deepEqual(derived.map((item) => [item.manifestId, item.action, item.resource, item.context]), expected.map(([id, action]) => [id, action, "*", [{ key: "aws:RequestedRegion", type: "string", values: ["eu-west-2"] }] ]).sort(([left], [right]) => left.localeCompare(right)));
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

test("Stage A live-evidence policy source contains no mutation permission", () => {
  const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json", "utf8"));
  const statement = policy.Statement.find((item) => item.Sid === "ReadStageALivePrerequisites");
  assert.deepEqual(statement, { Sid: "ReadStageALivePrerequisites", Effect: "Allow", Action: ["ec2:DescribeSubnets", "ec2:DescribeRouteTables", "ec2:DescribeSecurityGroups", "ecs:DescribeClusters", "rds:DescribeDBInstances"], Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } });
  for (const action of ["ec2:CreateSubnet", "ecs:UpdateService", "rds:ModifyDBInstance"]) {
    const evaluation = { id: `unrelated-${action}`, action, resource: "*", context: [{ key: "aws:RequestedRegion", type: "string", values: ["eu-west-2"] }], expectedMissingContextValues: [] };
    Object.defineProperty(evaluation, "forbidden", { value: true });
    assert.equal(validateSimulationResult(evaluation, { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }).decision, "implicitDeny");
  }
});

const listBucketEvaluation = () => deriveRequiredEvaluations(plan, manifest).forbidden.find((item) => item.manifestId === "backend-list-bucket-not-required");
const deniedListBucketSimulation = ({ evaluation }) => evaluation.manifestId === "backend-list-bucket-not-required"
  ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] }
  : allowRequiredDenyForbidden({ evaluation });

test("direct backend rejects unneeded ListBucket without missing context", () => {
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test-session", simulate: deniedListBucketSimulation, cloudTrail: clearCloudTrail });
  const result = report.forbiddenEvaluations.find((item) => item.manifestId === "backend-list-bucket-not-required");
  assert.equal(report.status, "valid");
  assert.deepEqual({ expected: result.expectedMissingContextValues, actual: result.missingContextValues, decision: result.decision, matchedStatements: result.matchedStatements, validation: result.validation }, { expected: [], actual: [], decision: "implicitDeny", matchedStatements: 0, validation: "accepted" });
});

test("direct backend rejects missing context on its unneeded ListBucket proof", () => {
  const item = listBucketEvaluation();
  assert.throws(() => simulatePrincipalPolicy({ roleArn, evaluation: item, run: () => JSON.stringify({ EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: item.resource, EvalDecision: "implicitDeny", MatchedStatements: [], MissingContextValues: ["s3:prefix"] }] }) }), /unexpected MissingContextValues/);
});

test("unexpected missing context is rejected for forbidden and required evaluations", () => {
  const forbidden = structuredClone(listBucketEvaluation());
  forbidden.forbidden = true;
  forbidden.expectedMissingContextValues = [];
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

test("signed permission reports bind expected and actual missing context", () => {
  const report = validReport();
  assertReport(report, reportBinding(report));
  for (const field of ["expectedMissingContextValues", "missingContextValues"]) {
    const tampered = structuredClone(report);
    tampered.forbiddenEvaluations.find((item) => item.manifestId === "backend-list-bucket-not-required")[field] = ["s3:prefix"];
    assert.throws(() => assertReport(tampered, reportBinding(tampered)), /different expected missing context|unexpected MissingContextValues|inconsistent validation evidence/);
  }
});

test("exact canary create derives Register, TagResource, and both PassRole evaluations", () => {
  const derived = deriveRequiredEvaluations(plan, manifest);
  const passRoles = derived.required.filter((item) => item.action === "iam:PassRole");
  assert.deepEqual(passRoles.map((item) => item.resource), [
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-execution",
    "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-read-only-canary-task",
  ]);
  assert.ok(derived.required.some((item) => item.action === "ecs:RegisterTaskDefinition"));
  assert.ok(derived.required.some((item) => item.action === "ecs:TagResource"));
});

test("exact broker managed-policy update derives version actions for the exact policy", () => {
  const derived = deriveRequiredEvaluations({ ...plan, resource_changes: [plan.resource_changes[1]] }, manifest);
  assert.deepEqual(derived.required.filter((item) => ["update-broker-managed-policy", "prune-broker-managed-policy-versions"].includes(item.manifestId)), [{
    id: "prune-broker-managed-policy-versions:arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime",
    manifestId: "prune-broker-managed-policy-versions",
    action: "iam:DeletePolicyVersion",
    resource: brokerPolicyArn,
    context: [],
    expectedMissingContextValues: [],
    phase: "apply",
  }, {
    id: "update-broker-managed-policy:arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime",
    manifestId: "update-broker-managed-policy",
    action: "iam:CreatePolicyVersion",
    resource: brokerPolicyArn,
    context: [],
    expectedMissingContextValues: [],
    phase: "apply",
  }]);
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
    simulate: ({ evaluation }) => evaluation.action.startsWith("iam:") ? { decision, matchedStatements: 1, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation }),
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
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "valid");
  assert.equal(report.planSha256, crypto.createHash("sha256").update(planBytes).digest("hex"));
  assert.equal(report.deniedCount, 0);
  assertReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now });
});

test("missing required PassRole fails closed", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => evaluation.action === "iam:PassRole" ? { decision: "implicitDeny", matchedStatements: 0, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation }),
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
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => evaluation.id.startsWith("pass-unrelated-role") ? { decision: "allowed", matchedStatements: 1, missingContextValues: [] } : allowRequiredDenyForbidden({ evaluation }),
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "invalid");
  assert.ok(report.forbiddenEvaluations.some((item) => item.id.startsWith("pass-unrelated-role") && item.decision === "allowed"));
});

test("wrong plan binding and stale reports are rejected", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.throws(() => assertReport(report, { planSha256: "0".repeat(64), savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /different plan/);
  const stale = { ...report, generatedAt: "2026-08-01T11:00:00.000Z" };
  assert.throws(() => assertPermissionReport(stale, { signatureArtifact: reportSignature(stale), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /expired/);
  const oneHourOld = { ...report, generatedAt: new Date(Date.parse(now) - 60 * 60 * 1000).toISOString() };
  assert.ok(60 * 60 * 1000 > PERMISSION_EVIDENCE_MAX_AGE_MS);
  assert.throws(() => assertPermissionReport(oneHourOld, { signatureArtifact: reportSignature(oneHourOld), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /expired/);
});

test("image provenance and permission evidence use independent freshness windows", () => {
  assert.notEqual(IMAGE_EVIDENCE_MAX_AGE_MS, PERMISSION_EVIDENCE_MAX_AGE_MS);
  assert.ok(IMAGE_EVIDENCE_MAX_AGE_MS > PERMISSION_EVIDENCE_MAX_AGE_MS);
});

test("permission preflight requires binary-plan bytes and the report carries both plan hashes", () => {
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /Saved binary plan bytes/);
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  assert.match(report.savedPlanSha256, /^[a-f0-9]{64}$/);
  assert.match(report.canonicalPlanJsonSha256, /^[a-f0-9]{64}$/);
  const missingSavedHash = { ...report, savedPlanSha256: undefined };
  assert.throws(() => assertPermissionReport(missingSavedHash, { signatureArtifact: reportSignature(missingSavedHash), verifySignature: () => true, planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /saved binary plan/);
});

test("CloudTrail denial supplements simulation and blocks preflight", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
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
    change: { actions: ["create"], after: { family: mapping.family } },
  })), plan.resource_changes[1]] };
  const derived = deriveRequiredEvaluations(fullPlan, manifest);
  assert.equal(derived.coveredChanges.length, 13);
  assert.equal(derived.required.filter((item) => item.action === "ecs:RegisterTaskDefinition").length, 12);
  assert.equal(derived.required.filter((item) => item.action === "ecs:TagResource").length, 12);
  assert.equal(derived.required.filter((item) => item.action === "iam:PassRole").length, 24);
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

test("unsigned, modified, wrong-key, wrong-algorithm, wrong-hash, and stale reports fail signature verification", () => {
  const report = validReport();
  const artifact = reportSignature(report);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: undefined }), /signature/);
  assert.throws(() => assertPermissionReport({ ...report, status: "valid", deniedCount: 1 }, { ...reportBinding(report), signatureArtifact: artifact }), /different report/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/other" } }), /identity or algorithm/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256" } }), /identity or algorithm/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, reportSha256: "0".repeat(64) } }), /different report/);
  assert.throws(() => assertPermissionReport(report, { ...reportBinding(report), signatureArtifact: { ...artifact, signedAt: "2026-08-01T11:00:00.000Z" } }), /stale/);
});

test("release-deployer cannot generate a report or sign through the CLI", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-signing-caller-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json");
  fs.writeFileSync(planPath, planBytes); fs.writeFileSync(savedPath, savedPlanBytes); fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.throws(() => runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", path.join(directory, "report.json"), "--signature-output", path.join(directory, "signature.json"), "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test"], { getCaller: () => roleArn }), /Report generator caller/);
});

test("CLI passes its parsed manifest through the same preflight entrypoint", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-flow-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "report.signature.json");
  fs.writeFileSync(planPath, planBytes); fs.writeFileSync(savedPath, savedPlanBytes); fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  let received;
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test"], { getCaller: () => generatorArn, collectPolicyEvidence: () => policyEvidence, runPreflight: (input) => { received = input.manifest; return { status: "valid", generatedAt: now }; }, signReport: (report) => reportSignature(report) });
  assert.deepEqual(received, manifest);
  assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).status, "valid");
  assert.equal(JSON.parse(fs.readFileSync(signaturePath, "utf8")).reportSha256, reportSignature(JSON.parse(fs.readFileSync(outputPath, "utf8"))).reportSha256);
});

test("invalid administrator permission evidence is recorded but never signed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-invalid-preflight-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "report.signature.json");
  fs.writeFileSync(planPath, planBytes); fs.writeFileSync(savedPath, savedPlanBytes); fs.writeFileSync(manifestPath, JSON.stringify(manifest)); let signed = 0;
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test"], {
    getCaller: () => generatorArn, collectPolicyEvidence: () => policyEvidence,
    runPreflight: () => ({ status: "invalid", generatedAt: now, deniedCount: 2 }), signReport: () => { signed += 1; },
  });
  assert.equal(signed, 0); assert.equal(fs.existsSync(signaturePath), false); assert.equal(JSON.parse(fs.readFileSync(outputPath)).status, "invalid"); process.exitCode = 0;
});

test("CLI and programmatic preflight paths produce the same deterministic report", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-equivalence-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json"); const signaturePath = path.join(directory, "report.signature.json");
  fs.writeFileSync(planPath, planBytes); fs.writeFileSync(savedPath, savedPlanBytes); fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  const direct = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, manifest, plan, planBytes, savedPlanBytes, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--signature-output", signaturePath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test"], {
    getCaller: () => generatorArn,
    collectPolicyEvidence: () => policyEvidence,
    runPreflight: (input) => runPermissionPreflight({ ...input, generatedAt: now, now, simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }),
    signReport: (report) => reportSignature(report),
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(outputPath, "utf8")), direct);
});

function wrapperFixture({ approvedPlan = plan, shownPlan, savedBytes = savedPlanBytes, approvedBytes } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-binding-"));
  const planPath = path.join(directory, "approved.tfplan");
  const planJsonPath = path.join(directory, "approved.plan.json");
  const auditPath = path.join(directory, "approved.audit.json");
  const permissionPath = path.join(directory, "approved.permission.json");
  const imageEvidencePath = path.join(directory, "approved.image-evidence.json");
  const imageEvidenceSignaturePath = path.join(directory, "approved.image-evidence.signature.json");
  const releaseSha = "a".repeat(40);
  const effectivePlan = structuredClone(approvedPlan);
  effectivePlan.variables = {
    ...effectivePlan.variables,
    backend_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"a".repeat(64)}` },
    worker_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:${"b".repeat(64)}` },
    executor_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"c".repeat(64)}` },
    canary_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"d".repeat(64)}` },
    read_only_canary_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"d".repeat(64)}` },
  };
  const planImageVariable = (address) => address.startsWith("aws_ecs_task_definition.executor[") ? "executor_image" : `${/\["([^"]+)"\]$/.exec(address)?.[1]}_image`;
  for (const [address, family] of Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)) {
    const change = effectivePlan.resource_changes.find((candidate) => candidate.address === address);
    if (change) change.change.after.container_definitions = JSON.stringify([{ image: effectivePlan.variables[planImageVariable(address)].value }]);
    else effectivePlan.resource_changes.push({ address, type: "aws_ecs_task_definition", change: { actions: ["create"], after: { family, container_definitions: JSON.stringify([{ image: effectivePlan.variables[planImageVariable(address)].value }]) } } });
  }
  let effectiveShownPlan = structuredClone(shownPlan || effectivePlan);
  let effectiveApprovedBytes = approvedBytes || Buffer.from(JSON.stringify(effectivePlan));
  fs.writeFileSync(planPath, savedBytes);
  fs.writeFileSync(planJsonPath, effectiveApprovedBytes);
  let auditBytes = Buffer.from(JSON.stringify({ audit: true, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256: "c".repeat(64), broker: {
    aliasArn: STAGE_B.brokerAliasArn,
    aliasName: "reviewed",
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  } }));
  fs.writeFileSync(auditPath, auditBytes);
  const savedHash = crypto.createHash("sha256").update(savedBytes).digest("hex");
  let planHash = crypto.createHash("sha256").update(effectiveApprovedBytes).digest("hex");
  let canonicalHash = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(JSON.parse(JSON.stringify(effectiveShownPlan))))).digest("hex");
  const requiredFixtureEntry = manifest.required.find((entry) => !entry.plan);
  const forbiddenFixtureEntry = manifest.forbidden.find((entry) => entry.id === "backend-list-bucket-not-required");
  const fixtureEvaluation = (entry, forbidden, decision, missingContextValues) => ({
    id: `${entry.id}:${entry.resources[0]}`,
    manifestId: entry.id,
    action: entry.action,
    resource: entry.resources[0],
    context: entry.context,
    expectedMissingContextValues: entry.expectedMissingContextValues || [],
    missingContextValues,
    decision,
    matchedStatements: forbidden ? 0 : 1,
    validation: forbidden ? "accepted" : "accepted",
  });
  const report = {
    schemaVersion: 1,
    purpose: "saved-plan-authorization",
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
    forbiddenEvaluations: [fixtureEvaluation(forbiddenFixtureEntry, true, "implicitDeny", [])],
    cloudTrail: { status: "clear", unresolvedDenials: [] },
    policyEvidence,
    requiredAllowedCount: 1,
    requiredDeniedCount: 0,
    forbiddenAllowedCount: 0,
    forbiddenDeniedCount: 1,
    deniedCount: 0,
    status: "valid",
  };
  fs.writeFileSync(permissionPath, JSON.stringify(report));
  const permissionSignaturePath = path.join(directory, "approved.permission.signature.json");
  fs.writeFileSync(permissionSignaturePath, JSON.stringify(reportSignature(report)));
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
  const imageRepositories = ["mscqr-backend", "mscqr-worker"].map((repository) => ({ repositoryName: repository, repositoryArn: `arn:aws:ecr:eu-west-2:368992683803:repository/${repository}`, registryId: "368992683803", repositoryUri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}`, imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: "2026-04-17T15:17:09.210Z", observedAt: imageObservedAt }));
  const imageEvidence = generateImageEvidence({ artifactBytes: imageArtifactBytes, imageReleaseSha: releaseSha, workflowRunId: "30760789616", artifactSha256: imageArtifactSha256, verifierCallerArn: generatorArn, observedAt: imageObservedAt, repositories: imageRepositories, describe: (repository, tag) => ({ digest: `sha256:${imageRecords.find((record) => record.repository === repository && record.image_tag === tag).image_digest.slice(7)}`, imagePushedAt: "2026-08-02T18:26:34.000Z" }) });
  const canonicalImageEvidenceSha256 = imageEvidenceSha256(imageEvidence);
  effectivePlan.variables.canonical_image_evidence_sha256 = { value: canonicalImageEvidenceSha256 };
  const approvedPlanObject = approvedBytes ? JSON.parse(effectiveApprovedBytes) : effectivePlan;
  approvedPlanObject.variables.canonical_image_evidence_sha256 = { value: canonicalImageEvidenceSha256 };
  effectiveApprovedBytes = Buffer.from(JSON.stringify(approvedPlanObject));
  effectiveShownPlan.variables = { ...effectiveShownPlan.variables, canonical_image_evidence_sha256: { value: canonicalImageEvidenceSha256 } };
  fs.writeFileSync(planJsonPath, effectiveApprovedBytes);
  planHash = crypto.createHash("sha256").update(effectiveApprovedBytes).digest("hex");
  canonicalHash = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(JSON.parse(JSON.stringify(effectiveShownPlan))))).digest("hex");
  auditBytes = Buffer.from(JSON.stringify({ audit: true, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256, broker: {
    aliasArn: STAGE_B.brokerAliasArn,
    aliasName: "reviewed",
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  } }));
  fs.writeFileSync(auditPath, auditBytes);
  report.canonicalImageEvidenceSha256 = canonicalImageEvidenceSha256;
  report.planSha256 = planHash;
  report.canonicalPlanJsonSha256 = canonicalHash;
  const projectCapabilities = (items) => items.map(({ id, action, resource, context, decision }) => ({ id, action, resource, context, decision }));
  report.planCapabilities = { schemaVersion: 1, required: projectCapabilities(report.requiredEvaluations), forbidden: projectCapabilities(report.forbiddenEvaluations) };
  fs.writeFileSync(permissionPath, JSON.stringify(report));
  fs.writeFileSync(permissionSignaturePath, JSON.stringify(reportSignature(report)));
  fs.writeFileSync(imageEvidencePath, `${JSON.stringify(imageEvidence, null, 2)}\n`);
  fs.writeFileSync(imageEvidenceSignaturePath, JSON.stringify(signImageEvidence(imageEvidence, { sign: () => "AQ==" })));
  const brokerPackagePath = path.join(directory, "broker.zip");
  fs.writeFileSync(brokerPackagePath, Buffer.from("broker package fixture"), { mode: 0o600 });
  const stageAStateBackupPath = path.join(directory, "stage-a-state.json");
  fs.writeFileSync(stageAStateBackupPath, JSON.stringify({ lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 35 }), { mode: 0o600 });
  const stageAInputPath = path.join(directory, "stage-a-prerequisites.json");
  const stageAInput = {
    schemaVersion: 2, generator: "scripts/aws/generate-production-green-stage-a-prerequisites.mjs", toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), stageAStateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 35, stageAStateSha256: crypto.createHash("sha256").update(fs.readFileSync(stageAStateBackupPath)).digest("hex"),
    networkEvidence: { vpcId: "vpc-0123456789abcdef0", privateSubnets: STAGE_B.privateSubnetIds.map((subnetId, index) => ({ subnetId, availabilityZone: `eu-west-2${index ? "b" : "a"}`, cidrBlock: `10.0.${index}.0/24`, routeTableId: "rtb-12345678", natGatewayId: "nat-12345678" })), securityGroups: [STAGE_B.databaseSecurityGroupId, STAGE_B.executorSecurityGroupId].map((groupId) => ({ groupId, vpcId: "vpc-0123456789abcdef0" })), ecsClusterArn: STAGE_B.clusterArn, databaseIdentifier: "mscqr-production-rls-green", rdsSubnetIds: STAGE_B.privateSubnetIds },
    accountId: STAGE_B.account, region: STAGE_B.region, vpcId: "vpc-0123456789abcdef0", privateSubnetIds: STAGE_B.privateSubnetIds, ecsClusterArn: STAGE_B.clusterArn, stageADatabaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, stageAExecutorSecurityGroupId: STAGE_B.executorSecurityGroupId, stageAExecutorTaskRoleArn: STAGE_B.executorRoleArn, stageABrokerRoleArn: STAGE_B.brokerRoleArn, stageAExecutorLogGroupName: "/ecs/mscqr-production/full-rls-green", stageAExecutorLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green:*", stageABrokerLogGroupName: "/aws/lambda/mscqr-production-rls-approval-broker", stageABrokerLogGroupArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:*", stageARuntimeSecretArns: Object.fromEntries(["app", "read", "preauth", "worker", "scheduled", "operator", "migration"].map((role) => [role, `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/${role}-abc123`])), stageAExecutorNetworkingReady: true, approvalSecretArn: STAGE_B.approvalSecretArn, approvalKmsKeyArn: STAGE_B.approvalKmsKeyArn, receiptBucketArn: `arn:aws:s3:::${STAGE_B.receiptBucket}`, stageAReadOnlyCanaryDatabaseSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-abc123",
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
  const brokerBytes = fs.readFileSync(brokerPackagePath);
  const tfvarsBindingReport = {
    schemaVersion: 1, tfvarsSchemaVersion: 1, generator: "scripts/aws/generate-production-green-stage-b-tfvars.mjs",
    toolingSha: "b".repeat(40), toolingTreeSha256: "e".repeat(64), imageReleaseSha: "a".repeat(40), imageEvidenceCanonicalSha256: canonicalImageEvidenceSha256,
    stageAInputPath, stageAInputSha256: crypto.createHash("sha256").update(fs.readFileSync(stageAInputPath)).digest("hex"), stageAStateBackupPath, stageAStateBackupSha256: crypto.createHash("sha256").update(fs.readFileSync(stageAStateBackupPath)).digest("hex"), stageAStateObject: "mscqr/production/rls-green/stage-a/terraform.tfstate", stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 35, stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stateSerial: 76, brokerPackagePath,
    brokerPackageRawSha256: crypto.createHash("sha256").update(brokerBytes).digest("hex"), brokerPackageBase64Sha256: crypto.createHash("sha256").update(brokerBytes).digest("base64"),
    tfvarsSha256: crypto.createHash("sha256").update(tfvarsBytes).digest("hex"),
    images: Object.fromEntries(Object.entries(tfvarsValues).map(([variable, imageReference]) => [variable === "read_only_canary_image" ? "readOnlyCanary" : variable.replace(/_image$/, ""), { terraformVariable: variable, service: variable === "worker_image" ? "worker" : variable === "executor_image" ? "rls-executor" : variable.includes("canary") ? "rls-canary" : "backend", repository: variable === "worker_image" ? "mscqr-worker" : "mscqr-backend", tag: "a".repeat(40), imageReference, digestLength: 71, digest: imageReference.slice(imageReference.indexOf("@") + 1), matchesEvidence: true }])),
  };
  const tfvarsBindingReportPath = path.join(directory, "canonical.binding.json");
  fs.writeFileSync(tfvarsBindingReportPath, JSON.stringify(tfvarsBindingReport) + "\n", { mode: 0o600 });
  return { directory, planPath, planJsonPath, auditPath, permissionReportPath: permissionPath, permissionReportSignaturePath: permissionSignaturePath, permissionReportSha256: crypto.createHash("sha256").update(fs.readFileSync(permissionPath)).digest("hex"), imageEvidencePath, imageEvidenceSha256: canonicalImageEvidenceSha256, imageEvidenceSignaturePath, imageEvidenceWorkflowRunId: imageEvidence.workflowRunId, imageEvidenceArtifactSha256: imageEvidence.canonicalArtifactSha256, planHash, auditHash: crypto.createHash("sha256").update(auditBytes).digest("hex"), savedHash, canonicalHash, shownBytes: Buffer.from(JSON.stringify(effectiveShownPlan)), verifyImageEvidence: () => true, tfvarsPath, tfvarsBindingReportPath, tfvarsBindingReportSha256: crypto.createHash("sha256").update(fs.readFileSync(tfvarsBindingReportPath)).digest("hex"), toolingTreeSha256: "e".repeat(64) };
}

const wrapperArgs = (fixture, verifyOnly = false) => [
  ...(verifyOnly ? ["--verify-only"] : []),
  "--closure-mode", "production",
  "--plan", fixture.planPath, "--plan-json", fixture.planJsonPath, "--reference-audit", fixture.auditPath,
  "--permission-report", fixture.permissionReportPath, "--permission-report-sha256", fixture.permissionReportSha256, "--permission-report-signature", fixture.permissionReportSignaturePath,
  "--image-evidence", fixture.imageEvidencePath, "--image-evidence-sha256", fixture.imageEvidenceSha256, "--image-evidence-signature", fixture.imageEvidenceSignaturePath, "--image-evidence-workflow-run-id", fixture.imageEvidenceWorkflowRunId, "--image-evidence-artifact-sha256", fixture.imageEvidenceArtifactSha256,
  "--tooling-sha", "b".repeat(40), "--image-release-sha", "a".repeat(40), "--tfvars", fixture.tfvarsPath, "--tfvars-binding-report", fixture.tfvarsBindingReportPath, "--tfvars-binding-report-sha256", fixture.tfvarsBindingReportSha256, "--tooling-tree-sha256", fixture.toolingTreeSha256,
  "--plan-sha256", fixture.planHash, "--audit-sha256", fixture.auditHash, "--saved-plan-sha256", fixture.savedHash, "--canonical-plan-json-sha256", fixture.canonicalHash,
];

const createValidStageBApplyFixture = (options = {}) => ({
  ...wrapperFixture(options),
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
  env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default" },
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
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default" },
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
  fs.writeFileSync(fixture.tfvarsBindingReportPath, `${JSON.stringify(bindingReport)}\n`);
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
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default" },
    deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true, verifyImageEvidence: fixture.verifyImageEvidence, getBackendMetadata: () => structuredClone(initializedBackendMetadata), apply: () => { throw new Error("apply must not be reached"); } },
  });
  assert.equal(result.status, "ready-to-apply");
});

test("apply wrapper rejects an unqualified broker target before apply", () => {
  const fixture = wrapperFixture();
  const audit = { audit: true, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256: fixture.imageEvidenceSha256, broker: {
    aliasArn: STAGE_B.brokerFunctionArn,
    aliasName: "reviewed",
    aliasFunctionVersion: "2",
    configurationFunctionArn: STAGE_B.brokerAliasArn,
    configurationVersion: "2",
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
  } };
  const auditBytes = Buffer.from(JSON.stringify(audit));
  fs.writeFileSync(fixture.auditPath, auditBytes);
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
  const brokerChange = (address, type, actions) => ({ address, type, change: { actions, after: {} } });
  const planWithBrokerChanges = (changes) => ({
    ...plan,
    resource_changes: [
      ...plan.resource_changes.filter((change) => !["aws_lambda_function.broker", "aws_lambda_alias.reviewed", "aws_iam_policy.broker"].includes(change.address)),
      ...changes,
    ],
  });
  const run = (approvedPlan, aliasArn) => {
    const fixture = wrapperFixture({ approvedPlan });
    const auditBytes = Buffer.from(JSON.stringify({ audit: true, toolingSha: "b".repeat(40), imageReleaseSha: "a".repeat(40), canonicalImageEvidenceSha256: fixture.imageEvidenceSha256, broker: {
      aliasArn,
      aliasName: "reviewed",
      aliasFunctionVersion: "2",
      configurationFunctionArn: STAGE_B.brokerAliasArn,
      configurationVersion: "2",
      resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:2`,
    } }));
    fs.writeFileSync(fixture.auditPath, auditBytes);
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
  const policyNoOpAliasUpdate = planWithBrokerChanges([
    brokerChange("aws_iam_policy.broker", "aws_iam_policy", ["no-op"]),
    brokerChange("aws_lambda_alias.reviewed", "aws_lambda_alias", ["update"]),
  ]);
  const policyUpdateAliasNoOp = planWithBrokerChanges([
    brokerChange("aws_iam_policy.broker", "aws_iam_policy", ["update"]),
    brokerChange("aws_lambda_alias.reviewed", "aws_lambda_alias", ["no-op"]),
  ]);
  const multipleResources = planWithBrokerChanges([
    brokerChange("aws_lambda_alias.reviewed", "aws_lambda_alias", ["no-op"]),
    brokerChange("aws_lambda_function.broker", "aws_lambda_function", ["update"]),
    brokerChange("aws_iam_policy.broker", "aws_iam_policy", ["no-op"]),
  ]);
  const allNoOp = planWithBrokerChanges([
    brokerChange("aws_iam_policy.broker", "aws_iam_policy", ["no-op"]),
    brokerChange("aws_lambda_alias.reviewed", "aws_lambda_alias", ["no-op"]),
  ]);
  const unqualified = STAGE_B.brokerFunctionArn;
  for (const candidate of [policyNoOpAliasUpdate, policyUpdateAliasNoOp, multipleResources]) {
    assert.throws(run(candidate, unqualified), (error) => error instanceof Error && error.message.includes("Difference: alias, qualifier"));
  }
  assert.doesNotThrow(run(allNoOp, unqualified));
  const forward = run(policyNoOpAliasUpdate, unqualified);
  const reverse = run(planWithBrokerChanges([
    brokerChange("aws_lambda_alias.reviewed", "aws_lambda_alias", ["update"]),
    brokerChange("aws_iam_policy.broker", "aws_iam_policy", ["no-op"]),
  ]), unqualified);
  assert.throws(forward, /Stage B broker alias ARN mismatch/);
  assert.throws(reverse, /Stage B broker alias ARN mismatch/);
});

test("verification-only and real apply paths reject an invalid report signature before apply", () => {
  const fixture = wrapperFixture();
  for (const verifyOnly of [true, false]) {
    assert.throws(() => runApply({
      argv: wrapperArgs(fixture, verifyOnly),
      env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default" },
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
      env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default" },
      deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true, verifyImageEvidence: fixture.verifyImageEvidence, apply: () => { applied = true; } },
    }), /Terraform image variable backend_image/);
    assert.equal(applied, false);
  }
});

test("apply wrapper rejects a non-STS caller during verification-only mode", () => {
  const fixture = wrapperFixture();
  assert.throws(() => runApply({
    argv: wrapperArgs(fixture, true),
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "default" },
    deps: { getCaller: () => roleArn, currentHead: () => "b".repeat(40), showPlan: () => fixture.shownBytes, validatePlan: () => {}, verifyPermissionSignature: () => true, apply: () => { throw new Error("apply must not be reached"); } },
  }), /STS assumed-role/);
});
