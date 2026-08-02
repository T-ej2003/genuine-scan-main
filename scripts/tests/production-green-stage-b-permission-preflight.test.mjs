import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertApplyArtifacts, assertPermissionReport, runApply } from "../apply-production-green-stage-b.mjs";
import {
  canonicalizeJson,
  deriveRequiredEvaluations,
  runCli,
  runPermissionPreflight,
  simulatePrincipalPolicy,
  validateManifest,
} from "../aws/validate-production-green-stage-b-permissions.mjs";
import simulatorAllowed from "./fixtures/aws-iam-simulate-principal-policy-allowed.mjs";
import { assertStageBReleaseCallerArn } from "../plan-production-green-stage-b.mjs";

const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
const generatorArn = "arn:aws:iam::368992683803:root";
const plan = {
  variables: {
    account_id: { value: "368992683803" },
    aws_region: { value: "eu-west-2" },
  },
  resource_changes: [{
    address: 'aws_ecs_task_definition.candidate["read_only_canary"]',
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: { family: "mscqr-production-full-rls-green-read-only-canary" } },
  }],
};
const planBytes = Buffer.from(JSON.stringify(plan));
const savedPlanBytes = Buffer.from("saved-binary-plan");
const now = "2026-08-01T12:00:00.000Z";
const clearCloudTrail = () => ({ status: "clear", eventsChecked: 0, unresolvedDenials: [] });
const allowRequiredDenyForbidden = ({ evaluation }) => ({ decision: evaluation.id.startsWith("pass-unrelated-role") || evaluation.id.startsWith("pass-to-lambda") || evaluation.id.startsWith("invoke-broker") || evaluation.id.startsWith("execute-ecs-task") || evaluation.id.startsWith("update-ecs-service") || evaluation.id.startsWith("create-iam-role") || evaluation.id.startsWith("deregister-task-definition") ? "explicitDeny" : "allowed", matchedStatements: 1 });

test("manifest is source-controlled, exact-accounted, and has no wildcard PassRole", () => {
  assert.equal(validateManifest(manifest), true);
  assert.equal(manifest.taskDefinitionMappings.length, 12);
  assert.equal(new Set(manifest.taskDefinitionMappings.map((entry) => entry.address)).size, 12);
  assert.equal(manifest.taskDefinitionMappings.filter((entry) => entry.family === "mscqr-production-full-rls-green-read-only-canary").length, 1);
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

test("complete mocked preflight passes and binds the exact plan SHA", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "valid");
  assert.equal(report.planSha256, crypto.createHash("sha256").update(planBytes).digest("hex"));
  assert.equal(report.deniedCount, 0);
  assertPermissionReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now });
});

test("missing required PassRole fails closed", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: ({ evaluation }) => evaluation.action === "iam:PassRole" ? { decision: "implicitDeny" } : allowRequiredDenyForbidden({ evaluation }),
    cloudTrail: clearCloudTrail,
  });
  assert.equal(report.status, "invalid");
  assert.ok(report.requiredEvaluations.some((item) => item.action === "iam:PassRole" && item.decision === "implicitDeny"));
  assert.throws(() => assertPermissionReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /valid permission-preflight report/);
});

test("PassRole with the wrong service context is rejected by the manifest", () => {
  const broken = structuredClone(manifest);
  broken.taskDefinitionMappings[0].passRoleContext[0].values = ["lambda.amazonaws.com"];
  assert.throws(() => validateManifest(broken), /PassRole context/);
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
    simulate: ({ evaluation }) => evaluation.id.startsWith("pass-unrelated-role") ? { decision: "allowed" } : allowRequiredDenyForbidden({ evaluation }),
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
  assert.throws(() => assertPermissionReport(report, { planSha256: "0".repeat(64), savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /different plan/);
  assert.throws(() => assertPermissionReport({ ...report, generatedAt: "2026-08-01T11:00:00.000Z" }, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /expired/);
});

test("permission preflight requires binary-plan bytes and the report carries both plan hashes", () => {
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /Saved binary plan bytes/);
  const report = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  assert.match(report.savedPlanSha256, /^[a-f0-9]{64}$/);
  assert.match(report.canonicalPlanJsonSha256, /^[a-f0-9]{64}$/);
  assert.throws(() => assertPermissionReport({ ...report, savedPlanSha256: undefined }, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /saved binary plan/);
});

test("CloudTrail denial supplements simulation and blocks preflight", () => {
  const report = runPermissionPreflight({
    reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: "2026-08-01T11:55:00.000Z", cloudTrailSessionName: "test-session",
    simulate: allowRequiredDenyForbidden,
    cloudTrail: () => ({ status: "unresolved-denial", eventsChecked: 1, unresolvedDenials: [{ eventName: "PassRole" }] }),
  });
  assert.equal(report.status, "invalid");
  assert.equal(report.deniedCount, 1);
  assert.throws(() => assertPermissionReport(report, { planSha256: report.planSha256, savedPlanSha256: report.savedPlanSha256, canonicalPlanJsonSha256: report.canonicalPlanJsonSha256, now }), /valid permission-preflight report/);
});

test("saved-plan apply wrapper refuses to run without a permission report", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-preflight-"));
  const planPath = path.join(directory, "plan.tfplan");
  fs.writeFileSync(planPath, "saved-plan");
  assert.throws(() => runApply({
    argv: ["--plan", planPath, "--plan-json", path.join(directory, "plan.json"), "--reference-audit", path.join(directory, "audit.json"), "--permission-report", path.join(directory, "permission.json"), "--permission-report-sha256", "0".repeat(64), "--plan-sha256", "0".repeat(64), "--audit-sha256", "0".repeat(64), "--saved-plan-sha256", "0".repeat(64), "--canonical-plan-json-sha256", "0".repeat(64)],
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "production" },
    deps: { getCaller: () => `${roleArn}/test-session`, apply: () => { throw new Error("apply must not be reached"); } },
  }), /Permission-preflight report is missing/);
});

test("AWS simulator accepts the hand-reviewed PascalCase CLI fixture", () => {
  const result = simulatePrincipalPolicy({
    roleArn,
    evaluation: { id: "lambda-fixture", action: simulatorAllowed.EvaluationResults[0].EvalActionName, resource: simulatorAllowed.EvaluationResults[0].EvalResourceName, context: [] },
    run: () => JSON.stringify(simulatorAllowed),
  });
  assert.deepEqual(result, { decision: "allowed", matchedStatements: 0, missingContextValues: [] });
});

test("AWS simulator rejects camelCase-only and incomplete responses", () => {
  const item = { id: "lambda-fixture", action: "lambda:UpdateFunctionConfiguration", resource: simulatorAllowed.EvaluationResults[0].EvalResourceName, context: [] };
  for (const response of [
    { evaluationResults: [{ evalDecision: "allowed", matchedStatements: [] }] },
    { EvaluationResults: [] },
    { EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: item.resource, MatchedStatements: [], MissingContextValues: [] }] },
    { EvaluationResults: [{ EvalActionName: item.action, EvalResourceName: item.resource, EvalDecision: "allowed", MatchedStatements: [], MissingContextValues: ["aws:ResourceTag/Environment"] }] },
    { EvaluationResults: [{ EvalActionName: "lambda:UpdateAlias", EvalResourceName: item.resource, EvalDecision: "allowed", MatchedStatements: [], MissingContextValues: [] }] },
  ]) assert.throws(() => simulatePrincipalPolicy({ roleArn, evaluation: item, run: () => JSON.stringify(response) }), /malformed|mismatch/);
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
  const fullPlan = { ...plan, resource_changes: manifest.taskDefinitionMappings.map((mapping) => ({
    address: mapping.address,
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: { family: mapping.family } },
  })) };
  const derived = deriveRequiredEvaluations(fullPlan, manifest);
  assert.equal(derived.coveredChanges.length, 12);
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

test("preflight requires a manifest and rejects an unapproved generator", () => {
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /manifest is required/);
  assert.throws(() => runPermissionPreflight({ reportGeneratorCallerArn: "arn:aws:iam::368992683803:user/operator", simulatedRoleArn: roleArn, plan, planBytes, savedPlanBytes, manifest, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }), /approved audit\/admin/);
});

test("CLI passes its parsed manifest through the same preflight entrypoint", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-flow-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json");
  fs.writeFileSync(planPath, planBytes); fs.writeFileSync(savedPath, savedPlanBytes); fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  let received;
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test"], { getCaller: () => generatorArn, runPreflight: (input) => { received = input.manifest; return { status: "valid" }; } });
  assert.deepEqual(received, manifest);
  assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).status, "valid");
});

test("CLI and programmatic preflight paths produce the same deterministic report", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-cli-equivalence-"));
  const planPath = path.join(directory, "plan.json"); const savedPath = path.join(directory, "plan.tfplan"); const manifestPath = path.join(directory, "manifest.json"); const outputPath = path.join(directory, "report.json");
  fs.writeFileSync(planPath, planBytes); fs.writeFileSync(savedPath, savedPlanBytes); fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  const direct = runPermissionPreflight({ reportGeneratorCallerArn: generatorArn, simulatedRoleArn: roleArn, manifest, plan, planBytes, savedPlanBytes, generatedAt: now, now, policyPublishedAt: now, cloudTrailSessionName: "test", simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail });
  runCli(["--report-generator-caller-arn", generatorArn, "--simulated-role-arn", roleArn, "--plan-json", planPath, "--saved-plan", savedPath, "--manifest", manifestPath, "--output", outputPath, "--expected-account", "368992683803", "--expected-region", "eu-west-2", "--policy-published-at", now, "--cloudtrail-session-name", "test"], {
    getCaller: () => generatorArn,
    runPreflight: (input) => runPermissionPreflight({ ...input, generatedAt: now, now, simulate: allowRequiredDenyForbidden, cloudTrail: clearCloudTrail }),
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(outputPath, "utf8")), direct);
});

function wrapperFixture({ approvedPlan = plan, shownPlan = approvedPlan, savedBytes = savedPlanBytes, approvedBytes = Buffer.from(JSON.stringify(approvedPlan)) } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-plan-binding-"));
  const planPath = path.join(directory, "approved.tfplan");
  const planJsonPath = path.join(directory, "approved.plan.json");
  const auditPath = path.join(directory, "approved.audit.json");
  const permissionPath = path.join(directory, "approved.permission.json");
  fs.writeFileSync(planPath, savedBytes);
  fs.writeFileSync(planJsonPath, approvedBytes);
  const auditBytes = Buffer.from("{\"audit\":true}");
  fs.writeFileSync(auditPath, auditBytes);
  const savedHash = crypto.createHash("sha256").update(savedBytes).digest("hex");
  const planHash = crypto.createHash("sha256").update(approvedBytes).digest("hex");
  const canonicalHash = crypto.createHash("sha256").update(Buffer.from(canonicalizeJson(JSON.parse(JSON.stringify(shownPlan))))).digest("hex");
  const report = {
    schemaVersion: 1,
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
    requiredEvaluations: [{ decision: "allowed" }],
    forbiddenEvaluations: [{ decision: "explicitDeny" }],
    cloudTrail: { status: "clear", unresolvedDenials: [] },
    requiredAllowedCount: 1,
    requiredDeniedCount: 0,
    forbiddenAllowedCount: 0,
    forbiddenDeniedCount: 1,
    deniedCount: 0,
    status: "valid",
  };
  fs.writeFileSync(permissionPath, JSON.stringify(report));
  const permissionReportSha256 = crypto.createHash("sha256").update(fs.readFileSync(permissionPath)).digest("hex");
  return { directory, planPath, planJsonPath, auditPath, permissionReportPath: permissionPath, permissionReportSha256, planHash, auditHash: crypto.createHash("sha256").update(auditBytes).digest("hex"), savedHash, canonicalHash, shownBytes: Buffer.from(JSON.stringify(shownPlan)) };
}

test("exact binary plan and derived JSON reach the ready-to-apply boundary without applying", () => {
  const fixture = wrapperFixture();
  const result = runApply({
    argv: ["--verify-only", "--plan", fixture.planPath, "--plan-json", fixture.planJsonPath, "--reference-audit", fixture.auditPath, "--permission-report", fixture.permissionReportPath, "--permission-report-sha256", fixture.permissionReportSha256, "--plan-sha256", fixture.planHash, "--audit-sha256", fixture.auditHash, "--saved-plan-sha256", fixture.savedHash, "--canonical-plan-json-sha256", fixture.canonicalHash],
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "production" },
    deps: { getCaller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {}, apply: () => { throw new Error("apply must not be reached"); } },
  });
  assert.equal(result.status, "ready-to-apply");
});

test("saved-plan binding rejects stale, changed, or semantically different binary plans", () => {
  const fixture = wrapperFixture({ shownPlan: { ...plan, resource_changes: [{ address: "unexpected", change: { actions: ["delete"] } }] } });
  assert.throws(() => assertApplyArtifacts({ ...fixture, planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {} }), /Saved binary Terraform plan/);
  const changed = wrapperFixture({ savedBytes: Buffer.from("changed-binary") });
  assert.throws(() => assertApplyArtifacts({ ...changed, planSha256: changed.planHash, auditSha256: changed.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: changed.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => changed.shownBytes, validatePlan: () => {} }), /Saved Terraform plan SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, planSha256: "0".repeat(64), auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {} }), /Plan JSON SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: "", callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {} }), /Canonical plan JSON SHA256/);
  assert.throws(() => assertApplyArtifacts({ ...fixture, permissionReportSha256: "0".repeat(64), planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {} }), /Permission-preflight report SHA256/);
});

test("canonical key ordering is ignored while semantic plan differences fail", () => {
  const reordered = JSON.stringify({ resource_changes: plan.resource_changes, variables: plan.variables });
  const fixture = wrapperFixture({ approvedBytes: Buffer.from(reordered) });
  assert.doesNotThrow(() => assertApplyArtifacts({ ...fixture, planSha256: fixture.planHash, auditSha256: fixture.auditHash, savedPlanSha256: fixture.savedHash, canonicalPlanJsonSha256: fixture.canonicalHash, callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", showPlan: () => fixture.shownBytes, validatePlan: () => {} }));
});

test("apply wrapper rejects a non-STS caller during verification-only mode", () => {
  const fixture = wrapperFixture();
  assert.throws(() => runApply({
    argv: ["--verify-only", "--plan", fixture.planPath, "--plan-json", fixture.planJsonPath, "--reference-audit", fixture.auditPath, "--permission-report", fixture.permissionReportPath, "--permission-report-sha256", fixture.permissionReportSha256, "--plan-sha256", fixture.planHash, "--audit-sha256", fixture.auditHash, "--saved-plan-sha256", fixture.savedHash, "--canonical-plan-json-sha256", fixture.canonicalHash],
    env: { MSCQR_STAGE_B_APPLY_ENABLED: "true", MSCQR_STAGE_B_APPLY_CONFIRM: "MSCQR_APPLY_PRODUCTION_GREEN_STAGE_B_ONCE", TF_WORKSPACE: "production" },
    deps: { getCaller: () => roleArn, showPlan: () => fixture.shownBytes, validatePlan: () => {}, apply: () => { throw new Error("apply must not be reached"); } },
  }), /STS assumed-role/);
});
