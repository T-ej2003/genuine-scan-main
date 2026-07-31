import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";

const historicalPolicyPath = "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v2.json";
const historicalCorrectedPolicyPath = "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v3.json";
const historicalPolicy = JSON.parse(fs.readFileSync(historicalPolicyPath, "utf8"));
const historicalCorrectedPolicy = JSON.parse(fs.readFileSync(historicalCorrectedPolicyPath, "utf8"));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const statements = historicalCorrectedPolicy.Statement;
const actions = statements.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
const statementOf = (candidate, action) => candidate.Statement.find(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes(action));
const statement = (action) => statementOf(historicalCorrectedPolicy, action);
const stageBTaskFamilies = [
  "mscqr-production-rls-green-backend-candidate",
  "mscqr-production-rls-green-worker-candidate",
  "mscqr-production-full-rls-green-application-canary",
  "mscqr-production-full-rls-green-full-rls-admin-bootstrap",
  "mscqr-production-full-rls-green-full-rls-admin-ownership",
  "mscqr-production-full-rls-green-full-rls-capability-preflight",
  "mscqr-production-full-rls-green-full-rls-role-provision",
  "mscqr-production-full-rls-green-full-rls-role-verify",
  "mscqr-production-full-rls-green-full-rls-rollback",
  "mscqr-production-full-rls-green-full-rls-runtime-policy",
  "mscqr-production-full-rls-green-full-rls-verification",
  "mscqr-production-full-rls-green-read-only-canary",
];
const stageBLogGroups = [
  "/ecs/mscqr-production/rls-green-backend",
  "/ecs/mscqr-production/rls-green-canary",
  "/ecs/mscqr-production/rls-green-worker",
  "/ecs/mscqr-production/rls-green-read-only-canary",
];
const arn = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:*`;
const logArn = (name) => `arn:aws:logs:eu-west-2:368992683803:log-group:${name}:*`;
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const auditActions = ["ecs:ListServices", "ecs:DescribeServices", "ecs:ListTasks", "ecs:DescribeTasks", "ecs:DescribeTaskDefinition", "lambda:GetFunctionConfiguration"];
const brokerFunctionArns = [
  "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker",
  "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:*",
];
const expectedV2Sha256 = "dccfa7c5cf64c266fd9ea1deabd78f6ed1b43b20132f729642cc5e2ceb65bc71";

test("PR #161 v2 remains the immutable historical artifact", () => {
  assert.equal(sha256(fs.readFileSync(historicalPolicyPath)), expectedV2Sha256);
  assert.deepEqual(statementOf(historicalPolicy, "ecs:DescribeTaskDefinition").Resource, stageBTaskFamilies.map(arn));
});

test("v3 changes only the dedicated DescribeTaskDefinition Resource field", () => {
  const v2Read = statementOf(historicalPolicy, "ecs:DescribeTaskDefinition");
  const v3Read = statement("ecs:DescribeTaskDefinition");
  assert.equal(v3Read.Sid, "DescribeStageBTaskDefinitionsReadOnly");
  assert.equal(v3Read.Effect, "Allow");
  assert.equal(v3Read.Action, "ecs:DescribeTaskDefinition");
  assert.equal(v3Read.Resource, "*");
  const normalize = (candidate) => candidate.Statement.map((value) => value.Sid === "DescribeStageBTaskDefinitionsReadOnly" ? { ...value, Resource: "<reviewed-correction>" } : value);
  assert.deepEqual(normalize(historicalPolicy), normalize(historicalCorrectedPolicy));
  assert.notDeepEqual(v2Read.Resource, v3Read.Resource);
});

test("release-deployer Stage B policy scopes deregistration to exact Stage B families", () => {
  const value = statement("ecs:DeregisterTaskDefinition");
  assert.deepEqual(value.Resource, stageBTaskFamilies.map(arn));
  assert.equal(value.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
  assert.ok(!value.Resource.some((resource) => /mscqr-(backend|frontend):/.test(resource)));
});

test("release-deployer Stage B policy scopes log-group creation to Stage B-owned groups", () => {
  const value = statement("logs:CreateLogGroup");
  assert.deepEqual(value.Resource, stageBLogGroups.map(logArn));
  assert.equal(value.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
  assert.ok(!value.Resource.some((resource) => resource.includes("/ecs/mscqr-production/full-rls-green:*")));
  assert.deepEqual(statement("logs:TagResource").Resource, stageBLogGroups.map(logArn));
});

test("permanent release policy contains every read action required for the plan-bound audit", () => {
  assert.deepEqual(auditActions.filter((action) => actions.includes(action)), auditActions);
  assert.deepEqual(statement("ecs:ListServices").Resource, "*");
  assert.deepEqual(statement("ecs:ListTasks").Resource, "*");
  for (const action of ["ecs:ListServices", "ecs:ListTasks"]) {
    const value = statement(action);
    assert.equal(value.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
    assert.equal(value.Condition.StringEquals["ecs:cluster"], clusterArn);
  }
  for (const action of ["ecs:DescribeServices", "ecs:DescribeTasks"]) {
    const value = statement(action);
    assert.equal(value.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
    assert.equal(value.Condition.StringEquals["ecs:cluster"], clusterArn);
    assert.equal(value.Resource.includes("mscqr-prod-euw2-main"), true);
  }
  const taskDefinitionRead = statement("ecs:DescribeTaskDefinition");
  assert.equal(statements.filter(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes("ecs:DescribeTaskDefinition")).length, 1);
  assert.equal(taskDefinitionRead.Sid, "DescribeStageBTaskDefinitionsReadOnly");
  assert.equal(taskDefinitionRead.Effect, "Allow");
  assert.equal(taskDefinitionRead.Action, "ecs:DescribeTaskDefinition");
  assert.equal(taskDefinitionRead.Resource, "*");
  assert.deepEqual(statement("lambda:GetFunctionConfiguration").Resource, brokerFunctionArns);
});

test("Stage B task-definition family enforcement remains exact outside the wildcard metadata read", () => {
  for (const action of ["ecs:TagResource", "ecs:DeregisterTaskDefinition"]) {
    assert.deepEqual(statement(action).Resource, stageBTaskFamilies.map(arn), action);
  }
  for (const action of ["ecs:TagResource", "ecs:DeregisterTaskDefinition", "ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:StopTask", "ecs:UpdateService", "ecs:DeleteService"]) {
    const value = statement(action);
    if (value) assert.notEqual(value.Resource, "*", action);
  }
  assert.equal(stageBTaskFamilies.length, 12);
  assert.ok(stageBTaskFamilies.every((family) => family.startsWith("mscqr-production-")));
});

test("audit read scope excludes blue services and all runtime mutation authority", () => {
  assert.equal(statement("ecs:DescribeServices").Resource.includes("mscqr-backend"), false);
  assert.equal(statement("ecs:DescribeServices").Resource.includes("mscqr-frontend"), false);
  for (const forbidden of ["ecs:RunTask", "ecs:StopTask", "ecs:UpdateService", "ecs:RegisterTaskDefinition", "lambda:InvokeFunction", "lambda:UpdateFunctionCode", "lambda:DeleteFunction"]) {
    assert.equal(actions.includes(forbidden), false, forbidden);
  }
  assert.equal(statement("lambda:GetFunctionConfiguration").Resource.some((resource) => resource.endsWith(":*:*")), false);
});

test("provider recovery policy adds no runtime, service, traffic, secret, database, or wildcard authority", () => {
  for (const forbidden of [
    "ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:StopTask", "ecs:UpdateService", "ecs:DeleteService",
    "logs:DeleteLogGroup", "logs:*", "iam:*", "sts:*",
    "secretsmanager:GetSecretValue", "kms:*", "rds:*", "route53:*", "elasticloadbalancing:*",
  ]) assert.equal(actions.includes(forbidden), false, forbidden);
  assert.equal(statement("ecs:DeregisterTaskDefinition").Resource.includes("*"), false);
  assert.equal(statement("logs:CreateLogGroup").Resource.includes("*"), false);
});

test("existing Stage B provider recovery permissions remain present", () => {
  assert.ok(actions.includes("iam:ListAttachedRolePolicies"));
  assert.deepEqual(statement("ecs:TagResource").Resource, stageBTaskFamilies.map(arn));
  assert.ok(actions.includes("dynamodb:TagResource"));
});

test("recovery runbook requires live policy update before retry", () => {
  const runbook = fs.readFileSync("documents/ops/iam/PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md", "utf8");
  assert.match(runbook, /DescribeTaskDefinition.*requires.*Resource \"\*\"/is);
  assert.match(runbook, /PRODUCTION_GREEN_STAGE_B_ECS_READBACK_RECOVERY_2026-07-30/i);
  assert.match(runbook, /audit generator and validator/i);
  assert.match(runbook, /not granted task execution or service mutation authority/i);
  assert.match(runbook, /v2.*immutable historical\s+artifact/is);
  assert.match(runbook, /v3.*post-merge correction/is);
  assert.match(runbook, /MSCQRProductionGreenStageBProviderRecovery-v2\.json/i);
  assert.match(runbook, /MSCQRProductionGreenStageBProviderRecovery-v3\.json/i);
  assert.match(runbook, /PROVIDER_DOCUMENT=.*MSCQRProductionGreenStageBProviderRecovery-v4\.json/);
  assert.match(runbook, /AUDIT_DOCUMENT=.*MSCQRProductionGreenStageBReferenceAuditReadOnly-v1\.json/);
  assert.match(runbook, /managed-policy version IDs?\s+are\s+discovered from the live policy/i);
  assert.match(runbook, /live managed policy remains on the pre-correction version until the\s+separately authorized update/i);
  assert.match(runbook, /merging source alone does not update AWS/i);
  assert.match(runbook, /must be version-updated after merge/i);
  assert.match(runbook, /must not be retried before the live managed policy matches source/i);
  assert.match(runbook, /fresh MFA-backed release session/i);
});
