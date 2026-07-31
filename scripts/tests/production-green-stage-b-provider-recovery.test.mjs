import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policyPath = "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v2.json";
const policy = JSON.parse(fs.readFileSync(policyPath, "utf8"));
const statements = policy.Statement;
const actions = statements.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
const statement = (action) => statements.find(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes(action));
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
  assert.match(runbook, /live managed policy has not been updated from PR #161/i);
  assert.match(runbook, /must not be\s+updated until this corrective PR is merged/i);
  assert.match(runbook, /merging source alone does not update AWS/i);
  assert.match(runbook, /must be version-updated after merge/i);
  assert.match(runbook, /must not be retried before the live managed policy matches source/i);
  assert.match(runbook, /fresh MFA-backed release session/i);
});
