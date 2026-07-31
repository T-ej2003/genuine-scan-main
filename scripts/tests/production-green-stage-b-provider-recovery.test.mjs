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

test("provider recovery policy adds no runtime, service, traffic, secret, database, or wildcard authority", () => {
  for (const forbidden of [
    "ecs:RegisterTaskDefinition", "ecs:RunTask", "ecs:StopTask", "ecs:UpdateService",
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
  assert.match(runbook, /merging source alone does not update AWS/i);
  assert.match(runbook, /must be version-updated after merge/i);
  assert.match(runbook, /must not be retried before the live managed policy matches source/i);
  assert.match(runbook, /fresh MFA-backed release session/i);
});
