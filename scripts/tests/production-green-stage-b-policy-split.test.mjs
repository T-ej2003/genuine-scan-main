import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";

const paths = {
  v2: "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v2.json",
  v3: "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v3.json",
  v4: "documents/ops/iam/MSCQRProductionGreenStageBProviderRecovery-v4.json",
  audit: "documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json",
};
const read = (path) => fs.readFileSync(path, "utf8");
const parse = (path) => JSON.parse(read(path));
const policies = Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, parse(path)]));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const actionsOf = (statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action];
const statementOf = (policy, sid) => policy.Statement.find((statement) => statement.Sid === sid);
const statementsForAction = (policy, action) => policy.Statement.filter((statement) => actionsOf(statement).includes(action));
const canonical = (policy) => ({
  Version: policy.Version,
  Statement: [...policy.Statement].sort((a, b) => a.Sid.localeCompare(b.Sid)),
});
const awsCharacterCount = (policy) => JSON.stringify(policy).replace(/\s/g, "").length;

const movedSids = [
  "ListAttachedRolePoliciesReadOnly",
  "ListStageBServicesReadOnly",
  "DescribeStageBServicesReadOnly",
  "ListStageBTasksReadOnly",
  "DescribeStageBTasksReadOnly",
  "DescribeStageBTaskDefinitionsReadOnly",
  "ReadStageBBrokerConfiguration",
];
const controlSids = [
  "TagExactStageBLogs",
  "CreateExactStageBLogs",
  "TagExactReplayTable",
  "TagExactStageBTaskDefinitions",
  "DeregisterExactStageBTaskDefinitions",
];
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
const arn = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:*`;
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const mutationActions = new Set([
  "ecs:TagResource",
  "ecs:DeregisterTaskDefinition",
  "ecs:RegisterTaskDefinition",
  "ecs:RunTask",
  "ecs:StopTask",
  "ecs:UpdateService",
  "ecs:DeleteService",
]);

test("all policy artifacts parse and historical v2/v3 remain byte-stable", () => {
  assert.equal(sha256(read(paths.v2)), "dccfa7c5cf64c266fd9ea1deabd78f6ed1b43b20132f729642cc5e2ceb65bc71");
  assert.equal(sha256(read(paths.v3)), "ff39b4afe356a06378e45d5941809739c172b007df1dc489ff66632247becf7e");
  assert.deepEqual(statementOf(policies.v2, "DescribeStageBTaskDefinitionsReadOnly").Resource, stageBTaskFamilies.map(arn));
});

test("v4 and the companion policy fit the AWS managed-policy document limit", () => {
  assert.equal(awsCharacterCount(policies.v3), 6651);
  assert.equal(awsCharacterCount(policies.v4), 4904);
  assert.equal(awsCharacterCount(policies.audit), 1785);
  assert.ok(awsCharacterCount(policies.v4) < 6144);
  assert.ok(awsCharacterCount(policies.audit) < 6144);
});

test("v4 plus the companion policy is semantically equivalent to v3", () => {
  assert.deepEqual(canonical(policies.v3), canonical({
    Version: policies.v3.Version,
    Statement: [...policies.v4.Statement, ...policies.audit.Statement],
  }));
});

test("the split has exactly seven moved statements and five provider-control statements", () => {
  assert.deepEqual(policies.audit.Statement.map(({ Sid }) => Sid), movedSids);
  assert.deepEqual(policies.v4.Statement.map(({ Sid }) => Sid), controlSids);
  assert.deepEqual(policies.v4.Statement.map(({ Sid }) => Sid).filter((sid) => movedSids.includes(sid)), []);
  assert.deepEqual(policies.audit.Statement.map(({ Sid }) => Sid).filter((sid) => controlSids.includes(sid)), []);
  assert.equal(new Set([...movedSids, ...controlSids]).size, 12);
  for (const sid of movedSids) assert.deepEqual(statementOf(policies.audit, sid), statementOf(policies.v3, sid));
  for (const sid of controlSids) assert.deepEqual(statementOf(policies.v4, sid), statementOf(policies.v3, sid));
});

test("DescribeTaskDefinition is isolated, wildcard-only, and read-only", () => {
  const matches = statementsForAction(policies.audit, "ecs:DescribeTaskDefinition");
  assert.equal(matches.length, 1);
  assert.deepEqual(matches[0], {
    Sid: "DescribeStageBTaskDefinitionsReadOnly",
    Effect: "Allow",
    Action: "ecs:DescribeTaskDefinition",
    Resource: "*",
    Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
  });
});

test("no ECS mutation statement in either deployable policy uses Resource wildcard", () => {
  for (const policy of [policies.v4, policies.audit]) {
    for (const statement of policy.Statement) {
      if (actionsOf(statement).some((action) => mutationActions.has(action))) assert.notEqual(statement.Resource, "*");
    }
  }
  assert.equal(policies.v4.Statement.some((statement) => actionsOf(statement).some((action) => mutationActions.has(action))), true);
  assert.equal(policies.audit.Statement.some((statement) => actionsOf(statement).some((action) => mutationActions.has(action))), false);
});

test("cluster, broker, and exact twelve-family restrictions remain unchanged", () => {
  const listServices = statementOf(policies.audit, "ListStageBServicesReadOnly");
  const describeServices = statementOf(policies.audit, "DescribeStageBServicesReadOnly");
  const listTasks = statementOf(policies.audit, "ListStageBTasksReadOnly");
  const describeTasks = statementOf(policies.audit, "DescribeStageBTasksReadOnly");
  for (const statement of [listServices, describeServices, listTasks, describeTasks]) {
    assert.equal(statement.Condition.StringEquals["aws:RequestedRegion"], "eu-west-2");
    assert.equal(statement.Condition.StringEquals["ecs:cluster"], clusterArn);
  }
  assert.deepEqual(statementOf(policies.audit, "ReadStageBBrokerConfiguration").Resource, [
    "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker",
    "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:*",
  ]);
  for (const sid of ["TagExactStageBTaskDefinitions", "DeregisterExactStageBTaskDefinitions"]) {
    assert.deepEqual(statementOf(policies.v4, sid).Resource, stageBTaskFamilies.map(arn));
  }
  assert.equal(stageBTaskFamilies.length, 12);
});

test("both policies carry no authority beyond the reviewed read and recovery actions", () => {
  const actions = [...policies.v4.Statement, ...policies.audit.Statement].flatMap(actionsOf);
  for (const forbidden of [
    "ecs:RunTask", "ecs:StopTask", "ecs:UpdateService", "ecs:DeleteService", "lambda:InvokeFunction",
    "lambda:UpdateFunctionCode", "iam:PutRolePolicy", "iam:AttachRolePolicy", "sts:AssumeRole",
    "secretsmanager:GetSecretValue", "kms:Decrypt", "rds:Connect", "route53:ChangeResourceRecordSets",
    "elasticloadbalancing:ModifyListener",
  ]) assert.equal(actions.includes(forbidden), false, forbidden);
  assert.equal(actions.includes("iam:ListAttachedRolePolicies"), true);
  assert.equal(actions.includes("lambda:GetFunctionConfiguration"), true);
});

test("validator rejects blue and unknown task-definition families and addresses", () => {
  const plan = (address, family) => ({
    resource_changes: [{ address, type: "aws_ecs_task_definition", change: { actions: ["create"], after: { family } } }],
  });
  for (const family of ["mscqr-backend", "mscqr-frontend", "unknown-task-family"]) {
    assert.throws(() => assertStageBPlan(plan(`aws_ecs_task_definition.candidate["${family}"]`, family)));
  }
  assert.throws(() => assertStageBPlan(plan("aws_ecs_task_definition.unknown[\"backend\"]", stageBTaskFamilies[0])));
});

test("the runbook targets v4 and the companion policy for the separately authorized live update", () => {
  const runbook = read("documents/ops/iam/PRODUCTION_GREEN_STAGE_B_PROVIDER_RECOVERY_2026-07-29.md");
  assert.match(runbook, /MSCQRProductionGreenStageBProviderRecovery-v4\.json/);
  assert.match(runbook, /MSCQRProductionGreenStageBReferenceAuditReadOnly-v1\.json/);
  assert.match(runbook, /mscqr-production-release-deployer/);
  assert.match(runbook, /attach-role-policy/);
  assert.match(runbook, /507/);
  assert.match(runbook, /6,144/);
  assert.match(runbook, /actual AWS-managed-policy\s+version ID/i);
});
