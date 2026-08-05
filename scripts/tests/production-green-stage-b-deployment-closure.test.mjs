import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { classifyStageBPlan } from "../aws/stage-b-deployment-contract.mjs";

const fixturePath = "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json";
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

test("production closure binds signed permission evidence to every selected plan artifact", () => {
  const source = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  assert.match(source, /assertPermissionReportPlanBinding/);
  for (const name of ["STAGE_B_PLAN_SHA256", "STAGE_B_SAVED_PLAN_SHA256", "STAGE_B_CANONICAL_PLAN_JSON_SHA256", "STAGE_B_PERMISSION_REPORT_SHA256"]) assert.match(source, new RegExp(name));
});

test("production closure hoists backend metadata and validates refresh evidence once", () => {
  const source = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  assert.match(source, /let backendMetadata;/);
  assert.match(source, /backendMetadata = assertStageBTerraformBackendMetadataPrivate/);
  assert.match(source, /expectedBackendMetadataSha256: backendMetadata\.backendMetadataSha256/);
  assert.match(source, /expectedTerraformDataDir: backendMetadata\.terraformDataDir/);
  assert.equal((source.match(/assertStageBRefreshEvidence\(/g) || []).length, 1);
  assert.ok(source.indexOf("let backendMetadata;") < source.indexOf('if (mode === "production")'));
});

test("plan approval validation is production-only while optional tfvars provenance remains available", () => {
  const source = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  const optionalProvenanceStart = source.indexOf('if (mode === "production" || tfvarsPath || bindingReportPath)');
  const approvalGate = source.indexOf('if (mode === "production") assertStageBPlanApprovedBinding');
  assert.ok(optionalProvenanceStart >= 0);
  assert.ok(approvalGate > optionalProvenanceStart);
  assert.match(source.slice(optionalProvenanceStart, approvalGate), /assertStageBRefreshEvidence/);
  assert.doesNotMatch(source.slice(optionalProvenanceStart, approvalGate), /assertStageBPlanApprovedBinding/);
  assert.match(source.slice(0, optionalProvenanceStart), /if \(mode === "production"\)/);
});

test("production-shaped Stage B plan is fully classified with zero destroys", () => {
  const result = classifyStageBPlan(fixture, { strict: false });
  assert.deepEqual(result.actionCounts, { "no-op": 58, create: 12, update: 3 });
  assert.deepEqual(result.unclassifiedResources, []);
});

test("unknown resources fail before apply classification", () => {
  const plan = structuredClone(fixture);
  plan.resource_changes.push(
    { address: "aws_iam_policy.other", type: "aws_iam_policy", change: { actions: ["update"], before: {}, after: {} } },
    { address: "aws_ecs_service.other", type: "aws_ecs_service", change: { actions: ["update"], before: {}, after: {} } },
  );
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), (error) => /no exact contract layer/.test(error.message) && /aws_ecs_service\.other/.test(error.message));
});

test("destructive actions fail closed", () => {
  const plan = structuredClone(fixture);
  plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.actions = ["delete"];
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), /unsupported/);
});

test("broker policy and attachment are exact contract entries", () => {
  const policy = fixture.resource_changes.find((change) => change.address === "aws_iam_policy.broker");
  const attachment = fixture.resource_changes.find((change) => change.address === "aws_iam_role_policy_attachment.broker");
  assert.equal(policy.type, "aws_iam_policy");
  assert.deepEqual(policy.change.actions, ["update"]);
  assert.equal(attachment.type, "aws_iam_role_policy_attachment");
  assert.deepEqual(attachment.change.actions, ["no-op"]);
});

const canonicalBrokerPolicy = () => ({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "RunOnlyApprovedExecutorAndCanaryRevisions",
      Effect: "Allow",
      Action: ["ecs:RunTask"],
      Resource: [
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-application-canary:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-admin-bootstrap:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-admin-ownership:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-capability-preflight:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-role-provision:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-role-verify:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-rollback:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-runtime-policy:1",
        "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-full-rls-verification:1",
      ],
    },
    {
      Sid: "PassOnlyApprovedTaskRoles",
      Effect: "Allow",
      Action: ["iam:PassRole"],
      Resource: [
        "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
        "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
        "arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-task",
        "arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-execution",
      ],
      Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } },
    },
    { Sid: "ClaimOnlyStageBReplayRows", Effect: "Allow", Action: ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], Resource: "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-rls-stage-b-replay" },
    { Sid: "ReadOnlyStageAApproval", Effect: "Allow", Action: ["secretsmanager:GetSecretValue"], Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho" },
    { Sid: "VerifyOnlyStageAApprovalKey", Effect: "Allow", Action: ["kms:Verify"], Resource: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478" },
    { Sid: "WriteOnlyBrokerReceipts", Effect: "Allow", Action: ["s3:PutObject"], Resource: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/rls-broker-receipts/*" },
    { Sid: "WriteOnlyStageABrokerLogs", Effect: "Allow", Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:log-stream:*" },
  ],
});

const concreteBrokerPlan = () => {
  const plan = structuredClone(fixture);
  const policy = plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker");
  policy.change.after.policy = JSON.stringify(canonicalBrokerPolicy());
  policy.change.after_unknown = { policy: false };
  return plan;
};

test("broker policy concrete resources and conditions match the exact contract", () => {
  assert.doesNotThrow(() => classifyStageBPlan(concreteBrokerPlan(), { strict: false }));
});

test("broker policy resource drift fails closed even when actions remain canonical", () => {
  const plan = concreteBrokerPlan();
  const policy = JSON.parse(plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy);
  policy.Statement.find((statement) => statement.Sid === "PassOnlyApprovedTaskRoles").Resource[0] = "arn:aws:iam::368992683803:role/unrelated";
  plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy = JSON.stringify(policy);
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), /resource differs/);
});

test("broker policy condition drift fails closed even when actions remain canonical", () => {
  const plan = concreteBrokerPlan();
  const policy = JSON.parse(plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy);
  policy.Statement.find((statement) => statement.Sid === "PassOnlyApprovedTaskRoles").Condition.StringEquals["iam:PassedToService"] = "lambda.amazonaws.com";
  plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy = JSON.stringify(policy);
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), /condition differs/);
});
