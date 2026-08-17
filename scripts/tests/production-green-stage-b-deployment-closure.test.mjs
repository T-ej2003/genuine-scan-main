import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { assertStageBClosureMatrixCoverage, assertStageBTerraformBrokerPolicySource, classifyStageBPlan, STAGE_B_RESOURCE_ACTION_MATRIX } from "../aws/stage-b-deployment-contract.mjs";
import { assertStageBNormalPlanCompleteness } from "../aws/stage-b-plan-approval-contract.mjs";

const fixturePath = "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json";
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const closureMatrix = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBDeploymentClosure-v1.json", "utf8"));
const terraformConfiguration = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");

test("broker policy source recognizes exact Sid assignments independent of HCL alignment", () => {
  for (const spacing of [" ", "    ", "      "]) {
    const source = terraformConfiguration.replace('Sid    = "ReadAndStopOnlyPreDeploymentInventory"', `Sid${spacing}= "ReadAndStopOnlyPreDeploymentInventory"`);
    assert.doesNotThrow(() => assertStageBTerraformBrokerPolicySource(source));
  }
});

test("broker policy source rejects wrong, fabricated, malformed, and duplicate Sid assignments", () => {
  const sid = 'Sid    = "ReadAndStopOnlyPreDeploymentInventory"';
  for (const replacement of [
    'Sid = "WrongReadAndStop"',
    `# ${sid}`,
    `/* ${sid} */`,
    `label = "${sid}"`,
    'Sid : "ReadAndStopOnlyPreDeploymentInventory"',
    `${sid}\n        ${sid}`,
  ]) assert.throws(() => assertStageBTerraformBrokerPolicySource(terraformConfiguration.replace(sid, replacement)), /Sid assignments/);
});

test("backend ECS Exec policy has one exact closure entry and only the four channel actions", () => {
  const entries = closureMatrix.resources.filter(({ addressPattern }) => addressPattern === "aws_iam_role_policy.backend_ecs_exec");
  assert.equal(entries.length, 1);
  assert.deepEqual(entries[0], {
    addressPattern: "aws_iam_role_policy.backend_ecs_exec",
    type: "aws_iam_role_policy",
    actions: ["create", "no-op"],
    identity: "exact backend task role and stage-b-backend-ecs-exec-ssm-channels policy",
    layers: ["plan-validator", "permission-manifest", "apply-wrapper"],
  });
  assert.deepEqual(STAGE_B_RESOURCE_ACTION_MATRIX["aws_iam_role_policy.backend_ecs_exec"], {
    type: "aws_iam_role_policy",
    actions: [["create"], ["no-op"]],
    identity: "exact backend task role and ECS Exec SSM-channel policy name",
  });
  const terraform = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  const block = terraform.match(/resource "aws_iam_role_policy" "backend_ecs_exec"[\s\S]*?(?=\nresource )/)?.[0] || "";
  const actions = [...block.matchAll(/"(ssmmessages:[A-Za-z]+Channel)"/g)].map(([, action]) => action);
  assert.deepEqual(actions, ["ssmmessages:CreateControlChannel", "ssmmessages:CreateDataChannel", "ssmmessages:OpenControlChannel", "ssmmessages:OpenDataChannel"]);
  assert.doesNotMatch(block, /ssm:(StartSession|SendCommand|GetParameter)|ecs:ExecuteCommand|iam:|ec2:/);
  assert.equal((block.match(/Resource\s*=\s*"\*"/g) || []).length, 1);
});

test("removing a closure entry or adding an unknown resource fails closed", () => {
  const declarations = ["aws_iam_role_policy.backend_ecs_exec"];
  const matrixBases = closureMatrix.resources.map(({ addressPattern }) => addressPattern.split("[")[0]);
  assert.doesNotThrow(() => assertStageBClosureMatrixCoverage({ declarations, matrixBases }));
  assert.throws(() => assertStageBClosureMatrixCoverage({ declarations, matrixBases: matrixBases.filter((base) => base !== "aws_iam_role_policy.backend_ecs_exec") }), /no closure matrix entry: aws_iam_role_policy\.backend_ecs_exec/);
  assert.throws(() => assertStageBClosureMatrixCoverage({ declarations: [...declarations, "aws_iam_role_policy.unknown"], matrixBases }), /no closure matrix entry: aws_iam_role_policy\.unknown/);
});

test("production closure binds signed permission evidence to every selected plan artifact", () => {
  const source = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  assert.match(source, /assertPermissionReportPlanBinding/);
  for (const name of ["STAGE_B_PLAN_SHA256", "STAGE_B_SAVED_PLAN_SHA256", "STAGE_B_CANONICAL_PLAN_JSON_SHA256", "STAGE_B_PERMISSION_REPORT_SHA256", "STAGE_B_PERMISSION_REPORT_SIGNATURE_SHA256"]) assert.match(source, new RegExp(name));
  assert.match(source, /verifyPermissionReportSignature/);
  assert.match(source, /resolveStageBPermissionProfile/);
  assert.match(source, /permissionProfile: permissionReport\.permissionProfile/);
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

test("recovery consumers use the canonical signed verifier, never the unsigned classification flag", () => {
  const closure = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  const planner = fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8");
  const apply = fs.readFileSync("scripts/apply-production-green-stage-b.mjs", "utf8");
  for (const source of [closure, planner, apply]) {
    assert.match(source, /assertVerifiedStageBRecovery/);
    assert.doesNotMatch(source, /attestationVerified/);
  }
  assert.match(apply, /allowReviewedResourceDrift: recoveryPlan \|\| partialApplyRecovery \|\| freshImagePartialApplyRecovery \|\| trustedRecovery !== null/);
  assert.match(closure, /allowReviewedResourceDrift: recoveryPlan \|\| partialApplyRecovery \|\| freshImagePartialApplyRecovery \|\| trustedRecovery !== null/);
  assert.ok(planner.indexOf("assertVerifiedStageBRecovery") < planner.indexOf("allowReviewedResourceDrift: true"));
});

test("pull-request closure rejects recovery inputs without production approval", () => {
  const source = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  assert.match(source, /Recovery artifacts are not authorization inputs in pull-request provenance mode/);
  const branch = source.slice(source.indexOf('if (mode === "production") {'), source.indexOf('} else if (hasRecoveryInputs)'));
  assert.match(branch, /approvalReport\.recoveryAttestationSha256/);
});

test("production-shaped Stage B plan is fully classified with zero destroys", () => {
  const retained = fixture.resource_changes.filter((change) => change.address.includes("_retained[")).map((change) => change.address);
  const result = assertStageBNormalPlanCompleteness(fixture, { expectedRetainedAddresses: retained, strict: false }).classification;
  assert.equal(result.actionCounts["no-op"], 71);
  assert.equal(result.actionCounts.create, 12);
  assert.equal(result.actionCounts.update, 3);
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
      Sid: "RunOnlyApprovedPreDeploymentInventory",
      Effect: "Allow",
      Action: ["ecs:RunTask"],
      Resource: ["arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:*"]
    },
    {
      Sid: "DescribeOnlyPreDeploymentInventoryTaskDefinitions",
      Effect: "Allow",
      Action: ["ecs:DescribeTaskDefinition"],
      Resource: "*",
      Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } },
    },
    {
      Sid: "ReadAndStopOnlyPreDeploymentInventory",
      Effect: "Allow",
      Action: ["ecs:DescribeTasks", "ecs:StopTask"],
      Resource: [
        "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*",
      ],
    },
    {
      Sid: "TagOnlyPreDeploymentInventoryTasks",
      Effect: "Allow",
      Action: ["ecs:TagResource"],
      Resource: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/*",
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
        "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
        "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
      ],
      Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } },
    },
    { Sid: "ClaimOnlyStageBReplayRows", Effect: "Allow", Action: ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], Resource: "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-rls-stage-b-replay" },
    { Sid: "ReadOnlyStageAApproval", Effect: "Allow", Action: ["secretsmanager:GetSecretValue"], Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho" },
    { Sid: "VerifyOnlyStageAApprovalKey", Effect: "Allow", Action: ["kms:Verify"], Resource: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478" },
    { Sid: "WriteOnlyBrokerReceipts", Effect: "Allow", Action: ["s3:PutObject"], Resource: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/rls-broker-receipts/*" },
    { Sid: "WriteOnlyStageABrokerLogs", Effect: "Allow", Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:log-stream:*" },
    { Sid: "ReadOnlyPreDeploymentInventoryLogs", Effect: "Allow", Action: ["logs:DescribeLogStreams", "logs:GetLogEvents"], Resource: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/rls-green-backend:log-stream:*" },
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

test("predeployment DescribeTaskDefinition region condition drift fails closed", () => {
  const plan = concreteBrokerPlan();
  const policy = JSON.parse(plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy);
  policy.Statement.find((statement) => statement.Sid === "DescribeOnlyPreDeploymentInventoryTaskDefinitions").Condition.StringEquals["aws:RequestedRegion"] = "us-east-1";
  plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy = JSON.stringify(policy);
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), /condition differs/);
});
