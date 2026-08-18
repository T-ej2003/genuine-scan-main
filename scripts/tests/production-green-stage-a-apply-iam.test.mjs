import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const refreshContract = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAProviderRefreshContract-v1.json", "utf8"));
const statements = policy.Statement;
const asArray = (value) => Array.isArray(value) ? value : [value];
const matches = (pattern, value) => pattern === "*" || pattern === value || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)));

const production = Object.freeze({
  region: "eu-west-2",
  bucketArn: refreshContract.backend.bucketArn,
  stateArn: refreshContract.backend.stateArn,
  lockArn: refreshContract.backend.lockArn,
  endpointSecurityGroupArn: "arn:aws:ec2:eu-west-2:368992683803:security-group/sg-04d5bf116755ba412",
  storageKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/254a1eed-9472-4216-9da0-133a2c3b8ed5",
  approvalKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478",
  rootDropKeyArn: "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-drop",
  approvalSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho",
  subnetGroupArn: "arn:aws:rds:eu-west-2:368992683803:subgrp:mscqr-production-rls-green-phase2",
  parameterGroupArn: "arn:aws:rds:eu-west-2:368992683803:pg:mscqr-production-rls-green-pg18",
  checkerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
  checkerSourceRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-independent-checker",
  executorLogArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green",
  brokerLogArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker",
  executorRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
  brokerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker",
});

const checkerPolicyRefresh = refreshContract.resourceTypes.find(({ type }) => type === "aws_iam_role_policy");

const context = (region = production.region, overrides = {}) => ({
  "aws:RequestedRegion": region,
  "aws:ResourceTag/Environment": "production",
  "aws:ResourceTag/ManagedBy": "Terraform",
  "aws:ResourceTag/Component": "full-rls-green-stage-a",
  ...overrides,
});

const rootDropTagContext = (overrides = {}) => ({
  "aws:RequestedRegion": production.region,
  "aws:RequestTag/Environment": "production",
  "aws:RequestTag/ManagedBy": "Terraform",
  "aws:RequestTag/Component": "full-rls-green-stage-a",
  "aws:RequestTag/Stack": "production-green-stage-a",
  "aws:TagKeys": ["Environment", "ManagedBy", "Component", "Stack"],
  "kms:CallerAccount": "368992683803",
  "kms:KeySpec": "RSA_3072",
  "kms:KeyUsage": "SIGN_VERIFY",
  ...overrides,
});

const conditionMatches = (condition = {}, values) => Object.entries(condition).every(([operator, entries]) => Object.entries(entries).every(([key, expectedValue]) => {
  const expected = asArray(expectedValue).map(String);
  const actual = values[key];
  if (operator === "ForAllValues:StringEquals") return Array.isArray(actual) && actual.every((value) => expected.includes(String(value)));
  if (operator !== "StringEquals") throw new Error(`Unsupported condition operator in focused contract: ${operator}`);
  return actual !== undefined && expected.includes(String(actual));
}));

const allows = ({ action, resource, values }) => statements.some((statement) => statement.Effect === "Allow"
  && asArray(statement.Action).includes(action)
  && asArray(statement.Resource).some((pattern) => matches(pattern, resource))
  && conditionMatches(statement.Condition, values));

const readCases = [
  ["ec2:DescribeVpcEndpoints", "*"],
  ["ec2:DescribeSecurityGroupRules", "*"],
  ["kms:DescribeKey", production.storageKeyArn],
  ["kms:DescribeKey", production.approvalKeyArn],
  ["kms:DescribeKey", production.rootDropKeyArn],
  ["rds:DescribeDBSubnetGroups", production.subnetGroupArn],
  ["rds:ListTagsForResource", production.subnetGroupArn],
  ["rds:DescribeDBParameterGroups", production.parameterGroupArn],
  ["rds:ListTagsForResource", production.parameterGroupArn],
  ["iam:GetRole", production.checkerRoleArn],
  ["iam:GetRolePolicy", production.checkerSourceRoleArn],
  ["iam:GetRolePolicy", production.checkerRoleArn],
  ["logs:ListTagsForResource", production.executorLogArn],
  ["logs:ListTagsForResource", production.brokerLogArn],
  ["secretsmanager:DescribeSecret", "*"],
];

test("Stage A provider refresh actions are exact and region-bound", () => {
  for (const [action, resource] of readCases) assert.equal(allows({ action, resource, values: context() }), true, `${action} ${resource}`);
  assert.equal(allows({ action: "rds:ListTagsForResource", resource: "arn:aws:rds:eu-west-2:368992683803:subgrp:unrelated", values: context() }), false);
  assert.equal(allows({ action: "rds:ListTagsForResource", resource: production.subnetGroupArn, values: context("us-east-1") }), false);
  assert.equal(allows({ action: "ec2:DescribeVpcEndpoints", resource: "*", values: context("us-east-1") }), false);
  assert.equal(allows({ action: "secretsmanager:DescribeSecret", resource: "*", values: context(production.region, { "aws:ResourceTag/Component": "unrelated" }) }), false);
  assert.equal(allows({ action: "iam:GetRolePolicy", resource: "arn:aws:iam::368992683803:role/unrelated", values: context() }), false);
});

test("the independent Stage A resource graph has a reviewed refresh contract", () => {
  const source = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  const discovered = new Set([...source.matchAll(/^resource "([^"]+)"/gm)].map(([, type]) => type));
  const contracted = new Set(refreshContract.resourceTypes.map(({ type }) => type));
  assert.deepEqual([...discovered].sort(), [...contracted].sort());
  assert.deepEqual(refreshContract.unmappedResourceTypes, []);
  for (const resourceType of refreshContract.resourceTypes) {
    assert.ok(resourceType.addresses.length > 0, resourceType.type);
    assert.ok(resourceType.readActions.length > 0, resourceType.type);
    for (const read of resourceType.readActions) {
      for (const resource of read.resources) {
        assert.equal(allows({ action: read.action, resource, values: context(read.region ?? production.region) }), true, `${resourceType.type} ${read.action} ${resource}`);
      }
    }
  }
  assert.deepEqual(checkerPolicyRefresh.addresses, ["aws_iam_role_policy.checker", "aws_iam_role_policy.checker_assume_target"]);
  assert.deepEqual(checkerPolicyRefresh.readActions, [{
    action: "iam:GetRolePolicy",
    resources: [production.checkerSourceRoleArn, production.checkerRoleArn],
    sourceOfProof: "provider iam/role_policy.go",
  }]);
});

test("the S3 backend contract covers exact state and lockfile lifecycle only", () => {
  for (const operation of refreshContract.backend.operations) {
    assert.equal(allows({ action: operation.action, resource: operation.resource, values: context() }), true, `${operation.action} ${operation.resource}`);
  }
  assert.equal(allows({ action: "s3:PutObject", resource: `${production.bucketArn}/mscqr/production/rls-green/stage-b/terraform.tfstate`, values: context() }), false);
  assert.equal(allows({ action: "s3:PutObject", resource: `${production.bucketArn}/arbitrary/object`, values: context() }), false);
  assert.equal(allows({ action: "s3:DeleteObject", resource: production.stateArn, values: context() }), false);
  assert.equal(allows({ action: "s3:DeleteObject", resource: `${production.bucketArn}/arbitrary.tflock`, values: context() }), false);
  assert.equal(allows({ action: "s3:GetObject", resource: "arn:aws:s3:::unrelated-bucket/state.tfstate", values: context() }), false);
  assert.equal(statements.flatMap(({ Action }) => asArray(Action)).includes("s3:ListBucket"), false);
});

test("Stage A apply permits only the exact endpoint security-group ingress", () => {
  assert.equal(allows({ action: "ec2:AuthorizeSecurityGroupIngress", resource: production.endpointSecurityGroupArn, values: context() }), true);
  assert.equal(allows({ action: "ec2:AuthorizeSecurityGroupIngress", resource: "arn:aws:ec2:eu-west-2:368992683803:security-group/sg-unrelated", values: context() }), false);
  assert.equal(allows({ action: "ec2:AuthorizeSecurityGroupIngress", resource: production.endpointSecurityGroupArn, values: context("us-east-1") }), false);
});

test("Stage A root-drop creation permits only exact KMS tag-on-create context", () => {
  assert.equal(allows({ action: "kms:TagResource", resource: "*", values: rootDropTagContext() }), true);
  assert.equal(allows({ action: "kms:TagResource", resource: "*", values: rootDropTagContext({ "aws:RequestTag/Stack": "legacy" }) }), false);
  assert.equal(allows({ action: "kms:TagResource", resource: "*", values: rootDropTagContext({ "kms:KeyUsage": "ENCRYPT_DECRYPT" }) }), false);
  assert.equal(allows({ action: "kms:TagResource", resource: "*", values: rootDropTagContext({ "aws:RequestedRegion": "us-east-1" }) }), false);
  assert.equal(allows({ action: "kms:TagResource", resource: "*", values: rootDropTagContext({ "aws:TagKeys": ["Environment", "ManagedBy", "Component", "Stack", "Extra"] }) }), false);
});

test("Stage A apply identity permits only the exact checker inline policies", () => {
  assert.equal(allows({ action: "iam:GetRolePolicy", resource: production.checkerSourceRoleArn, values: context() }), true);
  assert.equal(allows({ action: "iam:GetRolePolicy", resource: production.checkerRoleArn, values: context() }), true);
  assert.equal(allows({ action: "iam:GetRolePolicy", resource: "arn:aws:iam::368992683803:role/unrelated", values: context() }), false);
  assert.equal(allows({ action: "iam:PutRolePolicy", resource: production.checkerSourceRoleArn, values: context() }), true);
  assert.equal(allows({ action: "iam:PutRolePolicy", resource: production.checkerRoleArn, values: context() }), true);
  assert.equal(allows({ action: "iam:PutRolePolicy", resource: "arn:aws:iam::368992683803:role/unrelated", values: context() }), false);
  assert.equal(allows({ action: "iam:UpdateAssumeRolePolicy", resource: production.checkerRoleArn, values: context() }), true);
  for (const resource of [production.checkerSourceRoleArn, "arn:aws:iam::368992683803:role/unrelated", "arn:aws:iam::368992683803:role/mscqr-production-release-deployer"]) {
    assert.equal(allows({ action: "iam:UpdateAssumeRolePolicy", resource, values: context() }), false, resource);
  }
  for (const action of ["iam:AttachRolePolicy", "iam:PassRole", "iam:CreateRole", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:*"]) {
    assert.equal(allows({ action, resource: production.checkerRoleArn, values: context() }), false, action);
  }
});

test("independent checker permits only exact Stage B approval publication", () => {
  assert.equal(statements.some((statement) => statement.Effect === "Allow" && asArray(statement.Action).includes("secretsmanager:PutSecretValue") && asArray(statement.Resource).includes(production.approvalSecretArn)), false, "release policy must not publish approval");
  const checkerPolicy = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  assert.match(checkerPolicy, /Sid = "PublishExactStageBApproval"/);
  assert.match(checkerPolicy, /Action = "secretsmanager:PutSecretValue"/);
  assert.match(checkerPolicy, /Resource = aws_secretsmanager_secret\.approval\.arn/);
  assert.doesNotMatch(checkerPolicy, /secretsmanager:GetSecretValue/);
  assert.doesNotMatch(checkerPolicy, /secretsmanager:\*/);
});

test("Stage A policy has no unrelated mutation or secret/value authority", () => {
  const actions = statements.flatMap(({ Action }) => asArray(Action));
  for (const forbidden of [
    "ec2:RevokeSecurityGroupIngress", "ec2:ModifySecurityGroupRules", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
    "rds:ModifyDBInstance", "rds:ModifyDBCluster", "rds:DeleteDBInstance", "secretsmanager:GetSecretValue", "secretsmanager:UpdateSecret",
    "secretsmanager:ListSecretVersionIds", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "iam:AttachRolePolicy", "iam:PassRole",
    "logs:DeleteLogGroup", "ec2:RevokeSecurityGroupIngress", "ec2:ModifySecurityGroupRules", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup", "ecs:UpdateService", "ecs:RegisterTaskDefinition",
  ]) assert.equal(actions.includes(forbidden), false, forbidden);
  assert.equal(actions.some((action) => /^(ec2|rds|secretsmanager|kms):\*$/.test(action)), false);
  assert.equal(actions.includes("kms:Sign"), false);
  assert.equal(actions.includes("kms:PutKeyPolicy"), false);
  assert.equal(statements.filter(({ Action }) => asArray(Action).includes("ec2:AuthorizeSecurityGroupIngress")).length, 1);
  assert.equal(actions.includes("s3:DeleteObject"), true);
  assert.equal(actions.includes("s3:PutObject"), true);
  assert.equal(actions.includes("kms:*") || actions.includes("iam:*") || actions.includes("ec2:*") || actions.includes("rds:*") || actions.includes("secretsmanager:*") || actions.includes("logs:*") , false);
});
