import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const statements = policy.Statement;
const asArray = (value) => Array.isArray(value) ? value : [value];
const matches = (pattern, value) => pattern === "*" || pattern === value || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)));

const production = Object.freeze({
  region: "eu-west-2",
  endpointSecurityGroupArn: "arn:aws:ec2:eu-west-2:368992683803:security-group/sg-04d5bf116755ba412",
  storageKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/254a1eed-9472-4216-9da0-133a2c3b8ed5",
  approvalKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478",
  subnetGroupArn: "arn:aws:rds:eu-west-2:368992683803:subgrp:mscqr-production-rls-green-phase2",
  parameterGroupArn: "arn:aws:rds:eu-west-2:368992683803:pg:mscqr-production-rls-green-pg18",
  checkerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
  executorLogArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/ecs/mscqr-production/full-rls-green",
  brokerLogArn: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker",
  secrets: [
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-XNeSfh",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/canary/admin-email-gctAQZ",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-rR3kri",
  ],
});

const context = (region = production.region, overrides = {}) => ({
  "aws:RequestedRegion": region,
  ...overrides,
});

const conditionMatches = (condition = {}, values) => Object.entries(condition).every(([operator, entries]) => Object.entries(entries).every(([key, expectedValue]) => {
  const expected = asArray(expectedValue).map(String);
  const actual = values[key];
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
  ["rds:DescribeDBSubnetGroups", production.subnetGroupArn],
  ["rds:DescribeDBParameterGroups", production.parameterGroupArn],
  ["iam:GetRole", production.checkerRoleArn],
  ["logs:ListTagsForResource", production.executorLogArn],
  ["logs:ListTagsForResource", production.brokerLogArn],
  ...production.secrets.map((resource) => ["secretsmanager:DescribeSecret", resource]),
];

test("Stage A provider refresh actions are exact and region-bound", () => {
  for (const [action, resource] of readCases) assert.equal(allows({ action, resource, values: context() }), true, `${action} ${resource}`);
  assert.equal(allows({ action: "ec2:DescribeVpcEndpoints", resource: "*", values: context("us-east-1") }), false);
  assert.equal(allows({ action: "secretsmanager:DescribeSecret", resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:unrelated", values: context() }), false);
});

test("Stage A apply permits only the exact endpoint security-group ingress", () => {
  assert.equal(allows({ action: "ec2:AuthorizeSecurityGroupIngress", resource: production.endpointSecurityGroupArn, values: context() }), true);
  assert.equal(allows({ action: "ec2:AuthorizeSecurityGroupIngress", resource: "arn:aws:ec2:eu-west-2:368992683803:security-group/sg-unrelated", values: context() }), false);
  assert.equal(allows({ action: "ec2:AuthorizeSecurityGroupIngress", resource: production.endpointSecurityGroupArn, values: context("us-east-1") }), false);
});

test("Stage A policy has no unrelated mutation or secret/value authority", () => {
  const actions = statements.flatMap(({ Action }) => asArray(Action));
  for (const forbidden of [
    "ec2:RevokeSecurityGroupIngress", "ec2:ModifySecurityGroupRules", "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
    "rds:ModifyDBInstance", "rds:DeleteDBInstance", "secretsmanager:GetSecretValue", "secretsmanager:GetResourcePolicy",
    "secretsmanager:ListSecretVersionIds", "secretsmanager:PutSecretValue", "kms:ScheduleKeyDeletion", "iam:PassRole",
    "ecs:UpdateService", "ecs:RegisterTaskDefinition",
  ]) assert.equal(actions.includes(forbidden), false, forbidden);
  assert.equal(actions.some((action) => /^(ec2|rds|secretsmanager|kms):\*$/.test(action)), false);
  assert.equal(statements.filter(({ Action }) => asArray(Action).includes("ec2:AuthorizeSecurityGroupIngress")).length, 1);
});
