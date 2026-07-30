import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReadOnlyCanarySecretCreate-v1.json", "utf8"));
const stageA = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
const stageB = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const statements = Object.fromEntries(policy.Statement.map((statement) => [statement.Sid, statement]));
const name = "mscqr/production/rls-green/phase4/read-only-canary-database-url";
const arnPattern = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase4/read-only-canary-database-url-*";
const tags = { Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-a", Stack: "production-green-stage-a", Role: "read_only_canary" };
const tagKeys = Object.keys(tags);

const allowsCreate = ({ secretName, region = "eu-west-2", requestTags = tags }) => {
  const statement = statements.CreateOnlyExactStageAReadOnlyCanaryHandle;
  return statement.Condition.StringEquals["secretsmanager:Name"] === secretName
    && statement.Condition.StringEquals["aws:RequestedRegion"] === region
    && JSON.stringify(statement.Condition["ForAllValues:StringEquals"]["aws:TagKeys"].slice().sort()) === JSON.stringify(tagKeys.slice().sort())
    && JSON.stringify(requestTags) === JSON.stringify(tags);
};

test("CreateSecret is exact-name, eu-west-2, and exact-tag bounded", () => {
  const statement = statements.CreateOnlyExactStageAReadOnlyCanaryHandle;
  assert.deepEqual(statement.Action, "secretsmanager:CreateSecret");
  assert.equal(statement.Resource, "*");
  assert.equal(allowsCreate({ secretName: name }), true);
  assert.equal(allowsCreate({ secretName: "mscqr/production/rls-green/phase4/other" }), false);
  assert.equal(allowsCreate({ secretName: name, region: "us-east-1" }), false);
  assert.equal(allowsCreate({ secretName: name, requestTags: { ...tags, Extra: "denied" } }), false);
  assert.deepEqual(statement.Condition.StringEquals, {
    "secretsmanager:Name": name,
    "aws:RequestedRegion": "eu-west-2",
    "aws:RequestTag/Environment": "production",
    "aws:RequestTag/ManagedBy": "Terraform",
    "aws:RequestTag/Component": "full-rls-green-stage-a",
    "aws:RequestTag/Stack": "production-green-stage-a",
    "aws:RequestTag/Role": "read_only_canary",
  });
  assert.deepEqual(statement.Condition["ForAllValues:StringEquals"]["aws:TagKeys"].slice().sort(), tagKeys.slice().sort());
});

test("dependent tagging is limited to the generated ARN family and exact tags", () => {
  const statement = statements.TagOnlyExactStageAReadOnlyCanaryHandle;
  assert.deepEqual(statement.Action, "secretsmanager:TagResource");
  assert.equal(statement.Resource, arnPattern);
  assert.deepEqual(statement.Condition.StringEquals, {
    "aws:RequestedRegion": "eu-west-2",
    "aws:RequestTag/Environment": "production",
    "aws:RequestTag/ManagedBy": "Terraform",
    "aws:RequestTag/Component": "full-rls-green-stage-a",
    "aws:RequestTag/Stack": "production-green-stage-a",
    "aws:RequestTag/Role": "read_only_canary",
  });
});

test("no value, lifecycle, KMS, IAM, or broad Secrets Manager authority is granted", () => {
  const actions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  for (const forbidden of ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecret", "secretsmanager:DeleteSecret", "secretsmanager:RestoreSecret", "secretsmanager:RotateSecret", "secretsmanager:ReplicateSecretToRegions", "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret", "kms:*", "iam:*", "sts:*"]) assert.equal(actions.includes(forbidden), false, forbidden);
  assert.equal(actions.some((action) => action === "secretsmanager:*"), false);
  assert.equal(policy.Statement.length, 2);
});

test("Terraform remains the empty-handle owner and Stage B remains reference-only", () => {
  assert.match(stageA, /resource "aws_secretsmanager_secret" "read_only_canary"/);
  assert.doesNotMatch(stageA, /resource "aws_secretsmanager_secret_version" "read_only_canary"/);
  assert.doesNotMatch(stageA.match(/resource "aws_secretsmanager_secret" "read_only_canary" \{[\s\S]*?\n\}/)?.[0] || "", /secret_(?:string|binary)|rotation|replica|random_/);
  assert.doesNotMatch(stageB, /resource "aws_secretsmanager_secret(?:_version)?"/);
  assert.match(stageB, /var\.stage_a_read_only_canary_database_secret_arn/);
});
