import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const root = "infra/aws/terraform/production-green-stage-b-publisher-bootstrap";
const account = "368992683803";
const bucket = `arn:aws:s3:::mscqr-production-terraform-state-${account}-eu-west-2`;
const publisherRole = `arn:aws:iam::${account}:role/mscqr-production-stage-b-image-publisher`;
const publisherPolicy = `arn:aws:iam::${account}:policy/MSCQRProductionGreenStageBImagePublisher`;
const publisherBoundary = `arn:aws:iam::${account}:policy/MSCQRProductionStageBImagePublisherBoundary`;
const bootstrapUser = `arn:aws:iam::${account}:user/mscqr-production-bootstrap-operator`;
const trust = JSON.parse(fs.readFileSync(`${root}/trust-policy.json`, "utf8"));
const policy = JSON.parse(fs.readFileSync(`${root}/permissions-policy.json`, "utf8"));
const backend = JSON.parse(fs.readFileSync(`${root}/state-backend-contract.json`, "utf8"));
const evidence = JSON.parse(fs.readFileSync(`${root}/live-apply-evidence-template.json`, "utf8"));
const boundary = JSON.parse(fs.readFileSync(`${root}/publisher-permissions-boundary.json`, "utf8"));

const allow = (action, resource) => policy.Statement.some((statement) => statement.Effect === "Allow"
  && (statement.Action === action || statement.Action.includes?.(action))
  && (statement.Resource === resource || (Array.isArray(statement.Resource) && statement.Resource.includes(resource))));
const deny = (action) => policy.Statement.some((statement) => statement.Effect === "Deny"
  && (statement.Action === action || statement.Action.includes?.(action) || statement.Action.some?.((item) => item.endsWith("*") && action.startsWith(item.slice(0, -1)))));

test("only the existing MFA bootstrap operator can assume the short publisher bootstrap role", () => {
  const statement = trust.Statement[0];
  assert.equal(statement.Principal.AWS, bootstrapUser);
  assert.equal(statement.Action, "sts:AssumeRole");
  assert.deepEqual(statement.Condition, { Bool: { "aws:MultiFactorAuthPresent": "true" } });
  assert.doesNotMatch(JSON.stringify(trust), /root|Federated|github|oidc/i);
  assert.match(fs.readFileSync(`${root}/main.tf`, "utf8"), /max_session_duration = 3600/);
});

test("bootstrap role can manage only the exact publisher role, policy, and attachment", () => {
  assert.equal(allow("iam:CreateRole", publisherRole), true);
  const createRole = policy.Statement.find(({ Sid }) => Sid === "CreateOnlyTaggedPublisherRole");
  assert.equal(createRole.Condition.ArnEquals["iam:PermissionsBoundary"], publisherBoundary);
  for (const action of ["iam:GetRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole", "iam:DeleteRole", "iam:ListRolePolicies", "iam:ListRoleTags"]) {
    assert.equal(allow(action, publisherRole), true, action);
  }
  for (const action of ["iam:CreatePolicy", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion", "iam:DeletePolicy"]) {
    assert.equal(allow(action, publisherPolicy), true, action);
  }
  const attachment = policy.Statement.find(({ Sid }) => Sid === "AttachOnlyExactPublisherPolicy");
  assert.equal(attachment.Condition.ArnEquals["iam:PolicyARN"], publisherPolicy);
  assert.equal(allow("iam:AttachRolePolicy", publisherRole), true);
  const canAttach = (policyArn) => attachment.Resource === publisherRole
    && attachment.Condition.ArnEquals["iam:PolicyARN"] === policyArn;
  assert.equal(canAttach(publisherPolicy), true);
  assert.equal(canAttach(`arn:aws:iam::${account}:policy/Unrelated`), false);
  assert.equal(allow("iam:CreateRole", `arn:aws:iam::${account}:role/mscqr-production-release-deployer`), false);
  assert.equal(allow("iam:CreatePolicy", `arn:aws:iam::${account}:policy/Unrelated`), false);
  assert.equal(allow("iam:CreatePolicy", publisherBoundary), false);
  assert.equal(allow("iam:AttachRolePolicy", `arn:aws:iam::${account}:role/mscqr-production-release-deployer`), false);
  for (const action of ["iam:PassRole", "iam:CreateUser", "iam:CreateAccessKey"]) assert.equal(deny(action), true, action);
});

test("immutable publisher boundary limits effective permissions to the reviewed ECR surface", () => {
  const boundaryAllows = (action, resource) => boundary.Statement.some((statement) => statement.Effect === "Allow"
    && (statement.Action === action || statement.Action.includes?.(action))
    && (statement.Resource === resource || (Array.isArray(statement.Resource) && statement.Resource.includes(resource))));
  assert.equal(boundaryAllows("ecr:GetAuthorizationToken", "*"), true);
  for (const action of ["ecr:PutImage", "ecr:PutImageTagMutability", "ecr:PutImageScanningConfiguration", "ecr:PutLifecyclePolicy"]) {
    assert.equal(boundaryAllows(action, "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend"), true, action);
    assert.equal(boundaryAllows(action, "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker"), true, action);
    assert.equal(boundaryAllows(action, "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-unrelated"), false, action);
  }
  for (const action of ["iam:CreateRole", "sts:AssumeRole", "ecs:RunTask", "secretsmanager:GetSecretValue", "rds:ModifyDBInstance"]) {
    assert.equal(boundaryAllows(action, "*"), false, action);
  }
});

test("state access is confined to the exact publisher state object and lockfile", () => {
  assert.equal(backend.bucketName, `mscqr-production-terraform-state-${account}-eu-west-2`);
  assert.equal(backend.publisherStateKey, "mscqr/production/rls-green/stage-b-image-publisher/terraform.tfstate");
  assert.equal(backend.publisherStateLockKey, `${backend.publisherStateKey}.tflock`);
  assert.equal(allow("s3:GetObject", `${bucket}/${backend.publisherStateKey}`), true);
  assert.equal(allow("s3:PutObject", `${bucket}/${backend.publisherStateKey}`), true);
  assert.equal(allow("s3:DeleteObject", `${bucket}/${backend.publisherStateKey}`), false);
  assert.equal(allow("s3:DeleteObject", `${bucket}/${backend.publisherStateLockKey}`), true);
  for (const key of [
    "mscqr/production/rls-green/stage-a/terraform.tfstate",
    "staging-api/terraform.tfstate",
    "mscqr/production/dr/terraform.tfstate",
    backend.bootstrapStateKey,
  ]) assert.equal(allow("s3:GetObject", `${bucket}/${key}`), false, key);
});

test("unrelated infrastructure and secret-capable actions are explicitly denied or absent", () => {
  for (const action of [
    "ecs:RunTask", "ec2:CreateSecurityGroup", "ecr:PutImage", "lambda:InvokeFunction", "rds:ModifyDBInstance", "secretsmanager:GetSecretValue", "kms:Decrypt", "route53:ChangeResourceRecordSets", "elasticloadbalancing:ModifyListener",
  ]) {
    assert.equal(allow(action, "*"), false, action);
    assert.equal(deny(action), true, action);
  }
});

test("bootstrap root owns only the bootstrap role and its inline policy and records one-time break-glass evidence", () => {
  const main = fs.readFileSync(`${root}/main.tf`, "utf8");
  assert.match(main, /resource "aws_iam_policy" "publisher_permissions_boundary"/);
  assert.match(main, /resource "aws_iam_role" "publisher_bootstrap"/);
  assert.match(main, /resource "aws_iam_role_policy" "publisher_bootstrap"/);
  assert.doesNotMatch(main, /aws_(ecs|rds|db|lambda|secretsmanager|kms|security_group|ecr)_/);
  assert.equal(backend.rootApplyAllowed, false);
  assert.equal(backend.oneTimeBreakGlassBootstrapRequired, true);
  assert.equal(backend.publisherPermissionsBoundary, publisherBoundary);
  assert.equal(evidence.status, "template-only-no-live-apply-performed");
  assert.equal(evidence.noImagePublication, true);
  assert.equal(evidence.noSecretValueAccess, true);
  assert.equal(evidence.publisherPermissionsBoundaryArn, publisherBoundary);
});
