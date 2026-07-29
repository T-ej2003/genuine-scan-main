import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { assertStageBImageBindings } from "../aws/stage-b-image-bindings.mjs";

const root = "infra/aws/terraform/production-green-stage-b-image-publisher";
const dispatcher = yaml.load(fs.readFileSync(".github/workflows/production-green-stage-b-images.yml", "utf8"));
const reusable = yaml.load(fs.readFileSync(".github/workflows/production-green-stage-b-image-build.yml", "utf8"));
const trust = JSON.parse(fs.readFileSync(`${root}/trust-policy.json`, "utf8"));
const policy = JSON.parse(fs.readFileSync(`${root}/permissions-policy.json`, "utf8"));
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-stage-b-image-publisher";
const repos = [
  "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend",
  "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker",
];

const canAssume = (claims) => {
  const expected = trust.Statement[0].Condition.StringEquals;
  return Object.entries(expected).every(([name, value]) => claims[name] === value);
};
const allows = (action, resource) => policy.Statement.some((statement) => statement.Effect === "Allow"
  && (statement.Action === action || statement.Action.includes?.(action))
  && (statement.Resource === "*" || statement.Resource.includes?.(resource)));
const denies = (action) => policy.Statement.some((statement) => statement.Effect === "Deny"
  && statement.Action.some((pattern) => pattern === action || (pattern.endsWith("*") && action.startsWith(pattern.slice(0, -1)))));

test("Stage B dispatcher exposes only a merged release SHA and calls the fixed reusable workflow", () => {
  assert.deepEqual(Object.keys(dispatcher.on.workflow_dispatch.inputs), ["release_sha"]);
  assert.equal(dispatcher.permissions["id-token"], undefined);
  assert.match(dispatcher.jobs["verify-release"].steps.at(-1).run, /stage-b-release-gate\.mjs/);
  assert.equal(dispatcher.jobs["build-and-attest"].uses, "./.github/workflows/production-green-stage-b-image-build.yml");
  assert.deepEqual(Object.keys(dispatcher.jobs["build-and-attest"].with), ["release_sha"]);
  assert.equal(dispatcher.jobs["build-and-attest"].with.release_sha, "${{ inputs.release_sha }}");
});

test("only the reusable build job receives fixed OIDC publishing authority", () => {
  assert.equal(reusable.on.workflow_call.inputs.release_sha.required, true);
  assert.deepEqual(Object.keys(reusable.on.workflow_call.inputs), ["release_sha"]);
  assert.equal(reusable.permissions["id-token"], "write");
  const job = reusable.jobs["build-and-attest"];
  assert.equal(job.environment, "production");
  assert.equal(job.env.AWS_REGION, "eu-west-2");
  assert.equal(job.env.AWS_ACCOUNT_ID, "368992683803");
  assert.equal(job.env.BACKEND_ECR_REPO, "mscqr-backend");
  assert.equal(job.env.WORKER_ECR_REPO, "mscqr-worker");
  const steps = job.steps;
  assert.ok(steps.findIndex((step) => /stage-b-release-gate/.test(step.run || "")) < steps.findIndex((step) => step.uses === "aws-actions/configure-aws-credentials@v6"));
  assert.match(JSON.stringify(job), /PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE/);
  assert.doesNotMatch(JSON.stringify(reusable), /inputs\.(role|repository|dockerfile|context|tag|label|platform|build)/i);
  assert.doesNotMatch(JSON.stringify(reusable), /mscqr-frontend:20|ecs update-service|deploy-ecs-service/i);
});

test("OIDC trust permits only the reviewed production reusable workflow identity", () => {
  const expected = trust.Statement[0].Condition.StringEquals;
  assert.equal(trust.Statement[0].Principal.Federated, "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com");
  assert.deepEqual(expected, {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production",
    "token.actions.githubusercontent.com:repository": "T-ej2003/genuine-scan-main",
    "token.actions.githubusercontent.com:job_workflow_ref": "T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/main",
  });
  assert.equal(canAssume(expected), true);
  for (const [claim, value] of [
    ["token.actions.githubusercontent.com:job_workflow_ref", "T-ej2003/genuine-scan-main/.github/workflows/other.yml@refs/heads/main"],
    ["token.actions.githubusercontent.com:repository", "other/repository"],
    ["token.actions.githubusercontent.com:sub", "repo:T-ej2003/genuine-scan-main:ref:refs/heads/main"],
    ["token.actions.githubusercontent.com:sub", "repo:T-ej2003/genuine-scan-main:pull_request"],
    ["token.actions.githubusercontent.com:sub", "repo:T-ej2003/genuine-scan-main:environment:staging"],
    ["token.actions.githubusercontent.com:aud", "other-audience"],
  ]) assert.equal(canAssume({ ...expected, [claim]: value }), false);
});

test("publisher permissions are ECR-only for the reviewed repositories", () => {
  assert.equal(allows("ecr:GetAuthorizationToken", "*"), true);
  for (const repository of repos) {
    assert.equal(allows("ecr:PutImage", repository), true);
    assert.equal(allows("ecr:UploadLayerPart", repository), true);
    assert.equal(allows("ecr:BatchGetImage", repository), true);
    assert.equal(allows("ecr:DescribeImageScanFindings", repository), true);
  }
  assert.equal(allows("ecr:PutImage", "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-web"), false);
  for (const action of ["ecs:UpdateService", "ecs:RunTask", "lambda:InvokeFunction", "secretsmanager:GetSecretValue", "rds:ModifyDBInstance", "iam:CreateRole"]) {
    assert.equal(allows(action, "*"), false);
    assert.equal(denies(action), true);
  }
  assert.equal(allows("kms:Decrypt", "*"), false);
  assert.equal(allows("s3:PutObject", "*"), false);
  assert.equal(roleArn.endsWith("mscqr-production-stage-b-image-publisher"), true);
});

test("all four fixed Stage B service identities remain immutable image bindings", () => {
  const releaseSha = "a".repeat(40); const sourceContractSha256 = "b".repeat(64); const migrationSetDigest = "c".repeat(64);
  for (const [service, title] of [["backend", "mscqr-backend"], ["worker", "mscqr-worker"], ["rls-executor", "mscqr-rls-executor"], ["rls-canary", "mscqr-rls-canary"]]) {
    assert.doesNotThrow(() => assertStageBImageBindings({ service, releaseSha, sourceContractSha256, migrationSetDigest, labels: {
      "org.opencontainers.image.revision": releaseSha,
      "com.mscqr.rls.source-contract-sha256": sourceContractSha256,
      "com.mscqr.rls.migration-set-digest": migrationSetDigest,
      "org.opencontainers.image.title": title,
    } }));
  }
});

test("publisher Terraform plan safety root owns only the dedicated role and inline policy", () => {
  const main = fs.readFileSync(`${root}/main.tf`, "utf8");
  const provider = fs.readFileSync(`${root}/providers.tf`, "utf8");
  assert.match(main, /resource "aws_iam_role" "publisher"/);
  assert.match(main, /resource "aws_iam_role_policy" "publisher"/);
  assert.doesNotMatch(main, /aws_(ecs|db|rds|lambda|secretsmanager|security_group|vpc|ecr)_/);
  assert.match(provider, /allowed_account_ids = \["368992683803"\]/);
  assert.doesNotMatch(fs.readFileSync(`${root}/outputs.tf`, "utf8"), /aws_secretsmanager|password\s*=/i);
});
