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
const subjectTemplate = JSON.parse(fs.readFileSync(`${root}/oidc-subject-template.json`, "utf8"));
const transition = JSON.parse(fs.readFileSync("documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json", "utf8"));
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-stage-b-image-publisher";
const publisherSubject = "repo:T-ej2003/genuine-scan-main:environment:production:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/main";
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

test("OIDC trust permits only the customized production reusable-workflow subject", () => {
  const expected = trust.Statement[0].Condition.StringEquals;
  assert.equal(trust.Statement[0].Principal.Federated, "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com");
  assert.deepEqual(expected, {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": publisherSubject,
  });
  assert.equal(canAssume(expected), true);
  for (const value of [
    "repo:other/repository:environment:production:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/main",
    "repo:T-ej2003/genuine-scan-main:environment:staging:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/main",
    "repo:T-ej2003/genuine-scan-main:environment:production:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/other.yml@refs/heads/main",
    "repo:T-ej2003/genuine-scan-main:environment:production:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/release",
    "repo:T-ej2003/genuine-scan-main:pull_request",
    "repo:T-ej2003/genuine-scan-main:ref:refs/tags/v1:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/main",
    "repo:T-ej2003/genuine-scan-main:pull_request:job_workflow_ref:T-ej2003/genuine-scan-main/.github/workflows/production-green-stage-b-image-build.yml@refs/heads/main",
  ]) assert.equal(canAssume({ ...expected, "token.actions.githubusercontent.com:sub": value }), false);
  assert.equal(canAssume({ ...expected, "token.actions.githubusercontent.com:aud": "other-audience" }), false);
});

test("subject customization is exact and all repository OIDC consumers have a migration record", () => {
  assert.deepEqual(subjectTemplate.api.request, {
    use_default: false,
    include_claim_keys: ["repo", "context", "job_workflow_ref"],
  });
  assert.equal(subjectTemplate.publisherSubject, publisherSubject);
  const expectedWorkflows = [
    "aws-dr-alb-apply.yml", "aws-dr-cleanup-apply.yml", "aws-dr-db-apply.yml", "aws-dr-dns-apply.yml",
    "aws-dr-hardening-apply.yml", "aws-dr-object-storage-apply.yml", "aws-dr-operations.yml",
    "aws-dr-regional-readiness.yml", "aws-dr-snapshot-apply.yml", "auto-failover-monitor.yml",
    "deploy-ecs-release.yml", "production-green-stage-b-image-build.yml", "publish-ecs-images.yml",
    "release-gate.yml", "staging-terraform-remote-state-drift.yml",
  ];
  assert.deepEqual(transition.repositoryOidcConsumers.map(({ workflow }) => workflow.split("/").at(-1)).sort(), expectedWorkflows.sort());
  assert.ok(transition.transitionOrder.some((step) => /alongside/.test(step)));
  assert.ok(transition.rollback.some((step) => /use_default true/.test(step)));
});

test("Terraform OIDC trust policies use only the repository-approved AWS claim keys", () => {
  const allowed = new Set([
    "token.actions.githubusercontent.com:aud",
    "token.actions.githubusercontent.com:sub",
  ]);
  for (const file of fs.readdirSync("infra/aws/terraform", { recursive: true }).filter((entry) => entry.endsWith("trust-policy.json"))) {
    const document = JSON.parse(fs.readFileSync(`infra/aws/terraform/${file}`, "utf8"));
    for (const statement of document.Statement || []) {
      for (const conditions of Object.values(statement.Condition || {})) {
        for (const key of Object.keys(conditions)) {
          if (key.startsWith("token.actions.githubusercontent.com:")) assert.equal(allowed.has(key), true, `${file} uses unsupported ${key}`);
        }
      }
    }
  }
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
