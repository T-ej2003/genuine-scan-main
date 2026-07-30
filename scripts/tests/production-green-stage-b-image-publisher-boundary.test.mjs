import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { assertStageBImageBindings } from "../aws/stage-b-image-bindings.mjs";

const root = "infra/aws/terraform/production-green-stage-b-image-publisher";
const dispatcher = yaml.load(fs.readFileSync(".github/workflows/production-green-stage-b-images.yml", "utf8"));
const reusable = yaml.load(fs.readFileSync(".github/workflows/production-green-stage-b-image-build.yml", "utf8"));
const backendPublisher = yaml.load(fs.readFileSync(".github/workflows/production-green-backend-image-publish.yml", "utf8"));
const trust = JSON.parse(fs.readFileSync(`${root}/trust-policy.json`, "utf8"));
const policy = JSON.parse(fs.readFileSync(`${root}/permissions-policy.json`, "utf8"));
const subjectTemplate = JSON.parse(fs.readFileSync(`${root}/oidc-subject-template.json`, "utf8"));
const transition = JSON.parse(fs.readFileSync("documents/security/rls-program/PRODUCTION_GREEN_STAGE_B_OIDC_SUBJECT_TRANSITION.json", "utf8"));
const environmentContract = JSON.parse(fs.readFileSync(`${root}/github-environment-contract.json`, "utf8"));
const roleArn = "arn:aws:iam::368992683803:role/mscqr-production-stage-b-image-publisher";
const publisherEnvironment = "production-stage-b-image-publish";
const publisherSubject = `repo:T-ej2003/genuine-scan-main:environment:${publisherEnvironment}`;
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
  const job = reusable.jobs["build-and-attest"];
  assert.equal(reusable.permissions["id-token"], undefined);
  assert.equal(job.environment, publisherEnvironment);
  assert.equal(job.permissions["id-token"], "write");
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

test("OIDC trust permits only the dedicated default-sub publishing environment", () => {
  const expected = trust.Statement[0].Condition.StringEquals;
  assert.equal(trust.Statement[0].Principal.Federated, "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com");
  assert.deepEqual(expected, {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": publisherSubject,
  });
  assert.equal(canAssume(expected), true);
  for (const value of [
    "repo:other/repository:environment:production-stage-b-image-publish",
    "repo:T-ej2003/genuine-scan-main:environment:production",
    "repo:T-ej2003/genuine-scan-main:environment:staging",
    "repo:T-ej2003/genuine-scan-main:environment:other-publisher",
    "repo:T-ej2003/genuine-scan-main:pull_request",
    "repo:T-ej2003/genuine-scan-main:ref:refs/heads/main",
    "repo:T-ej2003/genuine-scan-main:ref:refs/tags/v1",
  ]) assert.equal(canAssume({ ...expected, "token.actions.githubusercontent.com:sub": value }), false);
  assert.equal(canAssume({ ...expected, "token.actions.githubusercontent.com:aud": "other-audience" }), false);
});

test("repository OIDC stays default and all existing consumers require no subject migration", () => {
  assert.deepEqual(subjectTemplate.repositoryOidcSubjectTemplate, { use_default: true, activation: "do-not-change" });
  assert.equal(subjectTemplate.publisherEnvironment, publisherEnvironment);
  assert.equal(subjectTemplate.publisherSubject, publisherSubject);
  const expectedWorkflows = [
    "aws-dr-alb-apply.yml", "aws-dr-cleanup-apply.yml", "aws-dr-db-apply.yml", "aws-dr-dns-apply.yml",
    "aws-dr-hardening-apply.yml", "aws-dr-object-storage-apply.yml", "aws-dr-operations.yml",
    "aws-dr-regional-readiness.yml", "aws-dr-snapshot-apply.yml", "auto-failover-monitor.yml",
    "deploy-ecs-release.yml", "production-green-stage-b-image-build.yml", "publish-ecs-images.yml",
    "release-gate.yml", "staging-terraform-remote-state-drift.yml",
  ];
  assert.deepEqual(transition.repositoryOidcConsumers.map(({ workflow }) => workflow.split("/").at(-1)).sort(), expectedWorkflows.sort());
  assert.equal(transition.status, "superseded-do-not-apply");
  assert.ok(transition.repositoryOidcConsumers.slice(1).every(({ migration }) => migration.startsWith("none;")));
  assert.ok(transition.repositoryOidcConsumers.find(({ workflow }) => workflow.endsWith("staging-terraform-remote-state-drift.yml")).migration.includes("missing MSCQRStagingTerraformPlanRole"));
});

test("dedicated GitHub environment contract is approval-gated and used by no unrelated workflow", () => {
  assert.deepEqual(environmentContract, {
    name: publisherEnvironment,
    deploymentBranches: "protected-main-only",
    requiredReviewers: true,
    authorizedRequiredReviewers: ["T-ej2003"],
    preventSelfReview: true,
    forbidUnprotectedBranchesAndTags: true,
    variables: ["PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE"],
    forbiddenSecrets: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
    requiresEnvironmentSecrets: false,
    activation: "operator-configured; not managed by Terraform",
  });
  const workflowFiles = fs.readdirSync(".github/workflows").filter((file) => file.endsWith(".yml"));
  for (const file of workflowFiles.filter((file) => !["production-green-stage-b-image-build.yml", "production-green-backend-image-publish.yml"].includes(file))) {
    assert.doesNotMatch(fs.readFileSync(`.github/workflows/${file}`, "utf8"), new RegExp(`environment:\\s*${publisherEnvironment}`));
  }
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
    assert.equal(allows("ecr:PutImageTagMutability", repository), true);
    assert.equal(allows("ecr:PutImageScanningConfiguration", repository), true);
    assert.equal(allows("ecr:PutLifecyclePolicy", repository), true);
  }
  for (const action of ["ecr:PutImage", "ecr:PutImageTagMutability", "ecr:PutImageScanningConfiguration", "ecr:PutLifecyclePolicy"]) assert.equal(allows(action, "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-web"), false, action);
  for (const action of ["ecs:UpdateService", "ecs:RunTask", "lambda:InvokeFunction", "secretsmanager:GetSecretValue", "rds:ModifyDBInstance", "iam:CreateRole"]) {
    assert.equal(allows(action, "*"), false);
    assert.equal(denies(action), true);
  }
  assert.equal(allows("kms:Decrypt", "*"), false);
  assert.equal(allows("s3:PutObject", "*"), false);
  assert.equal(roleArn.endsWith("mscqr-production-stage-b-image-publisher"), true);
});

test("dedicated backend publisher is exact-SHA, environment-scoped, digest-first, and deployment-free", () => {
  assert.deepEqual(Object.keys(backendPublisher.on.workflow_dispatch.inputs), ["release_sha"]);
  assert.deepEqual(backendPublisher.permissions, { contents: "read", "id-token": "write" });
  const job = backendPublisher.jobs["publish-and-verify"];
  assert.equal(job.environment, publisherEnvironment);
  assert.equal(job.env.AWS_REGION, "eu-west-2");
  assert.equal(job.env.BACKEND_ECR_REPO, "mscqr-backend");
  assert.equal(job.env.PLATFORMS, "linux/amd64");
  const text = JSON.stringify(backendPublisher);
  assert.match(text, /PRODUCTION_STAGE_B_IMAGE_PUBLISH_ROLE/);
  assert.match(text, /stage-b-release-gate/);
  assert.match(text, /apply-ecr-repository-controls\.sh backend/);
  assert.match(text, /publish-ecs-images\.sh backend/);
  assert.match(text, /@sha256:/);
  assert.equal(job.steps.some((step) => step.uses === "aquasecurity/trivy-action@v0.36.0" && step.with?.severity === "CRITICAL" && step.with?.["exit-code"] === "1"), true);
  assert.equal(job.steps.some((step) => step.uses === "aquasecurity/trivy-action@v0.36.0" && step.with?.severity === "HIGH" && step.with?.output?.endsWith("trivy-high.json")), true);
  assert.match(text, /trivy-high\.json/);
  assert.match(text, /backend\.spdx\.json/);
  assert.match(text, /cosign sign/);
  const provenanceType = "https://mscqr.com/attestations/release-provenance/v1";
  const legacyProvenanceType = ["mscqr", "release", "provenance"].join("-");
  const attestationStep = job.steps.find((step) => step.name === "Generate SBOM, sign, attest, and verify immutable digest");
  assert.equal(new URL(provenanceType).protocol, "https:");
  assert.equal(job.env.PROVENANCE_ATTESTATION_TYPE, provenanceType);
  assert.match(attestationStep.run, /cosign attest --yes --type "\$PROVENANCE_ATTESTATION_TYPE"/);
  assert.match(attestationStep.run, /PROVENANCE_ATTESTATION_TYPE="\$PROVENANCE_ATTESTATION_TYPE" .*verify-release-artifacts/s);
  assert.doesNotMatch(attestationStep.run, new RegExp(`--type ${legacyProvenanceType}`));
  assert.match(text, /verify-release-artifacts/);
  assert.match(text, /production-green-read-only-rls-canary\.mjs/);
  assert.doesNotMatch(text, /AWS_ROLE_TO_ASSUME|aws-actions\/configure-aws-credentials@v6[\s\S]*AWS_ACCESS_KEY_ID|ecs:(?:UpdateService|RunTask)|lambda:InvokeFunction|deploy-ecs-service|inputs\.(?:role|repository|services|platform)/i);
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

test("publisher Terraform plan safety root owns only the dedicated role, exact policy, and attachment", () => {
  const main = fs.readFileSync(`${root}/main.tf`, "utf8");
  const provider = fs.readFileSync(`${root}/providers.tf`, "utf8");
  assert.match(main, /resource "aws_iam_role" "publisher"/);
  assert.match(main, /resource "aws_iam_policy" "publisher"/);
  assert.match(main, /resource "aws_iam_role_policy_attachment" "publisher"/);
  assert.match(main, /permissions_boundary = "arn:aws:iam::368992683803:policy\/MSCQRProductionStageBImagePublisherBoundary"/);
  assert.doesNotMatch(main, /aws_(ecs|db|rds|lambda|secretsmanager|security_group|vpc|ecr)_/);
  assert.match(provider, /allowed_account_ids = \["368992683803"\]/);
  assert.doesNotMatch(fs.readFileSync(`${root}/outputs.tf`, "utf8"), /aws_secretsmanager|password\s*=/i);
});
