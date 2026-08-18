import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const root = "infra/aws/terraform/production-green-stage-a";
const source = fs.readFileSync(`${root}/main.tf`, "utf8");
const variables = fs.readFileSync(`${root}/variables.tf`, "utf8");
const outputs = fs.readFileSync(`${root}/outputs.tf`, "utf8");
const readme = fs.readFileSync(`${root}/README.md`, "utf8");
const checkerContract = JSON.parse(fs.readFileSync("documents/security/rls-program/production-full-rls-executor-contract.json", "utf8"));
const tfvarsExample = fs.readFileSync(`${root}/terraform.tfvars.example`, "utf8");
const receiptPattern = /^arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an$/;

test("Stage A accepts only the reviewed production receipt bucket", () => {
  assert.equal(receiptPattern.test("arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"), true);
  for (const value of ["arn:aws:s3:::mscqr-staging-euw2-artifacts-368992683803", "arn:aws:s3:::mscqr-prod-euw2-artifacts-000000000000-eu-west-2-an", "arn:aws:s3:::arbitrary", "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/*"]) assert.equal(receiptPattern.test(value), false);
  assert.match(variables, /mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an/);
});

test("Stage A canonically owns its existing Stack tag", () => {
  assert.match(source.match(/resource "aws_kms_key" "root_drop" \{([\s\S]*?)\n\}/)?.[1] || "", /tags\s*=\s*local\.tags/);
});

const terraformVariables = (tags) => [
    "aws_region=eu-west-2",
    "vpc_id=vpc-00000000000000000",
    "private_subnet_ids=[]",
    "runtime_security_group_ids=[]",
    "s3_prefix_list_id=pl-00000000",
    "vpc_dns_resolver_cidr=10.0.0.2/32",
    "checker_principal_arns=[\"arn:aws:iam::368992683803:role/mscqr-production-independent-checker\"]",
    "release_role_arn=arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
    "receipt_bucket_arn=arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
    `tags=${JSON.stringify(tags)}`,
];

const terraformDiagnostic = (phase, result) => {
  const output = `${result.stderr || ""}\n${result.stdout || ""}`
    .replace(/(AWS_[A-Z_]+|(?:access|secret|session)[-_]?(?:key|token)|password|authorization)\s*=\s*\S+/gi, "$1=<redacted>")
    .trim()
    .slice(-2000);
  return `${phase} failed${result.error ? `: ${result.error.message}` : ""}${output ? `\n${output}` : ""}`;
};

const createTerraformConsole = () => {
  const executionDir = fs.mkdtempSync(path.join(os.tmpdir(), "stage-a-terraform-test-"));
  const cleanup = () => fs.rmSync(executionDir, { recursive: true, force: true });
  try {
    const terraformRoot = path.join(executionDir, "configuration");
    fs.cpSync(path.resolve(root), terraformRoot, {
      recursive: true,
      filter(sourcePath) {
        const relativePath = path.relative(path.resolve(root), sourcePath);
        return relativePath !== ".terraform" && !relativePath.startsWith(`.terraform${path.sep}`);
      },
    });
    assert.equal(fs.existsSync(path.join(terraformRoot, ".terraform")), false, "Terraform test must not copy ambient .terraform data");
    assert.equal(fs.existsSync(path.join(terraformRoot, ".terraform.lock.hcl")), true, "Terraform test must retain the committed provider lockfile");
    const versionsPath = path.join(terraformRoot, "versions.tf");
    const versions = fs.readFileSync(versionsPath, "utf8");
    assert.match(versions, /backend\s+"s3"\s*\{\s*\}/);
    fs.writeFileSync(versionsPath, versions.replace(/\n\s*backend\s+"s3"\s*\{\s*\}\s*/, "\n"));
    const tfDataDir = path.join(executionDir, "terraform-data");
    fs.mkdirSync(tfDataDir);
    assert.deepEqual(fs.readdirSync(tfDataDir), [], "Terraform test data directory must start empty");
    const env = { ...process.env, TF_DATA_DIR: tfDataDir };
    const init = spawnSync("terraform", [
      `-chdir=${terraformRoot}`,
      "init",
      "-backend=false",
      "-input=false",
      "-lockfile=readonly",
    ], { cwd: process.cwd(), env, encoding: "utf8" });
    assert.equal(init.status, 0, terraformDiagnostic("terraform init", init));

    return {
      cleanup,
      evaluateTags(tags) {
        const result = spawnSync("terraform", [
          `-chdir=${terraformRoot}`,
          "console",
          "-state=/dev/null",
          "-input=false",
          ...terraformVariables(tags).flatMap((value) => ["-var", value]),
        ], { cwd: process.cwd(), env, input: "jsonencode(local.tags)\n", encoding: "utf8" });
        assert.equal(result.status, 0, terraformDiagnostic("terraform console", result));
        return JSON.parse(JSON.parse(result.stdout.trim()));
      },
    };
  } catch (error) {
    cleanup();
    throw error;
  }
};

test("Terraform keeps Stack canonical while preserving unrelated caller tags", () => {
  const runtime = createTerraformConsole();
  try {
    assert.equal(runtime.evaluateTags({}).Stack, "production-green-stage-a");
    assert.deepEqual(runtime.evaluateTags({ Stack: "legacy", Owner: "test" }), {
      Component: "full-rls-green-stage-a",
      Environment: "production",
      ManagedBy: "Terraform",
      Owner: "test",
      Stack: "production-green-stage-a",
    });
  } finally {
    runtime.cleanup();
  }
});

test("Stage A keeps checker and protected deployer distinct", () => {
  assert.match(variables, /checker_is_independent_of_release_deployer/);
  assert.match(variables, /!contains\(var\.checker_principal_arns, var\.release_role_arn\)/);
  assert.match(variables, /mscqr-production-release-deployer/);
});

test("checker chain has one MFA boundary and an exact role-to-role target", () => {
  const checkerTrust = source.match(/resource "aws_iam_role" "checker" \{([\s\S]*?)\n\}/)?.[1] || "";
  const chainPolicy = source.match(/resource "aws_iam_role_policy" "checker_assume_target" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(variables, /var\.checker_principal_arns\s*==\s*toset\(\["arn:aws:iam::368992683803:role\/mscqr-production-independent-checker"\]\)/);
  assert.match(checkerTrust, /Principal\s*=\s*\{\s*AWS\s*=\s*var\.checker_principal_arns\s*\}/);
  assert.match(checkerTrust, /Action\s*=\s*"sts:AssumeRole"/);
  assert.doesNotMatch(checkerTrust, /MultiFactorAuthPresent|Principal\s*=\s*"\*"|Resource\s*=\s*"\*"/);
  assert.match(chainPolicy, /role\s*=\s*local\.checker_assumer_role_name/);
  assert.match(chainPolicy, /Action\s*=\s*"sts:AssumeRole"/);
  assert.match(chainPolicy, /Resource\s*=\s*aws_iam_role\.checker\.arn/);
  assert.doesNotMatch(chainPolicy, /sts:\*|Resource\s*=\s*"\*"/);
  for (const forbidden of [
    "arn:aws:iam::368992683803:root",
    "arn:aws:iam::368992683803:role/mscqr-production-bootstrap-operator",
    "arn:aws:iam::368992683803:role/github-actions-mscqr-deploy",
    "arn:aws:iam::368992683803:role/mscqr-production-backend-runtime",
  ]) assert.doesNotMatch(variables, new RegExp(forbidden.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.deepEqual(checkerContract.checkerAuthentication, {
    sourceIamUser: "arn:aws:iam::368992683803:user/mscqr-production-checker-operator",
    mfaSerial: "arn:aws:iam::368992683803:mfa/mscqr-production-checker-operator",
    sourceRole: "arn:aws:iam::368992683803:role/mscqr-production-independent-checker",
    sourceTrustRequiresMfa: true,
    targetRole: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
    targetTrustPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-independent-checker",
    targetTrustRequiresFreshMfa: false,
    targetTrustReason: "AWS role chaining does not carry a fresh MFA request; the exact source-role trust is reachable only through the MFA-gated checker IAM user.",
    sourceRolePermission: "sts:AssumeRole on the exact targetRole only",
    sessionBinding: "The exact target-role STS session ARN is recorded in and signed by the approval artifact.",
  });
});

test("Stage A owns the exact checker role chain without wildcard escalation", () => {
  const chain = source.match(/resource "aws_iam_role_policy" "checker_assume_target" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(source, /checker_assumer_role_name\s*=\s*"mscqr-production-independent-checker"/);
  assert.match(tfvarsExample, /checker_principal_arns\s*=\s*\["arn:aws:iam::368992683803:role\/mscqr-production-independent-checker"\]/);
  assert.match(chain, /name\s*=\s*"mscqr-production-independent-checker-role-chain"/);
  assert.match(chain, /role\s*=\s*local\.checker_assumer_role_name/);
  assert.match(chain, /Action\s*=\s*"sts:AssumeRole"/);
  assert.match(chain, /Resource\s*=\s*aws_iam_role\.checker\.arn/);
  assert.doesNotMatch(chain, /sts:\*|Resource\s*=\s*"\*"|release-deployer|bootstrap|root/i);
  const trust = source.match(/resource "aws_iam_role" "checker" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(trust, /Principal\s*=\s*\{ AWS = var\.checker_principal_arns \}/);
  assert.doesNotMatch(trust, /MultiFactorAuthPresent/);
  assert.equal(checkerContract.checkerAuthentication.sourceTrustRequiresMfa, true);
  assert.equal(checkerContract.checkerAuthentication.targetTrustRequiresFreshMfa, false);
});

test("Stage A owns no blue infrastructure or release activation", () => {
  for (const forbidden of ["aws_ecs_cluster", "aws_ecs_service", "aws_ecs_task_definition", "aws_ecr_repository", "aws_lb", "aws_route53", "mscqr-prod-db", "aws_lambda_function", "traffic-switch", "image ="]) assert.doesNotMatch(source, new RegExp(forbidden));
  assert.match(source, /engine_version\s+=\s+"18\.4"/);
  assert.match(source, /publicly_accessible\s+=\s+false/);
  assert.match(source, /referenced_security_group_id/);
  const databaseIngress = [...source.matchAll(/resource "aws_vpc_security_group_ingress_rule" "(?:executor_database|runtime_database)" \{([\s\S]*?)\n\}/g)].map((match) => match[1]);
  assert.equal(databaseIngress.length, 2);
  for (const rule of databaseIngress) assert.doesNotMatch(rule, /cidr_ipv4|cidr_ipv6/);
});

test("Stage A declares executor egress only through standalone reviewed rules and keeps database ingress SG-to-SG only", () => {
  const executor = source.match(/resource "aws_security_group" "executor" \{([\s\S]*?)\n\}/)?.[1] || "";
  assert.match(executor, /name\s+=\s+"mscqr-production-rls-green-executor"/);
  assert.match(executor, /description\s+=\s+"No-ingress or egress executor security group until reviewed Stage B networking"/);
  assert.match(executor, /vpc_id\s+=\s+var\.vpc_id/);
  assert.doesNotMatch(executor, /name_prefix|lifecycle|ignore_changes|create_before_destroy/);
  assert.doesNotMatch(executor, /egress\s*\{|0\.0\.0\.0\/0|::\/0|cidr_/);
  const ingress = [...source.matchAll(/resource "aws_vpc_security_group_ingress_rule" "(?:executor_database|runtime_database)"[\s\S]*?\n\}/g)].map((match) => match[0]);
  assert.equal(ingress.length, 2);
  for (const rule of ingress) {
    assert.match(rule, /referenced_security_group_id/);
    assert.doesNotMatch(rule, /cidr_ipv4|cidr_ipv6|0\.0\.0\.0\/0|::\/0/);
  }
  assert.doesNotMatch(source, /aws_ecs_task_definition|aws_ecs_service|aws_lambda_function/);
});

test("Stage A preserves the RDS force-SSL parameter's provider-stable apply method", () => {
  const parameterGroup = source.match(/resource "aws_db_parameter_group" "green" \{([\s\S]*?)\n\}/)?.[1] || "";
  const parameter = parameterGroup.match(/parameter \{([\s\S]*?)\n  \}/)?.[1] || "";
  assert.match(parameter, /name\s+=\s+"rds\.force_ssl"/);
  assert.match(parameter, /value\s+=\s+"1"/);
  assert.match(parameter, /apply_method\s+=\s+"pending-reboot"/);
  assert.doesNotMatch(parameterGroup, /lifecycle[\s\S]*ignore_changes/);
});

test("Stage A exposes only the RDS-managed administrator secret ARN", () => {
  assert.match(source, /manage_master_user_password\s+=\s+true/);
  assert.match(outputs, /output "rds_managed_administrator_secret"/);
  assert.match(outputs, /master_user_secret.*secret_arn/);
  assert.doesNotMatch(outputs, /password\s*=/);
  assert.match(readme, /separate\s+from the 15 empty application\/runtime secret handles/);
});

test("Stage A needs no image digest and Stage B keeps canaries mandatory", () => {
  assert.doesNotMatch(`${source}\n${variables}`, /sha256|image/);
  const stageB = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b/release-activation-contract.json", "utf8"));
  assert.equal(stageB.trafficSwitchBeforeCanariesAllowed, false);
  assert.equal(stageB.frontendTaskDefinition, "mscqr-frontend:20");
  assert.equal(stageB.networking.requiredBeforeExecutor, true);
  assert.equal(stageB.networking.stageAExecutorEgress, "none");
});
