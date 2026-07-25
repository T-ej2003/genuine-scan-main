import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  GREEN_EXECUTOR_MODES,
  PRODUCTION_GREEN,
  validateGreenExecutorMode,
  validateProductionAdministratorUrl,
} from "../../backend/scripts/production-full-rls-green-executor.mjs";
import {
  applyProductionFullRlsRelease,
  buildTaskDefinition,
  validateProductionReleaseEnvironment,
} from "../aws/apply-production-full-rls-release.mjs";

const releaseSha = "a".repeat(40);
const sourceContractSha256 = "b".repeat(64);
const packageChecksumSha256 = "c".repeat(64);
const image = (repository, digest) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@sha256:${digest.repeat(64)}`;
const env = {
  RELEASE_GIT_SHA: releaseSha,
  MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256: sourceContractSha256,
  MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256: packageChecksumSha256,
  PRODUCTION_RLS_EXECUTOR_IMAGE: image("mscqr-backend", "1"),
  PRODUCTION_BACKEND_IMAGE: image("mscqr-backend", "2"),
  PRODUCTION_WORKER_IMAGE: image("mscqr-worker", "3"),
  PRODUCTION_FRONTEND_IMAGE: image("mscqr-web", "4"),
  PRODUCTION_RLS_CLUSTER_ARN: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
  PRODUCTION_RLS_TASK_ROLE_ARN: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
  PRODUCTION_RLS_EXECUTION_ROLE_ARN: "arn:aws:iam::368992683803:role/mscqr-production-ecs-execution-role",
  PRODUCTION_RLS_ADMIN_SECRET_ARN: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/admin-Ab12Cd",
  PRODUCTION_RLS_RECEIPT_BUCKET: "mscqr-production-release-artifacts-368992683803",
  PRODUCTION_RLS_PRIVATE_SUBNETS_JSON: '["subnet-abc123"]',
  PRODUCTION_RLS_SECURITY_GROUPS_JSON: '["sg-abc123"]',
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("production executor accepts only the exact production identity and TLS endpoint", () => {
  assert.equal(validateProductionAdministratorUrl(
    "postgresql://mscqr_prod_admin@mscqr-production-db.internal/mscqr_production?sslmode=require"
  ).username, "mscqr_prod_admin");
  assert.throws(() => validateProductionAdministratorUrl(
    "postgresql://mscqr_prod_admin@mscqr-staging-db.internal/mscqr_production?sslmode=require"
  ), /production administrator/);
  for (const mode of GREEN_EXECUTOR_MODES) {
    const confirmation = PRODUCTION_GREEN.confirmations[mode];
    assert.equal(validateGreenExecutorMode(mode, confirmation || ""), mode);
  }
});

test("production task definition is checksum-bound, fixed, secret-backed, and hardened", () => {
  const config = validateProductionReleaseEnvironment(env);
  const definition = buildTaskDefinition("full-rls-runtime-policy", config);
  assert.equal(definition.family, "mscqr-production-full-rls-green-runtime-policy");
  assert.equal(definition.containerDefinitions[0].image, env.PRODUCTION_RLS_EXECUTOR_IMAGE);
  assert.deepEqual(definition.containerDefinitions[0].command, ["node", "scripts/production-full-rls-green-executor.mjs"]);
  assert.deepEqual(definition.containerDefinitions[0].secrets, [{ name: "DATABASE_URL", valueFrom: env.PRODUCTION_RLS_ADMIN_SECRET_ARN }]);
  assert.equal(definition.containerDefinitions[0].readonlyRootFilesystem, true);
  assert.deepEqual(definition.containerDefinitions[0].linuxParameters.capabilities, { add: [], drop: ["ALL"] });
  assert.equal(definition.containerDefinitions[0].environment.find((item) => item.name === "MSCQR_FULL_RLS_CONFIRMATION")?.value, PRODUCTION_GREEN.confirmations["full-rls-runtime-policy"]);
  assert(!JSON.stringify(definition).includes("postgresql://"));
});

test("production release rejects mutable images, foreign infrastructure, and arbitrary package bindings", () => {
  for (const candidate of [
    { PRODUCTION_RLS_EXECUTOR_IMAGE: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:latest" },
    { PRODUCTION_RLS_CLUSTER_ARN: env.PRODUCTION_RLS_CLUSTER_ARN.replace("prod", "staging") },
    { PRODUCTION_RLS_ADMIN_SECRET_ARN: env.PRODUCTION_RLS_ADMIN_SECRET_ARN.replace("production", "staging") },
    { PRODUCTION_RLS_PRIVATE_SUBNETS_JSON: '["subnet-good","forged"]' },
  ]) assert.throws(() => validateProductionReleaseEnvironment({ ...env, ...candidate }), /production contract|release binding|immutable ECR/);
});

test("production release runs the exact ordered package and writes one bound receipt bundle", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-production-release-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "release-receipt.json");
  const modes = [];
  const modeByTask = new Map();
  const aws = (args) => {
    if (args[0] === "ecs" && args[1] === "register-task-definition") {
      const definition = JSON.parse(fs.readFileSync(args.at(-1).replace("file://", ""), "utf8"));
      const mode = definition.containerDefinitions[0].environment.find((item) => item.name === "MSCQR_FULL_RLS_MODE").value;
      const arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${definition.family}:1`;
      modeByTask.set(arn, mode);
      return { taskDefinition: { taskDefinitionArn: arn } };
    }
    if (args[0] === "ecs" && args[1] === "run-task") {
      assert(!args.includes("--overrides"));
      modes.push(modeByTask.get(args[args.indexOf("--task-definition") + 1]));
      return { tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fixture" }], failures: [] };
    }
    if (args[0] === "ecs" && args[1] === "wait") return {};
    if (args[0] === "ecs" && args[1] === "describe-tasks") return { tasks: [{ containers: [{ exitCode: 0 }] }] };
    if (args[0] === "s3api" && args[1] === "list-objects-v2") {
      const prefix = args[args.indexOf("--prefix") + 1];
      return { Contents: [{ Key: `${prefix}fixture.json`, LastModified: new Date().toISOString() }] };
    }
    if (args[0] === "s3api" && args[1] === "get-object") {
      const key = args[args.indexOf("--key") + 1];
      const mode = key.split("/").at(-2);
      const value = {
        schemaVersion: 1,
        environment: "production",
        database: PRODUCTION_GREEN.database,
        deploymentId: PRODUCTION_GREEN.deploymentId,
        mode,
        status: "passed",
        releaseSha,
        sourceContractSha256,
        packageChecksumSha256,
        catalogueSha256: "d".repeat(64),
        completedAt: new Date().toISOString(),
        nonce: crypto.randomUUID(),
      };
      value.receiptSha256 = sha256(`${JSON.stringify(value)}\n`);
      fs.writeFileSync(args.at(-1), `${JSON.stringify(value)}\n`);
      return {};
    }
    throw new Error(`Unexpected AWS test call: ${args.join(" ")}`);
  };
  const bundle = await applyProductionFullRlsRelease({ env, aws, outputPath });
  assert.deepEqual(modes, [
    "full-rls-capability-preflight",
    "full-rls-admin-bootstrap",
    "full-rls-role-provision",
    "full-rls-role-verify",
    "full-rls-admin-ownership",
    "full-rls-runtime-policy",
    "full-rls-verification",
  ]);
  assert.equal(bundle.receipts.length, 7);
  assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).receiptBundleSha256, bundle.receiptBundleSha256);
});

test("production workflow applies the verified database receipt before application deployment", () => {
  const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  const apply = workflow.indexOf("Apply and verify checksum-bound production RLS package");
  const backend = workflow.indexOf("Deploy backend ECS service");
  assert(apply > 0 && backend > apply);
  assert.match(workflow, /PRODUCTION_RLS_RELEASE_RECEIPT_PATH/);
  assert.match(workflow, /production-rls-release-receipt/);
  assert.doesNotMatch(workflow, /PRODUCTION_DATABASE_URL|RLS_DATABASE_URL/);
});

test("production Terraform grants only exact executor secrets and receipt writes", () => {
  const source = fs.readFileSync("infra/aws/terraform/main.tf", "utf8");
  const variables = fs.readFileSync("infra/aws/terraform/variables.tf", "utf8");
  const policy = source.match(/resource "aws_iam_role_policy" "full_rls_green_executor"[\s\S]*?\n\}/)?.[0] || "";
  const executionPolicy = source.match(/resource "aws_iam_role_policy" "full_rls_green_execution_secret"[\s\S]*?\n\}/)?.[0] || "";
  assert.match(policy, /ReadOnlyProductionGreenAdministratorCredential[\s\S]*full_rls_green_admin_secret_arn/);
  assert.match(policy, /ProvisionOnlyExactProductionGreenRuntimeCredentials[\s\S]*full_rls_green_runtime/);
  assert.match(policy, /AppendOnlyProductionGreenReceipts[\s\S]*rls-receipts\/\*/);
  assert.doesNotMatch(policy, /Resource\s*=\s*"\*"|s3:GetObject|secretsmanager:CreateSecret/);
  assert.match(executionPolicy, /secretsmanager:GetSecretValue[\s\S]*full_rls_green_admin_secret_arn/);
  assert.doesNotMatch(executionPolicy, /Resource\s*=\s*"\*"|PutSecretValue|CreateSecret/);
  assert.match(source, /full_rls_green_execution_role_guard[\s\S]*mscqr-production-ecs-execution-role/);
  assert.match(variables, /database-url\/admin-\[A-Za-z0-9\]\{6\}/);
  assert.match(source, /recovery_window_in_days = 30/);
});
