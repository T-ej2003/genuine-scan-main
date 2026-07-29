import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  GREEN_EXECUTOR_MODES,
  PRODUCTION_GREEN,
  productionAdministratorUrlFromEnvironment,
  validateGreenExecutorMode,
  validateProductionAdministratorUrl,
} from "../../backend/scripts/production-full-rls-green-executor.mjs";
import {
  applyProductionFullRlsRelease,
  validateProductionReleaseEnvironment,
} from "../aws/apply-production-full-rls-release.mjs";
import {
  provisionProductionGreenCanaries,
  validateCanaryEnvironment,
} from "../../backend/scripts/production-green-canary-provision.mjs";

const releaseSha = "a".repeat(40);
const sourceContractSha256 = "b".repeat(64);
const migrationSetDigest = "c".repeat(64);
const packageChecksumSha256 = "d".repeat(64);
const approvalContractSha256 = "e".repeat(64);
const approvalId = "APR-130-RLS-ACTIVATION";
const image = (repository, digest) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@sha256:${digest.repeat(64)}`;
const env = {
  RELEASE_GIT_SHA: releaseSha,
  MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256: sourceContractSha256,
  MSCQR_FULL_RLS_MIGRATION_SET_DIGEST: migrationSetDigest,
  MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256: packageChecksumSha256,
  PRODUCTION_RLS_APPROVAL_ID: approvalId,
  PRODUCTION_RLS_BROKER_ARN: "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed",
  PRODUCTION_RLS_EXECUTOR_IMAGE: image("mscqr-backend", "1"),
  PRODUCTION_BACKEND_IMAGE: image("mscqr-backend", "2"),
  PRODUCTION_WORKER_IMAGE: image("mscqr-worker", "3"),
  PRODUCTION_RLS_CANARY_IMAGE: image("mscqr-backend", "4"),
  PRODUCTION_FRONTEND_TASK_DEFINITION: "mscqr-frontend:20",
  PRODUCTION_RLS_CLUSTER_ARN: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
  PRODUCTION_RLS_RECEIPT_BUCKET: "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const randomMfaSecret = () =>
  [...crypto.randomBytes(32)].map((value) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[value & 31]).join("");

test("production executor accepts only the exact production identity and TLS endpoint", () => {
  assert.equal(validateProductionAdministratorUrl(
    "postgresql://mscqr_prod_admin@mscqr-production-db.internal/mscqr_production?sslmode=require"
  ).username, "mscqr_prod_admin");
  assert.throws(() => validateProductionAdministratorUrl(
    "postgresql://mscqr_prod_admin@mscqr-staging-db.internal/mscqr_production?sslmode=require"
  ), /production administrator/);
  assert.equal(new URL(productionAdministratorUrlFromEnvironment({
    MSCQR_RLS_ADMIN_USERNAME: "mscqr_prod_admin",
    MSCQR_RLS_ADMIN_PASSWORD: crypto.randomBytes(24).toString("base64url"),
    MSCQR_RLS_GREEN_ENDPOINT: "mscqr-production-green.internal",
  })).username, "mscqr_prod_admin");
  for (const mode of GREEN_EXECUTOR_MODES) {
    const confirmation = PRODUCTION_GREEN.confirmations[mode];
    assert.equal(validateGreenExecutorMode(mode, confirmation || ""), mode);
  }
});

test("production green canary provisioning is approval-bound, secret-safe and idempotent", async () => {
  const smokeSource = fs.readFileSync(path.resolve("scripts/smoke-release.mjs"), "utf8");
  assert.match(smokeSource, /\/auth\/logout/);
  assert.match(smokeSource, /logout\/session revocation/);

  const fixture = (suffix) => `${suffix.padEnd(20, "A")}234567`;
  const config = validateCanaryEnvironment({
    MSCQR_CANARY_ORDINARY_EMAIL: "ordinary@green-canary.invalid",
    MSCQR_CANARY_ORDINARY_PASSWORD: fixture("ordinary-password-"),
    MSCQR_CANARY_ORDINARY_MFA_SECRET: randomMfaSecret(),
    MSCQR_CANARY_ADMIN_EMAIL: "admin@green-canary.invalid",
    MSCQR_CANARY_ADMIN_PASSWORD: fixture("admin-password-"),
    MSCQR_CANARY_ADMIN_MFA_SECRET: randomMfaSecret(),
    AUTH_MFA_ENCRYPTION_KEY: crypto.randomBytes(32).toString("base64url"),
    MSCQR_PRODUCTION_RLS_APPROVAL_ARTIFACT: JSON.stringify({
      approvalId,
      ticketId: "CHG-PRODUCTION-RLS-2026-07",
      independentCheckerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/reviewer",
    }),
  });
  assert.throws(() => validateCanaryEnvironment({}), /missing or invalid/);

  const created = { users: [], mfa: [], audit: [] };
  const tx = {
    $executeRaw: () => 1,
    user: {
      findMany: async () => created.users.map(({ id, email, role, metadata }) => ({ id, email, role, metadata })),
      upsert: async ({ create, update }) => {
        const existing = created.users.find((item) => item.email === create.email);
        if (existing) Object.assign(existing, update);
        else created.users.push(create);
      },
    },
    organization: { upsert: async () => undefined },
    licensee: { upsert: async () => undefined },
    adminMfaCredential: { upsert: async ({ create }) => { created.mfa.push(create); } },
    auditLog: { upsert: async ({ create }) => { created.audit.push(create); } },
  };
  const prisma = { $transaction: (operation) => operation(tx) };
  assert.deepEqual(await provisionProductionGreenCanaries(prisma, config), { status: "created", userCount: 2 });
  assert.deepEqual(await provisionProductionGreenCanaries(prisma, config), { status: "reconciled", userCount: 2 });
  assert.equal(created.users.length, 2);
  assert.equal(created.mfa.length, 4);
  assert.equal(created.audit[0].details.independentCheckerIdentity, config.checker);
  const stored = JSON.stringify(created);
  for (const secret of [
    config.ordinaryPassword,
    config.adminPassword,
    config.ordinaryMfaSecret,
    config.adminMfaSecret,
    config.encryptionKey,
  ]) assert.doesNotMatch(stored, new RegExp(secret));
});

test("production release rejects mutable images and incomplete broker bindings", () => {
  for (const candidate of [
    { PRODUCTION_RLS_EXECUTOR_IMAGE: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:latest" },
    { PRODUCTION_FRONTEND_TASK_DEFINITION: "mscqr-frontend:21" },
    { PRODUCTION_RLS_CLUSTER_ARN: env.PRODUCTION_RLS_CLUSTER_ARN.replace("prod", "staging") },
    { PRODUCTION_RLS_BROKER_ARN: env.PRODUCTION_RLS_BROKER_ARN.replace("production", "staging") },
    { MSCQR_FULL_RLS_MIGRATION_SET_DIGEST: "" },
  ]) assert.throws(() => validateProductionReleaseEnvironment({ ...env, ...candidate }), /release binding|immutable ECR/);
});

test("production release uses only the approval broker, runs canaries, and writes one receipt bundle", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-production-release-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const outputPath = path.join(directory, "release-receipt.json");
  const modes = [];
  const aws = (args) => {
    if (args[0] === "lambda" && args[1] === "invoke") {
      const request = JSON.parse(fs.readFileSync(args.find((item) => item.startsWith("fileb://")).slice(8), "utf8"));
      modes.push(request.mode);
      fs.writeFileSync(args.at(-1), JSON.stringify({
        status: "started",
        mode: request.mode,
        approvalId,
        taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/fixture",
      }));
      return { StatusCode: 200 };
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
        migrationSetDigest,
        packageChecksumSha256,
        approvalContractSha256,
        approvalId,
        ticketId: "CHG-PRODUCTION-RLS-2026-07",
        administratorIdentity: "mscqr_prod_admin",
        independentCheckerIdentity: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
        approvalExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        catalogueSha256: "f".repeat(64),
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
    "full-rls-application-canary",
  ]);
  assert.equal(bundle.applicationCanary, "passed");
  assert.equal(bundle.receipts.length, 7);
  assert.equal(JSON.parse(fs.readFileSync(outputPath, "utf8")).approvalId, approvalId);
});

test("production workflow applies verified green and canaries before backend traffic switch", () => {
  const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  const apply = workflow.indexOf("Apply and verify checksum-bound production RLS package");
  const backend = workflow.indexOf("Deploy backend ECS service");
  assert(apply > 0 && backend > apply);
  assert.match(workflow, /PRODUCTION_RLS_APPROVAL_SECRET_ARN/);
  assert.match(workflow, /MSCQR_FULL_RLS_MIGRATION_SET_DIGEST/);
  assert.match(workflow, /SECRET_UPDATES_JSON/);
  assert.match(workflow, /Require complete production worker deployment configuration/);
  assert.match(workflow, /mscqr-frontend:20/);
  assert.doesNotMatch(workflow, /PRODUCTION_RLS_ADMIN_SECRET_ARN|PRODUCTION_RLS_PRIVATE_SUBNETS_JSON/);
});

test("production Terraform Stage A provisions isolated PG18 while Stage B remains approval-bound", () => {
  const source = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  const variables = fs.readFileSync("infra/aws/terraform/production-green-stage-a/variables.tf", "utf8");
  const provider = fs.readFileSync("infra/aws/terraform/production-green-stage-a/providers.tf", "utf8");
  const stageB = fs.readFileSync("infra/aws/terraform/production-green-stage-b/release-activation-contract.json", "utf8");
  assert.match(source, /resource "aws_db_instance" "green"[\s\S]*engine_version\s*=\s*"18\.4"/);
  assert.match(source, /publicly_accessible\s*=\s*false[\s\S]*deletion_protection\s*=\s*true/);
  assert.match(source, /customer_master_key_spec\s*=\s*"RSA_3072"/);
  assert.match(source, /mscqr-production-rls-independent-checker/);
  assert.match(source, /aws_secretsmanager_secret" "canary/);
  assert.match(variables, /checker_is_independent_of_release_deployer/);
  assert.match(stageB, /immutable-backend-worker-executor-images/);
  assert.match(fs.readFileSync("backend/Dockerfile", "utf8"), /scripts\/release-smoke/);
  assert.doesNotMatch(source, /aws_ecs_task_definition|aws_ecs_service|aws_lambda_function/);
  assert.match(provider, /allowed_account_ids\s*=\s*\["368992683803"\]/);
  assert.doesNotMatch(source, /BYPASSRLS|SUPERUSER/);
  assert.doesNotMatch(source, /cidr_ipv4\s*=\s*"(?:0\.0\.0\.0\/0|::\/0)"/);
  assert.match(source, /cidr_ipv4\s*=\s*var\.vpc_dns_resolver_cidr/);
});

test("production operator, scoped executor egress, and RDS-managed-secret contracts remain fail-closed", () => {
  const contract = JSON.parse(fs.readFileSync("documents/security/rls-program/production-full-rls-executor-contract.json", "utf8"));
  const stageA = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  assert.equal(contract.stageAOperatorPath.bootstrapOperator, "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator");
  assert.equal(contract.stageAOperatorPath.releaseRole, "arn:aws:iam::368992683803:role/mscqr-production-release-deployer");
  assert.equal(contract.stageANetworking.executorEgress, "green database plus reviewed AWS endpoints, regional S3 and exact VPC resolver only");
  assert.equal(contract.stageANetworking.stageBRequiredBeforeExecutorRuns, true);
  assert.equal(contract.rdsManagedAdministratorSecret.manageMasterUserPassword, true);
  assert.equal(contract.rdsManagedAdministratorSecret.terraformStoresPassword, false);
  assert.equal(contract.rdsManagedAdministratorSecret.applicationRuntimeMayRead, false);
  assert.match(stageA, /executor_database[\s\S]*referenced_security_group_id\s*=\s*aws_security_group\.database\.id/);
  assert.match(stageA, /executor_interface_endpoints/);
  assert.match(stageA, /executor_s3/);
  assert.match(stageA, /executor_dns_(?:udp|tcp)/);
  assert.doesNotMatch(stageA, /0\.0\.0\.0\/0|::\/0/);
});
