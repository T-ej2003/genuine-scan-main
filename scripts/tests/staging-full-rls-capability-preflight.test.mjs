import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  GREEN_EXECUTOR_MODES,
  GREEN_MUTATING_MODE_CONFIRMATIONS,
  fixedRunTaskRequest,
  validateBrokerEvent,
} from "../../infra/terraform/staging-api/lambda/database-role-executor-broker/index.mjs";
import {
  GREEN_EXECUTOR_MODES as EXECUTOR_MODES,
  GREEN_MUTATION_CONFIRMATIONS,
  STAGING_GREEN,
  validateGreenExecutorMode,
  validateStagingAdministratorUrl,
  verifyBoundPackage,
} from "../../backend/scripts/staging-full-rls-green-executor.mjs";

const contract = JSON.parse(fs.readFileSync("documents/security/rls-program/staging-full-rls-executor-contract.json", "utf8"));
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

test("green executor contract is exact, isolated, TLS-only, and mutation-enabled", () => {
  assert.equal(contract.schemaVersion, 3);
  assert.equal(contract.environment, "staging");
  assert.equal(contract.status, "green-executor-implemented-ready-for-reviewed-activation");
  assert.equal(contract.blueExecutor.fullRlsMutationAllowed, false);
  assert.equal(contract.greenExecutor.implemented, true);
  assert.equal(contract.greenExecutor.mutationAllowed, true);
  assert.equal(contract.greenExecutor.database, STAGING_GREEN.database);
  assert.equal(contract.greenExecutor.databaseAdministrator, STAGING_GREEN.administrator);
  assert.equal(contract.greenExecutor.targetMustBeFresh, true);
  assert.equal(contract.greenExecutor.managedRolesMustBeNew, true);
  assert.equal(contract.greenExecutor.tlsRequired, true);
  assert.deepEqual(Object.keys(contract.greenExecutor.modes), GREEN_EXECUTOR_MODES);
  assert.deepEqual(GREEN_EXECUTOR_MODES, EXECUTOR_MODES);
  assert.deepEqual(GREEN_MUTATING_MODE_CONFIRMATIONS, GREEN_MUTATION_CONFIRMATIONS);
  assert.equal(contract.greenExecutor.modes["full-rls-admin-ownership"].schemaMigration, "prisma migrate deploy");
});

test("green modes require distinct confirmations and reject caller overrides", () => {
  for (const mode of GREEN_EXECUTOR_MODES) {
    const confirmation = GREEN_MUTATING_MODE_CONFIRMATIONS[mode];
    assert.equal(validateBrokerEvent({ mode, ...(confirmation ? { confirmation } : {}) }), mode);
    assert.equal(validateGreenExecutorMode(mode, confirmation || ""), mode);
    if (confirmation) {
      assert.throws(() => validateBrokerEvent({ mode }), /unreviewed fields/);
      assert.throws(() => validateGreenExecutorMode(mode, "YES"), /fixed mode contract/);
    }
    for (const key of ["command", "environment", "network", "secret", "package", "role", "taskDefinition"]) {
      assert.throws(() => validateBrokerEvent({ mode, ...(confirmation ? { confirmation } : {}), [key]: "forged" }), /unreviewed fields/);
    }
  }
  assert.equal(new Set(Object.values(GREEN_MUTATING_MODE_CONFIRMATIONS)).size, Object.keys(GREEN_MUTATING_MODE_CONFIRMATIONS).length);
});

test("green broker launches only its fixed task definition with no overrides", () => {
  const greenTaskDefinitionArns = Object.fromEntries(GREEN_EXECUTOR_MODES.map((mode, index) => [
    mode,
    `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-full-rls-green-${mode.replace("full-rls-", "")}:${index + 1}`,
  ]));
  const config = {
    clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-staging-euw2-main",
    taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-database-role-admin:1",
    greenTaskDefinitionArns,
    subnets: ["subnet-abc123"],
    securityGroups: ["sg-abc123"],
  };
  const mode = "full-rls-runtime-policy";
  const request = fixedRunTaskRequest(mode, config, GREEN_MUTATING_MODE_CONFIRMATIONS[mode]);
  assert.equal(request.taskDefinition, greenTaskDefinitionArns[mode]);
  assert(!Object.hasOwn(request, "overrides"));
});

test("administrator URL is staging-only, exact-user, exact-database, and TLS required", () => {
  const valid = `postgresql://${STAGING_GREEN.administrator}@mscqr-staging-db.internal/${STAGING_GREEN.maintenanceDatabase}?sslmode=require`;
  assert.equal(validateStagingAdministratorUrl(valid).hostname, "mscqr-staging-db.internal");
  for (const invalid of [
    valid.replace("staging", "production"),
    valid.replace(STAGING_GREEN.administrator, "postgres"),
    valid.replace(STAGING_GREEN.maintenanceDatabase, "other"),
    valid.replace("sslmode=require", "sslmode=disable"),
  ]) assert.throws(() => validateStagingAdministratorUrl(invalid), /unreviewed staging administrator/);
});

test("package validation binds source, manifest roles, and every generated file checksum", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-staging-green-package-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sqlRoot = path.join(root, "sql");
  const evidenceRoot = path.join(root, "evidence");
  fs.mkdirSync(sqlRoot);
  fs.mkdirSync(evidenceRoot);
  const sourceContract = "a".repeat(64);
  const sql = Buffer.from("SELECT 1;\n");
  fs.writeFileSync(path.join(sqlRoot, "runtime-policy.sql"), sql);
  const roles = {
    owner: `${STAGING_GREEN.rolePrefix}owner`,
    authOwner: `${STAGING_GREEN.rolePrefix}auth_owner`,
    app: `${STAGING_GREEN.rolePrefix}app`,
    read: `${STAGING_GREEN.rolePrefix}read`,
    preauth: `${STAGING_GREEN.rolePrefix}preauth`,
    worker: `${STAGING_GREEN.rolePrefix}worker`,
    scheduled: `${STAGING_GREEN.rolePrefix}scheduled`,
    operator: `${STAGING_GREEN.rolePrefix}operator`,
    migration: `${STAGING_GREEN.rolePrefix}migration`,
  };
  const manifest = Buffer.from(`${JSON.stringify({
    environment: "staging",
    deploymentId: STAGING_GREEN.deploymentId,
    sourceContractSha256: sourceContract,
    roles,
  })}\n`);
  fs.writeFileSync(path.join(evidenceRoot, "full-rls-implementation-manifest.json"), manifest);
  const checksums = Buffer.from(`${JSON.stringify({
    schemaVersion: 3,
    deploymentModel: "clean-room-blue-green",
    sourceContractSha256: sourceContract,
    files: {
      "runtime-policy.sql": sha256(sql),
      "full-rls-implementation-manifest.json": sha256(manifest),
    },
  })}\n`);
  fs.writeFileSync(path.join(evidenceRoot, "checksums.json"), checksums);
  const input = {
    expectedSourceContract: sourceContract,
    expectedPackageChecksum: sha256(checksums),
    expectedReleaseSha: "b".repeat(40),
    sqlRoot,
    evidenceRoot,
  };
  assert.equal(verifyBoundPackage(input).packageChecksum, input.expectedPackageChecksum);
  fs.writeFileSync(path.join(sqlRoot, "runtime-policy.sql"), "SELECT 2;\n");
  assert.throws(() => verifyBoundPackage(input), /package file mismatch/);
});

test("Terraform gives the green executor only exact secrets, receipts, and fixed tasks", () => {
  const source = fs.readFileSync("infra/terraform/staging-api/main.tf", "utf8");
  const variables = fs.readFileSync("infra/terraform/staging-api/variables.tf", "utf8");
  assert.match(source, /resource "aws_iam_role" "full_rls_green_executor_task"/);
  assert.match(source, /ReadOnlyGreenAdministratorCredential[\s\S]*rls_green_admin_database_url/);
  assert.match(source, /ecs_execution_staging_secrets[\s\S]*rls_green_admin_database_url/);
  assert.match(source, /ProvisionOnlyExactGreenRuntimeCredentials[\s\S]*full_rls_green_runtime/);
  assert.match(source, /AppendOnlyGreenReceipts[\s\S]*rls-receipts\/\*/);
  assert.match(source, /for_each\s+= local\.full_rls_green_modes/);
  assert.match(source, /readonlyRootFilesystem = true/);
  assert.match(source, /capabilities\s+= \{ add = \[\], drop = \["ALL"\] \}/);
  assert.match(variables, /full_rls_green_executor_image_uri[\s\S]*@sha256:/);
  assert.doesNotMatch(source.match(/resource "aws_iam_role_policy" "full_rls_green_executor"[\s\S]*?\n\}/)?.[0] || "", /Resource\s*=\s*"\*"/);
});
