const assert = require("node:assert/strict");
const fs = require("node:fs");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { PrismaClient } = require("@prisma/client");

const {
  ALLOWED_DB_HOSTS_ENV,
  CONFIRMATION_PHRASE,
  IDS,
  QR_CODES,
  readConfig,
  seedStagingRlsValidationData,
} = require("../scripts/seed-staging-rls-validation-data");
const {
  P2TestDbSkip,
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
} = require("./helpers/p2TestDb");

const backendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(backendRoot, "..");
const scriptPath = path.join(backendRoot, "scripts/seed-staging-rls-validation-data.js");
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const baseEnv = {
  STAGING_RLS_SEED_ENABLED: "true",
  STAGING_RLS_SEED_CONFIRM: CONFIRMATION_PHRASE,
  STAGING_RLS_SEED_ENVIRONMENT: "staging",
  DATABASE_URL: "postgresql://staging_user@localhost:5432/mscqr_staging_seed_test",
};

const assertThrowsMessage = (fn, fragment) => {
  assert.throws(fn, (error) => {
    assert(String(error.message).includes(fragment), `Expected "${error.message}" to include "${fragment}"`);
    return true;
  });
};

const runCli = (env, args = []) =>
  spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: backendRoot,
    env: { PATH: process.env.PATH, ...env },
    encoding: "utf8",
  });

const assertNoSensitiveOutput = (text) => {
  const forbiddenGroups = [
    { label: "database_url", values: [baseEnv.DATABASE_URL, "postgresql://"] },
    { label: "auth_or_secret", values: ["Bearer", "raw-secret-value", "tokenHash"] },
    { label: "qr_code", values: QR_CODES },
    { label: "disallowed_ids", values: [IDS.licensee, IDS.licenseeAdmin, IDS.manufacturer, IDS.org] },
  ];
  for (const group of forbiddenGroups) {
    for (const [index, forbidden] of group.values.entries()) {
      assert(!text.includes(forbidden), `Output leaked forbidden ${group.label} value at index ${index}`);
    }
  }
};

const runSafetyGateTests = () => {
  assertThrowsMessage(() => readConfig({ ...baseEnv, STAGING_RLS_SEED_ENABLED: "" }), "STAGING_RLS_SEED_ENABLED=true");
  assertThrowsMessage(() => readConfig({ ...baseEnv, STAGING_RLS_SEED_CONFIRM: "wrong" }), "STAGING_RLS_SEED_CONFIRM");
  assertThrowsMessage(() => readConfig({ ...baseEnv, DATABASE_URL: "" }), "DATABASE_URL is required");
  assertThrowsMessage(
    () => readConfig({ ...baseEnv, DATABASE_URL: "postgresql://u:p@mscqr-prod-db-proxy.proxy-c3ewey6o6mq5.eu-west-2.rds.amazonaws.com/app" }),
    "production-looking",
  );
  assertThrowsMessage(
    () => readConfig({ ...baseEnv, DATABASE_URL: "postgresql://user@db.internal/mscqr" }),
    "Refusing non-local DATABASE_URL",
  );
  assert.doesNotThrow(() =>
    readConfig({ ...baseEnv, DATABASE_URL: "postgresql://user@staging-db.internal/mscqr_staging" }),
  );
  assertThrowsMessage(
    () => readConfig({ ...baseEnv, DATABASE_URL: "postgresql://user@reviewed-db.internal/mscqr" }),
    "Refusing non-local DATABASE_URL",
  );
  assert.doesNotThrow(() =>
    readConfig({
      ...baseEnv,
      DATABASE_URL: "postgresql://user@reviewed-db.internal/mscqr",
      [ALLOWED_DB_HOSTS_ENV]: "reviewed-db.internal",
    }),
  );
  assertThrowsMessage(
    () =>
      readConfig({
        ...baseEnv,
        DATABASE_URL: "postgresql://user@mscqr-prod-db-proxy.internal/mscqr_staging",
        [ALLOWED_DB_HOSTS_ENV]: "mscqr-prod-db-proxy.internal",
      }),
    "production-looking",
  );
  assertThrowsMessage(
    () => readConfig({ ...baseEnv, NODE_ENV: "production" }),
    "Refusing NODE_ENV=production",
  );
  assert.doesNotThrow(() =>
    readConfig({
      ...baseEnv,
      NODE_ENV: "production",
      STAGING_RLS_SEED_ALLOW_PRODUCTION_NODE_ENV_FOR_STAGING: "true",
      DATABASE_URL: "postgresql://staging_user@mscqr-staging-db.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com/mscqr_staging",
    }),
  );
};

const runCliTests = () => {
  const help = runCli({}, ["--help"]);
  assert.equal(help.status, 0, help.stderr);
  assert(help.stdout.includes("Safety contract"));

  const missingGates = runCli({ DATABASE_URL: baseEnv.DATABASE_URL });
  assert.notEqual(missingGates.status, 0);
  assertNoSensitiveOutput(missingGates.stdout);
  const payload = JSON.parse(missingGates.stdout);
  assert.equal(payload.ok, false);
  assert.equal(payload.databaseUrlPrinted, false);
  assert.equal(payload.authTokenPrinted, false);

  const runtimeFailureUrl = "postgresql://staging_user@staging-db.internal:5432/mscqr_staging";
  const runtimeFailure = runCli({
    ...baseEnv,
    DATABASE_URL: runtimeFailureUrl,
  });
  assert.notEqual(runtimeFailure.status, 0);
  const runtimePayload = JSON.parse(runtimeFailure.stdout);
  assert.equal(runtimePayload.errorCode, "STAGING_RLS_VALIDATION_SEED_RUNTIME_ERROR");
  assert.equal(runtimePayload.databaseUrlPrinted, false);
  assert(!runtimeFailure.stdout.includes(runtimeFailureUrl), "Runtime failure output leaked database URL");
  assert(!runtimeFailure.stdout.includes("staging-db.internal"), "Runtime failure output leaked database host");
  assertNoSensitiveOutput(runtimeFailure.stdout);
};

const runTerraformSafetyTextTests = () => {
  const main = fs.readFileSync(path.join(repoRoot, "infra/terraform/staging-api/main.tf"), "utf8");
  const providers = fs.readFileSync(path.join(repoRoot, "infra/terraform/staging-api/providers.tf"), "utf8");
  const variables = fs.readFileSync(path.join(repoRoot, "infra/terraform/staging-api/variables.tf"), "utf8");
  const readme = fs.readFileSync(path.join(repoRoot, "infra/terraform/staging-api/README.md"), "utf8");

  assert(main.includes("enable_execute_command = true"), "Terraform ECS service must enable ECS Exec.");
  assert(main.includes('"ssmmessages:CreateControlChannel"'), "Terraform task role must allow ECS Exec control channels.");
  assert(main.includes('"ssmmessages:CreateDataChannel"'), "Terraform task role must allow ECS Exec data channels.");
  assert(main.includes('"ssmmessages:OpenControlChannel"'), "Terraform task role must open ECS Exec control channels.");
  assert(main.includes('"ssmmessages:OpenDataChannel"'), "Terraform task role must open ECS Exec data channels.");
  assert(main.includes('"aws:RequestedRegion" = var.aws_region'), "Terraform ECS Exec channel permissions must be region-scoped.");
  assert(providers.includes("allowed_account_ids = [var.account_id]"), "Terraform provider must pin allowed_account_ids.");
  assert(variables.includes('cidr != "0.0.0.0/0"'), "Terraform CIDR validation must reject IPv4 world-open ingress.");
  assert(variables.includes('cidr != "::/0"'), "Terraform CIDR validation must reject IPv6 world-open ingress.");
  assert(variables.includes(">= 24") && variables.includes("<= 32"), "Terraform CIDR validation must constrain IPv4 masks to /24 through /32.");
  assert(variables.includes(">= 120") && variables.includes("<= 128"), "Terraform CIDR validation must constrain IPv6 masks to /120 through /128.");
  assert(readme.includes("Root credentials must not be used for apply."), "Terraform README must document root credential prohibition.");
  assert(readme.includes("Operators still need explicit IAM permission for `ecs:ExecuteCommand`"), "Terraform README must document operator ECS Exec authorization.");
  assert(readme.includes("CloudTrail plus the backend CloudWatch log group"), "Terraform README must document ECS Exec audit surfaces.");
  assert(readme.includes('Resource = "*"'), "Terraform README must document why ECS Exec channel permissions require wildcard resources.");
};

const runP2IdempotencyTest = async () => {
  if (!isTruthy(process.env.STAGING_RLS_SEED_P2_IDEMPOTENCY_TEST)) {
    console.log("staging RLS validation seed P2 idempotency test skipped. Set STAGING_RLS_SEED_P2_IDEMPOTENCY_TEST=true to run.");
    return;
  }

  let databaseInfo;
  let prisma;
  try {
    databaseInfo = resolveP2TestDatabase();
    runPrismaSchemaSetup(databaseInfo.databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseInfo.databaseUrl } } });

    const config = readConfig({ ...baseEnv, DATABASE_URL: databaseInfo.databaseUrl, STAGING_RLS_SEED_ENVIRONMENT: "p2" });
    const first = await seedStagingRlsValidationData(config, prisma);
    const second = await seedStagingRlsValidationData(config, prisma);

    assert.equal(first.stagingBatchId, IDS.batch);
    assert.equal(second.stagingBatchId, IDS.batch);
    assert.equal(first.created.qrCodes, QR_CODES.length);
    assert.equal(second.created.qrCodes, 0);
    assert.equal(second.reused.qrCodes, QR_CODES.length);
    assert.equal(await prisma.batch.count({ where: { id: IDS.batch } }), 1);
    assert.equal(await prisma.qRCode.count({ where: { batchId: IDS.batch } }), QR_CODES.length);

    const output = JSON.stringify(second);
    assertNoSensitiveOutput(output);
    assert(output.includes(IDS.batch), "Allowed stagingBatchId must be present for collector use.");
  } catch (error) {
    if (error instanceof P2TestDbSkip) {
      console.log(`staging RLS validation seed P2 idempotency test skipped: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    await prisma?.$disconnect?.().catch(() => undefined);
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
};

(async () => {
  runSafetyGateTests();
  runCliTests();
  runTerraformSafetyTextTests();
  await runP2IdempotencyTest();
  console.log("staging RLS validation seed script tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
