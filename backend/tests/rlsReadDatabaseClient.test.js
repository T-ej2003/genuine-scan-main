const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

process.env.NODE_ENV = "test";

const {
  RLS_READ_DATABASE_URL_ENV,
  RlsReadConfigurationError,
  RlsReadInitializationError,
  STAGING_RLS_BATCHES_READ_FLAG,
  STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG,
  STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG,
  disconnectRlsReadPrisma,
  getRlsReadDatabaseHealth,
  getRlsReadPrisma,
  initializeRlsReadPrisma,
  setRlsReadPrismaFactoryForTests,
  validateRlsReadDatabaseConfiguration,
} = require("../dist/config/rlsReadDatabase");

const buildTestDatabaseUrl = ({ username, password, database = "mscqr_test" }) => {
  const protocol = "postgresql:";
  const authority = `//${username}:${password}@127.0.0.1:55432`;
  return `${protocol}${authority}/${database}`;
};

const validDefaultUrl = buildTestDatabaseUrl({
  username: "owner",
  password: "owner-password",
});

const validRlsUrl = buildTestDatabaseUrl({
  username: "runtime",
  password: "runtime-password",
});
const enabledEnv = (overrides = {}) => ({
  DATABASE_URL: validDefaultUrl,
  [RLS_READ_DATABASE_URL_ENV]: validRlsUrl,
  [STAGING_RLS_BATCHES_READ_FLAG]: "true",
  ...overrides,
});

const safePosture = () => ({
  row_security_on: true,
  role_attributes_safe: true,
  no_inherited_roles: true,
  protected_table_count: 6,
  all_tables_protected: true,
  all_tables_selectable: true,
  no_table_write_privileges: true,
  no_sequence_privileges: true,
  no_schema_create_privileges: true,
  no_owned_tables: true,
  candidate_policy_count: 6,
  helper_function_count: 17,
  all_helpers_executable: true,
});

const makeFactory = (options = {}) => {
  const state = { created: 0, connected: 0, disconnected: 0, postureQueries: 0, healthQueries: 0, transactions: 0 };
  const client = {
    async $connect() {
      state.connected += 1;
      if (options.connectError) throw options.connectError;
    },
    async $disconnect() {
      state.disconnected += 1;
    },
    async $queryRaw(strings) {
      const query = Array.isArray(strings) ? strings.join("") : String(strings);
      if (query.trim() === "SELECT 1") {
        state.healthQueries += 1;
        return [{ "?column?": 1 }];
      }
      state.postureQueries += 1;
      return [options.posture || safePosture()];
    },
    async $transaction(callback) {
      state.transactions += 1;
      return callback({});
    },
  };
  return {
    state,
    client,
    factory: () => {
      state.created += 1;
      return client;
    },
  };
};

const expectConfigurationError = (env, code) => {
  assert.throws(
    () => validateRlsReadDatabaseConfiguration(env),
    (error) => error instanceof RlsReadConfigurationError && error.code === code
  );
};

(async () => {
  await setRlsReadPrismaFactoryForTests(null);

  assert.deepEqual(validateRlsReadDatabaseConfiguration({}), { enabled: false });
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: "" }),
    "RLS_READ_DATABASE_URL_MISSING"
  );
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: "not-a-url" }),
    "RLS_READ_DATABASE_URL_INVALID"
  );
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: ["https:", "//runtime:secret@example.test/db"].join("") }),
    "RLS_READ_DATABASE_URL_INVALID_PROTOCOL"
  );
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: ["postgresql:", "//runtime:secret@127.0.0.1:55432"].join("") }),
    "RLS_READ_DATABASE_NAME_MISSING"
  );
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: ["postgresql:", "//runtime:secret@127.0.0.1:55432/%ZZ"].join("") }),
    "RLS_READ_DATABASE_URL_INVALID"
  );
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: "postgresql://127.0.0.1:55432/mscqr_test" }),
    "RLS_READ_DATABASE_URL_CREDENTIAL_INCOMPLETE"
  );
  expectConfigurationError(
    enabledEnv({ [RLS_READ_DATABASE_URL_ENV]: validDefaultUrl }),
    "RLS_READ_DATABASE_URL_REUSES_DEFAULT"
  );
  assert.equal(validateRlsReadDatabaseConfiguration(enabledEnv()).enabled, true);

  const allocationOnlyEnv = enabledEnv({
    [STAGING_RLS_BATCHES_READ_FLAG]: "false",
    [STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG]: "true",
  });
  const manufacturerPrintersOnlyEnv = enabledEnv({
    [STAGING_RLS_BATCHES_READ_FLAG]: "false",
    [STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG]: "true",
  });
  const allRoutesEnv = enabledEnv({
    [STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG]: "true",
    [STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG]: "true",
  });

  const startupFailure = spawnSync(process.execPath, [path.resolve(__dirname, "../dist/index.js")], {
    cwd: path.resolve(__dirname, ".."),
    env: {
      ...process.env,
      NODE_ENV: "test",
      DATABASE_URL: validDefaultUrl,
      JWT_SECRET: "rls-read-startup-test-secret-that-is-long-enough-for-local-validation",
      [STAGING_RLS_BATCHES_READ_FLAG]: "true",
      MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED: "false",
      MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED: "false",
      [RLS_READ_DATABASE_URL_ENV]: "",
    },
    encoding: "utf8",
    timeout: 10_000,
  });
  const startupOutput = `${startupFailure.stdout || ""}${startupFailure.stderr || ""}`;
  assert.equal(startupFailure.status, 1, "enabled startup must fail before listening when the RLS URL is missing");
  assert.match(startupOutput, /RLS_READ_DATABASE_URL is required/);
  assert.doesNotMatch(startupOutput, /owner-password|runtime-password/);

  const disabledFactory = makeFactory();
  await setRlsReadPrismaFactoryForTests(disabledFactory.factory);
  assert.deepEqual(await getRlsReadDatabaseHealth({}), {
    configured: false,
    required: false,
    ready: true,
  });
  assert.equal(disabledFactory.state.created, 0, "disabled flags must not create the RLS client");

  const lifecycle = makeFactory();
  await setRlsReadPrismaFactoryForTests(lifecycle.factory);
  const first = getRlsReadPrisma(enabledEnv());
  const second = getRlsReadPrisma(enabledEnv());
  assert.strictEqual(first, second, "RLS reads must share one process-level client");
  assert.equal(lifecycle.state.created, 1);
  assert.equal(lifecycle.state.connected, 0, "getRlsReadPrisma must remain lazy");

  const [initializedA, initializedB] = await Promise.all([
    initializeRlsReadPrisma(enabledEnv()),
    initializeRlsReadPrisma(enabledEnv()),
  ]);
  assert.equal(initializedA, true);
  assert.equal(initializedB, true);
  assert.equal(lifecycle.state.connected, 1, "concurrent initialization must share one connection attempt");
  assert.equal(lifecycle.state.postureQueries, 1);
  assert.deepEqual(await getRlsReadDatabaseHealth(enabledEnv()), {
    configured: true,
    required: true,
    ready: true,
  });
  assert.equal(lifecycle.state.connected, 1, "readiness must reuse the initialized client");
  assert.equal(lifecycle.state.postureQueries, 1, "readiness must not repeat the posture probe");
  assert.equal(lifecycle.state.healthQueries, 1, "readiness must perform a lightweight liveness query");

  await disconnectRlsReadPrisma();
  assert.equal(lifecycle.state.disconnected, 1, "clean shutdown must disconnect the cached RLS client once");

  const allocationOnly = makeFactory();
  await setRlsReadPrismaFactoryForTests(allocationOnly.factory);
  assert.equal(await initializeRlsReadPrisma(allocationOnlyEnv), true);

  const manufacturerPrintersOnly = makeFactory({
    posture: {
      ...safePosture(),
      protected_table_count: 10,
      candidate_policy_count: 10,
    },
  });
  await setRlsReadPrismaFactoryForTests(manufacturerPrintersOnly.factory);
  assert.equal(await initializeRlsReadPrisma(manufacturerPrintersOnlyEnv), true);

  const allRoutes = makeFactory({
    posture: {
      ...safePosture(),
      protected_table_count: 16,
      candidate_policy_count: 16,
    },
  });
  await setRlsReadPrismaFactoryForTests(allRoutes.factory);
  assert.equal(await initializeRlsReadPrisma(allRoutesEnv), true);

  const wrongPhaseCount = makeFactory({
    posture: {
      ...safePosture(),
      protected_table_count: 16,
      candidate_policy_count: 16,
    },
  });
  await setRlsReadPrismaFactoryForTests(wrongPhaseCount.factory);
  await assert.rejects(
    initializeRlsReadPrisma(enabledEnv()),
    RlsReadInitializationError
  );

  const secret = "do-not-print-this-password";
  const failing = makeFactory({ connectError: new Error(`connection failed for ${["postgresql:", `//runtime:${secret}@host/db`].join("")}`) });
  await setRlsReadPrismaFactoryForTests(failing.factory);
  await assert.rejects(
    initializeRlsReadPrisma(enabledEnv()),
    (error) => error instanceof RlsReadInitializationError && !error.message.includes(secret)
  );
  const failedHealth = await getRlsReadDatabaseHealth(enabledEnv());
  assert.equal(failedHealth.ready, false);
  assert.equal(failedHealth.error, "RLS_READ_DATABASE_UNAVAILABLE");
  assert.equal(JSON.stringify(failedHealth).includes(secret), false);

  const unsafePosture = makeFactory({ posture: { ...safePosture(), no_owned_tables: false } });
  await setRlsReadPrismaFactoryForTests(unsafePosture.factory);
  await assert.rejects(initializeRlsReadPrisma(enabledEnv()), RlsReadInitializationError);

  const writeCapablePosture = makeFactory({ posture: { ...safePosture(), no_table_write_privileges: false } });
  await setRlsReadPrismaFactoryForTests(writeCapablePosture.factory);
  await assert.rejects(initializeRlsReadPrisma(enabledEnv()), RlsReadInitializationError);

  await setRlsReadPrismaFactoryForTests(null);
  console.log("RLS read database configuration and lifecycle tests passed");
})().catch(async (error) => {
  await disconnectRlsReadPrisma().catch(() => undefined);
  console.error(error);
  process.exit(1);
});
