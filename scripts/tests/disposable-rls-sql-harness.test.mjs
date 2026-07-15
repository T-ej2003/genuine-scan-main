import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CONFIRM_ENV,
  CONFIRM_VALUE,
  HarnessSafetyError,
  assertHarnessConfirmation,
  assertNoUnsafeAmbientDatabaseUrls,
  assertSafeAppRole,
  assertSafeDisposableDatabaseUrl,
  assertSqlFileSafe,
  assertRuntimeRoleDiagnostics,
  parseArgs,
  runHarness,
  sanitizeConnectionMetadata,
} from "../run-disposable-rls-sql-harness.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const candidateSqlPath = path.join(repoRoot, "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql");
const rollbackSqlPath = path.join(repoRoot, "documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql");
const pgScheme = ["post", "gres", "ql"].join("");
const localHarnessHost = "127.0.0.1";
const harnessPort = "55432";

const assertRefused = (fn, pattern) => {
  assert.throws(fn, (error) => error instanceof HarnessSafetyError && pattern.test(error.message));
};

const dbUrl = ({
  database,
  host = localHarnessHost,
  user = "fixture_user",
  password = "fixture_password",
  port = harnessPort,
}) => {
  const parsed = new URL(`${pgScheme}:${"/".repeat(2)}${host}`);
  parsed.username = user;
  if (password) parsed.password = password;
  parsed.port = port;
  parsed.pathname = `/${database}`;
  return parsed.toString();
};

test("refuses missing confirmation env", () => {
  assertRefused(() => assertHarnessConfirmation({}), /MSCQR_DISPOSABLE_RLS_HARNESS_CONFIRM/);
});

test("accepts exact confirmation env", () => {
  assert.doesNotThrow(() => assertHarnessConfirmation({ [CONFIRM_ENV]: CONFIRM_VALUE }));
});

test("refuses PUBLIC as app role", () => {
  assertRefused(() => assertSafeAppRole("public"), /public must not be used/);
});

test("refuses reserved and quoted role identifiers", () => {
  for (const role of ["postgres", "current_user", "RoleName", 'role"injected', "role-name"]) {
    assertRefused(() => assertSafeAppRole(role), /must not be used|unsafe characters/);
  }
});

test("refuses unsafe app role characters", () => {
  assertRefused(() => assertSafeAppRole("role;drop"), /unsafe characters/);
});

test("accepts safe app role placeholder values", () => {
  assert.equal(assertSafeAppRole("mscqr_rls_harness_app"), "mscqr_rls_harness_app");
});

test("refuses production-looking URL", () => {
  assertRefused(
    () => assertSafeDisposableDatabaseUrl(dbUrl({ database: "mscqr_production_rls_harness" })),
    /staging, production, cloud, or shared/,
  );
});

test("refuses staging-looking URL", () => {
  assertRefused(
    () => assertSafeDisposableDatabaseUrl(dbUrl({ database: "staging_rls_harness_test" })),
    /staging, production, cloud, or shared/,
  );
});

test("refuses AWS RDS hostname", () => {
  assertRefused(
    () => assertSafeDisposableDatabaseUrl(dbUrl({ host: ["example", "rds", "amazonaws", "com"].join("."), port: "5432", database: "rls_harness_test" })),
    /staging, production, cloud, or shared/,
  );
});

test("refuses public hostname", () => {
  assertRefused(
    () => assertSafeDisposableDatabaseUrl(dbUrl({ host: ["db", "example", "internal"].join("."), port: "5432", database: "rls_harness_test" })),
    /host must be local disposable Postgres/,
  );
});

test("refuses DB name without disposable marker", () => {
  assertRefused(
    () => assertSafeDisposableDatabaseUrl(dbUrl({ database: "customerdb" })),
    /database name must include/,
  );
});

test("accepts local disposable DB URL", () => {
  const metadata = assertSafeDisposableDatabaseUrl(dbUrl({ database: "mscqr_rls_harness_test" }));

  assert.equal(metadata.hostCategory, "local");
  assert.equal(metadata.databaseName, "mscqr_rls_harness_test");
});

test("ambient unsafe DATABASE_URL is refused even when supplied URL is safe", () => {
  assertRefused(
    () =>
      assertNoUnsafeAmbientDatabaseUrls(
        {
          DATABASE_URL: dbUrl({ database: "staging_rls_harness_test" }),
        },
        dbUrl({ database: "mscqr_rls_harness_test" }),
      ),
    /DATABASE_URL looks like/,
  );
});

test("sanitized metadata does not print raw password or full URL", () => {
  const fixturePassword = ["super", "secret", "password"].join("-");
  const rawUrl = dbUrl({ user: "harness_user", password: fixturePassword, database: "mscqr_rls_harness_test" });
  const serialized = JSON.stringify(sanitizeConnectionMetadata(rawUrl));

  assert.equal(serialized.includes(fixturePassword), false);
  assert.equal(serialized.includes(rawUrl), false);
  assert.equal(serialized.includes("passwordPresent"), true);
});

test("missing SQL files fail cleanly", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rls-harness-missing-sql-"));
  try {
    assertRefused(
      () => assertSqlFileSafe("documents/security/missing-template.sql", tempRoot, "Candidate SQL file"),
      /Candidate SQL file not found/,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("SQL files under Prisma migrations are refused", () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rls-harness-migration-sql-"));
  try {
    const migrationDir = path.join(tempRoot, "backend/prisma/migrations/20260709000000_rls");
    fs.mkdirSync(migrationDir, { recursive: true });
    fs.writeFileSync(path.join(migrationDir, "migration.sql"), "-- no-op\n", "utf8");

    assertRefused(
      () => assertSqlFileSafe("backend/prisma/migrations/20260709000000_rls/migration.sql", tempRoot, "Candidate SQL file"),
      /must not live under backend\/prisma\/migrations/,
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});

test("default PR #110 SQL files are present and outside migrations", () => {
  assert.equal(
    assertSqlFileSafe("documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql", repoRoot, "Candidate SQL file").relative,
    "documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql",
  );
  assert.equal(
    assertSqlFileSafe("documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql", repoRoot, "Rollback SQL file").relative,
    "documents/security/mscqr_staging_rls_candidate_rollback_2026-07-09.sql",
  );
});

test("argument parser keeps route tests opt-in", () => {
  const args = parseArgs(["--database-url", dbUrl({ database: "mscqr_rls_harness_test", password: "" })]);

  assert.equal(args.runRouteTests, false);
  assert.equal(args.prepareSchema, false);
});

test("argument parser accepts explicit route-test and schema-prep switches", () => {
  const args = parseArgs(["--prepare-schema", "--run-route-tests", "--no-evidence-file", "--json", "--runtime-role", "mscqr_rls_harness_app"]);

  assert.equal(args.runRouteTests, true);
  assert.equal(args.prepareSchema, true);
  assert.equal(args.evidenceFile, false);
  assert.equal(args.json, true);
  assert.equal(args.runtimeRole, "mscqr_rls_harness_app");
});

test("command refuses a missing explicit runtime role without connecting", async () => {
  const url = dbUrl({ database: "mscqr_rls_harness_test", password: "" });
  await assert.rejects(
    runHarness(parseArgs(["--database-url", url, "--no-evidence-file"]), {
      [CONFIRM_ENV]: CONFIRM_VALUE,
    }),
    (error) => error instanceof HarnessSafetyError && /Missing explicit non-owner runtime/.test(error.message),
  );
});

test("command refuses using the database owner username as runtime role", async () => {
  const url = dbUrl({ database: "mscqr_rls_harness_test", user: "same_role", password: "" });
  await assert.rejects(
    runHarness(parseArgs(["--database-url", url, "--runtime-role", "same_role", "--no-evidence-file"]), {
      [CONFIRM_ENV]: CONFIRM_VALUE,
    }),
    (error) => error instanceof HarnessSafetyError && /must differ/.test(error.message),
  );
});

test("legacy --app-role argument is rejected instead of silently reused", () => {
  assertRefused(() => parseArgs(["--app-role", "legacy_role"]), /Unknown argument/);
});

test("candidate and rollback SQL use exact function grants and never grant to PUBLIC", () => {
  const combined = `${fs.readFileSync(candidateSqlPath, "utf8")}\n${fs.readFileSync(rollbackSqlPath, "utf8")}`;

  assert.equal(/\bGRANT\s+EXECUTE\s+ON\s+ALL\s+FUNCTIONS\b/i.test(combined), false);
  assert.equal(/\bREVOKE\s+EXECUTE\s+ON\s+ALL\s+FUNCTIONS\b/i.test(combined), false);
  assert.equal(/\bGRANT\b[^;]+\bTO\s+PUBLIC\s*;/i.test(combined), false);
  assert.equal(combined.match(/REVOKE ALL ON FUNCTION app_(?:rls|auth)\.[^;]+ FROM PUBLIC;/g)?.length, 19);
});

test("candidate helper grants and rollback revokes preserve the split role boundary", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  const rollbackSql = fs.readFileSync(rollbackSqlPath, "utf8");
  assert.match(candidateSql, /GRANT EXECUTE ON FUNCTION app_auth\.lookup_password_user\(text\) TO :"mscqr_app_role";/);
  assert.match(candidateSql, /GRANT EXECUTE ON FUNCTION app_auth\.record_password_failure[\s\S]+TO :"mscqr_app_role";/);
  assert.doesNotMatch(candidateSql, /GRANT EXECUTE ON FUNCTION app_auth\.[^;]+TO :"mscqr_rls_read_role";/s);
  assert.match(candidateSql, /GRANT EXECUTE ON FUNCTION app_rls\.setting\(text\)[\s\S]+TO :"mscqr_rls_read_role", :"mscqr_app_role";/);
  assert.match(rollbackSql, /REVOKE EXECUTE ON FUNCTION app_auth\.lookup_password_user\(text\) FROM :"mscqr_app_role";/);
  assert.match(rollbackSql, /REVOKE EXECUTE ON FUNCTION app_rls\.setting\(text\) FROM :"mscqr_rls_read_role", :"mscqr_app_role";/);
});

test("candidate and rollback require explicit split roles and nonzero missing-variable exits", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  const rollbackSql = fs.readFileSync(rollbackSqlPath, "utf8");

  for (const variable of ["mscqr_app_role", "mscqr_rls_read_role", "mscqr_auth_owner_role"]) {
    assert.match(candidateSql, new RegExp(`\\\\if :\\{\\?${variable}\\}`));
    assert.match(rollbackSql, new RegExp(`\\\\if :\\{\\?${variable}\\}`));
  }
  for (const variable of ["mscqr_enable_shared_force_rls", "mscqr_enable_batch_force_rls", "mscqr_enable_printer_force_rls"]) {
    assert.match(candidateSql, new RegExp(`\\\\if :\\{\\?${variable}\\}`));
  }
  assert.equal(candidateSql.match(/\\set mscqr_[a-z_]+ __mscqr_missing__/g)?.length, 6);
  assert.equal(rollbackSql.match(/\\set mscqr_[a-z_]+ __mscqr_missing__/g)?.length, 3);
  assert.match(candidateSql, /RAISE EXCEPTION 'Missing one or more required candidate psql variables'/);
  assert.match(rollbackSql, /RAISE EXCEPTION 'Missing one or more required rollback psql variables'/);
  assert.match(candidateSql, /mscqr-staging-auth-owner-v1/);
  assert.match(rollbackSql, /mscqr-staging-auth-owner-v1/);
  assert.doesNotMatch(candidateSql, /mscqr_runtime_role/);
  assert.doesNotMatch(rollbackSql, /mscqr_runtime_role/);
});

const safeDiagnostics = () => ({
  identity: {
    session_user: "mscqr_harness_owner",
    current_user: "mscqr_harness_runtime",
    current_role: "mscqr_harness_runtime",
    row_security: "on",
  },
  role: {
    rolsuper: false,
    rolbypassrls: false,
    rolcreaterole: false,
    rolcreatedb: false,
    rolreplication: false,
  },
  memberships: [],
  tables: Array.from({ length: 16 }, (_, index) => ({
    relname: `table_${index}`,
    relrowsecurity: true,
    relforcerowsecurity: true,
    has_select: true,
    owns_or_inherits_owner: false,
    current_role_owns: false,
  })),
});

test("runtime diagnostic accepts separated least-privileged role", () => {
  assert.doesNotThrow(() => assertRuntimeRoleDiagnostics(safeDiagnostics(), "mscqr_harness_runtime"));
});

test("runtime diagnostic rejects table owner", () => {
  const diagnostics = safeDiagnostics();
  diagnostics.tables[0].current_role_owns = true;
  assertRefused(() => assertRuntimeRoleDiagnostics(diagnostics, "mscqr_harness_runtime"), /separation failed/);
});

test("runtime diagnostic rejects BYPASSRLS", () => {
  const diagnostics = safeDiagnostics();
  diagnostics.role.rolbypassrls = true;
  assertRefused(() => assertRuntimeRoleDiagnostics(diagnostics, "mscqr_harness_runtime"), /forbidden/);
});

test("runtime diagnostic rejects CREATEDB and CREATEROLE", () => {
  for (const attribute of ["rolcreatedb", "rolcreaterole"]) {
    const diagnostics = safeDiagnostics();
    diagnostics.role[attribute] = true;
    assertRefused(() => assertRuntimeRoleDiagnostics(diagnostics, "mscqr_harness_runtime"), /forbidden/);
  }
});

test("candidate and rollback do not reconstruct or broaden baseline table grants", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  const rollbackSql = fs.readFileSync(rollbackSqlPath, "utf8");
  assert.doesNotMatch(candidateSql, /(?:GRANT|REVOKE) (?:SELECT|INSERT|UPDATE|DELETE) ON TABLE/);
  assert.doesNotMatch(rollbackSql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE) ON TABLE/);
  assert.match(candidateSql, /Candidate apply never rewrites the application or read-role table baseline/);
});

test("candidate separates auth installation from explicit RLS table phases", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  assert.match(candidateSql, /\\if :mscqr_enable_shared_force_rls[\s\S]+ALTER TABLE "User" ENABLE ROW LEVEL SECURITY/);
  assert.match(candidateSql, /\\if :mscqr_enable_batch_force_rls[\s\S]+ALTER TABLE "Batch" ENABLE ROW LEVEL SECURITY/);
  assert.match(candidateSql, /\\if :mscqr_enable_printer_force_rls[\s\S]+ALTER TABLE "Printer" ENABLE ROW LEVEL SECURITY/);
});

test("exact application roles gate platform, tenant, and manufacturer context", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  assert.match(candidateSql, /current_role\(\) IN \('super_admin', 'platform_super_admin'\)/);
  assert.match(candidateSql, /current_role\(\) = 'licensee_admin'/);
  assert.match(candidateSql, /current_role\(\) = 'manufacturer'/);
  assert.doesNotMatch(candidateSql, /\b(org_admin|manufacturer_admin|manufacturer_user)\b/);
});
