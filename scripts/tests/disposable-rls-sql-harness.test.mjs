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
  parseArgs,
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
  assertRefused(() => assertSafeAppRole("PUBLIC"), /PUBLIC must not be used/);
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
  const args = parseArgs(["--prepare-schema", "--run-route-tests", "--no-evidence-file", "--json", "--app-role", "mscqr_rls_harness_app"]);

  assert.equal(args.runRouteTests, true);
  assert.equal(args.prepareSchema, true);
  assert.equal(args.evidenceFile, false);
  assert.equal(args.json, true);
  assert.equal(args.appRole, "mscqr_rls_harness_app");
});

test("candidate and rollback SQL do not grant or revoke all functions or PUBLIC", () => {
  const combined = `${fs.readFileSync(candidateSqlPath, "utf8")}\n${fs.readFileSync(rollbackSqlPath, "utf8")}`;

  assert.equal(/\bGRANT\s+EXECUTE\s+ON\s+ALL\s+FUNCTIONS\b/i.test(combined), false);
  assert.equal(/\bREVOKE\s+EXECUTE\s+ON\s+ALL\s+FUNCTIONS\b/i.test(combined), false);
  assert.equal(/\b(?:TO|FROM)\s+PUBLIC\b/i.test(combined), false);
});

test("candidate helper EXECUTE grants exactly match rollback revokes", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  const rollbackSql = fs.readFileSync(rollbackSqlPath, "utf8");
  const grantRegex = /GRANT EXECUTE ON FUNCTION\s+(app_rls\.[^(]+\([^)]*\))\s+TO\s+:"mscqr_staging_app_role";/g;
  const revokeRegex = /REVOKE EXECUTE ON FUNCTION\s+(app_rls\.[^(]+\([^)]*\))\s+FROM\s+:"mscqr_staging_app_role";/g;
  const grants = [...candidateSql.matchAll(grantRegex)].map((match) => match[1]).sort();
  const revokes = [...rollbackSql.matchAll(revokeRegex)].map((match) => match[1]).sort();

  assert.equal(grants.length, 17);
  assert.deepEqual(grants, revokes);
});

test("candidate and rollback require reviewed app role psql variable", () => {
  const candidateSql = fs.readFileSync(candidateSqlPath, "utf8");
  const rollbackSql = fs.readFileSync(rollbackSqlPath, "utf8");

  assert.match(candidateSql, /\\if :\{\?mscqr_staging_app_role\}/);
  assert.match(rollbackSql, /\\if :\{\?mscqr_staging_app_role\}/);
  assert.match(candidateSql, /GRANT USAGE ON SCHEMA app_rls TO :"mscqr_staging_app_role";/);
  assert.match(rollbackSql, /REVOKE USAGE ON SCHEMA app_rls FROM %I/);
});
