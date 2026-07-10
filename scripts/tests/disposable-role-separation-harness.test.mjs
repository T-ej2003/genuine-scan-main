import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  ADMIN_DATABASE_URL_ENV,
  APPLY_TEMPLATE,
  CONFIRM_ENV,
  CONFIRM_VALUE,
  RoleSeparationHarnessSafetyError,
  ROLLBACK_TEMPLATE,
  assertConfirmation,
  assertSafeLocalAdminUrl,
  parseArgs,
  protectedTables,
} from "../run-disposable-role-separation-harness.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const localUrl = "postgresql://mscqr_p2_test@127.0.0.1:55432/mscqr_p2_admin_test";
const applySql = fs.readFileSync(path.join(repoRoot, APPLY_TEMPLATE), "utf8");
const rollbackSql = fs.readFileSync(path.join(repoRoot, ROLLBACK_TEMPLATE), "utf8");

test("role-separation harness requires explicit confirmation", () => {
  assert.throws(
    () => assertConfirmation({}),
    (error) => error instanceof RoleSeparationHarnessSafetyError && /MSCQR_DISPOSABLE_ROLE_SEPARATION_CONFIRM/.test(error.message),
  );
  assert.doesNotThrow(() => assertConfirmation({ [CONFIRM_ENV]: CONFIRM_VALUE }));
});

test("role-separation harness accepts only local disposable admin URLs", () => {
  assert.equal(assertSafeLocalAdminUrl(localUrl).hostname, "127.0.0.1");
  for (const url of [
    "postgresql://role@db.example.internal:5432/mscqr_test",
    "postgresql://role@127.0.0.1:5432/mscqr_production",
    "postgresql://role@db.example.rds.amazonaws.com:5432/mscqr_test",
  ]) {
    assert.throws(() => assertSafeLocalAdminUrl(url), RoleSeparationHarnessSafetyError);
  }
});

test("role-separation harness argument parser has no implicit remote target", () => {
  assert.deepEqual(parseArgs([]), { adminDatabaseUrl: "", json: false, help: false });
  assert.deepEqual(parseArgs(["--admin-database-url", localUrl, "--json"]), {
    adminDatabaseUrl: localUrl,
    json: true,
    help: false,
  });
  assert.throws(() => parseArgs(["--admin-database-url"]), RoleSeparationHarnessSafetyError);
  assert.equal(ADMIN_DATABASE_URL_ENV, "MSCQR_DISPOSABLE_ROLE_SEPARATION_ADMIN_URL");
});

test("role-separation templates stay manual, credential-free, and production-refusing", () => {
  const combined = `${applySql}\n${rollbackSql}`;
  assert.match(applySql, /DO NOT RUN IN PRODUCTION/);
  assert.match(applySql, /DO NOT place this file in Prisma migrations/);
  assert.match(combined, /production-like database name/);
  assert.match(applySql, /BEGIN;/);
  assert.match(applySql, /COMMIT;/);
  assert.match(rollbackSql, /BEGIN;/);
  assert.match(rollbackSql, /COMMIT;/);
  assert.doesNotMatch(combined, /\bPASSWORD\b|postgresql:\/\/|postgres:\/\//i);
  assert.doesNotMatch(combined, /\bGRANT\b[^;]+\bTO\s+PUBLIC\s*;/i);
  assert.doesNotMatch(combined, /ALL PRIVILEGES/i);
  assert.doesNotMatch(combined, /prisma\s+(?:migrate|db\s+push)/i);
});

test("role-separation template requires all explicit role variables and validates least privilege", () => {
  for (const variable of [
    "mscqr_previous_owner_role",
    "mscqr_owner_role",
    "mscqr_migrator_role",
    "mscqr_app_role",
    "mscqr_rls_read_role",
  ]) {
    assert.match(applySql, new RegExp(`\\\\if :\\{\\?${variable}\\}`));
    assert.match(rollbackSql, new RegExp(`\\\\if :\\{\\?${variable}\\}`));
  }
  assert.match(applySql, /NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(applySql, /LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS/);
  assert.match(applySql, /WITH ADMIN FALSE, INHERIT FALSE, SET TRUE/);
  assert.match(applySql, /RLS read role grant verification failed/);
  assert.match(applySql, /PUBLIC grants remain/);
});

test("role-separation template grants the exact protected RLS read table set", () => {
  const rlsSection = applySql.slice(applySql.indexOf("-- The dedicated RLS read role"));
  const rlsGrant = rlsSection.match(/GRANT SELECT ON TABLE\s+([\s\S]*?)\s+TO :"mscqr_rls_read_role";/);
  assert(rlsGrant, "missing explicit RLS read grant");
  const grantedTables = [...rlsGrant[1].matchAll(/"([A-Za-z0-9_]+)"/g)].map((match) => match[1]).sort();
  assert.deepEqual(grantedTables, [...protectedTables].sort());
  assert.match(applySql, /Public sequences exist; update the reviewed role grant inventory/);
});
