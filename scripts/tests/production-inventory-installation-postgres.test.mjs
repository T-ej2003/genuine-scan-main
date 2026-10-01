import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { canonicalInventoryInstallation, executeInventoryInstallation } from "../aws/production-rotation-inventory-installation.mjs";
import { rotationInventoryFunctionSql, ROTATION_INVENTORY_TABLES } from "../rls/lib/rotation-inventory-contract.mjs";
const requireBackend = createRequire(new URL("../../backend/package.json", import.meta.url));
const url = process.env.MSCQR_INVENTORY_INSTALL_TEST_DATABASE_URL;
const admin = process.env.MSCQR_INVENTORY_INSTALL_TEST_ADMIN_URL;
const sql = (connection, query) => execFileSync("psql", [connection, "-XAt", "-v", "ON_ERROR_STOP=1", "-c", query], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
test("actual production-shaped PostgreSQL18 contract install is atomic and refuses a blind retry", { skip: !url || !admin }, async () => {
  const { PrismaClient } = requireBackend("@prisma/client");
  const contract = canonicalInventoryInstallation();
  assert.equal(sql(admin, "SELECT count(*) FROM pg_database WHERE datname='mscqr_production_rls_green_phase2'"), "0");
  sql(admin, "CREATE ROLE mscqr_prod_admin LOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE mscqr_prd_rls_phase2_owner NOLOGIN NOINHERIT NOBYPASSRLS; CREATE ROLE mscqr_prd_rls_phase2_app LOGIN NOINHERIT NOBYPASSRLS; GRANT mscqr_prd_rls_phase2_owner TO mscqr_prod_admin WITH INHERIT FALSE, SET TRUE;");
  sql(admin, "CREATE DATABASE mscqr_production_rls_green_phase2 OWNER mscqr_prod_admin");
  const setup = new URL(admin); setup.pathname = "/mscqr_production_rls_green_phase2";
  const columns = { RefreshToken: '"userId" text,"revokedAt" timestamp,"expiresAt" timestamp', User: '"id" text,"status" text,"isActive" boolean,"deletedAt" timestamp,"role" text', CustomerAuthSession: '"revokedAt" timestamp,"expiresAt" timestamp', CustomerVerificationSession: '"expiresAt" timestamp', Invite: '"usedAt" timestamp,"expiresAt" timestamp', PasswordReset: '"usedAt" timestamp,"expiresAt" timestamp', EmailVerificationToken: '"usedAt" timestamp,"expiresAt" timestamp', QRCode: '"issuanceMode" text,"tokenExpiresAt" timestamp', CompliancePackJob: '"signatureAlgorithm" text,"finishedAt" timestamp' };
  const db = new PrismaClient({ datasources: { db: { url } } });
  try {
    sql(setup, `CREATE SCHEMA app_rls AUTHORIZATION ${contract.owner}; GRANT USAGE ON SCHEMA public,app_rls TO ${contract.app}; ${ROTATION_INVENTORY_TABLES.map((t) => `CREATE TABLE public."${t}" (${columns[t]}); ALTER TABLE public."${t}" OWNER TO ${contract.owner}; ALTER TABLE public."${t}" ENABLE ROW LEVEL SECURITY; ALTER TABLE public."${t}" FORCE ROW LEVEL SECURITY;`).join(" ")}`);
    const result = await db.$transaction((tx) => executeInventoryInstallation(tx, contract), { timeout: 60000 });
    assert.equal(result.status, "APPLIED"); assert.equal(result.policyCount, 9); assert.equal(result.directTableGrantsAdded, 0);
    await assert.rejects(() => db.$transaction((tx) => executeInventoryInstallation(tx, contract)), /already exists or is partial/);
    const app = new URL(url); app.username = contract.app;
    assert.equal(sql(app, "BEGIN READ ONLY; SELECT (app_rls.production_rotation_inventory()->'refreshSessions'->>'count')::int; ROLLBACK"), "BEGIN\n0\nROLLBACK");
    assert.match(rotationInventoryFunctionSql(contract), /REVOKE ALL.*FROM PUBLIC/);
  } finally {
    await db.$disconnect(); sql(admin, "DROP DATABASE mscqr_production_rls_green_phase2 WITH (FORCE)"); sql(admin, "DROP ROLE mscqr_prod_admin,mscqr_prd_rls_phase2_owner,mscqr_prd_rls_phase2_app");
  }
});
