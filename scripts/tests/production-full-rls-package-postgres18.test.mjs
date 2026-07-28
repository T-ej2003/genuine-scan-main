import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  PRODUCTION_RLS_APPROVAL_ALGORITHM,
  canonicalProductionApprovalPayload,
} from "../../backend/scripts/production-rls-approval.mjs";
import { calculateCleanRoomSourceContract } from "../rls/lib/clean-room-source-contract.mjs";

const enabled = process.env.MSCQR_PRODUCTION_PACKAGE_POSTGRES18_TEST === "true";
const root = process.cwd();
const sqlRoot = path.join(root, "scripts/rls/sql/generated");
const evidenceRoot = path.join(root, "documents/security/rls-program/generated");
const targetDatabase = "mscqr_production_rls_green_phase2";
const administrator = "mscqr_prod_admin";
const randomMfaSecret = () =>
  [...crypto.randomBytes(32)].map((value) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[value & 31]).join("");

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    env: { ...process.env, ...(options.env || {}) },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${options.label || command} failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  }
  return String(result.stdout || "").trim();
};

const safeAdminUrl = () => {
  const value = String(process.env.MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL || "");
  const url = new URL(value);
  if (!["127.0.0.1", "localhost", "::1"].includes(url.hostname)
      || !/disposable|full_rls|_test/i.test(url.pathname)
      || Number(url.port || 5432) < 1024) {
    throw new Error("Production package certification requires an explicit loopback disposable PostgreSQL URL.");
  }
  return url;
};

const databaseUrl = (base, database, user) => {
  const url = new URL(base);
  url.pathname = `/${database}`;
  url.username = user;
  url.password = "";
  return url.toString();
};

const psql = (url, args, label) => run("psql", [url, "-X", "-v", "ON_ERROR_STOP=1", ...args], { label });
const scalar = (url, sql, label) => psql(url, ["-q", "-t", "-A", "-c", sql], label).split("\n").at(-1);

test("approved production package executes on disposable PostgreSQL 18 and rollback removes every managed role", { skip: !enabled }, () => {
  const adminUrl = safeAdminUrl();
  assert.equal(Number(scalar(adminUrl, "SELECT current_setting('server_version_num')::integer / 10000", "PostgreSQL major")), 18);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-production-package-"));
  const sqlBackup = path.join(temporary, "sql");
  const evidenceBackup = path.join(temporary, "evidence");
  fs.cpSync(sqlRoot, sqlBackup, { recursive: true });
  fs.cpSync(evidenceRoot, evidenceBackup, { recursive: true });

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicKeyPath = path.join(temporary, "approval-public.pem");
  const approvalPath = path.join(temporary, "approval.json");
  fs.writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
  const { sourceContractSha256, migrationSetDigest } = calculateCleanRoomSourceContract();
  const issuedAt = new Date();
  const approval = {
    schemaVersion: 1,
    environment: "production",
    releaseSha: "a".repeat(40),
    deploymentId: "phase2",
    greenDatabase: targetDatabase,
    sourceContractSha256,
    migrationSetDigest,
    approvalId: "APR-DISPOSABLE-PG18",
    ticketId: "CHG-DISPOSABLE-PG18",
    administratorIdentity: administrator,
    independentCheckerIdentity:
      "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/disposable-test",
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 60 * 60_000).toISOString(),
    kmsKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/00000000-0000-4000-8000-000000000001",
    signatureAlgorithm: PRODUCTION_RLS_APPROVAL_ALGORITHM,
  };
  approval.signatureBase64 = crypto.sign("sha256", canonicalProductionApprovalPayload(approval), {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  }).toString("base64");
  fs.writeFileSync(approvalPath, `${JSON.stringify(approval)}\n`, { mode: 0o600 });

  const maintenanceUrl = adminUrl.toString();
  const greenUrl = databaseUrl(adminUrl, targetDatabase, administrator);
  const migrationUrl = databaseUrl(adminUrl, targetDatabase, "mscqr_prd_rls_phase2_migration");
  let residue = null;
  try {
    assert.equal(scalar(maintenanceUrl, `SELECT count(*) FROM pg_roles WHERE rolname=${JSON.stringify(administrator).replaceAll('"', "'")} OR rolname LIKE 'mscqr_prd_rls_phase2_%'`, "clean roles"), "0");
    assert.equal(scalar(maintenanceUrl, `SELECT count(*) FROM pg_database WHERE datname='${targetDatabase}'`, "clean database"), "0");
    run(process.execPath, [
      "scripts/rls/generate-clean-room-rls-sql.mjs",
      "--environment", "production",
      "--deployment-id", "phase2",
      "--release-sha", approval.releaseSha,
      "--approval-artifact", approvalPath,
      "--approval-kms-key-arn", approval.kmsKeyArn,
      "--local-disposable-approval-public-key", publicKeyPath,
      "--local-disposable-approval-confirm", "MSCQR_RUN_LOCAL_PRODUCTION_PACKAGE_CERTIFICATION",
    ], { env: { NODE_ENV: "test" }, label: "production package generation" });

    psql(maintenanceUrl, ["-q", "-c", `CREATE ROLE "${administrator}" LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS`], "create administrator");
    psql(databaseUrl(adminUrl, adminUrl.pathname.slice(1), administrator), ["-q", "-c", `CREATE DATABASE "${targetDatabase}" OWNER "${administrator}" TEMPLATE template0`], "create green database");
    psql(greenUrl, ["-q", "-f", path.join(sqlRoot, "admin-bootstrap.sql")], "administrator bootstrap");
    psql(migrationUrl, ["-q", "-f", path.join(sqlRoot, "migration.sql")], "migration boundary");
    run("npx", ["prisma", "migrate", "deploy", "--schema", "prisma/schema.prisma"], {
      cwd: path.join(root, "backend"),
      env: { DATABASE_URL: migrationUrl, NODE_ENV: "test" },
      label: "zero-based Prisma migration",
    });
    const canaryEnv = {
      DATABASE_URL: migrationUrl,
      NODE_ENV: "production",
      MSCQR_FULL_RLS_MODE: "full-rls-admin-ownership",
      MSCQR_FULL_RLS_CONFIRMATION: "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS",
      MSCQR_PRODUCTION_RLS_APPROVAL_ARTIFACT: JSON.stringify(approval),
      MSCQR_CANARY_ORDINARY_EMAIL: "ordinary@green-canary.invalid",
      MSCQR_CANARY_ORDINARY_PASSWORD: crypto.randomBytes(32).toString("base64url"),
      MSCQR_CANARY_ORDINARY_MFA_SECRET: randomMfaSecret(),
      MSCQR_CANARY_ADMIN_EMAIL: "admin@green-canary.invalid",
      MSCQR_CANARY_ADMIN_PASSWORD: crypto.randomBytes(32).toString("base64url"),
      MSCQR_CANARY_ADMIN_MFA_SECRET: randomMfaSecret(),
      AUTH_MFA_ENCRYPTION_KEY: crypto.randomBytes(32).toString("base64url"),
    };
    for (const label of ["create canaries", "reconcile canaries"]) {
      run(process.execPath, ["scripts/production-green-canary-provision.mjs"], {
        cwd: path.join(root, "backend"),
        env: canaryEnv,
        label,
      });
    }
    assert.equal(scalar(migrationUrl, 'SELECT count(*) FROM "User"', "canary users"), "2");
    assert.equal(scalar(migrationUrl, 'SELECT count(*) FROM "AdminMfaCredential" WHERE "isEnabled"', "canary MFA"), "2");
    assert.equal(scalar(migrationUrl, 'SELECT count(*) FROM "Licensee"', "canary and isolation-control licensees"), "2");
    assert.equal(
      scalar(migrationUrl, `SELECT count(*) FROM "AuditLog" WHERE action='PRODUCTION_GREEN_CANARY_IDENTITIES_PROVISIONED'`, "canary audit attribution"),
      "1"
    );
    for (const file of ["admin-ownership.sql", "runtime-policy.sql", "verification.sql"]) {
      psql(greenUrl, ["-q", "-f", path.join(sqlRoot, file)], file);
    }
    assert(Number(scalar(greenUrl, "SELECT count(*) FROM pg_class WHERE relrowsecurity AND relforcerowsecurity", "forced RLS")) > 0);
    assert(Number(scalar(greenUrl, "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('app_auth','app_rls')", "restricted functions")) > 0);
    assert.equal(
      scalar(greenUrl, "SELECT approval_id || ':' || administrator_role FROM mscqr_rls_install.state", "approval install state"),
      `APR-DISPOSABLE-PG18:${administrator}`
    );
  } finally {
    try {
      if (scalar(maintenanceUrl, `SELECT count(*) FROM pg_database WHERE datname='${targetDatabase}'`, "inspect green database") === "1") {
        psql(maintenanceUrl, ["-q", "-c", `DROP DATABASE "${targetDatabase}" WITH (FORCE)`], "drop green database");
      }
      if (scalar(maintenanceUrl, `SELECT count(*) FROM pg_roles WHERE rolname LIKE 'mscqr_prd_rls_phase2_%'`, "inspect managed roles") !== "0") {
        psql(databaseUrl(adminUrl, adminUrl.pathname.slice(1), administrator), [
          "-q", "-v", `candidate_database=${targetDatabase}`, "-f", path.join(sqlRoot, "clean-room-cleanup.sql"),
        ], "clean managed roles");
      }
      residue = scalar(maintenanceUrl, "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'mscqr_prd_rls_phase2_%'", "zero managed role residue");
      if (scalar(maintenanceUrl, `SELECT count(*) FROM pg_roles WHERE rolname='${administrator}'`, "inspect administrator") === "1") {
        psql(maintenanceUrl, ["-q", "-c", `DROP ROLE "${administrator}"`], "drop administrator");
      }
    } finally {
      fs.rmSync(sqlRoot, { recursive: true, force: true });
      fs.rmSync(evidenceRoot, { recursive: true, force: true });
      fs.cpSync(sqlBackup, sqlRoot, { recursive: true });
      fs.cpSync(evidenceBackup, evidenceRoot, { recursive: true });
      fs.rmSync(temporary, { recursive: true, force: true });
    }
  }
  assert.equal(residue, "0");
});
