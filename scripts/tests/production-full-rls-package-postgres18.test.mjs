import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createRequire } from "node:module";
import { collectAppOnlyDatabaseCatalogue } from "../aws/production-app-only-database-verifier.mjs";
import { createAppOnlyRequirements, assertAppOnlyRequirements, compareAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { buildAppOnlyVerifierCommand, authenticateAppOnlyVerifierResult } from "../aws/production-app-only-verifier-command.mjs";
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
    env: { ...(options.cleanEnv ? {} : process.env), ...(options.env || {}) },
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

test("approved production package executes on disposable PostgreSQL 18 and rollback removes every managed role", { skip: !enabled }, async () => {
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
  let verifierCreated = false;
  let appOnlyRequirements;
  let rdsMembershipsNormalized = false;
  const verifierRole = "mscqr_prod_rls_canary_read";
  const restoreDisposableMemberships = () => psql(maintenanceUrl, ["-q", "-c", `DO $restore_disposable_memberships$
    DECLARE managed_role text;
    BEGIN
      FOR managed_role IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'mscqr\\_prd\\_rls\\_phase2\\_%' ESCAPE '\\'
      LOOP
        EXECUTE format('GRANT %I TO %I WITH ADMIN TRUE, INHERIT FALSE, SET FALSE', managed_role, '${administrator}');
        EXECUTE format('SET ROLE %I', '${administrator}');
        EXECUTE format('GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', managed_role, '${administrator}');
        RESET ROLE;
      END LOOP;
    END $restore_disposable_memberships$;`], "restore disposable-superuser membership topology");
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
    const migrationPreflightSql = fs.readFileSync(path.join(sqlRoot, "15-migration-preflight.sql"), "utf8");
    assert.match(migrationPreflightSql, /pg_has_role\('mscqr_prod_admin',r\.oid,'MEMBER'\)/);
    assert.doesNotMatch(migrationPreflightSql, /pg_has_role\(current_user,r\.oid,'MEMBER'\)/);

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
    // The disposable superuser path deliberately leaves a second ADMIN-only
    // membership per managed role. Amazon RDS exposes the source-defined
    // rdsadmin-granted SET-only topology instead; requirements must model that
    // production topology, not a local-superuser implementation detail.
    psql(maintenanceUrl, ["-q", "-c", `DO $normalize_rds_memberships$
      DECLARE managed_role text;
      BEGIN
        FOR managed_role IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'mscqr\\_prd\\_rls\\_phase2\\_%' ESCAPE '\\'
        LOOP
          EXECUTE format('REVOKE ADMIN OPTION FOR %I FROM %I GRANTED BY CURRENT_USER CASCADE', managed_role, '${administrator}');
          EXECUTE format('GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', managed_role, '${administrator}');
        END LOOP;
      END $normalize_rds_memberships$;`], "normalize production RDS membership topology");
    rdsMembershipsNormalized = true;
    assert.equal(scalar(maintenanceUrl, `SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid
      JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname LIKE 'mscqr\\_prd\\_rls\\_phase2\\_%' ESCAPE '\\'
      AND member.rolname='${administrator}' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option`, "production RDS membership topology"), "9");
    // Requirements come from the canonical, fully installed source package in
    // this disposable server, never from production's observed catalogue.
    assert.equal(scalar(maintenanceUrl, `SELECT count(*) FROM pg_roles WHERE rolname='${verifierRole}'`, "verifier role absent"), "0");
    psql(maintenanceUrl, ["-q", "-c", `CREATE ROLE ${verifierRole} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`], "local verifier identity");
    verifierCreated = true;
    // The source-owned canary provisioner adds schema USAGE and a fixed probe.
    // Include it in the oracle rather than declaring those real grants drift.
    // Its initializer-owned scope table is only a local provisioning fixture;
    // it is not part of the candidate's public-schema requirements catalogue.
    psql(databaseUrl(adminUrl, targetDatabase, adminUrl.username), ["-q", "-c", `GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner;
      SET ROLE mscqr_prd_rls_phase2_auth_owner;
      CREATE TABLE app_rls.production_read_only_canary_control(scope_name text PRIMARY KEY, scope_id text UNIQUE);
      INSERT INTO app_rls.production_read_only_canary_control VALUES ('canary','00000000-0000-4000-8000-000000000001');
      RESET ROLE;`], "local canary initializer fixture");
    psql(databaseUrl(adminUrl, targetDatabase, adminUrl.username), ["-q", "-v", "canary_credential_rotation=false", "-f",
      path.join(root, "documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql")], "canonical local read-only canary provisioning");
    psql(databaseUrl(adminUrl, targetDatabase, adminUrl.username), ["-q", "-c", "REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner"], "restore canonical schema privilege boundary after local fixture setup");
    const { PrismaClient } = createRequire(new URL("../../backend/package.json", import.meta.url))("@prisma/client");
    const verifier = new PrismaClient({ datasources: { db: { url: databaseUrl(adminUrl, targetDatabase, verifierRole) } } });
    try {
      const catalogue = await collectAppOnlyDatabaseCatalogue(verifier);
      const sourceSha = run("git", ["rev-parse", "HEAD"]);
      const context = { repositoryRoot: root, sourceSha,
        candidateSourceSha: process.env.MSCQR_APP_ONLY_CANDIDATE_SOURCE_SHA || sourceSha };
      const requirements = createAppOnlyRequirements({ ...context, catalogue,
        packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
      assertAppOnlyRequirements(requirements, context);
      assert.ok(catalogue.tables.length >= 79 && catalogue.policies.length >= 351);
      assert.ok(Object.values(compareAppOnlyRequirements(catalogue, requirements)).every((value) => value === "COMPATIBLE"));
      const identity = { sourceSha, candidateSourceSha: context.candidateSourceSha,
        account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
        databaseHostname: adminUrl.hostname, verifierImageDigest: `sha256:${"3".repeat(64)}`,
        predecessorTaskDefinition: `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`,
        predecessorBackendDigest: `sha256:${"1".repeat(64)}`, candidateDigest: `sha256:${"2".repeat(64)}` };
      const command = buildAppOnlyVerifierCommand({ requirements, identity, repositoryRoot: root });
      const verifierUrl = new URL(databaseUrl(adminUrl, targetDatabase, verifierRole));
      verifierUrl.password = "synthetic-local-verifier-password";
      verifierUrl.searchParams.set("sslmode", "require");
      verifierUrl.searchParams.set("application_name", "mscqr-production-green-read-only-rls-canary");
      // macOS injects this process-launch variable even with a clean env. It is
      // not present in ECS/Linux and must not widen the production allowlist.
      const localCommand = [...command.command];
      if (process.platform === "darwin") localCommand[1] = `delete process.env.__CF_USER_TEXT_ENCODING;\n${localCommand[1]}`;
      const message = run(process.execPath, localCommand, { cwd: path.join(root, "backend"),
        cleanEnv: true, env: { RLS_CANARY_DATABASE_URL: verifierUrl.toString(), NODE_ENV: "production", PORT: "4000",
          RUN_DB_MIGRATIONS_ON_START: "false", GIT_SHA: sourceSha, RELEASE_GIT_SHA: sourceSha,
          AWS_EXECUTION_ENV: "AWS_ECS_FARGATE", AWS_REGION: APP_ONLY.region, AWS_DEFAULT_REGION: APP_ONLY.region,
          AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/local-disposable",
          ECS_CONTAINER_METADATA_URI_V4: "http://169.254.170.2/v4/local-disposable" },
        label: "fixed verifier command against canonical local PostgreSQL" });
      authenticateAppOnlyVerifierResult({ message, identity, requirementsSha256: requirements.requirementsSha256,
        verificationContractSha256: command.verificationContractSha256 });
      const hostile = structuredClone(catalogue);
      hostile.routines[0].security_definer = !hostile.routines[0].security_definer;
      assert.equal(compareAppOnlyRequirements(hostile, requirements).RLS_FUNCTIONS, "INCOMPATIBLE");
      appOnlyRequirements = requirements;
    } finally { await verifier.$disconnect(); }
    restoreDisposableMemberships();
    rdsMembershipsNormalized = false;
    const migrationPassword = "synthetic-migration-password";
    psql(greenUrl, ["-q", "-c", `ALTER ROLE "${new URL(migrationUrl).username}" PASSWORD '${migrationPassword}'`], "migration credential provisioning");
    const connectableMigrationUrl = new URL(migrationUrl); connectableMigrationUrl.password = migrationPassword;
    const bootstrapContext = "SELECT set_config('app.auth_assurance','system-verified',true),set_config('app.operator_environment','production',true),set_config('app.request_id','00000000-0000-4000-8000-000000000099',true),set_config('app.purpose','bootstrap-configured-super-admin',true),set_config('app.context_installed','1',true)";
    assert.equal(scalar(connectableMigrationUrl, `BEGIN;${bootstrapContext};SELECT status FROM app_ops.bootstrap_configured_super_admin('administration@mscqr.com','synthetic-argon2id-hash','MSCQR Administration',true);COMMIT`, "initial administrator bootstrap"), "created");
    assert.equal(scalar(connectableMigrationUrl, `BEGIN;${bootstrapContext};SELECT status||':'||email||':'||role FROM app_ops.bootstrap_configured_super_admin('administration@mscqr.com','synthetic-argon2id-hash','MSCQR Administration',true);COMMIT`, "duplicate administrator bootstrap"), "skipped_existing:administration@mscqr.com:SUPER_ADMIN");
    assert.throws(() => scalar(greenUrl, `BEGIN;SET LOCAL ROLE "mscqr_prd_rls_phase2_app";${bootstrapContext};SELECT status FROM app_ops.bootstrap_configured_super_admin('administration@mscqr.com','synthetic-argon2id-hash','MSCQR Administration',true);COMMIT`, "ordinary application bootstrap"), /permission denied/);
    assert(Number(scalar(greenUrl, "SELECT count(*) FROM pg_class WHERE relrowsecurity AND relforcerowsecurity", "forced RLS")) > 0);
    assert(Number(scalar(greenUrl, "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('app_auth','app_rls')", "restricted functions")) > 0);
    assert.equal(
      scalar(greenUrl, "SELECT approval_id || ':' || administrator_role FROM mscqr_rls_install.state", "approval install state"),
      `APR-DISPOSABLE-PG18:${administrator}`
    );
  } finally {
    try {
      if (rdsMembershipsNormalized) {
        restoreDisposableMemberships();
        rdsMembershipsNormalized = false;
      }
      if (scalar(maintenanceUrl, `SELECT count(*) FROM pg_database WHERE datname='${targetDatabase}'`, "inspect green database") === "1") {
        psql(maintenanceUrl, ["-q", "-c", `DROP DATABASE "${targetDatabase}" WITH (FORCE)`], "drop green database");
      }
      if (verifierCreated) psql(maintenanceUrl, ["-q", "-c", `DROP ROLE ${verifierRole}`], "drop local verifier");
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
  // The protected producer owns this private destination. Publish only after
  // certification AND cleanup/restoration succeed; failed runs emit no proof.
  if (process.env.MSCQR_APP_ONLY_REQUIREMENTS_PATH) {
    assert.ok(appOnlyRequirements);
    writeStageBPrivateFileExclusive({ filePath: process.env.MSCQR_APP_ONLY_REQUIREMENTS_PATH,
      repositoryRoot: root, bytes: Buffer.from(`${JSON.stringify(appOnlyRequirements)}\n`) });
  }
});
