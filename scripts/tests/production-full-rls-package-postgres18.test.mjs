import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createRequire } from "node:module";
import { collectAppOnlyDatabaseCatalogue, collectAppOnlyDatabaseCatalogueRows } from "../aws/production-app-only-database-verifier.mjs";
import { createAppOnlyRequirements, assertAppOnlyRequirements, compareAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { buildAppOnlyVerifierCommand, authenticateAppOnlyVerifierResult } from "../aws/production-app-only-verifier-command.mjs";
import { buildPrintingRoutineDeltaCommand, canonicalPrintingRoutineDelta } from "../aws/apply-production-printing-routine-delta.mjs";
import { buildB01ExecutorInput, canonicalB01Prerequisite, collectB01State, executeB01Transaction } from "../aws/apply-production-b01-prerequisite.mjs";
import { B01_PREREQUISITE } from "../aws/production-b01-prerequisite-contract.mjs";
import { classifyProductionRlsCatalogue, hashProductionRlsCatalogue, RLS_PROBE_CLASSIFICATIONS } from "../aws/probe-production-rls-catalogue.mjs";
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
const printingDeltaRuntime = createRequire(import.meta.url)("../aws/production-printing-routine-delta-executor.cjs");
const b01Runtime = createRequire(import.meta.url)("../aws/production-b01-prerequisite-executor.cjs");
const b01ReadOnlyRuntime = createRequire(import.meta.url)("../aws/production-b01-prerequisite-readonly.cjs");
const printingRoutine = (source, name) => {
  const marker = `CREATE OR REPLACE FUNCTION app_rls.${name}(`;
  assert.equal(source.split(marker).length, 2);
  const start = source.indexOf(marker), end = source.indexOf("\n$fn$;", start);
  assert.ok(end > start);
  return source.slice(start, end + 6).replaceAll("{{APP_ROLE}}", "'mscqr_prd_rls_phase2_app'");
};

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

const b01PolicyFixtureSql = (installSource, dropSource) => {
  const policyLines = (source) => source.split("\n").filter((line) =>
    /^(?:CREATE POLICY|COMMENT ON POLICY) "b01_[^"]+" ON public\."[^"]+"/.test(line));
  const drops = policyLines(dropSource).flatMap((line) => {
    const match = /^CREATE POLICY "([^"]+)" ON public\."([^"]+)"/.exec(line);
    return match ? [`DROP POLICY IF EXISTS "${match[1]}" ON public."${match[2]}";`] : [];
  });
  const installs = policyLines(installSource).map((line) => line
    .replaceAll("mscqr_rls_cert_auth_owner", "mscqr_prd_rls_phase2_auth_owner")
    .replaceAll("mscqr_rls_cert_preauth", "mscqr_prd_rls_phase2_preauth"));
  assert.ok(drops.length > 0 && installs.length > 0 && installs.length % 2 === 0);
  return `${drops.join("\n")}\n${installs.join("\n")}`;
};

const collectCatalogueRows = (client) => client.$transaction(async (tx) => {
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
  return collectAppOnlyDatabaseCatalogueRows(tx);
}, { maxWait: 5000, timeout: 30000 });

const collectUnpinnedDeparserSurface = (client) => client.$transaction(async (tx) => {
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
  const [constraints, defaults, policies] = await Promise.all([
    tx.$queryRawUnsafe(`SELECT c.relname AS "table",k.conname AS name,pg_catalog.pg_get_constraintdef(k.oid) AS value
      FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY 1,2`),
    tx.$queryRawUnsafe(`SELECT c.relname AS "table",a.attname AS name,pg_catalog.pg_get_expr(d.adbin,d.adrelid) AS value
      FROM pg_catalog.pg_attrdef d JOIN pg_catalog.pg_class c ON c.oid=d.adrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=d.adnum
      WHERE n.nspname='public' ORDER BY 1,2`),
    tx.$queryRawUnsafe(`SELECT c.relname AS "table",p.polname AS name,pg_catalog.pg_get_expr(p.polqual,p.polrelid) AS "using",
      pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) AS "check" FROM pg_catalog.pg_policy p
      JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' ORDER BY 1,2`),
  ]);
  return { constraints, defaults, policies };
}, { maxWait: 5000, timeout: 30000 });

const changedRowCount = (left, right) => left.filter((row, index) => JSON.stringify(row) !== JSON.stringify(right[index])).length;
const changedFieldCount = (left, right, field) => left.filter((row, index) => row[field] !== right[index]?.[field]).length;

test("approved production package executes on disposable PostgreSQL 18 and rollback removes every managed role", { skip: !enabled }, async (t) => {
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
    const administratorClient = new PrismaClient({ datasources: { db: { url: greenUrl } } });
    const maintenanceClient = new PrismaClient({ datasources: { db: { url: databaseUrl(adminUrl, targetDatabase, adminUrl.username) } } });
    try {
      psql(maintenanceUrl, ["-q", "-c", `ALTER ROLE "${administrator}" INHERIT;
        GRANT pg_read_all_data TO "${administrator}" WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`], "production-equivalent inherited public access");
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege(current_user,'public','USAGE')", "administrator public usage"), "t");
      assert.equal(scalar(databaseUrl(adminUrl, targetDatabase, verifierRole), "SELECT has_schema_privilege(current_user,'public','USAGE')", "canary public usage"), "f");
      const [rawCanary, rawAdministrator] = await Promise.all([
        collectUnpinnedDeparserSurface(verifier), collectUnpinnedDeparserSurface(administratorClient),
      ]);
      const rawDifferences = {
        constraints: changedRowCount(rawCanary.constraints, rawAdministrator.constraints),
        defaults: changedRowCount(rawCanary.defaults, rawAdministrator.defaults),
        policyUsing: changedFieldCount(rawCanary.policies, rawAdministrator.policies, "using"),
        policyCheck: changedFieldCount(rawCanary.policies, rawAdministrator.policies, "check"),
      };
      assert.ok(Object.values(rawDifferences).every((count) => count > 0));
      const [canaryCatalogue, administratorCatalogue] = await Promise.all([
        collectCatalogueRows(verifier), collectCatalogueRows(administratorClient),
      ]);
      for (const collection of ["routines", "tables", "policies", "schemas", "roles"]) {
        assert.deepEqual(administratorCatalogue[collection], canaryCatalogue[collection]);
      }
      assert.equal(scalar(greenUrl, "SHOW search_path", "collector search path remains transaction-local"), '"$user", public');
      const collectionDigests = Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"]
        .map((collection) => [collection, crypto.createHash("sha256").update(JSON.stringify(canaryCatalogue[collection])).digest("hex")]));
      t.diagnostic(JSON.stringify({ principalInvariantCatalogue: { rawDifferences, collectionDigests } }));
      const catalogue = await collectAppOnlyDatabaseCatalogue(verifier);
      const sourceSha = run("git", ["rev-parse", "HEAD"]);
      const context = { repositoryRoot: root, sourceSha,
        candidateSourceSha: process.env.MSCQR_APP_ONLY_CANDIDATE_SOURCE_SHA || sourceSha };
      const requirements = createAppOnlyRequirements({ ...context, catalogue,
        packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
      assertAppOnlyRequirements(requirements, context);
      assert.ok(catalogue.tables.length >= 79 && catalogue.policies.length >= 351);
      assert.ok(Object.values(compareAppOnlyRequirements(catalogue, requirements)).every((value) => value === "COMPATIBLE"));
      const assertDurableDrift = async (sql, label) => {
        await assert.rejects(maintenanceClient.$transaction(async (tx) => {
          await tx.$executeRawUnsafe(sql);
          const changed = await collectAppOnlyDatabaseCatalogueRows(tx);
          assert.equal(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(changed), requirements).classification,
            RLS_PROBE_CLASSIFICATIONS.UNEXPECTED);
          throw new Error(`rollback ${label}`);
        }), new RegExp(`rollback ${label}`));
        assert.equal(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(await collectCatalogueRows(verifier)), requirements).classification,
          RLS_PROBE_CLASSIFICATIONS.MATCH);
      };
      await assertDurableDrift("GRANT USAGE ON SCHEMA app_rls TO PUBLIC", "schema ACL drift");
      await assertDurableDrift("ALTER SCHEMA app_rls OWNER TO mscqr_prod_admin", "schema owner drift");
      await assertDurableDrift(`ALTER POLICY "full_rls_auditlog_select_sql_profile_audit_log_licen_9fc3407041"
        ON public."AuditLog" USING (true)`, "policy drift");
      await assertDurableDrift("GRANT pg_read_all_settings TO mscqr_prod_rls_canary_read", "role membership drift");
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

      psql(maintenanceUrl, ["-q", "-c", `ALTER ROLE "${administrator}" NOINHERIT; REVOKE pg_read_all_data FROM "${administrator}"`], "restore production administrator identity");

      const b01Delta = canonicalB01Prerequisite();
      const currentB01PolicySource = fs.readFileSync(path.join(sqlRoot, "30-policies.sql"), "utf8");
      const historicalB01PolicySource = run("git", ["show", `${B01_PREREQUISITE.rlsDeltaOriginSha}:scripts/rls/sql/generated/30-policies.sql`]);
      psql(greenUrl, ["-q", "-c", `BEGIN;
        SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner;
        DROP FUNCTION app_auth.finalize_refresh_token_rotation(text,text[],text,timestamp without time zone,text);
        ${b01Delta.predecessorBindSql}
        RESET ROLE;
        COMMIT;`], "install B01 predecessor functions");
      psql(greenUrl, ["-q", "-c", `BEGIN;
        SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        ${b01PolicyFixtureSql(historicalB01PolicySource, currentB01PolicySource)}
        DROP POLICY b01_auditlogoutbox_select ON public."AuditLogOutbox";
        RESET ROLE;
        COMMIT;`], "reconstruct exact historical B01 predecessor policy state");
      const b01Input = buildB01ExecutorInput({ deploymentSourceSha: sourceSha, databaseHostname: adminUrl.hostname });
      const b01Predecessor = await administratorClient.$transaction((tx) => collectB01State(tx));
      assert.deepEqual(b01Predecessor.functions, b01Delta.predecessor.functions);
      assert.deepEqual(b01Predecessor.roles, b01Delta.predecessor.roles);
      assert.deepEqual(b01Predecessor.policies, b01Delta.predecessor.policies);
      assert.deepEqual(b01Predecessor.catalogue, b01Delta.predecessor.catalogue);
      const applyB01Mutations = async (tx) => {
        await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner");
        for (const mutation of b01Input.contract.mutations.slice(0, 4)) await tx.$executeRawUnsafe(mutation.sql);
        await tx.$executeRawUnsafe("RESET ROLE");
        await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_owner");
        for (const mutation of b01Input.contract.mutations.slice(4)) await tx.$executeRawUnsafe(mutation.sql);
        await tx.$executeRawUnsafe("RESET ROLE");
      };
      const waitForAdvisoryWaiter = async () => {
        for (let attempt = 0; attempt < 100; attempt++) {
          const [{ waiting }] = await maintenanceClient.$queryRawUnsafe(`SELECT count(*)::integer AS waiting FROM pg_catalog.pg_locks
            WHERE locktype='advisory' AND NOT granted`);
          if (waiting > 0) return;
          await new Promise((resolve) => setImmediate(resolve));
        }
        assert.fail("read-only reconciliation never waited on the B01 advisory lock");
      };
      const startLockHolder = ({ apply = false, fail = false } = {}) => {
        let release, ready;
        const released = new Promise((resolve) => { release = resolve; });
        const acquired = new Promise((resolve) => { ready = resolve; });
        const transaction = administratorClient.$transaction(async (tx) => {
          await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
          await tx.$executeRawUnsafe(b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL);
          ready(); await released;
          if (apply) await applyB01Mutations(tx);
          if (fail) throw new Error("injected ambiguous rollback");
        }, { maxWait: 10000, timeout: 120000 });
        return { acquired, release, transaction };
      };
      const committed = startLockHolder({ apply: true }); await committed.acquired;
      let commitProbeStarted;
      const commitProbeSync = new Promise((resolve) => { commitProbeStarted = resolve; });
      const commitProbe = b01ReadOnlyRuntime.executeB01ReadOnlyTransaction({ client: administratorClient,
        input: { contract: b01Input.contract }, collect: collectB01State, inspect: b01Runtime.inspectB01State,
        lockSql: b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL,
        stage: (stage) => { if (stage === "DATABASE_SYNCHRONIZATION") commitProbeStarted(); } });
      await commitProbeSync; await waitForAdvisoryWaiter(); committed.release(); await committed.transaction;
      assert.equal((await commitProbe).classification, "SUCCESSOR");
      psql(greenUrl, ["-q", "-c", `BEGIN;
        SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner;
        DROP FUNCTION app_auth.finalize_refresh_token_rotation(text,text[],text,timestamp without time zone,text);
        ${b01Delta.predecessorBindSql}
        RESET ROLE;
        SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        DROP POLICY b01_auditlogoutbox_select ON public."AuditLogOutbox";
        RESET ROLE;
        COMMIT;`], "restore predecessor after synchronized commit test");
      const rolledBackHolder = startLockHolder({ fail: true }); await rolledBackHolder.acquired;
      let rollbackProbeStarted;
      const rollbackProbeSync = new Promise((resolve) => { rollbackProbeStarted = resolve; });
      const rollbackProbe = b01ReadOnlyRuntime.executeB01ReadOnlyTransaction({ client: administratorClient,
        input: { contract: b01Input.contract }, collect: collectB01State, inspect: b01Runtime.inspectB01State,
        lockSql: b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL,
        stage: (stage) => { if (stage === "DATABASE_SYNCHRONIZATION") rollbackProbeStarted(); } });
      await rollbackProbeSync; await waitForAdvisoryWaiter(); rolledBackHolder.release(); await assert.rejects(rolledBackHolder.transaction, /injected ambiguous rollback/);
      assert.equal((await rollbackProbe).classification, "PREDECESSOR");
      const timedOut = startLockHolder({ fail: true }); await timedOut.acquired;
      await assert.rejects(b01ReadOnlyRuntime.executeB01ReadOnlyTransaction({ client: administratorClient,
        input: { contract: b01Input.contract }, collect: collectB01State, inspect: b01Runtime.inspectB01State,
        lockSql: b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL, lockTimeoutMs: 100 }));
      timedOut.release(); await assert.rejects(timedOut.transaction, /injected ambiguous rollback/);
      const readOnlyPredecessor = await b01ReadOnlyRuntime.executeB01ReadOnlyTransaction({ client: administratorClient,
        input: { contract: b01Input.contract }, collect: collectB01State, inspect: b01Runtime.inspectB01State,
        lockSql: b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL });
      assert.deepEqual({ classification: readOnlyPredecessor.classification, transactionReadOnly: readOnlyPredecessor.transactionReadOnly,
        livePredecessorMatch: readOnlyPredecessor.livePredecessorMatch, liveSuccessorMatch: readOnlyPredecessor.liveSuccessorMatch },
      { classification: "PREDECESSOR", transactionReadOnly: true, livePredecessorMatch: true, liveSuccessorMatch: false });
      for (const sql of ['INSERT INTO public."User" DEFAULT VALUES', 'UPDATE public."User" SET id=id WHERE false',
        'DELETE FROM public."User" WHERE false', 'CREATE TABLE public.b01_readonly_forbidden(id integer)']) {
        await assert.rejects(administratorClient.$transaction(async (tx) => {
          await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY");
          await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_owner"); await tx.$executeRawUnsafe(sql);
        }), /read-only transaction/);
      }
      await assert.rejects(administratorClient.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY");
        return executeB01Transaction({ tx, input: { contract: b01Input.contract } });
      }), /read-only transaction|transaction characteristics|read_only/);
      await assert.rejects(administratorClient.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY");
        await tx.$executeRawUnsafe("SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner");
        await tx.$queryRawUnsafe("SELECT app_auth.b01_audit('B01_READONLY_DENIED','synthetic-token',statement_timestamp()::timestamp without time zone)");
      }), /read-only transaction/);
      const policyPredicate = (name, field) => scalar(greenUrl, `SELECT pg_get_expr(p.${field},p.polrelid) FROM pg_policy p WHERE p.polname='${name}'`, `${name} ${field}`);
      const refreshSelectUsing = policyPredicate("b01_refreshtoken_select", "polqual");
      const refreshUpdateUsing = policyPredicate("b01_refreshtoken_update", "polqual");
      const refreshUpdateCheck = policyPredicate("b01_refreshtoken_update", "polwithcheck");
      const generatedPolicies = fs.readFileSync(path.join(sqlRoot, "30-policies.sql"), "utf8").split("\n");
      const restorePolicy = (name) => { const index = generatedPolicies.findIndex((line) => line.startsWith(`CREATE POLICY "${name}"`));
        assert.ok(index >= 0 && generatedPolicies[index + 1].startsWith(`COMMENT ON POLICY "${name}"`)); return `${generatedPolicies[index]};${generatedPolicies[index + 1]}`; };
      const hostilePredecessors = [
        ["wrong function", `SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner; ALTER FUNCTION app_auth.b01_bind_predecessor(text,text,text,text) STABLE`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner; ALTER FUNCTION app_auth.b01_bind_predecessor(text,text,text,text) VOLATILE`],
        ["unexpected policy", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; CREATE POLICY b01_bridge_conflict ON public."User" FOR SELECT TO mscqr_prd_rls_phase2_auth_owner USING (true)`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; DROP POLICY b01_bridge_conflict ON public."User"`],
        ["unexpected grant", `SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner; GRANT EXECUTE ON FUNCTION app_auth.b01_bind_predecessor(text,text,text,text) TO mscqr_prd_rls_phase2_preauth`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner; REVOKE EXECUTE ON FUNCTION app_auth.b01_bind_predecessor(text,text,text,text) FROM mscqr_prd_rls_phase2_preauth`],
        ["missing predecessor object", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; REVOKE SELECT (payload) ON public."AuditLogOutbox" FROM mscqr_prd_rls_phase2_auth_owner`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; GRANT SELECT (payload) ON public."AuditLogOutbox" TO mscqr_prd_rls_phase2_auth_owner`],
        ["extra conflicting object", `SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner; ${b01Delta.mutations.find(({ name }) => name === "finalizer").sql}`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner; DROP FUNCTION app_auth.finalize_refresh_token_rotation(text,text[],text,timestamp without time zone,text)`],
        ["B01 USING predicate drift", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; ALTER POLICY b01_refreshtoken_select ON public."RefreshToken" USING (true)`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; ALTER POLICY b01_refreshtoken_select ON public."RefreshToken" USING (${refreshSelectUsing})`],
        ["B01 WITH CHECK predicate drift", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; ALTER POLICY b01_refreshtoken_update ON public."RefreshToken" WITH CHECK (true)`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; ALTER POLICY b01_refreshtoken_update ON public."RefreshToken" USING (${refreshUpdateUsing}) WITH CHECK (${refreshUpdateCheck})`],
        ["B01 policy role drift", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; ALTER POLICY b01_refreshtoken_select ON public."RefreshToken" TO mscqr_prd_rls_phase2_preauth`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; ALTER POLICY b01_refreshtoken_select ON public."RefreshToken" TO mscqr_prd_rls_phase2_auth_owner`],
        ["B01 policy command drift", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; DROP POLICY b01_refreshtoken_select ON public."RefreshToken";
          CREATE POLICY b01_refreshtoken_select ON public."RefreshToken" AS PERMISSIVE FOR DELETE TO mscqr_prd_rls_phase2_auth_owner USING (${refreshSelectUsing})`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; DROP POLICY b01_refreshtoken_select ON public."RefreshToken";${restorePolicy("b01_refreshtoken_select")}`],
        ["B01 policy permissiveness drift", `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; DROP POLICY b01_refreshtoken_select ON public."RefreshToken";
          CREATE POLICY b01_refreshtoken_select ON public."RefreshToken" AS RESTRICTIVE FOR SELECT TO mscqr_prd_rls_phase2_auth_owner USING (${refreshSelectUsing})`,
          `SET LOCAL ROLE mscqr_prd_rls_phase2_owner; DROP POLICY b01_refreshtoken_select ON public."RefreshToken";${restorePolicy("b01_refreshtoken_select")}`],
      ];
      for (const [label, mutation, restore] of hostilePredecessors) {
        psql(greenUrl, ["-q", "-c", `BEGIN;${mutation};RESET ROLE;COMMIT;`], `install ${label}`);
        let checkpointReached = false;
        try {
          await assert.rejects(administratorClient.$transaction((tx) => executeB01Transaction({ tx, input: { contract: b01Input.contract },
            checkpoint: async () => { checkpointReached = true; } }), { maxWait: 10000, timeout: 120000 }), /neither the exact predecessor nor successor/);
          assert.equal(checkpointReached, false, `${label} reached a mutation checkpoint`);
        } finally {
          psql(greenUrl, ["-q", "-c", `BEGIN;${restore};RESET ROLE;COMMIT;`], `restore ${label}`);
        }
      }
      for (const failAfter of b01Input.contract.mutations.map(({ name }) => name)) {
        await assert.rejects(administratorClient.$transaction((tx) => executeB01Transaction({ tx, input: { contract: b01Input.contract },
          checkpoint: async (name) => { if (name === failAfter) throw new Error(`injected ${name}`); } }), { maxWait: 10000, timeout: 120000 }), new RegExp(`injected ${failAfter}`));
        const rolledBack = await administratorClient.$transaction((tx) => collectB01State(tx));
        assert.deepEqual(rolledBack.roles, b01Delta.predecessor.roles); assert.deepEqual(rolledBack.functions, b01Delta.predecessor.functions); assert.deepEqual(rolledBack.policies, b01Delta.predecessor.policies);
        assert.deepEqual(rolledBack.catalogue, b01Delta.predecessor.catalogue);
      }
      let b01CollectCount = 0;
      const b01Applied = await administratorClient.$transaction((tx) => executeB01Transaction({ tx, input: { contract: b01Input.contract }, collect: async (inner) => {
        const state = await collectB01State(inner);
        if (++b01CollectCount === 2) {
          assert.deepEqual(state.functions, b01Delta.successor.functions);
          assert.deepEqual(state.roles, b01Delta.successor.roles);
          assert.deepEqual(state.policies, b01Delta.successor.policies);
          assert.deepEqual(state.catalogue, b01Delta.successor.catalogue);
        }
        return state;
      } }), { maxWait: 10000, timeout: 120000 });
      assert.deepEqual(b01Applied, { status: "APPLIED", writeCount: 7, predecessorRlsIdentity: b01Delta.predecessorRlsIdentity,
        successorRlsIdentity: b01Delta.successorRlsIdentity, liveRlsIdentity: b01Delta.successorRlsIdentity });
      const readOnlySuccessor = await b01ReadOnlyRuntime.executeB01ReadOnlyTransaction({ client: administratorClient,
        input: { contract: b01Input.contract }, collect: collectB01State, inspect: b01Runtime.inspectB01State,
        lockSql: b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL });
      assert.equal(readOnlySuccessor.classification, "SUCCESSOR"); assert.equal(readOnlySuccessor.liveSuccessorMatch, true);
      const b01Converged = await administratorClient.$transaction((tx) => executeB01Transaction({ tx, input: { contract: b01Input.contract } }), { maxWait: 10000, timeout: 120000 });
      assert.equal(b01Converged.status, "ALREADY_CONVERGED"); assert.equal(b01Converged.writeCount, 0);
      psql(greenUrl, ["-q", "-c", `BEGIN;SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        ALTER POLICY b01_refreshtoken_select ON public."RefreshToken" USING (true);RESET ROLE;COMMIT;`], "install successor predicate drift");
      try {
        const readOnlyPartial = await b01ReadOnlyRuntime.executeB01ReadOnlyTransaction({ client: administratorClient,
          input: { contract: b01Input.contract }, collect: collectB01State, inspect: b01Runtime.inspectB01State,
          lockSql: b01Runtime.B01_MUTATION_ADVISORY_LOCK_SQL });
        assert.equal(readOnlyPartial.classification, "PARTIAL"); assert.equal(readOnlyPartial.unauthorizedCatalogueDelta, true);
        await assert.rejects(administratorClient.$transaction((tx) => executeB01Transaction({ tx, input: { contract: b01Input.contract } }),
          { maxWait: 10000, timeout: 120000 }), /neither the exact predecessor nor successor/);
      } finally {
        psql(greenUrl, ["-q", "-c", `BEGIN;SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
          ALTER POLICY b01_refreshtoken_select ON public."RefreshToken" USING (${refreshSelectUsing});RESET ROLE;COMMIT;`], "restore successor predicate drift");
      }
      const currentB01Functions = fs.readFileSync(path.join(root, "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql"), "utf8");
      psql(greenUrl, ["-q", "-c", `BEGIN;
        SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner;
        ${currentB01Functions}
        RESET ROLE;
        SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        ${b01PolicyFixtureSql(currentB01PolicySource, currentB01PolicySource)}
        RESET ROLE;
        COMMIT;`], "restore current generated B01 package after historical prerequisite proof");
      assert.equal(classifyProductionRlsCatalogue(hashProductionRlsCatalogue(await collectCatalogueRows(verifier)), requirements).classification,
        RLS_PROBE_CLASSIFICATIONS.MATCH);

      const predecessorSource = run("git", ["show", "6d5a48ce7c32b12ce8671731392f92ddfa625a88:backend/src/rls-waves/session-c/c02/printingLifecycle.sql"]);
      const predecessorSql = canonicalPrintingRoutineDelta().map(({ name }) => printingRoutine(predecessorSource, name)).join("\n");
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", "routine owner schema CREATE absent"), "f");
      assert.throws(() => psql(greenUrl, ["-q", "-c", `BEGIN;${predecessorSql}COMMIT;`], "direct administrator routine replacement"), /permission denied|must be owner/);
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", "failed direct replacement preserved privilege"), "f");
      assert.throws(() => psql(greenUrl, ["-q", "-c", `BEGIN;
        SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner;
        RESET ROLE;
        ${predecessorSql}
        COMMIT;`], "grant without routine-owner role switch"), /permission denied|must be owner/);
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", "failed no-switch replacement rolled back privilege"), "f");
      psql(greenUrl, ["-q", "-c", `BEGIN;
        SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner;
        RESET ROLE;
        SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner;
        ${predecessorSql}
        RESET ROLE;
        SET LOCAL ROLE mscqr_prd_rls_phase2_owner;
        REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner;
        RESET ROLE;
        COMMIT;`], "install exact printing-routine predecessor through minimum privilege bridge");
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", "predecessor privilege restored"), "f");
      const builtDelta = buildPrintingRoutineDeltaCommand({ sourceSha, requirements, databaseHostname: adminUrl.hostname });
      const deltaInput = printingDeltaRuntime.decodeInput(builtDelta.command[2], builtDelta.command[3]).input;
      const classifyLive = async () => classifyProductionRlsCatalogue(hashProductionRlsCatalogue(await collectAppOnlyDatabaseCatalogue(verifier)), requirements).classification;
      assert.equal(await classifyLive(), RLS_PROBE_CLASSIFICATIONS.EXPECTED);
      for (const failStage of ["after-grant", "after-owner-role", "after-routine-1", "after-routine-2", "after-routine-3",
        "before-revoke", "after-revoke", "after-successor-readback"]) {
        await assert.rejects(administratorClient.$transaction((tx) => printingDeltaRuntime.executePrintingRoutineDeltaTransaction({
          tx, input: deltaInput, checkpoint: async (stage) => { if (stage === failStage) throw new Error(`injected ${stage} failure`); },
        }), { maxWait: 10000, timeout: 120000 }), new RegExp(`injected ${failStage} failure`));
        assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", `${failStage} privilege rollback`), "f");
        assert.equal(await classifyLive(), RLS_PROBE_CLASSIFICATIONS.EXPECTED);
      }
      for (const failStage of ["TRANSACTION_SETUP", "DATABASE_IDENTITY_AUTHENTICATION", "PREDECESSOR_COLLECTION", "PREDECESSOR_AUTHENTICATION", "PRIVILEGE_GRANT",
        "ROUTINE_OWNER_SWITCH", "REPLACE_PRINTING_READINESS", "REPLACE_PRINTING_CREATE_JOB", "REPLACE_PRINTING_CONNECTOR_IDENTITY",
        "PRIVILEGE_RESTORATION", "SUCCESSOR_AUTHENTICATION", "COMMIT"]) {
        await assert.rejects(administratorClient.$transaction((tx) => printingDeltaRuntime.executePrintingRoutineDeltaTransaction({
          tx, input: deltaInput, setStage: (stage) => { if (stage === failStage) throw new Error(`injected ${stage} failure`); },
        }), { maxWait: 10000, timeout: 120000 }), new RegExp(`injected ${failStage} failure`));
        assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", `${failStage} privilege rollback`), "f");
        assert.equal(await classifyLive(), RLS_PROBE_CLASSIFICATIONS.EXPECTED);
      }
      const applied = await administratorClient.$transaction((tx) => printingDeltaRuntime.executePrintingRoutineDeltaTransaction({ tx, input: deltaInput }), { maxWait: 10000, timeout: 120000 });
      assert.deepEqual(applied, { status: "APPLIED", writeCount: 3 });
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", "successful privilege restoration"), "f");
      assert.equal(await classifyLive(), RLS_PROBE_CLASSIFICATIONS.MATCH);
      const converged = await administratorClient.$transaction((tx) => printingDeltaRuntime.executePrintingRoutineDeltaTransaction({ tx, input: deltaInput }), { maxWait: 10000, timeout: 120000 });
      assert.deepEqual(converged, { status: "ALREADY_CONVERGED", writeCount: 0 });
      assert.equal(scalar(greenUrl, "SELECT has_schema_privilege('mscqr_prd_rls_phase2_auth_owner','app_rls','CREATE')", "already-converged privilege unchanged"), "f");
    } finally { await Promise.all([maintenanceClient.$disconnect(), administratorClient.$disconnect(), verifier.$disconnect()]); }
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
