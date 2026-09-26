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
import { assertAppOnlyCandidateAncestor } from "../aws/produce-production-app-only-requirements.mjs";
import { createLiveSecurityRebaselineInventory, createSecurityRebaselineInventory, diffSecurityRebaselineInventories, SECURITY_REBASELINE_COVERAGE, SECURITY_REBASELINE_NORMALIZED_COLLECTIONS } from "../aws/production-security-rebaseline-inventory.mjs";
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
const liveTaskEvidence = (sourceSha, candidateSourceSha, digest, taskId = "9") => ({ taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${taskId.repeat(32)}`,
  taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/security-rebaseline:1", containerName: "security-rebaseline", containerExitCode: 0,
  probeRuntimeSourceSha: sourceSha, probeImageSourceSha: sourceSha, probeImageDigest: `sha256:${"a".repeat(64)}`,
  applicationImageSourceSha: candidateSourceSha, applicationImageDigest: `sha256:${"b".repeat(64)}`, requestSha256: digest, verificationContractSha256: digest });
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
const asProductionEquivalentCatalogue = (catalogue) => {
  const result = structuredClone(catalogue);
  result.securityRoles = result.securityRoles.filter(({ name }) => !["mscqr_p2_test","certification-administrator"].includes(name));
  result.roleMetadata = result.roleMetadata.filter(({ name }) => !["mscqr_p2_test","certification-administrator"].includes(name));
  for (const role of result.securityRoles) for (const membership of [...role.memberships, ...role.members])
    if (membership.grantor === "mscqr_p2_test") membership.grantor = "rdsadmin";
  for (const operator of result.operatorCapabilities) for (const membership of operator.memberships)
    if (membership.grantor === "mscqr_p2_test") membership.grantor = "rdsadmin";
  for (const extension of result.securityExtensions)
    if (extension.name === "plpgsql" && extension.owner === "mscqr_p2_test") extension.owner = "rdsadmin";
  for (const binding of result.securityBindings) if (binding.kind === "language" && binding.name === "plpgsql") {
    if (binding.owner === "mscqr_p2_test") binding.owner = "rdsadmin";
    for (const grant of binding.definition.grants) {
      if (grant.grantor === "mscqr_p2_test") grant.grantor = "rdsadmin";
      if (grant.role === "mscqr_p2_test") grant.role = "rdsadmin";
    }
  }
  return result;
};

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
  let appOnlyRequirements, securityRebaselineCanonical;
  let rdsMembershipsNormalized = false;
  const verifierRole = "mscqr_prod_rls_canary_read";
  let subscriptionObserverProvisionStarted = false;
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
    assert.equal(scalar(maintenanceUrl, `SELECT count(*) FROM pg_roles WHERE rolname=${JSON.stringify(administrator).replaceAll('"', "'")} OR rolname LIKE 'mscqr_prd_rls_phase2_%' OR rolname IN ('${verifierRole}','mscqr_prod_subscription_observer')`, "clean roles"), "0");
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
    subscriptionObserverProvisionStarted = true;
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
      psql(maintenanceUrl, ["-q", "-c", `ALTER ROLE "${administrator}" NOINHERIT; REVOKE pg_read_all_data FROM "${administrator}"`], "restore production administrator identity after privilege comparison");
      const [canaryCatalogue, administratorCatalogue] = await Promise.all([
        collectCatalogueRows(verifier), collectCatalogueRows(maintenanceClient),
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
      assertAppOnlyCandidateAncestor(context);
      const requirements = createAppOnlyRequirements({ ...context, catalogue,
        packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
      securityRebaselineCanonical = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha: context.candidateSourceSha,
        catalogue, repositoryRoot: root, packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
      assert.equal(securityRebaselineCanonical.protectedMainSha, sourceSha);
      assert.equal(securityRebaselineCanonical.candidateSourceSha, context.candidateSourceSha);
      assert.equal(securityRebaselineCanonical.appOnlyRequirementsSha256, requirements.requirementsSha256);
      const canonicalMemberships = securityRebaselineCanonical.objects.filter(({ collection }) => ["roleMemberships","roleMembers","operatorMemberships"].includes(collection));
      assert.ok(canonicalMemberships.length > 0 && canonicalMemberships.every(({ identity }) => !identity.includes("mscqr_p2_test")));
      assert.ok(canonicalMemberships.some(({ identity }) => identity.includes("rdsadmin")), "canonical PG18 harness grantors map to the production semantic identity");
      const productionEquivalentCatalogue = asProductionEquivalentCatalogue(catalogue);
      const productionEquivalentLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: productionEquivalentCatalogue,
        canonical: securityRebaselineCanonical, taskEvidence: liveTaskEvidence(sourceSha, context.candidateSourceSha, "8".repeat(64)) });
      const productionEquivalentDiff = diffSecurityRebaselineInventories(productionEquivalentLive, securityRebaselineCanonical);
      assert.equal(productionEquivalentDiff.differenceCount, 0,
        `production-equivalent membership grantors do not create canonical harness drift: ${JSON.stringify(productionEquivalentDiff.differences.map(({collection,identity,field})=>({collection,identity,field})))}`);
      assert.equal(productionEquivalentDiff.safeToConstructConvergencePlan, true, "canonical managed-role membership topology is nonblocking");
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        const assertManagedMembershipBlocks = async (label) => {
          const observed = asProductionEquivalentCatalogue(await collectAppOnlyDatabaseCatalogueRows(tx));
          const inventory = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: observed,
            canonical: securityRebaselineCanonical, taskEvidence: productionEquivalentLive.taskEvidence });
          const diff = diffSecurityRebaselineInventories(inventory, securityRebaselineCanonical);
          assert.equal(diff.safeToConstructConvergencePlan, false, `${label} must block plan construction`);
          assert.ok(diff.differences.some(({ collection }) => ["roleMemberships","roleMembers"].includes(collection)),
            `${label} must be represented in the ordinary membership topology`);
        };
        const app = '"mscqr_prd_rls_phase2_app"', admin = '"mscqr_prod_admin"';
        for (const privilegedRole of ["pg_read_all_data","pg_write_all_data"]) {
          assert.equal(catalogue.securityRoles.find(({ name }) => name === "mscqr_prd_rls_phase2_app").memberships
            .some(({ role }) => role === privilegedRole), false, `canonical app role must not already belong to ${privilegedRole}`);
          await tx.$executeRawUnsafe(`GRANT ${privilegedRole} TO ${app} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`);
          await assertManagedMembershipBlocks(`managed application membership in ${privilegedRole}`);
          await tx.$executeRawUnsafe(`REVOKE ${privilegedRole} FROM ${app}`);
        }
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_managed_intermediate NOLOGIN");
        await tx.$executeRawUnsafe("GRANT pg_write_all_data TO rebaseline_managed_intermediate WITH ADMIN FALSE, INHERIT TRUE, SET TRUE");
        await tx.$executeRawUnsafe(`GRANT rebaseline_managed_intermediate TO ${app} WITH ADMIN FALSE, INHERIT TRUE, SET TRUE`);
        await assertManagedMembershipBlocks("managed role membership in an intermediate privileged role");
        await tx.$executeRawUnsafe(`REVOKE rebaseline_managed_intermediate FROM ${app}`);
        await tx.$executeRawUnsafe("DROP ROLE rebaseline_managed_intermediate");

        await tx.$executeRawUnsafe(`REVOKE "mscqr_prd_rls_phase2_app" FROM ${admin}`);
        await assertManagedMembershipBlocks("removal of a canonical managed membership");
        await tx.$executeRawUnsafe(`GRANT "mscqr_prd_rls_phase2_app" TO ${admin} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`);
        for (const options of [
          { admin: "TRUE", inherit: "FALSE", set: "TRUE" },
          { admin: "FALSE", inherit: "TRUE", set: "TRUE" },
          { admin: "FALSE", inherit: "FALSE", set: "FALSE" },
        ]) {
          await tx.$executeRawUnsafe(`GRANT "mscqr_prd_rls_phase2_app" TO ${admin} WITH ADMIN ${options.admin}, INHERIT ${options.inherit}, SET ${options.set}`);
          await assertManagedMembershipBlocks(`canonical membership option change ${JSON.stringify(options)}`);
          await tx.$executeRawUnsafe(`GRANT "mscqr_prd_rls_phase2_app" TO ${admin} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`);
        }
        throw new Error("rollback managed role membership drift fixtures");
      }, { maxWait: 5000, timeout: 30000 }), /rollback managed role membership drift fixtures/);
      const operatorCoverage = SECURITY_REBASELINE_COVERAGE.find(({ surface }) => surface === "operator capabilities");
      assert.equal(operatorCoverage.rawCollection, "operatorCapabilities");
      for (const collection of ["operatorInheritedCapabilities","operatorSetRoles","operatorSetRoleCapabilities","operatorAdminCapabilities"])
        assert.ok(operatorCoverage.normalizedCollections.split("/").includes(collection) && SECURITY_REBASELINE_NORMALIZED_COLLECTIONS.includes(collection));
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        const admin = '"mscqr_prod_admin"';
        const operator = async () => (await collectAppOnlyDatabaseCatalogueRows(tx)).operatorCapabilities[0];
        const grant = async (role, member, options) => tx.$executeRawUnsafe(`GRANT "${role}" TO "${member}" WITH ADMIN FALSE, INHERIT ${options.inherit ? "TRUE" : "FALSE"}, SET ${options.set ? "TRUE" : "FALSE"}`);
        await tx.$executeRawUnsafe("ALTER ROLE mscqr_prod_admin INHERIT");
        const beforeSetOnlyGrant = await operator();
        assert.ok(beforeSetOnlyGrant.set_role_closure.includes("mscqr_prd_rls_phase2_app"), "canonical operator can SET ROLE to its managed application role");
        assert.equal(beforeSetOnlyGrant.set_role_capability_closure.includes("pg_write_all_data"), false);
        await tx.$executeRawUnsafe("GRANT pg_write_all_data TO mscqr_prd_rls_phase2_app WITH ADMIN FALSE, INHERIT FALSE, SET TRUE");
        const afterSetOnlyGrant = await operator();
        assert.deepEqual(afterSetOnlyGrant.memberships, beforeSetOnlyGrant.memberships, "no direct operator membership changed");
        for (const field of ["login","superuser","inherit","create_role","create_database","replication","bypass_rls","database_connect","database_create","database_temporary"])
          assert.equal(afterSetOnlyGrant[field], beforeSetOnlyGrant[field], `operatorCapabilities.${field} is unchanged`);
        assert.ok(afterSetOnlyGrant.set_role_capability_closure.includes("pg_write_all_data"));
        const setOnlyCatalogue = await collectAppOnlyDatabaseCatalogueRows(tx);
        const setOnlyLiveCatalogue = structuredClone(setOnlyCatalogue);
        for (const membership of setOnlyLiveCatalogue.operatorCapabilities[0].memberships)
          if (membership.grantor === "mscqr_p2_test") membership.grantor = "rdsadmin";
        const setOnlyLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: setOnlyLiveCatalogue,
          canonical: securityRebaselineCanonical, taskEvidence: productionEquivalentLive.taskEvidence });
        const setOnlyDiff = diffSecurityRebaselineInventories(setOnlyLive, securityRebaselineCanonical);
        assert.equal(setOnlyDiff.safeToConstructConvergencePlan, false);
        assert.ok(setOnlyDiff.differences.some(({ collection, identity }) => collection === "operatorSetRoleCapabilities" && identity.includes("pg_write_all_data")));
        assert.equal(setOnlyDiff.differences.some(({ collection }) => collection === "operatorMemberships"), false,
          "the blocker catches the new transitive SET capability even though the direct operator membership inventory is unchanged");
        await tx.$executeRawUnsafe("REVOKE pg_write_all_data FROM mscqr_prd_rls_phase2_app");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_ii NOLOGIN INHERIT");
        await grant("pg_write_all_data", "rebaseline_cap_ii", { inherit:true,set:false });
        await grant("rebaseline_cap_ii", "mscqr_prod_admin", { inherit:true,set:false });
        let capabilities = await operator();
        assert.ok(capabilities.membership_closure.includes("pg_write_all_data"), "INHERIT TRUE across both edges is immediately available");
        await tx.$executeRawUnsafe(`REVOKE "rebaseline_cap_ii" FROM ${admin}`);
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_ss_a NOLOGIN NOINHERIT");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_ss_b NOLOGIN NOINHERIT");
        await grant("pg_read_all_data", "rebaseline_cap_ss_b", { inherit:false,set:true });
        await grant("rebaseline_cap_ss_b", "rebaseline_cap_ss_a", { inherit:false,set:true });
        await grant("rebaseline_cap_ss_a", "mscqr_prod_admin", { inherit:false,set:true });
        capabilities = await operator();
        assert.ok(capabilities.set_role_closure.includes("pg_read_all_data"), "SET TRUE transitive path reaches the terminal role");
        assert.equal(capabilities.membership_closure.includes("pg_read_all_data"), false, "SET reachability is not reported as automatic inheritance");
        await tx.$executeRawUnsafe("GRANT pg_read_all_data TO rebaseline_cap_ss_b WITH ADMIN FALSE, INHERIT FALSE, SET FALSE");
        capabilities = await operator();
        assert.equal(capabilities.set_role_closure.includes("pg_read_all_data"), false, "revoking SET removes SET-only reachability");
        assert.equal(capabilities.set_role_capability_closure.includes("pg_read_all_data"), false);
        await tx.$executeRawUnsafe(`REVOKE "rebaseline_cap_ss_a" FROM ${admin}`);
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_is_a NOLOGIN INHERIT");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_is_b NOLOGIN NOINHERIT");
        await grant("rebaseline_cap_is_b", "rebaseline_cap_is_a", { inherit:false,set:true });
        await grant("rebaseline_cap_is_a", "mscqr_prod_admin", { inherit:true,set:false });
        capabilities = await operator();
        assert.ok(capabilities.membership_closure.includes("rebaseline_cap_is_a"));
        assert.equal(capabilities.membership_closure.includes("rebaseline_cap_is_b"), false, "INHERIT then SET does not cross the non-inheriting edge");
        assert.equal(capabilities.set_role_closure.includes("rebaseline_cap_is_b"), false, "SET must be true on every edge");
        await tx.$executeRawUnsafe(`REVOKE "rebaseline_cap_is_a" FROM ${admin}`);
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_si NOLOGIN INHERIT");
        await grant("pg_write_all_data", "rebaseline_cap_si", { inherit:true,set:false });
        await grant("rebaseline_cap_si", "mscqr_prod_admin", { inherit:false,set:true });
        capabilities = await operator();
        assert.equal(capabilities.membership_closure.includes("pg_write_all_data"), false, "SET then INHERIT is not immediate operator inheritance");
        assert.equal(capabilities.set_role_closure.includes("pg_write_all_data"), false, "the terminal membership does not permit SET directly");
        assert.ok(capabilities.set_role_capability_closure.includes("pg_write_all_data"), "after SET to the intermediate, its automatic INHERIT grants the capability");
        const hostileCatalogue = await collectAppOnlyDatabaseCatalogueRows(tx);
        const hostileInventory = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: hostileCatalogue,
          canonical: securityRebaselineCanonical, taskEvidence: productionEquivalentLive.taskEvidence });
        const hostileDiff = diffSecurityRebaselineInventories(hostileInventory, securityRebaselineCanonical);
        assert.equal(hostileDiff.safeToConstructConvergencePlan, false);
        assert.ok(hostileDiff.differences.some(({ collection, identity }) => collection === "operatorSetRoleCapabilities" && identity.includes("pg_write_all_data")),
          "the actual SET->INHERIT privileged path blocks through the normalized inventory and diff");
        await tx.$executeRawUnsafe(`REVOKE "rebaseline_cap_si" FROM ${admin}`);
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_none_a NOLOGIN NOINHERIT");
        await grant("pg_monitor", "rebaseline_cap_none_a", { inherit:false,set:false });
        await grant("rebaseline_cap_none_a", "mscqr_prod_admin", { inherit:false,set:false });
        capabilities = await operator();
        for (const field of ["membership_closure","set_role_closure","set_role_capability_closure"])
          assert.equal(capabilities[field].includes("pg_monitor"), false, `neither option grants reachability in ${field}`);
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_cap_admin_target NOLOGIN");
        await tx.$executeRawUnsafe(`GRANT rebaseline_cap_admin_target TO ${admin} WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`);
        capabilities = await operator();
        assert.ok(capabilities.admin_option_closure.includes("rebaseline_cap_admin_target"), "ADMIN OPTION administrative reachability is separately observed");
        throw new Error("rollback operator capability topology");
      }, { maxWait: 5000, timeout: 30000 }), /rollback operator capability topology/);
      const databaseBeforeTemplateChange = await collectAppOnlyDatabaseCatalogue(verifier);
      assert.equal(databaseBeforeTemplateChange.databases.find(({ database }) => database === targetDatabase)?.is_template, false);
      psql(maintenanceUrl, ["-q", "-c", `ALTER DATABASE "${targetDatabase}" IS_TEMPLATE TRUE`], "enable template state on disposable test database");
      try {
        const templateCatalogue = await collectAppOnlyDatabaseCatalogue(verifier);
        assert.equal(templateCatalogue.databases.find(({ database }) => database === targetDatabase)?.is_template, true);
        const templateLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: templateCatalogue,
          canonical: securityRebaselineCanonical, taskEvidence: productionEquivalentLive.taskEvidence });
        const templateDiff = diffSecurityRebaselineInventories(templateLive, securityRebaselineCanonical);
        assert.equal(templateDiff.safeToConstructConvergencePlan, false);
        assert.ok(templateDiff.differences.some(({ collection, field }) => collection === "databases" && field === "is_template"),
          "real pg_database.datistemplate drift blocks security-plan construction");
      } finally {
        psql(maintenanceUrl, ["-q", "-c", `ALTER DATABASE "${targetDatabase}" IS_TEMPLATE FALSE`], "restore disposable database template state");
      }
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        const [created] = await tx.$queryRawUnsafe("SELECT pg_catalog.lo_create(0)::text AS oid");
        await tx.$executeRawUnsafe(`ALTER LARGE OBJECT ${created.oid} OWNER TO mscqr_prd_rls_phase2_app`);
        await tx.$executeRawUnsafe(`GRANT SELECT ON LARGE OBJECT ${created.oid} TO mscqr_prod_rls_canary_read`);
        const liveCatalogue = await collectAppOnlyDatabaseCatalogueRows(tx);
        const liveInventory = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: liveCatalogue,
          canonical: securityRebaselineCanonical, taskEvidence: productionEquivalentLive.taskEvidence });
        const liveDiff = diffSecurityRebaselineInventories(liveInventory, securityRebaselineCanonical);
        assert.equal(liveDiff.safeToConstructConvergencePlan, false, "large-object access absent from the canonical target blocks planning");
        assert.ok(liveDiff.differences.some(({ collection, identity }) => collection === "bindings" && identity.startsWith("large_objects:")),
          "real PG18 LO metadata survives collection, normalization and diffing");
        throw new Error("rollback live large-object inventory fixture");
      }), /rollback live large-object inventory fixture/);
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        const parent = "mscqr_prd_rls_phase2_app";
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_unexpected_canonical_grantor NOLOGIN");
        await tx.$executeRawUnsafe(`GRANT "${parent}" TO rebaseline_unexpected_canonical_grantor WITH ADMIN OPTION`);
        await tx.$executeRawUnsafe(`REVOKE "${parent}" FROM "${administrator}" GRANTED BY CURRENT_USER CASCADE`);
        await tx.$executeRawUnsafe("SET ROLE rebaseline_unexpected_canonical_grantor");
        await tx.$executeRawUnsafe(`GRANT "${parent}" TO "${administrator}" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`);
        await tx.$executeRawUnsafe("RESET ROLE");
        const unsupportedGrantorCatalogue = await collectAppOnlyDatabaseCatalogueRows(tx);
        assert.throws(() => createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha: context.candidateSourceSha,
          catalogue: unsupportedGrantorCatalogue, repositoryRoot: root,
          packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) }), /unsupported grantor/);
        throw new Error("rollback unexpected canonical grantor fixture");
      }), /rollback unexpected canonical grantor fixture/);
      const collectedSecurityDomains = new Set(securityRebaselineCanonical.objects.map(({ collection }) => collection));
      for (const collection of ["extensions","bindings","routines","routineGrants","tables","tableGrants","columnGrants","constraintTriggers","policies","schemas","schemaGrants","roles","roleMetadata",
        "roleMembers","databases","databaseGrants","defaultPrivileges","types","typeGrants","operatorCapabilities",
        "operatorMemberships","operatorInheritedCapabilities","operatorSetRoles","operatorSetRoleCapabilities"]) assert.ok(collectedSecurityDomains.has(collection), `Real collector omitted ${collection}`);
      assert.ok(catalogue.roles.every(({ memberships, members }) => Array.isArray(memberships) && Array.isArray(members)));
      for (const collection of ["securityExtensions","securityBindings","securityRoutines","securityTables","securityTriggers","securityConstraintTriggers","securityRules","securityEventTriggers","securityPolicies","securitySchemas","roleMetadata","databases","defaults","parameterPrivileges","types","sequences","operatorCapabilities"]) assert.ok(Array.isArray(catalogue[collection]), `Real collector omitted ${collection}`);
      assert.ok(catalogue.securityExtensions.some(({ name, version, schema, relocatable }) => name === "plpgsql" && typeof version === "string" && schema === "pg_catalog" && typeof relocatable === "boolean"));
      assert.ok(catalogue.securityTables.every(({ kind }) => ["r","p","v","m","f"].includes(kind)));
      assert.ok(catalogue.securityRoutines.every(({ schema }) => schema !== "information_schema" && !schema.startsWith("pg_")));
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("CREATE VIEW public.rebaseline_view_contract AS SELECT 1::integer AS id");
        await tx.$executeRawUnsafe("CREATE MATERIALIZED VIEW public.rebaseline_matview_contract AS SELECT 1::integer AS id");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_trigger_contract(id integer)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_partition_contract(id integer) PARTITION BY RANGE (id)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_partition_contract_low PARTITION OF public.rebaseline_partition_contract FOR VALUES FROM (0) TO (10)");
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_partition_contract ADD CONSTRAINT rebaseline_partition_check CHECK (id > 0)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_inherit_parent_a(id integer)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_inherit_parent_b(id integer)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_inherit_child(extra integer) INHERITS (public.rebaseline_inherit_parent_a)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_replica_contract(id integer NOT NULL, alternate integer NOT NULL)");
        await tx.$executeRawUnsafe("CREATE UNIQUE INDEX rebaseline_replica_a ON public.rebaseline_replica_contract(id)");
        await tx.$executeRawUnsafe("CREATE UNIQUE INDEX rebaseline_replica_b ON public.rebaseline_replica_contract(alternate)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_index_contract(id integer)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_persistence_contract(id integer)");
        await tx.$executeRawUnsafe("CREATE TYPE public.rebaseline_typed_row AS (id integer)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_typed_table OF public.rebaseline_typed_row");
        await tx.$executeRawUnsafe("CREATE TYPE public.rebaseline_composite_contract AS (id integer)");
        await tx.$executeRawUnsafe("CREATE TYPE public.rebaseline_range_contract AS RANGE (subtype=integer)");
        await tx.$executeRawUnsafe("CREATE UNLOGGED SEQUENCE public.rebaseline_sequence_persistence_contract");
        await tx.$executeRawUnsafe("CREATE FUNCTION public.rebaseline_trigger_one() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'");
        await tx.$executeRawUnsafe("CREATE FUNCTION public.rebaseline_trigger_two() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'");
        await tx.$executeRawUnsafe("CREATE FUNCTION public.rebaseline_event_guard() RETURNS event_trigger LANGUAGE plpgsql AS 'BEGIN RETURN; END'");
        await tx.$executeRawUnsafe("CREATE EVENT TRIGGER rebaseline_event_guard ON ddl_command_start EXECUTE FUNCTION public.rebaseline_event_guard()");
        await tx.$executeRawUnsafe("CREATE TRIGGER rebaseline_contract_trigger BEFORE INSERT ON public.rebaseline_trigger_contract FOR EACH ROW EXECUTE FUNCTION public.rebaseline_trigger_one()");
        await tx.$executeRawUnsafe("CREATE RULE rebaseline_expected_rule AS ON UPDATE TO public.rebaseline_trigger_contract DO INSTEAD NOTHING");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_internal_parent(id integer PRIMARY KEY)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_internal_child(parent_id integer REFERENCES public.rebaseline_internal_parent(id))");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_publication_a(id integer, tenant integer)");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_publication_b(id integer)");
        await tx.$executeRawUnsafe("CREATE PUBLICATION rebaseline_publication_contract FOR TABLE public.rebaseline_publication_a (id, tenant) WHERE (tenant > 0)");
        const fixtureCatalogue = await collectAppOnlyDatabaseCatalogueRows(tx);
        const fixtureCanonical = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha: context.candidateSourceSha,
          catalogue: fixtureCatalogue, repositoryRoot: root, packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
        const evidence = liveTaskEvidence(sourceSha, context.candidateSourceSha, "e".repeat(64), "d");
        const compare = async () => {
          const collected = await collectAppOnlyDatabaseCatalogueRows(tx);
          const simulatedProduction = structuredClone(collected);
          for (const binding of simulatedProduction.securityBindings) if (binding.kind === "language" && binding.name === "plpgsql") {
            if (binding.owner === "mscqr_p2_test") binding.owner = "rdsadmin";
            for (const grant of binding.definition.grants) {
              if (grant.role === "mscqr_p2_test") grant.role = "rdsadmin";
              if (grant.grantor === "mscqr_p2_test") grant.grantor = "rdsadmin";
            }
          }
          const liveInventory = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: simulatedProduction, canonical: fixtureCanonical, taskEvidence: evidence });
          return { collected, diff: diffSecurityRebaselineInventories(liveInventory, fixtureCanonical) };
        };
        let result = await compare();
        assert.equal(result.diff.differences.filter(({ collection }) => ["tables","triggers","constraintTriggers","rules","eventTriggers","bindings"].includes(collection)).length, 0,
          "identical real relation/view/trigger/rule/event-trigger catalogues have no drift");
        const partitionChild = result.collected.securityTables.find(({ name }) => name === "rebaseline_partition_contract_low");
        assert.equal(partitionChild.constraints.find(({ name }) => name === "rebaseline_partition_check").parent_identity,
          "public.rebaseline_partition_contract.rebaseline_partition_check", "partition constraint parent identity is stable, not a backend-local OID");
        assert.deepEqual(partitionChild.parents, [{ schema:"public",name:"rebaseline_partition_contract",partition:true,detach_pending:false }],
          "partition hierarchy uses stable relation identity");
        const inherited = () => result.collected.securityTables.find(({ name }) => name === "rebaseline_inherit_child").parents;
        assert.deepEqual(inherited(), [{ schema:"public",name:"rebaseline_inherit_parent_a",partition:false,detach_pending:false }]);
        assert.ok(result.collected.securityRules.some(({ name, definition }) => name === "rebaseline_expected_rule" && definition.includes("DO INSTEAD NOTHING")));
        assert.ok(result.collected.securityEventTriggers.some(({ name, event, function: routine }) => name === "rebaseline_event_guard" && event === "ddl_command_start" && routine.endsWith("rebaseline_event_guard()")));
        const publicationBinding = result.collected.securityBindings.find(({ kind, name }) => kind === "publication_relation" && name === "rebaseline_publication_contract:public.rebaseline_publication_a");
        assert.deepEqual(publicationBinding.definition.columns, ["id","tenant"]);
        assert.match(publicationBinding.definition.row_filter, /tenant > 0/);
        const databaseState = result.collected.databases[0];
        assert.equal(databaseState.allow_connections, true);
        assert.equal(databaseState.connection_limit, -1);
        await tx.$executeRawUnsafe(`ALTER DATABASE "${targetDatabase}" CONNECTION LIMIT 7`);
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, field }) => collection === "databases" && field === "connection_limit"));
        await tx.$executeRawUnsafe(`ALTER DATABASE "${targetDatabase}" CONNECTION LIMIT -1`);
        const baselineView = result.collected.securityTables.find(({ name }) => name === "rebaseline_view_contract").view_definition;
        await tx.$executeRawUnsafe("CREATE OR REPLACE VIEW public.rebaseline_view_contract AS SELECT 1 :: integer AS id");
        result = await compare();
        assert.equal(result.collected.securityTables.find(({ name }) => name === "rebaseline_view_contract").view_definition, baselineView,
          "PostgreSQL canonicalizes formatting-only view SQL");
        assert.equal(result.diff.differences.filter(({ collection }) => ["tables","triggers"].includes(collection)).length, 0);
        await tx.$executeRawUnsafe("ALTER VIEW public.rebaseline_view_contract SET (security_barrier=true)");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_view_contract" && field === "view_security_options"));
        await tx.$executeRawUnsafe("ALTER VIEW public.rebaseline_view_contract RESET (security_barrier)");
        result = await compare();
        assert.equal(result.diff.differences.filter(({ collection }) => ["tables","triggers"].includes(collection)).length, 0);
        for (const sql of [
          "CREATE OR REPLACE VIEW public.rebaseline_view_contract AS SELECT 2::integer AS id",
          "CREATE OR REPLACE VIEW public.rebaseline_view_contract AS SELECT 1::integer AS id WHERE 1=1",
          "CREATE OR REPLACE VIEW public.rebaseline_view_contract AS SELECT c.oid::integer AS id FROM pg_catalog.pg_class AS c",
          "CREATE OR REPLACE VIEW public.rebaseline_view_contract AS SELECT d.oid::integer AS id FROM pg_catalog.pg_database AS d",
        ]) {
          await tx.$executeRawUnsafe(sql);
          result = await compare();
          assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "tables"
            && identity === "public.rebaseline_view_contract" && field === "view_definition"), "real view definition change reaches diff");
        }
        await tx.$executeRawUnsafe("DROP MATERIALIZED VIEW public.rebaseline_matview_contract");
        await tx.$executeRawUnsafe("CREATE MATERIALIZED VIEW public.rebaseline_matview_contract AS SELECT 2::integer AS id");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_matview_contract" && field === "view_definition"));
        await tx.$executeRawUnsafe("DROP TABLE public.rebaseline_partition_contract_low");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_partition_contract_low PARTITION OF public.rebaseline_partition_contract FOR VALUES FROM (0) TO (20)");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_partition_contract_low" && field === "partition_bound"));
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_inherit_child NO INHERIT public.rebaseline_inherit_parent_a");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_inherit_child" && field === "parents"));
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_inherit_child INHERIT public.rebaseline_inherit_parent_a");
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_inherit_child INHERIT public.rebaseline_inherit_parent_b");
        result = await compare();
        assert.deepEqual(inherited(), [
          { schema:"public",name:"rebaseline_inherit_parent_a",partition:false,detach_pending:false },
          { schema:"public",name:"rebaseline_inherit_parent_b",partition:false,detach_pending:false },
        ], "multiple inheritance follows stable PostgreSQL parent order without OIDs");
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_inherit_child" && field === "parents"));
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_inherit_child NO INHERIT public.rebaseline_inherit_parent_b");
        for (const [sql, mode, index] of [
          ["ALTER TABLE public.rebaseline_replica_contract REPLICA IDENTITY FULL","FULL",null],
          ["ALTER TABLE public.rebaseline_replica_contract REPLICA IDENTITY NOTHING","NOTHING",null],
          ["ALTER TABLE public.rebaseline_replica_contract REPLICA IDENTITY USING INDEX rebaseline_replica_a","USING_INDEX","public.rebaseline_replica_a"],
          ["ALTER TABLE public.rebaseline_replica_contract REPLICA IDENTITY USING INDEX rebaseline_replica_b","USING_INDEX","public.rebaseline_replica_b"],
        ]) {
          await tx.$executeRawUnsafe(sql); result = await compare();
          assert.deepEqual(result.collected.securityTables.find(({ name }) => name === "rebaseline_replica_contract").replica_identity, { mode,index });
          assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_replica_contract" && field === "replica_identity"));
        }
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_replica_contract REPLICA IDENTITY DEFAULT");
        await tx.$executeRawUnsafe("CREATE UNIQUE INDEX rebaseline_index_contract_unique ON public.rebaseline_index_contract(id)");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_index_contract" && field === "behavior_indexes"),
          "a standalone unique index that changes accepted writes reaches the security diff");
        await tx.$executeRawUnsafe("DROP INDEX public.rebaseline_index_contract_unique");
        await tx.$executeRawUnsafe("CREATE INDEX rebaseline_index_contract_partial ON public.rebaseline_index_contract(id) WHERE id > 0");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_index_contract" && field === "behavior_indexes"),
          "a nonunique partial index whose predicate executes during writes reaches the security diff");
        await tx.$executeRawUnsafe("DROP INDEX public.rebaseline_index_contract_partial");
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_persistence_contract SET UNLOGGED");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_persistence_contract" && field === "persistence"));
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_persistence_contract SET LOGGED");
        await tx.$executeRawUnsafe("ALTER SEQUENCE public.rebaseline_sequence_persistence_contract SET LOGGED");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "sequences"
          && identity === "public.rebaseline_sequence_persistence_contract" && field === "persistence"));
        await tx.$executeRawUnsafe("REFRESH MATERIALIZED VIEW public.rebaseline_matview_contract WITH NO DATA");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_matview_contract" && field === "populated"));
        await tx.$executeRawUnsafe("REFRESH MATERIALIZED VIEW public.rebaseline_matview_contract");
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_typed_table NOT OF");
        result = await compare();
        assert.ok(result.diff.differences.some(({ identity, field }) => identity === "public.rebaseline_typed_table" && field === "of_type"));
        await tx.$executeRawUnsafe("ALTER TYPE public.rebaseline_composite_contract ALTER ATTRIBUTE id TYPE bigint");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "types"
          && identity === "public.rebaseline_composite_contract" && field === "composite_attributes"));
        await tx.$executeRawUnsafe("DROP TYPE public.rebaseline_range_contract");
        await tx.$executeRawUnsafe("CREATE TYPE public.rebaseline_range_contract AS RANGE (subtype=bigint)");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "types"
          && identity === "public.rebaseline_range_contract" && field === "range_definition"));
        await tx.$executeRawUnsafe("CREATE TRIGGER rebaseline_unexpected_trigger AFTER INSERT ON public.rebaseline_trigger_contract FOR EACH ROW EXECUTE FUNCTION public.rebaseline_trigger_one()");
        result = await compare();
        assert.equal(result.diff.safeToConstructConvergencePlan, false, "unexpected user trigger blocks plan construction");
        assert.ok(result.diff.differences.some(({ collection, identity }) => collection === "triggers" && identity.endsWith(".rebaseline_unexpected_trigger")));
        await tx.$executeRawUnsafe("DROP TRIGGER rebaseline_contract_trigger ON public.rebaseline_trigger_contract");
        await tx.$executeRawUnsafe("CREATE TRIGGER rebaseline_contract_trigger BEFORE INSERT ON public.rebaseline_trigger_contract FOR EACH ROW EXECUTE FUNCTION public.rebaseline_trigger_two()");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "triggers" && identity.endsWith(".rebaseline_contract_trigger") && field === "function"));
        await tx.$executeRawUnsafe("DROP TRIGGER rebaseline_contract_trigger ON public.rebaseline_trigger_contract");
        await tx.$executeRawUnsafe("CREATE TRIGGER rebaseline_contract_trigger AFTER INSERT ON public.rebaseline_trigger_contract FOR EACH ROW EXECUTE FUNCTION public.rebaseline_trigger_two()");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "triggers" && identity.endsWith(".rebaseline_contract_trigger") && field === "definition"));
        await tx.$executeRawUnsafe("DROP TRIGGER rebaseline_contract_trigger ON public.rebaseline_trigger_contract");
        await tx.$executeRawUnsafe("CREATE TRIGGER rebaseline_contract_trigger BEFORE INSERT ON public.rebaseline_trigger_contract FOR EACH ROW EXECUTE FUNCTION public.rebaseline_trigger_one()");
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_trigger_contract DISABLE TRIGGER rebaseline_contract_trigger");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "triggers" && identity.endsWith(".rebaseline_contract_trigger") && field === "enabled"));
        assert.ok(result.collected.securityConstraintTriggers.some(({ constraint_name, enabled }) => constraint_name === "rebaseline_internal_child_parent_id_fkey" && enabled === "O"));
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_internal_child DISABLE TRIGGER ALL");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "constraintTriggers" && identity.includes("rebaseline_internal_child_parent_id_fkey") && field === "enabled"), "disabled internal FK enforcement reaches the diff");
        await tx.$executeRawUnsafe("ALTER TABLE public.rebaseline_internal_child ENABLE TRIGGER ALL");
        result = await compare();
        assert.equal(result.diff.differences.filter(({ collection }) => collection === "constraintTriggers").length, 0);
        await tx.$executeRawUnsafe("ALTER PUBLICATION rebaseline_publication_contract SET TABLE public.rebaseline_publication_a (id) WHERE (tenant > 1), public.rebaseline_publication_b");
        result = await compare();
        assert.ok(result.diff.differences.some(({ collection, identity }) => collection === "bindings" && identity === "publication_relation:rebaseline_publication_contract:public.rebaseline_publication_a"));
        assert.ok(result.diff.differences.some(({ collection, identity }) => collection === "bindings" && identity === "publication_relation:rebaseline_publication_contract:public.rebaseline_publication_b"));
        await tx.$executeRawUnsafe("ALTER PUBLICATION rebaseline_publication_contract SET TABLE public.rebaseline_publication_a (id, tenant) WHERE (tenant > 0)");
        result = await compare();
        assert.equal(result.diff.differences.filter(({ collection }) => collection === "bindings").length, 0);
        await tx.$executeRawUnsafe("CREATE OR REPLACE RULE rebaseline_expected_rule AS ON UPDATE TO public.rebaseline_trigger_contract DO ALSO NOTHING");
        result = await compare();
        assert.equal(result.diff.safeToConstructConvergencePlan, false, "rewrite-rule drift blocks plan construction");
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "rules" && identity.endsWith(".rebaseline_expected_rule") && field === "definition"));
        await tx.$executeRawUnsafe("ALTER EVENT TRIGGER rebaseline_event_guard DISABLE");
        result = await compare();
        assert.equal(result.diff.safeToConstructConvergencePlan, false, "event-trigger enablement drift blocks plan construction");
        assert.ok(result.diff.differences.some(({ collection, identity, field }) => collection === "eventTriggers" && identity === "rebaseline_event_guard" && field === "enabled"));
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_acl_grantor_subject(id integer)");
        await tx.$executeRawUnsafe('GRANT USAGE ON SCHEMA public TO "mscqr_prod_admin", pg_database_owner');
        await tx.$executeRawUnsafe('GRANT SELECT ON public.rebaseline_acl_grantor_subject TO "mscqr_prod_admin" WITH GRANT OPTION');
        await tx.$executeRawUnsafe("GRANT SELECT ON public.rebaseline_acl_grantor_subject TO pg_database_owner WITH GRANT OPTION");
        await tx.$executeRawUnsafe('GRANT SELECT ON public.rebaseline_acl_grantor_subject TO "mscqr_prd_rls_phase2_app"');
        await tx.$executeRawUnsafe('SET ROLE "mscqr_prod_admin"');
        await tx.$executeRawUnsafe('GRANT SELECT ON public.rebaseline_acl_grantor_subject TO "mscqr_prd_rls_phase2_auth_owner"');
        await tx.$executeRawUnsafe("RESET ROLE");
        let aclState = await collectAppOnlyDatabaseCatalogueRows(tx);
        const aclCanonical = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha: context.candidateSourceSha,
          catalogue: aclState, repositoryRoot: root, packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
        const firstGrant = aclState.securityTables.find(({ name }) => name === "rebaseline_acl_grantor_subject").grants
          .find(({ role }) => role === "mscqr_prd_rls_phase2_auth_owner");
        assert.equal(firstGrant.grantor, "mscqr_prod_admin");
        let aclLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: aclState, canonical: aclCanonical, taskEvidence: evidence });
        const sameAclDiff = diffSecurityRebaselineInventories(aclLive, aclCanonical);
        assert.equal(sameAclDiff.differences.filter(({ collection, identity }) => collection === "tableGrants" && identity.includes("rebaseline_acl_grantor_subject")).length, 0,
          "same real PG18 grantor state has no grant diff");
        await tx.$executeRawUnsafe('SET ROLE "mscqr_prod_admin"');
        await tx.$executeRawUnsafe('REVOKE SELECT ON public.rebaseline_acl_grantor_subject FROM "mscqr_prd_rls_phase2_auth_owner"');
        await tx.$executeRawUnsafe("RESET ROLE");
        await tx.$executeRawUnsafe("SET ROLE pg_database_owner");
        await tx.$executeRawUnsafe('GRANT SELECT ON public.rebaseline_acl_grantor_subject TO "mscqr_prd_rls_phase2_auth_owner"');
        await tx.$executeRawUnsafe("RESET ROLE");
        aclState = await collectAppOnlyDatabaseCatalogueRows(tx);
        const secondGrant = aclState.securityTables.find(({ name }) => name === "rebaseline_acl_grantor_subject").grants
          .find(({ role }) => role === "mscqr_prd_rls_phase2_auth_owner");
        assert.equal(secondGrant.grantor, "pg_database_owner", "real PG18 ACL grantor change is collected");
        aclLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: aclState, canonical: aclCanonical, taskEvidence: evidence });
        assert.ok(diffSecurityRebaselineInventories(aclLive, aclCanonical).differences.some(({ collection, identity }) => collection === "tableGrants" && identity.includes("rebaseline_acl_grantor_subject") && identity.includes("pg_database_owner")));
        throw new Error("rollback real view and trigger inventory fixtures");
      }, { timeout: 60000 }), /rollback real view and trigger inventory fixtures/);
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("CREATE VIEW public.rebaseline_unexpected_view AS SELECT 1 AS value");
        await tx.$executeRawUnsafe('ALTER VIEW public.rebaseline_unexpected_view OWNER TO "mscqr_prod_admin"');
        await tx.$executeRawUnsafe("CREATE FUNCTION public.rebaseline_unexpected() RETURNS integer LANGUAGE sql AS 'SELECT 1'");
        await tx.$executeRawUnsafe("CREATE PROCEDURE public.rebaseline_unexpected_procedure() LANGUAGE plpgsql AS 'BEGIN NULL; END'");
        await tx.$executeRawUnsafe("CREATE AGGREGATE public.rebaseline_unexpected_aggregate(integer) (SFUNC = pg_catalog.int4pl, STYPE = integer, INITCOND = '0')");
        await tx.$executeRawUnsafe('ALTER FUNCTION public.rebaseline_unexpected() OWNER TO "mscqr_prod_admin"');
        await tx.$executeRawUnsafe("CREATE MATERIALIZED VIEW public.rebaseline_unexpected_materialized AS SELECT 1 AS value");
        await tx.$executeRawUnsafe('ALTER MATERIALIZED VIEW public.rebaseline_unexpected_materialized OWNER TO "mscqr_prod_admin"');
        await tx.$executeRawUnsafe("CREATE EXTENSION IF NOT EXISTS postgres_fdw");
        await tx.$executeRawUnsafe("CREATE PUBLICATION rebaseline_unexpected_publication");
        await tx.$executeRawUnsafe("CREATE OPERATOR public.=== (LEFTARG=integer, RIGHTARG=integer, FUNCTION=pg_catalog.int4eq)");
        await tx.$executeRawUnsafe("CREATE SERVER rebaseline_fixture_server FOREIGN DATA WRAPPER postgres_fdw OPTIONS (host '127.0.0.1', dbname 'postgres')");
        await tx.$executeRawUnsafe("CREATE FOREIGN TABLE public.rebaseline_unexpected_foreign (id integer) SERVER rebaseline_fixture_server OPTIONS (schema_name 'public', table_name 'unused')");
        await tx.$executeRawUnsafe("CREATE TYPE public.rebaseline_unexpected_enum AS ENUM ('one','two')");
        await tx.$executeRawUnsafe("CREATE DOMAIN public.rebaseline_security_domain AS integer NOT NULL CHECK (VALUE > 0)");
        await tx.$executeRawUnsafe("CREATE SEQUENCE public.rebaseline_unexpected_sequence");
        await tx.$executeRawUnsafe("CREATE TABLE public.rebaseline_acl_grantor_subject(id integer)");
        await tx.$executeRawUnsafe("GRANT UPDATE (id) ON TABLE public.rebaseline_acl_grantor_subject TO PUBLIC");
        await tx.$executeRawUnsafe("GRANT EXECUTE ON FUNCTION public.rebaseline_unexpected() TO PUBLIC");
        await tx.$executeRawUnsafe("CREATE SCHEMA rebaseline_acl_schema AUTHORIZATION mscqr_prod_admin");
        await tx.$executeRawUnsafe("GRANT USAGE ON SCHEMA rebaseline_acl_schema TO PUBLIC");
        await tx.$executeRawUnsafe("GRANT USAGE ON TYPE public.rebaseline_unexpected_enum TO PUBLIC");
        await tx.$executeRawUnsafe("GRANT USAGE ON SEQUENCE public.rebaseline_unexpected_sequence TO PUBLIC");
        await tx.$executeRawUnsafe(`GRANT CONNECT ON DATABASE "${targetDatabase}" TO PUBLIC`);
        const testCanonical = securityRebaselineCanonical;
        await tx.$executeRawUnsafe("GRANT SELECT ON public.rebaseline_unexpected_view TO PUBLIC");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_intermediate_writer NOLOGIN");
        await tx.$executeRawUnsafe("GRANT pg_write_all_data TO rebaseline_intermediate_writer");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_unexpected_login LOGIN");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_unexpected_bypass NOLOGIN BYPASSRLS");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_unexpected_createrole NOLOGIN CREATEROLE");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_unexpected_createdb NOLOGIN CREATEDB");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_membership_grantor NOLOGIN");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_membership_parent NOLOGIN");
        await tx.$executeRawUnsafe("GRANT rebaseline_membership_parent TO rebaseline_membership_grantor WITH ADMIN OPTION");
        await tx.$executeRawUnsafe("SET ROLE rebaseline_membership_grantor");
        await tx.$executeRawUnsafe("GRANT rebaseline_membership_parent TO rebaseline_unexpected_login");
        await tx.$executeRawUnsafe("RESET ROLE");
        await tx.$executeRawUnsafe("CREATE ROLE rebaseline_default_owner NOLOGIN");
        await tx.$executeRawUnsafe("ALTER DEFAULT PRIVILEGES FOR ROLE rebaseline_default_owner GRANT SELECT ON TABLES TO PUBLIC");
        await tx.$executeRawUnsafe("ALTER DEFAULT PRIVILEGES FOR ROLE rebaseline_default_owner GRANT INSERT ON TABLES TO mscqr_prd_rls_phase2_app");
        await tx.$executeRawUnsafe("ALTER DEFAULT PRIVILEGES FOR ROLE rebaseline_default_owner IN SCHEMA public GRANT USAGE ON SEQUENCES TO PUBLIC");
        await tx.$executeRawUnsafe("GRANT SET ON PARAMETER session_replication_role TO mscqr_prd_rls_phase2_app");
        await tx.$executeRawUnsafe('ALTER ROLE "mscqr_prod_admin" INHERIT');
        await tx.$executeRawUnsafe('GRANT rebaseline_intermediate_writer TO "mscqr_prod_admin" WITH ADMIN TRUE, INHERIT FALSE, SET TRUE');
        await tx.$executeRawUnsafe('GRANT pg_write_all_data TO "mscqr_prod_admin"');
        const changed = await collectAppOnlyDatabaseCatalogueRows(tx), taskDigest = "f".repeat(64);
        const publicViewGrant = changed.securityTables.find(({ name }) => name === "rebaseline_unexpected_view").grants.find(({ role }) => role === "PUBLIC");
        assert.ok(publicViewGrant?.grantor, "PUBLIC relation ACL retains its real grantor");
        assert.ok(changed.securityTables.find(({ name }) => name === "rebaseline_acl_grantor_subject").column_grants.some(({ role, grantor }) => role === "PUBLIC" && grantor));
        assert.ok(changed.securityRoutines.find(({ name }) => name === "rebaseline_unexpected").grants.some(({ role, grantor }) => role === "PUBLIC" && grantor));
        assert.ok(changed.securitySchemas.find(({ name }) => name === "rebaseline_acl_schema").grants.some(({ role, grantor }) => role === "PUBLIC" && grantor));
        assert.ok(changed.databases.length > 0 && changed.databases.every(({ grantor }) => typeof grantor === "string"));
        assert.ok(changed.defaults.some(({ owner, grantor }) => owner === "rebaseline_default_owner" && grantor === owner));
        assert.ok(changed.types.find(({ name }) => name === "rebaseline_unexpected_enum").grants.some(({ role, grantor }) => role === "PUBLIC" && grantor));
        assert.ok(changed.sequences.find(({ name }) => name === "rebaseline_unexpected_sequence").grants.some(({ role, grantor }) => role === "PUBLIC" && grantor));
        assert.ok(changed.securityRoutines.some(({ schema, name }) => schema === "public" && name === "rebaseline_unexpected"));
        assert.ok(changed.securityRoutines.some(({ schema, name, kind }) => schema === "public" && name === "rebaseline_unexpected_procedure" && kind === "p"));
        assert.ok(changed.securityRoutines.some(({ schema, name, kind, aggregate_state_sha256 }) => schema === "public" && name === "rebaseline_unexpected_aggregate" && kind === "a" && /^[a-f0-9]{64}$/.test(aggregate_state_sha256)));
        assert.ok(changed.securityExtensions.some(({ name, version, schema, relocatable }) => name === "postgres_fdw" && typeof version === "string" && schema === "public" && typeof relocatable === "boolean"));
        assert.ok(changed.securityBindings.some(({ kind, name }) => kind === "publication" && name === "rebaseline_unexpected_publication"));
        assert.ok(changed.securityBindings.some(({ kind, name }) => kind === "operator" && name.includes("===") && name.includes("integer")));
        assert.ok(changed.securityBindings.some(({ kind, name }) => kind === "foreign_server" && name === "rebaseline_fixture_server"));
        assert.equal(changed.securityRoutines.some(({ name }) => name === "postgres_fdw_handler"), false,
          "extension-owned routines are represented by their installed extension rather than duplicated as application routines");
        assert.ok(changed.securityTables.some(({ schema, name, kind }) => schema === "public" && name === "rebaseline_unexpected_view" && kind === "v"));
        assert.ok(changed.securityTables.some(({ schema, name, kind }) => schema === "public" && name === "rebaseline_unexpected_materialized" && kind === "m"));
        assert.ok(changed.securityTables.some(({ schema, name, kind }) => schema === "public" && name === "rebaseline_unexpected_foreign" && kind === "f"));
        assert.ok(changed.types.some(({ schema, name }) => schema === "public" && name === "rebaseline_unexpected_enum"));
        const domainState = changed.types.find(({ name }) => name === "rebaseline_security_domain");
        assert.equal(domainState.base_type, "integer");
        assert.equal(domainState.not_null, true);
        assert.ok(domainState.constraints.some(({ definition }) => definition.includes("CHECK")), "real domain check constraint is collected alongside PG18's not-null constraint");
        assert.deepEqual(changed.types.find(({ name }) => name === "rebaseline_unexpected_enum").enum_labels, ["one","two"]);
        assert.ok(changed.sequences.some(({ schema, name }) => schema === "public" && name === "rebaseline_unexpected_sequence"));
        assert.equal(typeof changed.sequences.find(({ name }) => name === "rebaseline_unexpected_sequence").increment_by, "string");
        assert.ok(changed.securityRoles.some(({ name, login }) => name === "rebaseline_unexpected_login" && login));
        assert.ok(changed.securityRoles.some(({ name, bypass_rls }) => name === "rebaseline_unexpected_bypass" && bypass_rls));
        assert.ok(changed.securityRoles.some(({ name, create_role }) => name === "rebaseline_unexpected_createrole" && create_role));
        assert.ok(changed.securityRoles.some(({ name, create_database }) => name === "rebaseline_unexpected_createdb" && create_database));
        assert.ok(changed.securityRoles.find(({ name }) => name === "rebaseline_unexpected_login").memberships.some(({ role, grantor }) => role === "rebaseline_membership_parent" && grantor === "rebaseline_membership_grantor"));
        assert.ok(changed.defaults.some(({ owner, schema, role }) => owner === "rebaseline_default_owner" && schema === "*" && role === "PUBLIC"));
        assert.ok(changed.defaults.some(({ owner, schema, role }) => owner === "rebaseline_default_owner" && schema === "*" && role === "mscqr_prd_rls_phase2_app"));
        assert.ok(changed.defaults.some(({ owner, schema, role, object_type }) => owner === "rebaseline_default_owner" && schema === "public" && role === "PUBLIC" && object_type === "S"));
        assert.ok(changed.parameterPrivileges.some(({ parameter, role, grantor, privilege }) => parameter === "session_replication_role" && role === "mscqr_prd_rls_phase2_app" && grantor && privilege === "SET"));
        assert.ok(changed.operatorCapabilities[0].membership_closure.includes("pg_write_all_data"));
        assert.ok(changed.operatorCapabilities[0].set_role_closure.includes("pg_write_all_data"));
        assert.equal(changed.operatorCapabilities[0].membership_closure.includes("rebaseline_intermediate_writer"), false);
        assert.ok(changed.operatorCapabilities[0].set_role_closure.includes("rebaseline_intermediate_writer"));
        const liveInventory = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: changed, canonical: testCanonical,
          taskEvidence: liveTaskEvidence(sourceSha, context.candidateSourceSha, taskDigest, "a") });
        const diff = diffSecurityRebaselineInventories(liveInventory, testCanonical);
        assert.equal(diff.safeToConstructConvergencePlan, false);
        assert.ok(diff.differences.some(({ collection, identity }) => collection === "tableGrants" && identity.includes("public.rebaseline_unexpected_view")));
        assert.ok(diff.differences.some(({ collection }) => collection === "operatorInheritedCapabilities"));
        assert.ok(diff.differences.some(({ collection }) => collection === "operatorSetRoles"));
        assert.ok(diff.differences.some(({ collection }) => collection === "operatorSetRoleCapabilities"));
        assert.ok(diff.differences.some(({ collection }) => collection === "operatorAdminCapabilities"));
        const sourceLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: changed, canonical: securityRebaselineCanonical,
          taskEvidence: liveInventory.taskEvidence }), sourceDiff = diffSecurityRebaselineInventories(sourceLive, securityRebaselineCanonical);
        assert.equal(sourceDiff.safeToConstructConvergencePlan, false);
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "tables" && identity === "public.rebaseline_unexpected_view" && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "tables" && identity === "public.rebaseline_unexpected_materialized" && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "tables" && identity === "public.rebaseline_unexpected_foreign" && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "types" && identity === "public.rebaseline_unexpected_enum" && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "sequences" && identity === "public.rebaseline_unexpected_sequence" && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "routines" && identity.startsWith("public.rebaseline_unexpected(") && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "routines" && identity.startsWith("public.rebaseline_unexpected_procedure()") && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "routines" && identity.startsWith("public.rebaseline_unexpected_aggregate(integer)") && operation === "UNEXPECTED_OBJECT"));
        assert.ok(sourceDiff.differences.some(({ collection, identity }) => collection === "extensions" && identity === "postgres_fdw"));
        assert.ok(sourceDiff.differences.some(({ collection, identity }) => collection === "bindings" && identity === "publication:rebaseline_unexpected_publication"));
        assert.ok(sourceDiff.differences.some(({ collection, identity }) => collection === "bindings" && identity.startsWith('operator:public."==="')));
        assert.ok(sourceDiff.differences.some(({ collection, identity }) => collection === "bindings" && identity === "foreign_server:rebaseline_fixture_server"));
        for (const name of ["rebaseline_unexpected_login","rebaseline_unexpected_bypass","rebaseline_unexpected_createrole","rebaseline_unexpected_createdb","rebaseline_default_owner"]) {
          assert.ok(sourceDiff.differences.some(({ collection, identity, operation }) => collection === "unexpectedRoles" && identity === name && operation === "UNEXPECTED_OBJECT"), `${name} must hard-stop as an unexpected role`);
        }
        assert.ok(sourceDiff.differences.some(({ collection, identity }) => collection === "defaultPrivileges" && identity.includes('"*"') && identity.includes('"PUBLIC"')));
        assert.ok(sourceDiff.differences.some(({ collection, identity }) => collection === "parameterPrivileges" && identity.includes("session_replication_role")));
        assert.equal(sourceDiff.safeToConstructConvergencePlan, false);
        throw new Error("rollback real security collector drift");
      }), /rollback real security collector drift/);
      await maintenanceClient.$executeRawUnsafe("CREATE TABLE public.rebaseline_subscription_target(id integer)");
      await maintenanceClient.$executeRawUnsafe("CREATE SUBSCRIPTION rebaseline_disabled_subscription CONNECTION 'host=127.0.0.1 dbname=unused password=synthetic_test_value' PUBLICATION rebaseline_remote_z, rebaseline_remote_a WITH (connect=false,slot_name=NONE)");
      try {
        const withoutRelationCatalogue = await collectCatalogueRows(maintenanceClient);
        const withoutRelationCanonical = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha,
          candidateSourceSha: context.candidateSourceSha, catalogue: withoutRelationCatalogue, repositoryRoot: root,
          packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
        await maintenanceClient.$executeRawUnsafe(`INSERT INTO pg_catalog.pg_subscription_rel(srsubid,srrelid,srsubstate,srsublsn)
          SELECT s.oid,c.oid,'i',NULL FROM pg_catalog.pg_subscription s CROSS JOIN pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE s.subname='rebaseline_disabled_subscription' AND n.nspname='public' AND c.relname='rebaseline_subscription_target'`);
        const appearedCatalogue = await collectCatalogueRows(verifier);
        const appearedDiff = diffSecurityRebaselineInventories(createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha,
          catalogue: appearedCatalogue, canonical: withoutRelationCanonical, taskEvidence: liveTaskEvidence(sourceSha, context.candidateSourceSha, "f".repeat(64), "a") }), withoutRelationCanonical);
        assert.ok(appearedDiff.differences.some(({ collection, identity }) => collection === "bindings"
          && identity === "subscription_relation:rebaseline_disabled_subscription:public.rebaseline_subscription_target"),
        "a real pg_subscription_rel binding appearing reaches the restricted collector and diff");
        const canonicalSubscriptionCatalogue = await collectCatalogueRows(maintenanceClient);
        const canonicalSubscription = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha,
          candidateSourceSha: context.candidateSourceSha, catalogue: canonicalSubscriptionCatalogue, repositoryRoot: root,
          packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
        const restrictedSubscriptionCatalogue = await collectCatalogueRows(verifier);
        const subscription = (catalogue) => catalogue.securityBindings.find(({ kind, name }) => kind === "subscription" && name === "rebaseline_disabled_subscription");
        const subscriptionRelation = (catalogue) => catalogue.securityBindings.find(({ kind, name }) => kind === "subscription_relation"
          && name === "rebaseline_disabled_subscription:public.rebaseline_subscription_target");
        assert.equal(subscription(restrictedSubscriptionCatalogue)?.definition.enabled, false);
        assert.deepEqual(subscription(restrictedSubscriptionCatalogue)?.definition.publications, ["rebaseline_remote_a","rebaseline_remote_z"]);
        assert.equal(subscription(restrictedSubscriptionCatalogue)?.definition.skip_lsn, "0/0");
        const firstDigest = subscription(restrictedSubscriptionCatalogue)?.definition.connection_info_sha256;
        assert.match(firstDigest || "", /^[a-f0-9]{64}$/);
        assert.equal(JSON.stringify(restrictedSubscriptionCatalogue).includes("host=127.0.0.1"), false);
        const evidence = liveTaskEvidence(sourceSha, context.candidateSourceSha, "f".repeat(64), "a");
        const before = diffSecurityRebaselineInventories(createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha,
          catalogue: restrictedSubscriptionCatalogue, canonical: canonicalSubscription, taskEvidence: evidence }), canonicalSubscription);
        assert.deepEqual(subscriptionRelation(restrictedSubscriptionCatalogue)?.definition, { subscription:"rebaseline_disabled_subscription",
          schema:"public",relation:"rebaseline_subscription_target",state:"i",state_lsn:null });
        assert.equal(before.differences.filter(({ collection, identity }) => collection === "bindings"
          && identity === "subscription_relation:rebaseline_disabled_subscription:public.rebaseline_subscription_target").length, 0,
          "identical restricted and direct subscription-relation state has no drift");
        await maintenanceClient.$executeRawUnsafe(`UPDATE pg_catalog.pg_subscription_rel SET srsubstate='s',srsublsn='0/16B6C50'
          WHERE srsubid=(SELECT oid FROM pg_catalog.pg_subscription WHERE subname='rebaseline_disabled_subscription')`);
        let changedRelationCatalogue = await collectCatalogueRows(verifier);
        assert.equal(subscriptionRelation(changedRelationCatalogue)?.definition.state_lsn, "0/16B6C50");
        let relationDiff = diffSecurityRebaselineInventories(createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha,
          catalogue: changedRelationCatalogue, canonical: canonicalSubscription, taskEvidence: evidence }), canonicalSubscription);
        assert.ok(relationDiff.differences.some(({ collection, identity }) => collection === "bindings"
          && identity === "subscription_relation:rebaseline_disabled_subscription:public.rebaseline_subscription_target"),
        "subscription synchronization state and its meaningful transition LSN reach the diff");
        await maintenanceClient.$executeRawUnsafe(`UPDATE pg_catalog.pg_subscription_rel SET srsublsn='0/16B6D00'
          WHERE srsubid=(SELECT oid FROM pg_catalog.pg_subscription WHERE subname='rebaseline_disabled_subscription')`);
        changedRelationCatalogue = await collectCatalogueRows(verifier);
        assert.equal(subscriptionRelation(changedRelationCatalogue)?.definition.state_lsn, "0/16B6D00");
        await maintenanceClient.$executeRawUnsafe(`DELETE FROM pg_catalog.pg_subscription_rel
          WHERE srsubid=(SELECT oid FROM pg_catalog.pg_subscription WHERE subname='rebaseline_disabled_subscription')`);
        changedRelationCatalogue = await collectCatalogueRows(verifier);
        relationDiff = diffSecurityRebaselineInventories(createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha,
          catalogue: changedRelationCatalogue, canonical: canonicalSubscription, taskEvidence: evidence }), canonicalSubscription);
        assert.ok(relationDiff.differences.some(({ collection, identity }) => collection === "bindings"
          && identity === "subscription_relation:rebaseline_disabled_subscription:public.rebaseline_subscription_target"),
        "a subscription relation disappearing reaches the diff");
        await maintenanceClient.$executeRawUnsafe(`INSERT INTO pg_catalog.pg_subscription_rel(srsubid,srrelid,srsubstate,srsublsn)
          SELECT s.oid,c.oid,'i',NULL FROM pg_catalog.pg_subscription s CROSS JOIN pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
          WHERE s.subname='rebaseline_disabled_subscription' AND n.nspname='public' AND c.relname='rebaseline_subscription_target'`);
        await maintenanceClient.$executeRawUnsafe("ALTER SUBSCRIPTION rebaseline_disabled_subscription SKIP (lsn = '0/16B6C50')");
        const skippedSubscriptionCatalogue = await collectCatalogueRows(verifier), directSkippedSubscriptionCatalogue = await collectCatalogueRows(maintenanceClient);
        assert.equal(subscription(skippedSubscriptionCatalogue)?.definition.skip_lsn, "0/16B6C50");
        assert.equal(subscription(directSkippedSubscriptionCatalogue)?.definition.skip_lsn, "0/16B6C50", "canonical and restricted collection use identical skip-state semantics");
        const skipped = diffSecurityRebaselineInventories(createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha,
          catalogue: skippedSubscriptionCatalogue, canonical: canonicalSubscription, taskEvidence: evidence }), canonicalSubscription);
        assert.notDeepEqual(skipped.differences.find(({ collection, identity }) => collection === "bindings" && identity === "subscription:rebaseline_disabled_subscription")?.afterSha256,
          before.differences.find(({ collection, identity }) => collection === "bindings" && identity === "subscription:rebaseline_disabled_subscription")?.afterSha256,
          "the real restricted PG18 projection preserves and diffs a pending subscription skip LSN");
        await maintenanceClient.$executeRawUnsafe("ALTER SUBSCRIPTION rebaseline_disabled_subscription CONNECTION 'host=127.0.0.2 dbname=unused password=synthetic_test_value'");
        const changedSubscriptionCatalogue = await collectCatalogueRows(verifier);
        const secondDigest = subscription(changedSubscriptionCatalogue)?.definition.connection_info_sha256;
        assert.match(secondDigest || "", /^[a-f0-9]{64}$/);
        assert.notEqual(secondDigest, firstDigest, "endpoint change changes the restricted digest");
        assert.equal(JSON.stringify(changedSubscriptionCatalogue).includes("host=127.0.0.2"), false);
        const after = diffSecurityRebaselineInventories(createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha,
          catalogue: changedSubscriptionCatalogue, canonical: canonicalSubscription, taskEvidence: evidence }), canonicalSubscription);
        const row = (diff) => diff.differences.find(({ collection, identity }) => collection === "bindings" && identity === "subscription:rebaseline_disabled_subscription");
        assert.notEqual(row(after)?.afterSha256, row(before)?.afterSha256, "the real restricted collector-to-diff path detects changed connection binding");
      } finally {
        await maintenanceClient.$executeRawUnsafe("ALTER SUBSCRIPTION rebaseline_disabled_subscription SET (slot_name=NONE)");
        await maintenanceClient.$executeRawUnsafe("DROP SUBSCRIPTION IF EXISTS rebaseline_disabled_subscription");
        await maintenanceClient.$executeRawUnsafe("DROP TABLE IF EXISTS public.rebaseline_subscription_target");
      }
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("CREATE SCHEMA rebaseline_extension_schema AUTHORIZATION mscqr_prod_admin");
        await tx.$executeRawUnsafe("CREATE EXTENSION postgres_fdw WITH SCHEMA rebaseline_extension_schema");
        const extensionCatalogue = await collectAppOnlyDatabaseCatalogueRows(tx), extension = extensionCatalogue.securityExtensions.find(({ name }) => name === "postgres_fdw");
        assert.equal(extension.schema, "rebaseline_extension_schema");
        const extensionCanonical = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha: context.candidateSourceSha, catalogue: extensionCatalogue,
          repositoryRoot: root, packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
        await tx.$executeRawUnsafe("ALTER EXTENSION postgres_fdw SET SCHEMA public");
        let changed = await collectAppOnlyDatabaseCatalogueRows(tx);
        let extensionLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: changed, canonical: extensionCanonical,
          taskEvidence: productionEquivalentLive.taskEvidence });
        assert.ok(diffSecurityRebaselineInventories(extensionLive, extensionCanonical).differences.some(({ collection, identity, field }) => collection === "extensions" && identity === "postgres_fdw" && field === "schema"));
        await tx.$executeRawUnsafe("DROP EXTENSION postgres_fdw CASCADE");
        changed = await collectAppOnlyDatabaseCatalogueRows(tx);
        extensionLive = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: changed, canonical: extensionCanonical,
          taskEvidence: productionEquivalentLive.taskEvidence });
        assert.ok(diffSecurityRebaselineInventories(extensionLive, extensionCanonical).differences.some(({ collection, identity }) => collection === "extensions" && identity === "postgres_fdw"));
        throw new Error("rollback real extension inventory fixtures");
      }), /rollback real extension inventory fixtures/);
      await assert.rejects(maintenanceClient.$transaction(async (tx) => {
        await tx.$executeRawUnsafe("CREATE FOREIGN DATA WRAPPER rebaseline_digest_fdw OPTIONS (endpoint 'fdw_first')");
        await tx.$executeRawUnsafe("CREATE SERVER rebaseline_digest_server FOREIGN DATA WRAPPER rebaseline_digest_fdw OPTIONS (host 'first.invalid', dbname 'firstdb')");
        await tx.$executeRawUnsafe("CREATE USER MAPPING FOR mscqr_prod_admin SERVER rebaseline_digest_server OPTIONS (user 'remote_one', password 'fixture_secret_one')");
        await tx.$executeRawUnsafe("CREATE FOREIGN TABLE public.rebaseline_digest_foreign(id integer OPTIONS (column_name 'first_id')) SERVER rebaseline_digest_server OPTIONS (schema_name 'public', table_name 'first_table')");
        const baseline = await collectAppOnlyDatabaseCatalogueRows(tx), serialized = JSON.stringify(baseline);
        for (const secret of ["fdw_first","first.invalid","firstdb","remote_one","fixture_secret_one","first_table","first_id"]) assert.equal(serialized.includes(secret), false, `raw foreign option ${secret} escaped`);
        const canonical = createSecurityRebaselineInventory({ kind: "CANONICAL", protectedMainSha: sourceSha, candidateSourceSha: context.candidateSourceSha, catalogue: baseline,
          repositoryRoot: root, packageChecksums: JSON.parse(fs.readFileSync(path.join(evidenceRoot, "checksums.json"), "utf8")) });
        await tx.$executeRawUnsafe("ALTER FOREIGN DATA WRAPPER rebaseline_digest_fdw OPTIONS (SET endpoint 'fdw_second')");
        await tx.$executeRawUnsafe("ALTER SERVER rebaseline_digest_server OPTIONS (SET host 'second.invalid')");
        await tx.$executeRawUnsafe("ALTER USER MAPPING FOR mscqr_prod_admin SERVER rebaseline_digest_server OPTIONS (SET user 'remote_two', SET password 'fixture_secret_two')");
        await tx.$executeRawUnsafe("ALTER FOREIGN TABLE public.rebaseline_digest_foreign OPTIONS (SET table_name 'second_table')");
        await tx.$executeRawUnsafe("ALTER FOREIGN TABLE public.rebaseline_digest_foreign ALTER COLUMN id OPTIONS (SET column_name 'second_id')");
        const changed = await collectAppOnlyDatabaseCatalogueRows(tx), changedSerialized = JSON.stringify(changed);
        for (const secret of ["fdw_second","second.invalid","remote_two","fixture_secret_two","second_table","second_id"]) assert.equal(changedSerialized.includes(secret), false, `changed foreign option ${secret} escaped`);
        const live = createLiveSecurityRebaselineInventory({ protectedMainSha: sourceSha, catalogue: changed, canonical, taskEvidence: productionEquivalentLive.taskEvidence });
        const diff = diffSecurityRebaselineInventories(live, canonical);
        for (const identity of ["foreign_data_wrapper:rebaseline_digest_fdw","foreign_server:rebaseline_digest_server","user_mapping:rebaseline_digest_server:mscqr_prod_admin","foreign_table:public.rebaseline_digest_foreign"])
          assert.ok(diff.differences.some(({ collection, identity: observed }) => collection === "bindings" && observed === identity), `${identity} option digest drift is observable`);
        assert.ok(diff.differences.some(({ collection, identity, field }) => collection === "tables" && identity === "public.rebaseline_digest_foreign" && field === "columns"),
          "foreign-column option-value digest drift reaches the real normalized relation inventory");
        throw new Error("rollback real foreign binding digest fixtures");
      }), /rollback real foreign binding digest fixtures/);
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
      const localCommand = [path.join(root, "scripts/aws/production-app-only-verifier-runtime.mjs"), ...command.command.slice(1)];
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
      const privilegedGreenUrl = databaseUrl(adminUrl, targetDatabase, adminUrl.username);
      psql(privilegedGreenUrl, ["-q", "-c", "ALTER FUNCTION app_rls.production_security_subscription_inventory() RESET search_path"], "tamper subscription inventory helper contract");
      try {
        await assert.rejects(administratorClient.$transaction((tx) => printingDeltaRuntime.executePrintingRoutineDeltaTransaction({ tx, input: deltaInput }),
          { maxWait: 10000, timeout: 120000 }));
      } finally {
        psql(privilegedGreenUrl, ["-q", "-c", "ALTER FUNCTION app_rls.production_security_subscription_inventory() SET search_path=pg_catalog"], "restore subscription inventory helper contract");
      }
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
        psql(maintenanceUrl, ["-q", "-c", `DROP DATABASE "${targetDatabase}" WITH (FORCE)`], "drop disposable green database with harness administrator");
      }
      if (subscriptionObserverProvisionStarted && scalar(maintenanceUrl, "SELECT count(*) FROM pg_roles WHERE rolname='mscqr_prod_subscription_observer'", "inspect disposable observer") === "1") {
        psql(maintenanceUrl, ["-q", "-c", "REVOKE SELECT (subconninfo) ON pg_catalog.pg_subscription FROM mscqr_prod_subscription_observer; DROP ROLE mscqr_prod_subscription_observer"], "remove disposable subscription observer role and global catalogue grant");
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
  if (process.env.MSCQR_SECURITY_REBASELINE_CANONICAL_PATH) {
    assert.ok(securityRebaselineCanonical);
    writeStageBPrivateFileExclusive({ filePath: process.env.MSCQR_SECURITY_REBASELINE_CANONICAL_PATH,
      repositoryRoot: root, bytes: Buffer.from(`${JSON.stringify(securityRebaselineCanonical)}\n`) });
  }
});
