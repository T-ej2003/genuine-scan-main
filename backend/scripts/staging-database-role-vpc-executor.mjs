#!/usr/bin/env node
import crypto from "node:crypto";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { PrismaClient } from "@prisma/client";
import {
  CreateSecretCommand,
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
  TagResourceCommand,
  UpdateSecretVersionStageCommand,
} from "@aws-sdk/client-secrets-manager";

export const REGION = "eu-west-2";
export const DATABASE = "mscqr_staging";
export const ROLES = {
  app: "mscqr_staging_app",
  migrator: "mscqr_staging_migrator",
  rlsRead: "mscqr_staging_rls_read",
};
export const SECRETS = {
  app: "mscqr/staging/database-url/app",
  migrator: "mscqr/staging/database-url/migrator",
  rlsRead: "mscqr/staging/database-url/rls-read",
};
export const RLS_READ_TABLES = ["Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrinterRegistration", "Printer", "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot"];
export const DENIALS = {
  app: ["create-role", "create-schema", "alter-table", "set-owner"],
  migrator: ["create-role"],
  rlsRead: ["insert", "update", "create-table", "outside-graph"],
};
const PROBE_SUFFIX = crypto.randomUUID().replaceAll("-", "");
const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"];
const MODE = process.env.MSCQR_VPC_EXECUTOR_MODE || "probe";
const FAILURE = process.env.MSCQR_TEST_FAILURE_PHASE || "";
const sm = new SecretsManagerClient({ region: REGION });
const injectedFailures = new Set();
let compensating = false;
let phase = "startup";
let recoveryRequired = false;
let interruptionSignal = "";

const safe = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const failAt = (name) => { if (FAILURE === name && !injectedFailures.has(name)) { injectedFailures.add(name); throw Object.assign(new Error(`Injected failure at ${name}.`), { code: "INJECTED_FAILURE" }); } };
const interruptionCheckpoint = () => { if (interruptionSignal) throw Object.assign(new Error("Executor interrupted; compensation required."), { code: interruptionSignal }); };
const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;
const roleIdent = (value) => {
  if (!Object.values(ROLES).includes(value)) throw new Error("Unreviewed role identifier.");
  return `"${value}"`;
};
const secretUrl = (raw) => {
  try {
    const parsed = JSON.parse(raw);
    return typeof parsed === "string" ? parsed : parsed.DATABASE_URL || parsed.databaseUrl || parsed.url;
  } catch { return raw; }
};
const RLS_SHARED_MODES = Object.freeze({
  "rls-shared-apply": "mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql",
  "rls-shared-verify": "mscqr_staging_rls_shared_batch_phase_verify_2026-07-15.sql",
  "rls-shared-rollback": "mscqr_staging_rls_shared_batch_phase_rollback_2026-07-15.sql",
});
const rlsSqlError = (result, mode) => {
  if (result.error) {
    return Object.assign(new Error(`Shared RLS ${mode} could not start psql.`), {
      code: "RLS_PSQL_LAUNCH_FAILED",
      safeReason: "psql could not be started inside the helper container.",
    });
  }
  const stderr = String(result.stderr || "").replaceAll(/\x1b\[[0-9;]*m/g, "");
  const infrastructureFailure = /timeout|canceling statement/i.test(stderr)
    ? ["RLS_DATABASE_TIMEOUT", "PostgreSQL timed out; connection details suppressed."]
    : /permission denied|must be owner|insufficient privilege/i.test(stderr)
      ? ["RLS_DATABASE_PERMISSION_DENIED", "PostgreSQL denied the administrative SQL operation."]
      : /FATAL:|could not connect|connection (?:refused|failed)|no pg_hba/i.test(stderr)
        ? ["RLS_DATABASE_CONNECTION_FAILED", "PostgreSQL connection failed; endpoint details suppressed."]
        : null;
  if (infrastructureFailure) {
    const [code, safeReason] = infrastructureFailure;
    return Object.assign(new Error(`Shared RLS ${mode} SQL task failed.`), { code, safeReason });
  }
  const assertion = stderr.match(/\bERROR:\s*([^\r\n]*)/i)?.[1]
    ?.replaceAll(/postgres(?:ql)?:\/\/\S+/gi, "[REDACTED_DATABASE_URL]")
    .replaceAll(/\bpassword\s*=\s*\S+/gi, "password=[REDACTED]")
    .slice(0, 500);
  if (assertion) {
    return Object.assign(new Error(`Shared RLS ${mode} SQL assertion failed.`), {
      code: "RLS_SQL_ASSERTION_FAILED",
      safeReason: assertion,
    });
  }
  return Object.assign(new Error(`Shared RLS ${mode} SQL task failed.`), {
    code: "RLS_SQL_EXECUTION_FAILED",
    safeReason: "PostgreSQL rejected the shared RLS SQL; sensitive details suppressed.",
  });
};
export function runRlsSharedPhase(mode, rawDatabaseUrl = process.env.DATABASE_URL, spawn = spawnSync) {
  const file = RLS_SHARED_MODES[mode];
  if (!file) throw new Error("Unsupported shared RLS executor mode.");
  const databaseUrl = secretUrl(rawDatabaseUrl);
  let url;
  try { url = new URL(databaseUrl); } catch { throw new Error("Admin DATABASE_URL has an invalid shape."); }
  const database = decodeURIComponent(url.pathname.slice(1));
  if (!["postgres:", "postgresql:"].includes(url.protocol)
      || database !== DATABASE || decodeURIComponent(url.username) !== "mscqr_staging_admin"
      || !/(?:staging|stg)/i.test(url.hostname) || /prod|production|live/i.test(url.hostname)) {
    throw new Error("Shared RLS executor refused a non-staging admin database endpoint.");
  }
  const sslmode = url.searchParams.get("sslmode") || "require";
  if (!new Set(["require", "verify-ca", "verify-full"]).has(sslmode)) {
    throw new Error("Shared RLS executor requires PostgreSQL TLS verification mode.");
  }
  const { DATABASE_URL: _databaseUrl, ...baseEnv } = process.env;
  const result = spawn("psql", [
    "-X", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1",
    "-v", `mscqr_app_role=${ROLES.app}`,
    "-v", `mscqr_rls_read_role=${ROLES.rlsRead}`,
    "-v", "mscqr_auth_owner_role=mscqr_staging_auth_owner",
    "-f", path.join("/app/documents/security", file),
  ], {
    encoding: "utf8",
    env: {
      ...baseEnv,
      PGAPPNAME: `mscqr-${mode}`,
      PGHOST: url.hostname,
      PGPORT: url.port || "5432",
      PGDATABASE: database,
      PGUSER: decodeURIComponent(url.username),
      PGPASSWORD: decodeURIComponent(url.password),
      PGSSLMODE: sslmode,
    },
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error || result.status !== 0) throw rlsSqlError(result, mode);
  const evidenceLine = String(result.stdout || "").trim().split("\n").reverse().find((line) => line.trim().startsWith("{"));
  try { return JSON.parse(evidenceLine); } catch { throw new Error("Shared RLS SQL task returned invalid evidence."); }
}
const client = (url) => new PrismaClient({ datasources: { db: { url } }, log: [] });
const password = () => crypto.randomBytes(48).toString("base64url");
const roleUrl = (adminUrl, username, generatedPassword) => {
  const url = new URL(adminUrl);
  if (decodeURIComponent(url.pathname.slice(1)) !== DATABASE || !/(?:staging|stg)/i.test(url.hostname) || /prod|production|live/i.test(url.hostname)) throw new Error("Executor refused non-staging database endpoint.");
  url.username = username;
  url.password = generatedPassword;
  url.searchParams.set("sslmode", "require");
  return url.toString();
};
const roleTag = (key) => key === "rlsRead" ? "rls-read" : key;
const secretTags = (key) => [
  { Key: "Environment", Value: "staging" },
  { Key: "Application", Value: "mscqr" },
  { Key: "Purpose", Value: "database-role-credential" },
  { Key: "ManagedBy", Value: "manual-reviewed-script" },
  { Key: "Role", Value: roleTag(key) },
];

async function metadata(key) {
  try {
    const value = await sm.send(new DescribeSecretCommand({ SecretId: SECRETS[key] }));
    const stages = value.VersionIdsToStages || {};
    const currentVersionId = Object.entries(stages).find(([, names]) => names.includes("AWSCURRENT"))?.[0] || null;
    return { exists: true, arn: value.ARN, currentVersionId, versionIds: Object.keys(stages), stages };
  } catch (error) {
    if (error.name === "ResourceNotFoundException") return { exists: false, arn: null, currentVersionId: null, versionIds: [], stages: {} };
    throw error;
  }
}

async function currentUrl(key, state) {
  if (!state.currentVersionId) return null;
  const value = await sm.send(new GetSecretValueCommand({ SecretId: SECRETS[key], VersionId: state.currentVersionId, VersionStage: "AWSCURRENT" }));
  return secretUrl(value.SecretString);
}

async function isPlaceholder(key, state) {
  if (!state?.exists || !state.currentVersionId) return false;
  const value = await sm.send(new GetSecretValueCommand({ SecretId: SECRETS[key], VersionId: state.currentVersionId, VersionStage: "AWSCURRENT" }));
  try { return JSON.parse(value.SecretString)?.status === "unprovisioned"; } catch { return false; }
}

async function setPasswords(admin, urls, nullPasswords = false) {
  await admin.$transaction(async (tx) => {
    let index = 0;
    for (const [key, role] of Object.entries(ROLES)) {
      const sql = nullPasswords
        ? `ALTER ROLE ${roleIdent(role)} PASSWORD NULL`
        : `ALTER ROLE ${roleIdent(role)} PASSWORD ${quote(new URL(urls[key]).password)}`;
      await tx.$executeRawUnsafe(sql);
      if (++index === 1) failAt("first-role-password-assignment");
    }
  }, { timeout: 30_000 });
}

const isPermissionDenial = (error) => /permission denied|must be owner|not permitted|insufficient privilege/i.test(String(error?.message || error));

export async function verifyDeniedOperation(db, { label, sql, mutating = false }) {
  let operationError;
  let unexpectedlySucceeded = false;
  try {
    if (mutating) {
      await db.$transaction(async (tx) => {
        try { await tx.$executeRawUnsafe(sql); }
        catch (error) { operationError = error; throw error; }
        unexpectedlySucceeded = true;
        throw Object.assign(new Error(`${label} unexpectedly succeeded; rolling back.`), { unexpectedProbeSuccess: true });
      });
    } else {
      try { await db.$executeRawUnsafe(sql); }
      catch (error) { operationError = error; }
      if (!operationError) unexpectedlySucceeded = true;
    }
  } catch (error) {
    if (!operationError && !error?.unexpectedProbeSuccess) throw new Error(`${label} rollback failed; verification is unsafe.`);
    if (operationError && String(error?.message || error) !== String(operationError?.message || operationError)) throw new Error(`${label} rollback failed; verification is unsafe.`);
    if (!operationError) operationError = error;
  }

  try { await db.$queryRawUnsafe("SELECT 1 AS connection_reusable"); }
  catch { throw new Error(`${label} left the connection unusable after rollback.`); }

  if (unexpectedlySucceeded) throw new Error(`${label} unexpectedly succeeded; transaction was rolled back.`);
  if (!isPermissionDenial(operationError)) throw new Error(`${label} failed for a non-permission reason.`);
  return { label, result: "permission-denied" };
}

export async function verifyCredentials(urls, { clientFactory = client } = {}) {
  const results = [];
  for (const [key, url] of Object.entries(urls)) {
    const db = clientFactory(url, key);
    try {
      const identity = await db.$queryRawUnsafe("SELECT current_database() AS database_name, current_user AS database_user");
      if (identity[0]?.database_name !== DATABASE || identity[0]?.database_user !== ROLES[key]) throw new Error(`${key} identity verification failed.`);
      const expectDenied = (label, sql, mutating = false) => verifyDeniedOperation(db, { label, sql, mutating });
      const tests = [];
      if (key === "app") {
        await db.$transaction(async (tx) => {
          await tx.$queryRawUnsafe('SELECT 1 FROM "User" LIMIT 1');
          await tx.$queryRawUnsafe('SELECT 1 FROM "Batch" LIMIT 1');
          await tx.$queryRawUnsafe('SELECT 1 FROM "Printer" LIMIT 1');
          await tx.$executeRawUnsafe(`INSERT INTO "ActionIdempotencyKey" ("id","keyHash","action","scope","requestHash","createdAt","expiresAt") VALUES ('credential-proof-'||pg_backend_pid(),'credential-proof-'||pg_backend_pid(),'credential-proof','credential-proof','rolled-back',now(),now()+interval '1 minute')`);
          await tx.$executeRawUnsafe(`UPDATE "ActionIdempotencyKey" SET "requestHash"='updated' WHERE "id"='credential-proof-'||pg_backend_pid()`);
          await tx.$executeRawUnsafe(`DELETE FROM "ActionIdempotencyKey" WHERE "id"='credential-proof-'||pg_backend_pid()`);
          throw Object.assign(new Error("intentional verification rollback"), { verificationRollback: true });
        }).catch((error) => { if (!error.verificationRollback) throw error; });
        tests.push({ label: "required-crud-rollback", result: "passed" });
        for (const [label, sql] of [["create-role", `CREATE ROLE mscqr_forbidden_${PROBE_SUFFIX}`], ["create-schema", `CREATE SCHEMA mscqr_forbidden_${PROBE_SUFFIX}`], ["alter-table", `ALTER TABLE "User" ADD COLUMN forbidden_${PROBE_SUFFIX} text`], ["set-owner", 'SET LOCAL ROLE "mscqr_staging_owner"']]) tests.push(await expectDenied(label, sql, true));
      } else if (key === "migrator") {
        await db.$transaction(async (tx) => {
          await tx.$executeRawUnsafe('SET LOCAL ROLE "mscqr_staging_owner"');
          await tx.$executeRawUnsafe("CREATE TABLE mscqr_staging_migrator_credential_proof(id integer)");
          throw Object.assign(new Error("intentional verification rollback"), { verificationRollback: true });
        }).catch((error) => { if (!error.verificationRollback) throw error; });
        tests.push({ label: "set-owner-ddl-rollback", result: "passed" });
        tests.push(await expectDenied("create-role", `CREATE ROLE mscqr_forbidden_${PROBE_SUFFIX}`, true));
      } else {
        for (const table of RLS_READ_TABLES) await db.$queryRawUnsafe(`SELECT 1 FROM "${table}" LIMIT 1`);
        tests.push({ label: "complete-16-table-read-graph", result: "passed", tableCount: RLS_READ_TABLES.length });
        for (const [label, sql, mutating] of [["insert", 'INSERT INTO "User" DEFAULT VALUES', true], ["update", 'UPDATE "User" SET id=id WHERE false', true], ["create-table", `CREATE TABLE mscqr_forbidden_${PROBE_SUFFIX}(id integer)`, true], ["outside-graph", 'SELECT 1 FROM "AuditLog" LIMIT 1', false]]) tests.push(await expectDenied(label, sql, mutating));
      }
      results.push({ role: ROLES[key], identity: "passed", permissionTests: tests });
    } finally { await db.$disconnect(); }
  }
  failAt("role-verification");
  return results;
}

export function assertCompleteVerification(results) {
  if (!Array.isArray(results) || results.length !== Object.keys(ROLES).length) throw new Error("Permission matrix has an incomplete or duplicate role set.");
  const byRole = new Map((results || []).map((result) => [result.role, result]));
  for (const [key, role] of Object.entries(ROLES)) {
    const result = byRole.get(role);
    if (!result || result.identity !== "passed" || !Array.isArray(result.permissionTests)) throw new Error(`Incomplete permission matrix for ${role}.`);
    const labels = new Set(result.permissionTests.map((test) => test.label));
    for (const label of DENIALS[key]) if (!labels.has(label) || result.permissionTests.find((test) => test.label === label)?.result !== "permission-denied") throw new Error(`Missing expected denial ${key}/${label}.`);
    if (key === "app" && !labels.has("required-crud-rollback")) throw new Error("App CRUD proof is incomplete.");
    if (key === "migrator" && !labels.has("set-owner-ddl-rollback")) throw new Error("Migrator owner-role proof is incomplete.");
    if (key === "rlsRead") {
      const graph = result.permissionTests.find((test) => test.label === "complete-16-table-read-graph");
      if (graph?.tableCount !== RLS_READ_TABLES.length) throw new Error("RLS-read graph proof is incomplete.");
    }
  }
  if (byRole.size !== Object.keys(ROLES).length) throw new Error("Permission matrix contains unexpected or duplicate roles.");
  return true;
}

export async function databaseInvariants(admin) {
  const rows = await admin.$queryRawUnsafe(`SELECT current_database() AS database_name,
    (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND c.relrowsecurity) AS rls_enabled_count,
    (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND c.relforcerowsecurity) AS force_rls_count,
    (SELECT count(*)::int FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AS policy_count`);
  const value = rows[0] || {};
  if (value.database_name !== DATABASE || Number(value.rls_enabled_count) !== 0 || Number(value.force_rls_count) !== 0 || Number(value.policy_count) !== 0) throw new Error("Database/RLS invariants failed.");
  return { databaseName: value.database_name, rlsEnabledCount: 0, forceRlsCount: 0, policyCount: 0 };
}

export function assertRouteFlagsFalse(env = process.env) {
  for (const name of ["MSCQR_STAGING_RLS_BATCHES_READ_ENABLED", "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED", "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED"]) if (env[name] !== "false") throw new Error(`${name} must remain explicitly false.`);
  return true;
}

async function createPlaceholder(key) {
  await sm.send(new CreateSecretCommand({
    Name: SECRETS[key], ClientRequestToken: crypto.randomUUID(), SecretString: JSON.stringify({ status: "unprovisioned" }),
    Description: `MSCQR staging ${key} database URL`, Tags: secretTags(key),
  }));
}

export async function ensureAllPlaceholders({ metadataFn = metadata, isPlaceholderFn = isPlaceholder, createPlaceholderFn = createPlaceholder } = {}) {
  const states = {};
  for (const key of Object.keys(ROLES)) {
    states[key] = await metadataFn(key);
    if (!states[key].exists) { await createPlaceholderFn(key); states[key] = await metadataFn(key); }
    if (!await isPlaceholderFn(key, states[key])) throw new Error(`Secret ${key} is not a recoverable placeholder.`);
  }
  return states;
}

export function classifyProvisioningMode(states, placeholderFlags) {
  const existingKeys = Object.keys(ROLES).filter((key) => states[key]?.exists);
  const existingArePlaceholders = existingKeys.every((key) => placeholderFlags[key] === true);
  if (existingKeys.length === 0) return "first-time";
  if (existingArePlaceholders) return "first-time-recoverable";
  if (existingKeys.length === Object.keys(ROLES).length && existingKeys.every((key) => placeholderFlags[key] === false)) return "rotation";
  throw Object.assign(new Error("Mixed credential/placeholder secret state requires operator recovery."), { code: "MIXED_SECRET_STATE" });
}

async function putPending(key, url) {
  const token = crypto.randomUUID();
  await sm.send(new PutSecretValueCommand({ SecretId: SECRETS[key], ClientRequestToken: token, SecretString: url, VersionStages: ["AWSPENDING"] }));
  await sm.send(new TagResourceCommand({ SecretId: SECRETS[key], Tags: secretTags(key) }));
  return token;
}

async function removePending(pending) {
  for (const [key, versionId] of Object.entries(pending)) {
    try {
      const state = await metadata(key);
      if (state.stages?.[versionId]?.includes("AWSPENDING")) await sm.send(new UpdateSecretVersionStageCommand({ SecretId: SECRETS[key], VersionStage: "AWSPENDING", RemoveFromVersionId: versionId }));
    } catch { recoveryRequired = true; }
  }
}

async function compensate(admin, provisionMode, previousUrls, pending, before) {
  compensating = true;
  recoveryRequired = false;
  try {
    const firstTime = provisionMode === "first-time" || provisionMode === "first-time-recoverable";
    await setPasswords(admin, firstTime ? {} : previousUrls, firstTime);
    for (const [key, pendingVersionId] of Object.entries(pending)) {
      const currentState = await metadata(key);
      if (!before[key].currentVersionId || currentState.currentVersionId !== pendingVersionId) continue;
      await sm.send(new UpdateSecretVersionStageCommand({ SecretId: SECRETS[key], VersionStage: "AWSCURRENT", MoveToVersionId: before[key].currentVersionId, RemoveFromVersionId: pendingVersionId }));
    }
    await removePending(pending);
    if (firstTime) {
      await ensureAllPlaceholders();
      const retryState = await Promise.all(Object.keys(ROLES).map(async (key) => isPlaceholder(key, await metadata(key))));
      if (!retryState.every(Boolean)) throw new Error("First-time compensation did not reach the three-placeholder retry state.");
    }
    return recoveryRequired ? "operator_recovery_required" : "restored";
  } catch { recoveryRequired = true; return "operator_recovery_required"; }
  finally { compensating = false; }
}

export async function executeExecutor() {
  if (!process.env.DATABASE_URL) throw new Error("Admin DATABASE_URL is unavailable inside the VPC executor.");
  const adminUrl = process.env.DATABASE_URL;
  const admin = client(adminUrl);
  const before = {};
  const previousUrls = {};
  const pending = {};
  let provisionMode = "unknown";
  try {
    phase = "reachability";
    const reachability = await admin.$queryRawUnsafe("SELECT current_database() AS database_name, current_user AS database_user");
    if (reachability[0]?.database_name !== DATABASE || reachability[0]?.database_user !== "mscqr_staging_admin") throw new Error("Staging admin reachability/identity proof failed.");
    if (Object.hasOwn(RLS_SHARED_MODES, MODE)) {
      assertRouteFlagsFalse();
      phase = MODE;
      const evidence = runRlsSharedPhase(MODE, adminUrl);
      safe({ ...evidence, mechanism: "brokered-disposable-ecs-admin-psql-task", phase: "complete" });
      return;
    }
    phase = "capture-secret-metadata";
    for (const key of Object.keys(ROLES)) before[key] = await metadata(key);
    const existingKeys = Object.keys(ROLES).filter((key) => before[key].exists);
    const placeholderFlags = Object.fromEntries(await Promise.all(existingKeys.map(async (key) => [key, await isPlaceholder(key, before[key])])));
    provisionMode = classifyProvisioningMode(before, placeholderFlags);
    if (provisionMode === "rotation" && Object.values(before).some((item) => !item.currentVersionId)) throw Object.assign(new Error("Rotation requires one captured AWSCURRENT version for every target secret."), { code: "MISSING_CURRENT_VERSION" });
    safe({ status: MODE === "probe" ? "probe_passed" : "executor_started", mechanism: "disposable-ecs-admin-task", database: DATABASE, databaseUser: "mscqr_staging_admin", mode: provisionMode, secretMetadata: Object.fromEntries(Object.entries(before).map(([key, item]) => [key, { exists: item.exists, currentVersionId: item.currentVersionId, versionIds: item.versionIds }])) });
    if (MODE === "probe") return;
    assertRouteFlagsFalse();
    const invariants = await databaseInvariants(admin);
    if (MODE === "verify") {
      if (provisionMode !== "rotation") throw new Error("Verify requires three provisioned AWSCURRENT credential secrets.");
      const currentUrls = {};
      for (const key of Object.keys(ROLES)) {
        currentUrls[key] = await currentUrl(key, before[key]);
        if (!currentUrls[key] || new URL(currentUrls[key]).username !== ROLES[key]) throw new Error(`${key} AWSCURRENT credential is invalid.`);
      }
      phase = "role-verification";
      const verification = await verifyCredentials(currentUrls);
      interruptionCheckpoint();
      assertCompleteVerification(verification);
      safe({ status: "verification_complete", phase: "complete", invariants, routeFlags: "all-false", verification });
      return;
    }
    if (MODE !== "provision") throw new Error("Executor mode must be probe, provision, or verify.");
    if (provisionMode === "first-time" || provisionMode === "first-time-recoverable") {
      phase = "normalize-placeholders";
      if (provisionMode === "first-time-recoverable") await setPasswords(admin, {}, true);
      let placeholderCount = 0;
      for (const key of Object.keys(ROLES)) {
        const state = await metadata(key);
        if (!state.exists) await createPlaceholder(key);
        interruptionCheckpoint();
        if (++placeholderCount === 1) failAt("first-placeholder-creation");
        if (placeholderCount === 2) failAt("second-placeholder-creation");
      }
      await ensureAllPlaceholders();
      for (const key of Object.keys(ROLES)) before[key] = await metadata(key);
      failAt("all-placeholders-created");
    }
    if (provisionMode === "rotation") for (const key of Object.keys(ROLES)) { previousUrls[key] = await currentUrl(key, before[key]); if (new URL(previousUrls[key]).username !== ROLES[key]) throw new Error(`${key} prior AWSCURRENT version has the wrong role identity.`); }
    const urls = Object.fromEntries(Object.entries(ROLES).map(([key, role]) => [key, roleUrl(adminUrl, role, password())]));
    phase = "password-transaction";
    await setPasswords(admin, urls);
    interruptionCheckpoint();
    failAt("password-transaction-commit");
    phase = "pending-versions";
    let count = 0;
    for (const key of Object.keys(ROLES)) {
      pending[key] = await putPending(key, urls[key]);
      interruptionCheckpoint();
      if (++count === 1) failAt("first-secret-pending-version");
      if (count === 2) failAt("second-secret-pending-version");
    }
    phase = "role-verification";
    const verification = await verifyCredentials(urls);
    interruptionCheckpoint();
    assertCompleteVerification(verification);
    phase = "promote-versions";
    count = 0;
    for (const key of Object.keys(ROLES)) {
      await sm.send(new UpdateSecretVersionStageCommand({ SecretId: SECRETS[key], VersionStage: "AWSCURRENT", MoveToVersionId: pending[key], ...(before[key].currentVersionId ? { RemoveFromVersionId: before[key].currentVersionId } : {}) }));
      await sm.send(new UpdateSecretVersionStageCommand({ SecretId: SECRETS[key], VersionStage: "AWSPENDING", RemoveFromVersionId: pending[key] }));
      interruptionCheckpoint();
      if (++count === 1) failAt("first-version-promotion");
    }
    safe({ status: "credentials_committed", phase: "complete", mode: provisionMode, pendingVersionIds: pending, previousCurrentVersionIds: Object.fromEntries(Object.entries(before).map(([key, item]) => [key, item.currentVersionId])), verification });
  } catch (error) {
    let rollbackResult = "not_required";
    if (MODE === "provision" && !compensating && ["normalize-placeholders", "password-transaction", "pending-versions", "role-verification", "promote-versions"].includes(phase)) rollbackResult = await compensate(admin, provisionMode, previousUrls, pending, before);
    safe({
      status: "blocked",
      phase,
      failureClassification: error.code || error.name || "EXECUTOR_FAILURE",
      ...(error.safeReason ? { failureReason: error.safeReason } : {}),
      rollbackResult,
      recoveryRequired: rollbackResult === "operator_recovery_required",
    });
    process.exitCode = 2;
  } finally { await admin.$disconnect(); }
}

export function installSignalHandlers() {
  for (const signal of SIGNALS) process.once(signal, () => { interruptionSignal = signal; });
}
if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) { installSignalHandlers(); await executeExecutor(); }
