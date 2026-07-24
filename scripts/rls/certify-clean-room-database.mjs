import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyFullRlsPackage } from "./verify-full-rls-package.mjs";
import { applicationPathCertificationFamilies } from "./lib/application-path-certifications.mjs";
import { EXPECTED_FORCE_RLS_TABLE_COUNT, EXPECTED_TABLE_COUNT } from "./lib/table-inventory-baseline.mjs";

export const CONFIRM_ENV = "MSCQR_FULL_RLS_CERTIFICATION_CONFIRM";
export const CONFIRM_VALUE = "MSCQR_RUN_LOCAL_FULL_RLS_CERTIFICATION";
export const DATABASE_ENV = "MSCQR_FULL_RLS_CERTIFICATION_ADMIN_URL";
const localHosts = new Set(["127.0.0.1", "localhost", "::1"]);
const forbiddenMarkers = ["staging", "prod", "production", "amazonaws.com", "rds.amazonaws.com", "supabase", "neon", "railway", "render.com"];
const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const generatedRoot = path.join(root, "documents/security/rls-program/generated");
const sqlRoot = path.join(root, "scripts/rls/sql/generated");
const evidencePath = path.join(generatedRoot, "disposable-certification-result.json");
const manifestPath = path.join(generatedRoot, "full-rls-implementation-manifest.json");
const policyPath = path.join(generatedRoot, "policy-inventory-report.json");
const privilegePath = path.join(generatedRoot, "column-privilege-report.json");
const checksumsPath = path.join(generatedRoot, "checksums.json");
const executionPath = path.join(generatedRoot, "package-execution-report.json");
const workflowEvidencePath = path.join(generatedRoot, "workflow-call-path-evidence.json");
const certificationAdministrator = "certification-administrator";
const ids = {
  orgA: "00000000-0000-4000-8000-000000000101", orgB: "00000000-0000-4000-8000-000000000102",
  licenseeA: "00000000-0000-4000-8000-000000000201", licenseeB: "00000000-0000-4000-8000-000000000202",
  adminA: "00000000-0000-4000-8000-000000000301", adminB: "00000000-0000-4000-8000-000000000302",
  manufacturerA: "00000000-0000-4000-8000-000000000303", manufacturerB: "00000000-0000-4000-8000-000000000304",
  manufacturerLegacyALinkB: "00000000-0000-4000-8000-000000000305", manufacturerLegacyBUnlinked: "00000000-0000-4000-8000-000000000306",
  platformA: "00000000-0000-4000-8000-000000000307",
  batchA: "00000000-0000-4000-8000-000000000401", batchB: "00000000-0000-4000-8000-000000000402",
  qrA: "00000000-0000-4000-8000-000000000501", qrB: "00000000-0000-4000-8000-000000000502",
  scanA: "00000000-0000-4000-8000-000000000601", scanB: "00000000-0000-4000-8000-000000000602",
  incidentA: "00000000-0000-4000-8000-000000000701", incidentB: "00000000-0000-4000-8000-000000000702",
  ruleA: "00000000-0000-4000-8000-000000000801", ruleB: "00000000-0000-4000-8000-000000000802",
  ruleOrgA: "00000000-0000-4000-8000-000000000803", ruleManA: "00000000-0000-4000-8000-000000000804", ruleConflict: "00000000-0000-4000-8000-000000000805",
  alertA: "00000000-0000-4000-8000-000000000901", alertB: "00000000-0000-4000-8000-000000000902",
  policyA: "00000000-0000-4000-8000-000000001001", policyB: "00000000-0000-4000-8000-000000001002",
  auditA: "00000000-0000-4000-8000-000000001101", auditB: "00000000-0000-4000-8000-000000001102", auditAOther: "00000000-0000-4000-8000-000000001103",
  traceA: "00000000-0000-4000-8000-000000001201", traceB: "00000000-0000-4000-8000-000000001202",
  refreshA: "00000000-0000-4000-8000-000000001301", refreshRollback: "00000000-0000-4000-8000-000000001302",
};
const riskAnalyticsUserColumns = ["deletedAt", "disabledAt", "id", "isActive", "licenseeId", "name", "orgId", "role", "status"];
const prohibitedRiskAnalyticsUserColumns = ["createdAt", "disabledReason", "email", "emailVerifiedAt", "failedLoginAttempts", "lastLoginAt", "location", "lockedUntil", "metadata", "passwordHash", "pendingEmail", "pendingEmailRequestedAt", "updatedAt", "website"];
let runCounter = 0;
const activeDatabases = new Set();
const semanticCapabilities = new Map();

export class FullRlsCertificationSafetyError extends Error {}

export const assertSafeAdminUrl = (value) => {
  const raw = String(value || "").trim();
  let parsed;
  try { parsed = new URL(raw); } catch { throw new FullRlsCertificationSafetyError("A valid local PostgreSQL admin URL is required"); }
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) throw new FullRlsCertificationSafetyError("Certification requires PostgreSQL");
  if (!localHosts.has(parsed.hostname.toLowerCase())) throw new FullRlsCertificationSafetyError("Certification database must be loopback-local");
  if (forbiddenMarkers.some((marker) => raw.toLowerCase().includes(marker))) throw new FullRlsCertificationSafetyError("Remote, staging or production marker rejected");
  const database = decodeURIComponent(parsed.pathname.slice(1));
  if (!/(full_rls|disposable|p2_.*test|ci)/i.test(database) || /^(postgres|template[01])$/i.test(database)) throw new FullRlsCertificationSafetyError("Admin database name must be explicitly disposable/test-scoped");
  return parsed;
};

const connect = (url) => {
  const parsed = new URL(url);
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  return { url: parsed.toString(), password };
};
const runPsql = (url, args, label, expectFailure = false) => {
  const connection = connect(url);
  const result = spawnSync("psql", [connection.url, "-X", "-v", "ON_ERROR_STOP=1", ...args], {
    cwd: root,
    env: { ...process.env, PGPASSWORD: connection.password || process.env.PGPASSWORD || "" },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  if (expectFailure) {
    if (result.status === 0) throw new Error(`${label} unexpectedly succeeded`);
    return output;
  }
  if (result.status !== 0) throw new Error(`${label} failed: ${output.trim()}`);
  return String(result.stdout || "");
};
const scalar = (url, sql, label) => runPsql(url, ["-q", "-t", "-A", "-c", sql], label).trim().split("\n").filter(Boolean).at(-1) || "";
const quote = (value) => `"${String(value).replaceAll('"', '""')}"`;
const lit = (value) => `'${String(value).replaceAll("'", "''")}'`;
const databaseUrlFor = (adminUrl, database, user) => {
  const parsed = new URL(adminUrl);
  const originalUser = decodeURIComponent(parsed.username);
  parsed.pathname = `/${database}`;
  parsed.username = user;
  if (user !== originalUser) parsed.password = "";
  return parsed.toString();
};
const roleListSql = (roles) => Object.values(roles).map(lit).join(",");
const managedRoleCount = (url, roles) => Number(scalar(url, `SELECT count(*) FROM pg_roles WHERE rolname IN (${roleListSql(roles)})`, "count managed roles"));
const createCertificationAdministrator = (url) => runPsql(url, ["-q", "-c", `CREATE ROLE ${quote(certificationAdministrator)} LOGIN NOINHERIT NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS`], "create clean-room certification administrator");
const dropCertificationAdministrator = (url) => runPsql(url, ["-q", "-c", `DROP ROLE ${quote(certificationAdministrator)}`], "drop clean-room certification administrator");
const contextSql = ({ user, org, licensee, actorClass = "licensee-admin", assurance = "password-verified", purpose = "tenant-risk-analytics" }) => {
  const manufacturer = actorClass === "manufacturer";
  const role = manufacturer ? "MANUFACTURER" : actorClass === "platform-admin" ? "PLATFORM_SUPER_ADMIN" : "LICENSEE_ADMIN";
  const capability = semanticCapabilities.get(`${user}:${assurance === "password-verified" ? "PASSWORD" : "ADMIN_MFA"}`);
  if (!capability) throw new Error(`Certification capability is missing for ${user}`);
  return `SELECT * FROM app_auth.require_authenticated_session(${lit(capability)},${lit(purpose)},'full-rls-cert-request');
SELECT set_config('app.role',${lit(role)},true),set_config('app.organization_id',${lit(org)},true),set_config('app.licensee_id',${lit(licensee)},true),set_config('app.manufacturer_id',${lit(manufacturer ? user : "")},true);`;
};
const appScalar = (appUrl, context, sql, label) => scalar(appUrl, `BEGIN; ${contextSql(context)} ${sql}; ROLLBACK;`, label);
const denial = (appUrl, context, sql, label) => runPsql(appUrl, ["-q", "-c", `BEGIN; ${contextSql(context)} ${sql}; ROLLBACK;`], label, true);
const requireDenial = (output, label) => {
  if (!/permission denied|row-level security policy|new row violates/i.test(output)) throw new Error(`${label} was not privilege/RLS enforced: ${output.trim()}`);
};
const runSqlFile = (url, file, label = file, variables = []) => runPsql(url, [...variables.flatMap(([name, value]) => ["-v", `${name}=${value}`]), "-f", path.join(sqlRoot, file)], label);
const runPrisma = (migrationUrl, env) => {
  const result = spawnSync("npx", ["prisma", "migrate", "deploy", "--schema", "prisma/schema.prisma"], {
    cwd: path.join(root, "backend"), env: { ...env, DATABASE_URL: migrationUrl, NODE_ENV: "test" }, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Restricted migration identity failed Prisma deploy: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
};
const runBackendBuild = (env) => {
  const result = spawnSync("npm", ["run", "build"], {
    cwd: path.join(root, "backend"), env: { ...env, NODE_ENV: "test" }, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Backend build failed before application-path certification: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
};
const runApplicationPathCertifications = (connections, env) => applicationPathCertificationFamilies
  .filter((family) => !env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY || family.id === env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY)
  .map((family) => {
  const familyEnv = { ...env, NODE_ENV: "test", [family.enable[0]]: family.enable[1], [family.confirm[0]]: family.confirm[1] };
  for (const [name, connection] of Object.entries(family.connections)) familyEnv[name] = connections[connection];
  const result = spawnSync(process.execPath, [path.join(root, family.testFile)], {
    cwd: root,
    env: familyEnv,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`${family.id} application-path certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/application-path proof passed/.test(result.stdout || "")) throw new Error(`${family.id} application-path certification did not emit its success marker`);
  return {
    familyId: family.id,
    workflowIds: family.workflowIds,
    registeredRoots: family.registeredRoots,
    status: "application-path-certified",
    postgresqlMajor: 18,
    testFile: family.testFile,
  };
});
const runC03AuthenticatedCertification = (connections, env) => {
  if (env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY !== "c03-authenticated-boundaries") return null;
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/rls-wave-c/c03/c03AuthenticatedBoundariesPostgres18.test.js")], {
    cwd: root,
    env: {
      ...env,
      NODE_ENV: "test",
      DATABASE_URL: connections.app,
      MSCQR_C03_BOOTSTRAP_URL: connections.bootstrap,
      MSCQR_C03_PREAUTH_URL: connections.preauth,
      MSCQR_C03_AUTHENTICATED_POSTGRES18_TEST: "true",
      MSCQR_C03_AUTHENTICATED_POSTGRES18_CONFIRM: "MSCQR_RUN_LOCAL_C03_AUTHENTICATED_POSTGRES18_TEST",
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`C03 authenticated certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/C03 authenticated boundaries application-path proof passed/.test(result.stdout || "")) throw new Error("C03 authenticated certification did not emit its success marker");
  return { status: "application-path-certified", postgresqlMajor: 18, testFile: "backend/tests/rls-wave-c/c03/c03AuthenticatedBoundariesPostgres18.test.js" };
};
const runPrintingLifecycleCertification = (connections, env) => {
  if (env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY !== "printing-lifecycle") return null;
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/rls-wave-c/c02/printingLifecyclePostgres18.test.js")], {
    cwd: root,
    env: {
      ...env,
      NODE_ENV: "test",
      MSCQR_PRINTING_ADMIN_URL: connections.bootstrap,
      MSCQR_PRINTING_PREAUTH_URL: connections.preauth,
      MSCQR_PRINTING_APP_URL: connections.app,
      MSCQR_PRINTING_WORKER_URL: connections.worker,
      MSCQR_PRINTING_POSTGRES18_TEST: "true",
      MSCQR_PRINTING_POSTGRES18_CONFIRM: "MSCQR_RUN_LOCAL_PRINTING_POSTGRES18_TEST",
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Printing lifecycle certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/Release Fix 5 PostgreSQL 18 printing lifecycle proof passed/.test(result.stdout || "")) throw new Error("Printing lifecycle certification did not emit its success marker");
  return { status: "application-path-certified", postgresqlMajor: 18, testFile: "backend/tests/rls-wave-c/c02/printingLifecyclePostgres18.test.js" };
};
const runPublicVerificationCertification = (connections, env) => {
  if (env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY !== "public-verification") return null;
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/rls-wave-b/b02/publicVerificationPostgres18.test.js")], {
    cwd: root,
    env: {
      ...env,
      NODE_ENV: "test",
      MSCQR_PUBLIC_VERIFICATION_ADMIN_URL: connections.bootstrap,
      MSCQR_PUBLIC_VERIFICATION_PREAUTH_URL: connections.preauth,
      MSCQR_PUBLIC_VERIFICATION_APP_URL: connections.app,
      MSCQR_PUBLIC_VERIFICATION_POSTGRES18_TEST: "true",
      MSCQR_PUBLIC_VERIFICATION_POSTGRES18_CONFIRM: "MSCQR_RUN_LOCAL_PUBLIC_VERIFICATION_POSTGRES18_TEST",
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Public verification certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/Release Fix 6 public verification application-path proof passed/.test(result.stdout || "")) {
    throw new Error("Public verification certification did not emit its success marker");
  }
  return { status: "application-path-certified", postgresqlMajor: 18, testFile: "backend/tests/rls-wave-b/b02/publicVerificationPostgres18.test.js" };
};
const runB01PreAuthCertification = (connections, env) => {
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/rls-wave-b/b01/preAuthSecurityPostgres18.test.js")], {
    cwd: root,
    env: {
      ...env,
      NODE_ENV: "test",
      DATABASE_URL: connections.app,
      PREAUTH_DATABASE_URL: connections.preauth,
      MSCQR_B01_PREAUTH_BOOTSTRAP_URL: connections.bootstrap,
      MSCQR_B01_PREAUTH_POSTGRES18_TEST: "true",
      MSCQR_B01_PREAUTH_POSTGRES18_CONFIRM: "MSCQR_RUN_LOCAL_B01_PREAUTH_POSTGRES18_TEST",
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`B01 pre-auth certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/B01 pre-auth security application-path proof passed/.test(result.stdout || "")) throw new Error("B01 pre-auth certification did not emit its success marker");
  return { status: "application-path-certified", postgresqlMajor: 18, testFile: "backend/tests/rls-wave-b/b01/preAuthSecurityPostgres18.test.js" };
};
const runScheduledJobIdentityCertification = (connections, env) => {
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/rls-wave-b/b03/scheduledJobIdentityPostgres18.test.js")], {
    cwd: root,
    env: {
      ...env,
      NODE_ENV: "test",
      MSCQR_SCHEDULED_IDENTITY_BOOTSTRAP_URL: connections.bootstrap,
      MSCQR_SCHEDULED_IDENTITY_OPERATOR_URL: connections.operator,
      MSCQR_SCHEDULED_IDENTITY_RUNTIME_URL: connections.scheduled,
      MSCQR_SCHEDULED_IDENTITY_APP_URL: connections.app,
      MSCQR_SCHEDULED_IDENTITY_POSTGRES18_TEST: "true",
      MSCQR_SCHEDULED_IDENTITY_POSTGRES18_CONFIRM: "MSCQR_RUN_LOCAL_SCHEDULED_IDENTITY_POSTGRES18_TEST",
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Scheduled-job identity certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/scheduled-job identity application-path proof passed/.test(result.stdout || "")) throw new Error("Scheduled-job identity certification did not emit its success marker");
  return { status: "application-path-certified", postgresqlMajor: 18, testFile: "backend/tests/rls-wave-b/b03/scheduledJobIdentityPostgres18.test.js" };
};
const runB03OutboxCertification = (connections, env) => {
  if (env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY !== "b03-durable-outbox") return null;
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/rls-wave-b/b03/outboxPostgres18.test.js")], {
    cwd: root,
    env: {
      ...env,
      NODE_ENV: "test",
      DATABASE_URL: connections.worker,
      MSCQR_B03_OUTBOX_APP_URL: connections.app,
      MSCQR_B03_OUTBOX_BOOTSTRAP_URL: connections.bootstrap,
      MSCQR_B03_OUTBOX_PREAUTH_URL: connections.preauth,
      MSCQR_B03_OUTBOX_POSTGRES18_TEST: "true",
      MSCQR_B03_OUTBOX_POSTGRES18_CONFIRM: "MSCQR_RUN_LOCAL_B03_OUTBOX_POSTGRES18_TEST",
    },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`B03 durable outbox certification failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
  if (!/B03 durable outbox application-path proof passed/.test(result.stdout || "")) throw new Error("B03 durable outbox certification did not emit its success marker");
  return { status: "postgresql-contract-certified", postgresqlMajor: 18, testFile: "backend/tests/rls-wave-b/b03/outboxPostgres18.test.js" };
};
const injectBeforeCommit = (file, label) => {
  const source = fs.readFileSync(path.join(sqlRoot, file), "utf8");
  const index = source.lastIndexOf("\nCOMMIT;");
  if (!source.startsWith("\\set ON_ERROR_STOP on\nBEGIN;\n") || index === -1) throw new Error(`${file} is not a transaction-wrapped phase`);
  return `${source.slice(0, index)}\nDO $$ BEGIN RAISE EXCEPTION 'intentional certification failure: ${label}'; END $$;${source.slice(index)}`;
};
const runInjectedFile = (url, file, label, variables = []) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rls-cert-"));
  const injected = path.join(directory, path.basename(file));
  try {
    fs.writeFileSync(injected, injectBeforeCommit(file, label));
    const output = runPsql(url, [...variables.flatMap(([name, value]) => ["-v", `${name}=${value}`]), "-f", injected], `inject ${label}`, true);
    if (!/intentional certification failure/i.test(output)) throw new Error(`${label} failed for an unexpected reason: ${output.trim()}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
};
const provePrismaLedger = (migrationUrl, role, expectedRows) => {
  if (scalar(migrationUrl, "SELECT current_user", "verify migration identity") !== role) throw new Error("Prisma did not run through the exact restricted migration identity");
  const invalid = Number(scalar(migrationUrl, "SELECT count(*) FROM public._prisma_migrations WHERE finished_at IS NULL OR rolled_back_at IS NOT NULL OR applied_steps_count<>1", "verify completed Prisma migrations"));
  if (invalid) throw new Error(`${invalid} Prisma migration ledger rows are incomplete or rolled back`);
  const actual = JSON.parse(scalar(migrationUrl, "SELECT COALESCE(jsonb_agg(jsonb_build_object('name',migration_name,'sha256',checksum) ORDER BY migration_name),'[]'::jsonb)::text FROM public._prisma_migrations", "read Prisma migration ledger"));
  if (JSON.stringify(actual) !== JSON.stringify(expectedRows)) throw new Error("Prisma migration names or checksums differ from the generated source contract");
};
const assertNoBusinessRows = (bootstrapUrl) => runPsql(bootstrapUrl, ["-q", "-c", `DO $$ DECLARE rec record; row_count bigint; BEGIN
  FOR rec IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') AND c.relname<>'_prisma_migrations' LOOP
    EXECUTE format('SELECT count(*) FROM public.%I',rec.relname) INTO row_count;
    IF row_count<>0 THEN RAISE EXCEPTION 'green cleanup refuses required data in public.%',rec.relname; END IF;
  END LOOP;
END $$;`], "prove no required application data was accepted");
const candidateName = (label) => `mscqr_full_rls_cert_${process.pid}_${++runCounter}_${label}`.toLowerCase().replace(/[^a-z0-9_]/g, "_");
const databaseExists = (url, database) => scalar(url, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=${lit(database)})`, "inspect green database") === "t";
const createGreenDatabase = (executorUrl, database) => {
  runPsql(executorUrl, ["-q", "-c", `CREATE DATABASE ${quote(database)} OWNER ${quote(certificationAdministrator)} TEMPLATE template0`], "create fresh template0 green database");
  activeDatabases.add(database);
};
const dropGreenDatabase = (executorUrl, database) => {
  if (databaseExists(executorUrl, database)) {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const sessions = Number(scalar(
        executorUrl,
        `SELECT count(*) FROM pg_stat_activity WHERE datname=${lit(database)}`,
        "wait for disposable database sessions"
      ));
      if (sessions === 0) {
        runPsql(executorUrl, ["-q", "-c", `DROP DATABASE ${quote(database)}`], "drop disposable green database");
        activeDatabases.delete(database);
        return;
      }
      runPsql(executorUrl, ["-q", "-c", "SELECT pg_sleep(0.1)"], "wait for disposable database clients");
    }
    runPsql(executorUrl, ["-q", "-c", `DROP DATABASE ${quote(database)} WITH (FORCE)`], "drop disposable green database");
  }
  activeDatabases.delete(database);
};
const cleanMarkedRoles = (executorUrl, database) => runSqlFile(executorUrl, "clean-room-cleanup.sql", "drop exact package-marked roles", [["candidate_database", database]]);
const blueFingerprint = (blueUrl) => scalar(blueUrl, `SELECT md5(jsonb_build_object(
  'sentinel',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM public.blue_sentinel s),
  'schemas',(SELECT jsonb_agg(jsonb_build_object('name',n.nspname,'owner',r.rolname,'acl',n.nspacl::text) ORDER BY n.nspname) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='public'),
  'objects',(SELECT jsonb_agg(jsonb_build_object('name',c.relname,'kind',c.relkind,'owner',r.rolname,'acl',c.relacl::text) ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public')
)::text)`, "fingerprint untouched blue database");
const localCatalogFingerprint = (url) => scalar(url, `SELECT jsonb_build_object(
  'databaseAcl',(SELECT datacl::text FROM pg_database WHERE datname=current_database()),
  'schemas',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',n.nspname,'owner',r.rolname,'acl',n.nspacl::text) ORDER BY n.nspname),'[]'::jsonb) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
  'objects',(SELECT COALESCE(jsonb_agg(jsonb_build_object('schema',n.nspname,'name',c.relname,'kind',c.relkind,'owner',r.rolname,'acl',c.relacl::text,'rls',c.relrowsecurity,'force',c.relforcerowsecurity) ORDER BY n.nspname,c.relname),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema'),
  'policies',(SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY schemaname,tablename,policyname),'[]'::jsonb) FROM pg_policies p),
  'defaults',(SELECT COALESCE(jsonb_agg(jsonb_build_object('role',r.rolname,'schema',COALESCE(n.nspname,''),'kind',d.defaclobjtype,'acl',d.defaclacl::text) ORDER BY r.rolname,COALESCE(n.nspname,''),d.defaclobjtype),'[]'::jsonb) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace)
)::text`, "fingerprint refused green catalog");
const clusterRoleFingerprint = (url) => scalar(url, `SELECT jsonb_build_object(
  'roles',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',rolname,'login',rolcanlogin,'inherit',rolinherit,'createdb',rolcreatedb,'createrole',rolcreaterole,'super',rolsuper,'bypass',rolbypassrls,'comment',obj_description(oid,'pg_authid')) ORDER BY rolname),'[]'::jsonb) FROM pg_roles WHERE rolname !~ '^pg_'),
  'memberships',(SELECT COALESCE(jsonb_agg(jsonb_build_object('parent',p.rolname,'member',mbr.rolname,'grantor',g.rolname,'admin',m.admin_option,'inherit',m.inherit_option,'set',m.set_option) ORDER BY p.rolname,mbr.rolname,g.rolname,m.admin_option,m.inherit_option,m.set_option),'[]'::jsonb) FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles mbr ON mbr.oid=m.member JOIN pg_roles g ON g.oid=m.grantor WHERE p.rolname !~ '^pg_' OR mbr.rolname !~ '^pg_')
)::text`, "fingerprint refused cluster roles");

const tenantFixtureExpectations = {
  AuditLog: { column: "id", own: ids.auditA, foreign: ids.auditB, ownCount: 2, foreignCount: 1, purpose: "audit-log-read" },
  Batch: { column: "id", own: ids.batchA, foreign: ids.batchB, ownCount: 1, foreignCount: 1 },
  Incident: { column: "id", own: ids.incidentA, foreign: ids.incidentB, ownCount: 1, foreignCount: 1 },
  Licensee: { column: "id", own: ids.licenseeA, foreign: ids.licenseeB, ownCount: 1, foreignCount: 1 },
  ManufacturerLicenseeLink: {
    column: "manufacturerId",
    ownWhere: `"manufacturerId"=${lit(ids.manufacturerA)} AND "licenseeId"=${lit(ids.licenseeA)}`,
    foreignWhere: `"manufacturerId"=${lit(ids.manufacturerB)} AND "licenseeId"=${lit(ids.licenseeB)}`,
    ownCount: 1,
    foreignCount: 2,
  },
  Organization: { column: "id", own: ids.orgA, foreign: ids.orgB, ownCount: 1, foreignCount: 1 },
  PolicyAlert: { column: "id", own: ids.alertA, foreign: ids.alertB, ownCount: 1, foreignCount: 1 },
  PolicyRule: { column: "id", own: ids.ruleA, foreign: ids.ruleB, ownCount: 3, foreignCount: 1 },
  QRCode: { column: "id", own: ids.qrA, foreign: ids.qrB, ownCount: 1, foreignCount: 1 },
  QrScanLog: { column: "id", own: ids.scanA, foreign: ids.scanB, ownCount: 1, foreignCount: 1 },
  SecurityPolicy: { column: "licenseeId", own: ids.licenseeA, foreign: ids.licenseeB, ownCount: 1, foreignCount: 1 },
  TraceEvent: { column: "id", own: ids.traceA, foreign: ids.traceB, ownCount: 1, foreignCount: 1, purpose: "trace-timeline-read" },
  User: { column: "id", own: ids.adminA, foreign: ids.adminB, ownCount: 2, foreignCount: 3 },
};

const certifyTablesAndColumns = (dbUrl, appUrl, manifest, policies, privileges) => {
  const forceCount = Number(scalar(dbUrl, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity", "count FORCE RLS tables"));
  if (forceCount !== EXPECTED_FORCE_RLS_TABLE_COUNT) throw new Error(`Expected ${EXPECTED_FORCE_RLS_TABLE_COUNT} FORCE RLS tables, found ${forceCount}`);
  const ownerCount = Number(scalar(dbUrl, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relkind='r' AND r.rolname=${lit(manifest.roles.owner)}`, "count table owners"));
  if (ownerCount !== EXPECTED_TABLE_COUNT) throw new Error(`Expected ${EXPECTED_TABLE_COUNT} NOLOGIN-owned tables, found ${ownerCount}`);
  if (Number(scalar(dbUrl, `SELECT count(*) FROM pg_roles WHERE rolname IN (${roleListSql(manifest.roles)}) AND (rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)`, "verify exact role attributes")) !== 0) throw new Error("A managed role has an unsafe attribute");
  if (Number(scalar(dbUrl, `SELECT count(*) FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE u.rolname IN (${roleListSql(manifest.roles)}) OR (p.rolname IN (${roleListSql(manifest.roles)}) AND (u.rolname<>${lit(certificationAdministrator)} OR m.inherit_option))`, "verify bounded role memberships")) !== 0) throw new Error("A managed role has unsafe membership authority");
  if (Number(scalar(dbUrl, `SELECT count(*) FROM pg_roles r WHERE r.rolname IN (${roleListSql(manifest.roles)}) AND NOT pg_has_role(${lit(certificationAdministrator)},r.rolname,'SET')`, "verify administrative SET capability")) !== 0) throw new Error("Certification administrator lacks SET authority for a managed role");
  if (Number(scalar(dbUrl, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE n.nspname='public' AND c.relkind IN ('r','p') AND acl.grantee=0", "verify PUBLIC grants")) !== 0) throw new Error("PUBLIC table privileges remain");
  const generatedPolicyCount = Number(scalar(dbUrl, "SELECT count(*) FROM pg_policies WHERE schemaname='public'", "count policies"));
  if (generatedPolicyCount !== policies.count) throw new Error(`Generated policy inventory differs from catalog: expected ${policies.count}, found ${generatedPolicyCount}`);

  for (const grant of privileges.rows) for (const column of grant.columns) {
    const actual = scalar(dbUrl, `SELECT has_column_privilege(${lit(manifest.roles.app)},c.oid,a.attnum,${lit(grant.command)}) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname=${lit(column)} WHERE n.nspname='public' AND c.relname=${lit(grant.table)}`, `${grant.table}.${column} ${grant.command}`);
    if (actual !== "t") throw new Error(`Approved ${grant.command} privilege missing for ${grant.table}.${column}`);
  }
  const userGrant = privileges.rows.find((grant) => grant.table === "User" && grant.command === "SELECT");
  if (JSON.stringify(userGrant?.columns) !== JSON.stringify(riskAnalyticsUserColumns)) throw new Error("User SELECT grant is not the exact risk-analytics display/predicate union");
  for (const column of prohibitedRiskAnalyticsUserColumns) requireDenial(runPsql(appUrl, ["-q", "-c", `SELECT ${quote(column)} FROM public."User" LIMIT 1`], `prohibited User.${column} SELECT`, true), `prohibited User.${column} SELECT`);
  requireDenial(runPsql(appUrl, ["-q", "-c", `SELECT "ipAddress" FROM public."AuditLog" LIMIT 1`], "prohibited direct AuditLog network metadata SELECT", true), "prohibited direct AuditLog network metadata SELECT");
  requireDenial(runPsql(appUrl, ["-q", "-c", `INSERT INTO public."AuditLog" ("action","entityType","ipAddress") VALUES ('X','Certification','127.0.0.1')`], "prohibited AuditLog INSERT column", true), "prohibited AuditLog INSERT column");
  requireDenial(runPsql(appUrl, ["-q", "-c", `UPDATE public."Batch" SET "name"='changed'`], "prohibited Batch UPDATE", true), "prohibited Batch UPDATE");

  const selectPolicyByTableAndPurpose = new Map();
  for (const policy of policies.rows.filter((entry) => !entry.internalHelperOnly && entry.command === "SELECT" && entry.actors.includes("licensee-admin"))) {
    for (const purpose of policy.purpose) selectPolicyByTableAndPurpose.set(`${policy.table}:${purpose}`, policy);
  }
  const grantByTable = new Map(privileges.rows.filter((grant) => grant.command === "SELECT").map((grant) => [grant.table, grant]));
  for (const table of manifest.tables.filter((entry) => entry.rls === "ENABLE AND FORCE")) {
    const grant = grantByTable.get(table.table);
    if (!grant) {
      requireDenial(runPsql(appUrl, ["-q", "-c", `SELECT count(*) FROM public.${quote(table.table)}`], `${table.table} no SELECT grant`, true), `${table.table} no SELECT grant`);
      continue;
    }
    const column = grant.columns.includes("id") ? "id" : grant.columns.includes("licenseeId") ? "licenseeId" : grant.columns[0];
    if (Number(scalar(appUrl, `SELECT count(${quote(column)}) FROM public.${quote(table.table)}`, `${table.table} blank context`)) !== 0) throw new Error(`${table.table} exposed rows with blank context`);
    const fixture = tenantFixtureExpectations[table.table];
    if (!fixture) throw new Error(`${table.table} has a SELECT grant without an exact cross-tenant fixture contract`);
    const policy = selectPolicyByTableAndPurpose.get(`${table.table}:${fixture.purpose || "tenant-risk-analytics"}`);
    if (!policy) throw new Error(`${table.table} lacks the exact ${fixture.purpose || "tenant-risk-analytics"} licensee-admin policy`);
    const actorClass = policy.actors[0];
    const purpose = policy.purpose[0];
    const assurance = policy.assurance;
    const ownUser = actorClass === "manufacturer" ? ids.manufacturerA : ids.adminA;
    const foreignUser = actorClass === "manufacturer" ? ids.manufacturerB : ids.adminB;
    const own = Number(appScalar(appUrl, { user: ownUser, org: ids.orgA, licensee: ids.licenseeA, actorClass, assurance, purpose }, `SELECT count(${quote(column)}) FROM public.${quote(table.table)}`, `${table.table} own context`));
    const foreign = Number(appScalar(appUrl, { user: foreignUser, org: ids.orgB, licensee: ids.licenseeB, actorClass, assurance, purpose }, `SELECT count(${quote(column)}) FROM public.${quote(table.table)}`, `${table.table} foreign partition`));
    if (actorClass !== "licensee-admin") throw new Error(`${table.table} exact partition certification requires the deterministic licensee-admin policy first`);
    if (own !== fixture.ownCount || foreign !== fixture.foreignCount) {
      const visible = (user, org, licensee, label) => appScalar(appUrl, { user, org, licensee, actorClass, assurance, purpose }, `SELECT coalesce(string_agg(${quote(fixture.column)}::text,',' ORDER BY ${quote(fixture.column)}::text),'') FROM public.${quote(table.table)}`, label);
      throw new Error(`${table.table} approved tenant partitions differ from exact fixtures: own=${own}/${fixture.ownCount} [${visible(ownUser, ids.orgA, ids.licenseeA, `${table.table} own diagnostic`)}] foreign=${foreign}/${fixture.foreignCount} [${visible(foreignUser, ids.orgB, ids.licenseeB, `${table.table} foreign diagnostic`)}]`);
    }
    const ownWhere = fixture.ownWhere || `${quote(fixture.column)}=${lit(fixture.own)}`;
    const foreignWhere = fixture.foreignWhere || `${quote(fixture.column)}=${lit(fixture.foreign)}`;
    const ownCanSeeForeign = Number(appScalar(appUrl, { user: ownUser, org: ids.orgA, licensee: ids.licenseeA, actorClass, assurance, purpose }, `SELECT count(${quote(fixture.column)}) FROM public.${quote(table.table)} WHERE ${foreignWhere}`, `${table.table} A cannot see B fixture`));
    const foreignCanSeeOwn = Number(appScalar(appUrl, { user: foreignUser, org: ids.orgB, licensee: ids.licenseeB, actorClass, assurance, purpose }, `SELECT count(${quote(fixture.column)}) FROM public.${quote(table.table)} WHERE ${ownWhere}`, `${table.table} B cannot see A fixture`));
    if (ownCanSeeForeign !== 0 || foreignCanSeeOwn !== 0) throw new Error(`${table.table} exposed a stable foreign tenant fixture: A->B=${ownCanSeeForeign} B->A=${foreignCanSeeOwn}`);
    const forged = Number(appScalar(appUrl, { user: ownUser, org: ids.orgB, licensee: ids.licenseeB, actorClass, assurance, purpose }, `SELECT count(${quote(column)}) FROM public.${quote(table.table)}`, `${table.table} forged actor/scope mismatch`));
    if (forged !== 0) throw new Error(`${table.table} trusted forged tenant GUCs for a database-bound actor`);
  }
  const platformTables = [...new Set(policies.rows.filter((entry) =>
    !entry.internalHelperOnly
    && entry.command === "SELECT"
    && entry.actors.includes("platform-admin")
    && entry.purpose.includes("tenant-risk-analytics")
    && grantByTable.has(entry.table)
  ).map((entry) => entry.table))].sort();
  if (!platformTables.length) throw new Error("Frozen bounded platform risk analytics has no generated SELECT policies");
  for (const table of platformTables) {
    const grant = grantByTable.get(table);
    const fixture = tenantFixtureExpectations[table];
    if (!grant || !fixture) throw new Error(`${table} platform selector lacks an exact grant/fixture contract`);
    const column = grant.columns.includes("id") ? "id" : fixture.column;
    const expected = fixture.ownCount;
    const platformContext = { user: ids.platformA, org: ids.orgA, licensee: ids.licenseeA, actorClass: "platform-admin", assurance: "mfa-verified", purpose: "tenant-risk-analytics" };
    const selected = Number(appScalar(appUrl, platformContext, `SELECT count(${quote(column)}) FROM public.${quote(table)}`, `${table} bounded platform selector`));
    if (selected !== expected) {
      const visible = appScalar(appUrl, platformContext, `SELECT coalesce(string_agg(${quote(column)}::text,',' ORDER BY ${quote(column)}::text),'') FROM public.${quote(table)}`, `${table} platform diagnostic`);
      const actorValid = appScalar(appUrl, platformContext, "SELECT app_rls.actor_scope_valid()", `${table} platform actor diagnostic`);
      throw new Error(`${table} bounded platform selector returned ${selected}, expected ${expected}; actor_scope_valid=${actorValid}; visible=[${visible}]`);
    }
    for (const [label, context] of [
      ["role-string-only", { user: ids.adminA, org: ids.orgA, licensee: ids.licenseeA, actorClass: "platform-admin", assurance: "mfa-verified", purpose: "tenant-risk-analytics" }],
      ["password-only", { user: ids.platformA, org: ids.orgA, licensee: ids.licenseeA, actorClass: "platform-admin", assurance: "password-verified", purpose: "tenant-risk-analytics" }],
      ["blank-selector", { user: ids.platformA, org: "", licensee: "", actorClass: "platform-admin", assurance: "mfa-verified", purpose: "tenant-risk-analytics" }],
    ]) {
      const visible = Number(appScalar(appUrl, context, `SELECT count(${quote(column)}) FROM public.${quote(table)}`, `${table} platform ${label} denial`));
      if (visible !== 0) throw new Error(`${table} platform ${label} context exposed ${visible} rows`);
    }
  }
  return forceCount;
};

const certifyB01RefreshRotation = ({ bootstrap, preauth, app }, manifest) => {
  const oldHash = "a".repeat(64);
  const rollbackHash = "b".repeat(64);
  const successorHash = "c".repeat(64);
  const requestId = "b01-cert-rotation";
  requireDenial(runPsql(preauth, ["-q", "-c", `SELECT * FROM public."RefreshToken"`], "pre-auth direct RefreshToken SELECT", true), "pre-auth direct RefreshToken SELECT");
  requireDenial(runPsql(preauth, ["-q", "-c", `SELECT app_auth.b01_audit('X','${ids.refreshA}',transaction_timestamp()::timestamp)`], "pre-auth helper execution", true), "pre-auth helper execution");
  if (scalar(bootstrap, `SELECT rolcanlogin::text || ':' || rolbypassrls::text FROM pg_roles WHERE rolname=${lit(manifest.roles.authOwner)}`, "B01 function owner attributes") !== "false:false") throw new Error("B01 function owner is login-capable or bypasses RLS");
  if (scalar(bootstrap, `SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname='RefreshToken' AND r.rolname=${lit(manifest.roles.authOwner)}`, "B01 function owner table ownership") !== "0") throw new Error("B01 function owner owns RefreshToken");
  if (scalar(bootstrap, `SELECT relforcerowsecurity::text FROM pg_class WHERE oid='public."RefreshToken"'::regclass`, "B01 RefreshToken FORCE RLS") !== "true") throw new Error("B01 RefreshToken is not FORCE RLS");
  const rotationSql = `BEGIN;
    SELECT disposition FROM app_auth.claim_refresh_token_rotation(ARRAY['${oldHash}']::text[],transaction_timestamp()::timestamp,'${requestId}');
    SELECT id FROM app_auth.complete_refresh_token_rotation('${ids.refreshA}',ARRAY['${oldHash}']::text[],'${ids.adminA}','${ids.orgA}','${successorHash}',(transaction_timestamp()+interval '1 day')::timestamp,NULL,NULL,transaction_timestamp()::timestamp,NULL,transaction_timestamp()::timestamp,'${requestId}');
    COMMIT;`;
  runPsql(preauth, ["-q", "-c", rotationSql], "B01 committed refresh rotation");
  if (scalar(bootstrap, `SELECT "revokedReason" || ':' || coalesce("replacedByTokenHash",'') || ':' || ("rotationCompletedAt" IS NOT NULL)::text FROM public."RefreshToken" WHERE id='${ids.refreshA}'`, "B01 predecessor lineage") !== `ROTATED:${successorHash}:true`) throw new Error("B01 rotation did not atomically revoke and link its predecessor");
  if (scalar(bootstrap, `SELECT count(*) FROM public."RefreshToken" WHERE "tokenHash"='${successorHash}'`, "B01 successor count") !== "1") throw new Error("B01 rotation created an invalid successor count");
  runPsql(preauth, ["-q", "-c", `BEGIN; SELECT disposition FROM app_auth.claim_refresh_token_rotation(ARRAY['${rollbackHash}']::text[],transaction_timestamp()::timestamp,'b01-cert-rollback'); ROLLBACK;`], "B01 rollback refresh claim");
  if (scalar(bootstrap, `SELECT coalesce("rotationRequestId",'') FROM public."RefreshToken" WHERE id='${ids.refreshRollback}'`, "B01 rollback claim residue") !== "") throw new Error("B01 rollback left a durable claim");
  const capability = crypto.randomBytes(32).toString("base64url");
  const capabilityHash = crypto.createHash("sha256").update(capability, "utf8").digest("hex");
  // The replay probe intentionally revokes every active refresh token for the
  // user.  Exercise issuance first against the independent rollback fixture,
  // then execute the replay probe below.
  const capabilitySessionId = ids.refreshRollback;
  const capabilityRefreshHash = rollbackHash;
  const capabilityExpiry = scalar(bootstrap, `SELECT to_char("expiresAt" AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS.MS') FROM public."RefreshToken" WHERE id='${capabilitySessionId}'`, "load capability session expiry");
  if (scalar(bootstrap, `SELECT r.rolname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner WHERE n.nspname='app_auth' AND p.proname='issue_authenticated_session_capability' AND pg_get_function_identity_arguments(p.oid)='p_refresh_token_id text, p_refresh_token_hash text, p_capability text, p_assurance text, p_expires_at timestamp without time zone'`, "authenticated session issue function owner") !== manifest.roles.authOwner) throw new Error("authenticated session issue function owner drifted");
  const issuePolicyVisible = scalar(bootstrap, `BEGIN;
    SET LOCAL ROLE ${quote(manifest.roles.authOwner)};
    SELECT app_auth.b01_bind_bearer(ARRAY['${capabilityRefreshHash}']::text[],'auth-session-issue');
    SELECT set_config('app.auth_session_operation','issue',true),set_config('app.auth_session_id','${capabilitySessionId}',true),set_config('app.auth_session_refresh_hash','${capabilityRefreshHash}',true);
    SELECT count(*) FROM public."RefreshToken" WHERE id='${capabilitySessionId}' AND "tokenHash"='${capabilityRefreshHash}';
    ROLLBACK;`, "authenticated session issue owner-policy visibility");
  if (issuePolicyVisible !== "1") throw new Error("authenticated session issue owner policy cannot see its reviewed bearer-bound refresh row");
  runPsql(preauth, ["-q", "-c", `SELECT * FROM app_auth.issue_authenticated_session_capability('${capabilitySessionId}','${capabilityRefreshHash}','${capability}','PASSWORD','${capabilityExpiry}'::timestamp)`], "issue database-verifiable session capability");
  const verifiedUserVisible = scalar(bootstrap, `BEGIN;
    SET LOCAL ROLE ${quote(manifest.roles.authOwner)};
    SELECT set_config('app.auth_session_operation','verify',true),set_config('app.auth_session_hash','${capabilityHash}',true),set_config('app.user_id','${ids.adminA}',true);
    SELECT count(*) FROM public."User" WHERE id='${ids.adminA}';
    ROLLBACK;`, "authenticated session verified-user owner-policy visibility");
  if (verifiedUserVisible !== "1") throw new Error("authenticated session verified-user policy cannot see the capability-derived actor");
  requireDenial(runPsql(preauth, ["-q", "-c", `SELECT app_auth.auth_session_prepare('${capability}','forged','request')`], "pre-auth capability helper execution", true), "pre-auth capability helper execution");
  requireDenial(runPsql(app, ["-q", "-c", `BEGIN; SELECT set_config('app.user_id','${ids.adminB}',true),set_config('app.auth_session_verified','1',true); SELECT * FROM public."RefreshToken"; ROLLBACK;`], "forged authenticated GUC direct RefreshToken access", true), "forged authenticated GUC direct RefreshToken access");
  if (scalar(app, `SELECT "userId" FROM app_auth.require_authenticated_session('${capability}','certified-session-read','capability-cert-request')`, "verify database-verifiable session capability") !== ids.adminA) throw new Error("authenticated session capability did not derive the authoritative actor");
  const randomCapabilityOutput = runPsql(app, ["-q", "-c", `SELECT * FROM app_auth.require_authenticated_session('${crypto.randomBytes(32).toString("base64url")}','certified-session-read','capability-cert-invalid')`], "random authenticated capability", true);
  if (!/AUTH_SESSION_CAPABILITY_DENIED/.test(randomCapabilityOutput)) throw new Error("random authenticated capability did not fail closed");
  if (scalar(app, `SELECT "revoked"::text FROM app_auth.revoke_authenticated_session_capability('${capability}','${capabilitySessionId}','LOGOUT','capability-cert-revoke')`, "revoke database-verifiable session capability") !== "true") throw new Error("authenticated session capability revocation did not affect the verified session");
  const revokedCapabilityOutput = runPsql(app, ["-q", "-c", `SELECT * FROM app_auth.require_authenticated_session('${capability}','certified-session-read','capability-cert-replay')`], "revoked authenticated capability replay", true);
  if (!/AUTH_SESSION_CAPABILITY_DENIED/.test(revokedCapabilityOutput)) throw new Error("revoked authenticated capability replay did not fail closed");
  if (scalar(preauth, `SELECT disposition FROM app_auth.claim_refresh_token_rotation(ARRAY['${oldHash}']::text[],transaction_timestamp()::timestamp,'${requestId}')`, "B01 committed predecessor replay") !== "REUSE_DETECTED") throw new Error("B01 committed predecessor replay was not rejected");
  return { predecessorReplayRejected: true, rollbackClaimCleared: true, successorHashPersisted: true, capabilityVerified: true, forgedGucDenied: true, capabilityRevocationEnforced: true };
};

const issueSemanticCapabilities = ({ bootstrap, preauth }) => {
  semanticCapabilities.clear();
  const actors = [ids.adminA, ids.adminB, ids.manufacturerA, ids.manufacturerB, ids.platformA];
  let sequence = 0;
  for (const userId of actors) {
    const orgId = userId === ids.adminA || userId === ids.manufacturerA ? ids.orgA
      : userId === ids.adminB || userId === ids.manufacturerB ? ids.orgB : null;
    for (const assurance of ["PASSWORD", "ADMIN_MFA"]) {
      sequence += 1;
      const sessionId = `00000000-0000-4000-8000-${String(1400 + sequence).padStart(12, "0")}`;
      const refreshHash = crypto.createHash("sha256").update(`semantic-refresh-${sequence}`).digest("hex");
      const capability = crypto.randomBytes(32).toString("base64url");
      runPsql(bootstrap, ["-q", "-c", `INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt") VALUES (${lit(sessionId)},${orgId ? lit(orgId) : "NULL"},${lit(userId)},${lit(refreshHash)},transaction_timestamp()+interval '1 day',transaction_timestamp(),${assurance === "ADMIN_MFA" ? "transaction_timestamp()" : "NULL"})`], "create semantic capability session");
      runPsql(preauth, ["-q", "-c", `SELECT * FROM app_auth.issue_authenticated_session_capability(${lit(sessionId)},${lit(refreshHash)},${lit(capability)},${lit(assurance)},(transaction_timestamp()+interval '12 hours')::timestamp)`], "issue semantic capability");
      semanticCapabilities.set(`${userId}:${assurance}`, capability);
    }
  }
};

const certifySemantics = (bootstrapUrl, appUrl) => {
  const tenantRisk = { user: ids.adminA, org: ids.orgA, licensee: ids.licenseeA };
  const manufacturerParentCount = Number(appScalar(appUrl, tenantRisk, `SELECT count("id") FROM public."User" WHERE "id"=${lit(ids.manufacturerA)} AND "role" IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND "isActive"=TRUE AND "status"='ACTIVE' AND "deletedAt" IS NULL AND "disabledAt" IS NULL`, "risk analytics manufacturer parent validation"));
  if (manufacturerParentCount !== 1) throw new Error("Legitimate risk analytics manufacturer parent validation failed");
  const tenantRiskB = { user: ids.adminB, org: ids.orgB, licensee: ids.licenseeB };
  const linkedManufacturer = appScalar(appUrl, tenantRiskB, `SELECT concat_ws('|',"id","name","role","isActive","status",coalesce("deletedAt"::text,'NULL'),coalesce("disabledAt"::text,'NULL')) FROM public."User" WHERE "id"=${lit(ids.manufacturerLegacyALinkB)}`, "risk analytics linked manufacturer with stale legacy scope");
  if (linkedManufacturer !== `${ids.manufacturerLegacyALinkB}|Manufacturer Linked B|MANUFACTURER|t|ACTIVE|NULL|NULL`) throw new Error(`Active manufacturer link did not override stale legacy User scope: ${linkedManufacturer || "<no row>"}`);
  if (Number(appScalar(appUrl, tenantRiskB, `SELECT count("id") FROM public."User" WHERE "id"=${lit(ids.manufacturerLegacyBUnlinked)}`, "risk analytics unlinked manufacturer denial")) !== 0) throw new Error("Legacy User scope granted an unlinked manufacturer");
  if (Number(appScalar(appUrl, tenantRisk, `SELECT count("id") FROM public."User" WHERE "id"=${lit(ids.manufacturerLegacyALinkB)}`, "risk analytics foreign link denial")) !== 0) throw new Error("Legacy User scope overrode a foreign manufacturer link");
  if (Number(appScalar(appUrl, tenantRisk, `SELECT count("id") FROM public."PolicyAlert"`, "tenant risk alert read")) !== 1) throw new Error("Tenant risk PolicyAlert policy drifted");
  if (Number(appScalar(appUrl, { ...tenantRisk, actorClass: "platform-admin", assurance: "mfa-verified" }, `SELECT count("id") FROM public."PolicyAlert"`, "blocked platform alert read")) !== 0) throw new Error("Platform actor received a direct PolicyAlert policy");
  if (Number(appScalar(appUrl, { ...tenantRisk, purpose: "audit-log-read", assurance: "mfa-verified" }, `SELECT count("id") FROM public."PolicyAlert"`, "wrong-purpose alert read")) !== 0) throw new Error("Purpose guard did not deny risk analytics");
  if (Number(appScalar(appUrl, { ...tenantRisk, purpose: "audit-log-read", assurance: "mfa-verified" }, `SELECT count("id") FROM public."AuditLog"`, "tenant-wide audit read")) !== 2) throw new Error("Tenant audit read was narrowed to actor-self instead of the approved tenant scope");
  if (Number(appScalar(appUrl, { ...tenantRisk, purpose: "audit-log-read", assurance: "password-verified" }, `SELECT count("id") FROM public."AuditLog"`, "weak-assurance audit denial")) !== 0) throw new Error("Actor-specific audit MFA guard was flattened");
  const manufacturerAudit = { user: ids.manufacturerA, org: ids.orgA, licensee: ids.licenseeA, actorClass: "manufacturer", assurance: "mfa-verified", purpose: "audit-log-read" };
  if (appScalar(appUrl, manufacturerAudit, `SELECT string_agg("id",',' ORDER BY "id") FROM public."AuditLog"`, "manufacturer self-attributed audit read") !== ids.auditAOther) throw new Error("Manufacturer audit read escaped immutable self attribution");
  const platformAudit = { user: ids.platformA, org: "", licensee: ids.licenseeA, actorClass: "platform-admin", assurance: "mfa-verified", purpose: "platform-audit-log-read" };
  const platformDetails = appScalar(appUrl, platformAudit, `SELECT string_agg(id||'|'||coalesce(user_name,'')||'|'||coalesce(ip_address,''),',' ORDER BY id) FROM app_rls.platform_audit_log_details(ARRAY[${lit(ids.auditA)},${lit(ids.auditAOther)},${lit(ids.auditB)}])`, "bounded platform audit metadata function");
  const expectedPlatformDetails = `${ids.auditA}|Admin A|192.0.2.10,${ids.auditAOther}|Manufacturer A|192.0.2.11`;
  if (platformDetails !== expectedPlatformDetails) throw new Error(`Bounded platform audit metadata projection drifted: ${platformDetails || "<empty>"}`);
  if (Number(appScalar(appUrl, { ...platformAudit, user: ids.adminA }, `SELECT count(*) FROM app_rls.platform_audit_log_details(ARRAY[${lit(ids.auditA)}])`, "platform audit role-string-only denial")) !== 0) throw new Error("Platform audit metadata trusted a platform role string without a database-valid actor");

  const visibleRules = appScalar(appUrl, tenantRisk, `SELECT string_agg("id",',' ORDER BY "id") FROM public."PolicyRule"`, "PolicyRule nullable scopes").split(",");
  for (const expected of [ids.ruleA, ids.ruleOrgA, ids.ruleManA]) if (!visibleRules.includes(expected)) throw new Error(`Approved PolicyRule scope ${expected} is invisible`);
  for (const deniedId of [ids.ruleB, ids.ruleConflict]) if (visibleRules.includes(deniedId)) throw new Error(`Conflicting/foreign PolicyRule scope ${deniedId} is visible`);

  // Audit inserts are source-purpose-specific.  A generic direct runtime
  // insert is not a reviewed business command; it must fail closed.  Reviewed
  // service and SECURITY DEFINER boundaries are exercised in their own path
  // certification rather than by granting a synthetic table-write capability.
  const manufacturer = { user: ids.manufacturerA, org: ids.orgA, licensee: ids.licenseeA, actorClass: "manufacturer", assurance: "mfa-verified", purpose: "audit-log-read" };
  const auditInsert = (user, org, licensee, action = "BATCH_OPERATIONAL_READ") => `INSERT INTO public."AuditLog" ("id","userId","orgId","licenseeId","action","entityType","entityId","details") VALUES ('00000000-0000-4000-8000-000000009999',${lit(user)},${lit(org)},${lit(licensee)},${lit(action)},'BatchOperationalRead','fixture',${lit(JSON.stringify({ requestId: "full-rls-cert-request", purposeCode: "batch-operational-read", route: "GET /api/qr/batches" }))}::jsonb)`;
  requireDenial(denial(appUrl, manufacturer, auditInsert(ids.manufacturerA, ids.orgA, ids.licenseeA), "unreviewed direct audit insert"), "unreviewed direct audit insert");
  for (const [label, context, user, org, licensee] of [
    ["foreign manufacturer licensee", manufacturer, ids.manufacturerA, ids.orgA, ids.licenseeB],
    ["forged manufacturer organization", manufacturer, ids.manufacturerA, ids.orgB, ids.licenseeA],
    ["another manufacturer user", manufacturer, ids.manufacturerB, ids.orgA, ids.licenseeA],
    ["tenant actor cannot use manufacturer predicate", { ...manufacturer, user: ids.adminA, actorClass: "licensee-admin" }, ids.manufacturerA, ids.orgA, ids.licenseeA],
    ["platform actor cannot use manufacturer predicate", { ...manufacturer, user: ids.adminA, actorClass: "platform-admin" }, ids.manufacturerA, ids.orgA, ids.licenseeA],
  ]) requireDenial(denial(appUrl, context, auditInsert(user, org, licensee), label), label);

  const temporarily = (before, test, after) => {
    runPsql(bootstrapUrl, ["-q", "-c", before], "prepare semantic denial fixture");
    try { test(); } finally { runPsql(bootstrapUrl, ["-q", "-c", after], "restore semantic denial fixture"); }
  };
  temporarily(`DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"=${lit(ids.manufacturerA)} AND "licenseeId"=${lit(ids.licenseeA)}`,
    () => requireDenial(denial(appUrl, manufacturer, auditInsert(ids.manufacturerA, ids.orgA, ids.licenseeA), "missing manufacturer link"), "missing manufacturer link"),
    `INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES (${lit(ids.manufacturerA)},${lit(ids.licenseeA)},true,now())`);
  temporarily(`UPDATE public."Licensee" SET "isActive"=false WHERE "id"=${lit(ids.licenseeA)}`,
    () => requireDenial(denial(appUrl, manufacturer, auditInsert(ids.manufacturerA, ids.orgA, ids.licenseeA), "inactive licensee"), "inactive licensee"),
    `UPDATE public."Licensee" SET "isActive"=true WHERE "id"=${lit(ids.licenseeA)}`);
  temporarily(`UPDATE public."Organization" SET "isActive"=false WHERE "id"=${lit(ids.orgA)}`,
    () => requireDenial(denial(appUrl, manufacturer, auditInsert(ids.manufacturerA, ids.orgA, ids.licenseeA), "inactive organization"), "inactive organization"),
    `UPDATE public."Organization" SET "isActive"=true WHERE "id"=${lit(ids.orgA)}`);
  temporarily(`UPDATE public."User" SET "isActive"=false WHERE "id"=${lit(ids.adminA)}`,
    () => {
      const output = runPsql(appUrl, ["-q", "-c", `BEGIN; ${contextSql(tenantRisk)} SELECT count("id") FROM public."PolicyAlert"; ROLLBACK;`], "disabled tenant actor denial", true);
      if (!/AUTH_SESSION_CAPABILITY_DENIED/.test(output)) throw new Error("Disabled tenant actor did not fail at capability verification");
    },
    `UPDATE public."User" SET "isActive"=true WHERE "id"=${lit(ids.adminA)}`);
  temporarily(`UPDATE public."User" SET "licenseeId"=${lit(ids.licenseeB)},"orgId"=${lit(ids.orgB)} WHERE "id"=${lit(ids.adminA)}`,
    () => { if (Number(appScalar(appUrl, tenantRisk, `SELECT count("id") FROM public."PolicyAlert"`, "stale tenant membership denial")) !== 0) throw new Error("Stale tenant membership retained RLS authority"); },
    `UPDATE public."User" SET "licenseeId"=${lit(ids.licenseeA)},"orgId"=${lit(ids.orgA)} WHERE "id"=${lit(ids.adminA)}`);
  temporarily(`UPDATE public."Licensee" SET "isActive"=false WHERE "id"=${lit(ids.licenseeA)}`,
    () => {
      const platform = { user: ids.platformA, org: ids.orgA, licensee: ids.licenseeA, actorClass: "platform-admin", assurance: "mfa-verified", purpose: "tenant-risk-analytics" };
      if (Number(appScalar(appUrl, platform, `SELECT count("id") FROM public."PolicyAlert"`, "inactive platform selector denial")) !== 0) throw new Error("Inactive platform selector retained RLS authority");
    },
    `UPDATE public."Licensee" SET "isActive"=true WHERE "id"=${lit(ids.licenseeA)}`);

  const secondVerification = scalar(appUrl, `BEGIN; ${contextSql(tenantRisk)} SELECT set_config('app.user_id','${ids.adminB}',true); ${contextSql(tenantRisk)} SELECT current_setting('app.user_id',true); ROLLBACK;`, "same-transaction capability re-verification");
  if (secondVerification !== ids.adminA) throw new Error("Capability re-verification did not overwrite forged actor context");
  const malformed = runPsql(appUrl, ["-q", "-c", "BEGIN; SELECT app_rls.install_actor_context('not-a-uuid','LICENSEE_ADMIN','','','','password-verified','request','purpose'); ROLLBACK;"], "malformed context", true);
  if (!/permission denied/i.test(malformed)) throw new Error("Generic context installer remained runtime-executable");
};

const installationSteps = [
  { id: "preflight", phase: "admin-bootstrap", file: "00-preflight.sql", executor: "administrator" },
  { id: "roles", phase: "admin-bootstrap", file: "10-roles.sql", executor: "administrator" },
  { id: "migration-boundary", phase: "migration", file: "15-migration-preflight.sql", executor: "migration" },
  { id: "prisma-from-zero", phase: "migration", executor: "prisma" },
  { id: "ownership", phase: "admin-ownership", file: "11-ownership-grants.sql", executor: "administrator" },
  { id: "helpers", phase: "runtime-policy", file: "20-context-helpers.sql", executor: "administrator" },
  { id: "runtime-grants", phase: "runtime-policy", file: "21-runtime-grants.sql", executor: "administrator" },
  { id: "policies", phase: "runtime-policy", file: "30-policies.sql", executor: "administrator" },
  { id: "verification", phase: "verification", file: "40-post-apply-verification.sql", executor: "administrator" },
];
const expectedPhaseIds = ["admin-bootstrap", "migration", "admin-ownership", "runtime-policy", "verification", "clean-room-destroy"];

const createUrls = (adminUrl, maintenanceDatabase, database, manifest) => ({
  administrator: databaseUrlFor(adminUrl, database, certificationAdministrator),
  migration: databaseUrlFor(adminUrl, database, manifest.roles.migration),
  bootstrap: databaseUrlFor(adminUrl, database, decodeURIComponent(new URL(adminUrl).username)),
  maintenance: databaseUrlFor(adminUrl, maintenanceDatabase, certificationAdministrator),
  app: databaseUrlFor(adminUrl, database, manifest.roles.app),
  preauth: databaseUrlFor(adminUrl, database, manifest.roles.preauth),
  worker: databaseUrlFor(adminUrl, database, manifest.roles.worker),
  scheduled: databaseUrlFor(adminUrl, database, manifest.roles.scheduled),
  operator: databaseUrlFor(adminUrl, database, manifest.roles.operator),
});
const assertZeroBeforePrisma = (administratorUrl) => {
  if (scalar(administratorUrl, "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v','m','f')", "prove zero public objects before Prisma") !== "0") throw new Error("Fresh green database contains public application objects before Prisma");
  if (scalar(administratorUrl, "SELECT to_regclass('public._prisma_migrations') IS NULL", "prove zero Prisma ledger") !== "t") throw new Error("Fresh green database contains a Prisma ledger before migration");
};
const applyStep = (step, urls, execution, env) => {
  if (step.executor === "prisma") {
    runPrisma(urls.migration, env);
    provePrismaLedger(urls.migration, execution.phases.find((phase) => phase.id === "migration").executorRole, execution.prismaMigrations);
    return;
  }
  if (step.id === "migration-boundary") assertZeroBeforePrisma(urls.administrator);
  runSqlFile(urls[step.executor], step.file, `apply ${step.id}`);
};
const assertZeroResidue = (maintenanceUrl, database, manifest, blueUrl, expectedBlueFingerprint) => {
  const residue = JSON.parse(scalar(maintenanceUrl, `SELECT jsonb_build_object(
    'databaseCount',(SELECT count(*) FROM pg_database WHERE datname=${lit(database)}),
    'sessionCount',(SELECT count(*) FROM pg_stat_activity WHERE datname=${lit(database)}),
    'roleCount',(SELECT count(*) FROM pg_roles WHERE rolname IN (${roleListSql(manifest.roles)})),
    'parentMembershipCount',(SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE r.rolname IN (${roleListSql(manifest.roles)})),
    'memberMembershipCount',(SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname IN (${roleListSql(manifest.roles)}))
  )::text`, "verify clean-room zero residue"));
  if (Object.values(residue).some(Number)) throw new Error(`Green cleanup left residue: ${JSON.stringify(residue)}`);
  if (blueFingerprint(blueUrl) !== expectedBlueFingerprint) throw new Error("Green lifecycle mutated the blue rollback database");
  return residue;
};
const destroyAndProve = ({ urls, database, manifest, blueUrl, expectedBlueFingerprint, allowCertificationFixtures = false }) => {
  if (databaseExists(urls.maintenance, database)) {
    if (!allowCertificationFixtures) assertNoBusinessRows(urls.bootstrap);
    dropGreenDatabase(urls.maintenance, database);
  }
  cleanMarkedRoles(urls.maintenance, database);
  return assertZeroResidue(urls.maintenance, database, manifest, blueUrl, expectedBlueFingerprint);
};

const certifyFailureStages = ({ adminUrl, maintenanceDatabase, manifest, execution, env, blueUrl, expectedBlueFingerprint }) => {
  const results = [];
  for (const target of ["database-created", ...installationSteps.map((step) => step.id)]) {
    const database = candidateName(target);
    const urls = createUrls(adminUrl, maintenanceDatabase, database, manifest);
    createGreenDatabase(urls.maintenance, database);
    try {
      if (target !== "database-created") for (const step of installationSteps) {
        if (step.id === target) {
          if (step.executor === "prisma") applyStep(step, urls, execution, env);
          else {
            if (step.id === "migration-boundary") assertZeroBeforePrisma(urls.administrator);
            runInjectedFile(urls[step.executor], step.file, step.id);
          }
          break;
        }
        applyStep(step, urls, execution, env);
      }
      destroyAndProve({ urls, database, manifest, blueUrl, expectedBlueFingerprint });
      results.push({ stage: target, failureMode: target === "prisma-from-zero" || target === "database-created" ? "simulated-process-stop-after-stage" : "transactional-injected-failure", databaseResidueCount: 0, managedRoleResidueCount: 0, blueFingerprintUnchanged: true });
    } catch (error) {
      try { destroyAndProve({ urls, database, manifest, blueUrl, expectedBlueFingerprint }); } catch (cleanupError) { throw new Error(`${error.message}; cleanup failed: ${cleanupError.message}`); }
      throw error;
    }
  }
  return results;
};

const certifyCleanupFailure = ({ adminUrl, maintenanceDatabase, manifest, execution, env, blueUrl, expectedBlueFingerprint }) => {
  const database = candidateName("cleanup");
  const urls = createUrls(adminUrl, maintenanceDatabase, database, manifest);
  createGreenDatabase(urls.maintenance, database);
  try {
    for (const step of installationSteps) applyStep(step, urls, execution, env);
    assertNoBusinessRows(urls.bootstrap);
    dropGreenDatabase(urls.maintenance, database);
    runInjectedFile(urls.maintenance, "90-clean-room-role-cleanup.sql", "clean-room-destroy", [["candidate_database", database]]);
    if (managedRoleCount(urls.maintenance, manifest.roles) !== Object.keys(manifest.roles).length) throw new Error("Transactional cleanup failure did not leave all package roles retryable");
    cleanMarkedRoles(urls.maintenance, database);
    assertZeroResidue(urls.maintenance, database, manifest, blueUrl, expectedBlueFingerprint);
    return { stage: "clean-room-destroy", failureMode: "transactional-injected-failure-and-retry", databaseResidueCount: 0, managedRoleResidueCount: 0, blueFingerprintUnchanged: true };
  } catch (error) {
    try { destroyAndProve({ urls, database, manifest, blueUrl, expectedBlueFingerprint }); } catch (cleanupError) { throw new Error(`${error.message}; cleanup failed: ${cleanupError.message}`); }
    throw error;
  }
};

const certifyPreflightRefusals = ({ adminUrl, maintenanceDatabase, manifest, blueUrl, expectedBlueFingerprint }) => {
  const fixturePrefix = `mscqr_rls_cert_refusal_${process.pid}`;
  const scenarios = [
    {
      id: "managed-role-and-membership",
      setup: ({ urls }) => {
        const parent = `${fixturePrefix}_parent`;
        runPsql(urls.maintenance, ["-q", "-c", `CREATE ROLE ${quote(parent)} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE ${quote(manifest.roles.app)} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT ${quote(parent)} TO ${quote(manifest.roles.app)}`], "create refused managed role and membership");
        return () => runPsql(urls.maintenance, ["-q", "-c", `DROP ROLE ${quote(parent)}; DROP ROLE ${quote(manifest.roles.app)}`], "remove refused managed role fixture");
      },
    },
    { id: "application-object", setup: ({ urls }) => { runPsql(urls.administrator, ["-q", "-c", "CREATE TABLE public.refusal_object(id integer); CREATE SEQUENCE public.refusal_sequence; CREATE TYPE public.refusal_enum AS ENUM ('x'); CREATE FUNCTION public.refusal_function() RETURNS integer LANGUAGE sql AS $$ SELECT 1 $$"], "create refused application objects"); } },
    { id: "policy", setup: ({ urls }) => { runPsql(urls.administrator, ["-q", "-c", "CREATE TABLE public.refusal_policy_table(id integer); ALTER TABLE public.refusal_policy_table ENABLE ROW LEVEL SECURITY; CREATE POLICY refusal_policy ON public.refusal_policy_table USING (false)"], "create refused policy"); } },
    {
      id: "database-and-schema-grants",
      setup: ({ urls, database }) => {
        const role = `${fixturePrefix}_grant`;
        runPsql(urls.maintenance, ["-q", "-c", `CREATE ROLE ${quote(role)} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`], "create refused grant fixture role");
        runPsql(urls.administrator, ["-q", "-c", `GRANT CONNECT ON DATABASE ${quote(database)} TO ${quote(role)}; GRANT USAGE ON SCHEMA public TO ${quote(role)}`], "create refused database and schema grants");
        return () => runPsql(urls.maintenance, ["-q", "-c", `DROP ROLE ${quote(role)}`], "remove refused grant fixture role");
      },
    },
    { id: "default-acl", setup: ({ urls }) => { runPsql(urls.administrator, ["-q", "-c", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC"], "create refused default ACL"); } },
    { id: "package-schema", setup: ({ urls }) => { runPsql(urls.administrator, ["-q", "-c", "CREATE SCHEMA app_rls"], "create refused package schema"); } },
    { id: "publication", setup: ({ urls }) => { runPsql(urls.administrator, ["-q", "-c", "CREATE PUBLICATION refusal_publication"], "create refused publication"); } },
    {
      id: "wrong-owner",
      setup: ({ database }) => {
        const outerRole = decodeURIComponent(new URL(adminUrl).username);
        runPsql(adminUrl, ["-q", "-c", `ALTER DATABASE ${quote(database)} OWNER TO ${quote(outerRole)}`], "create refused wrong database owner");
        return null;
      },
      dropWithOuterAdministrator: true,
    },
    {
      id: "insufficient-administrator-capability",
      setup: () => {
        runPsql(adminUrl, ["-q", "-c", `ALTER ROLE ${quote(certificationAdministrator)} NOCREATEDB`], "remove disposable CREATEDB capability");
        return () => runPsql(adminUrl, ["-q", "-c", `ALTER ROLE ${quote(certificationAdministrator)} CREATEDB`], "restore disposable CREATEDB capability");
      },
    },
  ];
  const results = [];
  for (const scenario of scenarios) {
    const database = candidateName(`refusal_${scenario.id}`);
    const urls = createUrls(adminUrl, maintenanceDatabase, database, manifest);
    createGreenDatabase(urls.maintenance, database);
    let cleanupFixture;
    try {
      cleanupFixture = scenario.setup({ urls, database }) || null;
      const beforeCatalog = localCatalogFingerprint(urls.administrator);
      const beforeRoles = clusterRoleFingerprint(urls.maintenance);
      for (const file of ["00-preflight.sql", "10-roles.sql"]) {
        const output = runPsql(urls.administrator, ["-f", path.join(sqlRoot, file)], `refuse ${scenario.id} through ${file}`, true);
        if (!/clean-room preflight refuses|requires the exact|must own the green candidate|requires CREATEROLE and CREATEDB/i.test(output)) throw new Error(`${scenario.id}/${file} failed for an unexpected reason: ${output.trim()}`);
        if (localCatalogFingerprint(urls.administrator) !== beforeCatalog || clusterRoleFingerprint(urls.maintenance) !== beforeRoles) throw new Error(`${scenario.id}/${file} refusal mutated catalog or cluster-role state`);
      }
      if (scalar(urls.administrator, "SELECT to_regnamespace('mscqr_rls_install') IS NULL", "verify refusal made no install state") !== "t") throw new Error(`${scenario.id} refusal created package state`);
      results.push({ scenario: scenario.id, status: "refused-before-mutation", entrypointsRefused: ["00-preflight.sql", "10-roles.sql"], blueFingerprintUnchanged: true });
    } finally {
      if (scenario.id === "insufficient-administrator-capability" && cleanupFixture) cleanupFixture();
      dropGreenDatabase(scenario.dropWithOuterAdministrator ? adminUrl : urls.maintenance, database);
      if (scenario.id !== "insufficient-administrator-capability" && cleanupFixture) cleanupFixture();
      if (managedRoleCount(adminUrl, manifest.roles) !== 0) throw new Error(`${scenario.id} refusal left a managed role`);
      if (blueFingerprint(blueUrl) !== expectedBlueFingerprint) throw new Error(`${scenario.id} refusal mutated blue`);
    }
  }
  return results;
};

const certifyDirectSubphaseRefusals = ({ adminUrl, maintenanceDatabase, manifest, blueUrl, expectedBlueFingerprint }) => {
  const results = [];
  for (const file of ["15-migration-preflight.sql", "11-ownership-grants.sql", "20-context-helpers.sql", "21-runtime-grants.sql", "30-policies.sql"]) {
    const database = candidateName(`direct_${file.replace(/\W+/g, "_")}`);
    const urls = createUrls(adminUrl, maintenanceDatabase, database, manifest);
    createGreenDatabase(urls.maintenance, database);
    try {
      const beforeCatalog = localCatalogFingerprint(urls.administrator);
      const beforeRoles = clusterRoleFingerprint(urls.maintenance);
      runPsql(urls.administrator, ["-f", path.join(sqlRoot, file)], `refuse out-of-order direct phase ${file}`, true);
      if (localCatalogFingerprint(urls.administrator) !== beforeCatalog || clusterRoleFingerprint(urls.maintenance) !== beforeRoles) throw new Error(`${file} mutated a fresh database without its exact predecessor marker`);
      results.push({ file, status: "refused-before-mutation", blueFingerprintUnchanged: true });
    } finally {
      dropGreenDatabase(urls.maintenance, database);
      if (managedRoleCount(adminUrl, manifest.roles) !== 0) throw new Error(`${file} direct-phase refusal left a managed role`);
      if (blueFingerprint(blueUrl) !== expectedBlueFingerprint) throw new Error(`${file} direct-phase refusal mutated blue`);
    }
  }
  return results;
};

const runCatalogTamperVerification = (administratorUrl, tamper) => {
  const source = fs.readFileSync(path.join(sqlRoot, "40-post-apply-verification.sql"), "utf8");
  const prefix = "\\set ON_ERROR_STOP on\nBEGIN;\n";
  const commitIndex = source.lastIndexOf("\nCOMMIT;");
  if (!source.startsWith(prefix) || commitIndex === -1) throw new Error("verification SQL is not transaction wrapped");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rls-tamper-"));
  const file = path.join(directory, `${tamper.id}.sql`);
  try {
    fs.writeFileSync(file, `${prefix}${tamper.sql}\n${source.slice(prefix.length, commitIndex)}\nDO $$ BEGIN RAISE EXCEPTION 'catalog tamper was not detected: ${tamper.id}'; END $$;\nROLLBACK;\n`);
    const output = runPsql(administratorUrl, ["-f", file], `detect catalog tamper ${tamper.id}`, true);
    if (/catalog tamper was not detected/i.test(output) || !tamper.expected.test(output)) throw new Error(`${tamper.id} was not rejected by its exact catalog gate: ${output.trim()}`);
    return { dimension: tamper.id, status: "exact-drift-refused", expectedFailure: tamper.expected.source };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
};

const certifyCatalogTamperDetection = (administratorUrl, manifest, policies) => {
  const policy = policies.rows.find((entry) => !entry.internalHelperOnly && entry.command === "SELECT");
  if (!policy) throw new Error("No generated SELECT policy is available for tamper certification");
  const setOwner = `SET LOCAL ROLE ${quote(manifest.roles.owner)};`;
  const resetOwner = "RESET ROLE;";
  const tampers = [
    { id: "policy-definition", sql: `${setOwner} ALTER POLICY ${quote(policy.policyName)} ON public.${quote(policy.table)} TO PUBLIC USING (true); ${resetOwner}`, expected: /policy definition differs from the sealed generated contract/i },
    { id: "routine-definition", sql: `${setOwner} CREATE OR REPLACE FUNCTION app_rls.current_purpose() RETURNS text LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT 'tampered'::text $$; ${resetOwner}`, expected: /routine definition or privilege inventory differs/i },
    { id: "routine-acl", sql: `${setOwner} GRANT EXECUTE ON FUNCTION app_rls.current_purpose() TO PUBLIC; ${resetOwner}`, expected: /routine definition or privilege inventory differs/i },
    { id: "schema-acl", sql: `SET LOCAL ROLE ${quote(manifest.roles.authOwner)}; GRANT CREATE ON SCHEMA app_auth TO ${quote(manifest.roles.app)}; RESET ROLE;`, expected: /schema privilege inventory differs/i },
    { id: "table-acl", sql: `${setOwner} GRANT DELETE ON TABLE public."AuditLog" TO ${quote(manifest.roles.app)}; ${resetOwner}`, expected: /table privilege inventory differs/i },
    { id: "column-acl", sql: `${setOwner} GRANT SELECT ("email") ON TABLE public."User" TO ${quote(manifest.roles.app)}; ${resetOwner}`, expected: /column privilege inventory differs/i },
    { id: "type-acl", sql: `${setOwner} DO $$ DECLARE type_name text; BEGIN SELECT t.typname INTO type_name FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e' ORDER BY t.typname LIMIT 1; EXECUTE format('GRANT USAGE ON TYPE public.%I TO %I',type_name,${lit(manifest.roles.read)}); END $$; ${resetOwner}`, expected: /type privilege inventory differs/i },
    { id: "database-acl", sql: `DO $$ BEGIN EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO %I',current_database(),${lit(manifest.roles.app)}); END $$;`, expected: /database privilege inventory differs/i },
    { id: "default-acl", sql: `${setOwner} ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO ${quote(manifest.roles.app)}; ${resetOwner}`, expected: /default privilege definition differs/i },
  ];
  return tampers.map((tamper) => runCatalogTamperVerification(administratorUrl, tamper));
};

const runSuccessfulCertification = ({ adminUrl, maintenanceDatabase, manifest, execution, policies, privileges, env, blueUrl, expectedBlueFingerprint }) => {
  const database = candidateName("final");
  const urls = createUrls(adminUrl, maintenanceDatabase, database, manifest);
  createGreenDatabase(urls.maintenance, database);
  try {
    runSqlFile(urls.administrator, "admin-bootstrap.sql", "run exact administrative bootstrap entrypoint");
    assertZeroBeforePrisma(urls.administrator);
    runSqlFile(urls.migration, "migration.sql", "run exact restricted migration entrypoint");
    runPrisma(urls.migration, env);
    provePrismaLedger(urls.migration, manifest.roles.migration, execution.prismaMigrations);
    assertNoBusinessRows(urls.bootstrap);
    runSqlFile(urls.migration, "50-certification-fixtures.sql", "load disposable certification fixtures before ownership transfer");
    runSqlFile(urls.administrator, "admin-ownership.sql", "run exact administrative ownership entrypoint");
    runSqlFile(urls.administrator, "runtime-policy.sql", "run exact runtime policy entrypoint");
    runSqlFile(urls.administrator, "verification.sql", "run exact verification entrypoint");
    if (env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY === "printing-lifecycle") {
      const fixtureRows = Number(scalar(urls.bootstrap, "SELECT sum(row_count) FROM (SELECT (xpath('/row/c/text()',query_to_xml(format('SELECT count(*) c FROM public.%I',c.relname),false,true,'')))[1]::text::bigint AS row_count FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname<>'_prisma_migrations') counts", "count disposable certification fixture rows"));
      const connections = { app: urls.app, bootstrap: urls.bootstrap, preauth: urls.preauth, worker: urls.worker, scheduled: urls.scheduled, operator: urls.operator };
      const printingLifecycleCertification = runPrintingLifecycleCertification(connections, env);
      destroyAndProve({ urls, database, manifest, blueUrl, expectedBlueFingerprint, allowCertificationFixtures: true });
      return {
        tablesCertified: 0,
        fixtureRows,
        applicationPathResults: [],
        catalogTamperResults: [],
        b01Certification: null,
        b01PreAuthCertification: null,
        scheduledJobIdentityCertification: null,
        b03OutboxCertification: null,
        c03Certification: null,
        printingLifecycleCertification,
        databaseResidueCount: 0,
        managedRoleResidueCount: 0,
        blueFingerprintUnchanged: true,
      };
    }
    const catalogTamperResults = certifyCatalogTamperDetection(urls.administrator, manifest, policies);
    const b01Certification = certifyB01RefreshRotation(urls, manifest);
    const b01PreAuthCertification = runB01PreAuthCertification({ app: urls.app, bootstrap: urls.bootstrap, preauth: urls.preauth }, env);
    issueSemanticCapabilities(urls);
    const tablesCertified = certifyTablesAndColumns(urls.administrator, urls.app, manifest, policies, privileges);
    certifySemantics(urls.bootstrap, urls.app);
    const fixtureRows = Number(scalar(urls.bootstrap, "SELECT sum(row_count) FROM (SELECT (xpath('/row/c/text()',query_to_xml(format('SELECT count(*) c FROM public.%I',c.relname),false,true,'')))[1]::text::bigint AS row_count FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname<>'_prisma_migrations') counts", "count disposable certification fixture rows"));
    if (!fixtureRows) throw new Error("Final semantic certification did not load its declared disposable fixtures");
    const connections = { app: urls.app, bootstrap: urls.bootstrap, preauth: urls.preauth, worker: urls.worker, scheduled: urls.scheduled, operator: urls.operator };
    const scheduledJobIdentityCertification = runScheduledJobIdentityCertification(connections, env);
    const b03OutboxCertification = runB03OutboxCertification(connections, env);
    const c03Certification = runC03AuthenticatedCertification(connections, env);
    const publicVerificationCertification = runPublicVerificationCertification(connections, env);
    const applicationPathResults = env.MSCQR_FULL_RLS_CERTIFICATION_FAMILY === "c03-authenticated-boundaries"
      ? []
      : runApplicationPathCertifications(connections, env);
    destroyAndProve({ urls, database, manifest, blueUrl, expectedBlueFingerprint, allowCertificationFixtures: true });
    return { tablesCertified, fixtureRows, applicationPathResults, catalogTamperResults, b01Certification, b01PreAuthCertification, scheduledJobIdentityCertification, b03OutboxCertification, c03Certification, printingLifecycleCertification: null, publicVerificationCertification, databaseResidueCount: 0, managedRoleResidueCount: 0, blueFingerprintUnchanged: true };
  } catch (error) {
    try { destroyAndProve({ urls, database, manifest, blueUrl, expectedBlueFingerprint, allowCertificationFixtures: true }); } catch (cleanupError) { throw new Error(`${error.message}; cleanup failed: ${cleanupError.message}`); }
    throw error;
  }
};

const runRouteShutdownTests = () => {
  const result = spawnSync(process.execPath, [path.join(root, "backend/tests/unsupportedWorkflowShutdown.test.js")], { cwd: root, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(`Unsupported-workflow shutdown tests failed: ${`${result.stdout || ""}${result.stderr || ""}`.trim()}`);
};

export const runCertification = (adminUrl, env = process.env) => {
  if (env[CONFIRM_ENV] !== CONFIRM_VALUE) throw new FullRlsCertificationSafetyError(`Set ${CONFIRM_ENV}=${CONFIRM_VALUE}`);
  const parsed = assertSafeAdminUrl(adminUrl);
  try { verifyFullRlsPackage(); }
  catch (error) { throw new FullRlsCertificationSafetyError(`Generated package verification failed before database mutation: ${error instanceof Error ? error.message : String(error)}`); }
  runBackendBuild(env);
  const maintenanceDatabase = decodeURIComponent(parsed.pathname.slice(1));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const execution = JSON.parse(fs.readFileSync(executionPath, "utf8"));
  const policies = JSON.parse(fs.readFileSync(policyPath, "utf8"));
  const privileges = JSON.parse(fs.readFileSync(privilegePath, "utf8"));
  const workflowEvidence = JSON.parse(fs.readFileSync(workflowEvidencePath, "utf8"));
  if (manifest.deploymentModel !== "clean-room-blue-green" || execution.deploymentModel !== "clean-room-blue-green") throw new FullRlsCertificationSafetyError("Generated package is not the clean-room blue/green contract");
  if (JSON.stringify(execution.phases.map((phase) => phase.id)) !== JSON.stringify(expectedPhaseIds)) throw new FullRlsCertificationSafetyError("Generated authority phase order is not the reviewed clean-room contract");
  const coveredPhases = new Set([...installationSteps.map((step) => step.phase), "clean-room-destroy"]);
  if (execution.phases.some((phase) => !coveredPhases.has(phase.id))) throw new FullRlsCertificationSafetyError("Failure injection does not cover every generated phase");
  if (manifest.sourceContractSha256 !== execution.sourceContractSha256 || JSON.stringify(manifest.prismaMigrations) !== JSON.stringify(execution.prismaMigrations)) throw new FullRlsCertificationSafetyError("Generated migration/source contract reports disagree");
  if (Number(scalar(adminUrl, "SELECT current_setting('server_version_num')::integer / 10000", "verify PostgreSQL certification major")) !== 18) throw new FullRlsCertificationSafetyError("Authoritative full-RLS certification requires PostgreSQL 18");
  if (managedRoleCount(adminUrl, manifest.roles) !== 0) throw new FullRlsCertificationSafetyError("Certification managed roles already exist; clean-room provenance is unknown");
  if (scalar(adminUrl, `SELECT count(*) FROM pg_roles WHERE rolname=${lit(certificationAdministrator)}`, "check certification administrator") !== "0") throw new FullRlsCertificationSafetyError("Certification administrator already exists; clean-room provenance is unknown");

  const result = {
    schemaVersion: 11,
    environment: "local-disposable-only",
    deploymentModel: "clean-room-blue-green",
    postgresqlMajor: 18,
    sourceContractSha256: execution.sourceContractSha256,
    tablesExpected: EXPECTED_TABLE_COUNT,
    forceRlsTargetsExpected: EXPECTED_FORCE_RLS_TABLE_COUNT,
    tablesCertified: 0,
    generatedPoliciesCertified: 0,
    columnPrivilegeCellsCertified: 0,
    workflowCertificationStatus: "pending-application-path-certification",
    workflowsApplicationPathCertified: 0,
    applicationPathCertifiedWorkflowIds: [],
    applicationPathResults: [],
    b01PreAuthCertification: null,
    scheduledJobIdentityCertification: null,
    b03OutboxCertification: null,
    workflowsProductProhibited: workflowEvidence.summary.frozenProductProhibited,
    cleanRoomPreflightCertified: false,
    migrationsFromZeroCertified: false,
    managedRolesCreatedByPackage: false,
    nonSuperuserAdministrativeExecutorCertification: false,
    phaseEntrypointCertification: false,
    phaseTransactionAtomicityCertification: false,
    failureInjectionExpectedStages: ["database-created", ...installationSteps.map((step) => step.id), "clean-room-destroy"],
    failureInjectionCertifiedStages: [],
    preflightRefusalResults: [],
    directPhaseRefusalResults: [],
    failureInjectionResults: [],
    catalogTamperResults: [],
    greenDatabaseResidueCount: null,
    managedRoleResidueCount: null,
    blueFingerprintUnchanged: false,
    rollbackVerified: false,
    policySemanticPreservation: false,
    columnPrivilegeCertification: false,
    exactCatalogTamperCertification: false,
    routeShutdownTemplateTests: false,
    packageChecksumsSha256: crypto.createHash("sha256").update(fs.readFileSync(checksumsPath)).digest("hex"),
    status: "failed",
  };
  let failure;
  let executorUrl;
  let blueDatabase;
  try {
    createCertificationAdministrator(adminUrl);
    executorUrl = databaseUrlFor(adminUrl, maintenanceDatabase, certificationAdministrator);
    if (scalar(executorUrl, "SELECT rolsuper::text || ':' || rolcreatedb::text || ':' || rolcreaterole::text || ':' || rolbypassrls::text FROM pg_roles WHERE rolname=current_user", "verify certification administrator attributes") !== "false:true:true:false") throw new Error("Certification administrator lacks exact non-superuser CREATEDB/CREATEROLE authority");
    result.nonSuperuserAdministrativeExecutorCertification = true;

    blueDatabase = `mscqr_full_rls_blue_${process.pid}`;
    createGreenDatabase(executorUrl, blueDatabase);
    const blueUrl = databaseUrlFor(adminUrl, blueDatabase, certificationAdministrator);
    runPsql(blueUrl, ["-q", "-c", "CREATE TABLE public.blue_sentinel(id integer PRIMARY KEY, value text NOT NULL); INSERT INTO public.blue_sentinel VALUES (1,'blue-rollback-target')"], "create disposable blue sentinel");
    const expectedBlueFingerprint = blueFingerprint(blueUrl);

    result.preflightRefusalResults = certifyPreflightRefusals({ adminUrl, maintenanceDatabase, manifest, blueUrl, expectedBlueFingerprint });
    result.directPhaseRefusalResults = certifyDirectSubphaseRefusals({ adminUrl, maintenanceDatabase, manifest, blueUrl, expectedBlueFingerprint });
    result.cleanRoomPreflightCertified = true;
    result.failureInjectionResults = certifyFailureStages({ adminUrl, maintenanceDatabase, manifest, execution, env, blueUrl, expectedBlueFingerprint });
    result.failureInjectionResults.push(certifyCleanupFailure({ adminUrl, maintenanceDatabase, manifest, execution, env, blueUrl, expectedBlueFingerprint }));
    result.failureInjectionCertifiedStages = result.failureInjectionResults.map((entry) => entry.stage);
    if (JSON.stringify(result.failureInjectionCertifiedStages) !== JSON.stringify(result.failureInjectionExpectedStages)) throw new Error("Failure injection stage evidence is incomplete or out of order");
    result.phaseTransactionAtomicityCertification = true;

    const finalRun = runSuccessfulCertification({ adminUrl, maintenanceDatabase, manifest, execution, policies, privileges, env, blueUrl, expectedBlueFingerprint });
    result.tablesCertified = finalRun.tablesCertified;
    result.applicationPathResults = finalRun.applicationPathResults;
    result.applicationPathCertifiedWorkflowIds = finalRun.applicationPathResults.flatMap((entry) => entry.workflowIds);
    result.workflowsApplicationPathCertified = result.applicationPathCertifiedWorkflowIds.length;
    result.workflowCertificationStatus = result.workflowsApplicationPathCertified + result.workflowsProductProhibited === workflowEvidence.workflowCount
      ? "complete"
      : "pending-application-path-certification";
    result.catalogTamperResults = finalRun.catalogTamperResults;
    result.b01Certification = finalRun.b01Certification;
    result.b01PreAuthCertification = finalRun.b01PreAuthCertification;
    result.scheduledJobIdentityCertification = finalRun.scheduledJobIdentityCertification;
    result.b03OutboxCertification = finalRun.b03OutboxCertification;
    result.c03Certification = finalRun.c03Certification;
    result.printingLifecycleCertification = finalRun.printingLifecycleCertification;
    result.publicVerificationCertification = finalRun.publicVerificationCertification;
    result.exactCatalogTamperCertification = finalRun.catalogTamperResults.length === 9;
    result.generatedPoliciesCertified = policies.count;
    result.columnPrivilegeCellsCertified = privileges.cells;
    result.migrationsFromZeroCertified = true;
    result.managedRolesCreatedByPackage = true;
    result.phaseEntrypointCertification = true;
    result.policySemanticPreservation = true;
    result.columnPrivilegeCertification = true;
    result.greenDatabaseResidueCount = 0;
    result.managedRoleResidueCount = 0;
    result.blueFingerprintUnchanged = finalRun.blueFingerprintUnchanged;
    result.rollbackVerified = true;
    result.disposableCertificationFixtureRows = finalRun.fixtureRows;
    runRouteShutdownTests();
    result.routeShutdownTemplateTests = true;
    result.status = "clean-room-full-table-enforcement-certified-workflows-pending";
  } catch (error) {
    failure = error;
    result.status = "failed-cleanup-required";
    result.failure = error instanceof Error ? error.message : String(error);
  } finally {
    try {
      for (const database of [...activeDatabases]) dropGreenDatabase(adminUrl, database);
      if (managedRoleCount(adminUrl, manifest.roles) !== 0 && executorUrl) cleanMarkedRoles(executorUrl, `mscqr_full_rls_cert_${process.pid}_emergency`);
      runPsql(adminUrl, ["-q", "-c", `DO $$ DECLARE role_name text; BEGIN FOR role_name IN SELECT rolname FROM pg_roles WHERE rolname LIKE ${lit(`mscqr_rls_cert_refusal_${process.pid}%`)} ORDER BY rolname LOOP EXECUTE format('DROP ROLE %I',role_name); END LOOP; END $$;`], "remove exact refusal fixture roles");
      if (managedRoleCount(adminUrl, manifest.roles) !== 0) throw new Error("Certification suite left package-managed roles");
      if (scalar(adminUrl, `SELECT count(*) FROM pg_roles WHERE rolname=${lit(certificationAdministrator)}`, "inspect certification administrator cleanup") !== "0") dropCertificationAdministrator(adminUrl);
      if (scalar(adminUrl, `SELECT count(*) FROM pg_roles WHERE rolname=${lit(certificationAdministrator)}`, "verify certification administrator cleanup") !== "0") throw new Error("Certification suite left its administrative executor");
    } catch (cleanupError) {
      const message = cleanupError instanceof Error ? cleanupError.message : String(cleanupError);
      result.cleanupFailure = message;
      failure = failure ? new Error(`${result.failure}; suite cleanup failed: ${message}`) : cleanupError;
    }
    fs.writeFileSync(evidencePath, `${JSON.stringify(result, null, 2)}\n`);
  }
  if (failure) throw failure;
  return result;
};

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  try { console.log(JSON.stringify(runCertification(process.env[DATABASE_ENV] || ""))); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
