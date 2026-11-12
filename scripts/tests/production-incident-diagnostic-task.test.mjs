import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { buildIncidentDiagnosticSql } from "../../backend/scripts/production-incident-diagnostic-sql.mjs";
import { validateIncidentTaskInput, runIncidentTask } from "../../backend/scripts/production-incident-diagnostic-task.mjs";

const digest = (value) => createHash("sha256").update(value).digest("hex");
const issuedAt = "2026-11-12T13:55:00.000Z";
const expiresAt = "2026-11-12T14:25:00.000Z";
const executionId = "11111111-1111-4111-8111-111111111111";
const diagnosticSourceSha = "a".repeat(40);
const sql = buildIncidentDiagnosticSql({ executionId, issuedAt, expiresAt });
const authorization = { account: "368992683803", region: "eu-west-2", sourceSha: sql.sourceSha,
  diagnosticSourceSha, database: "mscqr_production_rls_green_phase2", executionId, issuedAt, expiresAt,
  approvalEvidenceSha256: "b".repeat(64), provisionSha256: digest(sql.provision), querySha256: digest(sql.query),
  teardownSha256: digest(sql.teardown) };
const fixturePassword = randomBytes(16).toString("hex");
const fixtureUrl = new URL("postgresql://mscqr-production-rls-green-phase2.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com/mscqr_production_rls_green_phase2?sslmode=require&application_name=mscqr-production-green-read-only-rls-canary");
fixtureUrl.username = "mscqr_prod_rls_canary_read";
fixtureUrl.password = fixturePassword;
const env = { NODE_ENV: "production", RUN_DB_MIGRATIONS_ON_START: "false", AWS_REGION: "eu-west-2",
  AWS_DEFAULT_REGION: "eu-west-2", AWS_EXECUTION_ENV: "AWS_ECS_FARGATE", GIT_SHA: diagnosticSourceSha,
  RELEASE_GIT_SHA: diagnosticSourceSha, MSCQR_INCIDENT_DIAGNOSTIC_AUTHORIZATION: JSON.stringify(authorization),
  MSCQR_INCIDENT_ADMIN_PASSWORD: "local-admin-only",
  RLS_CANARY_DATABASE_URL: fixtureUrl.toString() };
const clock = () => new Date("2026-11-12T14:00:00.000Z");
assert.equal(validateIncidentTaskInput({ env, argv: [], now: clock() }).authorization.executionId, executionId);
assert.throws(() => validateIncidentTaskInput({ env, argv: [], now: new Date(expiresAt) }), /expiry/);
assert.throws(() => validateIncidentTaskInput({ env: { ...env, UNREVIEWED: "1" }, argv: [], now: clock() }), /runtime/);
assert.throws(() => validateIncidentTaskInput({ env: { ...env, MSCQR_INCIDENT_DIAGNOSTIC_AUTHORIZATION: JSON.stringify({ ...authorization, querySha256: "c".repeat(64) }) }, argv: [], now: clock() }), /digest/);

const objects = new Map();
const s3 = { async send(command) {
  const { Key, Body } = command.input;
  if (command.constructor.name === "PutObjectCommand") {
    if (objects.has(Key)) throw new Error("PreconditionFailed");
    objects.set(Key, Body); return {};
  }
  assert.equal(command.constructor.name, "GetObjectCommand");
  const bytes = Buffer.from(objects.get(Key));
  return { ContentLength: bytes.length, Body: { async transformToByteArray() { return bytes; } } };
} };
const sts = { async send() { return { Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-full-rls-green-read-only-canary-task/test" }; } };
const result = { identity: [{ role: "mscqr_prd_rls_phase2_owner", session_role: "mscqr_prod_rls_canary_read",
  database_name: "mscqr_production_rls_green_phase2", read_only: "on" }], rls: Array.from({ length: 12 }, () => ({ rls_enabled: true, force_rls: true })),
  printJobs: [], printEvents: [], testLabel: [], testLabelAudit: [], sessions: [], support: [], batch: [], qrCounts: [], activity: [] };
const statements = [];
const administrativeStatements = [];
const executeSql = async (statement) => { administrativeStatements.push(statement); };
const imageSource = () => ({ gitSha: diagnosticSourceSha });
const createClient = () => ({ async $transaction(callback) { return callback({
  async $executeRawUnsafe(statement) { statements.push(statement); },
  async $queryRawUnsafe(statement) { statements.push(statement); return statement.includes(" AS evidence") ? [{ evidence: result }] : [{ set_config: executionId }]; },
}); }, async $disconnect() {} });
const first = await runIncidentTask({ env, argv: [], now: clock, s3, sts, createClient, executeSql, imageSource });
assert.equal(first.status, "COMPLETE");
assert.deepEqual(statements, sql.queryStatements);
assert.deepEqual(administrativeStatements, [sql.provision, sql.teardown]);
assert.equal(objects.size, 2);
assert.ok(![...objects.values()].join("").includes(fixturePassword));
assert.doesNotMatch([...objects.values()].join(""), /tokenHash|sessionCapabilityHash/);
await assert.rejects(runIncidentTask({ env, argv: [], now: clock, s3, sts, createClient, executeSql, imageSource }), /PreconditionFailed/);
assert.equal(objects.size, 2);
objects.clear();
administrativeStatements.length = 0;
await assert.rejects(runIncidentTask({ env, argv: [], now: clock, s3, sts, executeSql, imageSource,
  createClient: () => { throw new Error("synthetic read failure"); } }), /synthetic read failure/);
assert.deepEqual(administrativeStatements, [sql.provision, sql.teardown]);
assert.equal(JSON.parse(objects.get(`production-incident-20261112/${executionId}/terminal.json`)).evidence, null);
assert.deepEqual(JSON.parse(objects.get(`production-incident-20261112/${executionId}/terminal.json`)).failurePhases, ["READ"]);

for (const provisionCommitted of [true, false]) {
  objects.clear();
  administrativeStatements.length = 0;
  const provisionError = new Error(provisionCommitted ? "connection lost after commit" : "transaction refused before commit");
  const attempt = async (statement) => {
    administrativeStatements.push(statement);
    if (statement === sql.provision) throw provisionError;
  };
  await assert.rejects(runIncidentTask({ env, argv: [], now: clock, s3, sts, executeSql: attempt,
    createClient, imageSource }), (error) => error === provisionError);
  assert.deepEqual(administrativeStatements, [sql.provision, sql.teardown]);
  assert.deepEqual(JSON.parse(objects.get(`production-incident-20261112/${executionId}/terminal.json`)).failurePhases, ["PROVISION"]);
}

objects.clear();
const cleanupError = new Error("cleanup identity mismatch");
await assert.rejects(runIncidentTask({ env, argv: [], now: clock, s3, sts, createClient, imageSource,
  executeSql: async (statement) => { if (statement === sql.teardown) throw cleanupError; } }), (error) => error === cleanupError);
assert.deepEqual(JSON.parse(objects.get(`production-incident-20261112/${executionId}/terminal.json`)).failurePhases, ["CLEANUP"]);
assert.equal(JSON.parse(objects.get(`production-incident-20261112/${executionId}/terminal.json`)).evidence, null);

objects.clear();
const provisionError = new Error("provision timed out");
await assert.rejects(runIncidentTask({ env, argv: [], now: clock, s3, sts, createClient, imageSource,
  executeSql: async (statement) => { throw statement === sql.provision ? provisionError : cleanupError; } }),
  (error) => error instanceof AggregateError && error.errors[0] === provisionError && error.errors[1] === cleanupError);
assert.deepEqual(JSON.parse(objects.get(`production-incident-20261112/${executionId}/terminal.json`)).failurePhases, ["PROVISION", "CLEANUP"]);

objects.clear();
const receiptError = new Error("terminal receipt unavailable");
await assert.rejects(runIncidentTask({ env, argv: [], now: clock, sts, createClient, imageSource,
  s3: { send(command) { if (command.input.Key?.endsWith("terminal.json") && command.constructor.name === "PutObjectCommand") throw receiptError;
    return s3.send(command); } }, executeSql: async (statement) => { if (statement === sql.provision) throw provisionError; } }),
  (error) => error instanceof AggregateError && error.errors[0] === provisionError && error.errors[1] === receiptError);

if (process.env.INCIDENT_DIAGNOSTIC_TEST_CONTAINER) {
  const runSql = (statement, asAdmin = true) => execFileSync("docker", ["exec", "-i",
    process.env.INCIDENT_DIAGNOSTIC_TEST_CONTAINER, "psql", "-U", "postgres", "-d",
    "mscqr_production_rls_green_phase2", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"],
  { input: `${asAdmin ? "SET ROLE mscqr_prod_admin;\n" : ""}${statement}\n`, encoding: "utf8", timeout: 15000 });
  const assertSqlFailure = (statement, expected, asAdmin = true) => {
    assert.throws(() => runSql(statement, asAdmin), (error) => String(error.stderr).includes(expected));
  };
  const localIssuedAt = new Date(Date.now() - 60_000).toISOString();
  const localExpiresAt = new Date(Date.parse(localIssuedAt) + 1_800_000).toISOString();
  const local = buildIncidentDiagnosticSql({ executionId, issuedAt: localIssuedAt, expiresAt: localExpiresAt });
  const wrong = buildIncidentDiagnosticSql({ executionId: "22222222-2222-4222-8222-222222222222",
    issuedAt: localIssuedAt, expiresAt: localExpiresAt });
  let extraObject = false;
  try {
    runSql("ALTER ROLE mscqr_prod_rls_canary_read LOGIN", false);
    assertSqlFailure(local.provision, "predecessor or execution identity mismatch", false);
    runSql(local.teardown);
    runSql(local.provision);
    assert.equal(runSql("SELECT count(*) FROM pg_policy WHERE polname LIKE 'incident_20261112_%'" ).trim(), "11");
    assert.equal(runSql(`SELECT pg_get_userbyid(n.nspowner)||'|'||
      has_schema_privilege('mscqr_prod_rls_canary_read',n.oid,'USAGE')||'|'||
      has_schema_privilege('public',n.oid,'USAGE') FROM pg_namespace n
      WHERE n.nspname='mscqr_incident_20261112'`).trim(), "mscqr_prd_rls_phase2_owner|true|false");
    assert.equal(runSql(`SELECT pg_get_userbyid(p.proowner)||'|'||p.prosecdef||'|'||p.proconfig[1]||'|'||
      has_function_privilege('mscqr_prod_rls_canary_read',p.oid,'EXECUTE')||'|'||
      has_function_privilege('public',p.oid,'EXECUTE') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='mscqr_incident_20261112'`).trim(),
    "mscqr_prd_rls_phase2_owner|true|search_path=pg_catalog, pg_temp|true|false");
    assertSqlFailure(wrong.teardown, "cleanup target mismatch");
    runSql("SET ROLE mscqr_prd_rls_phase2_owner; CREATE TABLE mscqr_incident_20261112.unrelated_probe (id integer)", false);
    extraObject = true;
    assertSqlFailure(local.teardown, "cannot drop schema");
    assert.equal(runSql("SELECT count(*) FROM pg_policy WHERE polname LIKE 'incident_20261112_%'" ).trim(), "11");
    runSql("SET ROLE mscqr_prd_rls_phase2_owner; DROP TABLE mscqr_incident_20261112.unrelated_probe", false);
    extraObject = false;
    runSql(local.teardown);
    runSql(local.teardown);
    assert.equal(runSql("SELECT count(*) FROM pg_policy WHERE polname LIKE 'incident_20261112_%'" ).trim(), "0");
  } finally {
    if (extraObject) runSql("SET ROLE mscqr_prd_rls_phase2_owner; DROP TABLE IF EXISTS mscqr_incident_20261112.unrelated_probe", false);
    try { runSql(local.teardown); } finally { runSql("ALTER ROLE mscqr_prod_rls_canary_read NOLOGIN", false); }
  }
}
console.log("one-use incident diagnostic task contract passed");
