import assert from "node:assert/strict";
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
const first = await runIncidentTask({ env, argv: [], now: clock, s3, sts, createClient, executeSql, imageSource, onFailure: (error) => { throw error; } });
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
const failed = await runIncidentTask({ env, argv: [], now: clock, s3, sts, executeSql, imageSource,
  createClient: () => { throw new Error("synthetic read failure"); } });
assert.equal(failed.status, "FAILED_OR_INDETERMINATE");
assert.deepEqual(administrativeStatements, [sql.provision, sql.teardown]);
assert.equal(JSON.parse(objects.get(failed.terminalKey)).evidence, null);
console.log("one-use incident diagnostic task contract passed");
