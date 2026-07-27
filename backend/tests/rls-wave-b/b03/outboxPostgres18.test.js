const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_B03_OUTBOX_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_B03_OUTBOX_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_B03_OUTBOX_POSTGRES18_TEST";
const ids = {
  org: "00000000-0000-4000-8000-000000000101",
  licensee: "00000000-0000-4000-8000-000000000201",
  user: "00000000-0000-4000-8000-000000000301",
  refresh: "00000000-0000-4000-8000-000000004001",
};
let sequence = 0;
const requestId = () => `00000000-0000-4000-8000-${String(4100 + ++sequence).padStart(12, "0")}`;
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");

const safeUrl = (raw) => {
  const value = String(raw || "");
  const parsed = new URL(value);
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert(!/(staging|prod|amazonaws|rds)/i.test(value));
  return value;
};
const psql = (url, sql, expectFailure = false) => {
  const parsed = new URL(safeUrl(url));
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  const result = spawnSync("psql", [parsed.toString(), "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8", env: { ...process.env, PGPASSWORD: password || process.env.PGPASSWORD || "" },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) { assert.notEqual(result.status, 0, "denial probe unexpectedly succeeded"); return output; }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean).at(-1) || "";
};

async function main() {
  if (!enabled) return console.log("B03 durable outbox PostgreSQL 18 proof skipped");
  assert(confirmed, "B03 durable outbox PostgreSQL 18 proof confirmation is required");
  const workerUrl = safeUrl(process.env.DATABASE_URL);
  const appUrl = safeUrl(process.env.MSCQR_B03_OUTBOX_APP_URL);
  const bootstrapUrl = safeUrl(process.env.MSCQR_B03_OUTBOX_BOOTSTRAP_URL);
  const preauthUrl = safeUrl(process.env.MSCQR_B03_OUTBOX_PREAUTH_URL);
  assert.equal(Number(psql(bootstrapUrl, "select current_setting('server_version_num')::int / 10000")), 18);

  process.env.MSCQR_RLS_B03_WORKER_BOUNDARIES_ENABLED = "true";
  process.env.MSCQR_WORKER_DATABASE_ROLE = "mscqr_rls_cert_worker";
  process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS = "false";
  process.env.RUN_AUDIT_OUTBOX_WORKER = "true";
  const { PrismaClient, Prisma } = require("@prisma/client");
  const app = new PrismaClient({ datasources: { db: { url: appUrl } } });
  const worker2 = new PrismaClient({ datasources: { db: { url: workerUrl } } });
  const workerModule = require("../../../dist/config/database");
  const worker = workerModule.default || workerModule;
  const repository = require("../../../dist/rls-waves/session-b/b03/repositoryFunctions");
  const auditOutbox = require("../../../dist/services/auditLogOutboxService");
  const siemOutbox = require("../../../dist/services/siemOutboxService");

  const capability = crypto.randomBytes(32).toString("base64url");
  const refreshHash = sha("b03-outbox-refresh");
  psql(bootstrapUrl, `INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt") VALUES ('${ids.refresh}','${ids.org}','${ids.user}','${refreshHash}',transaction_timestamp()+interval '1 day',transaction_timestamp(),transaction_timestamp())`);
  psql(preauthUrl, `SELECT * FROM app_auth.issue_authenticated_session_capability('${ids.refresh}','${refreshHash}','${capability}','ADMIN_MFA',(transaction_timestamp()+interval '12 hours')::timestamp)`);

  const authority = (request) => ({ requestId: request, organizationId: ids.org, licenseeId: ids.licensee, manufacturerId: null, initiatingUserId: ids.user, initiatingActorRoleSnapshot: "LICENSEE_ADMIN" });
  const authenticated = (purpose, callback) => app.$transaction(async (tx) => {
    await tx.$queryRaw(Prisma.sql`SELECT * FROM app_auth.require_authenticated_session(${capability},${purpose},${requestId()})`);
    return callback(tx);
  });
  const auditPayload = (suffix) => ({ userId: ids.user, orgId: ids.org, licenseeId: ids.licensee, action: `B03_${suffix}`, entityType: "Certification", entityId: suffix, details: { suffix } });

  await assert.rejects(app.auditLogOutbox.findMany(), /permission denied/i);
  await assert.rejects(worker.auditLogOutbox.findMany(), /permission denied/i);
  await assert.rejects(app.auditLogOutbox.create({ data: { payload: {}, status: "QUEUED" } }), /permission denied/i);
  await assert.rejects(worker.$executeRawUnsafe('UPDATE public."AuditLogOutbox" SET status=status'), /permission denied/i);
  assert.match(psql(workerUrl, "SELECT app_rls.b03_bind_outbox_operation('audit-claim','',repeat('0',64))", true), /permission denied/i);
  assert.match(psql(workerUrl, "SELECT app_rls.install_actor_context('00000000-0000-4000-8000-000000000301','PLATFORM_SUPER_ADMIN','','','','system-verified','x','x')", true), /permission denied/i);
  assert.match(psql(workerUrl, "BEGIN; SELECT set_config('app.b03_outbox_operation','audit-claim',true),set_config('app.role','PLATFORM_SUPER_ADMIN',true); SELECT id FROM public.\"AuditLogOutbox\"; ROLLBACK", true), /permission denied/i);

  const catalog = JSON.parse(psql(bootstrapUrl, `SELECT json_build_object(
    'ownerLogin',(SELECT rolcanlogin FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner'),
    'ownerBypass',(SELECT rolbypassrls FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner'),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname='mscqr_rls_cert_auth_owner' AND c.relkind IN ('r','p')),
    'auditForce',(SELECT relforcerowsecurity FROM pg_class WHERE oid='public."AuditLogOutbox"'::regclass),
    'securityForce',(SELECT relforcerowsecurity FROM pg_class WHERE oid='public."SecurityEventOutbox"'::regclass),
    'publicExecute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname LIKE '%outbox%' AND has_function_privilege('public',p.oid,'EXECUTE')),
    'workerExecute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname LIKE '%outbox%' AND has_function_privilege('mscqr_rls_cert_worker',p.oid,'EXECUTE')),
    'appExecute',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname LIKE '%outbox%' AND has_function_privilege('mscqr_rls_cert_app',p.oid,'EXECUTE'))
  )`));
  assert.deepEqual(catalog, { ownerLogin: false, ownerBypass: false, ownerTables: 0, auditForce: true, securityForce: true, publicExecute: 0, workerExecute: 6, appExecute: 2 });

  const rollbackRequest = requestId();
  const rollbackBefore = Number(psql(bootstrapUrl, 'SELECT count(*) FROM public."AuditLogOutbox"'));
  await assert.rejects(authenticated("b03-audit-enqueue", async (tx) => {
    await auditOutbox.queueAuditLogOutbox(auditPayload("ROLLBACK"), undefined, tx, authority(rollbackRequest));
    throw new Error("B03_INJECTED_ROLLBACK");
  }), /B03_INJECTED_ROLLBACK/);
  assert.equal(Number(psql(bootstrapUrl, 'SELECT count(*) FROM public."AuditLogOutbox"')), rollbackBefore);

  const raceRequest = requestId();
  const raceId = await authenticated("b03-audit-enqueue", (tx) => auditOutbox.queueAuditLogOutbox(auditPayload("RACE"), undefined, tx, authority(raceRequest)));
  const attemptedAt = new Date();
  const [claimA, claimB] = await Promise.all([
    worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt, batchSize: 1 })),
    worker2.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt, batchSize: 1 })),
  ]);
  assert.deepEqual([claimA.length, claimB.length].sort(), [0, 1]);
  const raceClaim = [...claimA, ...claimB][0];
  assert.equal(raceClaim.id, raceId);

  const auditCountBefore = Number(psql(bootstrapUrl, 'SELECT count(*) FROM public."AuditLog"'));
  const securityCountBefore = Number(psql(bootstrapUrl, `SELECT count(*) FROM public."SecurityEventOutbox" WHERE "eventType"='AUDIT_LOG'`));
  await assert.rejects(worker.$transaction(async (tx) => {
    await repository.consumeAuditLogOutbox(tx, { jobId: raceClaim.id, payloadDigest: raceClaim.payloadDigest, attemptedAt: new Date() });
    throw new Error("B03_CONSUME_ROLLBACK");
  }), /B03_CONSUME_ROLLBACK/);
  assert.equal(Number(psql(bootstrapUrl, 'SELECT count(*) FROM public."AuditLog"')), auditCountBefore);
  assert.equal(Number(psql(bootstrapUrl, `SELECT count(*) FROM public."SecurityEventOutbox" WHERE "eventType"='AUDIT_LOG'`)), securityCountBefore);
  const consumed = await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: raceClaim.id, payloadDigest: raceClaim.payloadDigest, attemptedAt: new Date() }));
  assert.equal(consumed.replayed, false);
  const replay = await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: raceClaim.id, payloadDigest: raceClaim.payloadDigest, attemptedAt: new Date() }));
  assert.equal(replay.replayed, true);
  assert.equal(replay.auditLogId, consumed.auditLogId);
  assert.equal(Number(psql(bootstrapUrl, `SELECT count(*) FROM public."SecurityEventOutbox" WHERE "eventType"='AUDIT_LOG' AND payload->>'id'='${consumed.auditLogId}'`)), 1);

  const failureRequest = requestId();
  await authenticated("b03-audit-enqueue", (tx) => auditOutbox.queueAuditLogOutbox(auditPayload("FAIL"), undefined, tx, authority(failureRequest)));
  const [failureClaim] = await worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 1 }));
  const failed = await worker.$transaction((tx) => repository.failAuditLogOutbox(tx, { jobId: failureClaim.id, payloadDigest: failureClaim.payloadDigest, attemptedAt: new Date(), attempt: failureClaim.attempt, errorCode: "CERTIFIED_FAILURE" }));
  assert.equal(failed.terminal, false);

  const serverEvents = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => { serverEvents.push(JSON.parse(body)); res.writeHead(204); res.end(); });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  process.env.SIEM_WEBHOOK_URL = `http://127.0.0.1:${server.address().port}/events`;
  process.env.SIEM_SINK_MODE = "webhook";
  try {
    const cspRequest = requestId();
    await authenticated("b03-security-enqueue", async (tx) => siemOutbox.queueSecurityEvent("CSP_VIOLATION", { disposition: "blocked", requestId: cspRequest }, {
      db: tx, authority: { ...authority(cspRequest), initiatingActorRoleSnapshot: undefined },
    }));
    await siemOutbox.flushSecurityEventOutbox();
    assert(serverEvents.some(({ eventType }) => eventType === "AUDIT_LOG"));
    assert(serverEvents.some(({ eventType }) => eventType === "CSP_VIOLATION"));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  const mismatchKey = sha("b03-fixed-key");
  const firstPayload = { action: "FIRST", entityType: "Certification" };
  await authenticated("b03-audit-enqueue", (tx) => repository.enqueueAuditLogOutbox(tx, {
    ...authority(requestId()), payload: firstPayload, payloadDigest: repository.b03PayloadDigest(firstPayload), idempotencyKey: mismatchKey,
    expiresAt: new Date(Date.now() + 60_000), initialErrorCode: null,
  }));
  const secondPayload = { action: "SECOND", entityType: "Certification" };
  await assert.rejects(authenticated("b03-audit-enqueue", (tx) => repository.enqueueAuditLogOutbox(tx, {
    ...authority(requestId()), payload: secondPayload, payloadDigest: repository.b03PayloadDigest(secondPayload), idempotencyKey: mismatchKey,
    expiresAt: new Date(Date.now() + 60_000), initialErrorCode: null,
  })), /B03_OUTBOX_REPLAY_MISMATCH|Unique constraint/);

  psql(bootstrapUrl, `INSERT INTO public."AuditLogOutbox" (id,payload,"jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","initiatingUserId","expiresAt","updatedAt") VALUES ('${requestId()}', '{"action":"EXPIRED","entityType":"Certification"}', 'AUDIT_LOG_RECOVERY','${requestId()}','${sha("expired-payload")}','${sha("expired-key")}','${ids.org}','${ids.licensee}','${ids.user}',transaction_timestamp()-interval '1 minute',transaction_timestamp())`);
  const activeClaims = await worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 250 }));
  assert(activeClaims.every(({ expiresAt }) => expiresAt.getTime() > Date.now() - 1000));

  await app.$transaction(async (tx) => {
    await tx.$queryRaw(Prisma.sql`SELECT * FROM app_auth.require_authenticated_session(${capability},'b03-context-isolation',${requestId()})`);
  });
  const leaked = await app.$queryRaw`SELECT coalesce(current_setting('app.auth_session_verified',true),'') AS value`;
  assert.equal(String(leaked[0].value || ""), "");
  await app.$disconnect();
  await worker2.$disconnect();
  await worker.$disconnect();
  console.log("B03 durable outbox application-path proof passed");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
