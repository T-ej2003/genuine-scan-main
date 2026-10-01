const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
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
  const auditPayload = (suffix) => ({ userId: ids.user, orgId: ids.org, licenseeId: ids.licensee, action: `B03_${suffix}`, entityType: "Certification", entityId: suffix, details: { suffix, at: new Date("2026-10-01T00:00:00.000Z"), omitted: undefined } });

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

  // Upgrade fixtures were written under the actual nullable pre-correction shape,
  // before the current trigger was installed. Recovery must not invent authority.
  const legacyId = "00000000-0000-4000-8000-000000006101";
  const legacyDuplicate = "00000000-0000-4000-8000-000000006102";
  assert.equal(psql(bootstrapUrl, `SELECT ("payloadDigest" IS NULL AND "authorityProvenance" IS NULL)::text FROM public."AuditLogOutbox" WHERE id='${legacyId}'`), "true");
  await assert.rejects(worker.$transaction(async (tx) => {
    await repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 1 });
    throw new Error("LEGACY_CLAIM_ROLLBACK");
  }), /LEGACY_CLAIM_ROLLBACK/);
  assert.equal(psql(bootstrapUrl, `SELECT ("payloadDigest" IS NULL)::text FROM public."AuditLogOutbox" WHERE id='${legacyId}'`), "true");
  const [legacyA, legacyB] = await Promise.all([
    worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 1 })),
    worker2.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 1 })),
  ]);
  assert.equal(legacyA.length + legacyB.length, 1, "one durable legacy identity must win concurrent recovery");
  const legacyClaim = [...legacyA, ...legacyB][0];
  assert.equal(legacyClaim.id, legacyId);
  await worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 250 }));
  assert.equal(psql(bootstrapUrl, `SELECT "lastError" FROM public."AuditLogOutbox" WHERE id='${legacyDuplicate}'`), "B03_AUDIT_RECORD_DUPLICATE");
  assert.equal(psql(bootstrapUrl, `SELECT "lastError" FROM public."AuditLogOutbox" WHERE id='00000000-0000-4000-8000-000000006103'`), "B03_AUDIT_RECORD_UNRECONSTRUCTABLE");
  assert.equal(psql(bootstrapUrl, `SELECT status FROM public."AuditLogOutbox" WHERE id='00000000-0000-4000-8000-000000006104'`), "SENT");
  const recovered = JSON.parse(psql(bootstrapUrl, `SELECT "authorityProvenance" FROM public."AuditLogOutbox" WHERE id='${legacyId}'`));
  assert.equal(recovered.origin, "legacy-recovery");
  assert.equal(recovered.originalDigestPresent, false);
  assert.equal(recovered.recoveryDigestDerived, true);
  assert.equal(recovered.recordId, legacyId);
  await assert.rejects(worker.$transaction(async (tx) => {
    await repository.consumeAuditLogOutbox(tx, { jobId: legacyId, payloadDigest: legacyClaim.payloadDigest, attemptedAt: new Date() });
    throw new Error("LEGACY_COMPLETION_ROLLBACK");
  }), /LEGACY_COMPLETION_ROLLBACK/);
  assert.equal(psql(bootstrapUrl, `SELECT status FROM public."AuditLogOutbox" WHERE id='${legacyId}'`), "QUEUED");
  const legacyResult = await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: legacyId, payloadDigest: legacyClaim.payloadDigest, attemptedAt: new Date() }));
  const legacyReplay = await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: legacyId, payloadDigest: legacyClaim.payloadDigest, attemptedAt: new Date() }));
  assert.equal(legacyReplay.replayed, true);
  assert.equal(legacyReplay.auditLogId, legacyResult.auditLogId);
  const projected = JSON.parse(psql(bootstrapUrl, `SELECT details FROM public."AuditLog" WHERE id='${legacyResult.auditLogId}'`));
  assert.equal(projected.auditRecovery.originalDigestPresent, false);
  assert.equal(projected.auditRecovery.recoveryDigestDerived, true);

  // SQL verifies the existing TypeScript digest byte-for-byte, including number
  // notation, Unicode ordering, nested arrays and escaping.
  for (const vector of [{ z: [1e-7, 1e21, -3.25e22, 0.000001], a: { "😀": "x", "\ue000": "y", "line": "a\nb" } }, { n: 1.2345678901234567e-20 }]) {
    const json = JSON.stringify(vector).replaceAll("'", "''");
    assert.equal(psql(bootstrapUrl, `SELECT encode(sha256(convert_to(app_rls.b03_stable_json('${json}'::jsonb),'UTF8')),'hex')`), repository.b03PayloadDigest(vector));
  }
  const tampered = auditPayload("TAMPERED");
  await assert.rejects(authenticated("b03-audit-enqueue", (tx) => repository.enqueueAuditLogOutbox(tx, {
    ...authority(requestId()), payload: tampered, payloadDigest: "f".repeat(64), idempotencyKey: "e".repeat(64),
    expiresAt: new Date(Date.now() + 60_000), initialErrorCode: null,
  })), /B03_AUDIT_DIGEST_MISMATCH|Unique constraint failed/);
  assert.match(psql(bootstrapUrl, `INSERT INTO public."AuditLogOutbox" (id,payload,"authorityProvenance","updatedAt") VALUES ('${requestId()}','{"action":"FORGED","entityType":"Certification"}','{"version":1}',transaction_timestamp())`, true), /B03_AUDIT_RECORD_DENIED/);

  // All 19 writes share one table trigger. Replay the three exact persistence
  // shapes used by the 17 canonical SQL producers; business checks are unchanged.
  const producerFiles = ["session-b/b01/b01PreAuthSecurityFunctions.sql", "session-b/b01/b01RefreshRotationFunctions.sql", "session-b/b01/b01AuthenticationClosureFunctions.sql", "session-b/b03/b03OutboxFunctions.sql", "session-b/b03/scheduledJobIdentityFunctions.sql", "session-c/c03/c03AuthenticatedBoundaries.sql"];
  const producedIds = [];
  for (const file of producerFiles) {
    const source = fs.readFileSync(path.join(__dirname, "../../../src/rls-waves", file), "utf8");
    for (const match of source.matchAll(/INSERT INTO public\."AuditLogOutbox"/g)) {
      const name = [...source.slice(0, match.index).matchAll(/CREATE OR REPLACE FUNCTION ([^(]+)/g)].at(-1)[1];
      const columns = source.slice(match.index, source.indexOf("VALUES", match.index));
      const rowId = requestId(); producedIds.push(rowId);
      const request = requestId();
      const payload = JSON.stringify({ ...auditPayload(name), details: { producer: name } }).replaceAll("'", "''");
      const full = columns.includes('"requestId"');
      const suppliedDigest = columns.includes('"payloadDigest"');
      const fields = full ? ',"requestId","organizationId","licenseeId","initiatingUserId","expiresAt"' : '';
      const values = full ? `,'${request}','${ids.org}','${ids.licensee}','${ids.user}',transaction_timestamp()+interval '1 day'` : '';
      const digestFields = suppliedDigest ? ',"payloadDigest","idempotencyKey"' : '';
      const digestValue = `encode(sha256(convert_to('${payload}'::jsonb::text,'UTF8')),'hex')`;
      const digestValues = suppliedDigest ? `,${digestValue},encode(sha256(convert_to('AUDIT_LOG_RECOVERY:${request}:'||${digestValue},'UTF8')),'hex')` : '';
      psql(bootstrapUrl, `INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt"${fields}${digestFields}) VALUES ('${rowId}','${payload}',transaction_timestamp()${values}${digestValues})`);
      assert.equal(psql(bootstrapUrl, `SELECT app_rls.b03_audit_record_valid(q)::text FROM public."AuditLogOutbox" q WHERE q.id='${rowId}'`), "true", name);
    }
  }
  assert.equal(producedIds.length, 19);
  // A reused client request and identical audit payload must not collapse
  // two bare producer events or roll back the second business operation.
  const reusedRequest = requestId();
  const repeatedPayload = JSON.stringify(auditPayload("PROFILE_REPEATED"));
  const repeatedIds = [requestId(), requestId()];
  for (const id of repeatedIds) {
    psql(bootstrapUrl, `INSERT INTO public."AuditLogOutbox" (id,payload,"requestId","updatedAt") VALUES ('${id}','${repeatedPayload}','${reusedRequest}',transaction_timestamp())`);
    assert.equal(psql(bootstrapUrl, `SELECT "requestId"=id AND "authorityProvenance"->>'originalRequestId'='${reusedRequest}' AND app_rls.b03_audit_record_valid(q) FROM public."AuditLogOutbox" q WHERE id='${id}'`), "t");
  }
  assert.equal(Number(psql(bootstrapUrl, `SELECT count(DISTINCT "idempotencyKey") FROM public."AuditLogOutbox" WHERE id IN ('${repeatedIds.join("','")}')`)), 2);
  const shapeClaims = await worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 250 }));
  assert.equal(shapeClaims.length, 21);
  for (const claim of shapeClaims) {
    await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: claim.id, payloadDigest: claim.payloadDigest, attemptedAt: new Date() }));
  }

  const uppercaseRequest = "AABBCCDD-1234-4000-8000-ABCDEFABCDEF";
  const casePayload = auditPayload("UUID_CASE");
  const caseId = await authenticated("b03-audit-enqueue", (tx) => auditOutbox.queueAuditLogOutbox(casePayload, undefined, tx, authority(uppercaseRequest)));
  const caseReplay = await authenticated("b03-audit-enqueue", (tx) => auditOutbox.queueAuditLogOutbox(casePayload, undefined, tx, authority(uppercaseRequest.toLowerCase())));
  assert.equal(caseReplay, caseId);
  assert.equal(psql(bootstrapUrl, `SELECT "requestId" FROM public."AuditLogOutbox" WHERE id='${caseId}'`), uppercaseRequest.toLowerCase());
  psql(bootstrapUrl, `UPDATE public."AuditLogOutbox" SET "initiatingActorRoleSnapshot"='MANUFACTURER' WHERE id='${caseId}'`);
  await assert.rejects(authenticated("b03-audit-enqueue", (tx) => auditOutbox.queueAuditLogOutbox(casePayload, undefined, tx, authority(uppercaseRequest))), /B03_OUTBOX_REPLAY_MISMATCH|Unique constraint failed/);
  psql(bootstrapUrl, `UPDATE public."AuditLogOutbox" SET "initiatingActorRoleSnapshot"='LICENSEE_ADMIN' WHERE id='${caseId}'`);
  const [caseClaim] = await worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 1 }));
  assert.equal(caseClaim.id, caseId);
  await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: caseClaim.id, payloadDigest: caseClaim.payloadDigest, attemptedAt: new Date() }));

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
  psql(bootstrapUrl, `UPDATE public."AuditLogOutbox" SET "nextAttemptAt"=transaction_timestamp(),"claimLeaseExpiresAt"=NULL WHERE id='${failureClaim.id}'`);
  const [retryClaim] = await worker.$transaction((tx) => repository.claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize: 1 }));
  assert.equal(retryClaim.id, failureClaim.id);
  assert.equal(retryClaim.attempt, 2);
  await assert.rejects(worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: retryClaim.id, payloadDigest: "f".repeat(64), attemptedAt: new Date() })), /B03_OUTBOX_DENIED/);
  await worker.$transaction((tx) => repository.consumeAuditLogOutbox(tx, { jobId: retryClaim.id, payloadDigest: retryClaim.payloadDigest, attemptedAt: new Date() }));


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

  const fixedRequest = requestId();
  const firstPayload = { action: "FIRST", entityType: "Certification" };
  const mismatchKey = sha(`AUDIT_LOG_RECOVERY:${fixedRequest}:${repository.b03PayloadDigest(firstPayload)}`);
  await authenticated("b03-audit-enqueue", (tx) => repository.enqueueAuditLogOutbox(tx, {
    ...authority(fixedRequest), payload: firstPayload, payloadDigest: repository.b03PayloadDigest(firstPayload), idempotencyKey: mismatchKey,
    expiresAt: new Date(Date.now() + 60_000), initialErrorCode: null,
  }));
  const secondPayload = { action: "SECOND", entityType: "Certification" };
  await assert.rejects(authenticated("b03-audit-enqueue", (tx) => repository.enqueueAuditLogOutbox(tx, {
    ...authority(fixedRequest), payload: secondPayload, payloadDigest: repository.b03PayloadDigest(secondPayload), idempotencyKey: mismatchKey,
    expiresAt: new Date(Date.now() + 60_000), initialErrorCode: null,
  })), /B03_OUTBOX_REPLAY_MISMATCH|Unique constraint/);

  const expiredId = requestId();
  psql(bootstrapUrl, `INSERT INTO public."AuditLogOutbox" (id,payload,"jobType","requestId","organizationId","licenseeId","initiatingUserId","expiresAt","updatedAt") VALUES ('${expiredId}', '{"action":"EXPIRED","entityType":"Certification"}', 'AUDIT_LOG_RECOVERY','${requestId()}','${ids.org}','${ids.licensee}','${ids.user}',transaction_timestamp()+interval '1 minute',transaction_timestamp()); UPDATE public."AuditLogOutbox" SET "expiresAt"=transaction_timestamp()-interval '1 minute' WHERE id='${expiredId}'`);
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
