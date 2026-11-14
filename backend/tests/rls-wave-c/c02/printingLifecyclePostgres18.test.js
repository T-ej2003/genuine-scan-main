const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const { generateKeyPairSync, randomUUID } = require("node:crypto");
const { readFileSync } = require("node:fs");
const path = require("node:path");

const enabled = process.env.MSCQR_PRINTING_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_PRINTING_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_PRINTING_POSTGRES18_TEST";
const ids = {
  orgA: "50000000-0000-4000-8000-000000000101",
  orgB: "50000000-0000-4000-8000-000000000102",
  licenseeA: "50000000-0000-4000-8000-000000000201",
  licenseeB: "50000000-0000-4000-8000-000000000202",
  maker: "50000000-0000-4000-8000-000000000301",
  checker: "50000000-0000-4000-8000-000000000302",
  outsider: "50000000-0000-4000-8000-000000000303",
  makerRefresh: "50000000-0000-4000-8000-000000000401",
  checkerRefresh: "50000000-0000-4000-8000-000000000402",
  outsiderRefresh: "50000000-0000-4000-8000-000000000403",
  batch: "50000000-0000-4000-8000-000000000501",
  raceBatch: "50000000-0000-4000-8000-000000000502",
  qr: "50000000-0000-4000-8000-000000000601",
  raceQr: "50000000-0000-4000-8000-000000000602",
  printer: "50000000-0000-4000-8000-000000000701",
  foreignPrinter: "50000000-0000-4000-8000-000000000702",
  discoveredPrinter: "50000000-0000-4000-8000-000000000703",
  registration: "50000000-0000-4000-8000-000000000801",
  staleRegistration: "50000000-0000-4000-8000-000000000803",
};
const caps = { maker: "M".repeat(43), checker: "C".repeat(43), outsider: "O".repeat(43) };
const quorumCases = [
  { key: "job", policy: { type: "ONE_PER_PRINT_JOB" }, required: 1, batch: "50000000-0000-4000-8000-000000000511", job: "50000000-0000-4000-8000-000000000551" },
  { key: "roll", policy: { type: "ONE_PER_ROLL" }, required: 1, batch: "50000000-0000-4000-8000-000000000512", job: "50000000-0000-4000-8000-000000000552" },
  { key: "labels", policy: { type: "ONE_PER_N_LABELS", n: 4 }, required: 3, batch: "50000000-0000-4000-8000-000000000513", job: "50000000-0000-4000-8000-000000000553" },
  { key: "percentage", policy: { type: "PERCENTAGE", percentage: 20, min: 3 }, required: 3, batch: "50000000-0000-4000-8000-000000000514", job: "50000000-0000-4000-8000-000000000554" },
].map((entry, caseIndex) => ({
  ...entry,
  qrs: Array.from({ length: entry.required }, (_, index) => ({
    id: `50000000-0000-4000-8000-${String(700 + caseIndex * 10 + index).padStart(12, "0")}`,
    code: `printing-quorum-${entry.key}-${index + 1}`,
    displayCode: `QUORUM-${entry.key.toUpperCase()}-${index + 1}`,
  })),
}));
const hash = (value) => require("node:crypto").createHash("sha256").update(value).digest("hex");
const signingPair = generateKeyPairSync("ed25519");
const signingPrivateKey = signingPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const signingPublicKey = signingPair.publicKey.export({ type: "spki", format: "pem" }).toString();
const requestId = (() => {
  let sequence = 0;
  return () => `50000000-0000-4000-8000-${String(++sequence).padStart(12, "0")}`;
})();

const connection = (raw) => {
  const parsed = new URL(String(raw || ""));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert(!/(staging|prod|amazonaws|rds|shared)/i.test(raw));
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  return { url: parsed.toString(), password };
};
const psql = (raw, sql, expectFailure = false) => {
  const target = connection(raw);
  const result = spawnSync("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8",
    env: { ...process.env, PGPASSWORD: target.password },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) {
    assert.notEqual(result.status, 0, `denial probe unexpectedly succeeded: ${sql}`);
    return output;
  }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean).at(-1) || "";
};
const denied = (url, sql, pattern = /permission denied|PRINTING_BOUNDARY_DENIED|CONNECTOR_SESSION_DENIED|CONNECTOR_SESSION_NOT_ACTIVE|CONNECTOR_SESSION_REPLAY|AUTH_SESSION_CAPABILITY_DENIED|INVALID_STATE_TRANSITION|PRINT_ACK_REQUIRED|SAMPLE_SCAN_REQUIRED/i) =>
  assert.match(psql(url, sql, true), pattern);
const json = (url, sql) => JSON.parse(psql(url, sql));
const psqlAsync = (raw, sql) => new Promise((resolve) => {
  const target = connection(raw);
  const child = spawn("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    env: { ...process.env, PGPASSWORD: target.password },
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  child.on("close", (status) => resolve({ status, output: output.trim() }));
});

async function main() {
  if (!enabled) return console.log("Release Fix 5 PostgreSQL 18 proof skipped");
  assert(confirmed, "Release Fix 5 PostgreSQL 18 proof confirmation is required");
  const admin = process.env.MSCQR_PRINTING_ADMIN_URL;
  const preauth = process.env.MSCQR_PRINTING_PREAUTH_URL;
  const app = process.env.MSCQR_PRINTING_APP_URL;
  const worker = process.env.MSCQR_PRINTING_WORKER_URL;
  for (const url of [admin, preauth, app, worker]) connection(url);
  assert.equal(Number(psql(admin, "select current_setting('server_version_num')::int / 10000")), 18);
  const idempotencyKeyHash = hash("printing-idempotency-key");
  const idempotencyRequestHash = hash("printing-idempotency-request");
  const abortedKeyHash = hash("printing-idempotency-aborted-key");
  const abortedRequestHash = hash("printing-idempotency-aborted-request");

  psql(admin, `
    DELETE FROM public."ActionIdempotencyKey" WHERE "keyHash" IN ('${idempotencyKeyHash}','${abortedKeyHash}');
    DELETE FROM public."PrintItemEvent" WHERE "actorUserId" IN ('${ids.maker}','${ids.checker}','${ids.outsider}');
    DELETE FROM public."PrintAuditEvent" WHERE "batchId" IN ('${ids.batch}','${ids.raceBatch}');
    DELETE FROM public."PrintItem" WHERE "qrCodeId" IN ('${ids.qr}','${ids.raceQr}');
    DELETE FROM public."PrintSession" WHERE "batchId" IN ('${ids.batch}','${ids.raceBatch}');
    DELETE FROM public."PrintReissueRequest" WHERE "batchId" IN ('${ids.batch}','${ids.raceBatch}');
    DELETE FROM public."PrintJob" WHERE "batchId" IN ('${ids.batch}','${ids.raceBatch}');
    DELETE FROM public."SensitiveActionApproval" WHERE "entityType"='Batch' AND "entityId" IN ('${ids.batch}','${ids.raceBatch}');
    DELETE FROM public."AuditLog" WHERE "entityId"='${ids.batch}' OR "licenseeId"='${ids.licenseeA}';
    DELETE FROM public."SecurityEventOutbox" WHERE "licenseeId"='${ids.licenseeA}';
    DELETE FROM public."PrinterAttestation" WHERE "printerRegistrationId" IN ('${ids.registration}','${ids.staleRegistration}');
    DELETE FROM public."PrinterAgentSession" WHERE "registrationId" IN ('${ids.registration}','${ids.staleRegistration}');
    DELETE FROM public."RefreshToken" WHERE id IN ('${ids.makerRefresh}','${ids.checkerRefresh}','${ids.outsiderRefresh}');
    DELETE FROM public."Printer" WHERE id IN ('${ids.printer}','${ids.foreignPrinter}','${ids.discoveredPrinter}');
    DELETE FROM public."PrinterRegistration" WHERE id IN ('${ids.registration}','${ids.staleRegistration}');
    DELETE FROM public."QRCode" WHERE id IN ('${ids.qr}','${ids.raceQr}');
    DELETE FROM public."Batch" WHERE id IN ('${ids.batch}','${ids.raceBatch}');
    DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.maker}';
    DELETE FROM public."User" WHERE id IN ('${ids.maker}','${ids.checker}','${ids.outsider}');
    DELETE FROM public."Licensee" WHERE id IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}');
    INSERT INTO public."Organization"(id,name,"updatedAt") VALUES
      ('${ids.orgA}','Printing Org A',now()),('${ids.orgB}','Printing Org B',now());
    INSERT INTO public."Licensee"(id,"orgId",name,prefix,"updatedAt") VALUES
      ('${ids.licenseeA}','${ids.orgA}','Printing Licensee A','PRA',now()),
      ('${ids.licenseeB}','${ids.orgB}','Printing Licensee B','PRB',now());
    INSERT INTO public."User"(id,email,name,role,"orgId","licenseeId",status,"isActive","updatedAt") VALUES
      ('${ids.maker}','printing-maker@example.invalid','Printing Maker','MANUFACTURER_ADMIN','${ids.orgA}',NULL,'ACTIVE',true,now()),
      ('${ids.checker}','printing-checker@example.invalid','Printing Checker','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,now()),
      ('${ids.outsider}','printing-outsider@example.invalid','Printing Outsider','LICENSEE_ADMIN','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,now());
    INSERT INTO public."ManufacturerLicenseeLink"("manufacturerId","licenseeId","isPrimary","updatedAt")
      VALUES('${ids.maker}','${ids.licenseeA}',true,now());
    INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","lifecycleState","sampleScanPolicy","updatedAt")
      VALUES
      ('${ids.batch}','Printing Batch','${ids.licenseeA}','${ids.maker}','LBL-0001','LBL-0001',1,'CODES_GENERATED','{"mode":"ONE_PER_PRINT_JOB"}',now()),
      ('${ids.raceBatch}','Printing Race Batch','${ids.licenseeA}','${ids.maker}','LBL-0002','LBL-0002',1,'CODES_GENERATED','{"mode":"ONE_PER_PRINT_JOB"}',now());
    INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId",status,"updatedAt")
      VALUES
      ('${ids.qr}','immutable-printing-code','LBL-0001','${ids.licenseeA}','${ids.batch}','ALLOCATED',now()),
      ('${ids.raceQr}','immutable-printing-race-code','LBL-0002','${ids.licenseeA}','${ids.raceBatch}','ALLOCATED',now());
    INSERT INTO public."PrinterRegistration"(id,"userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem","trustStatus","approvedAt","lastSeenAt","updatedAt")
      VALUES
      ('${ids.registration}','${ids.maker}','${ids.orgA}','${ids.licenseeA}','printing-device','printing-agent','${signingPublicKey.replace(/'/g, "''")}','TRUSTED',now(),now(),now()),
      ('${ids.staleRegistration}','${ids.maker}','${ids.orgA}','${ids.licenseeA}','printing-device-stale','printing-agent-stale','-----BEGIN PUBLIC KEY----- fixture','TRUSTED',now(),now(),now());
    INSERT INTO public."Printer"(id,name,"connectionType","commandLanguage","nativePrinterId","agentId","deviceFingerprint","printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive","isDefault","updatedAt")
      VALUES
      ('${ids.printer}','Printing Local Agent','LOCAL_AGENT','ZPL','printing-native','printing-agent-stale','printing-device-stale','${ids.staleRegistration}','${ids.orgA}','${ids.licenseeA}','${ids.maker}','${ids.maker}',true,true,now()),
      ('${ids.discoveredPrinter}','Printing Local Agent','LOCAL_AGENT','ZPL','printing-native','printing-agent','printing-device','${ids.registration}','${ids.orgA}','${ids.licenseeA}','${ids.maker}','${ids.maker}',true,false,now());
    INSERT INTO public."Printer"(id,name,"connectionType","commandLanguage","ipAddress",port,"orgId","licenseeId","assignedUserId","createdByUserId","isActive","isDefault","updatedAt")
      VALUES('${ids.foreignPrinter}','Other Manufacturer Printer','NETWORK_DIRECT','ZPL','127.0.0.2',9100,'${ids.orgA}','${ids.licenseeA}','${ids.outsider}','${ids.outsider}',true,false,now());
    INSERT INTO public."PrinterAttestation"(id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt","signatureValid","trustValid",metadata)
      VALUES('50000000-0000-4000-8000-000000000802','${ids.registration}','${hash("fixture-attestation")}','fixture_attestation_nonce',now(),now()+interval '10 minutes',true,true,
        '{"connected":true,"selectedPrinterId":"printing-native","printers":[{"printerId":"printing-native","printerName":"Printing Local Agent"}]}');
    INSERT INTO public."RefreshToken"(id,"orgId","userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt") VALUES
      ('${ids.makerRefresh}','${ids.orgA}','${ids.maker}','${hash("maker-refresh")}',now()+interval '1 day',now(),now()),
      ('${ids.checkerRefresh}','${ids.orgA}','${ids.checker}','${hash("checker-refresh")}',now()+interval '1 day',now(),now()),
      ('${ids.outsiderRefresh}','${ids.orgB}','${ids.outsider}','${hash("outsider-refresh")}',now()+interval '1 day',now(),now());
  `);
  for (const [name, refresh] of [["maker", ids.makerRefresh], ["checker", ids.checkerRefresh], ["outsider", ids.outsiderRefresh]]) {
    psql(preauth, `SELECT id FROM app_auth.issue_authenticated_session_capability(
      '${refresh}','${hash(`${name}-refresh`)}','${caps[name]}','ADMIN_MFA',(now()+interval '1 hour')::timestamp
    )`);
  }

  for (const table of ["Batch", "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrintItemEvent", "PrintJobChunk", "Printer", "PrinterRegistration", "PrinterAgentSession", "ActionIdempotencyKey"]) {
    denied(app, `SELECT * FROM public."${table}" LIMIT 1`);
  }
  assert.equal(psql(admin, `SELECT bool_and(c.relrowsecurity AND c.relforcerowsecurity) FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
      AND c.relname IN ('PrintItemEvent','PrintJobChunk')`), "t");
  denied(app, `UPDATE public."PrinterRegistration" SET "trustStatus"='REVOKED' WHERE id='${ids.registration}'`);
  // Each psql call is a distinct backend process. The database, not a process map,
  // serializes replacement and signed-message sequence advancement.
  const sessionA = "50000000-0000-4000-8000-000000000901";
  const sessionB = "50000000-0000-4000-8000-000000000902";
  const sessionPayload = (extra = {}) => JSON.stringify({
    printerHealth: { healthVersion: 1, selectedPrinterId: "printing-native", observedAt: new Date().toISOString(),
      discovered: true, queueAvailable: true, online: true },
    printerId: ids.discoveredPrinter, selectedPrinterId: "printing-native",
    agentId: "printing-agent", deviceFingerprint: "printing-device",
    publicKeyFingerprint: hash(signingPublicKey), ...extra,
  });
  const sessionSql = (operation, id, payload, reg = ids.registration) =>
    `SELECT app_rls.printing_connector_session('${operation}','${id}','${reg}','${sessionPayload(payload)}'::jsonb)`;
  assert.equal(psql(admin, `SELECT data_type FROM information_schema.columns
    WHERE table_schema='public' AND table_name='PrinterAgentSession' AND column_name='lastMessageSeq'`), "integer");
  const open = (id, connectionId) => sessionSql("OPEN", id, { connectionId, helloNonce: `signed_hello_${connectionId}`, expirySeconds: 3600 });
  const advance = (id, messageSeq) => sessionSql("ADVANCE", id, {
    messageSeq, messageType: "heartbeat", signatureVerified: true,
    signedPayloadHash: hash(`${id}:${messageSeq}:payload`),
    signatureHash: hash(`${id}:${messageSeq}:signature`),
    heartbeatNonce: `signed_nonce_${messageSeq}_fixture`,
    heartbeatIssuedAt: new Date().toISOString(),
  });
  denied(worker, open(sessionA, sessionA));
  denied(app, open(sessionA, sessionA).replace(`'${ids.registration}'`, `'${ids.staleRegistration}'`));
  denied(app, sessionSql("OPEN", sessionA, { connectionId: sessionA, expirySeconds: 3600,
    printerId: ids.foreignPrinter }));
  denied(app, sessionSql("OPEN", sessionA, { connectionId: sessionA, expirySeconds: 3600,
    selectedPrinterId: "another-queue" }));
  denied(app, sessionSql("OPEN", sessionA, { connectionId: sessionA, expirySeconds: 3600,
    publicKeyFingerprint: hash("forged-key") }));
  psql(admin, `UPDATE public."Printer" SET "licenseeId"='${ids.licenseeB}' WHERE id='${ids.discoveredPrinter}'`);
  denied(app, open(sessionA, sessionA));
  psql(admin, `UPDATE public."Printer" SET "licenseeId"='${ids.licenseeA}' WHERE id='${ids.discoveredPrinter}'`);
  assert.equal(json(app, open(sessionA, sessionA)).state, "CONNECTED");
  denied(app, sessionSql("OPEN", sessionB, { connectionId: sessionB,
    helloNonce: `signed_hello_${sessionA}`, expirySeconds: 3600 }), /CONNECTOR_SESSION_REPLAY/);
  assert.equal(psql(admin, `SELECT id FROM public."PrinterAgentSession" WHERE "registrationId"='${ids.registration}' AND "connectionState"='CONNECTED'`), sessionA);
  denied(app, sessionSql("CHECK", sessionA, {}), /PRINTER_HEALTH_NOT_READY/);
  denied(app, `UPDATE public."PrinterAgentSession" SET "lastMessageSeq"=100 WHERE id='${sessionA}'`);
  assert.equal(json(app, advance(sessionA, 1)).lastMessageSeq, 1);
  denied(app, advance(sessionA, 1), /CONNECTOR_SESSION_REPLAY/);
  psql(admin, `UPDATE public."PrinterRegistration" SET "licenseeId"='${ids.licenseeB}' WHERE id='${ids.registration}';
    UPDATE public."Printer" SET "licenseeId"='${ids.licenseeB}' WHERE id='${ids.discoveredPrinter}'`);
  denied(app, advance(sessionA, 2), /CONNECTOR_SESSION_DENIED/);
  psql(admin, `UPDATE public."PrinterRegistration" SET "licenseeId"='${ids.licenseeA}' WHERE id='${ids.registration}';
    UPDATE public."Printer" SET "licenseeId"='${ids.licenseeA}' WHERE id='${ids.discoveredPrinter}'`);
  const parallel = await Promise.all([psqlAsync(app, advance(sessionA, 2)), psqlAsync(app, advance(sessionA, 2))]);
  assert.deepEqual(parallel.map(result => result.status === 0).sort(), [false, true]);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "lastSignedHeartbeatAt"=now()-interval '36 seconds' WHERE id='${sessionA}'`);
  denied(app, sessionSql("CHECK", sessionA, {}), /PRINTER_HEALTH_NOT_READY/);
  assert.equal(json(app, advance(sessionA, 3)).lastMessageSeq, 3);
  assert.equal(json(app, sessionSql("CHECK", sessionA, {})).state, "CONNECTED");
  psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"=now()-interval '1 second' WHERE id='${sessionA}'`);
  denied(app, advance(sessionA, 4), /CONNECTOR_SESSION_NOT_ACTIVE/);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"=now()+interval '1 hour' WHERE id='${sessionA}'`);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "revokedAt"=now() WHERE id='${sessionA}'`);
  denied(app, advance(sessionA, 4), /CONNECTOR_SESSION_NOT_ACTIVE/);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "revokedAt"=NULL WHERE id='${sessionA}'`);
  denied(app, sessionSql("ADVANCE", sessionA, { messageSeq: 4, messageType: "heartbeat",
    selectedPrinterId: "another-queue" }), /CONNECTOR_SESSION_DENIED/);
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=now() WHERE id='${ids.registration}'`);
  denied(app, advance(sessionA, 4));
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=NULL WHERE id='${ids.registration}'`);
  const revoking = psqlAsync(admin, `BEGIN;
    UPDATE public."PrinterRegistration" SET "revokedAt"=now() WHERE id='${ids.registration}';
    SELECT pg_sleep(1.5) /* stage1_registration_revocation_lock */;
    COMMIT;`);
  let revocationLockHeld = false;
  for (let attempt = 0; attempt < 40 && !revocationLockHeld; attempt += 1) {
    revocationLockHeld = Number(psql(admin, `SELECT count(*) FROM pg_stat_activity
      WHERE wait_event='PgSleep' AND query LIKE '%stage1_registration_revocation_lock%'`)) > 0;
    if (!revocationLockHeld) await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal(revocationLockHeld, true, "registration revocation transaction must hold its row lock");
  const [revoked, racedHeartbeat] = await Promise.all([revoking, psqlAsync(app, advance(sessionA, 4))]);
  assert.equal(revoked.status, 0);
  assert.notEqual(racedHeartbeat.status, 0, "heartbeat must not survive committed revocation");
  assert.match(racedHeartbeat.output, /CONNECTOR_SESSION_DENIED/);
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=NULL WHERE id='${ids.registration}'`);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"=now()+interval '1 second' WHERE id='${sessionA}'`);
  const holdingRegistration = psqlAsync(admin, `BEGIN;
    UPDATE public."PrinterRegistration" SET "revokedAt"=NULL WHERE id='${ids.registration}';
    SELECT pg_sleep(2) /* stage1_session_expiry_lock */;
    COMMIT;`);
  let expiryLockHeld = false;
  for (let attempt = 0; attempt < 40 && !expiryLockHeld; attempt += 1) {
    expiryLockHeld = Number(psql(admin, `SELECT count(*) FROM pg_stat_activity
      WHERE wait_event='PgSleep' AND query LIKE '%stage1_session_expiry_lock%'`)) > 0;
    if (!expiryLockHeld) await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal(expiryLockHeld, true, "expiry probe must hold the registration row lock");
  const [expiryLockRelease, expiredHeartbeat] = await Promise.all([holdingRegistration, psqlAsync(app, advance(sessionA, 4))]);
  assert.equal(expiryLockRelease.status, 0);
  assert.match(expiredHeartbeat.output, /CONNECTOR_SESSION_NOT_ACTIVE/);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"=now()+interval '1 hour' WHERE id='${sessionA}'`);
  assert.equal(json(app, open(sessionB, sessionB)).state, "CONNECTED");
  denied(app, advance(sessionA, 4), /CONNECTOR_SESSION_NOT_ACTIVE/);
  const socketClaim = (sessionId) => `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','session_claim_${requestId()}',now()::timestamp,
    '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.discoveredPrinter}',NULL,NULL,
    '{"sessionId":"${sessionId}","deliveryMode":"PERSISTENT_SESSION"}'::jsonb)`;
  denied(app, socketClaim(sessionA), /CONNECTOR_SESSION_NOT_ACTIVE/);
  psql(admin, `UPDATE public."Printer" SET "licenseeId"='${ids.licenseeB}' WHERE id='${ids.discoveredPrinter}'`);
  denied(app, socketClaim(sessionB), /CONNECTOR_BOUNDARY_DENIED/);
  psql(admin, `UPDATE public."Printer" SET "licenseeId"='${ids.licenseeA}' WHERE id='${ids.discoveredPrinter}'`);
  denied(app, socketClaim(sessionB), /CONNECTOR_SESSION_NOT_ACTIVE/);
  const socketTestClaim = (sessionId) => `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','CLAIM','${ids.discoveredPrinter}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','test_session_claim_${sessionId.slice(-4)}',
      'issuedAt',now(),'sessionId','${sessionId}'), '{}'::jsonb)`;
  denied(app, socketTestClaim(sessionA), /CONNECTOR_SESSION_NOT_ACTIVE/);
  denied(app, socketTestClaim(sessionB), /CONNECTOR_SESSION_NOT_ACTIVE/);
  assert.equal(json(app, advance(sessionB, 1)).lastMessageSeq, 1);
  assert.equal(json(app, socketClaim(sessionB)).available, false);
  assert.equal(json(app, socketTestClaim(sessionB)).available, false);
  assert.equal(json(app, sessionSql("CLOSE", sessionB, { reason: "socket_closed" })).state, "DISCONNECTED");
  denied(app, advance(sessionB, 2), /CONNECTOR_SESSION_NOT_ACTIVE/);
  const sessionC = "50000000-0000-4000-8000-000000000903";
  const sessionD = "50000000-0000-4000-8000-000000000904";
  const replacementOpens = await Promise.all([
    psqlAsync(app, open(sessionC, sessionC)), psqlAsync(app, open(sessionD, sessionD)),
  ]);
  assert.deepEqual(replacementOpens.map(result => result.status), [0, 0]);
  const currentSession = psql(admin, `SELECT id FROM public."PrinterAgentSession"
    WHERE "registrationId"='${ids.registration}' AND "connectionState"='CONNECTED' AND "revokedAt" IS NULL`);
  assert([sessionC, sessionD].includes(currentSession));
  const replacedSession = currentSession === sessionC ? sessionD : sessionC;
  denied(app, advance(replacedSession, 1), /CONNECTOR_SESSION_NOT_ACTIVE/);
  assert.equal(json(app, advance(currentSession, 1)).lastMessageSeq, 1);
  assert.equal(json(app, sessionSql("CLOSE", currentSession, { reason: "replacement_test" })).state, "DISCONNECTED");
  process.env.DATABASE_URL = app;
  const signedSessionBoundary = require("../../../dist/services/printerAgentSessionBoundaryService");
  const sessionSigning = require("../../../dist/services/printerAgentSigningService");
  const connectorVersion = require("../../../dist/services/localAgentProtocol").LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION;
  const signedHello = {
    type: "hello", registrationId: ids.registration, agentId: "printing-agent",
    deviceFingerprint: "printing-device", selectedPrinterId: "printing-native",
    connectorVersion, nonce: randomUUID(), issuedAt: new Date().toISOString(),
    printerHealth: { capabilities: { supportsPersistentPrintSession: true } },
  };
  signedHello.signature = sessionSigning.signPrinterAgentPayload(signingPrivateKey,
    sessionSigning.buildPrinterAgentSessionPayload({ ...signedHello, messageType: "hello" }));
  const liveSession = await signedSessionBoundary.openTrustedPrinterAgentSession(signedHello);
  await assert.rejects(
    signedSessionBoundary.openTrustedPrinterAgentSession(signedHello),
    "An accepted signed hello must not replace its own live session on replay",
  );
  assert.equal(psql(admin, `SELECT id FROM public."PrinterAgentSession" WHERE "registrationId"='${ids.registration}' AND "connectionState"='CONNECTED'`), liveSession.id);
  assert.equal(await signedSessionBoundary.buildNextPrintChunkForSession(liveSession), null,
    "A signed hello alone must wait for health, without claiming or closing the session");
  const signedHeartbeat = (messageSeq, targetSession = liveSession, health = {}, rawHealth) => {
    const message = { type: "heartbeat", sessionId: targetSession.id, messageSeq,
      printerHealth: rawHealth === undefined
        ? { healthVersion: 1, selectedPrinterId: "printing-native", observedAt: new Date().toISOString(),
          discovered: true, queueAvailable: true, online: true, ...health }
        : rawHealth,
      nonce: randomUUID(), issuedAt: new Date().toISOString() };
    message.signature = sessionSigning.signPrinterAgentPayload(signingPrivateKey,
      sessionSigning.buildPrinterAgentSessionPayload({ ...message, messageType: "heartbeat",
        registrationId: ids.registration, agentId: "printing-agent",
        deviceFingerprint: "printing-device", selectedPrinterId: "printing-native", connectorVersion }));
    return message;
  };
  const renewalCount = () => Number(psql(admin, `SELECT count(*) FROM public."PrinterAttestation"
    WHERE "printerRegistrationId"='${ids.registration}' AND metadata->>'source'='PERSISTENT_SESSION'`));
  const baselineRenewals = renewalCount();
  denied(app, `INSERT INTO public."PrinterAttestation"(
    id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt",
    "signatureValid","trustValid",metadata) VALUES (
    gen_random_uuid()::text,'${ids.registration}','${hash("forged")}',
    'forged_browser_nonce',now(),now()+interval '35 seconds',true,true,
    '{"source":"PERSISTENT_SESSION","connected":true}')`, /permission denied|row-level security/i);
  await signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, signedHeartbeat(1));
  assert.equal(renewalCount(), baselineRenewals + 1, "first signed heartbeat must replace prior evidence with session-bound attestation");
  await signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, signedHeartbeat(2));
  assert.equal(renewalCount(), baselineRenewals + 1, "fresh session-bound attestation must not trigger another write");
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()-interval '1 second'
    WHERE "printerRegistrationId"='${ids.registration}' AND metadata->>'sessionId'='${liveSession.id}'`);
  await signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession,
    signedHeartbeat(3, liveSession, { buildVersion: "0.0.0", capabilities: { supportsPersistentPrintSession: false } }));
  assert.equal(renewalCount(), baselineRenewals + 2, "expired attestation must renew from a signed socket heartbeat");
  const renewedAttestation = json(admin, `SELECT jsonb_build_object(
    'sessionId',metadata->>'sessionId','messageSeq',metadata->>'messageSeq',
    'selectedPrinterId',metadata->>'selectedPrinterId',
    'buildVersion',metadata->>'buildVersion',
    'unsignedHealthVersion',metadata->'printerHealth'->>'buildVersion',
    'capabilitiesPresent',metadata ? 'capabilities',
    'signatureValid',"signatureValid",
    'trustValid',"trustValid",'fresh',"expiresAt">now())
    FROM public."PrinterAttestation" WHERE "printerRegistrationId"='${ids.registration}'
      AND metadata->>'source'='PERSISTENT_SESSION' ORDER BY "createdAt" DESC LIMIT 1`);
  assert.deepEqual(renewedAttestation, { sessionId: liveSession.id, messageSeq: "3",
    selectedPrinterId: "printing-native", buildVersion: connectorVersion,
    unsignedHealthVersion: "0.0.0", capabilitiesPresent: false,
    signatureValid: true, trustValid: true, fresh: true });
  const activeReadiness = json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`);
  assert.equal(activeReadiness.eligibleForPrinting, true);
  const relayedAttestationId = requestId();
  psql(admin, `INSERT INTO public."PrinterAttestation"
    (id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt",
     "signatureValid","trustValid",metadata,"createdAt")
    VALUES ('${relayedAttestationId}','${ids.registration}','${hash("rest-relay")}',
      '${requestId()}',clock_timestamp(),clock_timestamp()+interval '35 seconds',true,true,
      '{"source":"REST_HEARTBEAT"}'::jsonb,clock_timestamp()+interval '1 millisecond')`);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, true, "A browser-relayed heartbeat cannot displace active session attestation");
  psql(admin, `DELETE FROM public."PrinterAttestation" WHERE id='${relayedAttestationId}'`);
  assert.equal(json(app, `SELECT app_rls.printing_connector_identity(
    'LOCAL_AGENT','printing-agent','printing-device','${ids.discoveredPrinter}',NULL,NULL,'VERIFY')`).eligibleForPrinting, true);
  psql(admin, `UPDATE public."PrinterRegistration" SET "orgId"='${ids.orgB}' WHERE id='${ids.registration}'`);
  assert.equal(json(app, `SELECT app_rls.printing_connector_identity(
    'LOCAL_AGENT','printing-agent','printing-device','${ids.discoveredPrinter}',NULL,NULL,'VERIFY')`).eligibleForPrinting,
  false, "tenant reassignment invalidates the persisted session scope");
  psql(admin, `UPDATE public."PrinterRegistration" SET "orgId"='${ids.orgA}' WHERE id='${ids.registration}'`);
  const invalidHeartbeat = signedHeartbeat(4);
  invalidHeartbeat.nonce = randomUUID();
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, invalidHeartbeat), /signature/i);
  assert.equal(renewalCount(), baselineRenewals + 2, "invalid signature cannot issue an attestation");
  const acceptedHeartbeat = signedHeartbeat(4);
  await signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, acceptedHeartbeat);
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, acceptedHeartbeat), /replay/i);
  assert.equal(renewalCount(), baselineRenewals + 2, "duplicate signed message cannot issue another attestation");
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()+interval '20 seconds'
    WHERE "printerRegistrationId"='${ids.registration}' AND metadata->>'source'='PERSISTENT_SESSION'`);
  const simultaneousHeartbeat = signedHeartbeat(5);
  const simultaneousResults = await Promise.allSettled([
    signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, simultaneousHeartbeat),
    signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, simultaneousHeartbeat),
  ]);
  assert.deepEqual(simultaneousResults.map(result => result.status).sort(), ["fulfilled", "rejected"]);
  assert.equal(renewalCount(), baselineRenewals + 3, "concurrent duplicate heartbeat must produce one renewal");
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()-interval '1 second'
    WHERE "printerRegistrationId"='${ids.registration}' AND metadata->>'source'='PERSISTENT_SESSION'`);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"=now()-interval '1 second' WHERE id='${liveSession.id}'`);
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, signedHeartbeat(6)), /authorized|active/i);
  assert.equal(renewalCount(), baselineRenewals + 3, "expired socket session cannot renew expired attestation");
  psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"=now()+interval '1 hour' WHERE id='${liveSession.id}'`);
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=now() WHERE id='${ids.registration}'`);
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, signedHeartbeat(6)), /authorized|active/i);
  assert.equal(renewalCount(), baselineRenewals + 3, "revoked registration cannot renew expired attestation");
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=NULL WHERE id='${ids.registration}'`);
  denied(app, sessionSql("ADVANCE", liveSession.id, { messageSeq: 6, messageType: "heartbeat",
    selectedPrinterId: "another-queue" }), /CONNECTOR_SESSION_DENIED/);
  assert.equal(renewalCount(), baselineRenewals + 3, "printer substitution cannot renew expired attestation");
  const reconnectHello = { ...signedHello, nonce: randomUUID(), issuedAt: new Date().toISOString() };
  reconnectHello.signature = sessionSigning.signPrinterAgentPayload(signingPrivateKey,
    sessionSigning.buildPrinterAgentSessionPayload({ ...reconnectHello, messageType: "hello" }));
  const reconnectedSession = await signedSessionBoundary.openTrustedPrinterAgentSession(reconnectHello);
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, signedHeartbeat(6)), /authorized|active/i);
  await signedSessionBoundary.recordTrustedSessionHeartbeat(reconnectedSession, signedHeartbeat(1, reconnectedSession));
  assert.equal(renewalCount(), baselineRenewals + 4, "replacement session must issue its own bound attestation");
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()+interval '1 second'
    WHERE "printerRegistrationId"='${ids.registration}' AND metadata->>'sessionId'='${reconnectedSession.id}'`);
  denied(app, `BEGIN; SELECT pg_sleep(2); SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.discoveredPrinter}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("lock-wait-expiry")}","tokenIssuedAt":"${new Date().toISOString()}","tokenExpiresAt":"${new Date(Date.now() + 3_600_000).toISOString()}"}]'::jsonb
  ); ROLLBACK;`, /PRINTER_ATTESTATION_STALE/, "transaction start cannot extend expired print authorization");
  await signedSessionBoundary.recordTrustedSessionHeartbeat(reconnectedSession, signedHeartbeat(2, reconnectedSession));
  assert.equal(renewalCount(), baselineRenewals + 5, "fresh signed evidence restores authorization after expiry");
  await signedSessionBoundary.closeTrustedPrinterAgentSession(reconnectedSession.id, "test complete");
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(reconnectedSession, signedHeartbeat(3, reconnectedSession)), /authorized|active/i);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`).eligibleForPrinting, false);
  assert.equal(json(app, `SELECT app_rls.printing_connector_identity(
    'LOCAL_AGENT','printing-agent','printing-device','${ids.discoveredPrinter}',NULL,NULL,'VERIFY')`).eligibleForPrinting, false);
  denied(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.discoveredPrinter}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("closed-session")}","tokenExpiresAt":"${new Date(Date.now() + 3_600_000).toISOString()}"}]'::jsonb
  )`, /PRINTER_ATTESTATION_STALE/, "closed persistent session cannot authorize job creation");
  const { PrismaClient, Prisma } = require("@prisma/client");
  const prismaAdmin = new PrismaClient({ datasources: { db: { url: admin } } });
  const prismaRelayId = requestId();
  psql(admin, `INSERT INTO public."PrinterAttestation"
    (id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt","signatureValid","trustValid",metadata,"createdAt")
    VALUES('${prismaRelayId}','${ids.registration}','${hash("prisma-rest")}', '${requestId()}',now(),now()+interval '35 seconds',true,true,
      '{"source":"REST_HEARTBEAT"}'::jsonb,now()+interval '1 second')`);
  try {
    const attestation = await prismaAdmin.printerAttestation.findFirst({
      where: { printerRegistrationId: ids.registration, expiresAt: { gt: new Date() },
        metadata: { path: ["operation"], equals: Prisma.DbNull }, OR: [
          { metadata: { path: ["source"], equals: "PERSISTENT_SESSION" } },
          { printerRegistration: { agentSessions: { none: {} } } },
        ] },
      orderBy: [{ createdAt: "desc" }],
    });
    assert.equal(attestation?.metadata?.source, "PERSISTENT_SESSION");
    assert.equal(attestation?.metadata?.sessionId, reconnectedSession.id);
    assert.equal(await prismaAdmin.printerAttestation.count({
      where: { printerRegistrationId: ids.staleRegistration,
        metadata: { path: ["source"], equals: "PERSISTENT_SESSION" } },
    }), 0, "Prisma renewal query remains registration scoped");
  } finally {
    psql(admin, `DELETE FROM public."PrinterAttestation" WHERE id='${prismaRelayId}'`);
    await prismaAdmin.$disconnect();
  }
  const prismaApp = new PrismaClient({ datasources: { db: { url: app } } });
  try {
    await assert.rejects(prismaApp.printerAttestation.findFirst({
      where: { printerRegistrationId: ids.registration,
        metadata: { path: ["operation"], equals: Prisma.DbNull } },
    }), /permission denied/i, "runtime app role cannot bypass the governed attestation projection");
  } finally { await prismaApp.$disconnect(); }
  // Resume the pre-existing legacy REST-attestation lifecycle fixtures after
  // the persistent-session denial checks above. These later assertions exercise
  // the compatibility path independently of the closed socket session.
  psql(admin, `INSERT INTO public."PrinterAttestation"(
    id,"printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt",
    "expiresAt","signatureValid","trustValid",metadata,"createdAt") VALUES (
    '50000000-0000-4000-8000-000000000805','${ids.registration}','${hash("legacy-followup")}',
    'legacy_followup_nonce',now(),now()+interval '10 minutes',true,true,
    '{"connected":true,"selectedPrinterId":"printing-native","printers":[{"printerId":"printing-native","printerName":"Printing Local Agent"}]}',
    now()+interval '1 second')`);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`).eligibleForPrinting,
  false, "legacy REST evidence cannot downgrade a registration with persisted session history");
  denied(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.discoveredPrinter}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("legacy-downgrade")}","tokenExpiresAt":"${new Date(Date.now() + 3_600_000).toISOString()}"}]'::jsonb
  )`, /PRINTER_ATTESTATION_STALE/, "legacy attestation cannot authorize after persistent session revocation");
  // Advance persisted evidence ages rather than waiting an hour. The production
  // signature verifier, governed SQL and database clock remain unchanged.
  const continuousHello = { ...signedHello, nonce: randomUUID(), issuedAt: new Date().toISOString() };
  continuousHello.signature = sessionSigning.signPrinterAgentPayload(signingPrivateKey,
    sessionSigning.buildPrinterAgentSessionPayload({ ...continuousHello, messageType: "hello" }));
  const continuousSession = await signedSessionBoundary.openTrustedPrinterAgentSession(continuousHello);
  const continuousBaseline = renewalCount();
  let rejectedReplays = 0;
  for (let sequence = 1; sequence <= 240; sequence++) {
    psql(admin, `UPDATE public."PrinterAgentSession" SET "expiresAt"="expiresAt"-interval '15 seconds',
      "lastSignedHeartbeatAt"="lastSignedHeartbeatAt"-interval '15 seconds'
      WHERE id='${continuousSession.id}';
      UPDATE public."PrinterAttestation" SET "expiresAt"="expiresAt"-interval '15 seconds',
      "createdAt"="createdAt"-interval '15 seconds',"attestedAt"="attestedAt"-interval '15 seconds'
      WHERE "printerRegistrationId"='${ids.registration}'`);
    const message = signedHeartbeat(sequence, continuousSession);
    await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, message);
    await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, message), /replayed/);
    rejectedReplays++;
    assert.equal(json(app, `SELECT app_rls.printing_readiness(
      '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`).eligibleForPrinting, true);
  }
  assert.equal(renewalCount() - continuousBaseline, 240, "at most one renewal per 15-second signed heartbeat");
  assert.equal(rejectedReplays, 240);
  console.log("CONTINUOUS_OPERATION simulatedSeconds=3600 heartbeats=240 renewals=240 replayRejections=240");
  let healthSequence = 240;
  const forgedHealth = signedHeartbeat(healthSequence+1, continuousSession);
  forgedHealth.printerHealth.online = false;
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, forgedHealth), /signature/i);
  for (const health of [ { online: false }, { queueAvailable: false }, { discovered: false },
    { selectedPrinterId: "wrong-printer" } ]) {
    await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
      signedHeartbeat(++healthSequence, continuousSession, health));
    denied(app, sessionSql("CHECK", continuousSession.id, {}), /PRINTER_HEALTH_NOT_READY/);
    assert.equal(await signedSessionBoundary.buildNextPrintChunkForSession(continuousSession), null,
      "An unavailable printer leaves the authenticated socket idle, not disconnected");
    denied(app, socketClaim(continuousSession.id), /PRINTER_ATTESTATION_STALE/);
    denied(app, socketTestClaim(continuousSession.id), /PRINTER_ATTESTATION_STALE/);
    assert.equal(json(app, `SELECT app_rls.printing_readiness(
      '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
      .eligibleForPrinting, false, "Unavailable or stale health must block despite a connected session");
    assert.equal(json(app, `SELECT app_rls.printing_readiness(
      '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
      .connected, true, "Printer failure must not falsely classify the authenticated connector as disconnected");
    denied(app, `SELECT app_rls.printing_create_job(
      '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.discoveredPrinter}',1,
      'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
      '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("unhealthy")}","tokenExpiresAt":"${new Date(Date.now()+3_600_000).toISOString()}"}]'::jsonb
    )`, /PRINTER_ATTESTATION_STALE/, "A previous healthy observation cannot authorize a job after failure");
    await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
      signedHeartbeat(++healthSequence, continuousSession));
    assert.equal(json(app, `SELECT app_rls.printing_readiness(
      '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
      .eligibleForPrinting, true, "Fresh signed health must restore readiness");
  }
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()-interval '1 second'
    WHERE metadata->>'sessionId'='${continuousSession.id}'`);
  const futureHealth = signedHeartbeat(++healthSequence, continuousSession,
    { observedAt: new Date(Date.now()+60_000).toISOString() });
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, futureHealth);
  denied(app, sessionSql("CHECK", continuousSession.id, {}), /PRINTER_HEALTH_NOT_READY/);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, false, "Future health cannot authorize printing");
  const correctedHealthObservedAt = new Date(Date.now()+1_000).toISOString();
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
    signedHeartbeat(++healthSequence, continuousSession,
      { observedAt: correctedHealthObservedAt }));
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, true, "Corrected workstation time must recover without waiting for the future timestamp");
  const beforeOlderHealthy = renewalCount();
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
    signedHeartbeat(++healthSequence, continuousSession,
      { observedAt: new Date(Date.parse(correctedHealthObservedAt)-500).toISOString() }));
  assert.equal(renewalCount(), beforeOlderHealthy,
    "An older but still fresh healthy observation must not replace or extend newer evidence");
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, true, "An older healthy observation must not erase newer verified readiness");
  const staleHealth = signedHeartbeat(++healthSequence, continuousSession,
    { observedAt: new Date(Date.now()-60_000).toISOString() });
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, staleHealth);
  assert.equal(Number(psql(admin, `SELECT "lastMessageSeq" FROM public."PrinterAgentSession" WHERE id='${continuousSession.id}'`)),
    healthSequence, "A fresh signed message with stale health must be consumed exactly once");
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, false, "Stale health must immediately displace an unexpired healthy attestation");
  denied(app, sessionSql("CHECK", continuousSession.id, {}), /PRINTER_HEALTH_NOT_READY/);
  denied(app, socketClaim(continuousSession.id), /PRINTER_ATTESTATION_STALE/);
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, staleHealth), /replay/i);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, false, "A replay cannot replace the negative health attestation");
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
    signedHeartbeat(++healthSequence, continuousSession,
      { observedAt: new Date(Date.now()+1_000).toISOString() }));
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, true, "Fresh signed health restores readiness after stale evidence");
  for (const [label, observedAt] of [
    ["missing", undefined], ["empty", ""], ["invalid date", "not-a-date"],
    ["invalid timezone", "2026-10-30T00:00:00+99:00"],
    ["impossible date", "2026-02-30T00:00:00Z"],
    ["out of range", "99999-01-01T00:00:00Z"],
    ["unexpected number", 42], ["unexpected object", { value: "old" }],
  ]) {
    const malformed = signedHeartbeat(++healthSequence, continuousSession, { observedAt });
    await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, malformed);
    assert.equal(json(app, `SELECT app_rls.printing_readiness(
      '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
      .eligibleForPrinting, false, `${label} must immediately displace an unexpired healthy attestation`);
    denied(app, sessionSql("CHECK", continuousSession.id, {}), /PRINTER_HEALTH_NOT_READY/);
    denied(app, socketClaim(continuousSession.id), /PRINTER_ATTESTATION_STALE/);
    denied(app, socketTestClaim(continuousSession.id), /PRINTER_ATTESTATION_STALE/);
    if (label === "missing") denied(app, `SELECT app_rls.printing_create_job(
      '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.discoveredPrinter}',1,
      'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
      '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("malformed-health")}","tokenExpiresAt":"${new Date(Date.now()+3_600_000).toISOString()}"}]'::jsonb
    )`, /PRINTER_ATTESTATION_STALE/, "Malformed health must block print-job creation");
    await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, malformed), /replay/i);
    await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
      signedHeartbeat(++healthSequence, continuousSession,
        { observedAt: new Date(Date.now()+1_000).toISOString() }));
    assert.equal(json(app, `SELECT app_rls.printing_readiness(
      '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
      .eligibleForPrinting, true, `${label} recovery requires fresh signed health`);
  }
  const malformedObject = signedHeartbeat(++healthSequence, continuousSession, {}, "not-an-object");
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, malformedObject);
  denied(app, sessionSql("CHECK", continuousSession.id, {}), /PRINTER_HEALTH_NOT_READY/);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, false, "A signed non-object health payload must fail closed");
  await signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession,
    signedHeartbeat(++healthSequence, continuousSession,
      { observedAt: new Date(Date.now()+1_000).toISOString() }));
  await signedSessionBoundary.closeTrustedPrinterAgentSession(continuousSession.id, "continuous_operation_complete");
  psql(admin, `DELETE FROM public."PrinterAttestation" WHERE metadata->>'sessionId'='${continuousSession.id}';
    UPDATE public."PrinterAttestation" SET "expiresAt"="expiresAt"+interval '3600 seconds',
      "createdAt"="createdAt"+interval '3600 seconds',"attestedAt"="attestedAt"+interval '3600 seconds'
    WHERE "printerRegistrationId"='${ids.registration}'`);
  // Isolate the older REST compatibility assertions below from the signed
  // persistent-session fixture. The disposable database has no live sockets.
  psql(admin, `DELETE FROM public."PrinterAgentSession" WHERE "registrationId"='${ids.registration}'`);
  denied(app, `SELECT "underInvestigationReason" FROM public."QRCode" WHERE id='${ids.qr}'`);
  denied(app, `UPDATE public."QRCode" SET code='forged' WHERE id='${ids.qr}'`);
  denied(app, `SELECT app_rls.install_actor_context('${ids.maker}','MANUFACTURER_ADMIN','${ids.orgA}','${ids.licenseeA}','${ids.maker}','mfa-verified','forged','printing-create-job')`);
  denied(app, `SELECT app_rls.printing_create_job(
    '', 'printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("missing-cap")}","tokenExpiresAt":"${new Date(Date.now() + 3_600_000).toISOString()}"}]'::jsonb
  )`);
  denied(app, `SELECT app_rls.printing_readiness('${caps.outsider}','printing-readiness','${requestId()}','BATCH','${ids.batch}','{}'::jsonb)`);
  const readiness = json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','BATCH','${ids.batch}','{}'::jsonb
  )`);
  assert.equal(readiness.batch.id, ids.batch);
  assert.deepEqual(Object.keys(readiness.printableItems[0]).sort(), [
    "batchId", "code", "displayCode", "id", "licenseeId", "replayEpoch", "status",
  ]);
  const relinked = json(app, `SELECT app_rls.printing_printer_administration(
    '${caps.maker}','printing-printer-admin','${requestId()}','RELINK','${ids.printer}',
    '{"printerRegistrationId":"${ids.registration}","nativePrinterId":"printing-native","agentId":"printing-agent","deviceFingerprint":"printing-device"}'::jsonb
  )`);
  assert.equal(relinked.printerRegistrationId, ids.registration);
  assert.equal(relinked.nativePrinterId, "printing-native");
  const validationBefore = json(admin, `SELECT jsonb_build_object('status',"lastValidationStatus",'message',"lastValidationMessage")
    FROM public."Printer" WHERE id='${ids.printer}'`);
  denied(app, `SELECT app_rls.printing_printer_administration(
    '${caps.maker}','printing-printer-admin','${requestId()}','UPDATE','${ids.printer}',
    '{"lastValidationStatus":"READY","lastValidationMessage":"unapproved manufacturer update"}'::jsonb
  )`, /PRINTING_BOUNDARY_DENIED/);
  assert.deepEqual(json(admin, `SELECT jsonb_build_object('status',"lastValidationStatus",'message',"lastValidationMessage")
    FROM public."Printer" WHERE id='${ids.printer}'`), validationBefore,
    "manufacturer validation must not mutate printer registry through UPDATE");
  assert.deepEqual(json(admin, `SELECT jsonb_build_object(
    'active',"isActive",'default',"isDefault",'registration',"printerRegistrationId",
    'native',"nativePrinterId",'status',"lastValidationStatus"
  ) FROM public."Printer" WHERE id='${ids.discoveredPrinter}'`), {
    active: false,
    default: false,
    registration: null,
    native: null,
    status: "RELINKED",
  });
  const idempotencyStart = json(app, `SELECT app_rls.printing_idempotency(
    '${caps.maker}','printing-idempotency','${requestId()}','BEGIN','PRINT_JOB_CREATE',
    '${idempotencyKeyHash}','${idempotencyRequestHash}',NULL,'{}'::jsonb
  )`);
  assert.equal(idempotencyStart.replayed, false);
  assert.equal(json(app, `SELECT app_rls.printing_idempotency(
    '${caps.maker}','printing-idempotency','${requestId()}','COMPLETE','PRINT_JOB_CREATE',
    '${idempotencyKeyHash}','${idempotencyRequestHash}',201,'{"success":true}'::jsonb
  )`).idempotent, false);
  const idempotencyReplay = json(app, `SELECT app_rls.printing_idempotency(
    '${caps.maker}','printing-idempotency','${requestId()}','BEGIN','PRINT_JOB_CREATE',
    '${idempotencyKeyHash}','${idempotencyRequestHash}',NULL,'{}'::jsonb
  )`);
  assert.equal(idempotencyReplay.replayed, true);
  assert.equal(idempotencyReplay.statusCode, 201);
  denied(app, `SELECT app_rls.printing_idempotency(
    '${caps.outsider}','printing-idempotency','${requestId()}','BEGIN','PRINT_JOB_CREATE',
    '${idempotencyKeyHash}','${idempotencyRequestHash}',NULL,'{}'::jsonb
  )`, /IDEMPOTENCY_KEY_PAYLOAD_MISMATCH/);
  assert.equal(json(app, `SELECT app_rls.printing_idempotency(
    '${caps.maker}','printing-idempotency','${requestId()}','BEGIN','PRINT_JOB_CREATE',
    '${abortedKeyHash}','${abortedRequestHash}',NULL,'{}'::jsonb
  )`).replayed, false);
  assert.equal(json(app, `SELECT app_rls.printing_idempotency(
    '${caps.maker}','printing-idempotency','${requestId()}','ABORT','PRINT_JOB_CREATE',
    '${abortedKeyHash}','${abortedRequestHash}',NULL,'{}'::jsonb
  )`).aborted, true);
  assert.equal(json(app, `SELECT app_rls.printing_idempotency(
    '${caps.maker}','printing-idempotency','${requestId()}','BEGIN','PRINT_JOB_CREATE',
    '${abortedKeyHash}','${abortedRequestHash}',NULL,'{}'::jsonb
  )`).replayed, false);

  const expires = new Date(Date.now() + 3_600_000).toISOString();
  const signedAt = new Date(Date.now() - 2_100).toISOString();
  denied(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','PDF',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("wrong-payload")}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`, /PRINTER_PAYLOAD_MISMATCH/);
  denied(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.foreignPrinter}',1,
    'LBL-0001','LBL-0001','NETWORK_DIRECT','ZPL',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("foreign-printer")}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`, /PRINTING_BOUNDARY_DENIED/);
  assert.equal(json(app, `SELECT app_rls.printing_connector_identity(
    'LOCAL_AGENT','printing-agent','printing-device','${ids.printer}',NULL,NULL,'VERIFY'
  )`).eligibleForPrinting, true, "legacy compatibility attestation remains available after relink");
  const testJobId = "50000000-0000-4000-8000-000000000901";
  const queuedTest = json(app, `SELECT app_rls.printing_test_label_job(
    '${caps.maker}','${requestId()}','QUEUE','${ids.printer}','{}'::jsonb,
    jsonb_build_object(
      'testJobId','${testJobId}','status','PENDING','createdAt',now(),
      'expiresAt',now()+interval '2 minutes','code','PRINTER-TEST',
      'payloadContent','^XA^FDMSCQR TEST^FS^XZ','payloadHash','${hash("^XA^FDMSCQR TEST^FS^XZ")}',
      'payloadType','ZPL','commandLanguage','ZPL',
      'printer',jsonb_build_object('id','${ids.printer}','nativePrinterId','printing-native')
    )
  )`);
  assert.equal(queuedTest.testJobId, testJobId);
  const testClaim = json(app, `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','CLAIM','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','test_claim_nonce_001','issuedAt',now()),
    '{}'::jsonb
  )`);
  assert.equal(testClaim.available, true);
  assert.equal(testClaim.testJobId, testJobId);
  psql(admin, `UPDATE public."Printer" SET metadata=jsonb_set(metadata,
    '{pendingLocalAgentTestLabel,expiresAt}',to_jsonb(now()-interval '1 minute'),false)
    WHERE id='${ids.printer}'`);
  denied(app, `SELECT app_rls.printing_test_label_job(
    '${caps.maker}','${requestId()}','QUEUE','${ids.printer}','{}'::jsonb,'{}'::jsonb
  )`, /DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  const automaticDuringLocalDiagnostic = () => `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','local_diag_claim_${requestId()}',now()::timestamp,
    '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.printer}',NULL,NULL,'{}'::jsonb)`;
  denied(app, automaticDuringLocalDiagnostic(), /DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  assert.equal(json(app, `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','ACK','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','test_ack_nonce_00001','issuedAt',now()),
    '{"testJobId":"${testJobId}","metadata":{"deviceJobRef":"spool-test"}}'::jsonb
  )`).matched, true);
  denied(app, automaticDuringLocalDiagnostic(), /DIAGNOSTIC_RECONCILIATION_REQUIRED/,
    "a test ACK must not release production work before physical confirmation");
  assert.equal(json(app, `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','CONFIRM','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','test_confirm_nonce1','issuedAt',now()),
    '{"testJobId":"${testJobId}","payloadType":"ZPL","deviceJobRef":"spool-test","confirmationMode":"LOCAL_QUEUE"}'::jsonb
  )`).matched, true);
  assert.equal(json(app, automaticDuringLocalDiagnostic()).available, false,
    "confirmed local diagnostic must release the automatic dispatch gate");
  assert.equal(psql(admin, `SELECT metadata->'pendingLocalAgentTestLabel'->>'status' FROM public."Printer" WHERE id='${ids.printer}'`), "CONFIRMED");
  assert(psql(admin, `SELECT metadata->>'lastTestLabelConfirmedAt' FROM public."Printer" WHERE id='${ids.printer}'`));
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."AuditLog"
    WHERE action IN ('PRINTER_TEST_LABEL_ACK','PRINTER_TEST_LABEL_CONFIRM')
      AND "entityId"='${ids.printer}'`)), 2);
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()-interval '1 second' WHERE "printerRegistrationId"='${ids.registration}'`);
  assert.equal(json(app, `SELECT app_rls.printing_connector_identity(
    'LOCAL_AGENT','printing-agent','printing-device','${ids.printer}',NULL,NULL,'VERIFY'
  )`).eligibleForPrinting, false);
  denied(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("stale-printer")}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`, /PRINTER_ATTESTATION_STALE/);
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()+interval '10 minutes' WHERE "printerRegistrationId"='${ids.registration}'`);
  for (const issuedAt of [null, new Date(Date.now() + 3_600_000).toISOString()]) {
    const item = { qrCodeId: ids.qr, tokenNonce: "a".repeat(64), tokenHash: hash("invalid-issued-at"), tokenExpiresAt: expires };
    if (issuedAt) item.tokenIssuedAt = issuedAt;
    denied(app, `SELECT app_rls.printing_create_job(
      '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
      'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL',NULL,'${JSON.stringify([item])}'::jsonb
    )`, /PRINTING_INVALID_INPUT/);
    assert.equal(psql(admin, `SELECT count(*) FROM public."PrintJob" WHERE "batchId"='${ids.batch}'`), "0");
  }
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=now() WHERE id='${ids.registration}'`);
  denied(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL','${hash("revoked-lock")}',
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("revoked-token")}","tokenIssuedAt":"${signedAt}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`, /PRINTER_ATTESTATION_STALE/);
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintJob" WHERE "batchId"='${ids.batch}'`), "0");
  psql(admin, `UPDATE public."PrinterRegistration" SET "revokedAt"=NULL WHERE id='${ids.registration}'`);
  const registrationHolder = psqlAsync(admin, `BEGIN;
    UPDATE public."PrinterRegistration" SET "lastSeenAt"=clock_timestamp() WHERE id='${ids.registration}';
    SELECT pg_sleep(1.5) /* printing_registration_lock_held */;
    DO $lock_order$ BEGIN
      WHILE (SELECT count(*) FROM pg_stat_activity a
        WHERE a.pid<>pg_backend_pid()
          AND (a.query LIKE '%printing_create_lock_order_probe%'
            OR a.query LIKE '%printing_test_label_lock_order_probe%')
          AND a.wait_event_type='Lock' AND cardinality(pg_blocking_pids(a.pid))>0)<2 LOOP
        IF clock_timestamp()>transaction_timestamp()+interval '15 seconds' THEN
          RAISE EXCEPTION 'print create and diagnostic did not reach registration lock';
        END IF;
        PERFORM pg_sleep(0.05);
      END LOOP;
    END $lock_order$;
    SELECT id FROM public."Printer" WHERE id='${ids.printer}' FOR UPDATE;
    COMMIT;`);
  let registrationLockHeld = false;
  for (let attempt = 0; attempt < 40 && !registrationLockHeld; attempt += 1) {
    registrationLockHeld = Number(psql(admin, `SELECT count(*) FROM pg_stat_activity
      WHERE wait_event='PgSleep' AND query LIKE '%printing_registration_lock_held%'`)) > 0;
    if (!registrationLockHeld) await new Promise(resolve => setTimeout(resolve, 25));
  }
  assert.equal(registrationLockHeld, true, "registration transaction must hold its row lock");
  const createAttempt = psqlAsync(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL','${hash("print-lock")}',
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("print-token")}","tokenIssuedAt":"${signedAt}","tokenExpiresAt":"${expires}"}]'::jsonb
  ) /* printing_create_lock_order_probe */`);
  const diagnosticAttempt = psqlAsync(app, `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','CLAIM','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','concurrent_test_claim_0001','issuedAt',now()),
    '{}'::jsonb
  ) /* printing_test_label_lock_order_probe */`);
  const [registrationResult, createResult, diagnosticResult] = await Promise.all([registrationHolder, createAttempt, diagnosticAttempt]);
  assert.equal(registrationResult.status, 0, registrationResult.output);
  assert.equal(createResult.status, 0, createResult.output);
  assert.equal(diagnosticResult.status, 0, diagnosticResult.output);
  assert.equal(JSON.parse(diagnosticResult.output).available, false);
  const created = JSON.parse(createResult.output);
  assert.equal(created.preparedCount, 1);
  assert.equal(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE action='PRINT_JOB_CREATED' AND "entityId"='${created.job.id}'`), "1");
  assert.equal(new Date(`${psql(admin, `SELECT to_char("tokenIssuedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS') FROM public."QRCode" WHERE id='${ids.qr}'`)}Z`).toISOString(), signedAt);
  const immutableCode = psql(admin, `SELECT code FROM public."QRCode" WHERE id='${ids.qr}'`);
  psql(admin, `UPDATE public."Printer" SET metadata=jsonb_set(
    jsonb_set(metadata,'{pendingLocalAgentTestLabel,status}','"ACKED"'::jsonb,false),
    '{pendingLocalAgentTestLabel,claimedAt}',to_jsonb(now()-interval '2 minutes'),true)
    WHERE id='${ids.printer}'`);
  denied(app, automaticDuringLocalDiagnostic(), /DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintItem" pi JOIN public."PrintSession" ps
    ON ps.id=pi."printSessionId" WHERE ps."printJobId"='${created.job.id}' AND pi.state='RESERVED'`), "1",
    "diagnostic gate must reject the actual claim before RESERVED advances to ISSUED");
  psql(admin, `UPDATE public."Printer" SET metadata=jsonb_set(metadata,
    '{pendingLocalAgentTestLabel,status}','"CONFIRMED"'::jsonb,false) WHERE id='${ids.printer}'`);

  const claim = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','claim_nonce_00001',now()::timestamp,
    '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.printer}','${hash("claim")}',NULL,'{}'::jsonb
  )`);
  assert.equal(claim.available, true);
  const duplicateDelivery = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','claim_nonce_00002',now()::timestamp,
    '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.printer}','${hash("claim-again")}',NULL,'{}'::jsonb
  )`);
  assert.equal(duplicateDelivery.available, false, "A claimed item must not be delivered again after an uncertain spool submission");
  assert.equal(claim.qrCode.code, immutableCode);
  assert.equal(json(app, `SELECT app_rls.printing_connector_identity(
    'LOCAL_AGENT','printing-agent','printing-device','${ids.printer}',NULL,NULL,'VERIFY'
  )`).eligibleForPrinting, true, "action receipt cannot displace the latest readiness heartbeat");
  denied(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','confirm_too_early',now()::timestamp,
    '${requestId()}','CONFIRM','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash("early")}','spool-1','{}'::jsonb
  )`, /PRINT_ACK_REQUIRED/);
  denied(app, `BEGIN; SELECT app_rls.printing_control_job(
    '${caps.maker}','printing-job-control','${requestId()}','${created.job.id}','ABANDON','Unsafe after connector claim'
  ); ROLLBACK`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  const ack = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','ack_nonce_0000001',now()::timestamp,
    '${requestId()}','ACK','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash("ack")}','spool-1','{}'::jsonb
  )`);
  assert.equal(ack.operation, "ACK");
  denied(app, `SELECT app_rls.printing_control_job(
    '${caps.outsider}','printing-job-control','${requestId()}','${created.job.id}','ABANDON','Other tenant'
  )`, /PRINTING_BOUNDARY_DENIED/);
  denied(app, `BEGIN; SELECT app_rls.printing_control_job(
    '${caps.maker}','printing-job-control','${requestId()}','${created.job.id}','ABANDON','Unsafe after connector claim'
  ); ROLLBACK`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${created.job.id}'`), "SENT");
  assert.equal(psql(admin, `SELECT "confirmationDeadlineAt" IS NOT NULL FROM public."PrintItem" WHERE id='${claim.printItemId}'`), "t",
    "a signed local ACK must have a deadline for bounded reconciliation");
  const replayAck = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','ack_nonce_0000002',now()::timestamp,
    '${requestId()}','ACK','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash("ack-replay")}','spool-1','{}'::jsonb
  )`);
  assert.equal(replayAck.idempotent, true);
  const confirmation = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','confirm_nonce_001',now()::timestamp,
    '${requestId()}','CONFIRM','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash("confirm")}','spool-1','{"physical":true}'::jsonb
  )`);
  assert.equal(confirmation.remainingToPrint, 0);
  const sample = json(app, `SELECT app_rls.printing_record_sample(
    '${caps.maker}','printing-sample-scan','${requestId()}','${created.job.id}','${immutableCode}','{"scanner":"focused-proof"}'::jsonb
  )`);
  assert.equal(sample.satisfied, true);
  const serializedOld='00000000-0000-4000-8000-000000000901',serializedNew='00000000-0000-4000-8000-000000000902';
  const serializedOldSession=randomUUID(),serializedNewSession=randomUUID(),serializedOldQr=randomUUID(),serializedNewQr=randomUUID();
  const serializedOldItem=randomUUID(),serializedNewItem=randomUUID();
  psql(admin,`INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"createdAt","updatedAt")
    VALUES('${serializedOld}','${ids.raceBatch}','${ids.maker}','${ids.printer}','SENT','LOCAL_AGENT','PRINTER_ACKNOWLEDGED',1,'1800-01-01',now()),
      ('${serializedNew}','${ids.raceBatch}','${ids.maker}','${ids.printer}','PENDING','LOCAL_AGENT','QUEUED',1,'1801-01-01',now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","issuedItems","updatedAt")
    VALUES('${serializedOldSession}','${serializedOld}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,1,now()),
      ('${serializedNewSession}','${serializedNew}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,0,now());
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt")
    VALUES('${serializedOldQr}','serialized-old-${serializedOldQr}','${ids.licenseeA}','${ids.raceBatch}','${serializedOld}','ALLOCATED',now()),
      ('${serializedNewQr}','serialized-new-${serializedNewQr}','${ids.licenseeA}','${ids.raceBatch}','${serializedNew}','ALLOCATED',now());
    INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","issuedAt","agentAckedAt","confirmationDeadlineAt","updatedAt")
    VALUES('${serializedOldItem}','${serializedOldSession}','${serializedOldQr}','serialized-old','AGENT_ACKED','PRINTER_ACKNOWLEDGED',now()-interval '20 minutes',now()-interval '20 minutes',now()-interval '10 minutes',now()),
      ('${serializedNewItem}','${serializedNewSession}','${serializedNewQr}','serialized-new','RESERVED','QUEUED',NULL,NULL,NULL,now());`);
  const serializedClaim=(nonce)=>`SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device',
    '${nonce}',now()::timestamp,'${requestId()}','CLAIM',NULL,NULL,'${ids.printer}','${hash(nonce)}',NULL,'{}'::jsonb)`;
  const holdTransition=async(sql,marker,role=app)=>{
    const holder=psqlAsync(role,`BEGIN; ${sql}; SELECT pg_sleep(4) /* ${marker} */; COMMIT`);
    let held=false;
    for(let attempt=0;attempt<120&&!held;attempt++){
      held=psql(admin,`SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND wait_event='PgSleep' AND query LIKE '%${marker}%'`) !== '0';
      if(!held)await new Promise(resolve=>setTimeout(resolve,25));
    }
    assert(held,`${marker}: transition must finish inside a still-open transaction`);
    const blocked=json(app,serializedClaim(`${marker}_claim`));
    assert.equal(blocked.available,false,`${marker}: no newer claim during uncertain transition`);
    assert.equal(psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${serializedNewItem}'`),'RESERVED');
    const result=await holder;
    assert.equal(result.status,0,result.output);
  };
  await holdTransition(`SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${serializedOld}','STOP','Synthetic serial fence')`,'serial_stop');
  assert.equal(psql(admin,`SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${serializedOld}'`),'STOPPED:NEEDS_OPERATOR_ACTION');
  psql(admin,`UPDATE public."PrintJob" SET status='SENT',"pipelineState"='PRINTER_ACKNOWLEDGED' WHERE id='${serializedOld}';
    UPDATE public."PrintSession" SET status='ACTIVE' WHERE id='${serializedOldSession}';
    UPDATE public."PrintItem" SET state='AGENT_ACKED',"pipelineState"='PRINTER_ACKNOWLEDGED' WHERE id='${serializedOldItem}';`);
  await holdTransition(`SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',1)`,'serial_reconcile',worker);
  assert.equal(psql(admin,`SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${serializedOld}'`),'PAUSED:NEEDS_OPERATOR_ACTION');
  assert.equal(json(app,serializedClaim('serial_after_reconcile')).available,false);
  psql(admin,`DELETE FROM public."PrintItem" WHERE id IN ('${serializedOldItem}','${serializedNewItem}');
    DELETE FROM public."QRCode" WHERE id IN ('${serializedOldQr}','${serializedNewQr}');
    DELETE FROM public."PrintSession" WHERE id IN ('${serializedOldSession}','${serializedNewSession}');
    DELETE FROM public."PrintJob" WHERE id IN ('${serializedOld}','${serializedNew}');`);
  console.log('PASS PostgreSQL printer-scoped STOP/reconcile versus claim interleaving');
  const quorumBatchIds = quorumCases.map((entry) => `'${entry.batch}'`).join(",");
  const quorumJobIds = quorumCases.map((entry) => `'${entry.job}'`).join(",");
  const quorumQrIds = quorumCases.flatMap((entry) => entry.qrs).map((entry) => `'${entry.id}'`).join(",");
  psql(admin, `
    DELETE FROM public."PrintAuditEvent" WHERE "batchId" IN (${quorumBatchIds});
    DELETE FROM public."QRCode" WHERE id IN (${quorumQrIds});
    DELETE FROM public."PrintJob" WHERE id IN (${quorumJobIds});
    DELETE FROM public."Batch" WHERE id IN (${quorumBatchIds});
    ${quorumCases.map((entry) => `
      INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","lifecycleState","sampleScanPolicy","updatedAt")
      VALUES('${entry.batch}','Quorum ${entry.key}','${ids.licenseeA}','${ids.maker}','${entry.qrs[0].displayCode}','${entry.qrs.at(-1).displayCode}',10,'PRINT_CONFIRMED','${JSON.stringify(entry.policy)}'::jsonb,now());
      INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"pipelineState",quantity,"confirmedAt","updatedAt")
      VALUES('${entry.job}','${entry.batch}','${ids.maker}','${ids.printer}','CONFIRMED','PRINT_CONFIRMED',10,now(),now());
      ${entry.qrs.map((qr) => `INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId","printJobId",status,"updatedAt")
      VALUES('${qr.id}','${qr.code}','${qr.displayCode}','${ids.licenseeA}','${entry.batch}','${entry.job}','PRINTED',now());`).join("\n")}
    `).join("\n")}
  `);
  for (const entry of quorumCases) {
    let result;
    for (const qr of entry.qrs) {
      result = json(app, `SELECT app_rls.printing_record_sample(
        '${caps.maker}','printing-sample-scan','${requestId()}','${entry.job}','${qr.code}','{}'::jsonb
      )`);
    }
    assert.equal(result.required, entry.required, `${entry.key} quorum requirement`);
    assert.equal(result.actual, entry.required, `${entry.key} quorum evidence count`);
    assert.equal(result.satisfied, true, `${entry.key} quorum satisfaction`);
    assert.equal(psql(admin, `SELECT "lifecycleState" FROM public."Batch" WHERE id='${entry.batch}'`), "SAMPLE_VERIFIED");
  }
  denied(app, `SELECT app_rls.printing_release_batch(
    '${caps.maker}','printing-release','${requestId()}','${ids.batch}','APPROVE',NULL
  )`, /MAKER_CANNOT_APPROVE/);
  const released = json(app, `SELECT app_rls.printing_release_batch(
    '${caps.checker}','printing-release','${requestId()}','${ids.batch}','APPROVE','focused checker approval'
  )`);
  assert.equal(released.lifecycleState, "RELEASED");
  assert.equal(psql(admin, `SELECT code FROM public."QRCode" WHERE id='${ids.qr}'`), immutableCode);
  denied(app, `SELECT app_rls.printing_release_batch(
    '${caps.checker}','printing-release','${requestId()}','${ids.batch}','APPROVE',NULL
  )`, /BATCH_ALREADY_RELEASED/);

  const raceSql = (suffix) => `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.raceBatch}','${ids.printer}',1,
    'LBL-0002','LBL-0002','LOCAL_AGENT','ZPL','${hash(`race-lock-${suffix}`)}',
    '[{"qrCodeId":"${ids.raceQr}","tokenNonce":"${suffix.repeat(64)}","tokenHash":"${hash(`race-token-${suffix}`)}","tokenIssuedAt":"${signedAt}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`;
  const race = await Promise.all([psqlAsync(app, raceSql("b")), psqlAsync(app, raceSql("c"))]);
  assert.equal(race.filter((entry) => entry.status === 0).length, 1, "one concurrent print-job creation must win");
  assert.equal(race.filter((entry) => entry.status !== 0).length, 1, "the conflicting print-job creation must fail closed");
  assert.match(race.find((entry) => entry.status !== 0).output, /ACTIVE_PRINT_JOB_EXISTS|BATCH_BUSY/);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."PrintJob" WHERE "batchId"='${ids.raceBatch}'`)), 1);
  denied(app, `SELECT app_rls.printing_record_sample(
    '${caps.maker}','printing-sample-scan','${requestId()}','${created.job.id}','immutable-printing-race-code','{}'::jsonb
  )`, /QR_NOT_IN_PRINT_JOB/);

  const beforeAudit = Number(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE "entityId"='${ids.batch}'`));
  denied(app, `BEGIN; SELECT app_rls.printing_release_batch(
    '${caps.checker}','printing-release','${requestId()}','${ids.batch}','REJECT','rollback'
  ); SELECT 1/0; COMMIT`, /INVALID_STATE_TRANSITION|division by zero/);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE "entityId"='${ids.batch}'`)), beforeAudit);

  denied(app, `SELECT app_rls.printing_worker_reconcile('RECONCILE_BATCHES','${requestId()}',10)`);
  denied(worker, `SELECT app_rls.printing_readiness('${caps.maker}','printing-readiness','${requestId()}','BATCH','${ids.batch}','{}'::jsonb)`);
  denied(worker, `SELECT app_rls.printing_test_label_job(NULL,'${requestId()}','CLAIM','${ids.printer}','{}'::jsonb,'{}'::jsonb)`);
  assert.doesNotThrow(() => psql(worker, `SELECT app_rls.printing_worker_reconcile('RECONCILE_BATCHES','${requestId()}',10)`));

  // A non-subject list must reach its unchanged tenant/actor authorization branch.
  const reissueId="50000000-0000-4000-8000-000000000901";
  psql(admin, `INSERT INTO public."PrintReissueRequest"(id,"originalPrintJobId","requestedByUserId","licenseeId","manufacturerId","batchId","requestedByRole","targetApproverRole",reason,"updatedAt")
    VALUES('${reissueId}','${created.job.id}','${ids.maker}','${ids.licenseeA}','${ids.maker}','${ids.batch}','MANUFACTURER_ADMIN','LICENSEE_ADMIN','Local list certification',now())`);
  const listSql=(cap,subject="NULL",options="{}")=>`SELECT app_rls.printing_readiness('${cap}','printing-readiness','${requestId()}','REISSUE_LIST',${subject},'${options}'::jsonb)`;
  assert(json(app,listSql(caps.checker)).some(row=>row.id===reissueId));
  assert(json(app,listSql(caps.maker)).some(row=>row.id===reissueId));
  psql(admin,`UPDATE public."Batch" SET "manufacturerId"='${ids.outsider}' WHERE id='${ids.batch}'`);
  assert.deepEqual(json(app,listSql(caps.maker)),[]);
  psql(admin,`UPDATE public."Batch" SET "manufacturerId"='${ids.maker}' WHERE id='${ids.batch}'; DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.maker}' AND "licenseeId"='${ids.licenseeA}'; INSERT INTO public."ManufacturerLicenseeLink"("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES('${ids.maker}','${ids.licenseeB}',true,now())`);
  assert.deepEqual(json(app,listSql(caps.maker)),[]);
  assert.deepEqual(json(app,`SET app.printing_licensee_id='${ids.licenseeA}'; ${listSql(caps.maker)}`),[]);
  psql(admin,`DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.maker}'; INSERT INTO public."ManufacturerLicenseeLink"("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES('${ids.maker}','${ids.licenseeA}',true,now())`);
  assert(json(app,listSql(caps.maker)).some(row=>row.id===reissueId));
  assert.deepEqual(json(app,listSql(caps.outsider)),[]);
  psql(admin,`UPDATE public."User" SET "orgId"='${ids.orgB}' WHERE id='${ids.checker}'`);
  assert.deepEqual(json(app,listSql(caps.checker)),[]);
  psql(admin,`UPDATE public."User" SET "orgId"='${ids.orgA}' WHERE id='${ids.checker}'; UPDATE public."Licensee" SET "isActive"=false WHERE id='${ids.licenseeA}'`);
  assert.deepEqual(json(app,listSql(caps.checker)),[]);
  assert.deepEqual(json(app,listSql(caps.maker)),[]);
  psql(admin,`UPDATE public."Licensee" SET "isActive"=true WHERE id='${ids.licenseeA}'`);
  assert(json(app,listSql(caps.checker,"'00000000-0000-4000-8000-000000000000'")).some(row=>row.id===reissueId));
  assert.deepEqual(json(app,`SET app.role='SUPER_ADMIN'; SET app.printing_licensee_id='${ids.licenseeA}'; ${listSql(caps.outsider)}`),[]);
  denied(app,listSql("")); denied(app,listSql("Z".repeat(43)));
  denied(app,`SET app.auth_session_verified='1'; SET app.printing_role='SUPER_ADMIN'; ${listSql("")}`);
  denied(app,`SELECT * FROM public."PrintReissueRequest" LIMIT 1`);
  psql(admin,`UPDATE public."User" SET role='MANUFACTURER_ADMIN' WHERE id='${ids.outsider}'`);
  assert.deepEqual(json(app,listSql(caps.outsider)),[]);
  psql(admin,`UPDATE public."User" SET role='ORG_ADMIN' WHERE id='${ids.outsider}'`);
  denied(app,listSql(caps.outsider));
  psql(admin,`UPDATE public."User" SET role='LICENSEE_ADMIN' WHERE id='${ids.outsider}'`);
  for(const role of ['SUPER_ADMIN','PLATFORM_SUPER_ADMIN']) {
    psql(admin,`UPDATE public."User" SET role='${role}' WHERE id='${ids.checker}'`);
    assert(json(app,listSql(caps.checker,"NULL",'{"limit":1}')).some(row=>row.id===reissueId));
    assert(json(app,listSql(caps.checker,"NULL",'{"limit":10000}')).length<=200);
  }
  psql(admin,`UPDATE public."User" SET role='LICENSEE_ADMIN',"isActive"=false WHERE id='${ids.checker}'`);
  denied(app,listSql(caps.checker));
  psql(admin,`UPDATE public."User" SET "isActive"=true WHERE id='${ids.checker}'; UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=now() WHERE id='${ids.checkerRefresh}'`);
  denied(app,listSql(caps.checker));
  psql(admin,`UPDATE public."RefreshToken" SET "sessionCapabilityRevokedAt"=NULL WHERE id='${ids.checkerRefresh}'`);

  process.env.NODE_ENV="test";
  process.env.JWT_SECRET="local-printing-http-certification-secret-only";
  process.env.DATABASE_URL=app;
  const { createBackendApp }=require("../../../dist/app");
  const { signAccessToken }=require("../../../dist/services/auth/tokenService");
  const { sealCookieToken }=require("../../../dist/services/auth/cookieTokenProtectionService");
  const server=await new Promise(resolve=>{const server=createBackendApp().listen(0,"127.0.0.1",()=>resolve(server));});
  const httpList=async(name,expected,extraHeaders={})=>{
    const role=name==="maker"?"MANUFACTURER_ADMIN":"LICENSEE_ADMIN";
    const scopeVersion=name==="maker"?psql(admin,`SELECT to_char("updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.maker}' AND "licenseeId"='${ids.licenseeA}'`):null;
    const headers=name?{
      authorization:`Bearer ${signAccessToken({userId:ids[name],email:"printing-http@example.invalid",role,sessionId:ids[`${name}Refresh`],orgId:name==="outsider"?ids.orgB:ids.orgA,licenseeId:name==="outsider"?ids.licenseeB:ids.licenseeA,scopeVersion,authenticatedAt:new Date().toISOString()})}`,
      "x-database-session-capability":sealCookieToken(caps[name],"auth.database-session"),...extraHeaders,
    }:extraHeaders;
    const response=await fetch(`http://127.0.0.1:${server.address().port}/api/manufacturer/print-reissue-requests`,{headers});
    assert.equal(response.status,expected,`printing list HTTP status ${response.status}`);
    return response.json();
  };
  try {
    assert((await httpList("checker",200)).data.some(row=>row.id===reissueId));
    assert((await httpList("maker",200)).data.some(row=>row.id===reissueId));
    assert((await httpList("checker",200,{"x-request-id":"not-a-uuid"})).data.some(row=>row.id===reissueId),
      "server request-ID normalization preserves authorized database-backed printing reads");
    assert.deepEqual((await httpList("outsider",200)).data,[]);
    await httpList(null,401);
    await httpList("checker",401,{"x-database-session-capability":"invalid"});
    psql(admin,`UPDATE public."User" SET "isActive"=false WHERE id='${ids.checker}'`);
    await httpList("checker",401);
    psql(admin,`UPDATE public."User" SET "isActive"=true WHERE id='${ids.checker}'`);
  } finally { await new Promise(resolve=>server.close(resolve)); }

  // Fence an eligible queued job while concurrent authenticated claims race
  // the request. Already accepted work remains acknowledgeable/confirmable.
  const maintenanceSql = (capability, operation) => `SELECT app_rls.printing_printer_administration(
    '${capability}','printing-printer-admin','${requestId()}','${operation}','${ids.printer}','{}'::jsonb)`;
  denied(app, maintenanceSql(caps.outsider, 'MAINTENANCE_REQUEST'), /PRINTING_BOUNDARY_DENIED|query returned no rows/);
  denied(app, `SELECT app_rls.printing_maintenance_gate('forged','REQUEST','forged','{}'::jsonb)`, /permission denied/);
  const diagnosticReservation=requestId();
  const reserveDiagnostic=id=>`SELECT app_rls.printing_printer_administration('${caps.maker}','printing-printer-admin','${id}','DIAGNOSTIC_LEASE','${ids.printer}','{}'::jsonb)`;
  json(app,reserveDiagnostic(diagnosticReservation));
  denied(app,reserveDiagnostic(diagnosticReservation),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  const nextDiagnostic=requestId();
  denied(app,reserveDiagnostic(nextDiagnostic),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  const completeDiagnostic=id=>`SELECT app_rls.printing_printer_administration('${caps.maker}','printing-printer-admin','${id}','DIAGNOSTIC_COMPLETE','${ids.printer}','{"outcome":"confirmed","deviceJobRef":"synthetic-odometer:1"}'::jsonb)`;
  const abortDiagnostic=id=>`SELECT app_rls.printing_printer_administration('${caps.maker}','printing-printer-admin','${id}','DIAGNOSTIC_ABORT','${ids.printer}','{"outcome":"pre_dispatch_rejected","reason":"synthetic baseline unavailable before transmission"}'::jsonb)`;
  const rejectedDiagnostic=requestId();
  denied(app,abortDiagnostic(requestId()),/PRINTING_MAINTENANCE_DENIED/);
  denied(app,abortDiagnostic(diagnosticReservation).replace('pre_dispatch_rejected','uncertain'),/PRINTING_MAINTENANCE_DENIED/);
  denied(app,`SELECT app_rls.printing_printer_administration('${caps.outsider}','printing-printer-admin','${diagnosticReservation}','DIAGNOSTIC_ABORT','${ids.printer}',
    '{"outcome":"pre_dispatch_rejected","reason":"forged"}'::jsonb)`,/PRINTING_BOUNDARY_DENIED/);
  json(app,completeDiagnostic(diagnosticReservation));
  json(app,reserveDiagnostic(rejectedDiagnostic));
  json(app,abortDiagnostic(rejectedDiagnostic));
  denied(app,abortDiagnostic(rejectedDiagnostic),/PRINTING_MAINTENANCE_DENIED/);
  denied(app,completeDiagnostic(rejectedDiagnostic),/PRINTING_MAINTENANCE_DENIED/);
  denied(app,reserveDiagnostic(rejectedDiagnostic),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  const diagnosticInventory=json(app,reserveDiagnostic(nextDiagnostic));
  assert.equal(diagnosticInventory.diagnostics[diagnosticReservation].state,'CONFIRMED','completed diagnostic history remains durable');
  assert.equal(diagnosticInventory.diagnostics[rejectedDiagnostic].state,'REJECTED_PRE_DISPATCH','proved pre-dispatch failure is terminal and auditable');
  assert.equal(diagnosticInventory.diagnostics[nextDiagnostic].state,'ACCEPTED');
  psql(admin,`UPDATE public."SystemCheckpoint" SET value=jsonb_set(value,ARRAY['diagnostics','${nextDiagnostic}','acceptedAt'],
    to_jsonb(now()-interval '2 days'),false) WHERE key LIKE 'connector-maintenance:%' AND value->'diagnostics' ? '${nextDiagnostic}'`);
  denied(app,reserveDiagnostic(requestId()),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  psql(admin, `UPDATE public."PrintJob" SET status='SENT' WHERE id='${created.job.id}';
    UPDATE public."PrintSession" SET status='ACTIVE' WHERE "printJobId"='${created.job.id}';
    UPDATE public."PrintItem" SET state='ISSUED' WHERE id='${claim.printItemId}';`);
  const issuedBefore = psql(admin, `SELECT count(*) FROM public."PrintItem" WHERE state='ISSUED'`);
  const fencing = psqlAsync(app, `BEGIN; ${maintenanceSql(caps.maker,'MAINTENANCE_REQUEST')};
    SELECT pg_sleep(1.5) /* connector_maintenance_race */; COMMIT;`);
  let fenceHeld = false;
  for (let probe = 0; probe < 100 && !fenceHeld; probe++) {
    fenceHeld = Number(psql(admin, `SELECT count(*) FROM pg_stat_activity WHERE pid<>pg_backend_pid()
      AND query LIKE '%connector_maintenance_race%' AND wait_event='PgSleep'`)) > 0;
    if (!fenceHeld) await new Promise(resolve => setTimeout(resolve, 25));
  }
  if(!fenceHeld) assert.equal((await fencing).status,0,'maintenance request must succeed before its race can be certified');
  assert(fenceHeld, 'maintenance transaction must hold its lock before racing claims');
  const fencedClaims = await Promise.all(Array.from({ length: 4 }, (_, index) => psqlAsync(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','maintenance_race_${index}',now()::timestamp,
    '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.printer}',NULL,NULL,'{}'::jsonb)`)));
  assert.equal((await fencing).status, 0);
  for (const result of fencedClaims) {
    assert.notEqual(result.status, 0);
    assert.match(result.output, /CONNECTOR_MAINTENANCE_FENCED/);
  }
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintItem" WHERE state='ISSUED'`), issuedBefore);
  const fenceStatus = json(app, maintenanceSql(caps.maker,'MAINTENANCE_STATUS'));
  assert.equal(fenceStatus.state,'DISPATCH_FENCED');
  const advisoryHolder = new PrismaClient({ datasources: { db: { url: admin } } });
  try {
    await advisoryHolder.$transaction(async tx => {
      await tx.$queryRawUnsafe(`SELECT pg_advisory_xact_lock(hashtextextended('printing_printer_${ids.printer}',0))::text AS held`);
      const lockedClaim = await psqlAsync(app, `SELECT app_rls.printing_connector_event(
        '${ids.registration}','printing-agent','printing-device','maintenance_lock_race_1',now()::timestamp,
        '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.printer}',NULL,NULL,'{}'::jsonb)`);
      assert.notEqual(lockedClaim.status, 0, `fenced claim returned ${lockedClaim.output}`);
      assert.match(lockedClaim.output, /CONNECTOR_MAINTENANCE_FENCED/);
    }, { timeout: 10000 });
  } finally { await advisoryHolder.$disconnect(); }
  assert.equal(fenceStatus.upgradeAllowed,false,'backend fencing alone must never authorize legacy replacement');
  const settledLocalDiagnostics=json(app,maintenanceSql(caps.maker,'MAINTENANCE_INVENTORY'));
  assert.equal(settledLocalDiagnostics.inventory.localDiagnostics.length,0,
    'physically confirmed local diagnostic history does not require reconciliation');
  const fencedAck = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','maintenance_ack_1',now()::timestamp,
    '${requestId()}','ACK','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash('maint-ack')}','synthetic-spool','{}'::jsonb)`);
  assert.equal(fencedAck.operation,'ACK');
  const fencedConfirmation = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','maintenance_confirm',now()::timestamp,
    '${requestId()}','CONFIRM','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash('maint-confirm')}','synthetic-spool','{}'::jsonb)`);
  assert.equal(fencedConfirmation.operation,'CONFIRM');

  const maintainedSession=requestId();
  json(app,open(maintainedSession,maintainedSession).replaceAll(ids.discoveredPrinter,ids.printer));
  json(app,advance(maintainedSession,1).replaceAll(ids.discoveredPrinter,ids.printer));
  denied(app,socketClaim(maintainedSession).replaceAll(ids.discoveredPrinter,ids.printer),/CONNECTOR_MAINTENANCE_FENCED/);
  denied(app, `SELECT app_rls.printing_test_label_job(NULL,'${requestId()}','CLAIM','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent','deviceFingerprint','printing-device',
      'nonce','maintenance_diagnostic_claim','issuedAt',now()),'{}'::jsonb)`,/CONNECTOR_MAINTENANCE_FENCED/);
  const gatewayPrinter=randomUUID(), directPrinter=randomUUID(),gatewaySecret=hash('disposable-maintenance-gateway');
  psql(admin,`INSERT INTO public."Printer"(id,name,"connectionType","commandLanguage","deliveryMode","gatewayId","gatewaySecretHash","orgId","licenseeId","assignedUserId","isActive","updatedAt")
    VALUES('${gatewayPrinter}','isolated gateway','NETWORK_DIRECT','ZPL','SITE_GATEWAY','isolated-maintenance-gateway','${gatewaySecret}','${ids.orgA}','${ids.licenseeA}','${ids.maker}',true,now()),
    ('${directPrinter}','isolated direct','NETWORK_DIRECT','ZPL','DIRECT',NULL,NULL,'${ids.orgA}','${ids.licenseeA}','${ids.maker}',true,now());
    UPDATE public."PrintJob" SET "printerId"='${directPrinter}',"printMode"='NETWORK_DIRECT' WHERE "batchId"='${ids.raceBatch}';
    UPDATE public."PrintSession" SET "printerId"='${directPrinter}' WHERE "batchId"='${ids.raceBatch}';`);
  const gatewayCheck=(diagnosticRequestId)=>`SELECT app_rls.printing_gateway_job('isolated-maintenance-gateway','${gatewaySecret}','${requestId()}','CHECK_DISPATCH','NETWORK_DIRECT',NULL,NULL,
    '${JSON.stringify(diagnosticRequestId?{diagnosticRequestId}:{})}'::jsonb)`;
  const gatewayDiagnostic=(operation,id)=>`SELECT app_rls.printing_printer_administration('${caps.maker}','printing-printer-admin','${id}','${operation}','${gatewayPrinter}',
    '${operation==='DIAGNOSTIC_COMPLETE'?'{"outcome":"confirmed","deviceJobRef":"synthetic-odometer:2"}':'{}'}'::jsonb)`;
  assert.equal(json(app,gatewayCheck()).allowed,true);
  const gatewayLease=requestId();
  json(app,gatewayDiagnostic('DIAGNOSTIC_LEASE',gatewayLease));
  denied(app,gatewayCheck(),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  denied(app,`SELECT app_rls.printing_gateway_job('isolated-maintenance-gateway','${gatewaySecret}','${requestId()}','CLAIM','NETWORK_DIRECT',NULL,NULL,'{}'::jsonb)`,
    /DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  denied(app,gatewayCheck(requestId()),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  assert.equal(json(app,gatewayCheck(gatewayLease)).allowed,true,'gateway diagnostic may claim only its own lease');
  denied(app,gatewayDiagnostic('DIAGNOSTIC_LEASE',requestId()),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  json(app,gatewayDiagnostic('DIAGNOSTIC_COMPLETE',gatewayLease));
  assert.equal(json(app,gatewayCheck()).allowed,true,'completed diagnostic history must not block later work');
  const concurrentLeases=[requestId(),requestId()];
  const leaseRace=await Promise.all(concurrentLeases.map(id=>psqlAsync(app,gatewayDiagnostic('DIAGNOSTIC_LEASE',id))));
  assert.equal(leaseRace.filter(result=>result.status===0).length,1,'one concurrent diagnostic may own physical evidence');
  assert.match(leaseRace.find(result=>result.status!==0).output,/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  denied(app,`SELECT app_rls.printing_printer_administration('${caps.outsider}','printing-printer-admin','${requestId()}','DIAGNOSTIC_COMPLETE','${gatewayPrinter}',
    '{"outcome":"confirmed","deviceJobRef":"forged"}'::jsonb)`,/PRINTING_BOUNDARY_DENIED/);
  const winningLease=concurrentLeases[leaseRace.findIndex(result=>result.status===0)];
  json(app,gatewayDiagnostic('DIAGNOSTIC_COMPLETE',winningLease));
  assert.equal(json(app,gatewayCheck()).allowed,true);
  await require('./gatewayClaimLifecycleFixture')({admin,worker,app,capability:caps.maker,psql,appFactory:createBackendApp,printerId:gatewayPrinter,batchId:ids.raceBatch,secret:'disposable-maintenance-gateway',hash});
  // Restore the worker-race fixture's transport after gateway failure injection.
  psql(admin,`UPDATE public."PrintJob" SET "printerId"='${directPrinter}',"printMode"='NETWORK_DIRECT',status='PENDING',"pipelineState"='QUEUED' WHERE "batchId"='${ids.raceBatch}';
    UPDATE public."PrintSession" SET "printerId"='${directPrinter}',status='ACTIVE' WHERE "batchId"='${ids.raceBatch}';
    UPDATE public."PrintItem" pi SET state='RESERVED',"pipelineState"='QUEUED',"agentAckedAt"=NULL,
      "dispatchedAt"=NULL,"dispatchMetadata"=NULL,"printConfirmedAt"=NULL FROM public."PrintSession" ps WHERE ps.id=pi."printSessionId" AND ps."batchId"='${ids.raceBatch}';`);
  const directDiagnostic=(operation,id)=>`SELECT app_rls.printing_printer_administration('${caps.maker}','printing-printer-admin','${id}','${operation}','${directPrinter}',
    '${operation==='DIAGNOSTIC_COMPLETE'?'{"outcome":"confirmed","deviceJobRef":"synthetic-odometer:3"}':'{}'}'::jsonb)`;
  const workerClaim=()=>`SELECT app_rls.printing_worker_network_job('CLAIM_DIRECT','${requestId()}',NULL,'{}'::jsonb)`;
  const directLease=requestId();
  json(app,directDiagnostic('DIAGNOSTIC_LEASE',directLease));
  assert.equal(json(app,gatewayCheck()).allowed,true,'a separate physical printer remains dispatchable');
  denied(worker,workerClaim(),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  json(app,directDiagnostic('DIAGNOSTIC_COMPLETE',directLease));
  assert.equal(json(worker,workerClaim()).available,true,'completed diagnostic permits a new physical reservation');
  denied(app,directDiagnostic('DIAGNOSTIC_LEASE',requestId()),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  psql(admin,`UPDATE public."PrintItem" pi SET state='FAILED',"agentAckedAt"=now() FROM public."PrintSession" ps
    WHERE ps.id=pi."printSessionId" AND ps."batchId"='${ids.raceBatch}'`);
  denied(app,directDiagnostic('DIAGNOSTIC_LEASE',requestId()),/DIAGNOSTIC_RECONCILIATION_REQUIRED/);
  psql(admin,`UPDATE public."PrintJob" SET status='PENDING',"pipelineState"='QUEUED' WHERE "batchId"='${ids.raceBatch}';
    UPDATE public."PrintItem" pi SET state='RESERVED',"pipelineState"='QUEUED',"agentAckedAt"=NULL FROM public."PrintSession" ps WHERE ps.id=pi."printSessionId" AND ps."batchId"='${ids.raceBatch}';`);
  await require('./backendNetworkLifecycleFixture')({admin,worker,app,capability:caps.maker,psql,printerId:directPrinter,gatewayPrinterId:gatewayPrinter,batchId:ids.raceBatch,foreignItemId:claim.printItemId});
  json(app,maintenanceSql(caps.maker,'MAINTENANCE_REQUEST').replace(ids.printer,gatewayPrinter));
  json(app,maintenanceSql(caps.maker,'MAINTENANCE_REQUEST').replace(ids.printer,directPrinter));
  const networkAttempts=psql(admin,`SELECT sum("attemptCount") FROM public."PrintItem"`);
  for(const operation of ['CLAIM','CHECK_DISPATCH']) {
    denied(app,`SELECT app_rls.printing_gateway_job('isolated-maintenance-gateway','${gatewaySecret}','${requestId()}','${operation}','NETWORK_DIRECT',NULL,NULL,'{}'::jsonb)`,/CONNECTOR_MAINTENANCE_FENCED/);
  }
  denied(worker,`SELECT app_rls.printing_worker_network_job('CLAIM_DIRECT','${requestId()}',NULL,'{}'::jsonb)`,/CONNECTOR_MAINTENANCE_FENCED/);
  denied(app,maintenanceSql(caps.maker,'DIAGNOSTIC_LEASE').replace(ids.printer,directPrinter),/CONNECTOR_MAINTENANCE_FENCED/);
  assert.equal(psql(admin,`SELECT sum("attemptCount") FROM public."PrintItem"`),networkAttempts,'fenced gateway, worker and diagnostic paths cannot reserve additional physical work');
  // Real authenticated route and FORCE-RLS database; disposable evidence key.
  const authority=generateKeyPairSync('ed25519');
  process.env.CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM=authority.publicKey.export({type:'spki',format:'pem'}).toString();
  const maintenanceServer=await new Promise(resolve=>{const server=createBackendApp().listen(0,'127.0.0.1',()=>resolve(server));});
  const postMaintenance=async(name,body,expected,printerId=ids.printer)=>{
    const role=name==='maker'?'MANUFACTURER_ADMIN':'LICENSEE_ADMIN';
    const scopeVersion=name==='maker'?psql(admin,`SELECT to_char("updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.maker}' AND "licenseeId"='${ids.licenseeA}'`):null;
    const headers=name?{authorization:`Bearer ${signAccessToken({userId:ids[name],email:'printing-http@example.invalid',role,sessionId:ids[`${name}Refresh`],orgId:name==='outsider'?ids.orgB:ids.orgA,licenseeId:name==='outsider'?ids.licenseeB:ids.licenseeA,scopeVersion,authenticatedAt:new Date().toISOString()})}`,
      // Synchronous bulk fixture setup can outlive HTTP keep-alive timers.
      // Use a fresh connection; never retry a one-use authorization request.
      'x-database-session-capability':sealCookieToken(caps[name],'auth.database-session'),'content-type':'application/json',connection:'close'}:{'content-type':'application/json',connection:'close'};
    const response=await fetch(`http://127.0.0.1:${maintenanceServer.address().port}/api/manufacturer/printers/${printerId}/maintenance`,{method:'POST',headers,body:JSON.stringify(body)});
    const result=await response.json();
    if(expected!==undefined)assert.equal(response.status,expected,JSON.stringify(result));
    return {status:response.status,...result};
  };
  try {
    await postMaintenance(null,{action:'inventory'},401);
    await postMaintenance('outsider',{action:'inventory'},403);
    const snapshot=(await postMaintenance('maker',{action:'inventory'},200)).data;
    assert(snapshot.inventory.settledHistory.items>0,'inventory summary must see real FORCE-RLS protected history');
    assert.equal(snapshot.inventory.items.length,0,'the previously confirmed items are settled, not unresolved work');
    assert(snapshot.inventory.settledDiagnostics>=1,'completed diagnostic history remains auditable without individual reconciliation');
    assert.equal(snapshot.inventory.diagnostics[diagnosticReservation],undefined);
    assert.equal(snapshot.inventory.diagnostics[nextDiagnostic].state,'ACCEPTED','expired ambiguous diagnostic remains unresolved');
    const binding={printerId:ids.printer,registrationId:ids.registration,tenantId:ids.orgA,manufacturerId:ids.maker,
      agentId:'printing-agent',deviceFingerprint:'printing-device',publicKeySha256:hash(signingPublicKey),fenceRequestId:snapshot.requestId,attemptId:randomUUID(),
      statePath:'C:\\isolated-fixture\\.authenticqr\\local-print-agent-state.json',sourceVersion:'2026.6.26',targetVersion:'2026.10.29.1',protocolVersion:'local-agent-direct-v2',...Object.fromEntries(['sourceSha256','targetSha256','installerSha256','stateSha256','stateDiscoverySha256','configurationSha256','startupSha256','wrapperSha256','payloadSha256','sourcePayloadSha256','uninstallerSha256','uninstallDataSha256','uninstallRegistrationSha256'].map(field=>[field,hash(field)]))};
    const reconciliations=[...snapshot.inventory.items.map(item=>({itemId:item.id,outcome:'VOID_NO_REPLAY',reference:'isolated-synthetic-reconciliation'})),
      ...Object.keys(snapshot.inventory.diagnostics).map(diagnosticId=>({diagnosticId,outcome:'VOID_NO_REPLAY',reference:'isolated-synthetic-diagnostic'})),
      ...snapshot.inventory.localDiagnostics.map(entry=>({diagnosticId:entry.job.testJobId,outcome:'VOID_NO_REPLAY',reference:'isolated-synthetic-local-diagnostic'}))];
    const statement={purpose:'mscqr-legacy-connector-isolation-v1',binding,workDigest:snapshot.workDigest,verifiedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600000).toISOString(),
      isolationEvidence:[{kind:'dispatch-isolation',sha256:hash('isolated'),reference:'disposable-environment'},{kind:'connector-work-inventory',sha256:hash('inventory'),reference:'simulated-transport'}],reconciliations};
    const signedEvidence=value=>{const statement=JSON.stringify(value);return {statement,signature:require('crypto').sign(null,Buffer.from(statement),authority.privateKey).toString('base64')};};
    await postMaintenance('maker',{action:'authorize',evidence:{...signedEvidence(statement),signature:'AAAA'}},409);
    // Empty reconciliation is valid for this now-settled workset. The history
    // fixture below requires every entry for a real three-item unresolved set.
    await postMaintenance('maker',{action:'authorize',evidence:signedEvidence({...statement,binding:{...binding,tenantId:ids.orgB}})},409);
    const authorityResult=await postMaintenance('maker',{action:'authorize',evidence:signedEvidence(statement)},200);
    let token=authorityResult.data.token;
    await postMaintenance('maker',{action:'consume',token,binding:{...binding,attemptId:randomUUID()}},403);
    const consumeResults=await Promise.all([postMaintenance('maker',{action:'consume',token,binding}),postMaintenance('maker',{action:'consume',token,binding})]);
    assert.deepEqual(consumeResults.map(result=>result.status).sort(),[200,403],'exactly one concurrent consumption may succeed');
    await postMaintenance('maker',{action:'verify',token,binding},200);
    const expiredToken=token;
    psql(admin,`UPDATE public."SystemCheckpoint" SET value=jsonb_set(value,'{upgrade,expiresAt}',to_jsonb((clock_timestamp()-interval '1 second')::text))
      WHERE key LIKE 'connector-maintenance:%' AND value->'upgrade'->'binding'->>'attemptId'='${binding.attemptId}'`);
    await postMaintenance('maker',{action:'verify',token,binding},403);
    const renewal={...statement,verifiedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600000).toISOString()};
    token=(await postMaintenance('maker',{action:'authorize',evidence:signedEvidence(renewal)},200)).data.token;
    await postMaintenance('maker',{action:'consume',token,binding},200);
    await postMaintenance('maker',{action:'verify',token:expiredToken,binding},403);
    await postMaintenance('maker',{action:'verify',token,binding},200);
    assert.equal(psql(admin,`SELECT state FROM public."PrintItem" WHERE id='${claim.printItemId}'`),'PRINT_CONFIRMED','authorization must not reset lifecycle records');
    const releaseStatement={...statement,purpose:'mscqr-upgrade-verification-v1',runtime:{version:binding.targetVersion,sha256:binding.targetSha256,
      agentId:binding.agentId,deviceFingerprint:binding.deviceFingerprint,processCount:1,verificationSha256:hash('disposable-runtime-verification')}};
    await postMaintenance('maker',{action:'release',evidence:signedEvidence(statement)},409);
    await postMaintenance('maker',{action:'release',evidence:signedEvidence({...releaseStatement,runtime:{...releaseStatement.runtime,processCount:2}})},403);
    const released=await postMaintenance('maker',{action:'release',evidence:signedEvidence(releaseStatement)},200);
    assert.equal(released.data.dispatchFenced,false);
    assert.equal(json(app,maintenanceSql(caps.maker,'MAINTENANCE_STATUS')).state,'ACTIVE');
    await require('./maintenanceHistoryFixture')({admin,app,psql,psqlAsync,ids,capability:caps.maker,templateJobId:created.job.id,postMaintenance,binding,statement,signedEvidence,hash});
  } finally {await new Promise(resolve=>maintenanceServer.close(resolve));delete process.env.CONNECTOR_ISOLATION_AUTHORITY_PUBLIC_KEY_PEM;}

  const stopJobId = "50000000-0000-4000-8000-000000000597";
  const stopBatchId = "50000000-0000-4000-8000-000000000503";
  const stopSessionId = "50000000-0000-4000-8000-000000000598";
  const stopQrId = "50000000-0000-4000-8000-000000000699";
  const stopItemId = "50000000-0000-4000-8000-000000000799";
  psql(admin, `
    INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes","lifecycleState","sampleScanPolicy","updatedAt")
      VALUES('${stopBatchId}','Stopped Print Recovery Batch','${ids.licenseeA}','${ids.maker}','LBL-0003','LBL-0003',1,'CODES_GENERATED','{"mode":"ONE_PER_PRINT_JOB"}',now());
    INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"itemCount","updatedAt")
      VALUES('${stopJobId}','${stopBatchId}','${ids.maker}','${ids.printer}','PENDING','LOCAL_AGENT','QUEUED',1,1,now());
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"tokenNonce","tokenIssuedAt","tokenExpiresAt","tokenHash","issuanceMode","updatedAt")
      VALUES('${stopQrId}','synthetic-stop-code','${ids.licenseeA}','${stopBatchId}','${stopJobId}','ACTIVATED',
        '${"a".repeat(64)}',now(),now()+interval '1 day','${hash("stopped-token")}','GOVERNED_PRINT',now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","updatedAt")
      VALUES('${stopSessionId}','${stopJobId}','${stopBatchId}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,now());
    INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","updatedAt")
      VALUES('${stopItemId}','${stopSessionId}','${stopQrId}','synthetic-stop-code','RESERVED','QUEUED',now());
    INSERT INTO public."AuditLog"(id,"userId","orgId","licenseeId",action,"entityType","entityId",details)
      VALUES(gen_random_uuid()::text,'${ids.maker}','${ids.orgA}','${ids.licenseeA}','PRINT_JOB_CREATED','PrintJob','${stopJobId}',
        jsonb_build_object('batchId','${stopBatchId}','printerId','${ids.printer}','quantity',1,'printSessionId','${stopSessionId}'));
  `);
  const stopSql = (capability) => `SELECT app_rls.printing_control_job(
    '${capability}','printing-job-control','${requestId()}','${stopJobId}','STOP','Synthetic operator stop'
  )`;
  denied(app, stopSql(caps.outsider), /PRINTING_BOUNDARY_DENIED/);
  denied(app, `BEGIN; ${stopSql(caps.maker)}; SELECT 1/0; COMMIT`, /division by zero/);
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${stopJobId}'`), "PENDING");
  assert.equal(psql(admin, `SELECT state FROM public."PrintItem" WHERE id='${stopItemId}'`), "RESERVED");
  assert.equal(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE action='PRINT_JOB_STOP' AND "entityId"='${stopJobId}'`), "0");
  const stopped = json(app, stopSql(caps.maker));
  assert.equal(stopped.status, "STOPPED");
  assert.equal(stopped.sessionStatus, "STOPPED");
  assert.equal(json(app, `SELECT app_rls.printing_readiness('${caps.maker}','printing-readiness','${requestId()}','JOB','${stopJobId}','{}'::jsonb)`).job.status, "STOPPED");
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${stopJobId}'`), "STOPPED");
  assert.equal(psql(admin, `SELECT state FROM public."PrintItem" WHERE id='${stopItemId}'`), "CANCELLED");
  assert.equal(json(app, stopSql(caps.maker)).idempotent, true);
  assert.equal(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE action='PRINT_JOB_STOP' AND "entityId"='${stopJobId}'`), "1");
  const stoppedReadiness = json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTABLE_ITEMS','${stopBatchId}','{}'::jsonb)`);
  assert(!stoppedReadiness.printableItems.some(item => item.id === stopQrId),
    "ordinary creation must not advertise a stopped item's already-linked QR");
  const stoppedReissue = () => `SELECT app_rls.printing_reissue_request(
    '${caps.maker}','printing-reissue','${requestId()}','CREATE',NULL,
    '${stopJobId}',NULL,NULL,NULL,'Stopped before dispatch',NULL)`;
  denied(app, stoppedReissue().replace(`'${caps.maker}'`, `'${caps.outsider}'`), /PRINTING_BOUNDARY_DENIED|query returned no rows/);
  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='RELEASED',"releasedAt"=now() WHERE id='${stopBatchId}'`);
  denied(app, stoppedReissue(), /INVALID_STATE_TRANSITION/);
  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='CODES_GENERATED',"releasedAt"=NULL WHERE id='${stopBatchId}'`);
  psql(admin, `UPDATE public."Batch" SET "suspendedAt"=now() WHERE id='${stopBatchId}'`);
  denied(app, stoppedReissue(), /INVALID_STATE_TRANSITION/);
  psql(admin, `UPDATE public."Batch" SET "suspendedAt"=NULL WHERE id='${stopBatchId}'`);
  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='PRINT_CONFIRMED' WHERE id='${stopBatchId}';
    UPDATE public."PrintItem" SET "agentAckedAt"=now() WHERE id='${stopItemId}'`);
  denied(app, stoppedReissue(), /PHYSICAL_OUTCOME_UNCONFIRMED/,
    "confirmed batches must reach physical-evidence checks when reissue is requested");
  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='CODES_GENERATED' WHERE id='${stopBatchId}';
    UPDATE public."PrintItem" SET "agentAckedAt"=NULL WHERE id='${stopItemId}'`);
  const rejectUnsafeStop = (mutate, restore) => {
    psql(admin, mutate);
    denied(app, stoppedReissue(), /PHYSICAL_OUTCOME_UNCONFIRMED/);
    psql(admin, restore);
  };
  rejectUnsafeStop(
    `UPDATE public."PrintItem" SET state='ISSUED',"issuedAt"=now(),"attemptCount"=1 WHERE id='${stopItemId}'`,
    `UPDATE public."PrintItem" SET state='CANCELLED',"issuedAt"=NULL,"attemptCount"=0 WHERE id='${stopItemId}'`);
  rejectUnsafeStop(
    `UPDATE public."PrintItem" SET "agentAckedAt"=now() WHERE id='${stopItemId}'`,
    `UPDATE public."PrintItem" SET "agentAckedAt"=NULL WHERE id='${stopItemId}'`);
  rejectUnsafeStop(
    `UPDATE public."PrintItem" SET "dispatchMetadata"='{"transportReference":"spooled"}'::jsonb WHERE id='${stopItemId}'`,
    `UPDATE public."PrintItem" SET "dispatchMetadata"=NULL WHERE id='${stopItemId}'`);
  rejectUnsafeStop(
    `UPDATE public."PrintItem" SET "confirmationEvidence"='{"physical":true}'::jsonb WHERE id='${stopItemId}'`,
    `UPDATE public."PrintItem" SET "confirmationEvidence"=NULL WHERE id='${stopItemId}'`);
  rejectUnsafeStop(
    `UPDATE public."PrintJob" SET "completedAt"=NULL WHERE id='${stopJobId}'`,
    `UPDATE public."PrintJob" SET "completedAt"=now() WHERE id='${stopJobId}'`);
  rejectUnsafeStop(
    `UPDATE public."PrintSession" SET "completedAt"=NULL WHERE id='${stopSessionId}'`,
    `UPDATE public."PrintSession" SET "completedAt"=now() WHERE id='${stopSessionId}'`);
  rejectUnsafeStop(
    `UPDATE public."PrintItem" SET code='wrong-code' WHERE id='${stopItemId}'`,
    `UPDATE public."PrintItem" SET code='synthetic-stop-code' WHERE id='${stopItemId}'`);
  rejectUnsafeStop(
    `UPDATE public."QRCode" SET "tokenNonce"=NULL WHERE id='${stopQrId}'`,
    `UPDATE public."QRCode" SET "tokenNonce"='${"a".repeat(64)}' WHERE id='${stopQrId}'`);
  rejectUnsafeStop(
    `INSERT INTO public."PrintItemEvent"(id,"printItemId","eventType","previousState","nextState","actorUserId")
      VALUES('50000000-0000-4000-8000-000000000796','${stopItemId}','ISSUED','RESERVED','ISSUED','${ids.maker}')`,
    `DELETE FROM public."PrintItemEvent" WHERE id='50000000-0000-4000-8000-000000000796'`);
  rejectUnsafeStop(
    `INSERT INTO public."PrintJobChunk"(id,"printJobId","printSessionId","registrationId","idempotencyKey",
      "startSequence","endSequence","itemCount","itemIds","updatedAt") VALUES(
      '50000000-0000-4000-8000-000000000795','${stopJobId}','${stopSessionId}',
      '${ids.registration}','synthetic-stopped-conflicting-chunk',1,1,1,'["${stopItemId}"]'::jsonb,now())`,
    `DELETE FROM public."PrintJobChunk" WHERE id='50000000-0000-4000-8000-000000000795'`);
  rejectUnsafeStop(
    `UPDATE public."QRCode" SET "licenseeId"='${ids.licenseeB}' WHERE id='${stopQrId}'`,
    `UPDATE public."QRCode" SET "licenseeId"='${ids.licenseeA}' WHERE id='${stopQrId}'`);
  const stopConflictJobId = "50000000-0000-4000-8000-000000000594";
  const stopConflictSessionId = "50000000-0000-4000-8000-000000000595";
  const createStopConflict = `INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"itemCount","updatedAt")
    VALUES('${stopConflictJobId}','${stopBatchId}','${ids.maker}','${ids.printer}','PENDING','LOCAL_AGENT','QUEUED',1,1,now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerId",status,"totalItems","updatedAt")
    VALUES('${stopConflictSessionId}','${stopConflictJobId}','${stopBatchId}','${ids.maker}','${ids.printer}','ACTIVE',1,now())`;
  const clearStopConflict = `DELETE FROM public."PrintSession" WHERE id='${stopConflictSessionId}';
    DELETE FROM public."PrintJob" WHERE id='${stopConflictJobId}'`;
  psql(admin, createStopConflict);
  denied(app, stoppedReissue(), /PHYSICAL_OUTCOME_UNCONFIRMED/);
  psql(admin, clearStopConflict);
  const concurrentStoppedRequests = await Promise.all([psqlAsync(app, stoppedReissue()), psqlAsync(app, stoppedReissue())]);
  assert(concurrentStoppedRequests.every(result => result.status === 0), concurrentStoppedRequests.map(result => result.output).join("\n"));
  const [stoppedRequest, repeatedStoppedRequest] = concurrentStoppedRequests.map(result => JSON.parse(result.output));
  assert.equal(stoppedRequest.id, repeatedStoppedRequest.id);
  assert.deepEqual([stoppedRequest.idempotent, repeatedStoppedRequest.idempotent].sort(), [false, true]);
  assert.equal(stoppedRequest.originalPrintJobId, stopJobId);
  assert.equal(stoppedRequest.status, "PENDING");
  psql(admin, `UPDATE public."QRCode" SET "tokenExpiresAt"=now()-interval '1 second' WHERE id='${stopQrId}'`);
  const expiredRetry = json(app, stoppedReissue());
  assert.equal(expiredRetry.id, stoppedRequest.id);
  assert.equal(expiredRetry.idempotent, true);
  psql(admin, `UPDATE public."QRCode" SET "tokenExpiresAt"=now()+interval '1 day' WHERE id='${stopQrId}'`);
  psql(admin, `UPDATE public."PrintReissueRequest" SET status='APPROVED',"approvedByUserId"='${ids.checker}',
    "approvedAt"=now() WHERE id='${stoppedRequest.id}'`);
  const executeStopped = () => `SELECT app_rls.printing_reissue_request(
    '${caps.maker}','printing-reissue','${requestId()}','EXECUTE','${stoppedRequest.id}',
    NULL,NULL,NULL,NULL,NULL,NULL)`;
  denied(app, executeStopped().replace(`'${caps.maker}'`, `'${caps.outsider}'`), /PRINTING_BOUNDARY_DENIED|query returned no rows/);
  psql(admin, createStopConflict);
  assert.equal(json(app, stoppedReissue()).id, stoppedRequest.id);
  denied(app, executeStopped(), /PHYSICAL_OUTCOME_UNCONFIRMED/);
  psql(admin, clearStopConflict);
  psql(admin, `INSERT INTO public."PrintJobChunk"(id,"printJobId","printSessionId","registrationId","idempotencyKey",
    "startSequence","endSequence","itemCount","itemIds","updatedAt") VALUES(
    '50000000-0000-4000-8000-000000000795','${stopJobId}','${stopSessionId}',
    '${ids.registration}','synthetic-stopped-conflicting-chunk',1,1,1,'["${stopItemId}"]'::jsonb,now())`);
  denied(app, executeStopped(), /PHYSICAL_OUTCOME_UNCONFIRMED/);
  psql(admin, `DELETE FROM public."PrintJobChunk" WHERE id='50000000-0000-4000-8000-000000000795'`);
  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='RELEASED',"releasedAt"=now() WHERE id='${stopBatchId}'`);
  assert.equal(json(app, stoppedReissue()).idempotent, true, "an existing request remains idempotent after release");
  denied(app, executeStopped(), /INVALID_STATE_TRANSITION/);
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintJob" WHERE "reprintOfJobId"='${stopJobId}'`), "0");
  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='CODES_GENERATED',"releasedAt"=NULL WHERE id='${stopBatchId}'`);
  psql(admin, `UPDATE public."PrinterAgentSession" SET "lastSignedHeartbeatAt"=now()-interval '36 seconds'
    WHERE id='${maintainedSession}'`);
  denied(app, executeStopped(), /PRINTER_ATTESTATION_STALE/);
  json(app, advance(maintainedSession,2).replaceAll(ids.discoveredPrinter,ids.printer));
  const recoveredStop = json(app, executeStopped());
  assert.equal(recoveredStop.status, "EXECUTED");
  assert.equal(json(app, executeStopped()).idempotent, true);
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${stopJobId}'`), "STOPPED");
  assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${stopSessionId}'`), "STOPPED");
  assert.equal(psql(admin, `SELECT "printSessionId"||':'||state FROM public."PrintItem" WHERE id='${stopItemId}'`),
    `${psql(admin, `SELECT id FROM public."PrintSession" WHERE "printJobId"='${recoveredStop.replacementPrintJobId}'`)}:RESERVED`);
  assert.equal(psql(admin, `SELECT "printJobId"||':'||status FROM public."QRCode" WHERE id='${stopQrId}'`),
    `${recoveredStop.replacementPrintJobId}:ACTIVATED`);
  assert.equal(psql(admin, `SELECT "reprintOfJobId" FROM public."PrintJob" WHERE id='${recoveredStop.replacementPrintJobId}'`), stopJobId);
  assert.equal(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE action='PRINT_REISSUE_EXECUTE'
    AND details->>'originalPrintJobId'='${stopJobId}'
    AND details->>'replacementPrintJobId'='${recoveredStop.replacementPrintJobId}'`), "1");

  const unclaimedJobId = "50000000-0000-4000-8000-000000000599";
  const unclaimedSessionId = "50000000-0000-4000-8000-000000000587";
  const unclaimedQrId = "50000000-0000-4000-8000-000000000697";
  const unclaimedItemId = "50000000-0000-4000-8000-000000000797";
  psql(admin, `
    INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"updatedAt")
      VALUES('${unclaimedJobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','PENDING','LOCAL_AGENT','QUEUED',1,now());
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId",status,"updatedAt")
      VALUES('${unclaimedQrId}','synthetic-unclaimed-code','${ids.licenseeA}','${ids.raceBatch}','ALLOCATED',now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerId",status,"totalItems","updatedAt")
      VALUES('${unclaimedSessionId}','${unclaimedJobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','ACTIVE',1,now());
    INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","updatedAt")
      VALUES('${unclaimedItemId}','${unclaimedSessionId}','${unclaimedQrId}','synthetic-unclaimed-code','RESERVED','QUEUED',now());
  `);
  denied(app, `SELECT app_rls.printing_control_job('${caps.outsider}','printing-job-control','${requestId()}','${unclaimedJobId}','ABANDON','Wrong tenant')`, /PRINTING_BOUNDARY_DENIED/);
  for (const absentEvidence of ["NULL", "'null'::jsonb", "'{}'::jsonb"]) {
    psql(admin, `UPDATE public."PrintItem" SET "confirmationEvidence"=${absentEvidence} WHERE id='${unclaimedItemId}'`);
    assert.doesNotThrow(() => psql(app, `BEGIN; SELECT app_rls.printing_control_job(
      '${caps.maker}','printing-job-control','${requestId()}','${unclaimedJobId}','ABANDON','Never claimed'); ROLLBACK`));
  }
  psql(admin, `UPDATE public."PrintItem" SET "confirmationEvidence"='{"physical":true}'::jsonb WHERE id='${unclaimedItemId}'`);
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${unclaimedJobId}','ABANDON','Unsafe evidence')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  psql(admin, `UPDATE public."PrintItem" SET "confirmationEvidence"='null'::jsonb WHERE id='${unclaimedItemId}'`);
  assert.equal(json(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${unclaimedJobId}','ABANDON','Never claimed')`).status, "CANCELLED");
  assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${unclaimedSessionId}'`), "CANCELLED");
  assert.equal(psql(admin, `SELECT state FROM public."PrintItem" WHERE id='${unclaimedItemId}'`), "CANCELLED");
  assert.equal(json(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${unclaimedJobId}','ABANDON','Never claimed')`).idempotent, true);
  assert.equal(psql(admin, `SELECT count(*) FROM public."AuditLog" WHERE action='PRINT_JOB_ABANDON' AND "entityId"='${unclaimedJobId}'`), "1");

  const orphanJobId = "50000000-0000-4000-8000-000000000596";
  psql(admin, `INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,quantity,"updatedAt")
    VALUES('${orphanJobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','PENDING',1,now())`);
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${orphanJobId}','STOP','Synthetic missing session')`, /query returned no rows/);
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${orphanJobId}'`), "PENDING");

  const expiredJobId = "50000000-0000-4000-8000-000000000592";
  const expiredSessionId = "50000000-0000-4000-8000-000000000582";
  const expiredQrId = "50000000-0000-4000-8000-000000000692";
  const expiredItemId = "50000000-0000-4000-8000-000000000792";
  psql(admin, `
    INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"updatedAt")
      VALUES('${expiredJobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','SENT','LOCAL_AGENT','SENT_TO_PRINTER',1,now());
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt")
      VALUES('${expiredQrId}','synthetic-expired-code','${ids.licenseeA}','${ids.raceBatch}','${expiredJobId}','ACTIVATED',now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","issuedItems","updatedAt")
      VALUES('${expiredSessionId}','${expiredJobId}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,1,now());
    INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","issuedAt","agentAckedAt","confirmationDeadlineAt","updatedAt")
      VALUES('${expiredItemId}','${expiredSessionId}','${expiredQrId}','synthetic-expired-code','AGENT_ACKED','PRINTER_ACKNOWLEDGED',now()-interval '20 minutes',now()-interval '20 minutes',now()-interval '10 minutes',now());
  `);
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',10)`), "1");
  assert.equal(psql(admin, `SELECT state||':'||"pipelineState" FROM public."PrintItem" WHERE id='${expiredItemId}'`), "AGENT_ACKED:NEEDS_OPERATOR_ACTION");
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${expiredJobId}'`), "PAUSED:NEEDS_OPERATOR_ACTION");
  assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${expiredSessionId}'`), "PAUSED");
  assert.equal(psql(admin, `SELECT "confirmationDeadlineAt" IS NOT NULL FROM public."PrintItem" WHERE id='${expiredItemId}'`), "t");
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',10)`), "0");
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${expiredJobId}','ABANDON','Unsafe release')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${expiredJobId}','RESUME','Unsafe replay')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  assert.equal(psql(admin, `SELECT "printJobId" FROM public."QRCode" WHERE id='${expiredQrId}'`), expiredJobId);
  denied(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','disconnected_nonce_1',now()::timestamp,
    '${requestId()}','CONFIRM','${expiredJobId}','${expiredItemId}','${ids.printer}','${hash("disconnected-confirm")}',
    'spool-expired','{"deliveryMode":"PERSISTENT_SESSION","sessionId":"${sessionA}"}'::jsonb
  )`, /CONNECTOR_SESSION_NOT_ACTIVE/);
  const lateConfirmation = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','late_confirm_nonce_1',now()::timestamp,
    '${requestId()}','CONFIRM','${expiredJobId}','${expiredItemId}','${ids.printer}','${hash("late-confirm")}',
    'spool-expired','{"physical":true}'::jsonb
  )`);
  assert.equal(lateConfirmation.remainingToPrint, 0);
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${expiredJobId}'`), "CONFIRMED");
  assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${expiredSessionId}'`), "COMPLETED");
  assert.equal(psql(admin, `SELECT status FROM public."QRCode" WHERE id='${expiredQrId}'`), "PRINTED");
  assert.equal(psql(admin, `SELECT "failureReason" IS NULL FROM public."PrintJob" WHERE id='${expiredJobId}'`), "t");
  assert.equal(json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','late_confirm_nonce_2',now()::timestamp,
    '${requestId()}','CONFIRM','${expiredJobId}','${expiredItemId}','${ids.printer}','${hash("late-confirm-retry")}',
    'spool-expired','{"physical":true}'::jsonb
  )`).idempotent, true);

  const createExpiredRun = (label, count, unexpired = 0) => {
    const jobId = randomUUID();
    const sessionId = randomUUID();
    psql(admin, `
      INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"updatedAt")
        VALUES('${jobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','SENT','LOCAL_AGENT','SENT_TO_PRINTER',${count + unexpired},now());
      INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","issuedItems","updatedAt")
        VALUES('${sessionId}','${jobId}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',${count + unexpired},${count + unexpired},now());
      INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt")
        SELECT gen_random_uuid()::text,'expiry-${label}-'||n,'${ids.licenseeA}','${ids.raceBatch}','${jobId}','ACTIVATED',now()
        FROM generate_series(1,${count + unexpired}) n;
      INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","issuedAt","agentAckedAt","confirmationDeadlineAt","updatedAt")
        SELECT gen_random_uuid()::text,'${sessionId}',q.id,q.code,'AGENT_ACKED','PRINTER_ACKNOWLEDGED',
          now()-interval '20 minutes',now()-interval '20 minutes',
          CASE WHEN substring(q.code from '[0-9]+$')::integer<=${count} THEN now()-interval '10 minutes' ELSE now()+interval '10 minutes' END,now()
        FROM public."QRCode" q WHERE q."printJobId"='${jobId}';
    `);
    return { jobId, sessionId };
  };
  const resumed = createExpiredRun('resume', 1, 1);
  const [resumedExpired, resumedReserved] = psql(admin, `SELECT string_agg(id,',' ORDER BY code) FROM public."PrintItem" WHERE "printSessionId"='${resumed.sessionId}'`).split(',');
  psql(admin, `UPDATE public."PrintItem" SET state='RESERVED',"pipelineState"='QUEUED',"issuedAt"=NULL,
    "agentAckedAt"=NULL,"confirmationDeadlineAt"=NULL WHERE id='${resumedReserved}'`);
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`), '1');
  json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','resume_confirm_nonce_1',now()::timestamp,
    '${requestId()}','CONFIRM','${resumed.jobId}','${resumedExpired}','${ids.printer}','${hash('resume-confirm')}','spool-resume','{"physical":true}'::jsonb)`);
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${resumed.jobId}'`), 'PAUSED:PAUSED');
  assert.equal(json(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${resumed.jobId}','RESUME','Continue reserved work')`).sessionStatus, 'RESUME_PENDING');
  psql(admin, `UPDATE public."PrintJob" SET "createdAt"='2000-01-01' WHERE id='${resumed.jobId}'`);
  const resumedClaim = json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','resume_claim_nonce_1',now()::timestamp,
    '${requestId()}','CLAIM','${resumed.jobId}',NULL,'${ids.printer}','${hash('resume-claim')}',NULL,'{}'::jsonb)`);
  assert.equal(resumedClaim.printJobId, resumed.jobId);
  assert.equal(resumedClaim.printItemId, resumedReserved);
  assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${resumed.sessionId}'`), 'ACTIVE');

  for (const count of [1, 49, 50, 51, 100, 125]) {
    const run = createExpiredRun(`limit${count}`, count);
    let processed = 0;
    for (let pass = 0; pass < Math.ceil(count / 50) + 1; pass++) {
      const next = Number(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`));
      assert(next <= 50, `reconciliation exceeds its page bound for ${count} items`);
      processed += next;
      if (next === 0) break;
    }
    assert.equal(processed, count, `all ${count} expired acknowledgements need bounded reconciliation`);
    assert.equal(psql(admin, `SELECT count(*) FROM public."PrintItem" WHERE "printSessionId"='${run.sessionId}' AND "pipelineState"='NEEDS_OPERATOR_ACTION'`), String(count));
    assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${run.jobId}'`), 'PAUSED:NEEDS_OPERATOR_ACTION');
    assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${run.sessionId}'`), 'PAUSED');
    assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`), '0');
  }
  const alreadyPaused = createExpiredRun('already-paused', 1);
  psql(admin, `UPDATE public."PrintJob" SET status='PAUSED',"pipelineState"='PAUSED' WHERE id='${alreadyPaused.jobId}';
    UPDATE public."PrintSession" SET status='PAUSED' WHERE id='${alreadyPaused.sessionId}'`);
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${alreadyPaused.jobId}','RESUME','Unsafe in-flight work')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`), '1');
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${alreadyPaused.jobId}'`), 'PAUSED:NEEDS_OPERATOR_ACTION');
  const partial = createExpiredRun('partial', 2);
  const partialItems = psql(admin, `SELECT string_agg(id,',' ORDER BY code) FROM public."PrintItem" WHERE "printSessionId"='${partial.sessionId}'`).split(',');
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',1)`), '1');
  const firstPartial = psql(admin, `SELECT id FROM public."PrintItem" WHERE "printSessionId"='${partial.sessionId}' AND "pipelineState"='NEEDS_OPERATOR_ACTION'`);
  assert.equal(json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','partial_confirm_nonce_1',now()::timestamp,
    '${requestId()}','CONFIRM','${partial.jobId}','${firstPartial}','${ids.printer}','${hash('partial-confirm-1')}','spool-partial','{"physical":true}'::jsonb)`).operation, 'CONFIRM');
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${partial.jobId}'`), 'PAUSED:NEEDS_OPERATOR_ACTION',
    'unmarked overdue work must keep the parent paused');
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',1)`), '1');
  const secondPartial = partialItems.find((id) => id !== firstPartial);
  assert.equal(json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','partial_confirm_nonce_2',now()::timestamp,
    '${requestId()}','CONFIRM','${partial.jobId}','${secondPartial}','${ids.printer}','${hash('partial-confirm-2')}','spool-partial','{"physical":true}'::jsonb)`).remainingToPrint, 0);
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${partial.jobId}'`), 'CONFIRMED');
  assert.equal(json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','partial_ack_retry_nonce_1',now()::timestamp,
    '${requestId()}','ACK','${partial.jobId}','${firstPartial}','${ids.printer}','${hash('partial-ack-retry')}','spool-partial','{}'::jsonb)`).idempotent, true);
  const concurrentRun = createExpiredRun('concurrent', 100);
  const simultaneous = await Promise.all(Array.from({ length: 2 }, () =>
    psqlAsync(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`)));
  assert(simultaneous.every((result) => result.status === 0), JSON.stringify(simultaneous));
  const concurrentProcessed = simultaneous.reduce((sum, result) => sum + Number(result.output), 0);
  assert(concurrentProcessed <= 100);
  assert.equal(Number(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`)) + concurrentProcessed, 100);
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintItem" WHERE "printSessionId"='${concurrentRun.sessionId}' AND "pipelineState"='NEEDS_OPERATOR_ACTION'`), '100');

  const mixed = createExpiredRun('mixed', 1, 2);
  const [expiredMixed, laterAcked, laterFailed] = psql(admin, `SELECT string_agg(id,',' ORDER BY code) FROM public."PrintItem" WHERE "printSessionId"='${mixed.sessionId}'`).split(',');
  assert.equal(psql(worker, `SELECT app_rls.printing_worker_reconcile('EXPIRE_CONFIRMATIONS','${requestId()}',50)`), '1');
  psql(admin, `UPDATE public."PrintItem" SET state='ISSUED',"pipelineState"='SENT_TO_PRINTER',"agentAckedAt"=NULL,"confirmationDeadlineAt"=NULL WHERE id IN ('${laterAcked}','${laterFailed}')`);
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintJob" WHERE id='${mixed.jobId}' AND status IN ('PENDING','SENT')`), '0',
    'the paused job must not be selected for a new claim');
  const receipt = (operation, itemId, nonce, details = '{}') => `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','${nonce}',now()::timestamp,
    '${requestId()}','${operation}','${mixed.jobId}','${itemId}','${ids.printer}','${hash(nonce)}','spool-mixed','${details}'::jsonb)`;
  assert.equal(json(app, receipt('ACK', laterAcked, 'paused_ack_nonce_1')).operation, 'ACK');
  assert.equal(json(app, receipt('ACK', laterAcked, 'paused_ack_nonce_2')).idempotent, true);
  denied(app, receipt('ACK', laterAcked, 'paused_ack_nonce_1'), /duplicate key/);
  assert.equal(json(app, receipt('CONFIRM', expiredMixed, 'paused_confirm_nonce_1', '{"physical":true}')).operation, 'CONFIRM');
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${mixed.jobId}'`), 'PAUSED:NEEDS_OPERATOR_ACTION');
  assert.equal(json(app, receipt('FAIL', laterFailed, 'paused_fail_nonce_1', '{"reason":"definite_pre_dispatch_failure"}')).operation, 'FAIL');
  assert.equal(json(app, receipt('FAIL', laterFailed, 'paused_fail_nonce_2', '{"reason":"definite_pre_dispatch_failure"}')).idempotent, true);
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${mixed.jobId}'`), 'PAUSED:NEEDS_OPERATOR_ACTION');
  assert.equal(json(app, receipt('CONFIRM', laterAcked, 'paused_confirm_nonce_2', '{"physical":true}')).operation, 'CONFIRM');
  assert.equal(psql(admin, `SELECT status FROM public."PrintSession" WHERE id='${mixed.sessionId}'`), 'FAILED');
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${mixed.jobId}'`), 'FAILED');
  assert.equal(json(app, receipt('FAIL', laterFailed, 'paused_fail_nonce_3')).idempotent, true);
  assert.equal(psql(admin, `SELECT status FROM public."QRCode" q JOIN public."PrintItem" pi ON pi."qrCodeId"=q.id WHERE pi.id='${laterFailed}'`), 'ACTIVATED');
  denied(app, receipt('ACK', laterFailed, 'paused_invalid_ack'), /query returned no rows|INVALID_STATE_TRANSITION/);
  denied(app, receipt('CONFIRM', laterFailed, 'paused_invalid_confirm'), /query returned no rows|PRINT_ACK_REQUIRED/);
  denied(app, receipt('ACK', randomUUID(), 'paused_cross_item'), /query returned no rows/);
  denied(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','paused_wrong_printer',now()::timestamp,
    '${requestId()}','ACK','${mixed.jobId}','${laterAcked}','${ids.foreignPrinter}','${hash('wrong-printer')}',NULL,'{}'::jsonb)`, /query returned no rows/);

  const stoppedFailure = createExpiredRun('stopped-failure', 1);
  const stoppedFailureItem = psql(admin, `SELECT id FROM public."PrintItem" WHERE "printSessionId"='${stoppedFailure.sessionId}'`);
  json(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${stoppedFailure.jobId}','STOP','Stop uncertain work')`);
  assert.equal(json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','stopped_fail_nonce_1',now()::timestamp,
    '${requestId()}','FAIL','${stoppedFailure.jobId}','${stoppedFailureItem}','${ids.printer}','${hash('stopped-fail')}','spool-stop','{"reason":"definite_connector_failure"}'::jsonb)`).operation, 'FAIL');
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${stoppedFailure.jobId}'`), 'STOPPED:STOPPED');
  assert.equal(psql(admin, `SELECT state FROM public."PrintItem" WHERE id='${stoppedFailureItem}'`), 'FAILED');
  assert.equal(json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','stopped_fail_nonce_2',now()::timestamp,
    '${requestId()}','FAIL','${stoppedFailure.jobId}','${stoppedFailureItem}','${ids.printer}','${hash('stopped-fail-retry')}','spool-stop','{}'::jsonb)`).idempotent, true);

  const raceStop = async (suffix, itemState, connectorOperation) => {
    const jobId = `50000000-0000-4000-8000-00000000059${suffix}`;
    const sessionId = `50000000-0000-4000-8000-00000000058${suffix}`;
    const qrId = `50000000-0000-4000-8000-00000000069${suffix}`;
    const itemId = `50000000-0000-4000-8000-00000000079${suffix}`;
    psql(admin, `
      INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"updatedAt")
        VALUES('${jobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','SENT','LOCAL_AGENT','SENT_TO_PRINTER',1,now());
      INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt")
        VALUES('${qrId}','synthetic-stop-race-${suffix}','${ids.licenseeA}','${ids.raceBatch}','${jobId}','ALLOCATED',now());
      INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","issuedItems","updatedAt")
        VALUES('${sessionId}','${jobId}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,1,now());
      INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","issuedAt","agentAckedAt","updatedAt")
        VALUES('${itemId}','${sessionId}','${qrId}','synthetic-stop-race-${suffix}','${itemState}',
          '${itemState === "AGENT_ACKED" ? "PRINTER_ACKNOWLEDGED" : "SENT_TO_PRINTER"}',now(),
          ${itemState === "AGENT_ACKED" ? "now()" : "NULL"},now());
    `);
    const marker = `stop_${connectorOperation.toLowerCase()}_probe`;
    const holder = psqlAsync(admin, `BEGIN; SELECT id FROM public."PrintJob" WHERE id='${jobId}' FOR UPDATE;
      DO $hold$ BEGIN
        WHILE (SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'
          AND (query LIKE '%printing_connector_event(%' OR query LIKE '%printing_control_job(%')
          AND cardinality(pg_blocking_pids(pid))>0)<2 LOOP
          IF clock_timestamp()>transaction_timestamp()+interval '10 seconds' THEN RAISE EXCEPTION 'stop race did not reach job lock'; END IF;
          PERFORM pg_sleep(0.05);
          PERFORM pg_stat_clear_snapshot();
        END LOOP;
      END $hold$; COMMIT; /* ${marker}_holder */`);
    let lockHeld = false;
    for (let attempt = 0; attempt < 80 && !lockHeld; attempt += 1) {
      lockHeld = Number(psql(admin, `SELECT count(*) FROM pg_stat_activity WHERE wait_event='PgSleep' AND query LIKE '%${marker}_holder%'`)) > 0;
      if (!lockHeld) await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert(lockHeld, "stop race holder must acquire the job lock");
    const connector = psqlAsync(app, `SELECT app_rls.printing_connector_event(
      '${ids.registration}','printing-agent','printing-device','stop_race_${suffix}_${connectorOperation.toLowerCase()}_nonce',now()::timestamp,
      '${requestId()}','${connectorOperation}','${jobId}','${itemId}','${ids.printer}','${hash(marker)}','synthetic-spool','{}'::jsonb
    ) /* ${marker} */`);
    const stop = psqlAsync(app, `SELECT app_rls.printing_control_job(
      '${caps.maker}','printing-job-control','${requestId()}','${jobId}','STOP','Concurrent synthetic stop'
    ) /* ${marker} */`);
    const [holderResult, connectorResult, stopResult] = await Promise.all([holder, connector, stop]);
    assert.equal(holderResult.status, 0, JSON.stringify({ holder: holderResult.output, connector: connectorResult.output, stop: stopResult.output }));
    assert.equal(stopResult.status, 0, stopResult.output);
    const final = json(admin, `SELECT jsonb_build_object('job',(SELECT status FROM public."PrintJob" WHERE id='${jobId}'),
      'pipeline',(SELECT "pipelineState" FROM public."PrintJob" WHERE id='${jobId}'),
      'session',(SELECT status FROM public."PrintSession" WHERE id='${sessionId}'),
      'item',(SELECT state FROM public."PrintItem" WHERE id='${itemId}'),
      'qr',(SELECT status FROM public."QRCode" WHERE id='${qrId}'),
      'stopAudit',(SELECT count(*) FROM public."AuditLog" WHERE action='PRINT_JOB_STOP' AND "entityId"='${jobId}'))`);
    return { jobId, itemId, connectorResult, stopResult: JSON.parse(stopResult.output), final };
  };
  const ackRace = await raceStop("5", "ISSUED", "ACK");
  assert.deepEqual([ackRace.final.job, ackRace.final.session, ackRace.final.item, ackRace.final.qr],
    ["STOPPED", "STOPPED", ackRace.connectorResult.status === 0 ? "AGENT_ACKED" : "ISSUED", "ALLOCATED"]);
  assert.equal(ackRace.final.pipeline, 'NEEDS_OPERATOR_ACTION');
  assert.equal(ackRace.final.stopAudit, 1);
  const heldClaimJob = randomUUID();
  const heldClaimSession = randomUUID();
  const heldClaimQr = randomUUID();
  const heldClaimItem = randomUUID();
  psql(admin, `
    INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"createdAt","updatedAt")
      VALUES('${heldClaimJob}','${ids.raceBatch}','${ids.maker}','${ids.printer}','PENDING','LOCAL_AGENT','QUEUED',1,'1900-01-01',now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","updatedAt")
      VALUES('${heldClaimSession}','${heldClaimJob}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,now());
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt")
      VALUES('${heldClaimQr}','synthetic-held-claim','${ids.licenseeA}','${ids.raceBatch}','${heldClaimJob}','ACTIVATED',now());
    INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","updatedAt")
      VALUES('${heldClaimItem}','${heldClaimSession}','${heldClaimQr}','synthetic-held-claim','RESERVED','QUEUED',now());
  `);
  const blockedClaim = json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','stopped_claim_nonce_1',now()::timestamp,
    '${requestId()}','CLAIM',NULL,NULL,'${ids.printer}','${hash('stopped-claim')}',NULL,'{}'::jsonb)`);
  assert.equal(blockedClaim.available, false);
  assert.equal(blockedClaim.reconciliationRequired, true);
  const stoppedAck = json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','stopped_ack_nonce_1',now()::timestamp,
    '${requestId()}','ACK','${ackRace.jobId}','${ackRace.itemId}','${ids.printer}','${hash('stopped-ack')}','spool-stop','{}'::jsonb)`);
  assert(stoppedAck.operation === 'ACK' || stoppedAck.idempotent === true);
  assert.equal(json(app, `SELECT app_rls.printing_connector_event('${ids.registration}','printing-agent','printing-device','stopped_confirm_nonce_1',now()::timestamp,
    '${requestId()}','CONFIRM','${ackRace.jobId}','${ackRace.itemId}','${ids.printer}','${hash('stopped-confirm')}','spool-stop','{"physical":true}'::jsonb)`).operation, 'CONFIRM');
  assert.equal(psql(admin, `SELECT status FROM public."PrintJob" WHERE id='${ackRace.jobId}'`), 'CONFIRMED');
  const confirmRace = await raceStop("4", "AGENT_ACKED", "CONFIRM");
  assert([0, 1].includes(Number(confirmRace.final.stopAudit)));
  assert.deepEqual([confirmRace.final.job, confirmRace.final.session, confirmRace.final.item, confirmRace.final.qr],
    ["CONFIRMED", "COMPLETED", "PRINT_CONFIRMED", "PRINTED"]);

  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='CODES_GENERATED',"releasedAt"=NULL,"suspendedAt"=NULL
    WHERE id='${ids.raceBatch}'`);
  const uncertainJobId = "50000000-0000-4000-8000-000000000593";
  const uncertainSessionId = "50000000-0000-4000-8000-000000000583";
  const uncertainItemId = "50000000-0000-4000-8000-000000000793";
  const uncertainQrId = "50000000-0000-4000-8000-000000000693";
  psql(admin, `
    INSERT INTO public."PrintJob"(id,"batchId","manufacturerId","printerId",status,"printMode","pipelineState",quantity,"updatedAt")
      VALUES('${uncertainJobId}','${ids.raceBatch}','${ids.maker}','${ids.printer}','SENT','LOCAL_AGENT','SENT_TO_PRINTER',1,now());
    INSERT INTO public."QRCode"(id,code,"licenseeId","batchId","printJobId",status,"updatedAt")
      VALUES('${uncertainQrId}','synthetic-uncertain-code','${ids.licenseeA}','${ids.raceBatch}','${uncertainJobId}','ALLOCATED',now());
    INSERT INTO public."PrintSession"(id,"printJobId","batchId","manufacturerId","printerRegistrationId","printerId",status,"totalItems","issuedItems","updatedAt")
      VALUES('${uncertainSessionId}','${uncertainJobId}','${ids.raceBatch}','${ids.maker}','${ids.registration}','${ids.printer}','ACTIVE',1,1,now());
    INSERT INTO public."PrintItem"(id,"printSessionId","qrCodeId",code,state,"pipelineState","issuedAt","updatedAt")
      VALUES('${uncertainItemId}','${uncertainSessionId}','${uncertainQrId}','synthetic-uncertain-code','ISSUED','SENT_TO_PRINTER',now(),now());
  `);
  const uncertainFail = () => `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','uncertain_${requestId()}',now()::timestamp,
    '${requestId()}','FAIL','${uncertainJobId}','${uncertainItemId}','${ids.printer}','${hash('uncertain')}',NULL,
    '{"reason":"physical_outcome_unconfirmed","outcomeIndeterminate":true}'::jsonb
  )`;
  json(app, uncertainFail());
  assert.equal(psql(admin, `SELECT status||':'||"pipelineState" FROM public."PrintJob" WHERE id='${uncertainJobId}'`), "PAUSED:NEEDS_OPERATOR_ACTION");
  assert.equal(psql(admin, `SELECT state||':'||"pipelineState" FROM public."PrintItem" WHERE id='${uncertainItemId}'`), "FROZEN:NEEDS_OPERATOR_ACTION");
  assert.equal(psql(admin, `SELECT status FROM public."QRCode" WHERE id='${uncertainQrId}'`), "ALLOCATED");
  const uncertainReissue = () => `SELECT app_rls.printing_reissue_request(
    '${caps.maker}','printing-reissue','${requestId()}','CREATE',NULL,
    '${uncertainJobId}',1,NULL,NULL,'Physical outcome is unconfirmed',NULL
  )`;
  denied(app, uncertainReissue(), /PRINTING_BOUNDARY_DENIED/);
  denied(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','uncertain_confirm_${requestId()}',now()::timestamp,
    '${requestId()}','CONFIRM','${uncertainJobId}','${uncertainItemId}','${ids.printer}','${hash('uncertain')}',NULL,'{}'::jsonb
  )`, /PRINT_ACK_REQUIRED/);
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${uncertainJobId}','RESUME','Unsafe replay')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${uncertainJobId}','ABANDON','Unsafe release')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  json(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${uncertainJobId}','STOP','Hold for reconciliation')`);
  assert.equal(psql(admin, `SELECT state FROM public."PrintItem" WHERE id='${uncertainItemId}'`), "FROZEN");
  assert.equal(psql(admin, `SELECT "pipelineState" FROM public."PrintJob" WHERE id='${uncertainJobId}'`), "NEEDS_OPERATOR_ACTION");
  denied(app, `SELECT app_rls.printing_control_job('${caps.maker}','printing-job-control','${requestId()}','${uncertainJobId}','ABANDON','Unsafe release')`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  denied(app, uncertainReissue(), /PHYSICAL_OUTCOME_UNCONFIRMED/);
  const approvedUncertainReissueId = "50000000-0000-4000-8000-000000000902";
  psql(admin, `INSERT INTO public."PrintReissueRequest"(id,"originalPrintJobId","requestedByUserId","approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole","targetApproverRole",quantity,status,reason,"approvedAt","updatedAt")
    VALUES('${approvedUncertainReissueId}','${uncertainJobId}','${ids.maker}','${ids.checker}','${ids.licenseeA}','${ids.maker}','${ids.raceBatch}','MANUFACTURER_ADMIN','LICENSEE_ADMIN',1,'APPROVED','Prior approval',now(),now())`);
  denied(app, `SELECT app_rls.printing_reissue_request(
    '${caps.maker}','printing-reissue','${requestId()}','EXECUTE','${approvedUncertainReissueId}',
    NULL,NULL,NULL,NULL,'Prior approval',NULL
  )`, /PHYSICAL_OUTCOME_UNCONFIRMED/);
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintJob" WHERE "reprintOfJobId"='${uncertainJobId}'`), "0");
  assert.equal(psql(admin, `SELECT count(*) FROM public."PrintItemEvent" WHERE "printItemId"='${uncertainItemId}' AND "eventType"='INCIDENT_RAISED'`), "1");
  assert.equal(psql(admin, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname IN ('PrintItemEvent','PrintJobChunk')
      AND c.relrowsecurity AND c.relforcerowsecurity`), "2");
  denied(app, `SELECT "printItemId" FROM public."PrintItemEvent" LIMIT 1`, /permission denied/);
  denied(app, `SELECT "printJobId" FROM public."PrintJobChunk" LIMIT 1`, /permission denied/);

  const catalog = json(admin, `SELECT jsonb_build_object(
    'force',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname IN ('Batch','QRCode','PrintJob','PrintSession','PrintItem','Printer','PrinterRegistration','PrinterAgentSession')
        AND c.relrowsecurity AND c.relforcerowsecurity),
    'publicExecute',(SELECT count(*) FROM information_schema.routine_privileges
      WHERE specific_schema IN ('app_rls','app_worker') AND grantee='PUBLIC' AND routine_name LIKE 'printing_%'),
    'ownerSafe',(SELECT count(*) FROM pg_roles WHERE rolname IN ('mscqr_rls_cert_owner','mscqr_rls_cert_auth_owner')
      AND NOT rolcanlogin AND NOT rolbypassrls),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
      WHERE r.rolname='mscqr_rls_cert_auth_owner' AND c.relkind IN ('r','p')),
    'immutable',(SELECT code FROM public."QRCode" WHERE id='${ids.qr}'),
    'audit',(SELECT count(*) FROM public."AuditLog" WHERE "entityId" IN ('${ids.batch}','${created.job.id}')),
    'outbox',(SELECT count(*) FROM public."SecurityEventOutbox" WHERE "licenseeId"='${ids.licenseeA}')
  )`);
  assert.equal(catalog.force, 8);
  assert.equal(catalog.publicExecute, 0);
  assert.equal(catalog.ownerSafe, 2);
  assert.equal(catalog.ownerTables, 0);
  assert.equal(catalog.immutable, immutableCode);
  assert(catalog.audit >= 3);
  assert(catalog.outbox >= 3);

  const { printingSessionPrerequisiteSql } = require("../../../dist/rls-waves/session-c/c02/printingSessionPrerequisite");
  assert.equal(psql(app, printingSessionPrerequisiteSql("mscqr_rls_cert_")), "t|t|t|t|t",
    "The restricted runtime role must independently verify its installed C02 session prerequisite");

  const rollback = readFileSync(
    path.resolve(__dirname, "../../../src/rls-waves/session-c/c02/printingLifecycleRollback.sql"),
    "utf8"
  );
  const functionRollbackAt = rollback.indexOf("REVOKE ALL ON FUNCTION");
  assert(functionRollbackAt > 0, "printing rollback must separate policy and function ownership phases");
  psql(admin, `BEGIN;
    SET LOCAL ROLE "mscqr_rls_cert_owner";
    ${rollback.slice(0, functionRollbackAt)}
    RESET ROLE;
    SET LOCAL ROLE "mscqr_rls_cert_auth_owner";
    ${rollback.slice(functionRollbackAt)}
    RESET ROLE;
    COMMIT;`);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM pg_policies WHERE schemaname='public' AND policyname LIKE 'printing_lifecycle_%'`)), 0);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname LIKE 'printing_%'`)), 0);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE
    (n.nspname='app_auth' AND p.proname='require_authenticated_session')
    OR (n.nspname='app_rls' AND p.proname IN ('read_licensee_directory','session_c_admin_command','qr_allocate_range'))`)), 4);
  console.log("Release Fix 5 PostgreSQL 18 printing lifecycle proof passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
