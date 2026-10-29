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

  for (const table of ["Batch", "QRCode", "PrintJob", "PrintSession", "PrintItem", "Printer", "PrinterRegistration", "PrinterAgentSession", "ActionIdempotencyKey"]) {
    denied(app, `SELECT * FROM public."${table}" LIMIT 1`);
  }
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
  const open = (id, connectionId) => sessionSql("OPEN", id, { connectionId, expirySeconds: 3600 });
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
  assert.equal(await signedSessionBoundary.buildNextPrintChunkForSession(liveSession), null,
    "A signed hello alone must wait for health, without claiming or closing the session");
  const signedHeartbeat = (messageSeq, targetSession = liveSession, health = {}) => {
    const message = { type: "heartbeat", sessionId: targetSession.id, messageSeq,
      printerHealth: { healthVersion: 1, selectedPrinterId: "printing-native", observedAt: new Date().toISOString(),
        discovered: true, queueAvailable: true, online: true, ...health },
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
  await signedSessionBoundary.recordTrustedSessionHeartbeat(liveSession, signedHeartbeat(3));
  assert.equal(renewalCount(), baselineRenewals + 2, "expired attestation must renew from a signed socket heartbeat");
  const renewedAttestation = json(admin, `SELECT jsonb_build_object(
    'sessionId',metadata->>'sessionId','messageSeq',metadata->>'messageSeq',
    'selectedPrinterId',metadata->>'selectedPrinterId','signatureValid',"signatureValid",
    'trustValid',"trustValid",'fresh',"expiresAt">now())
    FROM public."PrinterAttestation" WHERE "printerRegistrationId"='${ids.registration}'
      AND metadata->>'source'='PERSISTENT_SESSION' ORDER BY "createdAt" DESC LIMIT 1`);
  assert.deepEqual(renewedAttestation, { sessionId: liveSession.id, messageSeq: "3",
    selectedPrinterId: "printing-native", signatureValid: true, trustValid: true, fresh: true });
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
  const staleHealth = signedHeartbeat(++healthSequence, continuousSession,
    { observedAt: new Date(Date.now()-60_000).toISOString() });
  await assert.rejects(signedSessionBoundary.recordTrustedSessionHeartbeat(continuousSession, staleHealth), /verification is unavailable/);
  assert.equal(Number(psql(admin, `SELECT "lastMessageSeq" FROM public."PrinterAgentSession" WHERE id='${continuousSession.id}'`)),
    healthSequence-1, "Stale health must not advance the accepted sequence or renew authorization");
  psql(admin, `UPDATE public."PrinterAttestation" SET "expiresAt"=now()-interval '1 second'
    WHERE metadata->>'sessionId'='${continuousSession.id}'`);
  assert.equal(json(app, `SELECT app_rls.printing_readiness(
    '${caps.maker}','printing-readiness','${requestId()}','PRINTER_STATUS','${ids.maker}','{}'::jsonb)`)
    .eligibleForPrinting, false, "Stale health cannot keep expired authorization ready");
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
  assert.equal(json(app, `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','ACK','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','test_ack_nonce_00001','issuedAt',now()),
    '{"testJobId":"${testJobId}","metadata":{"deviceJobRef":"spool-test"}}'::jsonb
  )`).matched, true);
  assert.equal(json(app, `SELECT app_rls.printing_test_label_job(
    NULL,'${requestId()}','CONFIRM','${ids.printer}',
    jsonb_build_object('registrationId','${ids.registration}','agentId','printing-agent',
      'deviceFingerprint','printing-device','nonce','test_confirm_nonce1','issuedAt',now()),
    '{"testJobId":"${testJobId}","payloadType":"ZPL","deviceJobRef":"spool-test","confirmationMode":"LOCAL_QUEUE"}'::jsonb
  )`).matched, true);
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
  const created = json(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL','${hash("print-lock")}',
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("print-token")}","tokenIssuedAt":"${signedAt}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`);
  assert.equal(created.preparedCount, 1);
  assert.equal(new Date(`${psql(admin, `SELECT to_char("tokenIssuedAt",'YYYY-MM-DD"T"HH24:MI:SS.MS') FROM public."QRCode" WHERE id='${ids.qr}'`)}Z`).toISOString(), signedAt);
  const immutableCode = psql(admin, `SELECT code FROM public."QRCode" WHERE id='${ids.qr}'`);

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
  const ack = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','ack_nonce_0000001',now()::timestamp,
    '${requestId()}','ACK','${created.job.id}','${claim.printItemId}','${ids.printer}','${hash("ack")}','spool-1','{}'::jsonb
  )`);
  assert.equal(ack.operation, "ACK");
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
      authorization:`Bearer ${signAccessToken({userId:ids[name],email:"printing-http@example.invalid",role,sessionId:ids[`${name}Refresh`],orgId:name==="outsider"?ids.orgB:ids.orgA,licenseeId:name==="outsider"?ids.licenseeB:ids.licenseeA,scopeVersion})}`,
      "x-database-session-capability":sealCookieToken(caps[name],"auth.database-session"),...extraHeaders,
    }:extraHeaders;
    const response=await fetch(`http://127.0.0.1:${server.address().port}/api/manufacturer/print-reissue-requests`,{headers});
    assert.equal(response.status,expected,`printing list HTTP status ${response.status}`);
    return response.json();
  };
  try {
    assert((await httpList("checker",200)).data.some(row=>row.id===reissueId));
    assert((await httpList("maker",200)).data.some(row=>row.id===reissueId));
    await httpList("checker",403,{"x-request-id":"not-a-uuid"});
    assert.deepEqual((await httpList("outsider",200)).data,[]);
    await httpList(null,401);
    await httpList("checker",401,{"x-database-session-capability":"invalid"});
    psql(admin,`UPDATE public."User" SET "isActive"=false WHERE id='${ids.checker}'`);
    await httpList("checker",401);
    psql(admin,`UPDATE public."User" SET "isActive"=true WHERE id='${ids.checker}'`);
  } finally { await new Promise(resolve=>server.close(resolve)); }

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
