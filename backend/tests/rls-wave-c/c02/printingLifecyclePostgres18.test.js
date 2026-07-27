const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
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
  registration: "50000000-0000-4000-8000-000000000801",
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
const denied = (url, sql, pattern = /permission denied|PRINTING_BOUNDARY_DENIED|AUTH_SESSION_CAPABILITY_DENIED|INVALID_STATE_TRANSITION|PRINT_ACK_REQUIRED|SAMPLE_SCAN_REQUIRED/i) =>
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
    DELETE FROM public."PrinterAttestation" WHERE "printerRegistrationId"='${ids.registration}';
    DELETE FROM public."RefreshToken" WHERE id IN ('${ids.makerRefresh}','${ids.checkerRefresh}','${ids.outsiderRefresh}');
    DELETE FROM public."Printer" WHERE id IN ('${ids.printer}','${ids.foreignPrinter}');
    DELETE FROM public."PrinterRegistration" WHERE id='${ids.registration}';
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
      VALUES('${ids.registration}','${ids.maker}','${ids.orgA}','${ids.licenseeA}','printing-device','printing-agent','-----BEGIN PUBLIC KEY----- fixture','TRUSTED',now(),now(),now());
    INSERT INTO public."Printer"(id,name,"connectionType","commandLanguage","nativePrinterId","agentId","deviceFingerprint","printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive","isDefault","updatedAt")
      VALUES('${ids.printer}','Printing Local Agent','LOCAL_AGENT','ZPL','printing-native','printing-agent','printing-device','${ids.registration}','${ids.orgA}','${ids.licenseeA}','${ids.maker}','${ids.maker}',true,true,now());
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

  for (const table of ["Batch", "QRCode", "PrintJob", "PrintSession", "PrintItem", "Printer", "PrinterRegistration", "ActionIdempotencyKey"]) {
    denied(app, `SELECT * FROM public."${table}" LIMIT 1`);
  }
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
  )`).eligibleForPrinting, true);
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
  const created = json(app, `SELECT app_rls.printing_create_job(
    '${caps.maker}','printing-create-job','${requestId()}','${ids.batch}','${ids.printer}',1,
    'LBL-0001','LBL-0001','LOCAL_AGENT','ZPL','${hash("print-lock")}',
    '[{"qrCodeId":"${ids.qr}","tokenNonce":"${"a".repeat(64)}","tokenHash":"${hash("print-token")}","tokenExpiresAt":"${expires}"}]'::jsonb
  )`);
  assert.equal(created.preparedCount, 1);
  const immutableCode = psql(admin, `SELECT code FROM public."QRCode" WHERE id='${ids.qr}'`);

  const claim = json(app, `SELECT app_rls.printing_connector_event(
    '${ids.registration}','printing-agent','printing-device','claim_nonce_00001',now()::timestamp,
    '${requestId()}','CLAIM','${requestId()}',NULL,'${ids.printer}','${hash("claim")}',NULL,'{}'::jsonb
  )`);
  assert.equal(claim.available, true);
  assert.equal(claim.qrCode.code, immutableCode);
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
    '[{"qrCodeId":"${ids.raceQr}","tokenNonce":"${suffix.repeat(64)}","tokenHash":"${hash(`race-token-${suffix}`)}","tokenExpiresAt":"${expires}"}]'::jsonb
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

  const catalog = json(admin, `SELECT jsonb_build_object(
    'force',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relname IN ('Batch','QRCode','PrintJob','PrintSession','PrintItem','Printer','PrinterRegistration')
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
  assert.equal(catalog.force, 7);
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
