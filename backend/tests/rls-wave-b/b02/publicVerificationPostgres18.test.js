const assert = require("node:assert/strict");
const { createHash, randomBytes } = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");

const enabled = process.env.MSCQR_PUBLIC_VERIFICATION_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_PUBLIC_VERIFICATION_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_PUBLIC_VERIFICATION_POSTGRES18_TEST";
const ids = {
  org: "60000000-0000-4000-8000-000000000101",
  otherOrg: "60000000-0000-4000-8000-000000000102",
  licensee: "60000000-0000-4000-8000-000000000201",
  otherLicensee: "60000000-0000-4000-8000-000000000202",
  manufacturer: "60000000-0000-4000-8000-000000000301",
  batch: "60000000-0000-4000-8000-000000000401",
  qr: "60000000-0000-4000-8000-000000000501",
};
const hash = (value) => createHash("sha256").update(value).digest("hex");
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
    assert.notEqual(result.status, 0, `denial unexpectedly succeeded: ${sql}`);
    return output;
  }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean).at(-1) || "";
};
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
const json = (url, sql) => JSON.parse(psql(url, sql));
const denied = (url, sql, pattern = /permission denied|PUBLIC_.*(?:INVALID|DENIED)|violates row-level security/i) =>
  assert.match(psql(url, sql, true), pattern);
const verifySql = (code, request, ip, device, start) => `
  SELECT row_to_json(v) FROM app_public.verify_raw_qr(
    '${code}',now()::timestamp,'${request}','${hash(ip)}','${hash(device)}','${hash(start)}'
  ) v`;

async function main() {
  if (!enabled) return console.log("Release Fix 6 PostgreSQL 18 proof skipped");
  assert(confirmed, "Release Fix 6 PostgreSQL 18 proof confirmation is required");
  const admin = process.env.MSCQR_PUBLIC_VERIFICATION_ADMIN_URL;
  const preauth = process.env.MSCQR_PUBLIC_VERIFICATION_PREAUTH_URL;
  const app = process.env.MSCQR_PUBLIC_VERIFICATION_APP_URL;
  [admin, preauth, app].forEach(connection);
  assert.equal(Number(psql(admin, "select current_setting('server_version_num')::int/10000")), 18);
  const customerCapability = randomBytes(32).toString("base64url");
  const customerUserId = "cust_11111111111111111111111111111111";
  const tokenIssuedAt = new Date(Date.now() - 60_000).toISOString();
  const tokenExpiresAt = new Date(Date.now() + 3_600_000).toISOString();

  psql(admin, `
    INSERT INTO public."Organization"(id,name,"isActive","updatedAt")
      VALUES('${ids.org}','Public Verification Org',true,now()),
        ('${ids.otherOrg}','Other Public Verification Org',true,now());
    INSERT INTO public."Licensee"(id,"orgId",name,"brandName",prefix,"isActive","updatedAt")
      VALUES('${ids.licensee}','${ids.org}','Public Verification Licensee','Public Brand','PV',true,now()),
        ('${ids.otherLicensee}','${ids.otherOrg}','Other Public Verification Licensee',
          'Other Public Brand','PX',true,now());
    INSERT INTO public."User"(id,email,name,role,website,"orgId",status,"isActive","updatedAt")
      VALUES('${ids.manufacturer}','public-manufacturer@example.invalid','Public Manufacturer',
        'MANUFACTURER_ADMIN','https://support.example.invalid','${ids.org}','ACTIVE',true,now());
    INSERT INTO public."Batch"(id,name,"licenseeId","manufacturerId","startCode","endCode","totalCodes",
      "lifecycleState","printedAt","updatedAt")
      VALUES('${ids.batch}','Public Batch','${ids.licensee}','${ids.manufacturer}',
        'PUBLICCODE01','PUBLICCODE01',1,'DRAFT',now(),now());
    INSERT INTO public."QRCode"(id,code,"displayCode","licenseeId","batchId",status,
      "issuanceMode","customerVerifiableAt","tokenNonce","tokenHash","tokenIssuedAt",
      "tokenExpiresAt","replayEpoch","printedAt","updatedAt")
      VALUES('${ids.qr}','PUBLICCODE01','PUB-0001','${ids.licensee}','${ids.batch}','PRINTED',
        'GOVERNED_PRINT',now(),'public_nonce_1234','${hash("signed-token")}',
        '${tokenIssuedAt}'::timestamp,'${tokenExpiresAt}'::timestamp,1,now(),now());
  `);

  for (const table of ["QRCode", "QrScanLog", "VerificationDecision", "VerificationEvidenceSnapshot",
    "CustomerVerificationSession", "CustomerTrustIntake", "CustomerAuthSession",
    "CustomerWebAuthnChallenge", "CustomerWebAuthnCredential", "Ownership", "OwnershipTransfer",
    "Incident", "SupportTicket"]) {
    denied(preauth, `SELECT * FROM public."${table}" LIMIT 1`);
    denied(app, `SELECT * FROM public."${table}" LIMIT 1`);
  }
  denied(app, verifySql("PUBLICCODE01", "app-denied", "app", "app", "app"));
  denied(preauth, `SELECT app_public.public_verify_execute(
    '${ids.qr}','MANUAL_CODE_LOOKUP',now()::timestamp,'internal-denied',
    '${hash("ip")}','${hash("device")}','${hash("start")}',NULL
  )`);

  const notReady = json(preauth, verifySql(
    "PUBLICCODE01", "not-ready", "ip-not-ready", "device-not-ready", "session-not-ready",
  ));
  assert.equal(notReady.result, "NOT_READY");
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."QrScanLog" WHERE "qrCodeId"='${ids.qr}'`)), 0);
  assert.equal(Number(psql(admin, `SELECT "scanCount" FROM public."QRCode" WHERE id='${ids.qr}'`)), 0);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."AuditLog"
    WHERE action='PUBLIC_VERIFICATION_RECORDED' AND details->>'classification'='NOT_READY_FOR_CUSTOMER_USE'`)), 1);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."SecurityEventOutbox"
    WHERE "eventType"='PUBLIC_VERIFICATION_DECISION'
      AND payload->>'classification'='NOT_READY_FOR_CUSTOMER_USE'`)), 1);
  const signedNotReady = json(preauth, `SELECT row_to_json(v) FROM app_public.verify_signed_qr(
    '${hash("signed-token")}','${ids.qr}','${ids.licensee}','${ids.batch}','${ids.manufacturer}',
    'public_nonce_1234',1,'test-v1',
    '${tokenIssuedAt}'::timestamp,'${tokenExpiresAt}'::timestamp,
    now()::timestamp,'signed-not-ready','${hash("signed-ip")}','${hash("signed-device")}',
    '${hash("signed-session")}'
  ) v`);
  assert.equal(signedNotReady.result, "NOT_READY");
  const notReadySession = json(preauth, `SELECT row_to_json(s) FROM app_public.start_verification_session(
    '${hash("session-not-ready")}','MANUAL_CODE',NULL,now()::timestamp,
    'not-ready-session-start','${hash("proof-not-ready")}'
  ) s`);
  assert.equal(notReadySession.entryMethod, "MANUAL_CODE");
  denied(preauth, `SELECT app_public.claim_customer_ownership(
    NULL,'${notReadySession.sessionId}','${hash("proof-not-ready")}',
    '${hash("not-ready-device")}','${hash("not-ready-ip")}',NULL,false,
    now()::timestamp,'not-ready-claim'
  )`, /PUBLIC_OWNERSHIP_NOT_READY/);
  denied(preauth, `SELECT app_public.submit_public_incident(
    '${notReadySession.sessionId}','${hash("tampered-report-proof")}','counterfeit_suspected',
    'The unreleased label is being offered to a customer.',NULL,false,'[]'::jsonb,
    now()::timestamp,'not-ready-incident-tampered','${hash("not-ready-incident-ip")}',
    '${hash("not-ready-incident-device")}','${hash("not-ready-incident-tampered")}'
  )`);
  denied(preauth, `SELECT app_public.submit_public_incident(
    '60000000-0000-4000-8000-000000000699','${hash("proof-not-ready")}','counterfeit_suspected',
    'The unreleased label is being offered to a customer.',NULL,false,'[]'::jsonb,
    now()::timestamp,'not-ready-incident-other-session','${hash("not-ready-incident-ip")}',
    '${hash("not-ready-incident-device")}','${hash("not-ready-incident-other-session")}'
  )`);
  const notReadyIncident = json(preauth, `SELECT row_to_json(i) FROM app_public.submit_public_incident(
    '${notReadySession.sessionId}','${hash("proof-not-ready")}','counterfeit_suspected',
    'The unreleased label is being offered to a customer.',NULL,false,'[]'::jsonb,
    now()::timestamp,'not-ready-incident','${hash("not-ready-incident-ip")}',
    '${hash("not-ready-incident-device")}','${hash("not-ready-incident-idempotency")}'
  ) i`);
  assert.equal(notReadyIncident.accepted, true);
  psql(admin, `UPDATE public."CustomerVerificationSession"
    SET "proofBindingExpiresAt"=now()-interval '1 second' WHERE id='${notReadySession.sessionId}'`);
  denied(preauth, `SELECT app_public.submit_public_incident(
    '${notReadySession.sessionId}','${hash("proof-not-ready")}','counterfeit_suspected',
    'The unreleased label is being offered to a customer.',NULL,false,'[]'::jsonb,
    now()::timestamp,'not-ready-incident-expired','${hash("not-ready-incident-ip")}',
    '${hash("not-ready-incident-device")}','${hash("not-ready-incident-expired")}'
  )`);

  psql(admin, `UPDATE public."Batch" SET "lifecycleState"='RELEASED' WHERE id='${ids.batch}'`);
  const first = json(preauth, verifySql("PUBLICCODE01", "first", "ip-a", "device-a", "session-a"));
  assert.equal(first.result, "AUTHENTIC");
  assert.equal(first.messageKey, "verification.first_scan");
  assert.equal(first.brandName, "Public Brand");
  for (const protectedField of ["qrCodeId", "batchId", "licenseeId", "manufacturerId", "riskScore",
    "actorIpHash", "actorDeviceHash", "auditId"]) {
    assert.equal(Object.hasOwn(first, protectedField), false);
  }
  const repeat = json(preauth, verifySql("PUBLICCODE01", "repeat", "ip-a", "device-a", "session-b"));
  assert.equal(repeat.result, "AUTHENTIC_REPEAT");
  const oneSignalOnly = json(preauth, verifySql(
    "PUBLICCODE01", "one-signal-only", "ip-a", "device-changed", "session-one-signal",
  ));
  assert.equal(oneSignalOnly.result, "REVIEW");
  const suspicious = json(preauth, verifySql("PUBLICCODE01", "changed-context", "ip-b", "device-b", "session-c"));
  assert.equal(suspicious.result, "REVIEW");
  const scanCountBeforeBlocked = Number(psql(admin, `SELECT "scanCount" FROM public."QRCode" WHERE id='${ids.qr}'`));
  const scanRowsBeforeBlocked = Number(psql(admin, `SELECT count(*) FROM public."QrScanLog" WHERE "qrCodeId"='${ids.qr}'`));
  psql(admin, `UPDATE public."QRCode" SET status='BLOCKED' WHERE id='${ids.qr}'`);
  const blocked = json(preauth, verifySql(
    "PUBLICCODE01", "blocked", "ip-blocked", "device-blocked", "session-blocked",
  ));
  assert.equal(blocked.result, "BLOCKED");
  assert.equal(Number(psql(admin, `SELECT "scanCount" FROM public."QRCode" WHERE id='${ids.qr}'`)), scanCountBeforeBlocked);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."QrScanLog" WHERE "qrCodeId"='${ids.qr}'`)), scanRowsBeforeBlocked);
  psql(admin, `UPDATE public."QRCode" SET status='PRINTED' WHERE id='${ids.qr}';
    INSERT INTO public."ReplacementChain"(id,status,"originalQrCodeId","replacementQrCodeId","createdAt")
    VALUES('60000000-0000-4000-8000-000000000601','ACTIVE','${ids.qr}',
      '60000000-0000-4000-8000-000000000602',now())`);
  const replaced = json(preauth, verifySql(
    "PUBLICCODE01", "replaced", "ip-replaced", "device-replaced", "session-replaced",
  ));
  assert.equal(replaced.result, "BLOCKED");
  assert.equal(Number(psql(admin, `SELECT "scanCount" FROM public."QRCode" WHERE id='${ids.qr}'`)), scanCountBeforeBlocked);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."QrScanLog" WHERE "qrCodeId"='${ids.qr}'`)), scanRowsBeforeBlocked);
  psql(admin, `DELETE FROM public."ReplacementChain" WHERE id='60000000-0000-4000-8000-000000000601'`);
  const evidenceBeforeUnknown = Number(psql(admin, `SELECT
    (SELECT count(*) FROM public."VerificationDecision")
    +(SELECT count(*) FROM public."VerificationEvidenceSnapshot")
    +(SELECT count(*) FROM public."AuditLog")
    +(SELECT count(*) FROM public."SecurityEventOutbox")`));
  const unknownStartedAt = Date.now();
  const unknown = json(preauth, verifySql("UNKNOWNCODE01", "unknown", "ip-c", "device-c", "session-d"));
  const unknownElapsedMs = Date.now() - unknownStartedAt;
  assert.equal(unknown.result, "NOT_FOUND");
  assert(unknownElapsedMs >= 10 && unknownElapsedMs < 250,
    `unknown-code padding must remain bounded; observed ${unknownElapsedMs}ms`);
  assert.equal(Number(psql(admin, `SELECT
    (SELECT count(*) FROM public."VerificationDecision")
    +(SELECT count(*) FROM public."VerificationEvidenceSnapshot")
    +(SELECT count(*) FROM public."AuditLog")
    +(SELECT count(*) FROM public."SecurityEventOutbox")`)), evidenceBeforeUnknown);
  psql(admin, `UPDATE public."QRCode" SET "batchId"=NULL WHERE id='${ids.qr}'`);
  assert.equal(json(preauth, verifySql(
    "PUBLICCODE01", "missing-batch", "ip-c", "device-c", "session-missing-batch",
  )).result, "NOT_READY");
  psql(admin, `UPDATE public."QRCode" SET "batchId"='${ids.batch}' WHERE id='${ids.qr}';
    UPDATE public."Organization" SET "isActive"=false WHERE id='${ids.org}'`);
  denied(preauth, verifySql(
    "PUBLICCODE01", "inactive-organization", "ip-c", "device-c", "session-inactive-org",
  ));
  psql(admin, `UPDATE public."Organization" SET "isActive"=true WHERE id='${ids.org}';
    UPDATE public."Licensee" SET "suspendedAt"=now() WHERE id='${ids.licensee}'`);
  denied(preauth, verifySql(
    "PUBLICCODE01", "suspended-licensee", "ip-c", "device-c", "session-suspended-licensee",
  ));
  psql(admin, `UPDATE public."Licensee" SET "suspendedAt"=NULL WHERE id='${ids.licensee}';
    UPDATE public."Batch" SET "licenseeId"='${ids.otherLicensee}' WHERE id='${ids.batch}'`);
  denied(preauth, verifySql(
    "PUBLICCODE01", "cross-tenant-batch", "ip-c", "device-c", "session-cross-tenant-batch",
  ));
  psql(admin, `UPDATE public."Batch" SET "licenseeId"='${ids.licensee}' WHERE id='${ids.batch}'`);

  assert.equal(psql(preauth, `SELECT "accepted" FROM app_public.issue_customer_auth_session(
    '${customerCapability}','${customerUserId}','customer@example.invalid','EMAIL_OTP','EMAIL_OTP',
    now()::timestamp,(now()+interval '1 hour')::timestamp,'customer-session-issue'
  )`), "t");
  const customerSession = json(preauth, `SELECT row_to_json(s) FROM app_public.read_customer_auth_session(
    '${customerCapability}',now()::timestamp,'customer-session-read'
  ) s`);
  assert.equal(customerSession.customerUserId, customerUserId);
  const session = json(preauth, `SELECT row_to_json(s) FROM app_public.start_verification_session(
    '${hash("session-a")}','MANUAL_CODE','${customerCapability}',now()::timestamp,'session-start','${hash("proof-a")}'
  ) s`);
  assert.equal(session.entryMethod, "MANUAL_CODE");
  const read = json(preauth, `SELECT row_to_json(s) FROM app_public.read_verification_session(
    '${session.sessionId}','${hash("proof-a")}','${customerCapability}',now()::timestamp,'session-read'
  ) s`);
  assert.equal(read.entryMethod, "MANUAL_CODE");
  denied(preauth, `SELECT * FROM app_public.read_verification_session(
    '${session.sessionId}','${hash("wrong-proof")}','${customerCapability}',now()::timestamp,'session-forged'
  )`);
  const claim = json(preauth, `SELECT app_public.claim_customer_ownership(
    '${customerCapability}','${session.sessionId}','${hash("proof-a")}',
    NULL,'${hash("claim-ip")}','${hash("claim-agent")}',false,now()::timestamp,'claim'
  )`);
  assert.equal(claim.claimResult, "CLAIMED_USER");
  denied(preauth, `SELECT app_public.claim_customer_ownership(
    'forged-capability-000000000000000000000000000000','${session.sessionId}',
    '${hash("proof-a")}',NULL,NULL,NULL,false,now()::timestamp,'claim-forged'
  )`);

  const passkey = json(preauth, `SELECT app_public.begin_customer_passkey(
    '${customerCapability}','${customerUserId}','customer@example.invalid','ENROLLMENT',
    '${hash("passkey-ticket")}','${hash("passkey-challenge")}',NULL,NULL,
    'http://localhost:8080','localhost',(now()+interval '5 minutes')::timestamp,
    now()::timestamp,'passkey-begin'
  )`);
  assert.equal(Array.isArray(passkey.credentials), true);
  const finishedPasskey = json(preauth, `SELECT app_public.finish_customer_passkey(
    '${customerCapability}',ARRAY['${hash("passkey-ticket")}']::text[],'ENROLLMENT',
    '{"credentialId":"credential-public-one","publicKeySpki":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","publicKeyAlgorithm":-7,"counter":0,"transports":["internal"],"label":"Public passkey"}'::jsonb,
    now()::timestamp,'passkey-finish'
  )`);
  assert.equal(finishedPasskey.credentialId, "credential-public-one");
  assert.equal(Number(psql(preauth, `SELECT count(*) FROM app_public.list_customer_passkeys(
    '${customerCapability}',now()::timestamp,'passkey-list'
  )`)), 1);

  const feedback = json(preauth, `SELECT row_to_json(f) FROM app_public.submit_product_feedback(
    'PUBLICCODE01',5,'very_satisfied','private note','AUTHENTIC','FIRST_SCAN',NULL,
    now()::timestamp,'feedback','${hash("feedback-ip")}','${hash("feedback-idempotency")}'
  ) f`);
  assert.equal(feedback.accepted, true);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."AuditLog"
    WHERE action='CUSTOMER_PRODUCT_FEEDBACK' AND details ? 'notes'`)), 0);

  const incident = json(preauth, `SELECT row_to_json(i) FROM app_public.submit_public_incident(
    '${session.sessionId}','${hash("proof-a")}','counterfeit_suspected','The label appears altered.',NULL,false,'[]'::jsonb,
    now()::timestamp,'incident','${hash("incident-ip")}','${hash("incident-device")}',
    '${hash("incident-idempotency")}'
  ) i`);
  assert.equal(incident.accepted, true);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."Incident" WHERE "qrCodeId"='${ids.qr}'`)), 2);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."SecurityEventOutbox"
    WHERE "eventType"='PUBLIC_VERIFICATION_CONCERN'`)), 2);
  const support = json(preauth, `SELECT row_to_json(s) FROM app_public.submit_public_support(
    'Public Customer','customer@example.invalid','product_concern','Concern about this label',
    'The label condition needs support review.','PUBLICCODE01',NULL,'/support',NULL,
    now()::timestamp,'support','${hash("support-idempotency")}'
  ) s`);
  assert.equal(support.accepted, true);
  assert.equal(support.deliveryRequired, true);
  assert.equal(psql(preauth, `SELECT "updated" FROM app_public.complete_public_support_delivery(
    '${hash("support-idempotency")}','DRY_RUN',NULL,'SENT',NULL,now()::timestamp,'support-delivery'
  )`), "t");
  const supportRetry = json(preauth, `SELECT row_to_json(s) FROM app_public.submit_public_support(
    'Public Customer','customer@example.invalid','product_concern','Concern about this label',
    'The label condition needs support review.','PUBLICCODE01',NULL,'/support',NULL,
    now()::timestamp,'support-retry','${hash("support-idempotency")}'
  ) s`);
  assert.equal(supportRetry.deliveryRequired, false);
  const supportRow = json(admin, `SELECT row_to_json(s) FROM (
    SELECT "verificationCode","licenseeId",priority,"emailDeliveryStatus",
      "acknowledgementEmailDeliveryStatus" FROM public."SupportIssueReport"
    ORDER BY "createdAt" DESC,id DESC LIMIT 1
  ) s`);
  assert.equal(supportRow.verificationCode, "PUBLICCODE01");
  assert.equal(supportRow.licenseeId, ids.licensee);
  assert.equal(supportRow.priority, "P2");
  assert.equal(supportRow.emailDeliveryStatus, "DRY_RUN");
  assert.equal(supportRow.acknowledgementEmailDeliveryStatus, "SENT");
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."SupportIssueReport"
    WHERE "referenceCode"='${support.publicReference}'`)), 1);
  denied(preauth, `SELECT * FROM app_public.complete_public_support_delivery(
    '${hash("forged-support-delivery")}','SENT',NULL,'SENT',NULL,now()::timestamp,'support-forged'
  )`);

  const access = json(preauth, `SELECT row_to_json(r) FROM app_public.submit_request_access(
    'Public Operator','operator@example.invalid','Public Company','Compliance Lead','United Kingdom',
    '10000','We need access to the MSCQR platform.','/request-access',NULL,
    now()::timestamp,'request-access','${hash("request-access-idempotency")}'
  ) r`);
  assert.equal(access.deliveryRequired, true);
  assert.equal(psql(preauth, `SELECT "updated" FROM app_public.complete_request_access_delivery(
    '${hash("request-access-idempotency")}','SENT',NULL,'DRY_RUN',NULL,
    now()::timestamp,'request-access-delivery'
  )`), "t");
  const accessRetry = json(preauth, `SELECT row_to_json(r) FROM app_public.submit_request_access(
    'Public Operator','operator@example.invalid','Public Company','Compliance Lead','United Kingdom',
    '10000','We need access to the MSCQR platform.','/request-access',NULL,
    now()::timestamp,'request-access-retry','${hash("request-access-idempotency")}'
  ) r`);
  assert.equal(accessRetry.deliveryRequired, false);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."RequestAccess"
    WHERE "referenceCode"='${access.publicReference}'`)), 1);

  const concurrentCode = "CONCURRENT01";
  psql(admin, `UPDATE public."QRCode" SET code='${concurrentCode}',"scanCount"=0,"scannedAt"=NULL WHERE id='${ids.qr}';
    DELETE FROM public."QrScanLog" WHERE "qrCodeId"='${ids.qr}';
    DELETE FROM public."VerificationEvidenceSnapshot" WHERE "verificationDecisionId" IN
      (SELECT id FROM public."VerificationDecision" WHERE "qrCodeId"='${ids.qr}');
    DELETE FROM public."VerificationDecision" WHERE "qrCodeId"='${ids.qr}';`);
  const race = await Promise.all([
    psqlAsync(preauth, verifySql(concurrentCode, "race-a", "race-ip-a", "race-device-a", "race-session-a")),
    psqlAsync(preauth, verifySql(concurrentCode, "race-b", "race-ip-b", "race-device-b", "race-session-b")),
  ]);
  assert.deepEqual(race.map((entry) => entry.status), [0, 0]);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."VerificationDecision"
    WHERE "qrCodeId"='${ids.qr}' AND classification='FIRST_SCAN'`)), 1);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM public."QrScanLog" WHERE "qrCodeId"='${ids.qr}'`)), 2);
  assert.equal(psql(preauth, `SELECT "revoked" FROM app_public.revoke_customer_auth_session(
    '${customerCapability}',now()::timestamp,'customer-session-revoke'
  )`), "t");
  assert.equal(psql(preauth, `SELECT "revoked" FROM app_public.revoke_customer_auth_session(
    '${customerCapability}',now()::timestamp,'customer-session-revoke-retry'
  )`), "t");
  denied(preauth, `SELECT * FROM app_public.read_customer_auth_session(
    '${customerCapability}',now()::timestamp,'customer-session-read-revoked'
  )`);

  assert.equal(Number(psql(admin, `SELECT count(*) FROM information_schema.routine_privileges
    WHERE routine_schema='app_public' AND grantee='PUBLIC'`)), 0);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM information_schema.routine_privileges
    WHERE routine_schema='app_public' AND grantee=current_database()`)), 0);
  assert.equal(Number(psql(admin, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='app_public' AND p.prosecdef=false`)), 0);
  console.log("Release Fix 6 public verification application-path proof passed");
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
