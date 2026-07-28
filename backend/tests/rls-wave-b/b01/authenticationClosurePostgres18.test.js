const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");

const enabled = process.env.MSCQR_B01_AUTH_CLOSURE_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_B01_AUTH_CLOSURE_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_B01_AUTH_CLOSURE_POSTGRES18_TEST";
const ids = {
  orgA: "10000000-0000-4000-8000-000000000101", orgB: "10000000-0000-4000-8000-000000000102",
  licenseeA: "10000000-0000-4000-8000-000000000201", licenseeB: "10000000-0000-4000-8000-000000000202",
  userA: "10000000-0000-4000-8000-000000000301", userB: "10000000-0000-4000-8000-000000000302",
};
const hash = (value) => createHash("sha256").update(`b01-auth-closure:${value}`).digest("hex");
const capabilities = { primary: "A".repeat(43), rollback: "B".repeat(43), mfa: "C".repeat(43), replacement: "D".repeat(43) };

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
    encoding: "utf8", env: { ...process.env, PGPASSWORD: target.password || "" },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) { assert.notEqual(result.status, 0, `denial probe succeeded: ${sql}`); return output; }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean);
};
const last = (raw, sql) => psql(raw, sql).at(-1) || "";
const denied = (raw, sql, pattern = /permission denied|AUTH_SESSION_CAPABILITY_DENIED|AUTH_LOGIN_SESSION_DENIED/i) => assert.match(psql(raw, sql, true), pattern);
const loginSession = (preauth, tokenHash, requestId, mfa = false) => last(preauth, `BEGIN;
  SELECT id FROM app_auth.lookup_password_user('auth-a@example.invalid');
  SELECT "actorState"->>'userId' FROM app_rls.load_recent_auth_session_risk_inputs(5);
  SELECT "recorded" FROM app_rls.record_auth_session_risk_signal(10,'LOW',ARRAY['KNOWN_DEVICE'],NULL,NULL,transaction_timestamp()::timestamp,NULL,NULL,NULL,NULL,NULL,'${requestId}');
  SELECT id FROM app_rls.create_refresh_token('${ids.userA}','${ids.orgA}','${tokenHash}',(transaction_timestamp()+interval '1 day')::timestamp,NULL,'focused-postgres18',transaction_timestamp()::timestamp,${mfa ? "transaction_timestamp()::timestamp" : "NULL"},transaction_timestamp()::timestamp);
  COMMIT;`);

async function main() {
  if (!enabled) return console.log("B01 authentication closure PostgreSQL 18 proof skipped");
  assert(confirmed, "B01 authentication closure PostgreSQL 18 proof confirmation is required");
  const bootstrap = process.env.MSCQR_B01_AUTH_CLOSURE_BOOTSTRAP_URL;
  const preauth = process.env.MSCQR_B01_AUTH_CLOSURE_PREAUTH_URL;
  const app = process.env.MSCQR_B01_AUTH_CLOSURE_APP_URL;
  for (const url of [bootstrap, preauth, app]) connection(url);
  assert.equal(Number(last(bootstrap, "select current_setting('server_version_num')::int / 10000")), 18);

  for (const table of ["User", "RefreshToken", "AuthSessionRiskSignal", "MfaLoginChallenge", "AuthWebAuthnChallenge"]) {
    denied(app, `SELECT * FROM public."${table}" LIMIT 1`);
    denied(preauth, `SELECT * FROM public."${table}" LIMIT 1`);
  }
  denied(app, `SELECT app_rls.install_actor_context('${ids.userA}','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','','password-verified','forged','auth-me')`);
  assert.equal(last(app, `BEGIN; SELECT set_config('app.user_id','${ids.userA}',true),set_config('app.organization_id','${ids.orgA}',true),set_config('app.licensee_id','${ids.licenseeA}',true),set_config('app.auth_session_verified','1',true); SELECT count(id) FROM public."User"; ROLLBACK`), "0");

  const password = "$argon2id$v=19$m=65536,t=3,p=1$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo";
  psql(bootstrap, `
    INSERT INTO public."Organization" (id,name,"updatedAt") VALUES ('${ids.orgA}','Auth Org A',now()),('${ids.orgB}','Auth Org B',now());
    INSERT INTO public."Licensee" (id,"orgId",name,prefix,"updatedAt") VALUES ('${ids.licenseeA}','${ids.orgA}','Auth Licensee A','ARA',now()),('${ids.licenseeB}','${ids.orgB}','Auth Licensee B','ARB',now());
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","passwordHash","emailVerifiedAt","updatedAt") VALUES
      ('${ids.userA}','auth-a@example.invalid','Auth A','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,'${password}',now(),now()),
      ('${ids.userB}','auth-b@example.invalid','Auth B','LICENSEE_ADMIN','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,'${password}',now(),now());
  `);

  denied(preauth, `BEGIN; SELECT id FROM app_auth.lookup_password_user('auth-a@example.invalid'); SELECT id FROM app_rls.create_refresh_token('${ids.userB}','${ids.orgB}','${hash("f")}',(transaction_timestamp()+interval '1 day')::timestamp,NULL,NULL,transaction_timestamp()::timestamp,NULL,transaction_timestamp()::timestamp); COMMIT`, /AUTH_LOGIN_SESSION_DENIED/);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."RefreshToken" WHERE "userId"='${ids.userB}'`), "0");

  const primaryId = loginSession(preauth, hash("a"), "auth-login-primary");
  assert.match(primaryId, /^[0-9a-f-]{36}$/i);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."AuthSessionRiskSignal" WHERE "userId"='${ids.userA}'`), "1");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."AuthSessionRiskSignal" WHERE "userId"='${ids.userB}'`), "0");
  assert.equal(last(preauth, `BEGIN; SELECT id FROM app_auth.lookup_password_user('auth-a@example.invalid'); SELECT "challengeCreated" FROM app_rls.record_auth_session_risk_signal(30,'MEDIUM',ARRAY['MFA_REQUIRED'],NULL,NULL,transaction_timestamp()::timestamp,NULL,'${hash("d")}','${hash("e")}',(transaction_timestamp()+interval '5 minutes')::timestamp,5,'auth-mfa-challenge'); COMMIT`), "t");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."MfaLoginChallenge" WHERE "userId"='${ids.userA}' AND "ticketHash"='${hash("d")}' AND "consumedAt" IS NULL AND "expiresAt">now()`), "1");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."MfaLoginChallenge" WHERE "userId"='${ids.userB}'`), "0");

  assert.equal(last(preauth, `SELECT id FROM app_auth.issue_authenticated_session_capability('${primaryId}','${hash("a")}','${capabilities.primary}','PASSWORD',(transaction_timestamp()+interval '1 hour')::timestamp)`), primaryId);
  const loadedChallenge = JSON.parse(last(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','admin-mfa-login-complete','auth-mfa-load');
    SELECT app_rls.load_admin_mfa_challenge(ARRAY['${hash("d")}'],ARRAY['${hash("e")}'],transaction_timestamp()::timestamp)::text;
    ROLLBACK;`));
  assert.match(loadedChallenge.expiresAt, /(Z|[+-]\d{2}:\d{2})$/);
  assert(Date.parse(loadedChallenge.expiresAt) > Date.now());
  const failedAttempt = JSON.parse(last(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','admin-mfa-login-complete','auth-mfa-failed');
    SELECT app_rls.record_admin_mfa_challenge_failure('LOGIN','${loadedChallenge.id}','AUTH_MFA_FAILURE',1,transaction_timestamp()::timestamp,NULL,NULL)::text;
    COMMIT;`));
  assert.equal(failedAttempt.recorded, true);
  assert.equal(failedAttempt.attempts, 1);
  assert.equal(last(bootstrap, `SELECT attempts FROM public."MfaLoginChallenge" WHERE id='${loadedChallenge.id}'`), "1");
  const completedChallenge = JSON.parse(last(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','admin-mfa-login-complete','auth-mfa-complete');
    SELECT app_rls.complete_admin_mfa_challenge('LOGIN','${loadedChallenge.id}','BACKUP_CODE',transaction_timestamp()::timestamp,NULL,NULL)::text;
    COMMIT;`));
  assert.equal(completedChallenge.completed, true);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."MfaLoginChallenge" WHERE "userId"='${ids.userA}' AND "ticketHash"='${hash("d")}' AND "consumedAt" IS NOT NULL`), "1");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE "requestId"='auth-mfa-complete' AND payload->>'action' IN ('AUTH_MFA_BACKUP_CODE_USED','AUTH_MFA_LOGIN_COMPLETE')`), "2");
  denied(app, "SELECT * FROM app_auth.require_authenticated_session('', 'auth-me', 'missing')");
  denied(app, `SELECT * FROM app_auth.require_authenticated_session('${"Z".repeat(43)}','auth-me','forged')`);

  const me = psql(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','auth-me-primary');
    SELECT count(*) FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${primaryId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'auth-me-primary');
    SELECT id FROM app_rls.load_authenticated_actor();
    SELECT id FROM app_rls.find_refresh_token_by_id('${primaryId}','${ids.userA}');
    COMMIT;`);
  assert.deepEqual(me.slice(-4), [ids.userA, "1", ids.userA, primaryId]);
  const replacementId = last(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','admin-mfa-step-up-proof','auth-session-replacement');
    SELECT id FROM app_rls.create_refresh_token('${ids.userA}','${ids.orgA}','${hash("6")}',(transaction_timestamp()+interval '1 day')::timestamp,NULL,'focused-postgres18-step-up',transaction_timestamp()::timestamp,transaction_timestamp()::timestamp,transaction_timestamp()::timestamp);
    COMMIT;`);
  assert.match(replacementId, /^[0-9a-f-]{36}$/i);
  assert.equal(last(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','admin-mfa-step-up-proof','auth-session-replacement-issue');
    SELECT id FROM app_auth.issue_authenticated_session_capability('${replacementId}','${hash("6")}','${capabilities.replacement}','ADMIN_MFA',(transaction_timestamp()+interval '1 hour')::timestamp);
    SELECT (current_setting('app.auth_session_verified',true)='1' AND current_setting('app.auth_session_id',true)='${primaryId}')::text;
    COMMIT;`), "true");
  assert.equal(last(app, `BEGIN; SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.replacement}','auth-me','replacement-capability'); ROLLBACK`), ids.userA);
  denied(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.primary}','admin-mfa-step-up-proof','auth-session-cross-actor');
    SELECT id FROM app_rls.create_refresh_token('${ids.userB}','${ids.orgB}','${hash("7")}',(transaction_timestamp()+interval '1 day')::timestamp,NULL,NULL,transaction_timestamp()::timestamp,transaction_timestamp()::timestamp,transaction_timestamp()::timestamp);
    COMMIT;`, /AUTH_LOGIN_SESSION_DENIED/);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."RefreshToken" WHERE id='${replacementId}' AND "userId"='${ids.userA}' AND "orgId"='${ids.orgA}'`), "1");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."RefreshToken" WHERE "userId"='${ids.userB}'`), "0");
  const foreignId = "10000000-0000-4000-8000-000000000399";
  psql(bootstrap, `INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","authenticatedAt","mfaVerifiedAt")
    VALUES ('${foreignId}','${ids.orgB}','${ids.userB}','${hash("8")}',now()+interval '1 day',now(),now())`);
  denied(app, `BEGIN;
    SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.replacement}','admin-mfa-step-up-proof','auth-session-cross-issue');
    SELECT id FROM app_auth.issue_authenticated_session_capability('${foreignId}','${hash("8")}','${"E".repeat(43)}','ADMIN_MFA',(transaction_timestamp()+interval '1 hour')::timestamp);
    COMMIT;`, /AUTH_SESSION_CAPABILITY_DENIED_LIFECYCLE/);
  assert.equal(last(bootstrap, `SELECT ("sessionCapabilityHash" IS NULL)::text FROM public."RefreshToken" WHERE id='${foreignId}'`), "true");
  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','tenant-mismatch'); SELECT count(*) FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${primaryId}','${ids.licenseeB}','${ids.orgB}',transaction_timestamp()::timestamp,'tenant-mismatch'); ROLLBACK`), "0");
  denied(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','actor-mismatch'); SELECT * FROM app_rls.revalidate_authenticated_actor('${ids.userB}','${primaryId}','${ids.licenseeB}','${ids.orgB}',transaction_timestamp()::timestamp,'actor-mismatch'); ROLLBACK`);

  psql(bootstrap, `UPDATE public."Licensee" SET "suspendedAt"=now() WHERE id='${ids.licenseeA}'`);
  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','stale-licensee'); SELECT count(*) FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${primaryId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'stale-licensee'); ROLLBACK`), "0");
  psql(bootstrap, `UPDATE public."Licensee" SET "suspendedAt"=NULL WHERE id='${ids.licenseeA}'; UPDATE public."User" SET role='MANUFACTURER',"orgId"=NULL,"licenseeId"=NULL WHERE id='${ids.userA}'; INSERT INTO public."ManufacturerLicenseeLink" ("manufacturerId","licenseeId","isPrimary","updatedAt") VALUES ('${ids.userA}','${ids.licenseeA}',true,now())`);
  denied(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','manufacturer-bootstrap','manufacturer-legacy'); SELECT app_rls.load_authenticated_manufacturer_scope(NULL,NULL,NULL,'manufacturer-bootstrap',false); ROLLBACK`, /MANUFACTURER_SCOPE_DENIED/);
  psql(bootstrap, `UPDATE public."User" SET role='MANUFACTURER_ADMIN' WHERE id='${ids.userA}'`);
  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','manufacturer-live'); SELECT count(*) FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${primaryId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'manufacturer-live'); ROLLBACK`), "1");
  const linkVersion = last(bootstrap, `SELECT to_char("updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.userA}' AND "licenseeId"='${ids.licenseeA}'`);
  const manufacturerScope = JSON.parse(last(app, `BEGIN;
    SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','manufacturer-bootstrap','manufacturer-scope-live');
    SELECT app_rls.load_authenticated_manufacturer_scope('${ids.licenseeA}','${ids.orgA}','${linkVersion}','manufacturer-bootstrap',true)::text;
    COMMIT;`));
  assert.equal(manufacturerScope.manufacturerId, ids.userA);
  assert.equal(manufacturerScope.selectedLicensee.id, ids.licenseeA);
  assert.deepEqual(manufacturerScope.linkedLicensees.map((item) => item.id), [ids.licenseeA]);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE "requestId"='manufacturer-scope-live' AND payload->>'action'='MANUFACTURER_BOOTSTRAP_READ'`), "1");
  const manufacturerReplacementId = last(app, `BEGIN;
    SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','manufacturer-bootstrap','manufacturer-session-create');
    SELECT id FROM app_rls.create_refresh_token('${ids.userA}','${ids.orgA}','${hash("manufacturer-replacement")}',(transaction_timestamp()+interval '1 day')::timestamp,NULL,'focused-postgres18-manufacturer',transaction_timestamp()::timestamp,transaction_timestamp()::timestamp,transaction_timestamp()::timestamp);
    COMMIT;`);
  assert.match(manufacturerReplacementId, /^[0-9a-f-]{36}$/i);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."RefreshToken" WHERE id='${manufacturerReplacementId}' AND "userId"='${ids.userA}' AND "orgId"='${ids.orgA}'`), "1");
  psql(bootstrap, `DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId"='${ids.userA}' AND "licenseeId"='${ids.licenseeA}'`);
  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','manufacturer-stale'); SELECT count(*) FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${primaryId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'manufacturer-stale'); ROLLBACK`), "0");
  denied(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','manufacturer-bootstrap','manufacturer-scope-stale'); SELECT app_rls.load_authenticated_manufacturer_scope(NULL,NULL,NULL,'manufacturer-bootstrap',false); ROLLBACK`, /MANUFACTURER_MEMBERSHIP_REQUIRED/);
  psql(bootstrap, `UPDATE public."User" SET role='LICENSEE_ADMIN',"orgId"='${ids.orgA}',"licenseeId"='${ids.licenseeA}' WHERE id='${ids.userA}'`);

  psql(bootstrap, `UPDATE public."User" SET "isActive"=false,status='DISABLED' WHERE id='${ids.userA}'`);
  denied(app, `SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','inactive')`);
  psql(bootstrap, `UPDATE public."User" SET "isActive"=true,status='ACTIVE' WHERE id='${ids.userA}'`);

  const rollbackId = loginSession(preauth, hash("b"), "auth-login-rollback");
  assert.equal(last(preauth, `SELECT id FROM app_auth.issue_authenticated_session_capability('${rollbackId}','${hash("b")}','${capabilities.rollback}','PASSWORD',(transaction_timestamp()+interval '1 hour')::timestamp)`), rollbackId);
  denied(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.rollback}','auth-logout','10000000-0000-4000-8000-000000000401'); SELECT * FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${rollbackId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'10000000-0000-4000-8000-000000000401'); SELECT id FROM app_rls.enqueue_audit_log_outbox('{"userId":"${ids.userA}","action":"AUTH_LOGOUT","entityType":"User","entityId":"${ids.userA}","details":{}}'::jsonb,'${hash("1")}','${hash("2")}','10000000-0000-4000-8000-000000000401','${ids.orgA}','${ids.licenseeA}',NULL,'${ids.userA}','LICENSEE_ADMIN',(transaction_timestamp()+interval '1 day')::timestamp,NULL); SELECT * FROM app_rls.revoke_refresh_token_by_id('${rollbackId}','${ids.userA}','LOGOUT',transaction_timestamp()::timestamp); SELECT 1/0; COMMIT`, /division by zero/);
  assert.equal(last(bootstrap, `SELECT ("revokedAt" IS NULL AND "sessionCapabilityRevokedAt" IS NULL)::text FROM public."RefreshToken" WHERE id='${rollbackId}'`), "true");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE "requestId"='10000000-0000-4000-8000-000000000401'`), "0");
  assert.equal(last(app, `BEGIN; SELECT "userId" FROM app_auth.require_authenticated_session('${capabilities.rollback}','auth-me','rollback-reuse'); ROLLBACK`), ids.userA);

  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-logout','10000000-0000-4000-8000-000000000402'); SELECT * FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${primaryId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'10000000-0000-4000-8000-000000000402'); SELECT id FROM app_rls.enqueue_audit_log_outbox('{"userId":"${ids.userA}","action":"AUTH_LOGOUT","entityType":"User","entityId":"${ids.userA}","details":{}}'::jsonb,'${hash("3")}','${hash("4")}','10000000-0000-4000-8000-000000000402','${ids.orgA}','${ids.licenseeA}',NULL,'${ids.userA}','LICENSEE_ADMIN',(transaction_timestamp()+interval '1 day')::timestamp,NULL); SELECT "revoked" FROM app_rls.revoke_refresh_token_by_id('${primaryId}','${ids.userA}','LOGOUT',transaction_timestamp()::timestamp); COMMIT`), "t");
  assert.equal(last(bootstrap, `SELECT ("revokedAt" IS NOT NULL AND "sessionCapabilityRevokedAt" IS NOT NULL)::text FROM public."RefreshToken" WHERE id='${primaryId}'`), "true");
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE "requestId"='10000000-0000-4000-8000-000000000402' AND payload->>'action'='AUTH_LOGOUT'`), "1");
  denied(app, `SELECT * FROM app_auth.require_authenticated_session('${capabilities.primary}','auth-me','revoked')`);
  denied(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.rollback}','auth-logout','cross-revoke'); SELECT * FROM app_rls.revalidate_authenticated_actor('${ids.userA}','${rollbackId}','${ids.licenseeA}','${ids.orgA}',transaction_timestamp()::timestamp,'cross-revoke'); SELECT * FROM app_rls.revoke_refresh_token_by_id('${primaryId}','${ids.userA}','LOGOUT',transaction_timestamp()::timestamp); ROLLBACK`);

  const mfaId = loginSession(preauth, hash("c"), "auth-login-mfa", true);
  assert.equal(last(preauth, `SELECT id FROM app_auth.issue_authenticated_session_capability('${mfaId}','${hash("c")}','${capabilities.mfa}','ADMIN_MFA',(transaction_timestamp()+interval '1 hour')::timestamp)`), mfaId);
  assert.match(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.mfa}','auth-me','recent-mfa'); SELECT "verifiedAt" FROM app_rls.require_recent_mfa_session('${mfaId}',transaction_timestamp()::timestamp,30); ROLLBACK`), /^\d{4}-\d{2}-\d{2}/);
  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.rollback}','auth-me','password-mfa'); SELECT count(*) FROM app_rls.require_recent_mfa_session('${rollbackId}',transaction_timestamp()::timestamp,30); ROLLBACK`), "0");
  psql(bootstrap, `UPDATE public."RefreshToken" SET "sessionCapabilityExpiresAt"=now()-interval '1 second' WHERE id='${mfaId}'`);
  denied(app, `SELECT * FROM app_auth.require_authenticated_session('${capabilities.mfa}','auth-me','expired')`);

  assert.equal(last(app, `BEGIN; SELECT * FROM app_auth.require_authenticated_session('${capabilities.rollback}','auth-me','context-reset'); COMMIT; SELECT coalesce(current_setting('app.auth_session_verified',true),'')=''`), "t");
  const catalog = last(bootstrap, `SELECT jsonb_build_object(
    'force',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname IN ('AuthSessionRiskSignal','AuthWebAuthnChallenge','MfaLoginChallenge') AND c.relrowsecurity AND c.relforcerowsecurity),
    'riskPolicies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename='AuthSessionRiskSignal' AND policyname='b01_auth_closure_authsessionrisksignal_insert' AND cmd='INSERT'),
    'mfaPolicies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename='MfaLoginChallenge' AND policyname='b01_auth_closure_mfaloginchallenge_insert' AND cmd='INSERT'),
    'webAuthnPolicies',(SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename='AuthWebAuthnChallenge' AND policyname LIKE 'b01_auth_closure%'),
    'publicExecute',(SELECT count(*) FROM information_schema.routine_privileges WHERE specific_schema='app_rls' AND grantee='PUBLIC' AND routine_name IN ('create_refresh_token','load_recent_auth_session_risk_inputs','record_auth_session_risk_signal','revalidate_authenticated_actor','load_authenticated_actor','load_authenticated_manufacturer_scope','find_refresh_token_by_id','revoke_refresh_token_by_id','require_recent_mfa_session')),
    'ownerSafe',(SELECT count(*) FROM pg_roles WHERE rolname='mscqr_rls_cert_auth_owner' AND NOT rolcanlogin AND NOT rolbypassrls),
    'ownerTables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND r.rolname='mscqr_rls_cert_auth_owner')
  )::text`);
  assert.deepEqual(JSON.parse(catalog), { force: 3, riskPolicies: 1, mfaPolicies: 1, webAuthnPolicies: 3, publicExecute: 0, ownerSafe: 1, ownerTables: 0 });
  assert.equal(last(bootstrap, `SELECT count(*) FROM information_schema.routine_privileges WHERE privilege_type='EXECUTE' AND ((specific_schema='app_rls' AND ((grantee='mscqr_rls_cert_preauth' AND routine_name IN ('create_refresh_token','load_recent_auth_session_risk_inputs','record_auth_session_risk_signal')) OR (grantee='mscqr_rls_cert_app' AND routine_name IN ('create_refresh_token','revalidate_authenticated_actor','load_authenticated_actor','load_authenticated_manufacturer_scope','find_refresh_token_by_id','revoke_refresh_token_by_id','require_recent_mfa_session')))) OR (specific_schema='app_auth' AND grantee='mscqr_rls_cert_app' AND routine_name='issue_authenticated_session_capability'))`), "11");
  psql(bootstrap, `
    DELETE FROM public."AuditLogOutbox" WHERE payload->>'userId' IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."AuthWebAuthnChallenge" WHERE "userId" IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."MfaLoginChallenge" WHERE "userId" IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."AuthSessionRiskSignal" WHERE "userId" IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."RefreshToken" WHERE "userId" IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId" IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."User" WHERE id IN ('${ids.userA}','${ids.userB}');
    DELETE FROM public."Licensee" WHERE id IN ('${ids.licenseeA}','${ids.licenseeB}');
    DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}');
  `);
  assert.equal(last(bootstrap, `SELECT count(*) FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}')`), "0");
  console.log("B01 authentication closure PostgreSQL 18 application-path proof passed");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
