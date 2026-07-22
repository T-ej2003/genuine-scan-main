const assert = require("node:assert/strict");
const { execFile, spawnSync } = require("node:child_process");
const { promisify } = require("node:util");

const execute = promisify(execFile);
const enabled = process.env.MSCQR_B01_PREAUTH_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_B01_PREAUTH_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_B01_PREAUTH_POSTGRES18_TEST";
const ids = {
  org: "00000000-0000-4000-8000-000000000101",
  licensee: "00000000-0000-4000-8000-000000000201",
  active: "00000000-0000-4000-8000-000000002001",
  invited: "00000000-0000-4000-8000-000000002002",
  rollback: "00000000-0000-4000-8000-000000002003",
  verify: "00000000-0000-4000-8000-000000002004",
  invite: "00000000-0000-4000-8000-000000002101",
  inviteRace: "00000000-0000-4000-8000-000000002102",
  resetRollback: "00000000-0000-4000-8000-000000002201",
  emailToken: "00000000-0000-4000-8000-000000002301",
  refresh: "00000000-0000-4000-8000-000000002401",
  appInviteUser: "00000000-0000-4000-8000-000000002501",
  appResetUser: "00000000-0000-4000-8000-000000002502",
  appVerifyUser: "00000000-0000-4000-8000-000000002503",
  appInvite: "00000000-0000-4000-8000-000000002601",
  appReset: "00000000-0000-4000-8000-000000002602",
  appVerify: "00000000-0000-4000-8000-000000002603",
  disabled: "00000000-0000-4000-8000-000000002701",
  disabledReset: "00000000-0000-4000-8000-000000002702",
  wrongPurpose: "00000000-0000-4000-8000-000000002703",
};

const connection = (raw) => {
  const parsed = new URL(String(raw || ""));
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname));
  assert(!/(staging|prod|amazonaws|rds)/i.test(raw));
  const password = decodeURIComponent(parsed.password || "");
  parsed.password = "";
  return { url: parsed.toString(), password };
};
const psql = (url, sql, expectFailure = false) => {
  const target = connection(url);
  const result = spawnSync("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8", env: { ...process.env, PGPASSWORD: target.password || process.env.PGPASSWORD || "" },
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim();
  if (expectFailure) { assert.notEqual(result.status, 0, "denial probe unexpectedly succeeded"); return output; }
  if (result.status !== 0) throw new Error(output || "psql failed");
  return String(result.stdout || "").trim().split("\n").filter(Boolean).at(-1) || "";
};
const concurrent = async (url, sql) => {
  const target = connection(url);
  const run = () => execute("psql", [target.url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    encoding: "utf8", env: { ...process.env, PGPASSWORD: target.password || process.env.PGPASSWORD || "" },
  }).then(({ stdout }) => stdout.trim()).catch((error) => `${error.stdout || ""}${error.stderr || ""}${error.message || ""}`.trim());
  return Promise.all([run(), run()]);
};

async function main() {
  if (!enabled) return console.log("B01 pre-auth PostgreSQL 18 proof skipped");
  assert(confirmed, "B01 pre-auth PostgreSQL 18 proof confirmation is required");
  const bootstrap = process.env.MSCQR_B01_PREAUTH_BOOTSTRAP_URL;
  const preauth = process.env.PREAUTH_DATABASE_URL;
  const app = process.env.DATABASE_URL;
  for (const url of [bootstrap, preauth, app]) connection(url);
  assert.equal(Number(psql(bootstrap, "select current_setting('server_version_num')::int / 10000")), 18);

  assert.match(psql(preauth, 'SELECT id FROM public."User" LIMIT 1', true), /permission denied/i);
  assert.match(psql(preauth, 'SELECT id FROM public."Invite" LIMIT 1', true), /permission denied/i);
  assert.match(psql(preauth, 'UPDATE public."PasswordReset" SET "usedAt"=transaction_timestamp()', true), /permission denied/i);
  assert.match(psql(preauth, 'DELETE FROM public."EmailVerificationToken"', true), /permission denied/i);
  assert.match(psql(preauth, "SELECT app_auth.b01_preauth_audit('AUTH_INVITE_ACCEPTED','Invite','x',transaction_timestamp()::timestamp,'{}')", true), /permission denied/i);
  assert.match(psql(preauth, "SELECT app_rls.install_actor_context('00000000-0000-4000-8000-000000000301','LICENSEE_ADMIN','','','','password-verified','x','x')", true), /permission denied/i);
  assert.match(psql(preauth, `BEGIN; SELECT set_config('app.b01_preauth_user_id','${ids.active}',true),set_config('app.b01_preauth_operation','reset-consume',true); UPDATE public."User" SET name='forged' WHERE id='${ids.active}'; ROLLBACK`, true), /permission denied/i);

  const password = "$argon2id$v=19$m=65536,t=3,p=1$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo";
  const activeHash = "1".repeat(64), inviteHash = "2".repeat(64), raceHash = "3".repeat(64), rollbackHash = "4".repeat(64), emailHash = "5".repeat(64), refreshHash = "6".repeat(64), disabledHash = "8".repeat(64), wrongPurposeHash = "9".repeat(64);
  psql(bootstrap, `
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","passwordHash","emailVerifiedAt","updatedAt") VALUES
      ('${ids.active}','b01-active@example.invalid','B01 Active','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','ACTIVE',true,'${password}',transaction_timestamp(),transaction_timestamp()),
      ('${ids.invited}','b01-invited@example.invalid','B01 Invited','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','INVITED',true,NULL,NULL,transaction_timestamp()),
      ('${ids.rollback}','b01-rollback@example.invalid','B01 Rollback','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','ACTIVE',true,'${password}',transaction_timestamp(),transaction_timestamp()),
      ('${ids.verify}','b01-verify@example.invalid','B01 Verify','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','ACTIVE',true,'${password}',NULL,transaction_timestamp()),
      ('${ids.disabled}','b01-disabled@example.invalid','B01 Disabled','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','DISABLED',false,'${password}',NULL,transaction_timestamp());
    INSERT INTO public."Invite" (id,"orgId","licenseeId",email,role,"tokenHash","expiresAt") VALUES
      ('${ids.invite}','${ids.org}','${ids.licensee}','b01-invited@example.invalid','LICENSEE_ADMIN','${inviteHash}',transaction_timestamp()+interval '1 hour');
    INSERT INTO public."PasswordReset" (id,"orgId","userId","tokenHash","expiresAt") VALUES
      ('${ids.resetRollback}','${ids.org}','${ids.rollback}','${rollbackHash}',transaction_timestamp()+interval '1 hour'),
      ('${ids.disabledReset}','${ids.org}','${ids.disabled}','${disabledHash}',transaction_timestamp()+interval '1 hour');
    INSERT INTO public."EmailVerificationToken" (id,"userId",email,purpose,"tokenHash","expiresAt") VALUES
      ('${ids.emailToken}','${ids.verify}','b01-verify@example.invalid','EMAIL_VERIFICATION','${emailHash}',transaction_timestamp()+interval '1 hour'),
      ('${ids.wrongPurpose}','${ids.verify}','b01-verify@example.invalid','PASSWORD_RESET','${wrongPurposeHash}',transaction_timestamp()+interval '1 hour');
    INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt") VALUES
      ('${ids.refresh}','${ids.org}','${ids.active}','${refreshHash}',transaction_timestamp()+interval '1 day');
  `);

  assert.equal(psql(preauth, "SELECT email FROM app_auth.lookup_password_user('b01-active@example.invalid')"), "b01-active@example.invalid");
  assert.match(psql(preauth, "SELECT * FROM app_auth.lookup_password_user('not-an-email')", true), /B01_PASSWORD_LOOKUP_DENIED/);
  assert.equal(psql(preauth, `SELECT id FROM app_auth.consume_password_reset_token(ARRAY['${"f".repeat(64)}'],'${password}',transaction_timestamp()::timestamp)`), "");
  assert.equal(psql(preauth, `SELECT id FROM app_auth.consume_password_reset_token(ARRAY['${disabledHash}'],'${password}',transaction_timestamp()::timestamp)`), "");
  assert.equal(psql(preauth, `SELECT "userId" FROM app_auth.consume_email_verification_token(ARRAY['${wrongPurposeHash}'],transaction_timestamp()::timestamp)`), "");
  const failures = await concurrent(preauth, "SELECT \"failedLoginAttempts\" FROM app_auth.record_password_failure('b01-active@example.invalid',transaction_timestamp()::timestamp,5,15)");
  assert.deepEqual(failures.map(Number).sort((a,b)=>a-b), [1,2]);
  assert.equal(psql(preauth, `SELECT "deliveryRequired" FROM app_auth.request_password_reset('b01-active@example.invalid','${activeHash}',(transaction_timestamp()+interval '1 hour')::timestamp,transaction_timestamp()::timestamp,NULL,NULL)`), "t");
  assert.equal(psql(bootstrap, `SELECT count(*) FROM public."PasswordReset" WHERE "tokenHash"='${activeHash}' AND "usedAt" IS NULL AND "expiresAt">transaction_timestamp()`), "1");
  assert.equal(psql(bootstrap, `BEGIN; SET LOCAL ROLE mscqr_rls_cert_auth_owner; SELECT set_config('app.b01_preauth_operation','reset-consume',true),set_config('app.b01_preauth_hashes','${activeHash}',true),set_config('app.b01_preauth_user_id','${ids.active}',true); SELECT (SELECT count(*) FROM public."PasswordReset" WHERE "tokenHash"='${activeHash}')::text||':'||(SELECT count(*) FROM public."User" WHERE id='${ids.active}')::text; ROLLBACK`), "1:1");
  assert.equal(psql(preauth, "SELECT \"deliveryRequired\" FROM app_auth.request_password_reset('missing@example.invalid','" + "7".repeat(64) + "',(transaction_timestamp()+interval '1 hour')::timestamp,transaction_timestamp()::timestamp,NULL,NULL)"), "f");

  const resetRace = await concurrent(preauth, `SELECT id FROM app_auth.consume_password_reset_token(ARRAY['${activeHash}'],'${password}',transaction_timestamp()::timestamp)`);
  assert.equal(resetRace.filter((value) => value===ids.active).length, 1, `password reset must have one winner: ${JSON.stringify(resetRace)}`);
  assert.equal(psql(preauth, `SELECT id FROM app_auth.consume_password_reset_token(ARRAY['${activeHash}'],'${password}',transaction_timestamp()::timestamp)`), "");
  assert.equal(psql(bootstrap, `SELECT ("usedAt" IS NOT NULL)::text||':'||(SELECT ("revokedAt" IS NOT NULL AND "sessionCapabilityRevokedAt" IS NOT NULL)::text FROM public."RefreshToken" WHERE id='${ids.refresh}') FROM public."PasswordReset" WHERE "tokenHash"='${activeHash}'`), "true:true");

  const rollbackOutput = psql(preauth, `BEGIN; SELECT * FROM app_auth.consume_password_reset_token(ARRAY['${rollbackHash}'],'${password}',transaction_timestamp()::timestamp); SELECT 1/0; COMMIT`, true);
  assert.match(rollbackOutput, /division by zero/i);
  assert.equal(psql(bootstrap, `SELECT ("usedAt" IS NULL)::text FROM public."PasswordReset" WHERE id='${ids.resetRollback}'`), "true");

  assert.equal(psql(preauth, `SELECT email FROM app_auth.lookup_invitation_token(ARRAY['${inviteHash}'],transaction_timestamp()::timestamp)`), "b01-invited@example.invalid");
  const inviteRace = await concurrent(preauth, `SELECT id FROM app_auth.consume_invitation_token(ARRAY['${inviteHash}'],'${password}',NULL,transaction_timestamp()::timestamp,'b01-race',NULL,NULL)`);
  assert.equal(inviteRace.filter((value) => value===ids.invited).length, 1, `invitation consume must have one winner: ${JSON.stringify(inviteRace)}`);
  assert.equal(psql(preauth, `SELECT id FROM app_auth.consume_invitation_token(ARRAY['${inviteHash}'],'${password}',NULL,transaction_timestamp()::timestamp,'b01-replay',NULL,NULL)`), "");

  const emailRace = await concurrent(preauth, `SELECT "userId" FROM app_auth.consume_email_verification_token(ARRAY['${emailHash}'],transaction_timestamp()::timestamp)`);
  assert.equal(emailRace.filter((value) => value===ids.verify).length, 1, `email verification must have one winner: ${JSON.stringify(emailRace)}`);
  assert.equal(psql(preauth, `SELECT "userId" FROM app_auth.consume_email_verification_token(ARRAY['${emailHash}'],transaction_timestamp()::timestamp)`), "");
  assert.equal(psql(preauth, `BEGIN; SELECT email FROM app_auth.lookup_password_user('b01-active@example.invalid'); COMMIT; SELECT coalesce(current_setting('app.b01_preauth_user_id',true),'')=''`), "t");
  assert.equal(psql(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE payload->>'action' IN ('AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_INVITE_ACCEPTED','AUTH_EMAIL_VERIFIED') AND payload ? 'tokenHash'`), "0");
  assert.equal(psql(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE payload->>'action' IN ('AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_INVITE_ACCEPTED','AUTH_EMAIL_VERIFIED')`), "4");

  // Exercise the production service -> repository -> SQL boundary path against
  // the same migration-derived schema and restricted pre-auth role.
  process.env.AUTHENTICATED_APP_DATABASE_URL = app;
  process.env.TOKEN_HASH_SECRET_CURRENT = "b01-preauth-postgres18-local-secret-material";
  const { hashToken } = require("../../../dist/utils/security");
  const { acceptInvite, getInvitePreview } = require("../../../dist/services/auth/inviteService");
  const { resetPasswordWithToken } = require("../../../dist/services/auth/passwordResetService");
  const { confirmEmailVerification } = require("../../../dist/services/auth/emailVerificationService");
  const raw = { invite: "b01-app-invite-token", reset: "b01-app-reset-token", verify: "b01-app-verify-token" };
  psql(bootstrap, `
    INSERT INTO public."User" (id,email,name,role,"orgId","licenseeId",status,"isActive","passwordHash","emailVerifiedAt","updatedAt") VALUES
      ('${ids.appInviteUser}','b01-app-invite@example.invalid','App Invite','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','INVITED',true,NULL,NULL,transaction_timestamp()),
      ('${ids.appResetUser}','b01-app-reset@example.invalid','App Reset','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','ACTIVE',true,'${password}',transaction_timestamp(),transaction_timestamp()),
      ('${ids.appVerifyUser}','b01-app-verify@example.invalid','App Verify','LICENSEE_ADMIN','${ids.org}','${ids.licensee}','ACTIVE',true,'${password}',NULL,transaction_timestamp());
    INSERT INTO public."Invite" (id,"orgId","licenseeId",email,role,"tokenHash","expiresAt") VALUES
      ('${ids.appInvite}','${ids.org}','${ids.licensee}','b01-app-invite@example.invalid','LICENSEE_ADMIN','${hashToken(raw.invite)}',transaction_timestamp()+interval '1 hour');
    INSERT INTO public."PasswordReset" (id,"orgId","userId","tokenHash","expiresAt") VALUES
      ('${ids.appReset}','${ids.org}','${ids.appResetUser}','${hashToken(raw.reset)}',transaction_timestamp()+interval '1 hour');
    INSERT INTO public."EmailVerificationToken" (id,"userId",email,purpose,"tokenHash","expiresAt") VALUES
      ('${ids.appVerify}','${ids.appVerifyUser}','b01-app-verify@example.invalid','EMAIL_VERIFICATION','${hashToken(raw.verify)}',transaction_timestamp()+interval '1 hour');
  `);
  const preview = await getInvitePreview(raw.invite);
  assert.equal(preview.email, "b01-app-invite@example.invalid");
  const accepted = await acceptInvite({ rawToken: raw.invite, password: "Local-Certification-Password-23!", name: "App Invite", requestId: "b01-app-invite", ipHash: null, userAgent: "local-certification" });
  assert.equal(accepted.id, ids.appInviteUser);
  const reset = await resetPasswordWithToken({ rawToken: raw.reset, newPassword: "Local-Certification-Password-24!", ipHash: null, userAgent: "local-certification" });
  assert.equal(reset.id, ids.appResetUser);
  const verified = await confirmEmailVerification({ rawToken: raw.verify, actorIpAddress: null, actorUserAgent: "local-certification" });
  assert.equal(verified.email, "b01-app-verify@example.invalid");
  assert.equal(psql(bootstrap, `SELECT count(*) FROM public."AuditLogOutbox" WHERE payload->>'userId' IN ('${ids.appInviteUser}','${ids.appResetUser}','${ids.appVerifyUser}')`), "3");

  const executeGrants = psql(bootstrap, `SELECT count(*) FROM information_schema.routine_privileges WHERE specific_schema='app_auth' AND grantee=(SELECT rolname FROM pg_roles WHERE rolname LIKE 'mscqr%preauth') AND privilege_type='EXECUTE' AND routine_name IN ('lookup_password_user','record_password_failure','request_password_reset','consume_password_reset_token','lookup_invitation_token','consume_invitation_token','consume_email_verification_token')`);
  assert.equal(executeGrants, "7");
  console.log("B01 pre-auth security application-path proof passed");
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
