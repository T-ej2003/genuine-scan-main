const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { PrismaClient } = require("@prisma/client");

const enabled = process.env.MSCQR_SESSION_C_OPERATOR_POSTGRES18_TEST === "true";
const confirmed = process.env.MSCQR_SESSION_C_OPERATOR_POSTGRES18_CONFIRM === "MSCQR_RUN_LOCAL_SESSION_C_OPERATOR_POSTGRES18_TEST";
const database = "mscqr_rls_wave_c_admin_governance_operator";
const postgresPort = Number(process.env.MSCQR_SESSION_C_OPERATOR_POSTGRES18_PORT || 55434);
const adminUrl = `postgresql://mscqr_rls_cert_admin@127.0.0.1:${postgresPort}/${database}`;
const roleUrl = (role) => `postgresql://${role}@127.0.0.1:${postgresPort}/${database}`;

const psql = (sql) => {
  const run = spawnSync("psql", [adminUrl, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", sql], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(run.stderr || run.stdout || "psql failed");
  return run.stdout.trim();
};

const psqlFile = (file) => {
  const run = spawnSync("psql", [adminUrl, "-X", "-v", "ON_ERROR_STOP=1", "-f", file], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(run.stderr || run.stdout || "psql file failed");
};

const ids = {
  operator: "00000000-0000-4400-8000-000000000001",
  approver1: "00000000-0000-4400-8000-000000000002",
  approver2: "00000000-0000-4400-8000-000000000003",
  target: "00000000-0000-4400-8000-000000000004",
  tenantActor: "00000000-0000-4400-8000-000000000005",
  diagnosticUnactivated: "00000000-0000-4400-8000-000000000006",
  diagnosticMfaIncomplete: "00000000-0000-4400-8000-000000000007",
  diagnosticMfaComplete: "00000000-0000-4400-8000-000000000008",
  diagnosticSuperseded: "00000000-0000-4400-8000-000000000009",
  orgA: "00000000-0000-4400-8000-000000000011",
  orgB: "00000000-0000-4400-8000-000000000012",
  licenseeA: "00000000-0000-4400-8000-000000000021",
  licenseeB: "00000000-0000-4400-8000-000000000022",
  batch: "00000000-0000-4400-8000-000000000031",
  setupApproval: "00000000-0000-4400-8000-000000000041",
  staleApproval: "00000000-0000-4400-8000-000000000042",
  mfaApproval: "00000000-0000-4400-8000-000000000043",
  fixtureApproval: "00000000-0000-4400-8000-000000000044",
  fixture: "00000000-0000-4302-8000-000000000001",
};

const setupSql = `
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mscqr_rls_wave_c_operator') THEN CREATE ROLE mscqr_rls_wave_c_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mscqr_rls_wave_c_breakglass') THEN CREATE ROLE mscqr_rls_wave_c_breakglass LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mscqr_rls_wave_c_migration') THEN CREATE ROLE mscqr_rls_wave_c_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mscqr_rls_wave_c_unrelated') THEN CREATE ROLE mscqr_rls_wave_c_unrelated LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS; END IF;
END $$;
GRANT CONNECT ON DATABASE ${database} TO mscqr_rls_wave_c_operator,mscqr_rls_wave_c_breakglass,mscqr_rls_wave_c_migration,mscqr_rls_wave_c_unrelated;
GRANT USAGE ON SCHEMA public,app_ops TO mscqr_rls_wave_c_operator,mscqr_rls_wave_c_breakglass,mscqr_rls_wave_c_migration;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM mscqr_rls_wave_c_operator,mscqr_rls_wave_c_breakglass,mscqr_rls_wave_c_migration,mscqr_rls_wave_c_unrelated;
GRANT EXECUTE ON FUNCTION app_ops.print_diagnostic(uuid) TO mscqr_rls_wave_c_operator;
GRANT EXECUTE ON FUNCTION app_ops.diagnose_account_onboarding(text) TO mscqr_rls_wave_c_operator;
GRANT EXECUTE ON FUNCTION app_ops.reissue_account_setup_link(uuid,uuid,text,uuid) TO mscqr_rls_wave_c_operator;
GRANT EXECUTE ON FUNCTION app_ops.prepare_rls_validation_fixture(uuid,text,uuid) TO mscqr_rls_wave_c_operator;
GRANT EXECUTE ON FUNCTION app_ops.reset_account_mfa(uuid,uuid,text,uuid) TO mscqr_rls_wave_c_breakglass;
GRANT EXECUTE ON FUNCTION app_ops.bootstrap_configured_super_admin(text,text,text,boolean) TO mscqr_rls_wave_c_migration;
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['User','Organization','Licensee','ManufacturerLicenseeLink','QRRange','Batch','QRCode','PrintJob','PrintSession','PrintItem','Invite','PasswordReset','RefreshToken','AdminMfaCredential','AdminWebAuthnCredential','UserMfaFactor','UserBackupCode','SensitiveActionApproval','ActionIdempotencyKey','AuditLog','SecurityEventOutbox']
  LOOP EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',t); EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',t); END LOOP;
END $$;
`;

const fixtureSql = `
DELETE FROM public."SecurityEventOutbox" WHERE "eventType" IN ('OPERATOR_PROCEDURE_AUDIT','AUTH_SETUP_LINK_REISSUE_REQUESTED');
DELETE FROM public."AuditLog" WHERE action LIKE 'OPERATOR_%' OR action LIKE 'AUTH_MFA_BREAK_GLASS%' OR action LIKE 'STAGING_RLS_%' OR action LIKE 'AUTH_SUPER_ADMIN_BOOTSTRAP%';
DELETE FROM public."ActionIdempotencyKey" WHERE action LIKE 'operator.%';
DELETE FROM public."SensitiveActionApproval" WHERE id IN ('${ids.setupApproval}','${ids.staleApproval}','${ids.mfaApproval}','${ids.fixtureApproval}');
DELETE FROM public."Invite" WHERE email='target-c04@example.invalid';
DELETE FROM public."Invite" WHERE email LIKE 'diagnostic-c04-%@example.invalid';
DELETE FROM public."AuditLog" WHERE "entityId" IN ('diagnostic-c04-no-account-invite','diagnostic-c04-unactivated-invite','diagnostic-c04-mfa-incomplete-invite','diagnostic-c04-mfa-complete-invite','diagnostic-c04-history-a','diagnostic-c04-history-b','diagnostic-c04-superseded-old','diagnostic-c04-superseded-new','${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."AuditLogOutbox" WHERE payload->>'entityId' IN ('diagnostic-c04-no-account-invite','diagnostic-c04-unactivated-invite','diagnostic-c04-mfa-incomplete-invite','diagnostic-c04-mfa-complete-invite','diagnostic-c04-history-a','diagnostic-c04-history-b','diagnostic-c04-superseded-old','diagnostic-c04-superseded-new','${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."PasswordReset" WHERE "userId"='${ids.target}';
DELETE FROM public."AdminMfaCredential" WHERE "userId"='${ids.target}';
DELETE FROM public."AdminMfaCredential" WHERE "userId" IN ('${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."AdminWebAuthnCredential" WHERE "userId" IN ('${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."UserMfaFactor" WHERE "userId" IN ('${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."UserBackupCode" WHERE "userId" IN ('${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."AdminWebAuthnCredential" WHERE "userId"='${ids.target}';
DELETE FROM public."UserMfaFactor" WHERE "userId"='${ids.target}';
DELETE FROM public."UserBackupCode" WHERE "userId"='${ids.target}';
DELETE FROM public."RefreshToken" WHERE "userId"='${ids.target}';
DELETE FROM public."QRCode" WHERE code LIKE 'RLS-%' OR "batchId"='${ids.batch}';
DELETE FROM public."PrintItem" WHERE "printSessionId" IN (SELECT id FROM public."PrintSession" WHERE "batchId"='${ids.batch}');
DELETE FROM public."PrintSession" WHERE "batchId"='${ids.batch}';
DELETE FROM public."PrintJob" WHERE "batchId"='${ids.batch}';
DELETE FROM public."Batch" WHERE id='${ids.batch}' OR metadata->>'synthetic'='true';
DELETE FROM public."QRRange" WHERE "licenseeId" IN (SELECT id FROM public."Licensee" WHERE metadata->>'synthetic'='true');
DELETE FROM public."ManufacturerLicenseeLink" WHERE "manufacturerId" IN (SELECT id FROM public."User" WHERE metadata->>'synthetic'='true');
DELETE FROM public."User" WHERE id IN ('${ids.operator}','${ids.approver1}','${ids.approver2}','${ids.target}','${ids.tenantActor}') OR metadata->>'synthetic'='true';
DELETE FROM public."User" WHERE id IN ('${ids.diagnosticUnactivated}','${ids.diagnosticMfaIncomplete}','${ids.diagnosticMfaComplete}','${ids.diagnosticSuperseded}');
DELETE FROM public."Licensee" WHERE id IN ('${ids.licenseeA}','${ids.licenseeB}') OR metadata->>'synthetic'='true';
DELETE FROM public."Organization" WHERE id IN ('${ids.orgA}','${ids.orgB}','${ids.fixture}');

INSERT INTO public."Organization" (id,name,"isActive","updatedAt") VALUES
 ('${ids.orgA}','C04 Org A',true,transaction_timestamp()),('${ids.orgB}','C04 Org B',true,transaction_timestamp());
INSERT INTO public."Licensee" (id,"orgId",name,prefix,"isActive","updatedAt") VALUES
 ('${ids.licenseeA}','${ids.orgA}','C04 Licensee A','C4A',true,transaction_timestamp()),('${ids.licenseeB}','${ids.orgB}','C04 Licensee B','C4B',true,transaction_timestamp());
INSERT INTO public."User" (id,email,"passwordHash",name,role,"orgId","licenseeId",status,"isActive","emailVerifiedAt","updatedAt") VALUES
 ('${ids.operator}','operator-c04@example.invalid','hash','C04 Operator','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,transaction_timestamp(),transaction_timestamp()),
 ('${ids.approver1}','approver1-c04@example.invalid','hash','C04 Approver One','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,transaction_timestamp(),transaction_timestamp()),
 ('${ids.approver2}','approver2-c04@example.invalid','hash','C04 Approver Two','PLATFORM_SUPER_ADMIN',NULL,NULL,'ACTIVE',true,transaction_timestamp(),transaction_timestamp()),
 ('${ids.target}','target-c04@example.invalid','hash','C04 Target','SUPER_ADMIN',NULL,NULL,'ACTIVE',true,transaction_timestamp(),transaction_timestamp()),
 ('${ids.tenantActor}','tenant-c04@example.invalid','hash','C04 Tenant Actor','LICENSEE_ADMIN','${ids.orgB}','${ids.licenseeB}','ACTIVE',true,transaction_timestamp(),transaction_timestamp());
INSERT INTO public."Batch" (id,name,"licenseeId","startCode","endCode","totalCodes","lifecycleState","updatedAt") VALUES
 ('${ids.batch}','C04 Diagnostic Batch','${ids.licenseeA}','C04-1','C04-2',2,'CODES_GENERATED',transaction_timestamp());
INSERT INTO public."Invite" (id,"orgId",email,role,"tokenHash","expiresAt","createdByUserId") VALUES
 (gen_random_uuid()::text,'${ids.orgA}','target-c04@example.invalid','SUPER_ADMIN','c04-invite-hash',transaction_timestamp()+interval '1 hour','${ids.operator}');
INSERT INTO public."PasswordReset" (id,"userId","tokenHash","expiresAt") VALUES
 (gen_random_uuid()::text,'${ids.target}','c04-reset-hash',transaction_timestamp()+interval '1 hour');
INSERT INTO public."AdminMfaCredential" (id,"userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","updatedAt") VALUES
 (gen_random_uuid()::text,'${ids.target}','cipher','iv','tag',ARRAY['backup'],true,transaction_timestamp(),transaction_timestamp());
INSERT INTO public."AdminWebAuthnCredential" (id,"userId","credentialId","publicKeySpki","publicKeyAlgorithm",transports,"updatedAt") VALUES
 (gen_random_uuid()::text,'${ids.target}','c04-credential','public-key',-7,ARRAY['internal'],transaction_timestamp());
INSERT INTO public."UserMfaFactor" (id,"userId",type,transports,"updatedAt") VALUES
 (gen_random_uuid()::text,'${ids.target}','TOTP',ARRAY[]::text[],transaction_timestamp());
INSERT INTO public."UserBackupCode" (id,"userId","codeHash") VALUES (gen_random_uuid()::text,'${ids.target}','c04-backup-code');
INSERT INTO public."RefreshToken" (id,"userId","tokenHash","expiresAt") VALUES (gen_random_uuid()::text,'${ids.target}','c04-refresh-token',transaction_timestamp()+interval '1 day');
INSERT INTO public."SensitiveActionApproval" (id,"actionKey",status,"requestedByUserId","reviewedByUserId","entityType","entityId",payload,"expiresAt","reviewedAt","updatedAt") VALUES
 ('${ids.setupApproval}','OPERATOR_ACCOUNT_SETUP_LINK_REISSUE','APPROVED','${ids.operator}','${ids.approver1}','User','${ids.target}','{}',transaction_timestamp()+interval '1 hour',transaction_timestamp(),transaction_timestamp()),
 ('${ids.staleApproval}','OPERATOR_ACCOUNT_SETUP_LINK_REISSUE','APPROVED','${ids.operator}','${ids.approver1}','User','${ids.target}','{}',transaction_timestamp()-interval '1 minute',transaction_timestamp(),transaction_timestamp()),
 ('${ids.mfaApproval}','BREAK_GLASS_MFA_RESET','APPROVED','${ids.operator}','${ids.approver1}','User','${ids.target}',jsonb_build_object('executorId','${ids.operator}','approverIds',jsonb_build_array('${ids.approver1}','${ids.approver2}')),transaction_timestamp()+interval '1 hour',transaction_timestamp(),transaction_timestamp()),
 ('${ids.fixtureApproval}','STAGING_RLS_VALIDATION_FIXTURE','APPROVED','${ids.operator}','${ids.approver1}','Organization','${ids.fixture}','{}',transaction_timestamp()+interval '1 hour',transaction_timestamp(),transaction_timestamp());

INSERT INTO public."User" (id,email,"passwordHash",name,role,"orgId","licenseeId",status,"isActive","emailVerifiedAt","updatedAt") VALUES
 ('${ids.diagnosticUnactivated}','diagnostic-c04-unactivated@example.invalid',NULL,'Diagnostic Unactivated','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','INVITED',true,NULL,transaction_timestamp()),
 ('${ids.diagnosticMfaIncomplete}','diagnostic-c04-mfa-incomplete@example.invalid','configured','Diagnostic MFA Incomplete','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp(),transaction_timestamp()),
 ('${ids.diagnosticMfaComplete}','diagnostic-c04-mfa-complete@example.invalid','configured','Diagnostic MFA Complete','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp(),transaction_timestamp()),
 ('${ids.diagnosticSuperseded}','diagnostic-c04-superseded@example.invalid','configured','Diagnostic Superseded','LICENSEE_ADMIN','${ids.orgA}','${ids.licenseeA}','ACTIVE',true,transaction_timestamp(),transaction_timestamp());
INSERT INTO public."Invite" (id,"orgId","licenseeId",email,role,"tokenHash","expiresAt","usedAt","acceptedByUserId","createdAt") VALUES
 ('diagnostic-c04-no-account-invite','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-no-account@example.invalid','LICENSEE_ADMIN','diagnostic-c04-no-account-token',transaction_timestamp()-interval '1 day',NULL,NULL,transaction_timestamp()-interval '2 days'),
 ('diagnostic-c04-unactivated-invite','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-unactivated@example.invalid','LICENSEE_ADMIN','diagnostic-c04-unactivated-token',transaction_timestamp()-interval '1 day',NULL,NULL,transaction_timestamp()-interval '2 days'),
 ('diagnostic-c04-mfa-incomplete-invite','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-mfa-incomplete@example.invalid','LICENSEE_ADMIN','diagnostic-c04-mfa-incomplete-token',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '2 days','${ids.diagnosticMfaIncomplete}',transaction_timestamp()-interval '3 days'),
 ('diagnostic-c04-mfa-complete-invite','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-mfa-complete@example.invalid','LICENSEE_ADMIN','diagnostic-c04-mfa-complete-token',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '2 days','${ids.diagnosticMfaComplete}',transaction_timestamp()-interval '3 days'),
 ('diagnostic-c04-history-a','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-history@example.invalid','ORG_ADMIN','diagnostic-c04-history-token-a',transaction_timestamp()-interval '1 day',NULL,NULL,transaction_timestamp()-interval '2 days'),
 ('diagnostic-c04-history-b','${ids.orgB}','${ids.licenseeB}','diagnostic-c04-history@example.invalid','LICENSEE_ADMIN','diagnostic-c04-history-token-b',transaction_timestamp()-interval '1 day',NULL,NULL,transaction_timestamp()-interval '2 days'),
 ('diagnostic-c04-superseded-old','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-superseded@example.invalid','LICENSEE_ADMIN','diagnostic-c04-superseded-token-old',transaction_timestamp()-interval '1 day',NULL,NULL,transaction_timestamp()-interval '3 days'),
 ('diagnostic-c04-superseded-new','${ids.orgA}','${ids.licenseeA}','diagnostic-c04-superseded@example.invalid','LICENSEE_ADMIN','diagnostic-c04-superseded-token-new',transaction_timestamp()-interval '1 day',transaction_timestamp()-interval '1 day','${ids.diagnosticSuperseded}',transaction_timestamp()-interval '2 days');
INSERT INTO public."AdminMfaCredential" (id,"userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","updatedAt") VALUES
 ('diagnostic-c04-mfa-complete','${ids.diagnosticMfaComplete}','fixture-cipher','fixture-iv','fixture-tag',ARRAY['fixture-backup'],true,transaction_timestamp(),transaction_timestamp());
INSERT INTO public."AuditLog" (id,action,"entityType","entityId",details,"createdAt") VALUES
 ('diagnostic-c04-audit-accepted','AUTH_INVITE_ACCEPTED','Invite','diagnostic-c04-mfa-incomplete-invite','{}',transaction_timestamp());
INSERT INTO public."AuditLogOutbox" (id,payload,"updatedAt") VALUES
 ('diagnostic-c04-outbox-created',jsonb_build_object('action','AUTH_INVITE_CREATED','entityType','Invite','entityId','diagnostic-c04-no-account-invite'),transaction_timestamp()),
 ('diagnostic-c04-outbox-mfa',jsonb_build_object('action','AUTH_MFA_ENROLLED','entityType','User','entityId','${ids.diagnosticMfaComplete}'),transaction_timestamp());
`;

async function main() {
  if (!enabled) return console.log("Session C operator PostgreSQL 18 proof skipped");
  assert(confirmed, "Session C operator PostgreSQL proof confirmation is required");
  assert.equal(Math.floor(Number(psql("select current_setting('server_version_num')::int")) / 10000), 18);
  psqlFile(path.resolve(__dirname, "../../../src/rls-waves/session-c/c04/operatorProcedures.sql"));
  psqlFile(path.resolve(__dirname, "../../../src/rls-waves/session-c/c04/accountOnboardingDiagnostic.sql"));
  psql(setupSql);
  psql(fixtureSql);

  const operator = new PrismaClient({ datasources: { db: { url: roleUrl("mscqr_rls_wave_c_operator") } } });
  const breakglass = new PrismaClient({ datasources: { db: { url: roleUrl("mscqr_rls_wave_c_breakglass") } } });
  const migration = new PrismaClient({ datasources: { db: { url: roleUrl("mscqr_rls_wave_c_migration") } } });
  const unrelated = new PrismaClient({ datasources: { db: { url: roleUrl("mscqr_rls_wave_c_unrelated") } } });
  const procedures = require("../../../dist/rls-waves/session-c/operatorProcedureService");
  const bootstrap = require("../../../dist/services/auth/superAdminBootstrapService");
  try {
    const accountDiagnosticInput = (normalizedEmail, requestId) => ({
      normalizedEmail, operatorId: ids.operator,
      purpose: "operator-account-onboarding-diagnostic", assurance: "operator-approved", environment: "production", requestId,
    });
    const diagnosticBefore = psql(`SELECT concat_ws('|',(SELECT count(*) FROM public."User"),(SELECT count(*) FROM public."Invite"),(SELECT count(*) FROM public."AdminMfaCredential"),(SELECT count(*) FROM public."AuditLog"),(SELECT count(*) FROM public."AuditLogOutbox"))`);
    const noAccount = await procedures.diagnoseAccountOnboarding(accountDiagnosticInput("diagnostic-c04-no-account@example.invalid", "00000000-0000-4400-8000-000000000201"), operator);
    const unactivated = await procedures.diagnoseAccountOnboarding(accountDiagnosticInput("diagnostic-c04-unactivated@example.invalid", "00000000-0000-4400-8000-000000000202"), operator);
    const mfaIncomplete = await procedures.diagnoseAccountOnboarding(accountDiagnosticInput("diagnostic-c04-mfa-incomplete@example.invalid", "00000000-0000-4400-8000-000000000203"), operator);
    const mfaComplete = await procedures.diagnoseAccountOnboarding(accountDiagnosticInput("diagnostic-c04-mfa-complete@example.invalid", "00000000-0000-4400-8000-000000000204"), operator);
    const history = await procedures.diagnoseAccountOnboarding(accountDiagnosticInput("diagnostic-c04-history@example.invalid", "00000000-0000-4400-8000-000000000205"), operator);
    const superseded = await procedures.diagnoseAccountOnboarding(accountDiagnosticInput("diagnostic-c04-superseded@example.invalid", "00000000-0000-4400-8000-000000000206"), operator);
    assert.equal(noAccount.stateClassification, "A_EXPIRED_UNUSED_INVITE_NO_ACCOUNT");
    assert.equal(noAccount.accountExists, false);
    assert.equal(noAccount.inviteCreatedPresent, true);
    assert.equal(unactivated.stateClassification, "B_EXPIRED_UNUSED_INVITE_EXISTING_UNACTIVATED_ACCOUNT");
    assert.equal(unactivated.passwordConfigured, false);
    assert.equal(mfaIncomplete.stateClassification, "C_ACTIVATED_ACCOUNT_MFA_INCOMPLETE");
    assert.equal(mfaIncomplete.mfaConfigured, false);
    assert.equal(mfaIncomplete.inviteAcceptedPresent, true);
    assert.equal(mfaComplete.stateClassification, "D_ACTIVATED_ACCOUNT_MFA_COMPLETE");
    assert.equal(mfaComplete.mfaConfigured, true);
    assert.equal(mfaComplete.mfaEnrolledPresent, true);
    assert.equal(history.inviteCount, 2);
    assert.equal(history.latestRole, "LICENSEE_ADMIN");
    assert.deepEqual(history.latestTenantBinding, { organizationId: ids.orgB, licenseeId: ids.licenseeB });
    assert.equal(superseded.inviteCount, 2);
    assert.equal(superseded.stateClassification, "C_ACTIVATED_ACCOUNT_MFA_INCOMPLETE");
    assert.equal(typeof mfaIncomplete.passwordConfigured, "boolean");
    assert.equal(typeof mfaComplete.mfaConfigured, "boolean");
    assert.deepEqual(Object.keys(mfaComplete).sort(), ["accountActive","accountEmailVerified","accountExists","accountRole","accountStatus","accountTenantBinding","inviteAcceptedPresent","inviteCount","inviteCreatedPresent","latestAcceptedByPresent","latestCreatedAt","latestExpired","latestExpiresAt","latestRole","latestTenantBinding","latestUsedAt","mfaConfigured","mfaEnrolledPresent","passwordConfigured","stateClassification"].sort());
    assert.equal(psql(`SELECT has_function_privilege(0::oid,'app_ops.diagnose_account_onboarding(text)'::regprocedure,'EXECUTE')::text`), "false");
    assert.equal(psql(`SELECT has_function_privilege('mscqr_rls_wave_c_operator','app_ops.diagnose_account_onboarding(text)','EXECUTE')::text`), "true");
    await assert.rejects(() => unrelated.$queryRawUnsafe("SELECT * FROM app_ops.diagnose_account_onboarding('diagnostic-c04-no-account@example.invalid')"), /permission denied/i);
    await assert.rejects(() => procedures.diagnoseAccountOnboarding(accountDiagnosticInput("x@example.invalid' OR '1'='1", "00000000-0000-4400-8000-000000000207"), operator), /normalizedEmail must be a valid email address/);
    await assert.rejects(() => procedures.diagnoseAccountOnboarding(accountDiagnosticInput("not-an-email", "00000000-0000-4400-8000-000000000208"), operator), /normalizedEmail must be a valid email address/);
    assert.equal(psql(`SELECT concat_ws('|',(SELECT count(*) FROM public."User"),(SELECT count(*) FROM public."Invite"),(SELECT count(*) FROM public."AdminMfaCredential"),(SELECT count(*) FROM public."AuditLog"),(SELECT count(*) FROM public."AuditLogOutbox"))`), diagnosticBefore);

    const diagnosticInput = {
      batchId: ids.batch, operatorId: ids.operator, licenseeId: ids.licenseeA,
      purpose: "operator-print-diagnostic", assurance: "operator-approved", environment: "staging",
      requestId: "00000000-0000-4400-8000-000000000101",
    };
    const diagnostic = await procedures.runPrintDiagnostic(diagnosticInput, operator);
    const diagnosticReplay = await procedures.runPrintDiagnostic(diagnosticInput, operator);
    assert.equal(diagnostic.batchId, ids.batch);
    assert.deepEqual(diagnosticReplay, diagnostic);

    await assert.rejects(() => procedures.runPrintDiagnostic({ ...diagnosticInput, operatorId: ids.tenantActor, licenseeId: ids.licenseeB, requestId: "00000000-0000-4400-8000-000000000102" }, operator), /FOREIGN_SCOPE/);
    await assert.rejects(() => procedures.runPrintDiagnostic({ ...diagnosticInput, assurance: "system-verified", requestId: "00000000-0000-4400-8000-000000000103" }, operator), /INVALID_CONTEXT/);
    await assert.rejects(() => operator.$queryRawUnsafe('SELECT email FROM public."User" LIMIT 1'), /permission denied/i);

    const reissueInput = {
      targetUserId: ids.target, operatorId: ids.operator, approvalId: ids.setupApproval, reason: "Approved account recovery for C04 proof",
      purpose: "operator-account-setup-link-reissue", assurance: "operator-approved", environment: "staging",
      requestId: "00000000-0000-4400-8000-000000000104",
    };
    const reissue = await procedures.reissueAccountSetupLink(reissueInput, operator);
    psql(`UPDATE public."SensitiveActionApproval" SET "expiresAt"=transaction_timestamp()-interval '1 minute' WHERE id='${ids.setupApproval}'`);
    const reissueReplay = await procedures.reissueAccountSetupLink({ ...reissueInput, requestId: "00000000-0000-4400-8000-000000000105" }, operator);
    assert.equal(reissue.deliveryQueued, true);
    assert.equal(reissueReplay.auditEventId, reissue.auditEventId);
    await assert.rejects(() => procedures.reissueAccountSetupLink({ ...reissueInput, approvalId: ids.staleApproval, requestId: "00000000-0000-4400-8000-000000000106" }, operator), /MISSING_STALE_OR_FOREIGN_APPROVAL/);

    const mfaInput = {
      targetUserId: ids.target, executorId: ids.operator, approvalId: ids.mfaApproval, reason: "Confirmed security incident requires MFA reset",
      purpose: "dual-approved-break-glass-mfa-reset", assurance: "dual-approved-break-glass", environment: "production",
      requestId: "00000000-0000-4400-8000-000000000107",
    };
    const mfa = await procedures.resetAccountMfaBreakGlass(mfaInput, breakglass);
    psql(`UPDATE public."SensitiveActionApproval" SET "expiresAt"=transaction_timestamp()-interval '1 minute' WHERE id='${ids.mfaApproval}'`);
    const mfaReplay = await procedures.resetAccountMfaBreakGlass({ ...mfaInput, requestId: "00000000-0000-4400-8000-000000000108" }, breakglass);
    assert.equal(mfa.status, "completed");
    assert.equal(mfaReplay.auditEventId, mfa.auditEventId);
    assert.equal(psql(`SELECT concat_ws('|',(SELECT "isEnabled" FROM public."AdminMfaCredential" WHERE "userId"='${ids.target}'),(SELECT count(*) FROM public."AdminWebAuthnCredential" WHERE "userId"='${ids.target}'),(SELECT count(*) FROM public."UserBackupCode" WHERE "userId"='${ids.target}'),(SELECT count(*) FROM public."RefreshToken" WHERE "userId"='${ids.target}' AND "revokedAt" IS NOT NULL))`), "f|0|0|1");

    const fixtureInput = {
      fixtureId: ids.fixture, tenantKey: "mscqr_staging_rls_validation", approvalId: ids.fixtureApproval, operatorId: ids.operator,
      purpose: "operator-staging-rls-validation-fixture", assurance: "operator-approved", environment: "staging",
      requestId: "00000000-0000-4400-8000-000000000109",
    };
    const fixture = await procedures.prepareRlsValidationFixture(fixtureInput, operator);
    psql(`UPDATE public."SensitiveActionApproval" SET "expiresAt"=transaction_timestamp()-interval '1 minute' WHERE id='${ids.fixtureApproval}'`);
    const fixtureReplay = await procedures.prepareRlsValidationFixture({ ...fixtureInput, requestId: "00000000-0000-4400-8000-000000000110" }, operator);
    assert.equal(fixture.affectedCount, 12);
    assert.equal(fixtureReplay.auditEventId, fixture.auditEventId);

    process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED = "true";
    process.env.SUPER_ADMIN_EMAIL = "migration-bootstrap-c04@example.invalid";
    process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD = "Correct horse battery staple 4400";
    process.env.NODE_ENV = "staging";
    const blockedStartup = await bootstrap.bootstrapConfiguredSuperAdmin();
    assert.equal(blockedStartup.status, "blocked");
    const migrationResult = await bootstrap.bootstrapConfiguredSuperAdmin(migration);
    assert.equal(migrationResult.status, "skipped_existing");
    await assert.rejects(() => operator.$queryRawUnsafe("SELECT * FROM app_ops.bootstrap_configured_super_admin('x','y','z',false)"), /permission denied/i);

    const [auditCount,outboxCount,forcedCount,directGrants] = psql(`SELECT concat_ws('|',(SELECT count(*) FROM public."AuditLog" WHERE action IN ('OPERATOR_PRINT_DIAGNOSTIC','OPERATOR_ACCOUNT_SETUP_LINK_REISSUED','AUTH_MFA_BREAK_GLASS_RESET','STAGING_RLS_VALIDATION_FIXTURE_PREPARED','AUTH_SUPER_ADMIN_BOOTSTRAP_SKIPPED_EXISTING')),(SELECT count(*) FROM public."SecurityEventOutbox" WHERE "eventType"='OPERATOR_PROCEDURE_AUDIT'),(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=ANY(ARRAY['User','Organization','Licensee','ManufacturerLicenseeLink','QRRange','Batch','QRCode','PrintJob','PrintSession','PrintItem','Invite','PasswordReset','RefreshToken','AdminMfaCredential','AdminWebAuthnCredential','UserMfaFactor','UserBackupCode','SensitiveActionApproval','ActionIdempotencyKey','AuditLog','SecurityEventOutbox']) AND c.relrowsecurity AND c.relforcerowsecurity),(SELECT count(*) FROM information_schema.role_table_grants WHERE grantee IN ('mscqr_rls_wave_c_operator','mscqr_rls_wave_c_breakglass','mscqr_rls_wave_c_migration') AND table_schema='public'))`).split("|");
    assert.equal(Number(auditCount), 5);
    assert.equal(Number(outboxCount), 5);
    assert.equal(Number(forcedCount), 21);
    assert.equal(Number(directGrants), 0);
    console.log("Session C operator PostgreSQL 18 application-path proof passed");
  } finally {
    await Promise.all([operator.$disconnect(),breakglass.$disconnect(),migration.$disconnect(),unrelated.$disconnect()]);
  }
}

main().catch((error) => { console.error(error); process.exit(1); });
