import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { renderVictoriaRecoverySql } from "../security/victoria-recovery-sql.mjs";
import { renderVictoriaRecoveryInstallationSql } from "../security/victoria-recovery-installation.mjs";

const generatedPath = "backend/src/rls-waves/session-c/c05/victoriaRecovery.sql";

test("generated recovery SQL is exactly reproducible from the complete dependency manifest", () => {
  assert.equal(fs.readFileSync(generatedPath, "utf8"), renderVictoriaRecoverySql());
});

test("database operation is target-fixed, argument-free, static SQL, and preserves forced RLS", () => {
  const sql = fs.readFileSync(generatedPath, "utf8");
  assert.match(sql, /victoria@mscqr\.com/);
  assert.match(sql, /mscqr_production/);
  assert.match(sql, /SECURITY DEFINER/);
  assert.match(sql, /SET row_security = on/);
  assert.match(sql, /SET search_path = pg_catalog, public/);
  assert.doesNotMatch(sql, /\bEXECUTE\s+format\b|\bEXECUTE\s+immediate\b|\bSET\s+row_security\s*=\s*off\b|\bBYPASSRLS\b|\bSELECT\s+\*/i);
  assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\('platform:' \|\| target_email, 0\)\)/);
  assert.match(sql, /set_config\('app\.victoria_recovery_user_id'/);
  assert.match(sql, /set_config\('app\.victoria_recovery_invite_ids'/);
  assert.match(sql, /ALTER FUNCTION app_ops\.victoria_failed_onboarding_recovery_v1\(\) OWNER TO \{\{AUTH_OWNER\}\}/);
  assert.match(sql, /REVOKE ALL ON FUNCTION app_ops\.victoria_failed_onboarding_recovery_v1\(\) FROM PUBLIC/);
  assert.match(sql, /pg_catalog\.pg_constraint/);
  assert.match(sql, /FORCED_RLS_STATE_INVALID/);
  assert.match(sql, /relrowsecurity AND c\.relforcerowsecurity/);
  assert.match(sql, /cardinality\(c\.conkey\)=1 AND cardinality\(c\.confkey\)=1/);
  assert.match(sql, /SCHEMA_DEPENDENCY_DRIFT/);
  assert.match(sql, /OR active_sessions OR refresh_state OR activated OR mfa_credential/);
  assert.match(sql, /AUTHENTICATION_SECURITY[\s\S]+?removable' IS DISTINCT FROM 'true'/);
  assert.match(sql, /p\."usedAt" IS NOT NULL OR p\."expiresAt">transaction_timestamp\(\)/);
  assert.match(sql, /t\."usedAt" IS NOT NULL OR t\."expiresAt">transaction_timestamp\(\)/);
  assert.match(sql, /'MfaLoginChallenge'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count\(\*\)::integer AS row_count, false::boolean AS removable/);
  assert.match(sql, /'AuthSessionRiskSignal'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count\(\*\)::integer AS row_count, false::boolean AS removable/);
});

test("installation is limited to the fixed login, function, and manifest-scoped policies", () => {
  const sql = renderVictoriaRecoveryInstallationSql();
  assert.match(sql, /mscqr_prod_victoria_recovery/);
  assert.match(sql, /GRANT rds_iam TO/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION app_ops\.victoria_failed_onboarding_recovery_v1\(\)/);
  assert.match(sql, /GRANT "mscqr_prod_victoria_recovery_owner" TO CURRENT_USER WITH SET TRUE, INHERIT FALSE/);
  assert.match(sql, /^-- ACTIVE database only[\s\S]*?\nBEGIN;/);
  assert.match(sql, /REVOKE CREATE ON SCHEMA app_ops[\s\S]*REVOKE "mscqr_prod_victoria_recovery_owner" FROM CURRENT_USER;\n\nCOMMIT;\n$/);
  assert.doesNotMatch(sql, /GRANT\s+(?:SELECT|DELETE)\s+ON\s+ALL\s+TABLES|\bBYPASSRLS\b|\bSUPERUSER\b|row_security\s*=\s*off/i);
  assert.ok(sql.includes('"User"'));
  assert.ok(sql.includes('"Invite"'));
  assert.ok(sql.includes("current_setting('app.victoria_recovery_target_email',true)='victoria@mscqr.com'"));
  assert.match(sql, /GRANT SELECT \("action","details","entityId","id","userId"\) ON public\."AuditLog"/);
  assert.match(sql, /GRANT SELECT \("id","initiatingUserId","payload"\) ON public\."AuditLogOutbox"/);
});

test("runtime gate rejects activation/security/business state and deletes only locked identifiers", () => {
  const sql = fs.readFileSync(generatedPath, "utf8");
  assert.match(sql, /user_status<>'INVITED'/);
  assert.match(sql, /email_verified OR disabled OR deleted/);
  assert.match(sql, /active_sessions OR refresh_state OR activated OR mfa_credential/);
  assert.match(sql, /blockers>0 OR hard_blockers>0 OR unknown_dependencies>0/);
  assert.match(sql, /"acceptedByUserId" IS DISTINCT FROM user_id/);
  assert.match(sql, /p\."usedAt" IS NOT NULL OR p\."expiresAt">transaction_timestamp\(\)/);
  assert.match(sql, /t\."usedAt" IS NOT NULL OR t\."expiresAt">transaction_timestamp\(\)/);
  assert.match(sql, /DELETE FROM public\."Invite" i WHERE i\.id=ANY\(invite_ids\)/);
  assert.match(sql, /DELETE FROM public\."User" u WHERE u\.id=user_id AND lower\(btrim\(u\.email\)\)=target_email/);
  assert.match(sql, /VICTORIA_RECOVERY_USER_COMPARE_AND_SET_FAILED/);
  assert.match(sql, /HISTORICAL_ACTIVATION_UNVERIFIABLE/);
  assert.match(sql, /'successfulActivationNotFound',false,'pruneSafe',false,'pruneComplete',false/);
  assert.match(sql, /VICTORIA_RECOVERY_POSTCONDITION_FAILED/);
  assert.match(sql, /VICTORIA_RECOVERY_AUDIT_PRESERVATION_FAILED/);
  assert.match(sql, /'validUnusedInviteBefore',valid_unused_invite/);
  assert.match(sql, /'deletedRows',jsonb_build_object/);
  assert.doesNotMatch(sql, /"passwordHash"|"tokenHash"|"codeHash"|"secretCiphertext"/i);
});
