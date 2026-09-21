const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const backend = path.resolve(__dirname, "../../..");
const sql = fs.readFileSync(path.join(backend, "src/rls-waves/session-c/c04/accountOnboardingDiagnostic.sql"), "utf8");
const generator = fs.readFileSync(path.join(backend, "../scripts/rls/generate-clean-room-rls-sql.mjs"), "utf8");
const service = fs.readFileSync(path.join(backend, "src/rls-waves/session-c/operatorProcedureService.ts"), "utf8");
const start = sql.indexOf("CREATE OR REPLACE FUNCTION app_ops.diagnose_account_onboarding");
const end = sql.indexOf("REVOKE ALL ON FUNCTION app_ops.diagnose_account_onboarding", start);
assert(start >= 0 && end > start, "onboarding diagnostic must be a distinct fixed operator function");
const diagnostic = sql.slice(start, end);
const returnContract = diagnostic.slice(diagnostic.indexOf("RETURNS TABLE"), diagnostic.indexOf("LANGUAGE plpgsql"));

for (const field of [
  "invite_count", "latest_created_at", "latest_expires_at", "latest_used_at", "latest_expired", "latest_role", "latest_tenant_binding", "latest_accepted_by_present",
  "account_exists", "account_status", "account_active", "account_email_verified", "password_configured", "account_role", "account_tenant_binding", "mfa_configured",
  "invite_created_present", "invite_accepted_present", "mfa_enrolled_present", "state_classification",
]) assert(diagnostic.includes(field), `missing bounded result field ${field}`);

for (const forbidden of ["passwordHash", "tokenHash", "secretCiphertext", "secretIv", "secretTag", "backupCodesHash", "recovery", "jwt", "sessionCapabilityHash"]) {
  assert(!returnContract.includes(forbidden), `diagnostic must not expose ${forbidden}`);
}

assert.match(diagnostic, /SECURITY DEFINER/);
assert.match(diagnostic, /SET search_path = pg_catalog, public/);
assert.match(diagnostic, /SESSION_C04_INVALID_NORMALIZED_EMAIL/);
assert.match(diagnostic, /SESSION_C04_PLATFORM_ACTOR_REQUIRED/);
assert.match(sql, /current_setting\('app\.request_id', true\) IS NULL\s+OR current_setting\('app\.request_id', true\) !~\*/);
assert.match(diagnostic, /SELECT count\(\*\) INTO target_count FROM public\."User" u WHERE lower\(u\.email\)=normalized_email/);
assert.match(diagnostic, /SESSION_C04_AMBIGUOUS_NORMALIZED_EMAIL/);
assert(diagnostic.includes("[\\x20-\\x21\\x23-\\x5B\\x5D-\\x7E]|\\\\[\\x20-\\x7E]"), "quoted local parts must use the canonical escaped-printable grammar");
assert.match(diagnostic, /target_unactivated := target_is_active AND target_status='INVITED' AND target_disabled_at IS NULL AND target_deleted_at IS NULL AND target_password_hash IS NULL/);
assert(!/target_exists AND NOT target_active AND latest_exists/.test(diagnostic), "disabled or deleted accounts must not be reported as unactivated");
assert.equal((diagnostic.match(/lower\(i\.email\)=normalized_email/g) || []).length, 7, "all invite selectors must use canonical matching");
assert.match(diagnostic, /AUTH_MFA_ENROLLED','AUTH_WEBAUTHN_ENROLLED/);
assert.match(diagnostic, /observed_at timestamp without time zone := clock_timestamp\(\)/);
assert.equal((diagnostic.match(/clock_timestamp\(\)/g) || []).length, 1, "invite expiry must use one observation time");
assert.match(diagnostic, /ORDER BY i\."createdAt" DESC,i\.id DESC/);
assert.match(diagnostic, /'A_EXPIRED_UNUSED_INVITE_NO_ACCOUNT'/);
assert.match(diagnostic, /'B_EXPIRED_UNUSED_INVITE_EXISTING_UNACTIVATED_ACCOUNT'/);
assert.match(diagnostic, /'C_ACTIVATED_ACCOUNT_MFA_INCOMPLETE'/);
assert.match(diagnostic, /'D_ACTIVATED_ACCOUNT_MFA_COMPLETE'/);
assert(!/\b(INSERT|UPDATE|DELETE)\b/.test(diagnostic), "diagnostic function must not mutate application state");
assert.match(sql, /REVOKE ALL ON FUNCTION app_ops\.diagnose_account_onboarding\(text\) FROM PUBLIC/);
assert.match(generator, /GRANT USAGE ON SCHEMA app_ops TO \$\{q\(roleNames\.operator\)\}/);
assert.match(generator, /GRANT EXECUTE ON FUNCTION \$\{signature\} TO \$\{q\(roleNames\.operator\)\}/);
assert.match(service, /normalizeEmailAddress\(input\.normalizedEmail\)/);
assert.match(service, /SET TRANSACTION READ ONLY/);
assert.match(service, /app_ops\.diagnose_account_onboarding\(\$\{normalizedEmail\}::text\)/);
assert(!service.includes("$queryRawUnsafe"), "diagnostic invocation must remain parameterized");

console.log("account onboarding diagnostic contract tests passed");
