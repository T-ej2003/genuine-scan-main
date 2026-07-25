import assert from "node:assert/strict";

// A function contract is deliberately separate from a workflow delegation. It
// records the database authority that a repository call contributes to its
// canonical workflow. A disposable fixture can prove a function's local
// behavior, but cannot establish production table authority by itself.
const refreshFixture = "backend/tests/rls-wave-b/b01/refreshSessionPostgres18.fixture.sql";

export const NAMED_SQL_FUNCTION_DEFINITION_EVIDENCE = Object.freeze([
  {
    schema: "app_auth",
    name: "claim_refresh_token_rotation",
    signature: "text[],timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "load_refresh_session_state",
    signature: "text,text[],text,text,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "create_refresh_mfa_challenge",
    signature: "text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "revoke_refresh_token_scope",
    signature: "text,text[],text,text,text,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
  {
    schema: "app_auth",
    name: "complete_refresh_token_rotation",
    signature: "text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text",
    definitionLocation: refreshFixture,
    definitionStatus: "fixture-only-non-production",
  },
]);

const b01Source = "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql";
const b01Rollback = "backend/src/rls-waves/session-b/b01/b01RefreshRotationRollback.sql";
const authenticatedSessionSource = "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql";
const authenticatedSessionRollback = "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityRollback.sql";
const authenticationClosureSource = "backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql";
const authenticationClosureRollback = "backend/src/rls-waves/session-b/b01/b01AuthenticationClosureRollback.sql";
const preAuthSource = "backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql";
const preAuthRollback = "backend/src/rls-waves/session-b/b01/b01PreAuthSecurityRollback.sql";
const c03Source = "backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql";
const c03Rollback = "backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundariesRollback.sql";
const c03PolicySource = "backend/src/rls-waves/session-c/c03/c03Policy.sql";
const c03PolicyRollback = "backend/src/rls-waves/session-c/c03/c03PolicyRollback.sql";
const c03GovernanceSource = "backend/src/rls-waves/session-c/c03/c03GovernanceFunctions.sql";
const c03GovernanceRollback = "backend/src/rls-waves/session-c/c03/c03GovernanceRollback.sql";
const c03ApprovalSource = "backend/src/rls-waves/session-c/c03/c03ApprovalFunctions.sql";
const c03ApprovalRollback = "backend/src/rls-waves/session-c/c03/c03ApprovalRollback.sql";
const c03IncidentSource = "backend/src/rls-waves/session-c/c03/c03IncidentFunctions.sql";
const c03IncidentRollback = "backend/src/rls-waves/session-c/c03/c03IncidentRollback.sql";
const c02AuditTraceSource = "backend/src/rls-waves/session-c/c02/auditTrace.sql";
const c02AuditTraceRollback = "backend/src/rls-waves/session-c/c02/auditTraceRollback.sql";
const riskAnalyticsSource = "backend/src/rls-waves/session-c/c02/riskAnalytics.sql";
const riskAnalyticsRollback = "backend/src/rls-waves/session-c/c02/riskAnalyticsRollback.sql";
const scheduledSource = "backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql";
const scheduledRollback = "backend/src/rls-waves/session-b/b03/scheduledJobIdentityRollback.sql";
const outboxSource = "backend/src/rls-waves/session-b/b03/b03OutboxFunctions.sql";
const outboxRollback = "backend/src/rls-waves/session-b/b03/b03OutboxRollback.sql";
const b03AuthenticatedSource = "backend/src/rls-waves/session-b/b03/b03AuthenticatedFunctions.sql";
const b03AuthenticatedRollback = "backend/src/rls-waves/session-b/b03/b03AuthenticatedRollback.sql";
const operationalReadSource = "backend/src/rls-waves/session-a/operationalReadBoundaries.sql";
const operationalReadRollback = "backend/src/rls-waves/session-a/operationalReadBoundariesRollback.sql";
const administrationSource = "backend/src/rls-waves/session-c/c01/administration.sql";
const administrationRollback = "backend/src/rls-waves/session-c/c01/administrationRollback.sql";
const qrSystemSource = "backend/src/rls-waves/session-c/c01/qrSystem.sql";
const qrSystemRollback = "backend/src/rls-waves/session-c/c01/qrSystemRollback.sql";
const printingLifecycleSource = "backend/src/rls-waves/session-c/c02/printingLifecycle.sql";
const printingLifecycleRollback = "backend/src/rls-waves/session-c/c02/printingLifecycleRollback.sql";
const publicVerificationSource = "backend/src/rls-waves/session-b/b02/publicVerificationFunctions.sql";
const publicVerificationRollback = "backend/src/rls-waves/session-b/b02/publicVerificationRollback.sql";
const b01Workflow = "workflow-internal-backend-src-services-auth-auth-service-ts-refresh-session";
const b01Context = "SECURITY DEFINER sets transaction-local B01 bearer-hash scope before the first RefreshToken read, then derives every user, tenant, manufacturer and MFA scope from the locked predecessor row. Caller app.* settings are never read as authority.";
const b01Security = Object.freeze({
  mode: "SECURITY DEFINER",
  ownerIdentity: "identity-auth-function-owner",
  ownerRole: "authOwner",
  searchPath: "pg_catalog,public",
  publicExecute: "revoked",
  runtimeExecuteGrantees: ["preauth"],
  functionSource: b01Source,
  rollbackDefinition: b01Rollback,
  deploymentPhase: "session-b-b01",
});
const b01Tables = Object.freeze({
  claim: [
    ["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"],
    ["ManufacturerLicenseeLink", "SELECT"], ["Licensee", "SELECT"], ["Organization", "SELECT"],
    ["AuditLogOutbox", "INSERT"],
  ],
  state: [
    ["RefreshToken", "SELECT"], ["User", "SELECT"], ["ManufacturerLicenseeLink", "SELECT"],
    ["Licensee", "SELECT"], ["Organization", "SELECT"], ["AdminMfaCredential", "SELECT"],
    ["AdminWebAuthnCredential", "SELECT"], ["UserMfaFactor", "SELECT"], ["UserBackupCode", "SELECT"],
    ["AuditLogOutbox", "INSERT"],
  ],
  challenge: [["RefreshToken", "SELECT"], ["User", "SELECT"], ["AuthMfaChallenge", "INSERT"], ["AuditLogOutbox", "INSERT"]],
  revoke: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"], ["AuditLogOutbox", "INSERT"]],
  complete: [["RefreshToken", "SELECT"], ["RefreshToken", "INSERT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"], ["ManufacturerLicenseeLink", "SELECT"], ["Licensee", "SELECT"], ["Organization", "SELECT"], ["AuditLogOutbox", "INSERT"]],
});

const preAuthOwner = `current_user={{AUTH_OWNER}}`;
const preAuthOperation = `current_setting('app.b01_preauth_operation',true)`;
const preAuthUserId = `current_setting('app.b01_preauth_user_id',true)`;
const preAuthTokenId = `current_setting('app.b01_preauth_token_id',true)`;
const preAuthHashes = `string_to_array(current_setting('app.b01_preauth_hashes',true),',')`;
const preAuthSecurity = Object.freeze({
  ...b01Security,
  functionSource: preAuthSource,
  rollbackDefinition: preAuthRollback,
  deploymentPhase: "session-b-b01-preauth",
  ownerPrivileges: [
    ["User", "SELECT", ["id","email","pendingEmail","passwordHash","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt","failedLoginAttempts","lockedUntil","lastLoginAt","emailVerifiedAt","pendingEmailRequestedAt"]],
    ["User", "UPDATE", ["email","pendingEmail","pendingEmailRequestedAt","passwordHash","name","status","failedLoginAttempts","lockedUntil","emailVerifiedAt","updatedAt"]],
    ["Invite", "SELECT", ["id","orgId","licenseeId","email","role","manufacturerId","tokenHash","expiresAt","usedAt"]],
    ["Invite", "UPDATE", ["usedAt","acceptedByUserId"]],
    ["PasswordReset", "SELECT", ["id","orgId","userId","tokenHash","expiresAt","usedAt"]],
    ["PasswordReset", "INSERT", ["id","orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","userAgentHash"]],
    ["PasswordReset", "UPDATE", ["usedAt"]],
    ["EmailVerificationToken", "SELECT", ["id","userId","email","pendingEmail","purpose","tokenHash","expiresAt","usedAt"]],
    ["EmailVerificationToken", "UPDATE", ["usedAt"]],
    ["RefreshToken", "SELECT", ["id","userId","revokedAt","sessionCapabilityRevokedAt"]],
    ["RefreshToken", "UPDATE", ["revokedAt","revokedReason","lastUsedAt","sessionCapabilityRevokedAt","sessionCapabilityRevokedReason"]],
    ["Licensee", "SELECT", ["id","orgId","name","isActive","suspendedAt"]],
    ["Organization", "SELECT", ["id","isActive"]],
    ["AuditLogOutbox", "INSERT", ["id","payload","updatedAt"]],
  ],
  ownerPolicies: [
    ["User", "SELECT", `(${preAuthOwner} AND ((${preAuthOperation} IN ('password-lookup','password-failure','reset-request','invite-lookup','invite-consume') AND lower(email)=current_setting('app.b01_preauth_email',true)) OR (${preAuthUserId}<>'' AND id=${preAuthUserId}) OR (${preAuthOperation}='email-consume' AND current_setting('app.b01_preauth_pending_email',true)<>'' AND lower(email)=current_setting('app.b01_preauth_pending_email',true))))`],
    ["User", "UPDATE", `(${preAuthOwner} AND ((${preAuthOperation}='password-failure' AND lower(email)=current_setting('app.b01_preauth_email',true)) OR (${preAuthOperation} IN ('reset-consume','invite-consume','email-consume') AND ${preAuthUserId}<>'' AND id=${preAuthUserId})))`],
    ["Invite", "SELECT", `(${preAuthOwner} AND ${preAuthOperation} IN ('invite-lookup','invite-consume') AND "tokenHash"=ANY(${preAuthHashes}))`],
    ["Invite", "UPDATE", `(${preAuthOwner} AND ${preAuthOperation}='invite-consume' AND id=${preAuthTokenId} AND "tokenHash"=ANY(${preAuthHashes}))`],
    ["PasswordReset", "SELECT", `(${preAuthOwner} AND ${preAuthOperation}='reset-consume' AND "tokenHash"=ANY(${preAuthHashes}))`],
    ["PasswordReset", "INSERT", `(${preAuthOwner} AND ${preAuthOperation}='reset-request' AND "userId"=${preAuthUserId} AND "tokenHash"=ANY(${preAuthHashes}))`],
    ["PasswordReset", "UPDATE", `(${preAuthOwner} AND ${preAuthOperation}='reset-consume' AND id=${preAuthTokenId} AND "userId"=${preAuthUserId})`],
    ["EmailVerificationToken", "SELECT", `(${preAuthOwner} AND ${preAuthOperation}='email-consume' AND "tokenHash"=ANY(${preAuthHashes}))`],
    ["EmailVerificationToken", "UPDATE", `(${preAuthOwner} AND ${preAuthOperation}='email-consume' AND id=${preAuthTokenId} AND "userId"=${preAuthUserId})`],
    ["RefreshToken", "SELECT", `(${preAuthOwner} AND ${preAuthOperation} IN ('reset-consume','email-consume') AND "userId"=${preAuthUserId})`],
    ["RefreshToken", "UPDATE", `(${preAuthOwner} AND ${preAuthOperation} IN ('reset-consume','email-consume') AND "userId"=${preAuthUserId})`],
    ["Licensee", "SELECT", `(${preAuthOwner} AND ${preAuthOperation} IN ('invite-lookup','invite-consume') AND id=current_setting('app.b01_preauth_licensee_id',true) AND "orgId"=current_setting('app.b01_preauth_org_id',true))`],
    ["Organization", "SELECT", `(${preAuthOwner} AND ${preAuthOperation} IN ('invite-lookup','invite-consume') AND id=current_setting('app.b01_preauth_org_id',true))`],
    ["AuditLogOutbox", "INSERT", `(${preAuthOwner} AND ${preAuthUserId}<>'' AND payload->>'userId'=${preAuthUserId} AND payload->>'action' IN ('AUTH_LOGIN_FAIL','AUTH_LOGIN_LOCKED','AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_EMAIL_VERIFIED','AUTH_EMAIL_CHANGE_CONFIRMED','AUTH_INVITE_ACCEPTED'))`],
  ],
});

const authClosureSessionBinding = `(current_user={{AUTH_OWNER}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.auth_closure_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.auth_closure_user_id',true)=current_setting('app.user_id',true) AND EXISTS (SELECT 1 FROM public."RefreshToken" auth_session WHERE auth_session.id=current_setting('app.auth_closure_session_id',true) AND auth_session."userId"=current_setting('app.auth_closure_user_id',true) AND auth_session."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND auth_session."sessionCapabilityHashVersion"='sha256-v1' AND auth_session."sessionCapabilityRevokedAt" IS NULL AND auth_session."sessionCapabilityExpiresAt">clock_timestamp() AND auth_session."revokedAt" IS NULL AND auth_session."expiresAt">clock_timestamp()))`;
const authClosureVerifiedBinding = `(current_user={{AUTH_OWNER}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.auth_closure_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.auth_closure_user_id',true)=current_setting('app.user_id',true))`;
const authClosureSessionRowBinding = `(current_user={{AUTH_OWNER}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.auth_closure_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.auth_closure_user_id',true)=current_setting('app.user_id',true) AND id=current_setting('app.auth_closure_session_id',true) AND "userId"=current_setting('app.auth_closure_user_id',true) AND "sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND "sessionCapabilityHashVersion"='sha256-v1')`;
const authClosureLoginBinding = `(current_user={{AUTH_OWNER}} AND current_setting('app.auth_closure_user_id',true)<>'' AND current_setting('app.auth_closure_user_id',true)=current_setting('app.b01_preauth_user_id',true))`;
const authenticationClosureSecurity = Object.freeze({
  ...b01Security,
  functionSource: authenticationClosureSource,
  rollbackDefinition: authenticationClosureRollback,
  deploymentPhase: "session-b-b01-authentication-closure",
  ownerPrivileges: [
    ["User", "SELECT", ["id","email","pendingEmail","passwordHash","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt","emailVerifiedAt","pendingEmailRequestedAt","createdAt"]],
    ["User", "UPDATE", ["passwordHash","pendingEmail","pendingEmailRequestedAt","name","failedLoginAttempts","lockedUntil","lastLoginAt","updatedAt"]],
    ["RefreshToken", "SELECT", ["id","userId","orgId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt","revokedAt","revokedReason","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["RefreshToken", "INSERT", ["id","orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt"]],
    ["RefreshToken", "UPDATE", ["authenticatedAt","revokedAt","revokedReason","lastUsedAt","sessionCapabilityRevokedAt","sessionCapabilityRevokedReason"]],
    ["EmailVerificationToken", "SELECT", ["id","userId","purpose","usedAt"]],
    ["EmailVerificationToken", "INSERT", ["id","userId","email","pendingEmail","purpose","tokenHash","secretVersion","expiresAt","createdAt","createdIpHash","userAgentHash"]],
    ["EmailVerificationToken", "UPDATE", ["usedAt"]],
    ["Licensee", "SELECT", ["id","orgId","name","prefix","brandName","isActive","suspendedAt"]],
    ["Organization", "SELECT", ["id","isActive"]],
    ["ManufacturerLicenseeLink", "SELECT", ["manufacturerId","licenseeId"]],
    ["AdminMfaCredential", "SELECT", ["id","userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","lastUsedAt","createdAt","updatedAt"]],
    ["AdminMfaCredential", "INSERT", ["id","userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","lastUsedAt","createdAt","updatedAt"]],
    ["AdminMfaCredential", "UPDATE", ["secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","lastUsedAt","updatedAt"]],
    ["AdminWebAuthnCredential", "SELECT", ["id","userId","label","credentialId","publicKeySpki","publicKeyAlgorithm","counter","transports","lastUsedAt","createdAt","updatedAt"]],
    ["AdminWebAuthnCredential", "INSERT", ["id","userId","label","credentialId","publicKeySpki","publicKeyAlgorithm","counter","transports","lastUsedAt","createdAt","updatedAt"]],
    ["AdminWebAuthnCredential", "UPDATE", ["label","publicKeySpki","publicKeyAlgorithm","counter","transports","lastUsedAt","updatedAt"]],
    ["AdminWebAuthnCredential", "DELETE", ["id","userId"]],
    ["UserMfaFactor", "SELECT", ["id","userId","type","label","credentialId","publicKey","counter","transports","credentialDeviceType","credentialBackedUp","secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","createdAt","updatedAt","lastUsedAt","disabledAt"]],
    ["UserMfaFactor", "INSERT", ["id","userId","type","label","credentialId","publicKey","counter","transports","credentialDeviceType","credentialBackedUp","secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","createdAt","updatedAt","lastUsedAt","disabledAt"]],
    ["UserMfaFactor", "UPDATE", ["userId","type","label","credentialId","publicKey","counter","transports","credentialDeviceType","credentialBackedUp","secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","updatedAt","lastUsedAt","disabledAt"]],
    ["UserMfaFactor", "DELETE", ["id","userId","type","legacySource"]],
    ["UserBackupCode", "SELECT", ["id","userId","codeHash","usedAt","createdAt"]],
    ["UserBackupCode", "INSERT", ["id","userId","codeHash","createdAt"]],
    ["UserBackupCode", "UPDATE", ["usedAt"]],
    ["UserBackupCode", "DELETE", ["id","userId","usedAt"]],
    ["AuthSessionRiskSignal", "INSERT", ["id","userId","riskScore","riskLevel","reasons","ipHash","userAgentHash","createdAt"]],
    ["MfaLoginChallenge", "INSERT", ["id","userId","ticketHash","purpose","riskScore","riskLevel","reasons","createdIpHash","createdUserAgentHash","attempts","maxAttempts","createdAt","updatedAt","expiresAt"]],
    ["MfaLoginChallenge", "SELECT", ["id","userId","ticketHash","purpose","riskScore","riskLevel","reasons","createdIpHash","createdUserAgentHash","attempts","maxAttempts","expiresAt","consumedAt"]],
    ["MfaLoginChallenge", "UPDATE", ["attempts","updatedAt","consumedAt"]],
    ["AuthMfaChallenge", "SELECT", ["id","userId","ticketHash","sessionBindingHash","purpose","riskScore","riskLevel","reasons","createdIpHash","createdUserAgentHash","attempts","maxAttempts","expiresAt","consumedAt","supersededAt"]],
    ["AuthMfaChallenge", "INSERT", ["id","userId","ticketHash","sessionBindingHash","purpose","riskScore","riskLevel","reasons","createdIpHash","createdUserAgentHash","attempts","maxAttempts","createdAt","updatedAt","expiresAt"]],
    ["AuthMfaChallenge", "UPDATE", ["attempts","updatedAt","consumedAt","supersededAt"]],
    ["AuthWebAuthnChallenge", "SELECT", ["id","userId","purpose","ticketHash","challengeHash","credentialIds","createdIpHash","createdUserAgentHash","origin","rpId","createdAt","expiresAt","consumedAt"]],
    ["AuthWebAuthnChallenge", "INSERT", ["id","userId","purpose","ticketHash","challengeHash","credentialIds","createdIpHash","createdUserAgentHash","origin","rpId","createdAt","expiresAt"]],
    ["AuthWebAuthnChallenge", "UPDATE", ["consumedAt"]],
    ["AuditLogOutbox", "INSERT", ["id","payload","requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt"]],
  ],
  ownerPolicies: [
    ["User", "SELECT", `(${authClosureSessionBinding} AND id=current_setting('app.auth_closure_user_id',true)) OR (${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true) IN ('login-risk-read','login-risk-write','login-session-create') AND id=current_setting('app.auth_closure_user_id',true))`],
    ["User", "UPDATE", `(${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-write' AND id=current_setting('app.auth_closure_user_id',true)) OR (${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('email-change','profile-update','password-change') AND id=current_setting('app.auth_closure_user_id',true))`],
    ["RefreshToken", "SELECT", `(${authClosureSessionRowBinding} AND "sessionCapabilityRevokedAt" IS NULL AND "sessionCapabilityExpiresAt">clock_timestamp() AND "revokedAt" IS NULL AND "expiresAt">clock_timestamp()) OR (${authClosureVerifiedBinding} AND current_setting('app.auth_closure_operation',true) IN ('session-list','sensitive-session-read') AND "userId"=current_setting('app.auth_closure_user_id',true)) OR (${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-read' AND "userId"=current_setting('app.auth_closure_user_id',true))`],
    ["RefreshToken", "INSERT", `${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-session-create' AND id=current_setting('app.auth_closure_token_id',true) AND "userId"=current_setting('app.auth_closure_user_id',true) AND "tokenHash"=current_setting('app.auth_closure_token_hash',true) AND coalesce("orgId",'')=current_setting('app.auth_closure_organization_id',true)`],
    ["RefreshToken", "UPDATE", `(${authClosureSessionRowBinding} AND current_setting('app.auth_session_operation',true)='revoke-one' AND id=current_setting('app.auth_session_target_id',true)) OR (${authClosureVerifiedBinding} AND ((current_setting('app.auth_closure_operation',true)='password-step-up' AND id=current_setting('app.auth_closure_session_id',true)) OR (current_setting('app.auth_closure_operation',true) IN ('session-revoke-all','password-change','mfa-disable') AND "userId"=current_setting('app.auth_closure_user_id',true))))`],
    ["EmailVerificationToken", "SELECT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='email-change' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["EmailVerificationToken", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='email-change' AND "userId"=current_setting('app.auth_closure_user_id',true) AND purpose='EMAIL_CHANGE' AND "pendingEmail"=current_setting('app.auth_closure_pending_email',true) AND "tokenHash"=current_setting('app.auth_closure_token_hash',true)`],
    ["EmailVerificationToken", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='email-change' AND "userId"=current_setting('app.auth_closure_user_id',true) AND purpose='EMAIL_CHANGE'`],
    ["Licensee", "SELECT", `((${authClosureSessionBinding}) OR (${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true) IN ('login-risk-read','login-session-create'))) AND (id=current_setting('app.auth_closure_licensee_id',true) OR "orgId"=current_setting('app.auth_closure_organization_id',true) OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=current_setting('app.auth_closure_user_id',true) AND ml."licenseeId"=public."Licensee".id))`],
    ["Organization", "SELECT", `((${authClosureSessionBinding}) OR (${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true) IN ('login-risk-read','login-session-create'))) AND (id=current_setting('app.auth_closure_organization_id',true) OR EXISTS (SELECT 1 FROM public."Licensee" l WHERE l."orgId"=public."Organization".id AND (l.id=current_setting('app.auth_closure_licensee_id',true) OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=current_setting('app.auth_closure_user_id',true) AND ml."licenseeId"=l.id))))`],
    ["ManufacturerLicenseeLink", "SELECT", `((${authClosureSessionBinding}) OR (${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true) IN ('login-risk-read','login-session-create'))) AND "manufacturerId"=current_setting('app.auth_closure_user_id',true)`],
    ["AdminMfaCredential", "SELECT", `(${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-read' AND "userId"=current_setting('app.auth_closure_user_id',true)) OR (${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) LIKE 'mfa-%' AND "userId"=current_setting('app.auth_closure_user_id',true))`],
    ["AdminMfaCredential", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-enrollment-begin' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AdminMfaCredential", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-enrollment-begin','mfa-enrollment-complete','mfa-verifier-consume','mfa-backup-replace','mfa-disable') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AdminWebAuthnCredential", "SELECT", `(${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-read' AND "userId"=current_setting('app.auth_closure_user_id',true)) OR (${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) LIKE 'mfa-%' AND "userId"=current_setting('app.auth_closure_user_id',true))`],
    ["AdminWebAuthnCredential", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-webauthn-registration-complete' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AdminWebAuthnCredential", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-webauthn-authentication-complete' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AdminWebAuthnCredential", "DELETE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-disable','mfa-webauthn-delete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["UserMfaFactor", "SELECT", `(${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-read' AND "userId"=current_setting('app.auth_closure_user_id',true)) OR (${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) LIKE 'mfa-%' AND "userId"=current_setting('app.auth_closure_user_id',true))`],
    ["UserMfaFactor", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-enrollment-begin','mfa-verifier-consume','mfa-webauthn-registration-complete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["UserMfaFactor", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-enrollment-begin','mfa-enrollment-complete','mfa-verifier-consume','mfa-disable','mfa-webauthn-registration-complete','mfa-webauthn-authentication-complete','mfa-webauthn-delete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["UserMfaFactor", "DELETE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-enrollment-begin' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["UserBackupCode", "SELECT", `(${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-read' AND "userId"=current_setting('app.auth_closure_user_id',true)) OR (${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) LIKE 'mfa-%' AND "userId"=current_setting('app.auth_closure_user_id',true))`],
    ["UserBackupCode", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-enrollment-begin','mfa-enrollment-complete','mfa-backup-replace') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["UserBackupCode", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-verifier-consume' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["UserBackupCode", "DELETE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-enrollment-complete','mfa-backup-replace','mfa-disable') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AuthSessionRiskSignal", "INSERT", `${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true)='login-risk-write' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["MfaLoginChallenge", "INSERT", `((${authClosureLoginBinding}) AND current_setting('app.auth_closure_operation',true)='login-mfa-challenge' OR (${authClosureSessionBinding}) AND current_setting('app.auth_closure_operation',true)='mfa-challenge-create') AND id=current_setting('app.auth_closure_challenge_id',true) AND "userId"=current_setting('app.auth_closure_user_id',true) AND "ticketHash"=current_setting('app.auth_closure_challenge_hash',true)`],
    ["MfaLoginChallenge", "SELECT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-challenge-read' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["MfaLoginChallenge", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-challenge-fail','mfa-challenge-complete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AuthMfaChallenge", "SELECT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-challenge-read' AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AuthMfaChallenge", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-challenge-create' AND id=current_setting('app.auth_closure_challenge_id',true) AND "userId"=current_setting('app.auth_closure_user_id',true) AND "ticketHash"=current_setting('app.auth_closure_challenge_hash',true)`],
    ["AuthMfaChallenge", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-challenge-create','mfa-challenge-fail','mfa-challenge-complete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AuthWebAuthnChallenge", "SELECT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-webauthn-challenge-read','mfa-webauthn-registration-complete','mfa-webauthn-authentication-complete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AuthWebAuthnChallenge", "INSERT", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true)='mfa-webauthn-challenge-create' AND id=current_setting('app.auth_closure_challenge_id',true) AND "userId"=current_setting('app.auth_closure_user_id',true) AND "ticketHash"=current_setting('app.auth_closure_challenge_hash',true)`],
    ["AuthWebAuthnChallenge", "UPDATE", `${authClosureSessionBinding} AND current_setting('app.auth_closure_operation',true) IN ('mfa-webauthn-registration-complete','mfa-webauthn-authentication-complete') AND "userId"=current_setting('app.auth_closure_user_id',true)`],
    ["AuditLogOutbox", "INSERT", `(${authClosureLoginBinding} AND current_setting('app.auth_closure_operation',true) IN ('login-mfa-challenge','login-session-create') AND payload->>'userId'=current_setting('app.auth_closure_user_id',true) AND payload->>'action' IN ('AUTH_MFA_CHALLENGE_ISSUED','AUTH_LOGIN_SUCCESS','AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA')) OR (${authClosureSessionBinding} AND ((current_setting('app.auth_closure_operation',true) IN ('profile-update','password-change','mfa-enrollment-complete','mfa-disable','mfa-challenge-create','mfa-challenge-fail','mfa-challenge-complete','mfa-webauthn-registration-complete','mfa-webauthn-delete') AND payload->>'action' IN ('AUTH_PROFILE_UPDATED','AUTH_PASSWORD_CHANGED','AUTH_MFA_ENROLLED','AUTH_MFA_REPLACED','AUTH_MFA_DISABLED','AUTH_MFA_CHALLENGE_ISSUED','AUTH_MFA_CHALLENGE_EXPIRED','AUTH_MFA_FAILURE','AUTH_MFA_TOO_MANY_ATTEMPTS','AUTH_MFA_BACKUP_CODE_USED','AUTH_MFA_SUCCESS','AUTH_WEBAUTHN_ENROLLED','AUTH_WEBAUTHN_CREDENTIAL_REMOVED')) OR (current_setting('app.auth_closure_operation',true)='manufacturer-scope-read' AND payload->>'action' IN ('MANUFACTURER_BOOTSTRAP_READ','MANUFACTURER_SCOPE_SWITCH'))) AND payload->>'userId'=current_setting('app.auth_closure_user_id',true))`],
  ],
});

const c03SessionBinding = `app_rls.c03_session_valid()`;
const c02SessionRowBinding = `(current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND current_setting('app.auth_session_verified',true)='1' AND id=current_setting('app.auth_session_id',true) AND "userId"=current_setting('app.user_id',true) AND "sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND "sessionCapabilityHashVersion"='sha256-v1' AND "sessionCapabilityRevokedAt" IS NULL AND "sessionCapabilityExpiresAt">clock_timestamp() AND "revokedAt" IS NULL AND "expiresAt">clock_timestamp())`;
const c02SessionBinding = `app_rls.c02_audit_trace_session_valid()`;
const c02AuditTraceSecurity = Object.freeze({
  mode: "SECURITY DEFINER",
  ownerIdentity: "identity-auth-function-owner",
  ownerRole: "authOwner",
  searchPath: "pg_catalog,public",
  publicExecute: "revoked",
  runtimeExecuteGrantees: ["app"],
  functionSource: c02AuditTraceSource,
  rollbackDefinition: c02AuditTraceRollback,
  deploymentPhase: "session-c-c03",
  ownerPrivileges: [
    ["RefreshToken", "SELECT", ["id","userId","expiresAt","revokedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["User", "SELECT", ["id","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt"]],
    ["Licensee", "SELECT", ["id","orgId","isActive","suspendedAt"]],
    ["Organization", "SELECT", ["id","isActive"]],
    ["ManufacturerLicenseeLink", "SELECT", ["manufacturerId","licenseeId"]],
    ["AuditLog", "SELECT", ["id","userId","orgId","licenseeId","action","entityType","entityId","details","ipAddress","userAgent","createdAt"]],
    ["AuditLog", "INSERT", ["id","userId","orgId","licenseeId","action","entityType","entityId","details"]],
    ["SecurityEventOutbox", "INSERT", ["id","eventType","payload","updatedAt"]],
  ],
  ownerPolicies: [
    ["RefreshToken", "SELECT", c02SessionRowBinding],
    ["User", "SELECT", `${c02SessionBinding} AND (id=current_setting('app.user_id',true) OR (current_setting('app.purpose',true)='platform-audit-log-read' AND "licenseeId"=current_setting('app.licensee_id',true)))`],
    ["Licensee", "SELECT", `${c02SessionBinding} AND id=current_setting('app.licensee_id',true) AND "isActive" AND "suspendedAt" IS NULL`],
    ["Organization", "SELECT", `${c02SessionBinding} AND "isActive" AND id IN (current_setting('app.organization_id',true),(SELECT l."orgId" FROM public."Licensee" l WHERE l.id=current_setting('app.licensee_id',true)))`],
    ["ManufacturerLicenseeLink", "SELECT", `${c02SessionBinding} AND "manufacturerId"=current_setting('app.user_id',true) AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["AuditLog", "SELECT", `${c02SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["AuditLog", "INSERT", `${c02SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "userId"=current_setting('app.user_id',true) AND action='CUSTOMER_FRAUD_REPORT_RESPONSE'`],
    ["SecurityEventOutbox", "INSERT", `${c02SessionBinding} AND "eventType"='AUDIT_LOG' AND payload->>'userId'=current_setting('app.user_id',true) AND payload->>'licenseeId'=current_setting('app.licensee_id',true)`],
  ],
});
const riskAnalyticsBinding = `app_rls.risk_analytics_session_valid()`;
const riskAnalyticsSecurity = Object.freeze({
  mode: "SECURITY DEFINER",
  ownerIdentity: "identity-auth-function-owner",
  ownerRole: "authOwner",
  searchPath: "pg_catalog,public",
  publicExecute: "revoked",
  runtimeExecuteGrantees: ["app"],
  functionSource: riskAnalyticsSource,
  rollbackDefinition: riskAnalyticsRollback,
  deploymentPhase: "session-c-c03",
  ownerPrivileges: [
    ["RefreshToken","SELECT",["id","userId","expiresAt","revokedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["User","SELECT",["id","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt"]],
    ["Licensee","SELECT",["id","orgId","isActive","suspendedAt"]],
    ["Organization","SELECT",["id","isActive"]],
    ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId"]],
    ["SecurityPolicy","SELECT",["licenseeId","multiScanThreshold","geoDriftThresholdKm","velocitySpikeThresholdPerMin"]],
    ["Batch","SELECT",["id","name","licenseeId","manufacturerId"]],
    ["QRCode","SELECT",["id","licenseeId","batchId","scanCount"]],
    ["QrScanLog","SELECT",["id","licenseeId","qrCodeId","batchId","latitude","longitude","scannedAt"]],
    ["PolicyAlert","SELECT",["id","licenseeId","batchId","qrCodeId","manufacturerId","incidentId","policyRuleId","acknowledgedAt"]],
    ["Incident","SELECT",["id","licenseeId"]],
    ["PolicyRule","SELECT",["id","licenseeId","orgId","manufacturerId","isActive"]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details"]],
  ],
  ownerPolicies: [
    ["RefreshToken","SELECT",c02SessionRowBinding],
    ["User","SELECT",`${riskAnalyticsBinding} AND (id=current_setting('app.risk_analytics_user_id',true) OR "licenseeId"=current_setting('app.risk_analytics_licensee_id',true) OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."manufacturerId"=id AND ml."licenseeId"=current_setting('app.risk_analytics_licensee_id',true)))`],
    ["Licensee","SELECT",`${riskAnalyticsBinding} AND id=current_setting('app.risk_analytics_licensee_id',true) AND "isActive" AND "suspendedAt" IS NULL`],
    ["Organization","SELECT",`${riskAnalyticsBinding} AND id=current_setting('app.risk_analytics_organization_id',true) AND "isActive"`],
    ["ManufacturerLicenseeLink","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["SecurityPolicy","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["Batch","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["QRCode","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["QrScanLog","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["PolicyAlert","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["Incident","SELECT",`${riskAnalyticsBinding} AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true)`],
    ["PolicyRule","SELECT",`${riskAnalyticsBinding} AND ("licenseeId"=current_setting('app.risk_analytics_licensee_id',true) OR "orgId"=current_setting('app.risk_analytics_organization_id',true) OR EXISTS (SELECT 1 FROM public."ManufacturerLicenseeLink" ml WHERE ml."licenseeId"=current_setting('app.risk_analytics_licensee_id',true) AND ml."manufacturerId"="manufacturerId"))`],
    ["AuditLog","INSERT",`${riskAnalyticsBinding} AND id=current_setting('app.risk_analytics_audit_id',true) AND "userId"=current_setting('app.risk_analytics_user_id',true) AND "licenseeId"=current_setting('app.risk_analytics_licensee_id',true) AND action='RISK_ANALYTICS_READ'`],
  ],
});
const c03LicenseeScope = `(id=current_setting('app.c03_licensee_id',true) AND "isActive" AND "suspendedAt" IS NULL AND (current_setting('app.c03_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR (id=current_setting('app.c03_actor_licensee_id',true) AND "orgId"=current_setting('app.c03_actor_organization_id',true))))`;
const c03Security = Object.freeze({
  mode: "SECURITY DEFINER",
  ownerIdentity: "identity-auth-function-owner",
  ownerRole: "authOwner",
  searchPath: "pg_catalog,public",
  publicExecute: "revoked",
  runtimeExecuteGrantees: ["app"],
  functionSource: c03Source,
  rollbackDefinition: c03Rollback,
  deploymentPhase: "session-c-c03",
  ownerPrivileges: [
    ["RefreshToken", "SELECT", ["id","userId","expiresAt","revokedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["User", "SELECT", ["id","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt"]],
    ["Licensee", "SELECT", ["id","orgId","isActive","suspendedAt"]],
    ["Organization", "SELECT", ["id","isActive"]],
    ["CompliancePackJob", "SELECT", ["id","licenseeId","status","triggerType","scheduledScheduleId","periodFrom","periodTo","fileName","storageKey","integrityHash","signatureAlgorithm","summary","errorMessage","startedByUserId","startedAt","finishedAt","createdAt","updatedAt"]],
    ["CompliancePackJob", "INSERT", ["id","licenseeId","status","triggerType","periodFrom","periodTo","startedByUserId","startedAt","updatedAt"]],
    ["CompliancePackJob", "UPDATE", ["status","fileName","storageKey","integrityHash","signatureAlgorithm","summary","errorMessage","finishedAt","updatedAt"]],
    ["ActionIdempotencyKey", "SELECT", ["id","keyHash","action","scope","requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"]],
    ["ActionIdempotencyKey", "INSERT", ["id","keyHash","action","scope","requestHash","expiresAt"]],
    ["ActionIdempotencyKey", "UPDATE", ["statusCode","responsePayload","completedAt"]],
    ["Incident", "SELECT", ["id","licenseeId","status","slaDueAt","createdAt"]],
    ["IncidentEvidence", "SELECT", ["id","incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"]],
    ["IncidentHandoff", "SELECT", ["incidentId","currentStage"]],
    ["AuditLog", "SELECT", ["licenseeId","action","createdAt"]],
    ["EvidenceRetentionPolicy", "SELECT", ["licenseeId","retentionDays"]],
    ["AuditLogOutbox", "INSERT", ["id","payload","updatedAt"]],
  ],
  ownerPolicies: [
    ["Licensee", "SELECT", `${c03SessionBinding} AND ${c03LicenseeScope}`],
    ["Organization", "SELECT", `${c03SessionBinding} AND "isActive" AND id IN (current_setting('app.c03_actor_organization_id',true),(SELECT l."orgId" FROM public."Licensee" l WHERE l.id=current_setting('app.c03_licensee_id',true)))`],
    ["CompliancePackJob", "SELECT", `${c03SessionBinding} AND (id=current_setting('app.c03_job_id',true) OR "licenseeId"=current_setting('app.c03_licensee_id',true)) AND (current_setting('app.c03_licensee_id',true)='' OR "licenseeId"=current_setting('app.c03_licensee_id',true))`],
    ["CompliancePackJob", "INSERT", `${c03SessionBinding} AND current_setting('app.c03_operation',true)='compliance-pack-start' AND id=current_setting('app.c03_job_id',true) AND "licenseeId"=current_setting('app.c03_licensee_id',true) AND "startedByUserId"=current_setting('app.c03_user_id',true)`],
    ["CompliancePackJob", "UPDATE", `${c03SessionBinding} AND id=current_setting('app.c03_job_id',true) AND "licenseeId"=current_setting('app.c03_licensee_id',true) AND current_setting('app.c03_operation',true) IN ('compliance-pack-complete','compliance-pack-fail','compliance-pack-rebuild')`],
    ["ActionIdempotencyKey", "SELECT", `${c03SessionBinding} AND action='c03-compliance-start' AND scope=current_setting('app.c03_licensee_id',true)`],
    ["ActionIdempotencyKey", "INSERT", `${c03SessionBinding} AND action='c03-compliance-start' AND scope=current_setting('app.c03_licensee_id',true)`],
    ["ActionIdempotencyKey", "UPDATE", `${c03SessionBinding} AND action='c03-compliance-start' AND scope=current_setting('app.c03_licensee_id',true)`],
    ["IncidentEvidence", "SELECT", `${c03SessionBinding} AND current_setting('app.c03_operation',true)='incident-evidence-read' AND "storageKey"=current_setting('app.c03_storage_key',true)`],
    ["Incident", "SELECT", `${c03SessionBinding} AND ("licenseeId"=current_setting('app.c03_licensee_id',true) OR (current_setting('app.c03_licensee_id',true)='' AND id=current_setting('app.c03_incident_id',true)))`],
    ["IncidentHandoff", "SELECT", `${c03SessionBinding} AND EXISTS (SELECT 1 FROM public."Incident" i WHERE i.id="incidentId" AND i."licenseeId"=current_setting('app.c03_licensee_id',true))`],
    ["AuditLog", "SELECT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.c03_licensee_id',true)`],
    ["EvidenceRetentionPolicy", "SELECT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.c03_licensee_id',true)`],
    ["AuditLogOutbox", "INSERT", `${c03SessionBinding} AND payload->>'userId'=current_setting('app.c03_user_id',true) AND payload->>'licenseeId'=current_setting('app.c03_licensee_id',true)`],
  ],
});

const c03PolicySecurity = Object.freeze({
  ...c03Security,
  functionSource: c03PolicySource,
  rollbackDefinition: c03PolicyRollback,
  ownerPrivileges: [
    ...c03Security.ownerPrivileges,
    ["PolicyRule", "SELECT", ["id","orgId","licenseeId","manufacturerId","createdByUserId","name","description","ruleType","isActive","threshold","windowMinutes","severity","autoCreateIncident","incidentSeverity","incidentPriority","actionConfig","createdAt","updatedAt"]],
    ["PolicyRule", "INSERT", ["id","orgId","licenseeId","manufacturerId","createdByUserId","name","description","ruleType","isActive","threshold","windowMinutes","severity","autoCreateIncident","incidentSeverity","incidentPriority","actionConfig","createdAt","updatedAt"]],
    ["PolicyRule", "UPDATE", ["name","description","ruleType","isActive","threshold","windowMinutes","severity","autoCreateIncident","incidentSeverity","incidentPriority","actionConfig","updatedAt"]],
  ],
  ownerPolicies: [
    ...c03Security.ownerPolicies,
    ["PolicyRule", "SELECT", `${c03SessionBinding} AND ("licenseeId"=current_setting('app.licensee_id',true) OR (current_setting('app.licensee_id',true)='' AND current_setting('app.role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')))`],
    ["PolicyRule", "INSERT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "createdByUserId"=current_setting('app.user_id',true)`],
    ["PolicyRule", "UPDATE", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
  ],
});

const c03GovernanceSecurity = Object.freeze({
  ...c03Security,
  functionSource: c03GovernanceSource,
  rollbackDefinition: c03GovernanceRollback,
  ownerPrivileges: [
    ...c03Security.ownerPrivileges,
    ["TenantFeatureFlag", "SELECT", ["id","licenseeId","key","enabled","config","updatedByUserId","createdAt","updatedAt"]],
    ["TenantFeatureFlag", "INSERT", ["id","licenseeId","key","enabled","config","updatedByUserId","updatedAt"]],
    ["TenantFeatureFlag", "UPDATE", ["enabled","config","updatedByUserId","updatedAt"]],
    ["EvidenceRetentionPolicy", "SELECT", ["id","licenseeId","retentionDays","purgeEnabled","exportBeforePurge","legalHoldTags","updatedByUserId","createdAt","updatedAt"]],
    ["EvidenceRetentionPolicy", "INSERT", ["id","licenseeId","retentionDays","purgeEnabled","exportBeforePurge","legalHoldTags","updatedAt"]],
    ["EvidenceRetentionPolicy", "UPDATE", ["retentionDays","purgeEnabled","exportBeforePurge","legalHoldTags","updatedByUserId","updatedAt"]],
    ["EvidenceRetentionJob", "INSERT", ["id","licenseeId","status","mode","cutoffAt","recordsEvaluated","recordsPurged","recordsExported","summary","startedByUserId","startedAt","finishedAt"]],
    ["SensitiveActionApproval", "SELECT", ["id","actionKey","status","requestedByUserId","reviewedByUserId","executedByUserId","licenseeId","payload","expiresAt","executedAt"]],
    ["SensitiveActionApproval", "UPDATE", ["status","executedByUserId","executedAt","updatedAt"]],
    ["AuditLog", "INSERT", ["id","userId","orgId","licenseeId","action","entityType","entityId","details"]],
    ["SecurityEventOutbox", "INSERT", ["id","eventType","payload","updatedAt"]],
  ],
  ownerPolicies: [
    ...c03Security.ownerPolicies,
    ["TenantFeatureFlag", "SELECT", `${c03SessionBinding} AND current_setting('app.c03_operation',true)='governance-feature-flag-list' AND "licenseeId"=current_setting('app.c03_licensee_id',true)`],
    ["TenantFeatureFlag", "INSERT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "updatedByUserId"=current_setting('app.user_id',true)`],
    ["TenantFeatureFlag", "UPDATE", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["EvidenceRetentionPolicy", "SELECT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["EvidenceRetentionPolicy", "INSERT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["EvidenceRetentionPolicy", "UPDATE", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["EvidenceRetentionJob", "INSERT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "startedByUserId"=current_setting('app.user_id',true)`],
    ["SensitiveActionApproval", "SELECT", `${c03SessionBinding} AND ("licenseeId"=current_setting('app.licensee_id',true) OR (current_setting('app.c03_operation',true)='sensitive-action-approval-revalidate' AND id=current_setting('app.c03_approval_id',true)))`],
    ["SensitiveActionApproval", "UPDATE", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND current_setting('app.user_id',true)<>"requestedByUserId"`],
    ["AuditLog", "INSERT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "userId"=current_setting('app.user_id',true)`],
    ["SecurityEventOutbox", "INSERT", `${c03SessionBinding} AND payload->>'licenseeId'=current_setting('app.licensee_id',true)`],
  ],
});

const c03ApprovalSecurity = Object.freeze({
  ...c03GovernanceSecurity,
  functionSource: c03ApprovalSource,
  rollbackDefinition: c03ApprovalRollback,
  ownerPrivileges: [
    ...c03GovernanceSecurity.ownerPrivileges,
    ["SensitiveActionApproval", "INSERT", ["id","actionKey","status","requestedByUserId","licenseeId","entityType","entityId","payload","summary","requestIpHash","requestUserAgentHash","expiresAt","updatedAt"]],
    ["SensitiveActionApproval", "UPDATE", ["status","reviewedByUserId","reviewNote","reviewedAt","updatedAt"]],
  ],
  ownerPolicies: [
    ...c03GovernanceSecurity.ownerPolicies,
    ["SensitiveActionApproval", "INSERT", `${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "requestedByUserId"=current_setting('app.user_id',true) AND status='PENDING'`],
  ],
});

const c03PublicIncidentBinding = `(current_user={{AUTH_OWNER}} AND session_user={{PREAUTH_ROLE}} AND current_setting('app.purpose',true)='public-incident-intake')`;
const c03IncidentSecurity = Object.freeze({
  ...c03Security,
  functionSource: c03IncidentSource,
  rollbackDefinition: c03IncidentRollback,
  ownerPrivileges: [
    ...c03Security.ownerPrivileges,
    ["QRCode","SELECT",["id","code","licenseeId"]],
    ["Incident","SELECT",["id","qrCodeId","qrCodeValue","licenseeId","reportedBy","customerName","customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact","incidentType","severity","severityOverridden","description","photos","purchasePlace","purchaseDate","productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion","locationCity","ipHash","userAgentHash","deviceFingerprintHash","status","priority","assignedToUserId","slaDueAt","tags","internalNotes","resolutionSummary","resolutionOutcome","createdAt","updatedAt"]],
    ["Incident","INSERT",["id","qrCodeId","qrCodeValue","licenseeId","reportedBy","customerName","customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact","incidentType","severity","description","photos","purchasePlace","purchaseDate","productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion","locationCity","ipHash","userAgentHash","deviceFingerprintHash","status","priority","slaDueAt","tags"]],
    ["Incident","UPDATE",["status","assignedToUserId","internalNotes","tags","severity","severityOverridden","priority","resolutionSummary","resolutionOutcome","updatedAt"]],
    ["IncidentEvent","SELECT",["id","incidentId","actorType","actorUserId","eventType","eventPayload","createdAt"]],
    ["IncidentEvent","INSERT",["id","incidentId","actorType","actorUserId","eventType","eventPayload"]],
    ["IncidentEvidence","SELECT",["id","incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"]],
    ["IncidentEvidence","INSERT",["id","incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy"]],
    ["IncidentCommunication","SELECT",["id","incidentId","direction","channel","toAddress","subject","bodyPreview","attemptedFrom","usedFrom","replyTo","providerMessageId","errorMessage","status","createdAt"]],
    ["PolicyAlert","SELECT",["id","licenseeId","alertType","severity","message","score","policyRuleId","incidentId","batchId","qrCodeId","manufacturerId","acknowledgedAt","createdAt"]],
    ["PolicyAlert","UPDATE",["incidentId"]],
  ],
  ownerPolicies: [
    ...c03Security.ownerPolicies,
    ["QRCode","SELECT",`${c03PublicIncidentBinding} AND current_setting('app.c03_public_operation',true)='incident-qr-read' AND code=current_setting('app.c03_public_code',true)`],
    ["Licensee","SELECT",`${c03PublicIncidentBinding} AND id=current_setting('app.c03_public_licensee_id',true) AND "isActive" AND "suspendedAt" IS NULL`],
    ["Organization","SELECT",`${c03PublicIncidentBinding} AND "isActive" AND EXISTS (SELECT 1 FROM public."Licensee" public_incident_licensee WHERE public_incident_licensee.id=current_setting('app.c03_public_licensee_id',true) AND public_incident_licensee."orgId"=id)`],
    ["Incident","SELECT",`(${c03PublicIncidentBinding} AND current_setting('app.c03_public_operation',true)='incident-history-read' AND "qrCodeId"=current_setting('app.c03_public_qr_id',true)) OR (${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND (id=current_setting('app.c03_incident_id',true) OR current_setting('app.purpose',true)='incident-list'))`],
    ["Incident","INSERT",`${c03PublicIncidentBinding} AND current_setting('app.c03_public_operation',true)='incident-create' AND "qrCodeId"=current_setting('app.c03_public_qr_id',true) AND "licenseeId"=current_setting('app.c03_public_licensee_id',true) AND "reportedBy"='CUSTOMER'`],
    ["Incident","UPDATE",`${c03SessionBinding} AND id=current_setting('app.c03_incident_id',true) AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["IncidentEvent","SELECT",`${c03SessionBinding} AND "incidentId"=current_setting('app.c03_incident_id',true)`],
    ["IncidentEvent","INSERT",`(${c03PublicIncidentBinding} AND current_setting('app.c03_public_operation',true)='incident-create' AND "incidentId"=current_setting('app.c03_public_incident_id',true) AND "actorType"='CUSTOMER') OR (${c03SessionBinding} AND "incidentId"=current_setting('app.c03_incident_id',true) AND "actorUserId"=current_setting('app.user_id',true))`],
    ["IncidentEvidence","SELECT",`${c03SessionBinding} AND "incidentId"=current_setting('app.c03_incident_id',true)`],
    ["IncidentEvidence","INSERT",`(${c03PublicIncidentBinding} AND current_setting('app.c03_public_operation',true)='incident-create' AND "incidentId"=current_setting('app.c03_public_incident_id',true) AND "uploadedBy"='CUSTOMER') OR (${c03SessionBinding} AND "incidentId"=current_setting('app.c03_incident_id',true) AND "uploadedByUserId"=current_setting('app.user_id',true))`],
    ["IncidentCommunication","SELECT",`${c03SessionBinding} AND "incidentId"=current_setting('app.c03_incident_id',true)`],
    ["PolicyAlert","SELECT",`${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true) AND "incidentId"=current_setting('app.c03_incident_id',true)`],
    ["PolicyAlert","UPDATE",`${c03SessionBinding} AND "licenseeId"=current_setting('app.licensee_id',true)`],
    ["ActionIdempotencyKey","SELECT",`(${c03PublicIncidentBinding} AND action='c03-public-incident') OR (${c03SessionBinding} AND action IN ('c03-incident-evidence','c03-alert-link'))`],
    ["ActionIdempotencyKey","INSERT",`(${c03PublicIncidentBinding} AND action='c03-public-incident' AND scope=current_setting('app.c03_public_licensee_id',true)) OR (${c03SessionBinding} AND action IN ('c03-incident-evidence','c03-alert-link'))`],
    ["ActionIdempotencyKey","UPDATE",`(${c03PublicIncidentBinding} AND action='c03-public-incident' AND scope=current_setting('app.c03_public_licensee_id',true)) OR (${c03SessionBinding} AND action IN ('c03-incident-evidence','c03-alert-link'))`],
  ],
});

const c03ComplianceWorkflow = "workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler";
const c03EvidenceWorkflow = "workflow-http-backend-src-controllers-incident-controller-ts-serve-incident-evidence-file";
const scheduledComplianceWorkflow = "workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler";
const c03Commands = Object.freeze({
  start: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["CompliancePackJob","INSERT"],["CompliancePackJob","SELECT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["Incident","SELECT"],["IncidentHandoff","SELECT"],["AuditLog","SELECT"],["EvidenceRetentionPolicy","SELECT"],["AuditLogOutbox","INSERT"]],
  transition: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["CompliancePackJob","SELECT"],["CompliancePackJob","UPDATE"],["AuditLogOutbox","INSERT"]],
  get: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["CompliancePackJob","SELECT"],["Incident","SELECT"],["IncidentHandoff","SELECT"],["AuditLog","SELECT"],["EvidenceRetentionPolicy","SELECT"]],
  evidence: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["IncidentEvidence","SELECT"]],
});

const scheduledBinding = `(current_user={{AUTH_OWNER}} AND session_user={{SCHEDULED_ROLE}} AND current_setting('app.scheduled_verified',true)='1' AND current_setting('app.scheduled_family',true)='compliance-pack' AND EXISTS (SELECT 1 FROM public."ScheduledJobCredential" scheduled_credential WHERE scheduled_credential.id=current_setting('app.scheduled_credential_id',true) AND scheduled_credential."capabilityHash"=current_setting('app.scheduled_capability_hash',true) AND scheduled_credential."capabilityHashVersion"='sha256-v1' AND scheduled_credential."identityName"='identity-scheduled-job' AND scheduled_credential."jobFamily"='compliance-pack' AND scheduled_credential."scheduleId"=current_setting('app.scheduled_schedule_id',true) AND scheduled_credential."revokedAt" IS NULL AND scheduled_credential."expiresAt">clock_timestamp()))`;
const scheduledSecurity = Object.freeze({
  mode: "SECURITY DEFINER",
  ownerIdentity: "identity-auth-function-owner",
  ownerRole: "authOwner",
  searchPath: "pg_catalog,public",
  publicExecute: "revoked",
  runtimeExecuteGrantees: ["scheduled"],
  functionSource: scheduledSource,
  rollbackDefinition: scheduledRollback,
  deploymentPhase: "session-b-b03-scheduled",
  ownerPrivileges: [
    ["ScheduledJobCredential", "SELECT", ["id","identityName","jobFamily","scheduleId","capabilityHash","capabilityHashVersion","expiresAt","revokedAt","revokedReason","rotatedFromCredentialId","lastUsedAt","createdAt","updatedAt"]],
    ["ScheduledJobCredential", "INSERT", ["id","identityName","jobFamily","scheduleId","capabilityHash","capabilityHashVersion","expiresAt","rotatedFromCredentialId","updatedAt"]],
    ["ScheduledJobCredential", "UPDATE", ["lastUsedAt","revokedAt","revokedReason","updatedAt"]],
    ["Licensee", "SELECT", ["id","orgId","isActive","suspendedAt"]],
    ["Organization", "SELECT", ["id","isActive"]],
    ["CompliancePackJob", "SELECT", ["id","licenseeId","status","triggerType","scheduledScheduleId","periodFrom","periodTo","fileName","storageKey","integrityHash","signatureAlgorithm","summary","errorMessage","startedByUserId","startedAt","finishedAt","createdAt","updatedAt"]],
    ["CompliancePackJob", "INSERT", ["id","licenseeId","status","triggerType","scheduledScheduleId","periodFrom","periodTo","startedByUserId","startedAt","updatedAt"]],
    ["CompliancePackJob", "UPDATE", ["status","fileName","storageKey","integrityHash","signatureAlgorithm","summary","errorMessage","finishedAt","updatedAt"]],
    ["ActionIdempotencyKey", "SELECT", ["id","keyHash","action","scope","requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"]],
    ["ActionIdempotencyKey", "INSERT", ["id","keyHash","action","scope","requestHash","expiresAt"]],
    ["ActionIdempotencyKey", "UPDATE", ["statusCode","responsePayload","completedAt"]],
    ["Incident", "SELECT", ["id","licenseeId","status","slaDueAt","createdAt"]],
    ["IncidentHandoff", "SELECT", ["incidentId","currentStage"]],
    ["AuditLog", "SELECT", ["licenseeId","action","createdAt"]],
    ["EvidenceRetentionPolicy", "SELECT", ["licenseeId","retentionDays"]],
    ["AuditLogOutbox", "INSERT", ["id","payload","updatedAt"]],
  ],
  ownerPolicies: [
    ["ScheduledJobCredential", "SELECT", `((current_user={{AUTH_OWNER}} AND session_user={{SCHEDULED_ROLE}} AND "capabilityHash"=current_setting('app.scheduled_capability_hash',true) AND "scheduleId"=current_setting('app.scheduled_schedule_id',true)) OR (current_user={{AUTH_OWNER}} AND session_user={{OPERATOR_ROLE}} AND current_setting('app.scheduled_admin_operation',true) IN ('provision','revoke')))`],
    ["ScheduledJobCredential", "INSERT", `(current_user={{AUTH_OWNER}} AND session_user={{OPERATOR_ROLE}} AND current_setting('app.scheduled_admin_operation',true)='provision' AND "capabilityHash"=current_setting('app.scheduled_capability_hash',true) AND "scheduleId"=current_setting('app.scheduled_schedule_id',true))`],
    ["ScheduledJobCredential", "UPDATE", `((current_user={{AUTH_OWNER}} AND session_user={{SCHEDULED_ROLE}} AND ((current_setting('app.scheduled_verified',true)='' AND "capabilityHash"=current_setting('app.scheduled_capability_hash',true) AND "scheduleId"=current_setting('app.scheduled_schedule_id',true)) OR (current_setting('app.scheduled_verified',true)='1' AND id=current_setting('app.scheduled_credential_id',true) AND "capabilityHash"=current_setting('app.scheduled_capability_hash',true)))) OR (current_user={{AUTH_OWNER}} AND session_user={{OPERATOR_ROLE}} AND current_setting('app.scheduled_admin_operation',true) IN ('provision','revoke')))`],
    ["Licensee", "SELECT", `${scheduledBinding} AND "isActive" AND "suspendedAt" IS NULL AND (current_setting('app.scheduled_operation',true)='claim' OR id=current_setting('app.scheduled_licensee_id',true))`],
    ["Organization", "SELECT", `${scheduledBinding} AND "isActive" AND (current_setting('app.scheduled_operation',true)='claim' OR id=current_setting('app.organization_id',true))`],
    ["CompliancePackJob", "SELECT", `${scheduledBinding} AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=current_setting('app.scheduled_schedule_id',true) AND (current_setting('app.scheduled_job_id',true)='' OR id=current_setting('app.scheduled_job_id',true))`],
    ["CompliancePackJob", "INSERT", `${scheduledBinding} AND current_setting('app.scheduled_operation',true)='claim' AND id=current_setting('app.scheduled_job_id',true) AND "licenseeId"=current_setting('app.scheduled_licensee_id',true) AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=current_setting('app.scheduled_schedule_id',true) AND "startedByUserId" IS NULL`],
    ["CompliancePackJob", "UPDATE", `${scheduledBinding} AND current_setting('app.scheduled_operation',true) IN ('complete','fail') AND id=current_setting('app.scheduled_job_id',true) AND "triggerType"='SCHEDULED' AND "scheduledScheduleId"=current_setting('app.scheduled_schedule_id',true) AND (current_setting('app.scheduled_licensee_id',true)='' OR "licenseeId"=current_setting('app.scheduled_licensee_id',true))`],
    ["ActionIdempotencyKey", "SELECT", `${scheduledBinding} AND action='scheduled-compliance-pack' AND scope=current_setting('app.scheduled_licensee_id',true)`],
    ["ActionIdempotencyKey", "INSERT", `${scheduledBinding} AND current_setting('app.scheduled_operation',true)='claim' AND action='scheduled-compliance-pack' AND scope=current_setting('app.scheduled_licensee_id',true)`],
    ["ActionIdempotencyKey", "UPDATE", `${scheduledBinding} AND current_setting('app.scheduled_operation',true)='claim' AND action='scheduled-compliance-pack' AND scope=current_setting('app.scheduled_licensee_id',true)`],
    ["Incident", "SELECT", `${scheduledBinding} AND "licenseeId"=current_setting('app.scheduled_licensee_id',true)`],
    ["IncidentHandoff", "SELECT", `${scheduledBinding} AND EXISTS (SELECT 1 FROM public."Incident" scheduled_incident WHERE scheduled_incident.id="incidentId" AND scheduled_incident."licenseeId"=current_setting('app.scheduled_licensee_id',true))`],
    ["AuditLog", "SELECT", `${scheduledBinding} AND "licenseeId"=current_setting('app.scheduled_licensee_id',true)`],
    ["EvidenceRetentionPolicy", "SELECT", `${scheduledBinding} AND "licenseeId"=current_setting('app.scheduled_licensee_id',true)`],
    ["AuditLogOutbox", "INSERT", `${scheduledBinding} AND payload->'details'->>'systemIdentity'='identity-scheduled-job' AND payload->>'licenseeId'=current_setting('app.scheduled_licensee_id',true)`],
  ],
});
const scheduledReadCommands = [["ScheduledJobCredential","SELECT"],["ScheduledJobCredential","UPDATE"],["Licensee","SELECT"],["Organization","SELECT"],["CompliancePackJob","SELECT"],["Incident","SELECT"],["IncidentHandoff","SELECT"],["AuditLog","SELECT"],["EvidenceRetentionPolicy","SELECT"]];
const scheduledTransitionCommands = [["ScheduledJobCredential","SELECT"],["ScheduledJobCredential","UPDATE"],["CompliancePackJob","SELECT"],["CompliancePackJob","UPDATE"],["AuditLogOutbox","INSERT"]];
const outboxOperation = `current_setting('app.b03_outbox_operation',true)`;
const outboxId = `current_setting('app.b03_outbox_id',true)`;
const outboxDigest = `current_setting('app.b03_outbox_digest',true)`;
const outboxIdempotencyKey = `current_setting('app.b03_outbox_idempotency_key',true)`;
const outboxSecurity = Object.freeze({
  mode: "SECURITY DEFINER", ownerIdentity: "identity-auth-function-owner", ownerRole: "authOwner",
  searchPath: "pg_catalog,public", publicExecute: "revoked", runtimeExecuteGrantees: ["worker"],
  functionSource: outboxSource, rollbackDefinition: outboxRollback, deploymentPhase: "session-b-b03-outbox",
  ownerPrivileges: [
    ["AuditLogOutbox","SELECT",["id","payload","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","claimedAt","claimLeaseExpiresAt","status","attempts","nextAttemptAt","lastError","flushedAuditLogId","createdAt","updatedAt"]],
    ["AuditLogOutbox","INSERT",["id","payload","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","lastError","updatedAt"]],
    ["AuditLogOutbox","UPDATE",["status","attempts","nextAttemptAt","lastError","flushedAuditLogId","claimedAt","claimLeaseExpiresAt","updatedAt"]],
    ["SecurityEventOutbox","SELECT",["id","eventType","payload","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","claimedAt","claimLeaseExpiresAt","sinkEventId","status","attempts","nextAttemptAt","lastError","sentAt","createdAt","updatedAt"]],
    ["SecurityEventOutbox","INSERT",["id","eventType","payload","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","updatedAt"]],
    ["SecurityEventOutbox","UPDATE",["status","attempts","nextAttemptAt","lastError","sentAt","claimedAt","claimLeaseExpiresAt","sinkEventId","updatedAt"]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details","ipAddress","ipHash","userAgent"]],
  ],
  ownerPolicies: [
    ["AuditLogOutbox","SELECT",`current_user={{AUTH_OWNER}} AND ((session_user={{APP_ROLE}} AND ${outboxOperation}='audit-enqueue' AND (id=${outboxId} OR "idempotencyKey"=${outboxIdempotencyKey})) OR (session_user={{WORKER_ROLE}} AND ${outboxOperation} LIKE 'audit-%' AND (${outboxId}='' OR id=${outboxId}) AND (${outboxDigest}=repeat('0',64) OR "payloadDigest"=${outboxDigest})))`],
    ["AuditLogOutbox","INSERT",`current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND ${outboxOperation}='audit-enqueue' AND id=${outboxId} AND "payloadDigest"=${outboxDigest}`],
    ["AuditLogOutbox","UPDATE",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND ${outboxOperation} IN ('audit-claim','audit-consume','audit-fail') AND (${outboxId}='' OR id=${outboxId}) AND (${outboxDigest}=repeat('0',64) OR "payloadDigest"=${outboxDigest})`],
    ["SecurityEventOutbox","SELECT",`current_user={{AUTH_OWNER}} AND ((session_user={{APP_ROLE}} AND ${outboxOperation}='security-enqueue' AND (id=${outboxId} OR "idempotencyKey"=${outboxIdempotencyKey})) OR (session_user={{WORKER_ROLE}} AND ${outboxOperation} LIKE 'security-%' AND (${outboxId}='' OR id=${outboxId}) AND (${outboxDigest}=repeat('0',64) OR "payloadDigest"=${outboxDigest})))`],
    ["SecurityEventOutbox","INSERT",`current_user={{AUTH_OWNER}} AND ((session_user={{APP_ROLE}} AND ${outboxOperation}='security-enqueue' AND id=${outboxId} AND "payloadDigest"=${outboxDigest}) OR (session_user={{WORKER_ROLE}} AND ${outboxOperation}='audit-consume' AND id=current_setting('app.b03_security_outbox_id',true) AND "payloadDigest"=current_setting('app.b03_security_outbox_digest',true) AND "eventType"='AUDIT_LOG'))`],
    ["SecurityEventOutbox","UPDATE",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND ${outboxOperation} IN ('security-claim','security-complete','security-fail') AND (${outboxId}='' OR id=${outboxId}) AND (${outboxDigest}=repeat('0',64) OR "payloadDigest"=${outboxDigest})`],
    ["AuditLog","INSERT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND ${outboxOperation}='audit-consume' AND id IS NOT NULL AND "userId" IS NOT DISTINCT FROM NULLIF(current_setting('app.b03_audit_user_id',true),'') AND "orgId" IS NOT DISTINCT FROM NULLIF(current_setting('app.b03_audit_organization_id',true),'') AND "licenseeId" IS NOT DISTINCT FROM NULLIF(current_setting('app.b03_audit_licensee_id',true),'')`],
  ],
});
const b03AuthenticatedBinding = `app_rls.b03_authenticated_context_valid()`;
const b03AuthenticatedSecurity = Object.freeze({
  mode:"SECURITY DEFINER",ownerIdentity:"identity-auth-function-owner",ownerRole:"authOwner",
  searchPath:"pg_catalog,public",publicExecute:"revoked",runtimeExecuteGrantees:["app"],
  functionSource:b03AuthenticatedSource,rollbackDefinition:b03AuthenticatedRollback,
  deploymentPhase:"session-b-b03-authenticated",
  ownerPrivileges:[
    ["RefreshToken","SELECT",["id","userId","expiresAt","revokedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["User","SELECT",["id","email","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt","createdAt"]],
    ["Licensee","SELECT",["id","orgId","isActive","suspendedAt"]],
    ["Organization","SELECT",["id","isActive"]],
    ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId"]],
    ["Notification","SELECT",["id","userId","orgId","licenseeId","incidentId","audience","channel","type","title","body","data","readAt","emailedAt","createdAt","updatedAt"]],
    ["Notification","INSERT",["id","userId","orgId","licenseeId","incidentId","audience","channel","type","title","body","data","updatedAt"]],
    ["Notification","UPDATE",["readAt","emailedAt","updatedAt"]],
    ["Incident","SELECT",["id","qrCodeId","scanEventId","licenseeId"]],
    ["QRCode","SELECT",["id","batchId"]],
    ["Batch","SELECT",["id","manufacturerId"]],
    ["IncidentCommunication","SELECT",["id","incidentId","toAddress","subject","bodyPreview","attemptedFrom","usedFrom","replyTo","providerMessageId","errorMessage","status"]],
    ["IncidentCommunication","INSERT",["id","incidentId","direction","channel","toAddress","subject","bodyPreview","attemptedFrom","usedFrom","replyTo","status"]],
    ["IncidentCommunication","UPDATE",["providerMessageId","errorMessage","usedFrom","status"]],
    ["IncidentEvent","INSERT",["id","incidentId","actorType","actorUserId","eventType","eventPayload"]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details"]],
    ["ActionIdempotencyKey","SELECT",["id","keyHash","action","scope","requestHash","statusCode","responsePayload","completedAt","expiresAt"]],
    ["ActionIdempotencyKey","INSERT",["id","keyHash","action","scope","requestHash","responsePayload","expiresAt"]],
    ["ActionIdempotencyKey","UPDATE",["statusCode","responsePayload","completedAt"]],
  ],
  ownerPolicies:[
    ["RefreshToken","SELECT",`current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND current_setting('app.auth_session_verified',true)='1' AND id=current_setting('app.auth_session_id',true) AND "userId"=current_setting('app.user_id',true) AND "sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND "sessionCapabilityHashVersion"='sha256-v1'`],
    ["User","SELECT",`${b03AuthenticatedBinding} AND (id=current_setting('app.b03_actor_id',true) OR current_setting('app.b03_operation',true)='superadmin-read' OR (current_setting('app.b03_operation',true) IN ('notification-write','actor-read') AND (current_setting('app.b03_actor_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR "licenseeId"=current_setting('app.b03_licensee_id',true) OR id=current_setting('app.b03_target_user_id',true))))`],
    ["Licensee","SELECT",`${b03AuthenticatedBinding} AND (current_setting('app.b03_actor_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR id=current_setting('app.b03_actor_licensee_id',true) OR id=current_setting('app.b03_licensee_id',true))`],
    ["Organization","SELECT",`${b03AuthenticatedBinding} AND (current_setting('app.b03_actor_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR id=current_setting('app.b03_actor_org_id',true) OR id=current_setting('app.b03_organization_id',true))`],
    ["ManufacturerLicenseeLink","SELECT",`${b03AuthenticatedBinding} AND ("manufacturerId"=current_setting('app.b03_actor_id',true) OR "licenseeId"=current_setting('app.b03_licensee_id',true))`],
    ["Notification","SELECT",`${b03AuthenticatedBinding} AND (current_setting('app.b03_operation',true)='notification-read' OR id=current_setting('app.b03_notification_id',true))`],
    ["Notification","INSERT",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='notification-write' AND ("userId"=current_setting('app.b03_target_user_id',true) OR current_setting('app.b03_target_user_id',true)='')`],
    ["Notification","UPDATE",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true) IN ('notification-read-update','notification-email-update') AND (id=current_setting('app.b03_notification_id',true) OR "userId"=current_setting('app.b03_actor_id',true))`],
    ["Incident","SELECT",`${b03AuthenticatedBinding} AND (id=current_setting('app.b03_incident_id',true) OR "licenseeId"=current_setting('app.b03_licensee_id',true))`],
    ["QRCode","SELECT",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='incident-scope-read'`],
    ["Batch","SELECT",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='incident-scope-read'`],
    ["IncidentCommunication","SELECT",`${b03AuthenticatedBinding} AND id=current_setting('app.b03_delivery_id',true)`],
    ["IncidentCommunication","INSERT",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='incident-email-write' AND "incidentId"=current_setting('app.b03_incident_id',true)`],
    ["IncidentCommunication","UPDATE",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='incident-email-complete' AND "incidentId"=current_setting('app.b03_incident_id',true)`],
    ["IncidentEvent","INSERT",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='incident-email-complete' AND "incidentId"=current_setting('app.b03_incident_id',true) AND "actorUserId"=current_setting('app.b03_actor_id',true)`],
    ["AuditLog","INSERT",`${b03AuthenticatedBinding} AND current_setting('app.b03_operation',true)='incident-email-complete' AND "userId"=current_setting('app.b03_actor_id',true) AND "licenseeId"=current_setting('app.b03_licensee_id',true)`],
    ["ActionIdempotencyKey","SELECT",`${b03AuthenticatedBinding} AND action='b03-incident-email'`],
    ["ActionIdempotencyKey","INSERT",`${b03AuthenticatedBinding} AND action='b03-incident-email' AND scope=current_setting('app.b03_incident_id',true)`],
    ["ActionIdempotencyKey","UPDATE",`${b03AuthenticatedBinding} AND action='b03-incident-email'`],
  ],
});
const auditQueueWorkflow = "workflow-internal-backend-src-services-audit-log-outbox-service-ts-queue-audit-log-outbox";
const auditFlushWorkflow = "workflow-worker-backend-src-services-audit-log-outbox-service-ts-flush-audit-log-outbox";
const securityQueueWorkflow = "workflow-internal-backend-src-services-siem-outbox-service-ts-queue-security-event";
const securityFlushWorkflow = "workflow-worker-backend-src-services-siem-outbox-service-ts-flush-security-event-outbox";
const operationalReadSecurity = Object.freeze({
  mode:"SECURITY DEFINER",ownerIdentity:"identity-auth-function-owner",ownerRole:"authOwner",
  searchPath:"pg_catalog,public",publicExecute:"revoked",runtimeExecuteGrantees:["app"],
  functionSource:operationalReadSource,rollbackDefinition:operationalReadRollback,deploymentPhase:"session-a-operational-read",
  ownerPrivileges:[
    ["User","SELECT",["id","email","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt"]],
    ["Licensee","SELECT",["id","orgId","name","prefix","brandName","isActive","suspendedAt"]],
    ["Organization","SELECT",["id","isActive"]],
    ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId","isPrimary","updatedAt"]],
    ["Batch","SELECT",["id","name","licenseeId","manufacturerId","parentBatchId","rootBatchId","startCode","endCode","totalCodes","lifecycleState","sampleScanPolicy","metadata","releasedAt","releasedByUserId","printedAt","suspendedAt","suspendedReason","printPackDownloadedAt","printPackDownloadedByUserId","createdAt","updatedAt"]],
    ["QRCode","SELECT",["id","code","displayCode","licenseeId","batchId","status","printJobId"]],
    ["InventoryStatusRollup","SELECT",["batchId","licenseeId","manufacturerId","totalCodes","dormant","active","activated","allocated","printed","redeemed","blocked","scanned"]],
    ["PrintItem","SELECT",["id","printSessionId","qrCodeId","state","agentAckedAt","dispatchedAt","deviceJobRef","printConfirmedAt","confirmationEvidence","deadLetterReason","failureReason"]],
    ["PrintSession","SELECT",["id","printJobId","batchId","status"]],
    ["PrintJob","SELECT",["id","batchId","status"]],
    ["AuditLog","SELECT",["id","userId","orgId","licenseeId","action","entityType","entityId","details"]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details"]],
  ],
  ownerPolicies:[],
});
const tenantDirectorySessionBinding = `(current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.tenant_directory_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.tenant_directory_user_id',true)=current_setting('app.user_id',true) AND current_setting('app.tenant_directory_role',true)=current_setting('app.role',true) AND current_setting('app.tenant_directory_operation',true) IN ('licensees','users') AND EXISTS (SELECT 1 FROM public."RefreshToken" directory_session WHERE directory_session.id=current_setting('app.tenant_directory_session_id',true) AND directory_session."userId"=current_setting('app.tenant_directory_user_id',true) AND directory_session."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND directory_session."sessionCapabilityHashVersion"='sha256-v1' AND directory_session."sessionCapabilityRevokedAt" IS NULL AND directory_session."sessionCapabilityExpiresAt">clock_timestamp() AND directory_session."revokedAt" IS NULL AND directory_session."expiresAt">clock_timestamp()))`;
const tenantDirectoryRole = `current_setting('app.tenant_directory_role',true)`;
const tenantDirectoryUser = `current_setting('app.tenant_directory_user_id',true)`;
const tenantDirectoryOrganization = `current_setting('app.tenant_directory_organization_id',true)`;
const tenantDirectoryLicensee = `current_setting('app.tenant_directory_licensee_id',true)`;
const tenantDirectoryScope = `string_to_array(current_setting('app.tenant_directory_scope_licensee_ids',true),',')`;
const tenantDirectoryOrganizationScope = `string_to_array(current_setting('app.tenant_directory_scope_organization_ids',true),',')`;
const tenantDirectoryUserScope = `string_to_array(current_setting('app.tenant_directory_scope_user_ids',true),',')`;
const tenantDirectoryPlatform = `${tenantDirectoryRole} IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')`;
const tenantDirectoryTenant = `${tenantDirectoryRole}='LICENSEE_ADMIN'`;
const tenantDirectoryManufacturer = `${tenantDirectoryRole}='MANUFACTURER_ADMIN'`;
const tenantDirectorySecurity = Object.freeze({
  ...operationalReadSecurity,
  ownerPrivileges: [
    ["User","SELECT",["id","email","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt","createdAt","location","website"]],
    ["Licensee","SELECT",["id","orgId","name","prefix","description","brandName","location","website","supportEmail","supportPhone","metadata","isActive","suspendedAt","suspendedReason","createdAt","updatedAt"]],
    ["Organization","SELECT",["id","isActive"]],
    ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId","isPrimary","createdAt","updatedAt"]],
    ["Invite","SELECT",["id","licenseeId","email","role","expiresAt","usedAt","createdAt"]],
    ["Batch","SELECT",["id","licenseeId"]],
    ["QRCode","SELECT",["id","licenseeId"]],
    ["QRRange","SELECT",["id","licenseeId","startCode","endCode","totalCodes","usedCodes","createdAt","updatedAt"]],
  ],
  ownerPolicies: [
    ["Licensee","SELECT",`${tenantDirectorySessionBinding} AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR id=ANY(${tenantDirectoryScope}))) OR (${tenantDirectoryTenant} AND id=${tenantDirectoryLicensee} AND "orgId"=${tenantDirectoryOrganization} AND "isActive" AND "suspendedAt" IS NULL) OR (${tenantDirectoryManufacturer} AND id=ANY(${tenantDirectoryScope}) AND "isActive" AND "suspendedAt" IS NULL))`],
    ["Organization","SELECT",`${tenantDirectorySessionBinding} AND ((${tenantDirectoryPlatform}) OR (${tenantDirectoryTenant} AND id=${tenantDirectoryOrganization} AND "isActive") OR (${tenantDirectoryManufacturer} AND id=ANY(${tenantDirectoryOrganizationScope}) AND "isActive"))`],
    ["ManufacturerLicenseeLink","SELECT",`${tenantDirectorySessionBinding} AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR "licenseeId"=ANY(${tenantDirectoryScope}))) OR (${tenantDirectoryTenant} AND "licenseeId"=${tenantDirectoryLicensee}) OR (${tenantDirectoryManufacturer} AND ((current_setting('app.tenant_directory_scope_licensee_ids',true)='' AND "manufacturerId"=${tenantDirectoryUser}) OR "licenseeId"=ANY(${tenantDirectoryScope}))))`],
    ["User","SELECT",`${tenantDirectorySessionBinding} AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR "licenseeId"=ANY(${tenantDirectoryScope}) OR id=ANY(${tenantDirectoryUserScope}))) OR ((${tenantDirectoryTenant} OR ${tenantDirectoryManufacturer}) AND ("licenseeId"=ANY(${tenantDirectoryScope}) OR id=ANY(${tenantDirectoryUserScope}))))`],
    ["Invite","SELECT",`${tenantDirectorySessionBinding} AND current_setting('app.tenant_directory_operation',true)='licensees' AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR "licenseeId"=ANY(${tenantDirectoryScope}))) OR (${tenantDirectoryTenant} AND "licenseeId"=${tenantDirectoryLicensee}))`],
    ["Batch","SELECT",`${tenantDirectorySessionBinding} AND current_setting('app.tenant_directory_operation',true)='licensees' AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR "licenseeId"=ANY(${tenantDirectoryScope}))) OR ((${tenantDirectoryTenant} OR ${tenantDirectoryManufacturer}) AND "licenseeId"=ANY(${tenantDirectoryScope})))`],
    ["QRCode","SELECT",`${tenantDirectorySessionBinding} AND current_setting('app.tenant_directory_operation',true)='licensees' AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR "licenseeId"=ANY(${tenantDirectoryScope}))) OR ((${tenantDirectoryTenant} OR ${tenantDirectoryManufacturer}) AND "licenseeId"=ANY(${tenantDirectoryScope})))`],
    ["QRRange","SELECT",`${tenantDirectorySessionBinding} AND current_setting('app.tenant_directory_operation',true)='licensees' AND ((${tenantDirectoryPlatform} AND (current_setting('app.tenant_directory_scope_licensee_ids',true)='' OR "licenseeId"=ANY(${tenantDirectoryScope}))) OR ((${tenantDirectoryTenant} OR ${tenantDirectoryManufacturer}) AND "licenseeId"=ANY(${tenantDirectoryScope})))`],
  ],
});

const adminSession = `(current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.admin_mutation_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.admin_mutation_user_id',true)=current_setting('app.user_id',true) AND current_setting('app.admin_mutation_role',true)=current_setting('app.role',true) AND current_setting('app.admin_mutation_operation',true) IN ('administration-create-licensee','administration-update-licensee','administration-delete-licensee','administration-create-user','administration-update-user','administration-delete-user','administration-restore-manufacturer','auth-invite-create','licensee-admin-invite-resend') AND EXISTS (SELECT 1 FROM public."RefreshToken" admin_session WHERE admin_session.id=current_setting('app.admin_mutation_session_id',true) AND admin_session."userId"=current_setting('app.admin_mutation_user_id',true) AND admin_session."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND admin_session."sessionCapabilityHashVersion"='sha256-v1' AND admin_session."sessionCapabilityRevokedAt" IS NULL AND admin_session."sessionCapabilityExpiresAt">clock_timestamp() AND admin_session."revokedAt" IS NULL AND admin_session."expiresAt">clock_timestamp()))`;
const adminOperation = `current_setting('app.admin_mutation_operation',true)`;
const adminUser = `current_setting('app.admin_mutation_user_id',true)`;
const adminTargetUser = `current_setting('app.admin_mutation_target_user_id',true)`;
const adminTargetLicensee = `current_setting('app.admin_mutation_target_licensee_id',true)`;
const adminTargetOrganization = `current_setting('app.admin_mutation_target_organization_id',true)`;
const administrationSecurity = Object.freeze({
  mode:"SECURITY DEFINER",ownerIdentity:"identity-auth-function-owner",ownerRole:"authOwner",
  searchPath:"pg_catalog,public",publicExecute:"revoked",runtimeExecuteGrantees:["app"],
  functionSource:administrationSource,rollbackDefinition:administrationRollback,deploymentPhase:"session-c-c01-administration",
  ownerPrivileges:[
    ["User","SELECT",["id","email","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt","passwordHash","location","website","createdAt"]],
    ["User","INSERT",["id","email","passwordHash","name","role","orgId","licenseeId","location","website","status","isActive","emailVerifiedAt","updatedAt"]],
    ["User","UPDATE",["email","passwordHash","name","orgId","licenseeId","location","website","status","isActive","disabledAt","deletedAt","updatedAt"]],
    ["User","DELETE",[]],
    ["Organization","SELECT",["id","name","isActive"]],
    ["Organization","INSERT",["id","name","isActive","updatedAt"]],
    ["Licensee","SELECT",["id","orgId","name","prefix","description","brandName","location","website","supportEmail","supportPhone","isActive","suspendedAt","createdAt","updatedAt"]],
    ["Licensee","INSERT",["id","orgId","name","prefix","description","brandName","location","website","supportEmail","supportPhone","isActive","updatedAt"]],
    ["Licensee","UPDATE",["name","description","brandName","location","website","supportEmail","supportPhone","isActive","updatedAt"]],
    ["Licensee","DELETE",[]],
    ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId","isPrimary","createdAt"]],
    ["ManufacturerLicenseeLink","INSERT",["manufacturerId","licenseeId","isPrimary","updatedAt"]],
    ["ManufacturerLicenseeLink","UPDATE",["isPrimary","updatedAt"]],
    ["ManufacturerLicenseeLink","DELETE",[]],
    ["RefreshToken","SELECT",["id","userId","expiresAt","revokedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["RefreshToken","UPDATE",["revokedAt","revokedReason","sessionCapabilityRevokedAt","sessionCapabilityRevokedReason"]],
    ["Batch","SELECT",["id","licenseeId","manufacturerId"]],
    ["Batch","UPDATE",["manufacturerId","updatedAt"]],
    ["QRRange","SELECT",["id","licenseeId"]],
    ["QRCode","SELECT",["id","licenseeId"]],
    ["ActionIdempotencyKey","SELECT",["keyHash","requestHash","completedAt","responsePayload"]],
    ["ActionIdempotencyKey","INSERT",["id","keyHash","action","scope","requestHash","expiresAt"]],
    ["ActionIdempotencyKey","UPDATE",["statusCode","responsePayload","completedAt"]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details","ipHash","userAgent","createdAt"]],
    ["SecurityEventOutbox","INSERT",["id","eventType","payload","requestId","organizationId","licenseeId","initiatingUserId","updatedAt"]],
    ["Invite","SELECT",["id","orgId","licenseeId","email","role","manufacturerId","tokenHash","expiresAt","usedAt","createdByUserId","createdAt"]],
    ["Invite","INSERT",["id","orgId","licenseeId","email","role","manufacturerId","tokenHash","expiresAt","createdByUserId","createdAt"]],
    ["Invite","UPDATE",["usedAt"]],
  ],
  ownerPolicies:[
    ["User","SELECT",`${adminSession} AND (id=${adminUser} OR id=${adminTargetUser} OR email=current_setting('app.admin_mutation_target_email',true) OR (${adminOperation}='licensee-admin-invite-resend' AND "licenseeId"=${adminTargetLicensee} AND role::text='LICENSEE_ADMIN'))`],
    ["User","INSERT",`${adminSession} AND ${adminOperation} IN ('administration-create-licensee','administration-create-user','auth-invite-create') AND id=${adminTargetUser} AND role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') AND ((role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND "orgId" IS NULL AND "licenseeId" IS NULL) OR (role::text IN ('LICENSEE_ADMIN','MANUFACTURER_ADMIN') AND "orgId"=${adminTargetOrganization} AND "licenseeId"=${adminTargetLicensee}))`],
    ["User","UPDATE",`${adminSession} AND ${adminOperation} IN ('administration-update-user','administration-delete-user','administration-restore-manufacturer') AND id=${adminTargetUser}`],
    ["User","DELETE",`${adminSession} AND ${adminOperation}='administration-delete-user' AND id=${adminTargetUser} AND current_setting('app.admin_mutation_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')`],
    ["Organization","SELECT",`${adminSession} AND id=${adminTargetOrganization}`],
    ["Organization","INSERT",`${adminSession} AND ${adminOperation} IN ('administration-create-licensee','auth-invite-create') AND id=${adminTargetOrganization}`],
    ["Licensee","SELECT",`${adminSession} AND id=${adminTargetLicensee} AND (current_setting('app.admin_mutation_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR id=current_setting('app.admin_mutation_licensee_id',true)) AND (${adminTargetOrganization}='' OR "orgId"=${adminTargetOrganization})`],
    ["Licensee","INSERT",`${adminSession} AND ${adminOperation}='administration-create-licensee' AND id=${adminTargetLicensee} AND "orgId"=${adminTargetOrganization}`],
    ["Licensee","UPDATE",`${adminSession} AND ${adminOperation}='administration-update-licensee' AND id=${adminTargetLicensee} AND "orgId"=${adminTargetOrganization}`],
    ["Licensee","DELETE",`${adminSession} AND ${adminOperation}='administration-delete-licensee' AND id=${adminTargetLicensee} AND "orgId"=${adminTargetOrganization}`],
    ["ManufacturerLicenseeLink","SELECT",`${adminSession} AND "manufacturerId"=${adminTargetUser}`],
    ["ManufacturerLicenseeLink","INSERT",`${adminSession} AND ${adminOperation} IN ('administration-create-user','administration-update-user','administration-restore-manufacturer','auth-invite-create') AND "manufacturerId"=${adminTargetUser}`],
    ["ManufacturerLicenseeLink","UPDATE",`${adminSession} AND ${adminOperation} IN ('administration-update-user','administration-delete-user','administration-restore-manufacturer') AND "manufacturerId"=${adminTargetUser}`],
    ["ManufacturerLicenseeLink","DELETE",`${adminSession} AND ${adminOperation}='administration-delete-user' AND "manufacturerId"=${adminTargetUser}`],
    ["RefreshToken","UPDATE",`current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND ${adminOperation} IN ('administration-update-user','administration-delete-user') AND "userId"=${adminTargetUser}`],
    ["Batch","SELECT",`${adminSession} AND ((${adminOperation}='administration-delete-licensee' AND "licenseeId"=${adminTargetLicensee}) OR (${adminOperation}='administration-delete-user' AND "manufacturerId"=${adminTargetUser}))`],
    ["Batch","UPDATE",`${adminSession} AND ${adminOperation}='administration-delete-user' AND "manufacturerId"=${adminTargetUser} AND current_setting('app.admin_mutation_role',true) IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')`],
    ["QRRange","SELECT",`${adminSession} AND ${adminOperation}='administration-delete-licensee' AND "licenseeId"=${adminTargetLicensee}`],
    ["QRCode","SELECT",`${adminSession} AND ${adminOperation}='administration-delete-licensee' AND "licenseeId"=${adminTargetLicensee}`],
    ["ActionIdempotencyKey","SELECT",`${adminSession} AND ${adminOperation} IN ('administration-create-licensee','auth-invite-create','licensee-admin-invite-resend') AND "keyHash"=current_setting('app.admin_mutation_idempotency_hash',true)`],
    ["ActionIdempotencyKey","INSERT",`${adminSession} AND ${adminOperation} IN ('administration-create-licensee','auth-invite-create','licensee-admin-invite-resend') AND "keyHash"=current_setting('app.admin_mutation_idempotency_hash',true)`],
    ["ActionIdempotencyKey","UPDATE",`${adminSession} AND ${adminOperation} IN ('administration-create-licensee','auth-invite-create','licensee-admin-invite-resend') AND "keyHash"=current_setting('app.admin_mutation_idempotency_hash',true)`],
    ["Invite","SELECT",`${adminSession} AND ${adminOperation} IN ('auth-invite-create','licensee-admin-invite-resend') AND (id=current_setting('app.admin_mutation_invite_id',true) OR (email=current_setting('app.admin_mutation_target_email',true) AND "licenseeId" IS NOT DISTINCT FROM nullif(${adminTargetLicensee},'')))`],
    ["Invite","INSERT",`${adminSession} AND ${adminOperation} IN ('auth-invite-create','licensee-admin-invite-resend') AND id=current_setting('app.admin_mutation_invite_id',true) AND email=current_setting('app.admin_mutation_target_email',true) AND "orgId"=${adminTargetOrganization}`],
    ["Invite","UPDATE",`${adminSession} AND ${adminOperation} IN ('auth-invite-create','licensee-admin-invite-resend') AND email=current_setting('app.admin_mutation_target_email',true) AND "licenseeId" IS NOT DISTINCT FROM nullif(${adminTargetLicensee},'')`],
    ["AuditLog","INSERT",`${adminSession} AND id=current_setting('app.admin_mutation_audit_id',true) AND "userId"=${adminUser}`],
    ["SecurityEventOutbox","INSERT",`${adminSession} AND id=current_setting('app.admin_mutation_outbox_id',true) AND "initiatingUserId"=${adminUser}`],
  ],
});

const qrSession = `(current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.qr_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.qr_user_id',true)=current_setting('app.user_id',true) AND current_setting('app.qr_role',true)=current_setting('app.role',true) AND current_setting('app.qr_operation',true) IN ('qr-range-allocate','qr-code-read','qr-code-stats','qr-code-delete','qr-code-token-bind','qr-code-scope','qr-batch-command','qr-allocation-request-approve','qr-inventory-read','qr-audit-export') AND EXISTS (SELECT 1 FROM public."RefreshToken" qr_session WHERE qr_session.id=current_setting('app.qr_session_id',true) AND qr_session."userId"=current_setting('app.qr_user_id',true) AND qr_session."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND qr_session."sessionCapabilityHashVersion"='sha256-v1' AND qr_session."sessionCapabilityRevokedAt" IS NULL AND qr_session."sessionCapabilityExpiresAt">clock_timestamp() AND qr_session."revokedAt" IS NULL AND qr_session."expiresAt">clock_timestamp()))`;
const qrRole = `current_setting('app.qr_role',true)`;
const qrUser = `current_setting('app.qr_user_id',true)`;
const qrLicensee = `current_setting('app.qr_licensee_id',true)`;
const qrTargetLicensee = `current_setting('app.qr_target_licensee_id',true)`;
const qrTargetBatch = `current_setting('app.qr_target_batch_id',true)`;
const qrSourceBatch = `current_setting('app.qr_source_batch_id',true)`;
const qrBatchIds = `string_to_array(current_setting('app.qr_target_batch_ids',true),',')`;
const qrCodeIds = `string_to_array(current_setting('app.qr_target_code_ids',true),',')`;
const qrUserIds = `string_to_array(current_setting('app.qr_target_user_ids',true),',')`;
const qrRequest = `current_setting('app.qr_target_request_id',true)`;
const qrScope = `string_to_array(current_setting('app.qr_scope_licensee_ids',true),',')`;
const qrVisible = `(${qrRole} IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR (${qrRole}='LICENSEE_ADMIN' AND "licenseeId"=${qrLicensee}) OR (${qrRole}='MANUFACTURER_ADMIN' AND "licenseeId"=ANY(${qrScope})))`;
const qrDeleteVisible = `(${qrRole} IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR (${qrRole}='LICENSEE_ADMIN' AND "licenseeId"=${qrLicensee}))`;
const qrSystemSecurity = Object.freeze({
  mode:"SECURITY DEFINER",ownerIdentity:"identity-auth-function-owner",ownerRole:"authOwner",
  searchPath:"pg_catalog,public",publicExecute:"revoked",runtimeExecuteGrantees:["app"],
  functionSource:qrSystemSource,rollbackDefinition:qrSystemRollback,deploymentPhase:"release-fix-4-qr-system",
  ownerPrivileges:[
    ["RefreshToken","SELECT",["id","userId","expiresAt","revokedAt","sessionCapabilityHash","sessionCapabilityHashVersion","sessionCapabilityExpiresAt","sessionCapabilityRevokedAt"]],
    ["RefreshToken","UPDATE",["sessionCapabilityLastUsedAt"]],
    ["User","SELECT",["id","email","name","role","orgId","licenseeId","status","isActive","disabledAt","deletedAt"]],
    ["Organization","SELECT",["id","isActive"]],
    ["Licensee","SELECT",["id","orgId","name","prefix","isActive","suspendedAt"]],
    ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId"]],
    ["QRRange","SELECT",["id","licenseeId","startCode","endCode","totalCodes","usedCodes","createdAt","updatedAt"]],
    ["QRRange","INSERT",["id","licenseeId","startCode","endCode","totalCodes","usedCodes","updatedAt"]],
    ["QRCode","SELECT",["id","code","displayCode","licenseeId","batchId","status","scanCount","createdAt","updatedAt","scannedAt","printedAt","blockedAt","redeemedAt","printJobId","replayEpoch","tokenNonce","tokenIssuedAt","tokenExpiresAt","tokenHash"]],
    ["QRCode","INSERT",["id","code","displayCode","licenseeId","batchId","status","tokenNonce","updatedAt"]],
    ["QRCode","UPDATE",["batchId","status","printJobId","tokenNonce","tokenIssuedAt","tokenExpiresAt","tokenHash","issuanceMode","customerVerifiableAt","printedAt","printedByUserId","redeemedAt","redeemedDeviceFingerprint","updatedAt"]],
    ["QRCode","DELETE",[]],
    ["Batch","SELECT",["id","licenseeId","name","manufacturerId","parentBatchId","rootBatchId","startCode","endCode","totalCodes","lifecycleState","printedAt","releasedAt","createdAt","updatedAt"]],
    ["Batch","INSERT",["id","name","licenseeId","manufacturerId","parentBatchId","rootBatchId","startCode","endCode","totalCodes","lifecycleState","updatedAt"]],
    ["Batch","UPDATE",["name","startCode","endCode","totalCodes","updatedAt"]],
    ["Batch","DELETE",[]],
    ["QrAllocationRequest","SELECT",["id","licenseeId","requestedByUserId","quantity","startNumber","endNumber","batchName","status"]],
    ["QrAllocationRequest","UPDATE",["status","approvedByUserId","approvedAt","decisionNote","startNumber","endNumber","quantity","updatedAt"]],
    ["AllocationEvent","INSERT",["id","licenseeId","createdByUserId","requestId","source","startCode","endCode","totalCodes"]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details","createdAt"]],
    ["SecurityEventOutbox","INSERT",["id","eventType","payload","requestId","organizationId","licenseeId","initiatingUserId","updatedAt"]],
    ["TraceEvent","SELECT",["id","eventType","licenseeId","batchId","qrCodeId","manufacturerId","userId","sourceAction","details","createdAt"]],
    ["PolicyAlert","SELECT",["id","licenseeId","alertType","severity","message","score","batchId","qrCodeId","manufacturerId","acknowledgedAt","acknowledgedByUserId","details","createdAt"]],
    ["InventoryStatusRollup","INSERT",["batchId","licenseeId","manufacturerId","totalCodes","dormant","active","activated","allocated","printed","redeemed","blocked","scanned","refreshedAt","createdAt","updatedAt"]],
    ["InventoryStatusRollup","SELECT",["batchId","licenseeId","manufacturerId","totalCodes","dormant","active","activated","allocated","printed","redeemed","blocked","scanned","refreshedAt","createdAt","updatedAt"]],
    ["InventoryStatusRollup","UPDATE",["licenseeId","manufacturerId","totalCodes","dormant","active","activated","allocated","printed","redeemed","blocked","scanned","refreshedAt","updatedAt"]],
    ["QrScanLog","SELECT",["qrCodeId","licenseeId","batchId","status","scannedAt","isFirstScan","isTrustedOwnerContext","device","locationName","locationCountry","locationCity"]],
    ["ScanMetricsHourlyRollup","INSERT",["id","bucketKey","hourBucket","licenseeId","batchId","manufacturerId","totalScanEvents","firstScanEvents","repeatScanEvents","blockedEvents","trustedOwnerEvents","externalEvents","namedLocationEvents","knownDeviceEvents","uniqueQrCodes","firstScannedAt","lastScannedAt","createdAt","updatedAt"]],
    ["ScanMetricsHourlyRollup","SELECT",["bucketKey","totalScanEvents","firstScanEvents","repeatScanEvents","blockedEvents","trustedOwnerEvents","externalEvents","namedLocationEvents","knownDeviceEvents","uniqueQrCodes","firstScannedAt","lastScannedAt","updatedAt"]],
    ["ScanMetricsHourlyRollup","UPDATE",["totalScanEvents","firstScanEvents","repeatScanEvents","blockedEvents","trustedOwnerEvents","externalEvents","namedLocationEvents","knownDeviceEvents","uniqueQrCodes","firstScannedAt","lastScannedAt","updatedAt"]],
    ["SystemCheckpoint","SELECT",["key","value"]],
    ["SystemCheckpoint","INSERT",["key","value","createdAt","updatedAt"]],
    ["SystemCheckpoint","UPDATE",["value","updatedAt"]],
  ],
  ownerPolicies:[
    ["Organization","SELECT",`${qrSession} AND id=current_setting('app.qr_target_organization_id',true) AND "isActive"`],
    ["Licensee","SELECT",`${qrSession} AND (${qrTargetLicensee}='' OR id=${qrTargetLicensee}) AND (${qrRole} IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') OR (${qrRole}='LICENSEE_ADMIN' AND id=${qrLicensee}) OR ${qrRole}='MANUFACTURER_ADMIN')`],
    ["ManufacturerLicenseeLink","SELECT",`${qrSession} AND ("manufacturerId"=${qrUser} OR (current_setting('app.qr_operation',true)='qr-batch-command' AND "manufacturerId"=current_setting('app.qr_target_manufacturer_id',true) AND "licenseeId"=${qrTargetLicensee}))`],
    ["User","SELECT",`${qrSession} AND ((current_setting('app.qr_operation',true)='qr-batch-command' AND role='MANUFACTURER_ADMIN' AND "isActive" AND status='ACTIVE' AND "disabledAt" IS NULL AND "deletedAt" IS NULL AND id=current_setting('app.qr_target_manufacturer_id',true)) OR (current_setting('app.qr_operation',true)='qr-audit-export' AND (id=current_setting('app.qr_target_manufacturer_id',true) OR id=ANY(${qrUserIds}))))`],
    ["TraceEvent","SELECT",`${qrSession} AND current_setting('app.qr_operation',true)='qr-audit-export' AND "batchId"=${qrSourceBatch} AND "licenseeId"=${qrTargetLicensee}`],
    ["PolicyAlert","SELECT",`${qrSession} AND current_setting('app.qr_operation',true)='qr-audit-export' AND "batchId"=${qrSourceBatch} AND "licenseeId"=${qrTargetLicensee}`],
    ["QRRange","SELECT",`${qrSession} AND ${qrVisible}`],
    ["QRRange","INSERT",`${qrSession} AND current_setting('app.qr_operation',true)='qr-range-allocate' AND "licenseeId"=${qrTargetLicensee}`],
    ["QRCode","SELECT",`(${qrSession} AND ${qrVisible}) OR (current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='inventory')`],
    ["QRCode","INSERT",`${qrSession} AND current_setting('app.qr_operation',true)='qr-range-allocate' AND "licenseeId"=${qrTargetLicensee} AND "batchId"=${qrTargetBatch}`],
    ["QRCode","UPDATE",`${qrSession} AND ((current_setting('app.qr_operation',true)='qr-code-token-bind' AND "licenseeId"=${qrTargetLicensee}) OR (current_setting('app.qr_operation',true)='qr-batch-command' AND ${qrVisible} AND ((current_setting('app.qr_batch_action',true)='CREATE_BATCH' AND "batchId" IS NULL AND "licenseeId"=${qrTargetLicensee}) OR id=ANY(${qrCodeIds}) OR "batchId"=ANY(${qrBatchIds}) OR "batchId"=${qrSourceBatch})))`],
    ["QRCode","DELETE",`${qrSession} AND current_setting('app.qr_operation',true)='qr-code-delete' AND ${qrDeleteVisible}`],
    ["Batch","SELECT",`(${qrSession} AND ${qrVisible}) OR (current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true) IN ('inventory','scan-hourly'))`],
    ["Batch","INSERT",`${qrSession} AND current_setting('app.qr_operation',true) IN ('qr-range-allocate','qr-batch-command') AND "licenseeId"=${qrTargetLicensee} AND id=${qrTargetBatch}`],
    ["Batch","UPDATE",`${qrSession} AND current_setting('app.qr_operation',true)='qr-batch-command' AND ${qrVisible} AND id=${qrSourceBatch}`],
    ["Batch","DELETE",`${qrSession} AND current_setting('app.qr_operation',true)='qr-batch-command' AND ${qrVisible} AND (id=${qrSourceBatch} OR id=ANY(${qrBatchIds}))`],
    ["QrAllocationRequest","SELECT",`${qrSession} AND current_setting('app.qr_operation',true)='qr-allocation-request-approve' AND ${qrRole} IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND id=${qrRequest}`],
    ["QrAllocationRequest","UPDATE",`${qrSession} AND current_setting('app.qr_operation',true)='qr-allocation-request-approve' AND ${qrRole} IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND id=${qrRequest}`],
    ["AllocationEvent","INSERT",`${qrSession} AND current_setting('app.qr_operation',true)='qr-range-allocate' AND "licenseeId"=${qrTargetLicensee} AND "createdByUserId"=${qrUser}`],
    ["AuditLog","INSERT",`${qrSession} AND id=current_setting('app.qr_audit_id',true) AND "userId"=${qrUser}`],
    ["SecurityEventOutbox","INSERT",`${qrSession} AND id=current_setting('app.qr_outbox_id',true) AND "initiatingUserId"=${qrUser}`],
    ["InventoryStatusRollup","INSERT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='inventory'`],
    ["InventoryStatusRollup","SELECT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='inventory'`],
    ["InventoryStatusRollup","UPDATE",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='inventory'`],
    ["QrScanLog","SELECT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='scan-hourly'`],
    ["ScanMetricsHourlyRollup","INSERT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='scan-hourly'`],
    ["ScanMetricsHourlyRollup","SELECT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='scan-hourly'`],
    ["ScanMetricsHourlyRollup","UPDATE",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true)='scan-hourly'`],
    ["SystemCheckpoint","SELECT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true) IN ('inventory','scan-hourly') AND "key"=CASE current_setting('app.analytics_rollup_operation',true) WHEN 'inventory' THEN 'rollup:inventory-status' ELSE 'rollup:scan-metrics-hourly' END`],
    ["SystemCheckpoint","INSERT",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true) IN ('inventory','scan-hourly') AND "key"=CASE current_setting('app.analytics_rollup_operation',true) WHEN 'inventory' THEN 'rollup:inventory-status' ELSE 'rollup:scan-metrics-hourly' END`],
    ["SystemCheckpoint","UPDATE",`current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND current_setting('app.analytics_rollup_operation',true) IN ('inventory','scan-hourly') AND "key"=CASE current_setting('app.analytics_rollup_operation',true) WHEN 'inventory' THEN 'rollup:inventory-status' ELSE 'rollup:scan-metrics-hourly' END`],
  ],
});

const printingOperation = `current_setting('app.printing_operation',true)`;
const printingSession = `current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND current_setting('app.printing_session_id',true)<>''`;
const printingBatchId = `current_setting('app.printing_batch_id',true)`;
const printingJobId = `current_setting('app.printing_job_id',true)`;
const printingSessionRowId = `current_setting('app.printing_session_row_id',true)`;
const printingItemId = `current_setting('app.printing_item_id',true)`;
const printingPrinterId = `current_setting('app.printing_printer_id',true)`;
const printingRegistrationId = `current_setting('app.printing_registration_id',true)`;
const printingReissueId = `current_setting('app.printing_reissue_id',true)`;
const printingIdempotencyKeyHash = `current_setting('app.printing_idempotency_key_hash',true)`;
const printingConnector = `current_user={{AUTH_OWNER}} AND session_user={{APP_ROLE}} AND ${printingOperation} LIKE 'printing-connector-%'`;
const printingConnectorEvidence = `${printingConnector} AND ${printingOperation} IN ('printing-connector-test-label-ack','printing-connector-test-label-confirm','printing-connector-test-label-fail')`;
const printingWorker = `current_user={{AUTH_OWNER}} AND session_user={{WORKER_ROLE}} AND ${printingOperation} LIKE 'printing-worker-%'`;
const printingOwnerPrivileges = [
  ["Batch","SELECT",["id","name","licenseeId","manufacturerId","startCode","lifecycleState","sampleScanPolicy","metadata","totalCodes","printedAt","releasedAt","releasedByUserId","suspendedAt","updatedAt"]],
  ["Batch","UPDATE",["lifecycleState","printedAt","releasedAt","releasedByUserId","updatedAt"]],
  ["QRCode","SELECT",["id","code","displayCode","licenseeId","batchId","status","printJobId","replayEpoch","tokenNonce","tokenIssuedAt","tokenExpiresAt","tokenHash","printedAt","scannedAt","scanCount"]],
  ["QRCode","UPDATE",["status","printJobId","tokenNonce","tokenIssuedAt","tokenExpiresAt","tokenHash","issuanceMode","printedAt","printedByUserId","customerVerifiableAt","updatedAt"]],
  ["PrintJob","SELECT",["id","jobNumber","batchId","manufacturerId","printerId","status","printMode","pipelineState","payloadType","payloadHash","quantity","itemCount","rangeStart","rangeEnd","sentAt","completedAt","failureReason","reprintOfJobId","approvedByUserId","reprintReason","printLockTokenHash","confirmedAt","createdAt","updatedAt"]],
  ["PrintJob","INSERT",["id","jobNumber","batchId","manufacturerId","printerId","status","printMode","pipelineState","payloadType","quantity","itemCount","rangeStart","rangeEnd","printLockTokenHash","reprintOfJobId","approvedByUserId","reprintReason","createdAt","updatedAt"]],
  ["PrintJob","UPDATE",["status","pipelineState","sentAt","completedAt","failureReason","confirmedAt","updatedAt"]],
  ["PrintSession","SELECT",["id","printJobId","batchId","manufacturerId","printerRegistrationId","printerId","status","totalItems","issuedItems","confirmedItems","frozenItems","failedReason","startedAt","completedAt","createdAt","updatedAt"]],
  ["PrintSession","INSERT",["id","printJobId","batchId","manufacturerId","printerRegistrationId","printerId","status","totalItems","createdAt","updatedAt"]],
  ["PrintSession","UPDATE",["status","issuedItems","confirmedItems","failedReason","completedAt","updatedAt"]],
  ["PrintItem","SELECT",["id","printSessionId","qrCodeId","code","state","pipelineState","issueSequence","attemptCount","currentRenderTokenHash","deviceJobRef","dispatchMetadata","confirmationEvidence","issuedAt","dispatchedAt","agentAckedAt","confirmationDeadlineAt","printConfirmedAt","closedAt","frozenAt","failedAt","failureReason","deadLetterReason","createdAt","updatedAt"]],
  ["PrintItem","INSERT",["id","printSessionId","qrCodeId","code","state","pipelineState","issueSequence","createdAt","updatedAt"]],
  ["PrintItem","UPDATE",["printSessionId","state","pipelineState","issueSequence","attemptCount","deviceJobRef","dispatchMetadata","confirmationEvidence","issuedAt","dispatchedAt","agentAckedAt","confirmationDeadlineAt","printConfirmedAt","failedAt","failureReason","updatedAt"]],
  ["PrintItemEvent","INSERT",["id","printItemId","eventType","previousState","nextState","details","actorUserId","createdAt"]],
  ["PrintAuditEvent","SELECT",["id","batchId","printJobId","qrCodeId","eventType","actorId","metadata","createdAt"]],
  ["PrintAuditEvent","INSERT",["id","batchId","printJobId","qrCodeId","eventType","actorId","metadata","createdAt"]],
  ["PrintReissueRequest","SELECT",["id","originalPrintJobId","replacementPrintJobId","requestedByUserId","approvedByUserId","licenseeId","manufacturerId","batchId","requestedByRole","targetApproverRole","quantity","affectedRangeStart","affectedRangeEnd","status","reason","decisionNote","rejectionReason","approvedAt","rejectedAt","executedAt","createdAt","updatedAt"]],
  ["PrintReissueRequest","INSERT",["id","originalPrintJobId","requestedByUserId","licenseeId","manufacturerId","batchId","requestedByRole","targetApproverRole","quantity","affectedRangeStart","affectedRangeEnd","status","reason","createdAt","updatedAt"]],
  ["PrintReissueRequest","UPDATE",["replacementPrintJobId","targetApproverRole","status","approvedByUserId","approvedAt","rejectedAt","executedAt","decisionNote","rejectionReason","updatedAt"]],
  ["SensitiveActionApproval","SELECT",["id","actionKey","status","requestedByUserId","reviewedByUserId","executedByUserId","licenseeId","entityType","entityId","payload","summary","expiresAt","createdAt"]],
  ["SensitiveActionApproval","INSERT",["id","actionKey","status","requestedByUserId","licenseeId","entityType","entityId","payload","summary","expiresAt","createdAt","updatedAt"]],
  ["SensitiveActionApproval","UPDATE",["status","reviewedByUserId","reviewedAt","executedByUserId","executedAt","updatedAt"]],
  ["Printer","SELECT",["id","name","vendor","model","connectionType","commandLanguage","printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive","isDefault","nativePrinterId","agentId","deviceFingerprint","deliveryMode","gatewayId","gatewaySecretHash","gatewayLastSeenAt","gatewayStatus","gatewayLastError","ipAddress","host","port","resourcePath","tlsEnabled","printerUri","calibrationProfile","capabilitySummary","metadata","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage","createdAt","updatedAt"]],
  ["Printer","INSERT",["id","name","vendor","model","connectionType","commandLanguage","ipAddress","host","port","resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewaySecretHash","gatewayStatus","gatewayLastError","nativePrinterId","agentId","deviceFingerprint","printerRegistrationId","orgId","licenseeId","assignedUserId","createdByUserId","isActive","isDefault","lastSeenAt","lastValidatedAt","lastValidationStatus","capabilitySummary","calibrationProfile","metadata","createdAt","updatedAt"]],
  ["Printer","UPDATE",["name","vendor","model","commandLanguage","ipAddress","host","port","resourcePath","tlsEnabled","printerUri","deliveryMode","gatewayId","gatewaySecretHash","gatewayLastSeenAt","gatewayStatus","gatewayLastError","printerRegistrationId","nativePrinterId","agentId","deviceFingerprint","orgId","licenseeId","assignedUserId","isActive","isDefault","capabilitySummary","calibrationProfile","metadata","lastSeenAt","lastValidatedAt","lastValidationStatus","lastValidationMessage","updatedAt"]],
  ["Printer","DELETE",[]],
  ["PrinterRegistration","SELECT",["id","userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem","certFingerprint","trustStatus","trustReason","approvedAt","revokedAt","lastSeenAt","createdAt","updatedAt"]],
  ["PrinterRegistration","INSERT",["id","userId","orgId","licenseeId","deviceFingerprint","agentId","publicKeyPem","certFingerprint","trustStatus","trustReason","approvedAt","lastSeenAt","createdAt","updatedAt"]],
  ["PrinterRegistration","UPDATE",["orgId","licenseeId","agentId","publicKeyPem","certFingerprint","trustStatus","trustReason","approvedAt","revokedAt","lastSeenAt","updatedAt"]],
  ["User","SELECT",["id","name","email","role","location","metadata"]],
  ["PrinterAttestation","SELECT",["id","printerRegistrationId","attestedAt","expiresAt","signatureValid","trustValid","rejectionReason","metadata","createdAt"]],
  ["PrinterAttestation","INSERT",["id","printerRegistrationId","signedPayloadHash","heartbeatNonce","attestedAt","expiresAt","sourceIpHash","userAgentHash","mtlsFingerprint","signatureValid","trustValid","rejectionReason","metadata","createdAt"]],
  ["ManufacturerLicenseeLink","SELECT",["manufacturerId","licenseeId"]],
  ["Licensee","SELECT",["id","orgId","name","prefix","location","metadata","isActive","suspendedAt"]],
  ["Organization","SELECT",["id","isActive"]],
  ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details","createdAt"]],
  ["SecurityEventOutbox","INSERT",["id","eventType","payload","requestId","organizationId","licenseeId","initiatingUserId","updatedAt"]],
  ["ActionIdempotencyKey","SELECT",["id","keyHash","action","scope","requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"]],
  ["ActionIdempotencyKey","INSERT",["id","keyHash","action","scope","requestHash","createdAt","expiresAt"]],
  ["ActionIdempotencyKey","UPDATE",["action","scope","requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"]],
];
const printingOwnerPolicies = [
  ["Batch","SELECT",`(${printingSession} AND (id=${printingBatchId} OR ${printingOperation}='printing-readiness')) OR (${printingConnector} AND id=${printingBatchId}) OR ${printingWorker}`],
  ["Batch","UPDATE",`(${printingSession} AND id=${printingBatchId} AND ${printingOperation} IN ('printing-create-job','printing-sample-scan','printing-release')) OR ${printingConnector} OR ${printingWorker}`],
  ["QRCode","SELECT",`(${printingSession} AND "batchId"=${printingBatchId}) OR (${printingConnector} AND "printJobId"=${printingJobId}) OR (${printingWorker} AND ${printingOperation}='printing-worker-network' AND "printJobId"=${printingJobId})`],
  ["QRCode","UPDATE",`(${printingSession} AND "batchId"=${printingBatchId} AND ${printingOperation} IN ('printing-create-job','printing-release','printing-sample-scan','printing-reissue')) OR (${printingConnector} AND "printJobId"=${printingJobId}) OR (${printingWorker} AND ${printingOperation}='printing-worker-network' AND "printJobId"=${printingJobId})`],
  ["PrintJob","SELECT",`(${printingSession} AND (${printingOperation}='printing-readiness' OR id=${printingJobId} OR "batchId"=${printingBatchId} OR (${printingOperation}='printing-printer-admin-delete' AND "printerId"=${printingPrinterId}))) OR (${printingConnector} AND (id=${printingJobId} OR (${printingOperation}='printing-connector-claim' AND "printerId"=${printingPrinterId}))) OR ${printingWorker}`],
  ["PrintJob","INSERT",`${printingSession} AND ${printingOperation} IN ('printing-create-job','printing-reissue') AND id=${printingJobId} AND "batchId"=${printingBatchId}`],
  ["PrintJob","UPDATE",`(${printingSession} AND id=${printingJobId} AND ${printingOperation} IN ('printing-job-control','printing-sample-scan','printing-reissue')) OR (${printingConnector} AND (id=${printingJobId} OR (${printingOperation}='printing-connector-claim' AND "printerId"=${printingPrinterId}))) OR ${printingWorker}`],
  ["PrintSession","SELECT",`(${printingSession} AND ("batchId"=${printingBatchId} OR id=${printingSessionRowId})) OR (${printingConnector} AND (id=${printingSessionRowId} OR ("printJobId"=${printingJobId} AND "printerRegistrationId"=${printingRegistrationId}))) OR ${printingWorker}`],
  ["PrintSession","INSERT",`${printingSession} AND ${printingOperation} IN ('printing-create-job','printing-reissue') AND id=${printingSessionRowId} AND "batchId"=${printingBatchId}`],
  ["PrintSession","UPDATE",`(${printingSession} AND id=${printingSessionRowId} AND ${printingOperation}='printing-job-control') OR (${printingConnector} AND (id=${printingSessionRowId} OR ("printJobId"=${printingJobId} AND "printerRegistrationId"=${printingRegistrationId}))) OR ${printingWorker}`],
  ["PrintItem","SELECT",`(${printingSession} AND (${printingOperation}='printing-readiness' OR "printSessionId"=${printingSessionRowId} OR (${printingOperation}='printing-reissue' AND "printSessionId"=current_setting('app.printing_original_session_id',true)))) OR (${printingConnector} AND "printSessionId"=${printingSessionRowId}) OR ${printingWorker}`],
  ["PrintItem","INSERT",`${printingSession} AND ${printingOperation}='printing-create-job' AND "printSessionId"=${printingSessionRowId}`],
  ["PrintItem","UPDATE",`(${printingSession} AND ${printingOperation}='printing-job-control' AND "printSessionId"=${printingSessionRowId}) OR (${printingSession} AND ${printingOperation}='printing-reissue' AND "printSessionId" IN (current_setting('app.printing_original_session_id',true),${printingSessionRowId})) OR (${printingConnector} AND "printSessionId"=${printingSessionRowId}) OR ${printingWorker}`],
  ["PrintItemEvent","INSERT",`${printingConnector} AND "printItemId"=${printingItemId}`],
  ["PrintAuditEvent","SELECT",`${printingSession} AND "batchId"=${printingBatchId}`],
  ["PrintAuditEvent","INSERT",`${printingSession} OR (${printingConnector} AND "printJobId"=${printingJobId}) OR (${printingWorker} AND "printJobId"=${printingJobId})`],
  ["PrintReissueRequest","SELECT",`${printingSession} AND (${printingOperation}='printing-readiness' OR id=${printingReissueId} OR "batchId"=${printingBatchId})`],
  ["PrintReissueRequest","INSERT",`${printingSession} AND ${printingOperation}='printing-reissue' AND id=${printingReissueId}`],
  ["PrintReissueRequest","UPDATE",`${printingSession} AND ${printingOperation}='printing-reissue' AND id=${printingReissueId}`],
  ["SensitiveActionApproval","SELECT",`${printingSession} AND ${printingOperation}='printing-release' AND "actionKey"='BATCH_RELEASE' AND "entityType"='Batch' AND "entityId"=${printingBatchId}`],
  ["SensitiveActionApproval","INSERT",`${printingSession} AND ${printingOperation}='printing-release' AND "actionKey"='BATCH_RELEASE' AND "entityType"='Batch' AND "entityId"=${printingBatchId} AND "licenseeId"=current_setting('app.printing_licensee_id',true)`],
  ["SensitiveActionApproval","UPDATE",`${printingSession} AND ${printingOperation}='printing-release' AND "actionKey"='BATCH_RELEASE' AND "entityType"='Batch' AND "entityId"=${printingBatchId}`],
  ["Printer","SELECT",`${printingSession} OR (${printingConnector} AND (("printerRegistrationId"=${printingRegistrationId}) OR (${printingOperation} IN ('printing-connector-identity','printing-connector-gateway-claim','printing-connector-gateway-ack','printing-connector-gateway-confirm','printing-connector-gateway-fail') AND "gatewayId"=current_setting('app.printing_gateway_id',true) AND "gatewaySecretHash"=current_setting('app.printing_gateway_secret_hash',true)))) OR (${printingWorker} AND ${printingOperation}='printing-worker-network' AND id=${printingPrinterId})`],
  ["Printer","INSERT",`${printingSession} AND ((${printingOperation}='printing-printer-admin-create' AND id=${printingPrinterId} AND "licenseeId"=current_setting('app.printing_licensee_id',true)) OR (${printingOperation}='printing-connector-registration-heartbeat' AND "assignedUserId"=current_setting('app.printing_user_id',true) AND "printerRegistrationId"=${printingRegistrationId}))`],
  ["Printer","UPDATE",`(${printingSession} AND ((${printingOperation} IN ('printing-printer-admin-update','printing-test-label-queue') AND id=${printingPrinterId}) OR (${printingOperation}='printing-printer-admin-relink' AND (id=${printingPrinterId} OR "assignedUserId"=current_setting('app.printing_user_id',true))) OR (${printingOperation}='printing-connector-registration-heartbeat' AND "assignedUserId"=current_setting('app.printing_user_id',true) AND "printerRegistrationId"=${printingRegistrationId}))) OR (${printingConnector} AND ${printingOperation} IN ('printing-connector-identity','printing-connector-gateway-claim','printing-connector-gateway-ack','printing-connector-gateway-confirm','printing-connector-gateway-fail','printing-connector-test-label-claim','printing-connector-test-label-ack','printing-connector-test-label-confirm','printing-connector-test-label-fail') AND (id=${printingPrinterId} OR ("gatewayId"=current_setting('app.printing_gateway_id',true) AND "gatewaySecretHash"=current_setting('app.printing_gateway_secret_hash',true))))`],
  ["Printer","DELETE",`${printingSession} AND ${printingOperation}='printing-printer-admin-delete' AND id=${printingPrinterId}`],
  ["PrinterRegistration","SELECT",`${printingSession} OR (${printingConnector} AND (id=${printingRegistrationId} OR (${printingOperation}='printing-connector-identity' AND "agentId"=current_setting('app.printing_agent_id',true) AND "deviceFingerprint"=current_setting('app.printing_device_fingerprint',true))))`],
  ["PrinterRegistration","INSERT",`${printingSession} AND ${printingOperation}='printing-connector-registration-heartbeat' AND id=${printingRegistrationId} AND "userId"=current_setting('app.printing_user_id',true)`],
  ["PrinterRegistration","UPDATE",`(${printingSession} AND ${printingOperation}='printing-connector-registration-heartbeat' AND "userId"=current_setting('app.printing_user_id',true)) OR (${printingConnector} AND ${printingOperation}='printing-connector-identity' AND id=${printingRegistrationId})`],
  ["User","SELECT",`(${printingSession} AND id IN (
    current_setting('app.printing_user_id',true),
    current_setting('app.printing_released_user_id',true),
    current_setting('app.printing_approved_user_id',true)
  )) OR (${printingConnector} AND id=current_setting('app.printing_user_id',true))`],
  ["PrinterAttestation","SELECT",`(${printingSession} OR ${printingConnector}) AND "printerRegistrationId"=${printingRegistrationId}`],
  ["PrinterAttestation","INSERT",`(${printingSession} AND ${printingOperation}='printing-connector-registration-heartbeat' AND "printerRegistrationId"=${printingRegistrationId}) OR (${printingConnector} AND "printerRegistrationId"=${printingRegistrationId})`],
  ["ManufacturerLicenseeLink","SELECT",printingSession],
  ["Licensee","SELECT",`${printingSession} OR (${printingConnector} AND id=current_setting('app.printing_licensee_id',true))`],
  ["Organization","SELECT",printingSession],
  ["AuditLog","INSERT",`(${printingSession} OR (${printingConnectorEvidence})) AND id=current_setting('app.printing_audit_id',true)`],
  ["SecurityEventOutbox","INSERT",`(${printingSession} OR (${printingConnectorEvidence})) AND id=current_setting('app.printing_outbox_id',true)`],
  ["ActionIdempotencyKey","SELECT",`${printingSession} AND ${printingOperation} LIKE 'printing-idempotency-%' AND "keyHash"=${printingIdempotencyKeyHash}`],
  ["ActionIdempotencyKey","INSERT",`${printingSession} AND ${printingOperation}='printing-idempotency-begin' AND "keyHash"=${printingIdempotencyKeyHash}`],
  ["ActionIdempotencyKey","UPDATE",`${printingSession} AND ${printingOperation} IN ('printing-idempotency-begin','printing-idempotency-complete','printing-idempotency-abort') AND "keyHash"=${printingIdempotencyKeyHash}`],
];
const printingLifecycleSecurity = Object.freeze({
  mode:"SECURITY DEFINER",ownerIdentity:"identity-auth-function-owner",ownerRole:"authOwner",
  searchPath:"pg_catalog,public",publicExecute:"revoked",runtimeExecuteGrantees:["app"],
  functionSource:printingLifecycleSource,rollbackDefinition:printingLifecycleRollback,
  deploymentPhase:"release-fix-5-printing-lifecycle",
  ownerPrivileges:printingOwnerPrivileges,ownerPolicies:printingOwnerPolicies,
});
const publicOperation = `current_setting('app.public_verification_operation',true)`;
const publicOwner = `current_user={{AUTH_OWNER}} AND session_user={{PREAUTH_ROLE}} AND ${publicOperation} LIKE 'public-verification-%'`;
const publicQrId = `current_setting('app.public_verification_qr_id',true)`;
const publicCode = `current_setting('app.public_verification_code',true)`;
const publicDecisionId = `current_setting('app.public_verification_decision_id',true)`;
const publicSessionId = `current_setting('app.public_verification_session_id',true)`;
const publicIdempotency = `current_setting('app.public_verification_idempotency_hash',true)`;
const publicTargetId = `current_setting('app.public_verification_target_id',true)`;
const publicSupportId = `current_setting('app.public_verification_support_id',true)`;
const publicAuditId = `current_setting('app.public_verification_audit_id',true)`;
const publicOutboxId = `current_setting('app.public_verification_outbox_id',true)`;
const publicOrganizationId = `current_setting('app.public_verification_organization_id',true)`;
const publicLicenseeId = `current_setting('app.public_verification_licensee_id',true)`;
const publicBatchId = `current_setting('app.public_verification_batch_id',true)`;
const publicManufacturerId = `current_setting('app.public_verification_manufacturer_id',true)`;
const publicCustomerSessionHash = `current_setting('app.public_verification_customer_session_hash',true)`;
const publicTransferTokenHash = `current_setting('app.public_verification_transfer_token_hash',true)`;
const publicPasskeyTicketHashes = `string_to_array(current_setting('app.public_verification_passkey_ticket_hashes',true),',')`;
const publicCustomerUserId = `current_setting('app.public_verification_customer_user_id',true)`;
const publicVerificationSecurity = Object.freeze({
  mode:"SECURITY DEFINER",ownerIdentity:"identity-auth-function-owner",ownerRole:"authOwner",
  searchPath:"pg_catalog,public",publicExecute:"revoked",runtimeExecuteGrantees:["preauth"],
  functionSource:publicVerificationSource,rollbackDefinition:publicVerificationRollback,
  deploymentPhase:"release-fix-6-public-verification",
  ownerPrivileges:[
    ["QRCode","SELECT",["id","code","licenseeId","batchId","status","scanCount","scannedAt","printedAt","tokenNonce","tokenIssuedAt","tokenExpiresAt","tokenHash","replayEpoch","issuanceMode","customerVerifiableAt","signedFirstSeenAt","lastSignedVerificationAt","lastSignedVerificationIpHash","lastSignedVerificationDeviceHash"]],
    ["QRCode","UPDATE",["scanCount","scannedAt","lastScanIp","lastScanUserAgent","lastScanDevice","signedFirstSeenAt","lastSignedVerificationAt","lastSignedVerificationIpHash","lastSignedVerificationDeviceHash","updatedAt"]],
    ["Organization","SELECT",["id","isActive"]],
    ["Licensee","SELECT",["id","orgId","name","brandName","website","supportEmail","supportPhone","isActive","suspendedAt"]],
    ["Batch","SELECT",["id","licenseeId","manufacturerId","lifecycleState","printedAt","suspendedAt"]],
    ["User","SELECT",["id","name","website"]],
    ["ReplacementChain","SELECT",["id","status","originalQrCodeId","replacementQrCodeId","createdAt"]],
    ["QrScanLog","SELECT",["id","qrCodeId","scannedAt","ipAddress","device"]],
    ["QrScanLog","INSERT",["id","code","qrCodeId","licenseeId","batchId","status","scannedAt","isFirstScan","scanCount","customerUserId","ownershipId","ownershipMatchMethod","isTrustedOwnerContext","ipAddress","userAgent","device","latitude","longitude","accuracy","locationName","locationCountry","locationRegion","locationCity"]],
    ["VerificationDecision","SELECT",["id","qrCodeId","code","licenseeId","batchId","proofSource","outcome","classification","metadata","createdAt"]],
    ["VerificationDecision","INSERT",["id","decisionVersion","qrCodeId","code","licenseeId","batchId","proofSource","proofTier","outcome","classification","reasonCodes","riskBand","replacementStatus","degradationMode","customerTrustLevel","isAuthentic","scanCount","riskScore","actorIpHash","actorDeviceHash","metadata","createdAt"]],
    ["VerificationEvidenceSnapshot","SELECT",["id","verificationDecisionId","metadata","createdAt"]],
    ["VerificationEvidenceSnapshot","INSERT",["id","verificationDecisionId","scanSummary","ownershipSnapshot","riskSignals","policySnapshot","lifecycleSnapshot","metadata","createdAt"]],
    ["VerificationEvidenceSnapshot","UPDATE",["metadata"]],
    ["CustomerVerificationSession","SELECT",["id","verificationDecisionId","qrCodeId","code","entryMethod","authState","customerUserId","customerEmail","intakeCompletedAt","revealedAt","expiresAt","proofBindingTokenHash","proofBindingIssuedAt","proofBindingExpiresAt","proofBindingReplayEpoch","metadata","createdAt","updatedAt"]],
    ["CustomerVerificationSession","INSERT",["id","verificationDecisionId","qrCodeId","code","entryMethod","authState","customerUserId","customerEmail","intakeCompletedAt","revealedAt","expiresAt","proofBindingTokenHash","proofBindingIssuedAt","proofBindingExpiresAt","proofBindingReplayEpoch","metadata","createdAt","updatedAt"]],
    ["CustomerVerificationSession","UPDATE",["authState","customerUserId","customerEmail","intakeCompletedAt","revealedAt","updatedAt"]],
    ["CustomerTrustIntake","SELECT",["id","sessionId"]],
    ["CustomerTrustIntake","INSERT",["id","sessionId","customerUserId","customerEmail","purchaseChannel","sourceCategory","platformName","sellerName","listingUrl","orderReference","storeName","purchaseCity","purchaseCountry","purchaseDate","packagingState","packagingConcern","scanReason","ownershipIntent","notes","answers","createdAt","updatedAt"]],
    ["CustomerTrustIntake","UPDATE",["customerUserId","customerEmail","purchaseChannel","sourceCategory","platformName","sellerName","listingUrl","orderReference","storeName","purchaseCity","purchaseCountry","purchaseDate","packagingState","packagingConcern","scanReason","ownershipIntent","notes","answers","updatedAt"]],
    ["CustomerAuthSession","SELECT",["id","tokenHash","customerUserId","customerEmail","authStrength","authProvider","issuedAt","expiresAt","lastSeenAt","revokedAt","createdAt","updatedAt"]],
    ["CustomerAuthSession","INSERT",["id","tokenHash","customerUserId","customerEmail","authStrength","authProvider","issuedAt","expiresAt","lastSeenAt","revokedAt","createdAt","updatedAt"]],
    ["CustomerAuthSession","UPDATE",["lastSeenAt","revokedAt","updatedAt"]],
    ["Ownership","SELECT",["id","qrCodeId","userId","deviceTokenHash","ipHash","userAgentHash","claimSource","linkedAt","claimedAt"]],
    ["Ownership","INSERT",["id","qrCodeId","userId","deviceTokenHash","ipHash","userAgentHash","claimSource","linkedAt","claimedAt"]],
    ["Ownership","UPDATE",["userId","ipHash","userAgentHash","claimSource","linkedAt","claimedAt"]],
    ["OwnershipTransfer","SELECT",["id","qrCodeId","ownershipId","initiatedByCustomerId","initiatedByEmail","recipientEmail","tokenHash","status","expiresAt","acceptedAt","cancelledAt","lastViewedAt","metadata","createdAt","updatedAt"]],
    ["OwnershipTransfer","INSERT",["id","qrCodeId","ownershipId","initiatedByCustomerId","initiatedByEmail","recipientEmail","tokenHash","status","expiresAt","acceptedAt","cancelledAt","lastViewedAt","metadata","createdAt","updatedAt"]],
    ["OwnershipTransfer","UPDATE",["status","acceptedAt","cancelledAt","lastViewedAt","updatedAt"]],
    ["CustomerWebAuthnChallenge","SELECT",["id","customerUserId","customerEmail","purpose","ticketHash","challengeHash","credentialIds","createdIpHash","createdUserAgentHash","origin","rpId","createdAt","expiresAt","consumedAt"]],
    ["CustomerWebAuthnChallenge","INSERT",["id","customerUserId","customerEmail","purpose","ticketHash","challengeHash","credentialIds","createdIpHash","createdUserAgentHash","origin","rpId","createdAt","expiresAt","consumedAt"]],
    ["CustomerWebAuthnChallenge","UPDATE",["consumedAt"]],
    ["CustomerWebAuthnCredential","SELECT",["id","customerUserId","customerEmail","label","credentialId","publicKeySpki","publicKeyAlgorithm","counter","transports","lastUsedAt","createdAt","updatedAt"]],
    ["CustomerWebAuthnCredential","INSERT",["id","customerUserId","customerEmail","label","credentialId","publicKeySpki","publicKeyAlgorithm","counter","transports","lastUsedAt","createdAt","updatedAt"]],
    ["CustomerWebAuthnCredential","UPDATE",["label","publicKeySpki","publicKeyAlgorithm","counter","transports","lastUsedAt","updatedAt"]],
    ["CustomerWebAuthnCredential","DELETE",[]],
    ["AuditLog","INSERT",["id","userId","orgId","licenseeId","action","entityType","entityId","details","ipAddress","ipHash","userAgent","createdAt"]],
    ["SecurityEventOutbox","INSERT",["id","eventType","payload","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","claimedAt","claimLeaseExpiresAt","sinkEventId","status","attempts","nextAttemptAt","lastError","sentAt","createdAt","updatedAt"]],
    ["ActionIdempotencyKey","SELECT",["id","keyHash","action","scope","requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"]],
    ["ActionIdempotencyKey","INSERT",["id","keyHash","action","scope","requestHash","statusCode","responsePayload","createdAt","completedAt","expiresAt"]],
    ["Incident","INSERT",["id","qrCodeId","qrCodeValue","scanEventId","licenseeId","reportedBy","customerName","customerEmail","customerPhone","customerCountry","preferredContactMethod","consentToContact","incidentType","severity","severityOverridden","description","photos","purchasePlace","purchaseDate","productBatchNo","locationLat","locationLng","locationName","locationCountry","locationRegion","locationCity","ipHash","userAgentHash","deviceFingerprintHash","status","priority","assignedToUserId","slaDueAt","tags","internalNotes","resolutionSummary","resolutionOutcome","createdAt","updatedAt"]],
    ["IncidentEvent","INSERT",["id","incidentId","actorType","actorUserId","eventType","eventPayload","createdAt"]],
    ["IncidentEvidence","INSERT",["id","incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"]],
    ["SupportTicket","INSERT",["id","incidentId","referenceCode","licenseeId","customerEmail","subject","status","priority","assignedToUserId","slaDueAt","firstResponseAt","resolvedAt","createdAt","updatedAt"]],
    ["SupportTicket","SELECT",["id","incidentId","referenceCode","customerEmail","status","priority","updatedAt","slaDueAt"]],
    ["IncidentHandoff","SELECT",["incidentId","currentStage","slaDueAt"]],
    ["RequestAccess","INSERT",["id","referenceCode","fullName","workEmail","companyName","roleTitle","country","monthlyGarmentVolume","message","sourcePage","referrer","status","internalNote","assignedToUserId","reviewedByUserId","reviewedAt","adminEmailDeliveryStatus","adminEmailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode","createdAt","updatedAt"]],
    ["RequestAccess","SELECT",["id"]],
    ["RequestAccess","UPDATE",["adminEmailDeliveryStatus","adminEmailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode","updatedAt"]],
    ["SupportIssueReport","INSERT",["id","reporterUserId","reporterRole","licenseeId","referenceCode","publicName","publicEmail","issueType","verificationCode","productReference","priority","title","description","status","internalNote","responseMessage","respondedAt","respondedByUserId","emailDeliveryStatus","emailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode","sourcePath","pageUrl","autoDetected","screenshotPath","screenshotMime","screenshotSize","diagnostics","createdAt","updatedAt"]],
    ["SupportIssueReport","SELECT",["id"]],
    ["SupportIssueReport","UPDATE",["emailDeliveryStatus","emailErrorCode","acknowledgementEmailDeliveryStatus","acknowledgementEmailErrorCode","updatedAt"]],
  ],
  ownerPolicies:[
    ["QRCode","SELECT",`${publicOwner} AND (id=${publicQrId} OR code=${publicCode})`],
    ["QRCode","UPDATE",`${publicOwner} AND id=${publicQrId} AND ${publicOperation}='public-verification-execute'`],
    ["Organization","SELECT",`${publicOwner} AND id=${publicOrganizationId}`],
    ["Licensee","SELECT",`${publicOwner} AND id=${publicLicenseeId}`],
    ["Batch","SELECT",`${publicOwner} AND id=${publicBatchId}`],
    ["User","SELECT",`${publicOwner} AND id=${publicManufacturerId}`],
    ["ReplacementChain","SELECT",`${publicOwner} AND ("originalQrCodeId"=${publicQrId} OR "replacementQrCodeId"=${publicQrId})`],
    ["QrScanLog","SELECT",`${publicOwner} AND "qrCodeId"=${publicQrId}`],
    ["QrScanLog","INSERT",`${publicOwner} AND "qrCodeId"=${publicQrId}`],
    ["VerificationDecision","SELECT",`${publicOwner} AND id=${publicDecisionId}`],
    ["VerificationDecision","INSERT",`${publicOwner} AND id=${publicDecisionId}`],
    ["VerificationEvidenceSnapshot","SELECT",`${publicOwner} AND ("verificationDecisionId"=${publicDecisionId} OR ${publicOperation}='public-verification-session-start')`],
    ["VerificationEvidenceSnapshot","INSERT",`${publicOwner} AND "verificationDecisionId"=${publicDecisionId}`],
    ["VerificationEvidenceSnapshot","UPDATE",`${publicOwner} AND ${publicOperation}='public-verification-session-start'`],
    ["CustomerVerificationSession","SELECT",`${publicOwner} AND id=${publicSessionId}`],
    ["CustomerVerificationSession","INSERT",`${publicOwner} AND id=${publicSessionId}`],
    ["CustomerVerificationSession","UPDATE",`${publicOwner} AND id=${publicSessionId}`],
    ["CustomerTrustIntake","SELECT",`${publicOwner} AND "sessionId"=${publicSessionId}`],
    ["CustomerTrustIntake","INSERT",`${publicOwner} AND "sessionId"=${publicSessionId}`],
    ["CustomerTrustIntake","UPDATE",`${publicOwner} AND "sessionId"=${publicSessionId}`],
    ["CustomerAuthSession","SELECT",`${publicOwner} AND "tokenHash"=${publicCustomerSessionHash}`],
    ["CustomerAuthSession","INSERT",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-customer-session-issue'`],
    ["CustomerAuthSession","UPDATE",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation} IN ('public-verification-customer-session-read','public-verification-customer-session-revoke','public-verification-customer-verification-session-start','public-verification-customer-verification-session-read','public-verification-customer-verification-session-write','public-verification-customer-ownership','public-verification-customer-passkey')`],
    ["Ownership","SELECT",`${publicOwner} AND "qrCodeId"=${publicQrId}`],
    ["Ownership","INSERT",`${publicOwner} AND id=${publicTargetId} AND "qrCodeId"=${publicQrId} AND ${publicOperation}='public-verification-ownership-claim'`],
    ["Ownership","UPDATE",`${publicOwner} AND id=${publicTargetId} AND "qrCodeId"=${publicQrId} AND ${publicOperation} IN ('public-verification-ownership-claim','public-verification-ownership-transfer-accept')`],
    ["OwnershipTransfer","SELECT",`${publicOwner} AND ("qrCodeId"=${publicQrId} OR "tokenHash"=${publicTransferTokenHash})`],
    ["OwnershipTransfer","INSERT",`${publicOwner} AND id=${publicSupportId} AND "qrCodeId"=${publicQrId} AND ${publicOperation}='public-verification-ownership-transfer-create'`],
    ["OwnershipTransfer","UPDATE",`${publicOwner} AND "qrCodeId"=${publicQrId} AND ${publicOperation} IN ('public-verification-ownership-transfer-create','public-verification-ownership-transfer-cancel','public-verification-ownership-transfer-accept')`],
    ["CustomerWebAuthnChallenge","SELECT",`${publicOwner} AND "ticketHash"=ANY(${publicPasskeyTicketHashes}) AND ${publicOperation}='public-verification-customer-passkey'`],
    ["CustomerWebAuthnChallenge","INSERT",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-customer-passkey'`],
    ["CustomerWebAuthnChallenge","UPDATE",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-customer-passkey'`],
    ["CustomerWebAuthnCredential","SELECT",`${publicOwner} AND ${publicOperation}='public-verification-customer-passkey' AND ("customerUserId"=${publicCustomerUserId} OR id=${publicSupportId} OR "credentialId"=${publicSupportId})`],
    ["CustomerWebAuthnCredential","INSERT",`${publicOwner} AND id=${publicSupportId} AND ${publicOperation}='public-verification-customer-passkey'`],
    ["CustomerWebAuthnCredential","UPDATE",`${publicOwner} AND id=${publicSupportId} AND ${publicOperation}='public-verification-customer-passkey'`],
    ["CustomerWebAuthnCredential","DELETE",`${publicOwner} AND id=${publicSupportId} AND "customerUserId"=${publicCustomerUserId} AND ${publicOperation}='public-verification-customer-passkey'`],
    ["AuditLog","INSERT",`${publicOwner} AND id=${publicAuditId}`],
    ["SecurityEventOutbox","INSERT",`${publicOwner} AND id=${publicOutboxId}`],
    ["ActionIdempotencyKey","SELECT",`${publicOwner} AND "keyHash"=${publicIdempotency}`],
    ["ActionIdempotencyKey","INSERT",`${publicOwner} AND "keyHash"=${publicIdempotency}`],
    ["Incident","INSERT",`${publicOwner} AND id=${publicTargetId} AND "qrCodeId"=${publicQrId}`],
    ["IncidentEvent","INSERT",`${publicOwner} AND "incidentId"=${publicTargetId}`],
    ["IncidentEvidence","INSERT",`${publicOwner} AND "incidentId"=${publicTargetId}`],
    ["SupportTicket","INSERT",`${publicOwner} AND id=${publicSupportId} AND "incidentId"=${publicTargetId}`],
    ["SupportTicket","SELECT",`${publicOwner} AND ${publicOperation}='public-verification-support-track' AND "referenceCode"=current_setting('app.public_verification_code',true) AND "customerEmail" IS NOT NULL AND encode(sha256(convert_to(lower("customerEmail"),'UTF8')),'hex')=substr(${publicIdempotency},11)`],
    ["IncidentHandoff","SELECT",`${publicOwner} AND ${publicOperation}='public-verification-support-track' AND "incidentId"=${publicTargetId}`],
    ["RequestAccess","INSERT",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-request-access'`],
    ["RequestAccess","SELECT",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-request-access-delivery'`],
    ["RequestAccess","UPDATE",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-request-access-delivery'`],
    ["SupportIssueReport","INSERT",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-support'`],
    ["SupportIssueReport","SELECT",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-support-delivery'`],
    ["SupportIssueReport","UPDATE",`${publicOwner} AND id=${publicTargetId} AND ${publicOperation}='public-verification-support-delivery'`],
  ],
});
const publicIdentityArguments = Object.freeze({
  issue_customer_auth_session: "p_capability text, p_customer_user_id text, p_customer_email text, p_auth_strength text, p_auth_provider text, p_issued_at timestamp without time zone, p_expires_at timestamp without time zone, p_request_id text",
  require_customer_auth_session: "p_capability text, p_checked_at timestamp without time zone, p_request_id text, p_operation text",
  read_customer_auth_session: "p_capability text, p_checked_at timestamp without time zone, p_request_id text",
  revoke_customer_auth_session: "p_capability text, p_revoked_at timestamp without time zone, p_request_id text",
  verify_signed_qr: "p_token_digest text, p_qr_id text, p_licensee_id text, p_batch_id text, p_manufacturer_id text, p_nonce text, p_replay_epoch integer, p_key_version text, p_issued_at timestamp without time zone, p_expires_at timestamp without time zone, p_checked_at timestamp without time zone, p_request_id text, p_actor_ip_hash text, p_actor_device_hash text, p_session_start_token_hash text",
  start_verification_session: "p_session_start_token_hash text, p_entry_method text, p_customer_capability text, p_checked_at timestamp without time zone, p_request_id text, p_session_proof_hash text",
  read_verification_session: "p_session_id text, p_session_proof_hash text, p_customer_capability text, p_checked_at timestamp without time zone, p_request_id text",
  write_verification_session: "p_session_id text, p_session_proof_hash text, p_customer_capability text, p_operation text, p_payload jsonb, p_checked_at timestamp without time zone, p_request_id text",
  submit_product_feedback: "p_requested_code text, p_rating integer, p_satisfaction text, p_notes text, p_observed_status text, p_observed_outcome text, p_page_url text, p_submitted_at timestamp without time zone, p_request_id text, p_actor_ip_hash text, p_idempotency_digest text",
  submit_public_incident: "p_session_id text, p_session_proof_hash text, p_incident_type text, p_description text, p_contact_email text, p_consent_to_contact boolean, p_evidence jsonb, p_submitted_at timestamp without time zone, p_request_id text, p_actor_ip_hash text, p_actor_device_hash text, p_idempotency_digest text",
  submit_request_access: "p_full_name text, p_work_email text, p_company_name text, p_role_title text, p_country text, p_monthly_volume text, p_message text, p_source_page text, p_referrer text, p_submitted_at timestamp without time zone, p_request_id text, p_idempotency_digest text",
  submit_public_support: "p_public_name text, p_public_email text, p_issue_type text, p_title text, p_description text, p_verified_code text, p_product_reference text, p_source_path text, p_page_url text, p_submitted_at timestamp without time zone, p_request_id text, p_idempotency_digest text",
  complete_request_access_delivery: "p_idempotency_digest text, p_admin_status text, p_admin_error text, p_ack_status text, p_ack_error text, p_completed_at timestamp without time zone, p_request_id text",
  complete_public_support_delivery: "p_idempotency_digest text, p_admin_status text, p_admin_error text, p_ack_status text, p_ack_error text, p_completed_at timestamp without time zone, p_request_id text",
  track_support_status: "p_reference_code text, p_proof_digest text, p_proof_version integer, p_checked_at timestamp without time zone, p_request_id text",
});
const publicContract = ({id,name,signature,identityArguments,returnType,tableCommands,workflow,caller,outputColumns,runtime=true}) => ({
  id:`release-fix-6-${id}`,schema:"app_public",name,signature,
  returnType:name==="verify_raw_qr"
    ? "TABLE(result text, messageKey text, nextAction text, maskedCode text, brandName text, brandWebsite text, brandSupportEmail text, brandSupportPhone text, manufacturerName text, manufacturerWebsite text, printedAt timestamp without time zone, firstVerifiedAt timestamp without time zone, latestVerifiedAt timestamp without time zone, ownershipClaimAvailable boolean, sessionStartToken text)"
    : name==="verify_signed_qr"
      ? "TABLE(result text, messageKey text, nextAction text, verificationMethod text, maskedCode text, brandName text, brandWebsite text, brandSupportEmail text, brandSupportPhone text, manufacturerName text, manufacturerWebsite text, printedAt timestamp without time zone, firstVerifiedAt timestamp without time zone, latestVerifiedAt timestamp without time zone, ownershipClaimAvailable boolean, sessionStartToken text)"
      : name==="start_verification_session"
    ? "TABLE(sessionId text, sessionProofToken text, maskedCode text, customerFacingState text, entryMethod text, authState text, startedAt timestamp without time zone, expiresAt timestamp without time zone, proofBindingExpiresAt timestamp without time zone, brandName text)"
    : name==="read_verification_session"
      ? "TABLE(sessionId text, maskedCode text, customerFacingState text, startedAt timestamp without time zone, expiresAt timestamp without time zone, proofBindingExpiresAt timestamp without time zone, entryMethod text, authState text, intakeCompleted boolean, revealed boolean, brandName text, verification jsonb)"
      : returnType,
  identityArguments:identityArguments || publicIdentityArguments[name],
  definitionLocation:publicVerificationSource,definitionKind:"checked-in-production-package",
  definitionStatus:"production-reviewed",
  security:runtime ? publicVerificationSecurity : {...publicVerificationSecurity,runtimeExecuteGrantees:[]},
  tableCommands,context:"Executes one exact anonymous hostile-input operation under the pre-auth runtime, stages row-local targets, derives tenant and lifecycle scope from protected rows, and returns an explicit customer-safe projection.",
  canonicalWorkflowIds:[workflow],repositoryCallers:[caller],
  inputAuthority:"server-verified signed material or exact canonical code selects one row; caller tenant, brand, batch, role and lifecycle values never establish authority",
  outputColumns:name==="verify_raw_qr"
    ? ["result","messageKey","nextAction","maskedCode","brandName","brandWebsite","brandSupportEmail","brandSupportPhone","manufacturerName","manufacturerWebsite","printedAt","firstVerifiedAt","latestVerifiedAt","ownershipClaimAvailable","sessionStartToken"]
    : name==="verify_signed_qr"
      ? ["result","messageKey","nextAction","verificationMethod","maskedCode","brandName","brandWebsite","brandSupportEmail","brandSupportPhone","manufacturerName","manufacturerWebsite","printedAt","firstVerifiedAt","latestVerifiedAt","ownershipClaimAvailable","sessionStartToken"]
      : name==="start_verification_session"
    ? ["sessionId","sessionProofToken","maskedCode","customerFacingState","entryMethod","authState","startedAt","expiresAt","proofBindingExpiresAt","brandName"]
    : name==="read_verification_session"
      ? ["sessionId","maskedCode","customerFacingState","startedAt","expiresAt","proofBindingExpiresAt","entryMethod","authState","intakeCompleted","revealed","brandName","verification"]
      : outputColumns,
  disposableProbes:["public-verification-postgres18"],
});
const dashboardWorkflows = Object.freeze({
  scope:"workflow-internal-backend-src-services-dashboard-snapshot-service-ts-compute-dashboard-snapshot",
  data:"workflow-internal-backend-src-services-dashboard-snapshot-service-ts-load-inventory-aggregate",
});
const batchWorkflows = Object.freeze({
  scope:["workflow-internal-backend-src-services-batch-allocation-service-ts-get-batch-allocation-map","workflow-internal-backend-src-services-batch-allocation-service-ts-read-batches"],
  total:"workflow-internal-backend-src-services-batch-allocation-service-ts-read-total",
  rollups:"workflow-internal-backend-src-services-batch-allocation-service-ts-read-rollups",
  ranges:"workflow-internal-backend-src-services-batch-allocation-service-ts-read-unassigned-ranges",
  fallback:"workflow-internal-backend-src-services-batch-allocation-service-ts-build-count-maps",
  reservable:"workflow-internal-backend-src-services-print-reservation-service-ts-list-reservable-qr-code-summaries",
});
const operationalCommonCommands = [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["AuditLog","SELECT"],["AuditLog","INSERT"]];
const operationalContract = ({id,name,signature,returnType,identityArguments,tableCommands,canonicalWorkflowIds,repositoryCallers,outputColumns}) => ({
  id,schema:"app_rls",name,signature,returnType,identityArguments,definitionLocation:operationalReadSource,
  definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:operationalReadSecurity,
  tableCommands,context:"Verifies the opaque authenticated-session capability inside the exact public overload, derives live actor authority, and invokes an ungranted SECURITY INVOKER implementation under operation-specific FORCE-RLS policies.",
  canonicalWorkflowIds,repositoryCallers,inputAuthority:"capability is authority; licensee, batch and route values are bounded selectors only",outputColumns,
  disposableProbes:[name.startsWith("dashboard_")?"dashboard-snapshot-postgres18":"batch-operational-read-postgres18"],
});

// A function is production-reviewed only when its deployable definition,
// contract, rollback and exact table-command evidence live together here.
export const NAMED_SQL_FUNCTION_CONTRACTS = Object.freeze([
  publicContract({id:"customer-session-issue",name:"issue_customer_auth_session",signature:"text,text,text,text,text,timestamp without time zone,timestamp without time zone,text",returnType:"TABLE(accepted boolean)",tableCommands:[["CustomerAuthSession","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-auth-handlers-ts-verify-customer-email-otp",caller:"backend/src/services/customerVerifyDatabaseSessionService.ts:registerCustomerVerifyDatabaseSession",outputColumns:["accepted"]}),
  publicContract({id:"customer-session-read",name:"read_customer_auth_session",signature:"text,timestamp without time zone,text",returnType:"TABLE(customerUserId text, customerEmail text, authStrength text, authProvider text)",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"]],workflow:"workflow-http-backend-src-controllers-verify-auth-handlers-ts-get-customer-verify-auth-session",caller:"backend/src/services/customerVerifyDatabaseSessionService.ts:readCustomerVerifyDatabaseSession",outputColumns:["customerUserId","customerEmail","authStrength","authProvider"]}),
  publicContract({id:"customer-session-revoke",name:"revoke_customer_auth_session",signature:"text,timestamp without time zone,text",returnType:"TABLE(revoked boolean)",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"]],workflow:"workflow-http-backend-src-controllers-verify-auth-handlers-ts-logout-customer-verify-session",caller:"backend/src/services/customerVerifyDatabaseSessionService.ts:revokeCustomerVerifyDatabaseSession",outputColumns:["revoked"]}),
  publicContract({id:"verify-raw",name:"verify_raw_qr",signature:"text,timestamp without time zone,text,text,text,text",identityArguments:"p_requested_code text, p_checked_at timestamp without time zone, p_request_id text, p_actor_ip_hash text, p_actor_device_hash text, p_session_start_token_hash text",returnType:"TABLE(result text, messageKey text, nextAction text, maskedCode text, brandName text, manufacturerName text, manufacturerWebsite text, printedAt timestamp without time zone, firstVerifiedAt timestamp without time zone, latestVerifiedAt timestamp without time zone, ownershipClaimAvailable boolean, sessionStartToken text)",tableCommands:[["QRCode","SELECT"],["QRCode","UPDATE"],["Organization","SELECT"],["Licensee","SELECT"],["Batch","SELECT"],["User","SELECT"],["ReplacementChain","SELECT"],["QrScanLog","SELECT"],["QrScanLog","INSERT"],["VerificationDecision","INSERT"],["VerificationEvidenceSnapshot","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-verification-handlers-ts-verify-qrcode",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:verifyRawQr",outputColumns:["result","messageKey","nextAction","maskedCode","brandName","manufacturerName","manufacturerWebsite","printedAt","firstVerifiedAt","latestVerifiedAt","ownershipClaimAvailable","sessionStartToken"]}),
  publicContract({id:"verify-signed",name:"verify_signed_qr",signature:"text,text,text,text,text,text,integer,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text,text,text,text",returnType:"TABLE(result text, messageKey text, nextAction text, verificationMethod text, maskedCode text, brandName text, manufacturerName text, manufacturerWebsite text, printedAt timestamp without time zone, firstVerifiedAt timestamp without time zone, latestVerifiedAt timestamp without time zone, ownershipClaimAvailable boolean, sessionStartToken text)",tableCommands:[["QRCode","SELECT"],["QRCode","UPDATE"],["Organization","SELECT"],["Licensee","SELECT"],["Batch","SELECT"],["User","SELECT"],["ReplacementChain","SELECT"],["QrScanLog","SELECT"],["QrScanLog","INSERT"],["VerificationDecision","INSERT"],["VerificationEvidenceSnapshot","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-verification-signed-token-resolver-ts-resolve-signed-verification-target",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:verifySignedQr",outputColumns:["result","messageKey","nextAction","verificationMethod","maskedCode","brandName","manufacturerName","manufacturerWebsite","printedAt","firstVerifiedAt","latestVerifiedAt","ownershipClaimAvailable","sessionStartToken"]}),
  publicContract({id:"session-start",name:"start_verification_session",signature:"text,text,text,timestamp without time zone,text,text",returnType:"TABLE(sessionId text, sessionProofToken text, maskedCode text, customerFacingState text, startedAt timestamp without time zone, expiresAt timestamp without time zone, brandName text)",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["VerificationEvidenceSnapshot","SELECT"],["VerificationEvidenceSnapshot","UPDATE"],["VerificationDecision","SELECT"],["Licensee","SELECT"],["CustomerVerificationSession","INSERT"]],workflow:"workflow-internal-backend-src-services-customer-verification-session-service-ts-create-customer-verification-session",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:startVerificationSession",outputColumns:["sessionId","sessionProofToken","maskedCode","customerFacingState","startedAt","expiresAt","brandName"]}),
  publicContract({id:"session-read",name:"read_verification_session",signature:"text,text,text,timestamp without time zone,text",returnType:"TABLE(sessionId text, maskedCode text, customerFacingState text, startedAt timestamp without time zone, expiresAt timestamp without time zone, intakeCompleted boolean, revealed boolean, brandName text, verification jsonb)",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerVerificationSession","SELECT"],["VerificationDecision","SELECT"],["VerificationEvidenceSnapshot","SELECT"],["Licensee","SELECT"]],workflow:"workflow-internal-backend-src-services-customer-verification-session-service-ts-get-customer-verification-session",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:readVerificationSession",outputColumns:["sessionId","maskedCode","customerFacingState","startedAt","expiresAt","intakeCompleted","revealed","brandName","verification"]}),
  publicContract({id:"session-write",name:"write_verification_session",signature:"text,text,text,text,jsonb,timestamp without time zone,text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerVerificationSession","SELECT"],["CustomerVerificationSession","UPDATE"],["CustomerTrustIntake","SELECT"],["CustomerTrustIntake","INSERT"],["CustomerTrustIntake","UPDATE"]],workflow:"workflow-internal-backend-src-services-customer-verification-session-service-ts-save-customer-trust-intake",caller:"backend/src/services/customerVerificationSessionService.ts:saveCustomerTrustIntake",outputColumns:["result"]}),
  publicContract({id:"ownership-claim",name:"claim_customer_ownership",signature:"text,text,text,text,text,text,boolean,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_session_id text, p_session_proof_hash text, p_device_token_hash text, p_ip_hash text, p_user_agent_hash text, p_link_only boolean, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerVerificationSession","SELECT"],["QRCode","SELECT"],["Batch","SELECT"],["Ownership","SELECT"],["Ownership","INSERT"],["Ownership","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-claim-handlers-ts-claim-product-ownership",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:claimCustomerOwnership",outputColumns:["result"]}),
  publicContract({id:"ownership-transfer-create",name:"create_customer_ownership_transfer",signature:"text,text,text,text,timestamp without time zone,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_requested_code text, p_recipient_email text, p_token_hash text, p_expires_at timestamp without time zone, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["QRCode","SELECT"],["Ownership","SELECT"],["OwnershipTransfer","UPDATE"],["OwnershipTransfer","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-create-ownership-transfer-handler-ts-create-ownership-transfer",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:createCustomerOwnershipTransfer",outputColumns:["result"]}),
  publicContract({id:"ownership-transfer-cancel",name:"cancel_customer_ownership_transfer",signature:"text,text,text,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_requested_code text, p_transfer_id text, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["QRCode","SELECT"],["OwnershipTransfer","SELECT"],["OwnershipTransfer","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-cancel-ownership-transfer-handler-ts-cancel-ownership-transfer",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:cancelCustomerOwnershipTransfer",outputColumns:["result"]}),
  publicContract({id:"ownership-transfer-accept",name:"accept_customer_ownership_transfer",signature:"text,text,text,text,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_token_hash text, p_ip_hash text, p_user_agent_hash text, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["OwnershipTransfer","SELECT"],["OwnershipTransfer","UPDATE"],["QRCode","SELECT"],["Ownership","SELECT"],["Ownership","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-accept-ownership-transfer-handler-ts-accept-ownership-transfer",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:acceptCustomerOwnershipTransfer",outputColumns:["result"]}),
  publicContract({id:"passkey-begin",name:"begin_customer_passkey",signature:"text,text,text,text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_customer_user_id text, p_customer_email text, p_purpose text, p_ticket_hash text, p_challenge_hash text, p_ip_hash text, p_user_agent_hash text, p_origin text, p_rp_id text, p_expires_at timestamp without time zone, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerWebAuthnCredential","SELECT"],["CustomerWebAuthnChallenge","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-passkey-auth-handlers-ts-begin-customer-passkey-assertion",caller:"backend/src/services/customerWebauthnService.ts:beginCustomerWebAuthnAssertion",outputColumns:["result"]}),
  publicContract({id:"passkey-load",name:"load_customer_passkey",signature:"text[],text,text,timestamp without time zone,text",identityArguments:"p_ticket_hashes text[], p_purpose text, p_credential_id text, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerWebAuthnChallenge","SELECT"],["CustomerWebAuthnCredential","SELECT"]],workflow:"workflow-internal-backend-src-services-customer-webauthn-service-ts-load-challenge-by-ticket",caller:"backend/src/services/customerWebauthnService.ts:loadChallengeByTicket",outputColumns:["result"]}),
  publicContract({id:"passkey-finish",name:"finish_customer_passkey",signature:"text,text[],text,jsonb,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_ticket_hashes text[], p_purpose text, p_payload jsonb, p_checked_at timestamp without time zone, p_request_id text",returnType:"jsonb",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerWebAuthnChallenge","SELECT"],["CustomerWebAuthnChallenge","UPDATE"],["CustomerWebAuthnCredential","SELECT"],["CustomerWebAuthnCredential","INSERT"],["CustomerWebAuthnCredential","UPDATE"]],workflow:"workflow-http-backend-src-controllers-verify-passkey-auth-handlers-ts-finish-customer-passkey-assertion",caller:"backend/src/services/customerWebauthnService.ts:completeCustomerWebAuthnAssertion",outputColumns:["result"]}),
  publicContract({id:"passkey-list",name:"list_customer_passkeys",signature:"text,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_checked_at timestamp without time zone, p_request_id text",returnType:"TABLE(payload jsonb)",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerWebAuthnCredential","SELECT"]],workflow:"workflow-http-backend-src-controllers-verify-passkey-auth-handlers-ts-list-customer-passkey-credentials",caller:"backend/src/services/customerWebauthnService.ts:listCustomerWebAuthnCredentials",outputColumns:["payload"]}),
  publicContract({id:"passkey-delete",name:"delete_customer_passkey",signature:"text,text,timestamp without time zone,text",identityArguments:"p_customer_capability text, p_credential_row_id text, p_checked_at timestamp without time zone, p_request_id text",returnType:"TABLE(deleted boolean)",tableCommands:[["CustomerAuthSession","SELECT"],["CustomerAuthSession","UPDATE"],["CustomerWebAuthnCredential","DELETE"]],workflow:"workflow-http-backend-src-controllers-verify-passkey-auth-handlers-ts-delete-customer-passkey-credential",caller:"backend/src/services/customerWebauthnService.ts:deleteCustomerWebAuthnCredential",outputColumns:["deleted"]}),
  publicContract({id:"feedback",name:"submit_product_feedback",signature:"text,integer,text,text,text,text,text,timestamp without time zone,text,text,text",returnType:"TABLE(accepted boolean, publicReference text, message text)",tableCommands:[["QRCode","SELECT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["AuditLog","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-feedback-handlers-ts-submit-product-feedback",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:submitProductFeedback",outputColumns:["accepted","publicReference","message"]}),
  publicContract({id:"incident",name:"submit_public_incident",signature:"text,text,text,text,text,boolean,jsonb,timestamp without time zone,text,text,text,text",returnType:"TABLE(accepted boolean, publicReference text, message text)",tableCommands:[["CustomerVerificationSession","SELECT"],["QRCode","SELECT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["Incident","INSERT"],["IncidentEvent","INSERT"],["IncidentEvidence","INSERT"],["SupportTicket","INSERT"],["SecurityEventOutbox","INSERT"]],workflow:"workflow-http-backend-src-controllers-verify-feedback-handlers-ts-report-fraud",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:submitPublicIncident",outputColumns:["accepted","publicReference","message"]}),
  publicContract({id:"request-access",name:"submit_request_access",signature:"text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text",returnType:"TABLE(accepted boolean, publicReference text, message text, deliveryRequired boolean)",tableCommands:[["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["RequestAccess","INSERT"]],workflow:"workflow-http-backend-src-controllers-public-intake-controller-ts-submit-public-request-access",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:submitRequestAccess",outputColumns:["accepted","publicReference","message","deliveryRequired"]}),
  publicContract({id:"support",name:"submit_public_support",signature:"text,text,text,text,text,text,text,text,text,timestamp without time zone,text,text",returnType:"TABLE(accepted boolean, publicReference text, message text, deliveryRequired boolean)",tableCommands:[["QRCode","SELECT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["SupportIssueReport","INSERT"]],workflow:"workflow-http-backend-src-controllers-public-intake-controller-ts-submit-public-support-issue",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:submitPublicSupport",outputColumns:["accepted","publicReference","message","deliveryRequired"]}),
  publicContract({id:"support-track",name:"track_support_status",signature:"text,text,integer,timestamp without time zone,text",returnType:"TABLE(referenceCode text, customerFacingStatus text, priority text, updatedAt timestamp without time zone, handoffStage text, slaDueAt timestamp without time zone)",tableCommands:[["SupportTicket","SELECT"],["IncidentHandoff","SELECT"]],workflow:"workflow-http-backend-src-controllers-support-controller-ts-track-support-ticket-public",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:trackSupportStatus",outputColumns:["referenceCode","customerFacingStatus","priority","updatedAt","handoffStage","slaDueAt"]}),
  publicContract({id:"request-access-delivery",name:"complete_request_access_delivery",signature:"text,text,text,text,text,timestamp without time zone,text",returnType:"TABLE(updated boolean)",tableCommands:[["ActionIdempotencyKey","SELECT"],["RequestAccess","SELECT"],["RequestAccess","UPDATE"]],workflow:"workflow-http-backend-src-controllers-public-intake-controller-ts-submit-public-request-access",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:completeRequestAccessDelivery",outputColumns:["updated"]}),
  publicContract({id:"support-delivery",name:"complete_public_support_delivery",signature:"text,text,text,text,text,timestamp without time zone,text",returnType:"TABLE(updated boolean)",tableCommands:[["ActionIdempotencyKey","SELECT"],["SupportIssueReport","SELECT"],["SupportIssueReport","UPDATE"]],workflow:"workflow-http-backend-src-controllers-public-intake-controller-ts-submit-public-support-issue",caller:"backend/src/rls-waves/session-b/b02/publicBoundaryRepository.ts:completePublicSupportDelivery",outputColumns:["updated"]}),
  operationalContract({id:"dashboard-snapshot-scope",name:"dashboard_snapshot_scope",signature:"text,text,text,text,text,text",returnType:"TABLE(scope_fingerprint text)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text",tableCommands:operationalCommonCommands,canonicalWorkflowIds:[dashboardWorkflows.scope],repositoryCallers:["backend/src/services/dashboardSnapshotService.ts:computeDashboardSnapshot"],outputColumns:["scope_fingerprint"]}),
  operationalContract({id:"dashboard-snapshot-data",name:"dashboard_snapshot_data",signature:"text,text,text,text,text,text,text",returnType:"TABLE(total_qr_codes bigint, active_licensees bigint, manufacturers bigint, total_batches bigint, dormant bigint, active bigint, activated bigint, allocated bigint, printed bigint, redeemed bigint, blocked bigint, scanned bigint, rollup_authoritative boolean)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, expected_scope_fingerprint text",tableCommands:[...operationalCommonCommands,["Batch","SELECT"],["QRCode","SELECT"],["InventoryStatusRollup","SELECT"]],canonicalWorkflowIds:[dashboardWorkflows.data],repositoryCallers:["backend/src/services/dashboardSnapshotService.ts:loadInventoryAggregate"],outputColumns:["total_qr_codes","active_licensees","manufacturers","total_batches","dormant","active","activated","allocated","printed","redeemed","blocked","scanned","rollup_authoritative"]}),
  operationalContract({id:"batch-operational-scope",name:"batch_operational_scope",signature:"text,text,text,text,text,text,text",returnType:"TABLE(scope_fingerprint text)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text",tableCommands:[...operationalCommonCommands,["Batch","SELECT"]],canonicalWorkflowIds:batchWorkflows.scope,repositoryCallers:["backend/src/services/batchAllocationService.ts:readBatches","backend/src/services/batchAllocationService.ts:getBatchAllocationMap"],outputColumns:["scope_fingerprint"]}),
  operationalContract({id:"batch-operational-rows",name:"batch_operational_rows",signature:"text,text,text,text,text,text,text,text,integer,integer",returnType:"TABLE(row_data jsonb)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, page_limit integer, page_offset integer",tableCommands:[...operationalCommonCommands,["Batch","SELECT"],["QRCode","SELECT"]],canonicalWorkflowIds:batchWorkflows.scope,repositoryCallers:["backend/src/services/batchAllocationService.ts:readBatches","backend/src/services/batchAllocationService.ts:getBatchAllocationMap"],outputColumns:["row_data"]}),
  operationalContract({id:"batch-operational-total",name:"batch_operational_total",signature:"text,text,text,text,text,text,text,text",returnType:"TABLE(total bigint)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text",tableCommands:[...operationalCommonCommands,["Batch","SELECT"]],canonicalWorkflowIds:[batchWorkflows.total],repositoryCallers:["backend/src/services/batchAllocationService.ts:readTotal"],outputColumns:["total"]}),
  operationalContract({id:"batch-inventory-rollups",name:"batch_inventory_rollups",signature:"text,text,text,text,text,text,text,text,text[]",returnType:"TABLE(batch_id text, dormant integer, active integer, activated integer, allocated integer, printed integer, redeemed integer, blocked integer, scanned integer)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]",tableCommands:[...operationalCommonCommands,["Batch","SELECT"],["InventoryStatusRollup","SELECT"]],canonicalWorkflowIds:[batchWorkflows.rollups],repositoryCallers:["backend/src/services/batchAllocationService.ts:readRollups"],outputColumns:["batch_id","dormant","active","activated","allocated","printed","redeemed","blocked","scanned"]}),
  operationalContract({id:"batch-unassigned-ranges",name:"batch_unassigned_ranges",signature:"text,text,text,text,text,text,text,text,text[]",returnType:"TABLE(batch_id text, item_count bigint, start_code text, end_code text)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]",tableCommands:[...operationalCommonCommands,["Batch","SELECT"],["QRCode","SELECT"]],canonicalWorkflowIds:[batchWorkflows.ranges],repositoryCallers:["backend/src/services/batchAllocationService.ts:readUnassignedRanges"],outputColumns:["batch_id","item_count","start_code","end_code"]}),
  operationalContract({id:"batch-status-fallback",name:"batch_status_fallback",signature:"text,text,text,text,text,text,text,text,text[]",returnType:"TABLE(batch_id text, status text, item_count bigint)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]",tableCommands:[...operationalCommonCommands,["Batch","SELECT"],["QRCode","SELECT"]],canonicalWorkflowIds:[batchWorkflows.fallback],repositoryCallers:["backend/src/services/batchAllocationService.ts:buildCountMaps"],outputColumns:["batch_id","status","item_count"]}),
  operationalContract({id:"batch-reservable-qr-summaries",name:"batch_reservable_qr_summaries",signature:"text,text,text,text,text,text,text,text,text[]",returnType:"TABLE(batch_id text, item_count bigint, start_code text, end_code text)",identityArguments:"p_capability text, p_purpose text, p_request_id text, audit_id text, requested_licensee_id text, route_surface text, focus_batch_id text, expected_scope_fingerprint text, batch_ids text[]",tableCommands:[...operationalCommonCommands,["Batch","SELECT"],["QRCode","SELECT"],["PrintItem","SELECT"],["PrintSession","SELECT"],["PrintJob","SELECT"]],canonicalWorkflowIds:[batchWorkflows.reservable],repositoryCallers:["backend/src/services/printReservationService.ts:listReservableQrCodeSummaries"],outputColumns:["batch_id","item_count","start_code","end_code"]}),
  {
    id:"tenant-directory-licensees",schema:"app_rls",name:"read_licensee_directory",signature:"text,text,text,text,boolean",returnType:"TABLE(payload jsonb)",
    identityArguments:"p_capability text, p_purpose text, p_request_id text, p_requested_licensee_id text, p_detail boolean",definitionLocation:operationalReadSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:tenantDirectorySecurity,
    tableCommands:[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Invite","SELECT"],["Batch","SELECT"],["QRCode","SELECT"],["QRRange","SELECT"]],
    context:"Verifies the opaque authenticated-session capability, derives live platform, tenant-admin, or manufacturer-linked scope, and treats the optional licensee identifier only as a narrowing selector.",
    canonicalWorkflowIds:["workflow-http-backend-src-controllers-licensee-controller-ts-get-licensee","workflow-http-backend-src-controllers-licensee-controller-ts-get-licensees"],repositoryCallers:["backend/src/rls-waves/session-a/tenantDirectoryRepository.ts:readLicenseeDirectory"],inputAuthority:"capability and live database relationships; the licensee identifier is a selector only",outputColumns:["payload"],disposableProbes:["tenant-directory-postgres18"],
  },
  {
    id:"tenant-directory-users",schema:"app_rls",name:"read_user_directory",signature:"text,text,text,text,boolean,text,integer,integer",returnType:"TABLE(payload jsonb, total bigint)",
    identityArguments:"p_capability text, p_purpose text, p_request_id text, p_requested_licensee_id text, p_include_inactive boolean, p_role_filter text, p_limit integer, p_offset integer",definitionLocation:operationalReadSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:tenantDirectorySecurity,
    tableCommands:[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"]],
    context:"Verifies the opaque authenticated-session capability and projects only users reachable through live platform, tenant-admin, or manufacturer-linked scope; filters and pagination never establish authority.",
    canonicalWorkflowIds:["workflow-http-backend-src-controllers-user-controller-ts-get-users"],repositoryCallers:["backend/src/rls-waves/session-a/tenantDirectoryRepository.ts:readUserDirectory"],inputAuthority:"capability and live database relationships; filters are selectors only",outputColumns:["payload","total"],disposableProbes:["tenant-directory-postgres18"],
  },
  ...[
    ["create-licensee","session_c_create_licensee",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","INSERT"],["Organization","SELECT"],["Organization","INSERT"],["Licensee","SELECT"],["Licensee","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-licensee-controller-ts-create-licensee","backend/src/rls-waves/session-c/c01/administrationRepository.ts:createLicensee"],
    ["update-licensee","session_c_update_licensee",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["Licensee","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-licensee-controller-ts-update-licensee","backend/src/rls-waves/session-c/c01/administrationRepository.ts:updateLicensee"],
    ["delete-licensee","session_c_delete_licensee",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Licensee","DELETE"],["Batch","SELECT"],["QRRange","SELECT"],["QRCode","SELECT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-licensee-controller-ts-delete-licensee","backend/src/rls-waves/session-c/c01/administrationRepository.ts:deleteLicensee"],
    ["create-user","session_c_create_user",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","INSERT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["ManufacturerLicenseeLink","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-user-controller-ts-create-user","backend/src/rls-waves/session-c/c01/administrationRepository.ts:createUser"],
    ["update-user","session_c_update_user",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","UPDATE"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["ManufacturerLicenseeLink","INSERT"],["ManufacturerLicenseeLink","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-user-controller-ts-update-user","backend/src/rls-waves/session-c/c01/administrationRepository.ts:updateUser"],
    ["delete-user","session_c_delete_user",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","UPDATE"],["User","DELETE"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["ManufacturerLicenseeLink","UPDATE"],["ManufacturerLicenseeLink","DELETE"],["Batch","SELECT"],["Batch","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-user-controller-ts-delete-user","backend/src/rls-waves/session-c/c01/administrationRepository.ts:deleteUser"],
    ["restore-manufacturer","session_c_restore_manufacturer",[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","UPDATE"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["ManufacturerLicenseeLink","INSERT"],["ManufacturerLicenseeLink","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],"workflow-http-backend-src-controllers-user-controller-ts-restore-manufacturer","backend/src/rls-waves/session-c/c01/administrationRepository.ts:restoreManufacturer"],
  ].map(([id,name,tableCommands,workflow,caller]) => ({
    id:`c01-administration-${id}`,schema:"app_rls",name,signature:"text,text,text,jsonb",returnType:"jsonb",
    identityArguments:"p_capability text, p_purpose text, p_request_id text, payload jsonb",
    definitionLocation:administrationSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",
    security:administrationSecurity,tableCommands,
    context:"Verifies the database session capability, derives the live actor and exact tenant scope, and executes one allowlisted administration transition atomically; payload identifiers are selectors only.",
    canonicalWorkflowIds:[workflow],repositoryCallers:[caller],inputAuthority:"verified capability and live database relationships; JSON fields cannot establish actor or tenant authority",outputColumns:["jsonb"],disposableProbes:["administration-mutation-postgres18"],
  })),
  ...[
    ["allocate-range","qr_allocate_range","text,text,text,text,integer,integer,text,text","p_capability text, p_purpose text, p_request_id text, p_licensee_id text, p_start_number integer, p_end_number integer, p_received_batch_name text, p_source text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRRange","SELECT"],["QRRange","INSERT"],["QRCode","SELECT"],["QRCode","INSERT"],["Batch","SELECT"],["Batch","INSERT"],["AllocationEvent","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-allocate-qr-range","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:allocateRange"],
    ["read-codes","qr_read_codes","text,text,text,text,text,text,integer,integer","p_capability text, p_purpose text, p_request_id text, p_licensee_id text, p_status text, p_query text, p_limit integer, p_offset integer","TABLE(payload jsonb, total bigint)",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"],["Batch","SELECT"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-get-qr-codes","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:readCodes"],
    ["stats","qr_stats","text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_licensee_id text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-get-stats","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:readStats"],
    ["delete-codes","qr_delete_codes","text,text,text,text[],text[]","p_capability text, p_purpose text, p_request_id text, p_ids text[], p_codes text[]","integer",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"],["QRCode","DELETE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-bulk-delete-qr-codes","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:deleteCodes"],
    ["get-code-scope","qr_get_code_scope","text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_qr_id text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-block-qr-code","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:getCodeScope"],
    ["bind-break-glass-tokens","qr_bind_break_glass_tokens","text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_licensee_id text, p_tokens jsonb","integer",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"],["QRCode","UPDATE"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-generate-qr-codes","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:bindBreakGlassTokens"],
    ["batch-command","qr_batch_command","text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_operation text, p_payload jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"],["QRCode","UPDATE"],["Batch","SELECT"],["Batch","INSERT"],["Batch","UPDATE"],["Batch","DELETE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      "workflow-http-backend-src-controllers-qr-controller-ts-create-batch","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:mutateBatch"],
    ["approve-allocation-request","qr_approve_allocation_request","text,text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_allocation_request_id text, p_decision_note text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QrAllocationRequest","SELECT"],["QrAllocationRequest","UPDATE"],["QRRange","SELECT"],["QRRange","INSERT"],["QRCode","SELECT"],["QRCode","INSERT"],["Batch","SELECT"],["Batch","INSERT"],["AllocationEvent","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      "workflow-http-backend-src-controllers-qr-request-controller-ts-approve-qr-allocation-request","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:approveAllocationRequest"],
    ["inventory-projection","qr_inventory_projection","text,text,text,text,text,text,text,text,integer,integer","p_capability text, p_purpose text, p_request_id text, p_licensee_id text, p_manufacturer_id text, p_batch_query text, p_code_query text, p_status text, p_limit integer, p_offset integer","TABLE(payload jsonb, total bigint)",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"],["Batch","SELECT"]],
      "workflow-internal-backend-src-services-qr-tracking-analytics-service-ts-build-inventory-analytics","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:readInventoryProjection"],
    ["audit-export","qr_export_codes","text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_batch_id text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["QRCode","SELECT"],["Batch","SELECT"],["TraceEvent","SELECT"],["PolicyAlert","SELECT"]],
      "workflow-http-backend-src-controllers-trace-policy-controller-ts-export-batch-audit-package-controller","backend/src/rls-waves/session-c/c01/qrSystemRepository.ts:readAuditExport"],
  ].map(([id,name,signature,identityArguments,returnType,tableCommands,workflow,caller]) => ({
    id:`release-fix-4-${id}`,schema:"app_rls",name,signature,returnType,
    identityArguments,definitionLocation:qrSystemSource,definitionKind:"checked-in-production-package",
    definitionStatus:"production-reviewed",security:qrSystemSecurity,tableCommands,
    context:"Verifies the database session capability and derives live platform, licensee, or manufacturer-linked scope before one fixed QR operation; selectors never establish authority.",
    canonicalWorkflowIds:[workflow],repositoryCallers:[caller],
    inputAuthority:"verified capability and live database relationships; QR, batch, range and tenant values are selectors only",
    outputColumns:returnType==="TABLE(payload jsonb, total bigint)"?["payload","total"]:
      returnType==="TABLE(payload jsonb)"?["payload"]:["result"],
    disposableProbes:["qr-system-postgres18"],
  })),
  {
    id:"release-fix-4-refresh-inventory-rollups",schema:"app_rls",name:"refresh_inventory_status_rollups",
    signature:"text",returnType:"integer",identityArguments:"p_request_id text",
    definitionLocation:qrSystemSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",
    security:{...qrSystemSecurity,runtimeExecuteGrantees:["worker"]},
    tableCommands:[["Batch","SELECT"],["QRCode","SELECT"],["InventoryStatusRollup","SELECT"],["InventoryStatusRollup","INSERT"],["InventoryStatusRollup","UPDATE"],["SystemCheckpoint","SELECT"],["SystemCheckpoint","INSERT"],["SystemCheckpoint","UPDATE"]],
    context:"The exact worker role invokes one set-based, checkpointed inventory rollup transaction; the function installs its fixed operation locally and the worker retains no table privilege.",
    canonicalWorkflowIds:["workflow-internal-backend-src-services-analytics-rollup-service-ts-refresh-inventory-status-rollups"],
    repositoryCallers:["backend/src/services/analyticsRollupService.ts:refreshInventoryStatusRollups"],
    inputAuthority:"exact worker database identity; request ID supplies attribution only",outputColumns:["result"],disposableProbes:["qr-system-postgres18"],
  },
  {
    id:"release-fix-4-refresh-scan-rollups",schema:"app_rls",name:"refresh_scan_metrics_hourly_rollups",
    signature:"text",returnType:"integer",identityArguments:"p_request_id text",
    definitionLocation:qrSystemSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",
    security:{...qrSystemSecurity,runtimeExecuteGrantees:["worker"]},
    tableCommands:[["QrScanLog","SELECT"],["Batch","SELECT"],["ScanMetricsHourlyRollup","SELECT"],["ScanMetricsHourlyRollup","INSERT"],["ScanMetricsHourlyRollup","UPDATE"],["SystemCheckpoint","SELECT"],["SystemCheckpoint","INSERT"],["SystemCheckpoint","UPDATE"]],
    context:"The exact worker role invokes one checkpointed hourly scan aggregation transaction; the function installs its fixed operation locally and the worker retains no table privilege.",
    canonicalWorkflowIds:["workflow-internal-backend-src-services-analytics-rollup-service-ts-refresh-scan-metrics-hourly-rollups"],
    repositoryCallers:["backend/src/services/analyticsRollupService.ts:refreshScanMetricsHourlyRollups"],
    inputAuthority:"exact worker database identity; request ID supplies attribution only",outputColumns:["result"],disposableProbes:["qr-system-postgres18"],
  },
  ...[
    ["readiness","printing_readiness","text,text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_operation text, p_subject_id text, p_options jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Batch","SELECT"],["QRCode","SELECT"],["PrintJob","SELECT"],["PrintSession","SELECT"],["PrintItem","SELECT"],["PrintAuditEvent","SELECT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:readPrintingProjection"]],
    ["create-job","printing_create_job","text,text,text,text,text,integer,text,text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_batch_id text, p_printer_id text, p_quantity integer, p_range_start text, p_range_end text, p_print_mode text, p_payload_type text, p_print_lock_token_hash text, p_items jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Batch","SELECT"],["Batch","UPDATE"],["QRCode","SELECT"],["QRCode","UPDATE"],["Printer","SELECT"],["PrinterRegistration","SELECT"],["PrinterAttestation","SELECT"],["PrintJob","SELECT"],["PrintJob","INSERT"],["PrintSession","SELECT"],["PrintSession","INSERT"],["PrintItem","SELECT"],["PrintItem","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:createPrintingJob"]],
    ["control-job","printing_control_job","text,text,text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_job_id text, p_operation text, p_reason text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Batch","SELECT"],["PrintJob","SELECT"],["PrintJob","UPDATE"],["PrintSession","SELECT"],["PrintSession","UPDATE"],["PrintItem","SELECT"],["PrintItem","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:controlPrintingJob"]],
    ["printer-administration","printing_printer_administration","text,text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_operation text, p_printer_id text, p_payload jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["PrinterRegistration","SELECT"],["Printer","SELECT"],["Printer","INSERT"],["Printer","UPDATE"],["Printer","DELETE"],["PrintJob","SELECT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:administerPrintingPrinter"]],
    ["idempotency","printing_idempotency","text,text,text,text,text,text,text,integer,jsonb","p_capability text, p_purpose text, p_request_id text, p_operation text, p_action text, p_key_hash text, p_request_hash text, p_status_code integer, p_response jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:beginPrintingIdempotency","backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:completePrintingIdempotency","backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:abortPrintingIdempotency"]],
    ["connector-registration","printing_connector_registration","text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_operation text, p_payload jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["PrinterRegistration","SELECT"],["PrinterRegistration","INSERT"],["PrinterRegistration","UPDATE"],["PrinterAttestation","SELECT"],["PrinterAttestation","INSERT"],["Printer","SELECT"],["Printer","INSERT"],["Printer","UPDATE"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:registerPrintingConnector"]],
    ["test-label-job","printing_test_label_job","text,text,text,text,jsonb,jsonb","p_capability text, p_request_id text, p_operation text, p_printer_id text, p_connector jsonb, p_job jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["PrinterRegistration","SELECT"],["PrinterAttestation","SELECT"],["Printer","SELECT"],["Printer","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:mutatePrintingTestLabelJob"]],
    ["connector-event","printing_connector_event","text,text,text,text,timestamp without time zone,text,text,text,text,text,text,text,jsonb","p_registration_id text, p_agent_id text, p_device_fingerprint text, p_nonce text, p_issued_at timestamp without time zone, p_request_id text, p_operation text, p_job_id text, p_item_id text, p_printer_id text, p_payload_hash text, p_device_job_ref text, p_details jsonb","jsonb",
      [["PrinterRegistration","SELECT"],["Printer","SELECT"],["PrinterAttestation","INSERT"],["Batch","UPDATE"],["QRCode","UPDATE"],["PrintJob","SELECT"],["PrintJob","UPDATE"],["PrintSession","SELECT"],["PrintSession","UPDATE"],["PrintItem","SELECT"],["PrintItem","UPDATE"],["PrintItemEvent","INSERT"],["PrintAuditEvent","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:recordConnectorEvent"]],
    ["connector-identity","printing_connector_identity","text,text,text,text,text,text,text","p_kind text, p_agent_id text, p_device_fingerprint text, p_printer_selector text, p_gateway_id text, p_gateway_secret_hash text, p_operation text","jsonb",
      [["PrinterRegistration","SELECT"],["PrinterRegistration","UPDATE"],["Printer","SELECT"],["Printer","UPDATE"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:resolvePrintingConnectorIdentity"]],
    ["gateway-job","printing_gateway_job","text,text,text,text,text,text,text,jsonb","p_gateway_id text, p_gateway_secret_hash text, p_request_id text, p_operation text, p_mode text, p_job_id text, p_item_id text, p_details jsonb","jsonb",
      [["Batch","UPDATE"],["QRCode","SELECT"],["QRCode","UPDATE"],["PrintJob","SELECT"],["PrintJob","UPDATE"],["PrintSession","SELECT"],["PrintSession","UPDATE"],["PrintItem","SELECT"],["PrintItem","UPDATE"],["PrintItemEvent","INSERT"],["PrintAuditEvent","INSERT"],["Printer","SELECT"],["Printer","UPDATE"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:recordGatewayPrintingEvent"]],
    ["record-sample","printing_record_sample","text,text,text,text,text,jsonb","p_capability text, p_purpose text, p_request_id text, p_job_id text, p_qr_code text, p_evidence jsonb","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Batch","SELECT"],["Batch","UPDATE"],["QRCode","SELECT"],["QRCode","UPDATE"],["PrintJob","SELECT"],["PrintAuditEvent","SELECT"],["PrintAuditEvent","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:recordPrintingSample"]],
    ["release-batch","printing_release_batch","text,text,text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_batch_id text, p_decision text, p_reason text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Batch","SELECT"],["Batch","UPDATE"],["QRCode","SELECT"],["QRCode","UPDATE"],["PrintJob","SELECT"],["PrintSession","SELECT"],["PrintItem","SELECT"],["SensitiveActionApproval","SELECT"],["SensitiveActionApproval","INSERT"],["SensitiveActionApproval","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:releasePrintingBatch"]],
    ["reissue-request","printing_reissue_request","text,text,text,text,text,text,integer,text,text,text,text","p_capability text, p_purpose text, p_request_id text, p_operation text, p_reissue_id text, p_original_job_id text, p_quantity integer, p_range_start text, p_range_end text, p_reason text, p_decision_note text","jsonb",
      [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Organization","SELECT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Batch","SELECT"],["QRCode","SELECT"],["QRCode","UPDATE"],["Printer","SELECT"],["PrinterAttestation","SELECT"],["PrintJob","SELECT"],["PrintJob","INSERT"],["PrintSession","SELECT"],["PrintSession","INSERT"],["PrintItem","SELECT"],["PrintItem","UPDATE"],["PrintReissueRequest","SELECT"],["PrintReissueRequest","INSERT"],["PrintReissueRequest","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
      ["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:mutatePrintingReissueRequest"]],
  ].map(([id,name,signature,identityArguments,returnType,tableCommands,repositoryCallers]) => ({
    id:`release-fix-5-${id}`,schema:"app_rls",name,signature,returnType,identityArguments,
    definitionLocation:printingLifecycleSource,definitionKind:"checked-in-production-package",
    definitionStatus:"production-reviewed",security:printingLifecycleSecurity,tableCommands,
    context:"Uses the authenticated database-session capability or the exact connector evidence boundary, derives live tenant and manufacturer scope, and validates one fixed printing lifecycle operation under FORCE RLS.",
    canonicalWorkflowIds:[`workflow-release-fix-5-${id}`],repositoryCallers,
    inputAuthority:"database-verified session or reviewed connector evidence; record identifiers are selectors only",
    outputColumns:["result"],disposableProbes:["printing-lifecycle-postgres18"],
  })),
  {
    id:"release-fix-5-worker-reconcile",schema:"app_rls",name:"printing_worker_reconcile",
    signature:"text,text,integer",returnType:"integer",
    identityArguments:"p_operation text, p_request_id text, p_limit integer",
    definitionLocation:printingLifecycleSource,definitionKind:"checked-in-production-package",
    definitionStatus:"production-reviewed",
    security:{...printingLifecycleSecurity,runtimeExecuteGrantees:["worker"]},
    tableCommands:[["Batch","SELECT"],["Batch","UPDATE"],["PrintJob","SELECT"],["PrintItem","SELECT"],["PrintItem","UPDATE"]],
    context:"The exact worker role runs only bounded confirmation-expiry or batch-reconciliation operations with SKIP LOCKED; no worker table privilege is retained.",
    canonicalWorkflowIds:["workflow-release-fix-5-worker-reconcile"],
    repositoryCallers:["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:reconcilePrintingLifecycle"],
    inputAuthority:"exact worker database identity and fixed operation",outputColumns:["result"],
    disposableProbes:["printing-lifecycle-postgres18"],
  },
  {
    id:"release-fix-5-worker-network",schema:"app_rls",name:"printing_worker_network_job",
    signature:"text,text,text,jsonb",returnType:"jsonb",
    identityArguments:"p_operation text, p_request_id text, p_job_id text, p_details jsonb",
    definitionLocation:printingLifecycleSource,definitionKind:"checked-in-production-package",
    definitionStatus:"production-reviewed",
    security:{...printingLifecycleSecurity,runtimeExecuteGrantees:["worker"]},
    tableCommands:[["Batch","SELECT"],["Batch","UPDATE"],["QRCode","SELECT"],["QRCode","UPDATE"],
      ["PrintJob","SELECT"],["PrintJob","UPDATE"],["PrintSession","SELECT"],["PrintSession","UPDATE"],
      ["PrintItem","SELECT"],["PrintItem","UPDATE"],["PrintAuditEvent","INSERT"],["Printer","SELECT"]],
    context:"The exact worker role claims bounded network-print chunks and records transport completion or failure; PostgreSQL derives membership and transitions and the worker retains no table privilege.",
    canonicalWorkflowIds:["workflow-release-fix-5-worker-network"],
    repositoryCallers:["backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts:runNetworkPrintingWorker"],
    inputAuthority:"exact worker database identity, fixed transport operation, and locked print-job membership",
    outputColumns:["result"],disposableProbes:["printing-lifecycle-postgres18"],
  },
  {
    id:"c01-administration-prepare-invitation",schema:"app_rls",name:"prepare_invitation",
    signature:"text,text,text,text,text,text,text,text,text,text,boolean,boolean,text,timestamp without time zone,timestamp without time zone,text,text",
    returnType:'TABLE("actorDisplayName" text, "actorEmail" text, "actorUserId" text, "inviteEmail" text, "inviteExpiresAt" timestamp without time zone, "inviteId" text, "inviteRole" text, "licenseeName" text, "linkAction" text, "userEmail" text, "userId" text, "userLicenseeId" text, "userName" text, "userOrganizationId" text, "userRole" text, "userStatus" text, "workspaceOrganizationId" text)',
    identityArguments:"p_capability text, p_actor_user_id text, p_actor_session_id text, p_request_id text, p_purpose text, p_requested_email text, p_requested_name text, p_requested_role text, p_requested_licensee_id text, p_requested_manufacturer_id text, p_allow_existing_invited_user boolean, p_require_existing_user boolean, p_token_hash text, p_created_at timestamp without time zone, p_expires_at timestamp without time zone, p_ip_hash text, p_user_agent text",
    definitionLocation:administrationSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:administrationSecurity,
    tableCommands:[["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","INSERT"],["Organization","SELECT"],["Organization","INSERT"],["Licensee","SELECT"],["ManufacturerLicenseeLink","SELECT"],["ManufacturerLicenseeLink","INSERT"],["Invite","SELECT"],["Invite","INSERT"],["Invite","UPDATE"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],
    context:"Verifies the authenticated capability and live actor, constrains role assignment to the four approved roles, derives tenant scope from active rows, and atomically creates or replaces one invitation or links one existing manufacturer account.",
    canonicalWorkflowIds:["workflow-http-backend-src-controllers-auth-controller-ts-invite","workflow-http-backend-src-controllers-licensee-invite-controller-ts-resend-licensee-admin-invite"],
    repositoryCallers:["backend/src/rls-waves/session-b/b01/invitationRepository.ts:prepareInvitation"],inputAuthority:"verified capability and token-bound target relationships; actor, tenant, role and manufacturer inputs are selectors only",
    outputColumns:["actorDisplayName","actorEmail","actorUserId","inviteEmail","inviteExpiresAt","inviteId","inviteRole","licenseeName","linkAction","userEmail","userId","userLicenseeId","userName","userOrganizationId","userRole","userStatus","workspaceOrganizationId"],disposableProbes:["administration-mutation-postgres18"],
  },
  {
    id:"b03-enqueue-audit-outbox",schema:"app_rls",name:"enqueue_audit_log_outbox",signature:"jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text",returnType:"TABLE(id text)",identityArguments:"p_payload jsonb, p_payload_digest text, p_idempotency_key text, p_request_id text, p_organization_id text, p_licensee_id text, p_manufacturer_id text, p_initiating_user_id text, p_initiating_actor_role text, p_expires_at timestamp without time zone, p_initial_error_code text",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:{...outboxSecurity,runtimeExecuteGrantees:["app"]},tableCommands:[["AuditLogOutbox","SELECT"],["AuditLogOutbox","INSERT"]],context:"Requires an already verified authenticated-session binding, freezes actor and tenant authority outside JSON and enqueues one digest-bound recovery record.",canonicalWorkflowIds:[auditQueueWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:enqueueAuditLogOutbox"],inputAuthority:"verified session plus immutable digest and idempotency key",outputColumns:["id"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-claim-audit-outbox",schema:"app_rls",name:"claim_audit_log_outbox_slice",signature:"timestamp without time zone,integer",returnType:"TABLE(id text, jobType text, requestId text, payloadDigest text, idempotencyKey text, organizationId text, licenseeId text, manufacturerId text, initiatingUserId text, expiresAt timestamp without time zone, attempt integer)",identityArguments:"p_attempted_at timestamp without time zone, p_batch_size integer",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:outboxSecurity,tableCommands:[["AuditLogOutbox","SELECT"],["AuditLogOutbox","UPDATE"]],context:"The exact worker role uses SKIP LOCKED and a five-minute lease to claim bounded, unexpired recovery records once per attempt.",canonicalWorkflowIds:[auditFlushWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:claimAuditLogOutboxSlice"],inputAuthority:"worker database identity; time and batch size are bounded inputs",outputColumns:["id","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","attempt"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-consume-audit-outbox",schema:"app_rls",name:"consume_audit_log_outbox",signature:"text,text,timestamp without time zone",returnType:"TABLE(auditLogId text, replayed boolean)",identityArguments:"p_job_id text, p_payload_digest text, p_attempted_at timestamp without time zone",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:outboxSecurity,tableCommands:[["AuditLogOutbox","SELECT"],["AuditLogOutbox","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]],context:"Locks the leased row, reconstructs only reviewed audit columns, atomically queues the matching SIEM projection and makes SENT terminal and replay-safe.",canonicalWorkflowIds:[auditFlushWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:consumeAuditLogOutbox"],inputAuthority:"worker identity plus row ID and immutable digest",outputColumns:["auditLogId","replayed"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-fail-audit-outbox",schema:"app_rls",name:"fail_audit_log_outbox",signature:"text,text,timestamp without time zone,integer,text",returnType:"TABLE(terminal boolean, nextAttemptAt timestamp without time zone)",identityArguments:"p_job_id text, p_payload_digest text, p_attempted_at timestamp without time zone, p_attempt integer, p_error_code text",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:outboxSecurity,tableCommands:[["AuditLogOutbox","SELECT"],["AuditLogOutbox","UPDATE"]],context:"Compare-and-sets the exact claimed attempt to bounded retry or terminal failure without mutating SENT rows.",canonicalWorkflowIds:[auditFlushWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:failAuditLogOutbox"],inputAuthority:"worker identity plus row digest and claimed attempt",outputColumns:["terminal","nextAttemptAt"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-enqueue-security-outbox",schema:"app_rls",name:"enqueue_security_event_outbox",signature:"text,jsonb,text,text,text,text,text,text,text,timestamp without time zone",returnType:"TABLE(id text)",identityArguments:"p_event_type text, p_payload jsonb, p_payload_digest text, p_idempotency_key text, p_request_id text, p_organization_id text, p_licensee_id text, p_manufacturer_id text, p_initiating_user_id text, p_expires_at timestamp without time zone",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:{...outboxSecurity,runtimeExecuteGrantees:["app"]},tableCommands:[["SecurityEventOutbox","SELECT"],["SecurityEventOutbox","INSERT"]],context:"Requires verified authenticated-session authority and enqueues only AUDIT_LOG or CSP_VIOLATION with immutable digest and tenant columns.",canonicalWorkflowIds:[securityQueueWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:enqueueSecurityEventOutbox"],inputAuthority:"verified session and exact allowlisted event type",outputColumns:["id"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-claim-security-outbox",schema:"app_rls",name:"claim_security_event_outbox_slice",signature:"timestamp without time zone,integer,text",returnType:"TABLE(id text, jobType text, requestId text, payloadDigest text, idempotencyKey text, organizationId text, licenseeId text, manufacturerId text, initiatingUserId text, expiresAt timestamp without time zone, attempt integer, eventType text, eventPayload jsonb, createdAt timestamp without time zone)",identityArguments:"p_attempted_at timestamp without time zone, p_batch_size integer, p_job_type text",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:outboxSecurity,tableCommands:[["SecurityEventOutbox","SELECT"],["SecurityEventOutbox","UPDATE"]],context:"The exact worker role claims one allowlisted event family using SKIP LOCKED and a bounded lease.",canonicalWorkflowIds:[securityFlushWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:claimSecurityEventOutboxSlice"],inputAuthority:"worker identity plus allowlisted job type",outputColumns:["id","jobType","requestId","payloadDigest","idempotencyKey","organizationId","licenseeId","manufacturerId","initiatingUserId","expiresAt","attempt","eventType","eventPayload","createdAt"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-complete-security-outbox",schema:"app_rls",name:"complete_security_event_outbox",signature:"text,text,timestamp without time zone,text",returnType:"TABLE(completed boolean, replayed boolean)",identityArguments:"p_job_id text, p_payload_digest text, p_attempted_at timestamp without time zone, p_sink_event_id text",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:outboxSecurity,tableCommands:[["SecurityEventOutbox","SELECT"],["SecurityEventOutbox","UPDATE"]],context:"Locks the leased row, records one bounded external sink identifier and makes SENT replay-safe and terminal.",canonicalWorkflowIds:[securityFlushWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:completeSecurityEventOutbox"],inputAuthority:"worker identity, row digest and external sink result",outputColumns:["completed","replayed"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-fail-security-outbox",schema:"app_rls",name:"fail_security_event_outbox",signature:"text,text,timestamp without time zone,integer,text",returnType:"TABLE(terminal boolean, nextAttemptAt timestamp without time zone)",identityArguments:"p_job_id text, p_payload_digest text, p_attempted_at timestamp without time zone, p_attempt integer, p_error_code text",definitionLocation:outboxSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:outboxSecurity,tableCommands:[["SecurityEventOutbox","SELECT"],["SecurityEventOutbox","UPDATE"]],context:"Compare-and-sets the exact claimed delivery attempt to bounded retry or terminal failure without reopening SENT rows.",canonicalWorkflowIds:[securityFlushWorkflow],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:failSecurityEventOutbox"],inputAuthority:"worker identity plus row digest and claimed attempt",outputColumns:["terminal","nextAttemptAt"],disposableProbes:["b03-outbox-postgres18"],
  },
  {
    id:"b03-primary-superadmin-email",schema:"app_rls",name:"b03_primary_superadmin_email",signature:"",returnType:"TABLE(email text)",identityArguments:"",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"]],context:"Returns at most the oldest live platform administrator email after capability revalidation.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:getPrimarySuperadminEmail"],inputAuthority:"authenticated capability",outputColumns:["email"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-superadmin-alert-emails",schema:"app_rls",name:"b03_superadmin_alert_emails",signature:"",returnType:"TABLE(email text)",identityArguments:"",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"]],context:"Returns a bounded live platform administrator delivery list after capability revalidation.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:getSuperadminAlertEmails"],inputAuthority:"authenticated capability",outputColumns:["email"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-resolve-incident-email-actor",schema:"app_rls",name:"b03_resolve_incident_email_actor",signature:"text",returnType:"TABLE(id text,email text,name text,role text,active boolean)",identityArguments:"p_actor_user_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"]],context:"Projects only the currently authenticated live actor and rejects caller-selected users.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:resolveIncidentEmailActor"],inputAuthority:"authenticated capability; user ID must equal actor",outputColumns:["id","email","name","role","active"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-create-role-notifications",schema:"app_rls",name:"b03_create_role_notifications",signature:"text,text,text,text,text,text,text,jsonb,text[],text",returnType:"TABLE(notificationId text,userId text,userEmail text,userRole text,userLicenseeId text,userOrganizationId text,channel text,writeResult jsonb,sideEffectRequired boolean)",identityArguments:"p_audience text, p_title text, p_body text, p_type text, p_licensee_id text, p_organization_id text, p_incident_id text, p_data jsonb, p_channels text[], p_request_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Incident","SELECT"],["Notification","INSERT"]],context:"Creates bounded per-recipient notification rows only within the capability-derived actor scope and canonical four-role model.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:createRoleNotifications"],inputAuthority:"authenticated capability; requested scope only narrows database-derived authority",outputColumns:["notificationId","userId","userEmail","userRole","userLicenseeId","userOrganizationId","channel","writeResult","sideEffectRequired"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-create-user-notification",schema:"app_rls",name:"b03_create_user_notification",signature:"text,text,text,text,text,text,text,jsonb,text,text",returnType:"TABLE(notificationId text,userId text,userEmail text,userRole text,userLicenseeId text,userOrganizationId text,channel text,writeResult jsonb,sideEffectRequired boolean,notification jsonb)",identityArguments:"p_user_id text, p_title text, p_body text, p_type text, p_licensee_id text, p_organization_id text, p_incident_id text, p_data jsonb, p_channel text, p_request_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Incident","SELECT"],["Notification","INSERT"]],context:"Creates one notification for a database-visible live target under the actor capability and returns the explicit projection.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:createUserNotification"],inputAuthority:"authenticated capability; target ID is selection-only",outputColumns:["notificationId","userId","userEmail","userRole","userLicenseeId","userOrganizationId","channel","writeResult","sideEffectRequired","notification"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-mark-notification-emailed",schema:"app_rls",name:"b03_mark_notification_emailed",signature:"text,timestamp without time zone,text",returnType:"TABLE(updated boolean)",identityArguments:"p_notification_id text, p_emailed_at timestamp without time zone, p_request_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Notification","UPDATE"]],context:"Idempotently records delivery only for a notification within the live actor scope.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:markNotificationEmailed"],inputAuthority:"authenticated capability; notification ID is selection-only",outputColumns:["updated"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-list-notifications",schema:"app_rls",name:"b03_list_notifications_for_user",signature:"text,integer,integer,boolean,timestamp without time zone,text,text",returnType:"TABLE(notifications jsonb,total integer,unread integer)",identityArguments:"p_user_id text, p_limit integer, p_offset integer, p_unread_only boolean, p_cursor_created_at timestamp without time zone, p_cursor_id text, p_request_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Notification","SELECT"]],context:"Returns one bounded stable page of direct and scoped broadcast notifications for the authenticated user only.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:listNotificationsForUser"],inputAuthority:"authenticated capability; user ID must equal actor",outputColumns:["notifications","total","unread"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-mark-notification-read",schema:"app_rls",name:"b03_mark_notification_read",signature:"text,text,timestamp without time zone,text",returnType:"TABLE(notification jsonb)",identityArguments:"p_notification_id text, p_user_id text, p_read_at timestamp without time zone, p_request_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Notification","SELECT"],["Notification","UPDATE"]],context:"Idempotently marks one direct notification read only for its authenticated owner.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:markNotificationRead"],inputAuthority:"authenticated capability; user ID must equal actor",outputColumns:["notification"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-mark-all-notifications-read",schema:"app_rls",name:"b03_mark_all_notifications_read",signature:"text,timestamp without time zone,text",returnType:"TABLE(count integer)",identityArguments:"p_user_id text, p_read_at timestamp without time zone, p_request_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Notification","UPDATE"]],context:"Marks only the authenticated user's unread direct web notifications read.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:markAllNotificationsRead"],inputAuthority:"authenticated capability; user ID must equal actor",outputColumns:["count"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-resolve-incident-notification-scope",schema:"app_rls",name:"b03_resolve_incident_notification_scope",signature:"text",returnType:"TABLE(incidentId text,licenseeId text,manufacturerOrganizationId text)",identityArguments:"p_incident_id text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Incident","SELECT"],["QRCode","SELECT"],["Batch","SELECT"]],context:"Resolves an incident's notification tenant and manufacturer organization only after live actor scope checks.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:resolveIncidentNotificationScope"],inputAuthority:"authenticated capability; incident ID is selection-only",outputColumns:["incidentId","licenseeId","manufacturerOrganizationId"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-claim-incident-email",schema:"app_rls",name:"b03_claim_incident_email_delivery",signature:"text,text,text,text,text,text,text,text,text,text,text,text,text,text",returnType:"TABLE(deliveryId text,disposition text,delivered boolean,providerMessageId text,emailErrorCode text,attemptedFrom text,usedFrom text,replyTo text)",identityArguments:"p_incident_id text, p_licensee_id text, p_actor_user_id text, p_sender_mode text, p_to_address text, p_subject text, p_body_preview text, p_attempted_from text, p_used_from text, p_reply_to text, p_template text, p_request_id text, p_idempotency_key text, p_payload_digest text",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["ManufacturerLicenseeLink","SELECT"],["Incident","SELECT"],["IncidentCommunication","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"]],context:"Claims one digest-bound incident email and creates its queued evidence atomically; replay returns the prior disposition.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:claimIncidentEmailDelivery"],inputAuthority:"authenticated capability and database incident scope",outputColumns:["deliveryId","disposition","delivered","providerMessageId","emailErrorCode","attemptedFrom","usedFrom","replyTo"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id:"b03-complete-incident-email",schema:"app_rls",name:"b03_complete_incident_email_delivery",signature:"text,text,text,text,text,text,text,timestamp without time zone",returnType:"TABLE(communicationId text,eventId text,auditLogId text)",identityArguments:"p_delivery_id text, p_idempotency_key text, p_provider_message_id text, p_email_error_code text, p_status text, p_smtp_config_source text, p_used_from text, p_completed_at timestamp without time zone",definitionLocation:b03AuthenticatedSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:b03AuthenticatedSecurity,tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Incident","SELECT"],["IncidentCommunication","SELECT"],["IncidentCommunication","UPDATE"],["IncidentEvent","INSERT"],["AuditLog","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","UPDATE"]],context:"Completes the exact claimed delivery, records the actual SMTP sender after fallback, and appends incident and audit evidence atomically; completed replay is stable.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:completeIncidentEmailDelivery"],inputAuthority:"authenticated capability plus prior digest-bound claim",outputColumns:["communicationId","eventId","auditLogId"],disposableProbes:["b03-authenticated-postgres18"],
  },
  {
    id: "b03-provision-scheduled-job-credential", schema: "app_rls", name: "provision_scheduled_job_credential", signature: "text,text,text,timestamp with time zone,text,text", returnType: "text",
    identityArguments: "p_credential_id text, p_schedule_id text, p_capability_hash text, p_expires_at timestamp with time zone, p_rotated_from_credential_id text, p_request_id text", definitionLocation: scheduledSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...scheduledSecurity, runtimeExecuteGrantees: ["operator"] }, tableCommands: [["ScheduledJobCredential","SELECT"],["ScheduledJobCredential","INSERT"],["ScheduledJobCredential","UPDATE"]], context: "The exact operator role provisions only a sha256-v1 hash and atomically revokes the predecessor during rotation; PostgreSQL never receives the raw capability.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-b/b03/scheduledJobCredentialService.ts:provisionScheduledJobCredential"], inputAuthority: "operator role plus server-generated credential ID and SHA-256 hash", outputColumns: ["credentialId"], disposableProbes: ["scheduled-job-identity-postgres18"],
  },
  {
    id: "b03-revoke-scheduled-job-credential", schema: "app_rls", name: "revoke_scheduled_job_credential", signature: "text,text,text", returnType: "boolean",
    identityArguments: "p_credential_id text, p_reason text, p_request_id text", definitionLocation: scheduledSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...scheduledSecurity, runtimeExecuteGrantees: ["operator"] }, tableCommands: [["ScheduledJobCredential","SELECT"],["ScheduledJobCredential","UPDATE"]], context: "The exact operator role revokes one credential ID without exposing its hash; repeat revocation is idempotent.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-b/b03/scheduledJobCredentialService.ts:revokeScheduledJobCredential"], inputAuthority: "operator role and exact credential selector", outputColumns: ["revoked"], disposableProbes: ["scheduled-job-identity-postgres18"],
  },
  {
    id: "b03-claim-compliance-pack-slice", schema: "app_rls", name: "claim_compliance_pack_slice", signature: "text,text,timestamp without time zone,integer", returnType: "TABLE(jobId text, requestId text, organizationId text, licenseeId text, scheduleScopeVersion text, expiresAt timestamp without time zone, attempt integer, report jsonb)",
    identityArguments: "p_capability text, p_schedule_id text, p_due_at timestamp without time zone, p_batch_size integer", definitionLocation: scheduledSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: scheduledSecurity, tableCommands: [...scheduledReadCommands,["CompliancePackJob","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLogOutbox","INSERT"]], context: "Hashes and verifies the exact scheduled capability before enumerating active database-derived licensee partitions and atomically claiming one daily job per partition.", canonicalWorkflowIds: [scheduledComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:claimCompliancePackSlice"], inputAuthority: "opaque scheduled capability; schedule ID is bound to its durable credential", outputColumns: ["jobId","requestId","organizationId","licenseeId","scheduleScopeVersion","expiresAt","attempt","report"], disposableProbes: ["scheduled-job-identity-postgres18"],
  },
  {
    id: "b03-get-scheduled-compliance-pack", schema: "app_rls", name: "scheduled_get_compliance_pack_job", signature: "text,text,text,text", returnType: "jsonb",
    identityArguments: "p_capability text, p_schedule_id text, p_request_id text, p_job_id text", definitionLocation: scheduledSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: scheduledSecurity, tableCommands: scheduledReadCommands, context: "Verifies the scheduled capability and returns one scheduled job plus a tenant-scoped report; job ID is selection-only.", canonicalWorkflowIds: [scheduledComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:getScheduledCompliancePackJob"], inputAuthority: "opaque scheduled capability plus credential-bound schedule", outputColumns: ["job","report"], disposableProbes: ["scheduled-job-identity-postgres18"],
  },
  {
    id: "b03-complete-scheduled-compliance-pack", schema: "app_rls", name: "scheduled_complete_compliance_pack_job", signature: "text,text,text,text,jsonb", returnType: "jsonb",
    identityArguments: "p_capability text, p_schedule_id text, p_request_id text, p_job_id text, p_result jsonb", definitionLocation: scheduledSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: scheduledSecurity, tableCommands: scheduledTransitionCommands, context: "Verifies the scheduled capability, locks one SCHEDULED RUNNING job and atomically compare-and-sets its immutable artifact result and audit outbox.", canonicalWorkflowIds: [scheduledComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:completeScheduledCompliancePackJob"], inputAuthority: "opaque scheduled capability; job ID and artifact are bounded mutation inputs", outputColumns: ["job"], disposableProbes: ["scheduled-job-identity-postgres18"],
  },
  {
    id: "b03-fail-scheduled-compliance-pack", schema: "app_rls", name: "scheduled_fail_compliance_pack_job", signature: "text,text,text,text,text", returnType: "jsonb",
    identityArguments: "p_capability text, p_schedule_id text, p_request_id text, p_job_id text, p_error_code text", definitionLocation: scheduledSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: scheduledSecurity, tableCommands: scheduledTransitionCommands, context: "Verifies the scheduled capability, locks one SCHEDULED RUNNING job and atomically records one bounded terminal failure and audit outbox.", canonicalWorkflowIds: [scheduledComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-b/b03/repositoryFunctions.ts:failScheduledCompliancePackJob"], inputAuthority: "opaque scheduled capability; job ID and bounded error code are mutation inputs", outputColumns: ["job"], disposableProbes: ["scheduled-job-identity-postgres18"],
  },
  {
    id: "b01-lookup-password-user", schema: "app_auth", name: "lookup_password_user", signature: "text",
    returnType: "TABLE(id text, email text, passwordHash text, name text, role text, licenseeId text, orgId text, status text, isActive boolean, disabledAt timestamp without time zone, deletedAt timestamp without time zone, failedLoginAttempts integer, lockedUntil timestamp without time zone, lastLoginAt timestamp without time zone, emailVerifiedAt timestamp without time zone)",
    identityArguments: "p_requested_email text", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["User","SELECT"]], context: "A normalized email selects at most one password bootstrap record; duplicate case-insensitive state fails closed and caller GUCs are overwritten.",
    canonicalWorkflowIds: ["workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-find-pre-candidate-password-user"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:lookupPasswordBootstrapUser"], inputAuthority: "normalized email is lookup-only and never establishes authenticated authority", outputColumns: ["id","email","passwordHash","name","role","licenseeId","orgId","status","isActive","disabledAt","deletedAt","failedLoginAttempts","lockedUntil","lastLoginAt","emailVerifiedAt"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-record-password-failure", schema: "app_auth", name: "record_password_failure", signature: "text,timestamp without time zone,integer,integer", returnType: "TABLE(failedLoginAttempts integer, lockedUntil timestamp without time zone)",
    identityArguments: "p_requested_email text, p_attempted_at timestamp without time zone, p_max_attempts integer, p_lockout_minutes integer", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["User","SELECT"],["User","UPDATE"]], context: "One bounded failed-login invocation atomically increments the exact normalized account and never shortens an existing lock.",
    canonicalWorkflowIds: ["workflow-startup-backend-src-services-auth-auth-bootstrap-repository-ts-record-password-login-failure"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:recordPasswordLoginFailure"], inputAuthority: "normalized email selects the account; bounded threshold and duration are mutation inputs", outputColumns: ["failedLoginAttempts","lockedUntil"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-request-password-reset", schema: "app_auth", name: "request_password_reset", signature: "text,text,timestamp without time zone,timestamp without time zone,text,text", returnType: "TABLE(accepted boolean, deliveryRequired boolean, userId text, email text, licenseeId text, orgId text, expiresAt timestamp without time zone)",
    identityArguments: "p_requested_email text, p_reset_token_hash text, p_expires_at timestamp without time zone, p_requested_at timestamp without time zone, p_created_ip_hash text, p_user_agent_hash text", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["User","SELECT"],["PasswordReset","INSERT"],["AuditLogOutbox","INSERT"]], context: "Issues one hashed reset bearer only for one eligible normalized account while preserving the constant-success external response and atomic audit outbox.",
    canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-password-reset-service-ts-request-password-reset"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:requestPasswordResetBoundary"], inputAuthority: "server-generated token hash and normalized email; the matched User row supplies user and tenant binding", outputColumns: ["accepted","deliveryRequired","userId","email","licenseeId","orgId","expiresAt"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-consume-password-reset", schema: "app_auth", name: "consume_password_reset_token", signature: "text[],text,timestamp without time zone", returnType: "TABLE(id text, email text, name text, role text, licenseeId text, orgId text)",
    identityArguments: "p_token_hash_candidates text[], p_new_password_hash text, p_consumed_at timestamp without time zone", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["PasswordReset","SELECT"],["PasswordReset","UPDATE"],["User","SELECT"],["User","UPDATE"],["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["AuditLogOutbox","INSERT"]], context: "Locks one unused reset bearer, derives its user, changes the password, consumes the token, revokes refresh/session capability state and audits atomically.",
    canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-password-reset-service-ts-reset-password-with-token"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:consumePasswordResetBoundary"], inputAuthority: "1..3 server-derived bearer hashes; PasswordReset.userId is the sole account authority", outputColumns: ["id","email","name","role","licenseeId","orgId"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-lookup-invitation", schema: "app_auth", name: "lookup_invitation_token", signature: "text[],timestamp without time zone", returnType: "TABLE(email text, role text, expiresAt timestamp without time zone, licenseeName text, requiresConnector boolean)",
    identityArguments: "p_token_hash_candidates text[], p_checked_at timestamp without time zone", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["Invite","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"]], context: "Returns only a minimal preview after exact-one bearer, bound invited-user, role-family and live tenant validation.",
    canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-invite-service-ts-get-invite-preview"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:lookupInvitationBoundary"], inputAuthority: "hashed invite bearer; all user and tenant data are derived from its stored relationship", outputColumns: ["email","role","expiresAt","licenseeName","requiresConnector"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-consume-invitation", schema: "app_auth", name: "consume_invitation_token", signature: "text[],text,text,timestamp without time zone,text,text,text", returnType: "TABLE(inviteId text, id text, email text, name text, role text, licenseeId text, orgId text, status text)",
    identityArguments: "p_token_hash_candidates text[], p_new_password_hash text, p_requested_name text, p_consumed_at timestamp without time zone, p_request_id text, p_ip_hash text, p_user_agent text", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["Invite","SELECT"],["Invite","UPDATE"],["User","SELECT"],["User","UPDATE"],["Licensee","SELECT"],["Organization","SELECT"],["AuditLogOutbox","INSERT"]], context: "Locks one invite and its pre-created same-email/same-role/same-tenant user, activates it without changing role or ownership, consumes the bearer and audits atomically.",
    canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-invite-service-ts-accept-invite"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:consumeInvitationBoundary"], inputAuthority: "hashed invitation bearer; request metadata is attribution only", outputColumns: ["inviteId","id","email","name","role","licenseeId","orgId","status"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-consume-email-verification", schema: "app_auth", name: "consume_email_verification_token", signature: "text[],timestamp without time zone", returnType: "TABLE(verified boolean, purpose text, userId text, email text)",
    identityArguments: "p_token_hash_candidates text[], p_consumed_at timestamp without time zone", definitionLocation: preAuthSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: preAuthSecurity,
    tableCommands: [["EmailVerificationToken","SELECT"],["EmailVerificationToken","UPDATE"],["User","SELECT"],["User","UPDATE"],["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["AuditLogOutbox","INSERT"]], context: "Locks one verification bearer and its bound active user; email change additionally proves the stored pending email and revokes sessions in the same transaction.",
    canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-email-verification-service-ts-confirm-email-verification"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/preAuthRepository.ts:consumeEmailVerificationBoundary"], inputAuthority: "hashed verification bearer; EmailVerificationToken.userId and pendingEmail supply all authority", outputColumns: ["verified","purpose","userId","email"], disposableProbes: ["b01-preauth-security-postgres18"],
  },
  {
    id: "b01-create-login-refresh-token", schema: "app_rls", name: "create_refresh_token", signature: "text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone", returnType: "TABLE(id text, expiresAt timestamp without time zone)",
    identityArguments: "p_user_id text, p_organization_id text, p_token_hash text, p_expires_at timestamp without time zone, p_ip_hash text, p_user_agent text, p_authenticated_at timestamp without time zone, p_mfa_verified_at timestamp without time zone, p_created_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["preauth"] },
    tableCommands: [["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["RefreshToken","INSERT"],["AuditLogOutbox","INSERT"]], context: "Creates one refresh credential and login audit for the password-verified application subject only after live account and tenant relationship validation; no GUC supplies user or tenant authority.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-refresh-token-service-ts-create-refresh-token"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:createRefreshTokenRecord"], inputAuthority: "trusted password-verification application boundary plus live database actor validation", outputColumns: ["id","expiresAt"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-load-login-risk-inputs", schema: "app_rls", name: "load_recent_auth_session_risk_inputs", signature: "integer", returnType: "TABLE(createdIpHash text, createdUserAgent text, createdAt timestamp without time zone, actorState jsonb)",
    identityArguments: "p_limit integer", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["preauth"] },
    tableCommands: [["User","SELECT"],["RefreshToken","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["AdminMfaCredential","SELECT"],["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"],["UserBackupCode","SELECT"]], context: "After application password proof, validates the live actor and returns that actor's bounded recent-session, tenant and MFA projection.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-session-risk-service-ts-assess-auth-session-risk"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:loadRecentAuthSessionRiskInputs"], inputAuthority: "password-verified application subject; database live state rejects inactive or foreign rows", outputColumns: ["createdIpHash","createdUserAgent","createdAt","actorState"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-record-login-risk", schema: "app_rls", name: "record_auth_session_risk_signal", signature: "integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text", returnType: "TABLE(recorded boolean, challengeCreated boolean)",
    identityArguments: "p_risk_score integer, p_risk_level text, p_reasons text[], p_ip_hash text, p_user_agent_hash text, p_recorded_at timestamp without time zone, p_password_hash text, p_challenge_ticket_hash text, p_challenge_session_hash text, p_challenge_expires_at timestamp without time zone, p_challenge_max_attempts integer, p_request_id text", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["preauth"] },
    tableCommands: [["User","SELECT"],["User","UPDATE"],["AuthSessionRiskSignal","INSERT"],["MfaLoginChallenge","INSERT"],["AuditLogOutbox","INSERT"]], context: "Atomically records the bounded risk result, successful-login state reset, optional password rehash and optional actor-bound MFA login challenge.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-session-risk-service-ts-assess-auth-session-risk"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:recordAuthSessionRiskSignal"], inputAuthority: "password-verified subject bound by app_auth.lookup_password_user; challenge and request values cannot redirect the actor", outputColumns: ["recorded","challengeCreated"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-revalidate-capability-actor", schema: "app_rls", name: "revalidate_authenticated_actor", signature: "text,text,text,text,timestamp without time zone,text", returnType: "TABLE(userId text, role text, organizationId text, licenseeId text, manufacturerId text, authAssurance text)",
    identityArguments: "p_user_id text, p_session_id text, p_requested_licensee_id text, p_requested_organization_id text, p_checked_at timestamp without time zone, p_request_id text", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"]], context: "Verifies the opaque capability and derives live actor scope before treating requested tenant fields as narrowing selectors only.", canonicalWorkflowIds: ["workflow-http-backend-src-middleware-auth-ts-hydrate-tenant-if-needed"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/actorRevalidationRepository.ts:revalidateAuthenticatedActor"], inputAuthority: "opaque database session capability", outputColumns: ["userId","role","organizationId","licenseeId","manufacturerId","authAssurance"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-load-capability-actor", schema: "app_rls", name: "load_authenticated_actor", signature: "", returnType: "TABLE(id text, email text, name text, role text, licenseeId text, orgId text, emailVerifiedAt timestamp without time zone, pendingEmail text, pendingEmailRequestedAt timestamp without time zone, isActive boolean, status text, deletedAt timestamp without time zone, disabledAt timestamp without time zone, createdAt timestamp without time zone, licenseeRecordId text, licenseeName text, licenseePrefix text, licenseeBrandName text, licenseeOrgId text)",
    identityArguments: "", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"]], context: "Returns the existing /auth/me actor projection only after capability verification and live account and tenant validation.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-auth-controller-ts-me"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:loadAuthenticatedActor"], inputAuthority: "opaque database session capability", outputColumns: ["id","email","name","role","licenseeId","orgId","emailVerifiedAt","pendingEmail","pendingEmailRequestedAt","isActive","status","deletedAt","disabledAt","createdAt","licenseeRecordId","licenseeName","licenseePrefix","licenseeBrandName","licenseeOrgId"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "rf7-load-authenticated-manufacturer-scope", schema: "app_rls", name: "load_authenticated_manufacturer_scope", signature: "text,text,text,text,boolean", returnType: "jsonb",
    identityArguments: "p_requested_licensee_id text, p_requested_org_id text, p_requested_scope_version text, p_purpose text, p_write_audit boolean", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["AuditLogOutbox","INSERT"]], context: "Returns the live bounded manufacturer-licensee projection for the capability actor, treats requested scope as a narrowing selector, and optionally queues attributed bootstrap or switch evidence.", canonicalWorkflowIds: ["workflow-http-backend-src-middleware-auth-ts-hydrate-tenant-if-needed","workflow-http-backend-src-controllers-auth-controller-ts-me"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:loadAuthenticatedManufacturerScope"], inputAuthority: "opaque database session capability; requested tenant and scope version cannot establish authority", outputColumns: ["selectedLicensee","linkedLicensees"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-find-capability-refresh-token", schema: "app_rls", name: "find_refresh_token_by_id", signature: "text,text", returnType: "TABLE(id text, userId text, orgId text, expiresAt timestamp without time zone, createdAt timestamp without time zone, createdIpHash text, createdUserAgent text, authenticatedAt timestamp without time zone, mfaVerifiedAt timestamp without time zone, lastUsedAt timestamp without time zone, revokedAt timestamp without time zone, revokedReason text)",
    identityArguments: "p_session_id text, p_user_id text", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"]], context: "Returns only the refresh row that is identical to the capability-derived current session.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-auth-controller-ts-me"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:findRefreshTokenByIdentifier"], inputAuthority: "opaque capability; session ID is equality-checked selector only", outputColumns: ["id","userId","orgId","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt","revokedAt","revokedReason"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-revoke-capability-refresh-token", schema: "app_rls", name: "revoke_refresh_token_by_id", signature: "text,text,text,timestamp without time zone", returnType: "TABLE(revoked boolean)",
    identityArguments: "p_session_id text, p_user_id text, p_reason text, p_revoked_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"]], context: "Atomically revokes the refresh row and capability only when the target is the capability-derived current session.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-refresh-token-service-ts-revoke-refresh-token-by-id"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:revokeRefreshTokenByIdentifier"], inputAuthority: "opaque capability; session ID is a selector restricted to the verified current session", outputColumns: ["revoked"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-require-capability-recent-mfa", schema: "app_rls", name: "require_recent_mfa_session", signature: "text,timestamp without time zone,integer", returnType: "TABLE(verifiedAt timestamp without time zone)",
    identityArguments: "p_session_id text, p_checked_at timestamp without time zone, p_max_age_minutes integer", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"]], context: "Uses the capability-derived current refresh row and its live MFA timestamp; no caller MFA flag establishes assurance.", canonicalWorkflowIds: ["workflow-http-backend-src-middleware-auth-ts-hydrate-tenant-if-needed"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:requireRecentMfaSession"], inputAuthority: "opaque capability plus bounded freshness window", outputColumns: ["verifiedAt"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-load-authenticated-password-actor", schema: "app_rls", name: "load_authenticated_password_actor", signature: "", returnType: "TABLE(id text, passwordHash text, role text, status text, isActive boolean, disabledAt timestamp without time zone, deletedAt timestamp without time zone)",
    identityArguments: "", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"]], context: "Returns the current active actor's password verifier only inside a capability-verified transaction so Node can perform Argon2 or legacy bcrypt proof without exposing it through HTTP.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-account-controller-ts-change-my-password","workflow-http-backend-src-controllers-auth-session-controller-ts-password-step-up-controller"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:loadAuthenticatedPasswordActor"], inputAuthority: "opaque authenticated-session capability", outputColumns: ["id","passwordHash","role","status","isActive","disabledAt","deletedAt"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-list-active-refresh-tokens", schema: "app_rls", name: "list_active_refresh_tokens", signature: "text,timestamp without time zone", returnType: "TABLE(id text, userId text, orgId text, expiresAt timestamp without time zone, createdAt timestamp without time zone, createdIpHash text, createdUserAgent text, authenticatedAt timestamp without time zone, mfaVerifiedAt timestamp without time zone, lastUsedAt timestamp without time zone, revokedAt timestamp without time zone, revokedReason text)",
    identityArguments: "p_user_id text, p_checked_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"]], context: "Returns at most 200 live refresh-session metadata rows for the capability-derived actor and never projects bearer or capability hashes.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-refresh-token-service-ts-list-active-refresh-tokens-for-user"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:listActiveRefreshTokenRecords"], inputAuthority: "opaque capability; user ID is equality-checked against its database actor", outputColumns: ["id","userId","orgId","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt","revokedAt","revokedReason"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-revoke-all-refresh-tokens", schema: "app_rls", name: "revoke_all_refresh_tokens", signature: "text,text,timestamp without time zone", returnType: "TABLE(revokedCount integer)",
    identityArguments: "p_user_id text, p_reason text, p_revoked_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"]], context: "Atomically revokes every live refresh and database-session capability for the capability-derived actor using one fixed reason.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-refresh-token-service-ts-revoke-all-user-refresh-tokens"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:revokeAllRefreshTokenRecords"], inputAuthority: "opaque capability; user ID is equality-checked against its database actor", outputColumns: ["revokedCount"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-prove-authenticated-password-step-up", schema: "app_rls", name: "prove_authenticated_password_step_up", signature: "text,text,timestamp without time zone", returnType: "TABLE(authorized boolean)",
    identityArguments: "p_session_id text, p_expected_password_hash text, p_verified_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"]], context: "Binds the Node-verified password hash to the exact live actor and current session before refreshing its password-authentication timestamp.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-account-controller-ts-change-my-password","workflow-http-backend-src-controllers-auth-session-controller-ts-password-step-up-controller"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:proveAuthenticatedPasswordStepUp"], inputAuthority: "opaque capability plus an exact verifier already read for that same actor in the transaction", outputColumns: ["authorized"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-require-recent-sensitive-session", schema: "app_rls", name: "require_recent_sensitive_session", signature: "text,timestamp without time zone,integer,integer", returnType: "TABLE(authorized boolean)",
    identityArguments: "p_session_id text, p_checked_at timestamp without time zone, p_max_password_age_minutes integer, p_max_mfa_age_minutes integer", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"]], context: "Evaluates password and role-required MFA freshness from the exact live capability session; caller flags cannot establish assurance.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-account-controller-ts-update-my-profile"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:requireRecentSensitiveSession"], inputAuthority: "opaque capability and bounded server-selected freshness windows", outputColumns: ["authorized"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-request-authenticated-email-change", schema: "app_rls", name: "request_authenticated_email_change", signature: "text,text,text,timestamp without time zone,timestamp without time zone,text,text", returnType: "TABLE(changed boolean, verificationRequired boolean, userId text, currentEmail text, pendingEmail text, orgId text, licenseeId text, expiresAt timestamp without time zone)",
    identityArguments: "p_next_email text, p_token_hash text, p_secret_version text, p_expires_at timestamp without time zone, p_requested_at timestamp without time zone, p_ip_hash text, p_user_agent_hash text", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["User","UPDATE"],["EmailVerificationToken","SELECT"],["EmailVerificationToken","INSERT"],["EmailVerificationToken","UPDATE"]], context: "Locks the capability-derived actor, rejects email collisions, consumes older email-change challenges and stores one hashed bounded challenge plus pending email atomically.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-auth-email-verification-service-ts-request-email-change-verification"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:prepareAuthenticatedEmailChange"], inputAuthority: "opaque capability; normalized email is mutation input while actor and tenant are database-derived", outputColumns: ["changed","verificationRequired","userId","currentEmail","pendingEmail","orgId","licenseeId","expiresAt"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-update-authenticated-profile", schema: "app_rls", name: "update_authenticated_profile", signature: "text,boolean,text,timestamp without time zone", returnType: "TABLE(id text, email text, name text, role text, licenseeId text, orgId text, emailVerifiedAt timestamp without time zone, pendingEmail text, pendingEmailRequestedAt timestamp without time zone, isActive boolean, status text, deletedAt timestamp without time zone, disabledAt timestamp without time zone, createdAt timestamp without time zone, licenseeRecordId text, licenseeName text, licenseePrefix text, licenseeBrandName text, licenseeOrgId text)",
    identityArguments: "p_name text, p_email_change_requested boolean, p_audit_pending_email text, p_changed_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["User","UPDATE"],["Licensee","SELECT"],["AuditLogOutbox","INSERT"]], context: "Updates only the capability-derived actor name, validates any email-change audit against live pending state, records durable audit evidence and returns the authoritative actor projection.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-account-controller-ts-update-my-profile"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:updateAuthenticatedProfile"], inputAuthority: "opaque capability; bounded name and already-stored pending email are mutation inputs", outputColumns: ["id","email","name","role","licenseeId","orgId","emailVerifiedAt","pendingEmail","pendingEmailRequestedAt","isActive","status","deletedAt","disabledAt","createdAt","licenseeRecordId","licenseeName","licenseePrefix","licenseeBrandName","licenseeOrgId"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "b01-change-authenticated-password", schema: "app_rls", name: "change_authenticated_password", signature: "text,text,timestamp without time zone", returnType: "TABLE(changed boolean)",
    identityArguments: "p_expected_password_hash text, p_password_hash text, p_changed_at timestamp without time zone", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["RefreshToken","UPDATE"],["User","SELECT"],["User","UPDATE"],["AuditLogOutbox","INSERT"]], context: "Uses an expected-hash compare-and-swap to change only the capability actor password, revoke all refresh/session capabilities and write audit evidence atomically.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-account-controller-ts-change-my-password"], repositoryCallers: ["backend/src/rls-waves/session-b/b01/authenticatedSecurityRepository.ts:changeAuthenticatedPassword"], inputAuthority: "opaque capability plus the exact same-transaction password verifier", outputColumns: ["changed"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  {
    id: "rf7-b01-admin-mfa-actor", schema: "app_rls", name: "b01_admin_mfa_actor", signature: "", returnType: "TABLE(userId text, role text, organizationId text, licenseeId text)",
    identityArguments: "", definitionLocation: authenticationClosureSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: [] }, internalOnly: true,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"]],
    context: "Owner-only helper that reuses the authenticated-session actor projection and rejects roles outside the exact RF7 administration allowlist.",
    canonicalWorkflowIds: ["workflow-http-backend-src-controllers-auth-admin-security-controller-ts-get-admin-mfa-status-controller"],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql:admin MFA capabilities"],
    inputAuthority: "transaction-local context installed by the reviewed authenticated-session capability; no caller-supplied actor or tenant scope",
    outputColumns: ["userId","role","organizationId","licenseeId"], disposableProbes: ["b01-authentication-closure-postgres18"],
  },
  ...[
    ["rf7-load-admin-mfa-state","load_admin_mfa_state","",[],[["AdminMfaCredential","SELECT"],["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"],["UserBackupCode","SELECT"]],"loadAdminMfaState"],
    ["rf7-begin-admin-totp","begin_admin_totp_enrollment","text,text,text,text,text[],timestamp without time zone,timestamp without time zone",["p_mode text","p_secret_ciphertext text","p_secret_iv text","p_secret_tag text","p_backup_hashes text[]","p_pending_cutoff timestamp without time zone","p_created_at timestamp without time zone"],[["AdminMfaCredential","SELECT"],["AdminMfaCredential","INSERT"],["AdminMfaCredential","UPDATE"],["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"],["UserMfaFactor","INSERT"],["UserMfaFactor","UPDATE"],["UserMfaFactor","DELETE"],["UserBackupCode","INSERT"]],"beginAdminTotpEnrollment"],
    ["rf7-load-admin-totp","load_admin_totp_enrollment","text,timestamp without time zone",["p_mode text","p_pending_cutoff timestamp without time zone"],[["AdminMfaCredential","SELECT"],["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"]],"loadAdminTotpEnrollment"],
    ["rf7-complete-admin-totp","complete_admin_totp_enrollment","text,text,text,text,text,timestamp without time zone,text,text",["p_mode text","p_factor_id text","p_secret_ciphertext text","p_secret_iv text","p_secret_tag text","p_completed_at timestamp without time zone","p_ip_hash text","p_user_agent text"],[["AdminMfaCredential","SELECT"],["AdminMfaCredential","UPDATE"],["UserMfaFactor","SELECT"],["UserMfaFactor","UPDATE"],["UserBackupCode","INSERT"],["UserBackupCode","DELETE"],["AuditLogOutbox","INSERT"]],"completeAdminTotpEnrollment"],
    ["rf7-load-admin-mfa-verifiers","load_admin_mfa_verifiers","",[],[["AdminMfaCredential","SELECT"],["UserMfaFactor","SELECT"],["UserBackupCode","SELECT"]],"loadAdminMfaVerifiers"],
    ["rf7-consume-admin-mfa-verifier","consume_admin_mfa_verifier","text,text,text[],text[],timestamp without time zone",["p_method text","p_record_id text","p_expected_legacy_hashes text[]","p_next_legacy_hashes text[]","p_used_at timestamp without time zone"],[["AdminMfaCredential","SELECT"],["AdminMfaCredential","UPDATE"],["UserMfaFactor","INSERT"],["UserMfaFactor","UPDATE"],["UserBackupCode","UPDATE"]],"consumeAdminMfaVerifier"],
    ["rf7-replace-admin-backup-codes","replace_admin_backup_codes","text[],timestamp without time zone",["p_hashes text[]","p_replaced_at timestamp without time zone"],[["AdminMfaCredential","UPDATE"],["UserBackupCode","INSERT"],["UserBackupCode","DELETE"]],"replaceAdminBackupCodes"],
    ["rf7-disable-admin-mfa","disable_admin_mfa","timestamp without time zone,text,text",["p_disabled_at timestamp without time zone","p_ip_hash text","p_user_agent text"],[["RefreshToken","UPDATE"],["AdminMfaCredential","UPDATE"],["AdminWebAuthnCredential","DELETE"],["UserMfaFactor","UPDATE"],["UserBackupCode","DELETE"],["AuditLogOutbox","INSERT"]],"disableAdminMfaBoundary"],
    ["rf7-create-admin-mfa-challenge","create_admin_mfa_challenge","text,text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone",["p_kind text","p_ticket_hash text","p_session_binding_hash text","p_purpose text","p_risk_score integer","p_risk_level text","p_reasons text[]","p_ip_hash text","p_user_agent_hash text","p_max_attempts integer","p_created_at timestamp without time zone","p_expires_at timestamp without time zone"],[["MfaLoginChallenge","INSERT"],["AuthMfaChallenge","SELECT"],["AuthMfaChallenge","INSERT"],["AuthMfaChallenge","UPDATE"],["AuditLogOutbox","INSERT"]],"createAdminMfaChallengeBoundary"],
    ["rf7-load-admin-mfa-challenge","load_admin_mfa_challenge","text[],text[],timestamp without time zone",["p_ticket_hashes text[]","p_session_binding_hashes text[]","p_checked_at timestamp without time zone"],[["MfaLoginChallenge","SELECT"],["AuthMfaChallenge","SELECT"]],"loadAdminMfaChallengeBoundary"],
    ["rf7-fail-admin-mfa-challenge","record_admin_mfa_challenge_failure","text,text,text,integer,timestamp without time zone,text,text",["p_kind text","p_challenge_id text","p_action text","p_expected_attempts integer","p_failed_at timestamp without time zone","p_ip_hash text","p_user_agent text"],[["MfaLoginChallenge","UPDATE"],["AuthMfaChallenge","UPDATE"],["AuditLogOutbox","INSERT"]],"recordAdminMfaChallengeFailure"],
    ["rf7-complete-admin-mfa-challenge","complete_admin_mfa_challenge","text,text,text,timestamp without time zone,text,text",["p_kind text","p_challenge_id text","p_method text","p_completed_at timestamp without time zone","p_ip_hash text","p_user_agent text"],[["MfaLoginChallenge","UPDATE"],["AuthMfaChallenge","UPDATE"],["AuditLogOutbox","INSERT"]],"completeAdminMfaChallengeBoundary"],
    ["rf7-load-admin-webauthn-credentials","load_admin_webauthn_credentials","",[],[["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"]],"loadAdminWebAuthnCredentials"],
    ["rf7-create-admin-webauthn-challenge","create_admin_webauthn_challenge","text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone",["p_purpose text","p_ticket_hash text","p_challenge_hash text","p_ip_hash text","p_user_agent_hash text","p_origin text","p_rp_id text","p_created_at timestamp without time zone","p_expires_at timestamp without time zone"],[["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"],["AuthWebAuthnChallenge","INSERT"]],"createAdminWebAuthnChallengeBoundary"],
    ["rf7-load-admin-webauthn-challenge","load_admin_webauthn_challenge","text[],text,text,timestamp without time zone",["p_ticket_hashes text[]","p_purpose text","p_credential_id text","p_checked_at timestamp without time zone"],[["AdminWebAuthnCredential","SELECT"],["UserMfaFactor","SELECT"],["AuthWebAuthnChallenge","SELECT"]],"loadAdminWebAuthnChallengeBoundary"],
    ["rf7-complete-admin-webauthn-registration","complete_admin_webauthn_registration","text,text,text,text,integer,text[],text,boolean,timestamp without time zone",["p_challenge_id text","p_credential_id text","p_label text","p_public_key text","p_counter integer","p_transports text[]","p_device_type text","p_backed_up boolean","p_completed_at timestamp without time zone"],[["UserMfaFactor","SELECT"],["UserMfaFactor","INSERT"],["UserMfaFactor","UPDATE"],["AdminWebAuthnCredential","SELECT"],["AdminWebAuthnCredential","INSERT"],["AuthWebAuthnChallenge","SELECT"],["AuthWebAuthnChallenge","UPDATE"],["AuditLogOutbox","INSERT"]],"completeAdminWebAuthnRegistrationBoundary"],
    ["rf7-complete-admin-webauthn-authentication","complete_admin_webauthn_authentication","text,text,text,integer,integer,text,boolean,timestamp without time zone",["p_challenge_id text","p_credential_kind text","p_credential_row_id text","p_expected_counter integer","p_next_counter integer","p_device_type text","p_backed_up boolean","p_completed_at timestamp without time zone"],[["UserMfaFactor","UPDATE"],["AdminWebAuthnCredential","UPDATE"],["AuthWebAuthnChallenge","SELECT"],["AuthWebAuthnChallenge","UPDATE"]],"completeAdminWebAuthnAuthenticationBoundary"],
    ["rf7-delete-admin-webauthn-credential","delete_admin_webauthn_credential","text,timestamp without time zone",["p_credential_row_id text","p_deleted_at timestamp without time zone"],[["UserMfaFactor","UPDATE"],["AdminWebAuthnCredential","DELETE"],["AuditLogOutbox","INSERT"]],"deleteAdminWebAuthnCredentialBoundary"],
  ].map(([id,name,signature,args,commands,caller]) => ({
    id, schema: "app_rls", name, signature, returnType: "jsonb",
    identityArguments: args.join(", "), definitionLocation: authenticationClosureSource,
    definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...authenticationClosureSecurity, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],...commands],
    context: "RF7 actor-bound admin MFA persistence capability; cryptographic verification remains in Node and protected row authority remains in PostgreSQL.",
    canonicalWorkflowIds: ["workflow-http-backend-src-controllers-auth-admin-security-controller-ts-get-admin-mfa-status-controller"],
    repositoryCallers: [`backend/src/rls-waves/session-b/b01/adminMfaRepository.ts:${caller}`],
    inputAuthority: "opaque authenticated-session capability; caller user and tenant identifiers cannot establish authority",
    outputColumns: ["result"], disposableProbes: ["b01-authentication-closure-postgres18"],
  })),
  {
    id: "rf7-risk-analytics-snapshot", schema: "app_rls", name: "risk_analytics_snapshot",
    signature: "text,text,text,text,text,integer,integer,timestamp without time zone", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_licensee_id text, p_expected_user_id text, p_lookback_hours integer, p_limit integer, p_checked_at timestamp without time zone",
    definitionLocation: riskAnalyticsSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: riskAnalyticsSecurity,
    tableCommands: [
      ["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],
      ["ManufacturerLicenseeLink","SELECT"],["SecurityPolicy","SELECT"],["Batch","SELECT"],["QRCode","SELECT"],
      ["QrScanLog","SELECT"],["PolicyAlert","SELECT"],["Incident","SELECT"],["PolicyRule","SELECT"],["AuditLog","INSERT"],
    ],
    context: "Returns one bounded, repeatable, tenant-authoritative risk snapshot and records its read evidence atomically after live capability, actor, organization and licensee revalidation.",
    canonicalWorkflowIds: ["workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"],
    repositoryCallers: ["backend/src/rls-waves/session-c/c02/riskAnalyticsRepository.ts:readRiskAnalyticsSnapshot"],
    inputAuthority: "opaque authenticated-session capability; licensee ID only selects a database-validated active scope",
    outputColumns: ["organizationId","policy","batches","scanLogs","alerts","qrs","manufacturers","manufacturerLinks","incidents","policyRules"],
    disposableProbes: ["risk-analytics-application-path-postgres18"],
  },
  {
    id: "c02-platform-audit-log-details", schema: "app_rls", name: "platform_audit_log_details", signature: "text[]", returnType: "TABLE(id text, ip_address text, user_agent text, user_id text, user_name text)",
    identityArguments: "audit_ids text[]", definitionLocation: c02AuditTraceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c02AuditTraceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["AuditLog","SELECT"]], context: "Returns network and actor details only for a bounded page of audit IDs already proven to belong to the capability-bound platform administrator's explicit live licensee scope.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-audit-controller-ts-get-logs"], repositoryCallers: ["backend/src/services/auditLogQueryService.ts:queryAuditLogs"], inputAuthority: "opaque authenticated-session capability and a maximum 500 row selector set; database rows establish scope", outputColumns: ["id","ip_address","user_agent","user_id","user_name"], disposableProbes: ["session-c-audit-trace-postgres18"],
  },
  {
    id: "c02-fraud-report-network-details", schema: "app_rls", name: "c02_fraud_report_network_details", signature: "text[]", returnType: "TABLE(id text, ip_address text)",
    identityArguments: "report_ids text[]", definitionLocation: c02AuditTraceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c02AuditTraceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["AuditLog","SELECT"]], context: "Returns only IP details for the bounded CUSTOMER_FRAUD_REPORT page in the capability-derived platform actor's explicit live licensee scope.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-audit-controller-ts-get-fraud-reports"], repositoryCallers: ["backend/src/services/fraudReportQueryService.ts:queryFraudReports"], inputAuthority: "opaque authenticated-session capability and a maximum 500 row selector set; database rows establish scope", outputColumns: ["id","ip_address"], disposableProbes: ["session-c-audit-trace-postgres18"],
  },
  {
    id: "c02-respond-fraud-report", schema: "app_rls", name: "c02_respond_fraud_report", signature: "text,text,text,boolean", returnType: "jsonb",
    identityArguments: "report_id text, response_status text, requested_message text, notify_customer boolean", definitionLocation: c02AuditTraceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c02AuditTraceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["AuditLog","SELECT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Locks one fraud report, revalidates a capability-bound unscoped platform administrator with fresh MFA, appends the response and security event atomically, and returns a bounded result.", canonicalWorkflowIds: ["workflow-http-backend-src-controllers-audit-controller-ts-respond-to-fraud-report"], repositoryCallers: ["backend/src/rls-waves/session-c/c02/auditTraceRepository.ts:respondToFraudReportInTransaction"], inputAuthority: "opaque authenticated-session capability; report ID is a selector and the database report supplies tenant scope", outputColumns: ["jsonb response"], disposableProbes: ["session-c-audit-trace-postgres18"],
  },
  {
    id: "c03-list-policy-rules", schema: "app_rls", name: "c03_list_policy_rules", signature: "text,boolean,integer,integer", returnType: "jsonb",
    identityArguments: "rule_type_filter text, active_filter boolean, row_limit integer, row_offset integer", definitionLocation: c03PolicySource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03PolicySecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["PolicyRule","SELECT"]], context: "Returns one bounded policy-rule page only after the authenticated capability has installed a live platform actor and explicit active licensee scope.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts:listPolicyRulesInTransaction"], inputAuthority: "capability-derived actor and licensee; filters and pagination only narrow the projection", outputColumns: ["rules","total"], disposableProbes: ["c03-policy-postgres18"],
  },
  {
    id: "c03-list-platform-policy-rules", schema: "app_rls", name: "c03_list_platform_policy_rules", signature: "text,boolean,integer,integer", returnType: "jsonb",
    identityArguments: "rule_type_filter text, active_filter boolean, row_limit integer, row_offset integer", definitionLocation: c03PolicySource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03PolicySecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["PolicyRule","SELECT"],["Organization","SELECT"],["Licensee","SELECT"]], context: "Returns a bounded platform policy projection only for a live unscoped platform administrator with fresh MFA.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts:listPlatformPolicyRulesInTransaction"], inputAuthority: "capability-derived unscoped platform actor", outputColumns: ["rules","total"], disposableProbes: ["c03-policy-postgres18"],
  },
  {
    id: "c03-create-policy-rule", schema: "app_rls", name: "c03_create_policy_rule", signature: "jsonb", returnType: "jsonb",
    identityArguments: "input jsonb", definitionLocation: c03PolicySource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03PolicySecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["PolicyRule","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"]], context: "Validates an allowlisted policy payload and atomically creates one rule in the capability-derived licensee with request-bound replay protection.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts:createPolicyRuleInTransaction"], inputAuthority: "capability-derived platform actor and licensee; JSON is bounded mutation data only", outputColumns: ["policy rule projection"], disposableProbes: ["c03-policy-postgres18"],
  },
  {
    id: "c03-update-policy-rule", schema: "app_rls", name: "c03_update_policy_rule", signature: "text,jsonb", returnType: "jsonb",
    identityArguments: "policy_rule_id text, patch jsonb", definitionLocation: c03PolicySource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03PolicySecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["PolicyRule","SELECT"],["PolicyRule","UPDATE"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"]], context: "Locks one capability-visible policy rule, rejects arbitrary fields, and applies one request-bound idempotent patch.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts:updatePolicyRuleInTransaction"], inputAuthority: "capability-derived actor and licensee; rule ID selects only a row in that scope", outputColumns: ["policy rule projection"], disposableProbes: ["c03-policy-postgres18"],
  },
  {
    id: "c03-list-feature-flags", schema: "app_rls", name: "c03_list_tenant_feature_flags", signature: "text", returnType: "jsonb",
    identityArguments: "target_licensee_id text", definitionLocation: c03GovernanceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03GovernanceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["TenantFeatureFlag","SELECT"]], context: "Returns the explicit feature-flag administration projection only after the live capability-bound platform actor is revalidated for the selected active licensee.", canonicalWorkflowIds: ["workflow-internal-backend-src-services-governance-service-ts-list-tenant-feature-flags"], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:listTenantFeatureFlagsInTransaction"], inputAuthority: "licensee ID is a selector; database rows and the authenticated capability establish authority", outputColumns: ["id","licenseeId","key","enabled","updatedAt"], disposableProbes: ["c03-governance-postgres18"],
  },
  {
    id: "c03-upsert-feature-flag", schema: "app_rls", name: "c03_upsert_tenant_feature_flag", signature: "text,boolean,jsonb", returnType: "jsonb",
    identityArguments: "key text, enabled boolean, config jsonb", definitionLocation: c03GovernanceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03GovernanceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["TenantFeatureFlag","INSERT"],["TenantFeatureFlag","UPDATE"],["SensitiveActionApproval","SELECT"],["SensitiveActionApproval","UPDATE"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Consumes a separate approved maker-checker request before one bounded, idempotent feature-flag upsert and its atomic evidence.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:upsertTenantFeatureFlagInTransaction"], inputAuthority: "capability-derived platform actor and approved payload", outputColumns: ["tenant feature flag projection"], disposableProbes: ["c03-governance-postgres18"],
  },
  {
    id: "c03-get-retention-policy", schema: "app_rls", name: "c03_get_or_create_retention_policy", signature: "", returnType: "jsonb",
    identityArguments: "", definitionLocation: c03GovernanceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03GovernanceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["EvidenceRetentionPolicy","SELECT"],["EvidenceRetentionPolicy","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Returns or atomically creates the fixed default retention policy for the capability-derived active licensee.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:getOrCreateRetentionPolicyInTransaction"], inputAuthority: "capability-derived platform actor and licensee", outputColumns: ["retention policy projection"], disposableProbes: ["c03-governance-postgres18"],
  },
  {
    id: "c03-run-retention-preview", schema: "app_rls", name: "c03_run_retention_lifecycle", signature: "text,text", returnType: "jsonb",
    identityArguments: "mode text, approval_id text", definitionLocation: c03GovernanceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03GovernanceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["EvidenceRetentionPolicy","SELECT"],["EvidenceRetentionPolicy","INSERT"],["Incident","SELECT"],["IncidentEvidence","SELECT"],["EvidenceRetentionJob","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Implements only the non-destructive preview operation; APPLY remains fail-closed pending its separately reviewed maker-checker executor.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:runRetentionLifecycleInTransaction"], inputAuthority: "capability-derived platform actor and licensee", outputColumns: ["job","policy","cutoffAt","evaluated","eligible","purged","exported"], disposableProbes: ["c03-governance-postgres18"],
  },
  {
    id: "c03-generate-compliance-report", schema: "app_rls", name: "c03_generate_compliance_report", signature: "timestamp with time zone,timestamp with time zone", returnType: "jsonb",
    identityArguments: "from_at timestamp with time zone, to_at timestamp with time zone", definitionLocation: c03GovernanceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03GovernanceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["EvidenceRetentionPolicy","SELECT"],["EvidenceRetentionPolicy","INSERT"],["Incident","SELECT"],["IncidentHandoff","SELECT"],["AuditLog","SELECT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Builds one bounded compliance projection from a single capability-authorized snapshot and records its immutable evidence.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:generateComplianceReportInTransaction"], inputAuthority: "capability-derived platform actor and licensee; timestamps only bound the report window", outputColumns: ["scope","generatedAt","metrics","controls","controlSummary"], disposableProbes: ["c03-governance-postgres18"],
  },
  {
    id: "c03-update-retention-policy", schema: "app_rls", name: "c03_update_retention_policy", signature: "jsonb", returnType: "jsonb",
    identityArguments: "patch jsonb", definitionLocation: c03GovernanceSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03GovernanceSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["EvidenceRetentionPolicy","SELECT"],["EvidenceRetentionPolicy","INSERT"],["EvidenceRetentionPolicy","UPDATE"],["SensitiveActionApproval","SELECT"],["SensitiveActionApproval","UPDATE"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Consumes an exact maker-checker approval before applying an allowlisted retention patch with atomic replay and audit evidence.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:updateRetentionPolicyInTransaction"], inputAuthority: "capability-derived platform actor plus an exact approved payload", outputColumns: ["retention policy projection"], disposableProbes: ["c03-governance-postgres18"],
  },
  {
    id: "c03-create-sensitive-approval", schema: "app_rls", name: "c03_create_sensitive_action_approval", signature: "jsonb", returnType: "jsonb",
    identityArguments: "input jsonb", definitionLocation: c03ApprovalSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03ApprovalSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["SensitiveActionApproval","INSERT"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Creates one bounded expiring maker-checker request for the capability-derived actor and licensee and records audit evidence atomically.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ApprovalRepository.ts:createSensitiveApprovalInTransaction"], inputAuthority: "capability-derived actor and licensee; allowlisted action payload is mutation data", outputColumns: ["approval projection"], disposableProbes: ["c03-approval-postgres18"],
  },
  {
    id: "c03-list-sensitive-approvals", schema: "app_rls", name: "c03_list_sensitive_action_approvals", signature: "text,integer,integer", returnType: "TABLE(result jsonb)",
    identityArguments: "status_filter text, row_limit integer, row_offset integer", definitionLocation: c03ApprovalSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03ApprovalSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["SensitiveActionApproval","SELECT"]], context: "Returns only a bounded page from the capability-derived active licensee.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ApprovalRepository.ts:listSensitiveApprovalsInTransaction"], inputAuthority: "capability-derived actor and licensee; status and pagination only narrow results", outputColumns: ["result"], disposableProbes: ["c03-approval-postgres18"],
  },
  {
    id: "c03-approve-sensitive-approval", schema: "app_rls", name: "c03_approve_sensitive_action_approval", signature: "text,text", returnType: "jsonb",
    identityArguments: "approval_id text, review_note text", definitionLocation: c03ApprovalSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03ApprovalSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["SensitiveActionApproval","SELECT"],["SensitiveActionApproval","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Locks a pending unexpired same-licensee approval, enforces fresh MFA and maker-checker separation, then records approval and evidence atomically.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ApprovalRepository.ts:approveSensitiveApprovalInTransaction"], inputAuthority: "capability-derived checker; approval ID is selection-only", outputColumns: ["approval projection"], disposableProbes: ["c03-approval-postgres18"],
  },
  {
    id: "c03-reject-sensitive-approval", schema: "app_rls", name: "c03_reject_sensitive_action_approval", signature: "text,text", returnType: "jsonb",
    identityArguments: "approval_id text, review_note text", definitionLocation: c03ApprovalSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03ApprovalSecurity,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["SensitiveActionApproval","SELECT"],["SensitiveActionApproval","UPDATE"],["AuditLog","INSERT"],["SecurityEventOutbox","INSERT"]], context: "Locks a pending unexpired same-licensee approval, enforces fresh MFA and maker-checker separation, then records rejection and evidence atomically.", canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ApprovalRepository.ts:rejectSensitiveApprovalInTransaction"], inputAuthority: "capability-derived checker; approval ID is selection-only", outputColumns: ["approval projection"], disposableProbes: ["c03-approval-postgres18"],
  },
  {
    id:"c03-assert-restricted-identity",schema:"app_rls",name:"c03_assert_restricted_identity",signature:"text",returnType:"boolean",identityArguments:"expected_identity text",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:{...c03IncidentSecurity,runtimeExecuteGrantees:["preauth","worker"]},
    tableCommands:[["User","SELECT"]],context:"Compares the requested restricted identity to session_user; it installs no authority and rejects cross-role use.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03RestrictedDatabase.ts:withRestrictedTransaction"],inputAuthority:"database session identity",outputColumns:["allowed"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-compute-incident-spam",schema:"app_rls",name:"c03_compute_incident_spam_signal",signature:"text,jsonb",returnType:"boolean",identityArguments:"qr_proof text, contact_hashes jsonb",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:{...c03IncidentSecurity,runtimeExecuteGrantees:["preauth"]},
    tableCommands:[["QRCode","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"]],context:"Resolves one exact immutable QR code under the pre-auth identity and derives a bounded recent-report signal without returning inventory.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:computeIncidentSpamSignalInTransaction"],inputAuthority:"exact QR code; hashes are non-authoritative bounded signals",outputColumns:["suspectedSpam"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-compute-incident-severity",schema:"app_rls",name:"c03_compute_incident_severity",signature:"text,jsonb",returnType:"text",identityArguments:"qr_proof text, input jsonb",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:{...c03IncidentSecurity,runtimeExecuteGrantees:["preauth"]},
    tableCommands:[["QRCode","SELECT"],["Licensee","SELECT"],["Organization","SELECT"]],context:"Resolves one exact immutable QR code before mapping an allowlisted incident type to the established severity model.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:computeIncidentSeverityInTransaction"],inputAuthority:"exact QR code; incident type is bounded classification input",outputColumns:["severity"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-create-public-incident",schema:"app_rls",name:"c03_create_public_incident_report",signature:"text,jsonb,jsonb,text",returnType:"jsonb",identityArguments:"qr_proof text, report jsonb, uploads jsonb, idempotency_key text",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:{...c03IncidentSecurity,runtimeExecuteGrantees:["preauth"]},
    tableCommands:[["QRCode","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","INSERT"],["IncidentEvent","INSERT"],["IncidentEvidence","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"]],context:"Atomically binds a bounded customer report and evidence list to the exact database QR and tenant with replay protection.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:createPublicIncidentReportInTransaction"],inputAuthority:"exact QR code derives tenant; report fields cannot choose scope",outputColumns:["id","status","severity","createdAt","qrCodeValue"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-get-incident-detail",schema:"app_rls",name:"c03_get_incident_detail",signature:"text",returnType:"jsonb",identityArguments:"incident_id text",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["IncidentEvent","SELECT"],["IncidentCommunication","SELECT"],["IncidentEvidence","SELECT"]],context:"Returns one incident and its evidence only after live capability and tenant revalidation.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:getIncidentDetailInTransaction"],inputAuthority:"capability-derived actor; incident ID is selection-only",outputColumns:["incident projection"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-list-incidents",schema:"app_rls",name:"c03_list_incidents",signature:"jsonb,integer,integer",returnType:"jsonb",identityArguments:"filters jsonb, row_limit integer, row_offset integer",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"]],context:"Returns one bounded page and total from the capability-derived active licensee.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:listIncidentsInTransaction"],inputAuthority:"capability-derived actor and licensee; filters only narrow",outputColumns:["rows","total"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-patch-incident",schema:"app_rls",name:"c03_patch_incident",signature:"text,jsonb",returnType:"jsonb",identityArguments:"incident_id text, patch jsonb",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["Incident","UPDATE"],["IncidentEvent","INSERT"]],context:"Locks one same-tenant incident, applies only allowlisted fields under fresh MFA and appends an event atomically.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:patchIncidentInTransaction"],inputAuthority:"capability-derived actor and tenant",outputColumns:["incident","changedFields"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-record-incident-event",schema:"app_rls",name:"c03_record_incident_event",signature:"text,text,jsonb",returnType:"jsonb",identityArguments:"incident_id text, event_type text, event_payload jsonb",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["IncidentEvent","INSERT"]],context:"Appends one allowlisted event for a capability-visible incident with actor attribution derived from the database session.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:recordIncidentEventInTransaction"],inputAuthority:"capability-derived actor and tenant",outputColumns:["event projection"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-add-incident-evidence",schema:"app_rls",name:"c03_add_incident_evidence",signature:"text,jsonb,text",returnType:"jsonb",identityArguments:"incident_id text, evidence jsonb, idempotency_key text",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["IncidentEvidence","INSERT"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"]],context:"Adds one bounded evidence record to the same-tenant incident under fresh MFA with deterministic replay.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:addIncidentEvidenceInTransaction"],inputAuthority:"capability-derived actor and tenant",outputColumns:["evidence","tamperChecks"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-incident-audit-snapshot",schema:"app_rls",name:"c03_build_incident_evidence_audit_snapshot",signature:"text",returnType:"jsonb",identityArguments:"incident_id text",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["IncidentEvidence","SELECT"],["IncidentEvent","SELECT"]],context:"Builds one stable same-tenant incident evidence snapshot under the authenticated capability.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03GovernanceRepository.ts:loadIncidentEvidenceAuditSnapshotInTransaction"],inputAuthority:"capability-derived actor and tenant",outputColumns:["incident","evidence","events"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-list-ir-alerts",schema:"app_rls",name:"c03_list_ir_alerts",signature:"text,text,text,jsonb,integer,integer",returnType:"TABLE(id text,licensee_id text,alert_type text,severity text,message text,score integer,policy_rule_id text,incident_id text,batch_id text,qr_code_id text,manufacturer_id text,acknowledged_at timestamp with time zone,created_at timestamp with time zone,total_count bigint)",identityArguments:"p_incident_authorization_id text, p_incident_id text, p_licensee_id text, p_filters jsonb, p_row_limit integer, p_row_offset integer",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["PolicyAlert","SELECT"]],context:"Returns a bounded alert page only for a step-up-verified platform incident scope.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts:listIncidentPolicyAlertsInTransaction"],inputAuthority:"capability-derived incident tenant; authorization ID and filters only narrow",outputColumns:["id","licensee_id","alert_type","severity","message","score","policy_rule_id","incident_id","batch_id","qr_code_id","manufacturer_id","acknowledged_at","created_at","total_count"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id:"c03-link-ir-alert",schema:"app_rls",name:"c03_link_ir_alert_incident",signature:"text,text,text,text,text",returnType:"jsonb",identityArguments:"incident_authorization_id text, alert_id text, incident_id text, reason text, idempotency_key text",
    definitionLocation:c03IncidentSource,definitionKind:"checked-in-production-package",definitionStatus:"production-reviewed",security:c03IncidentSecurity,
    tableCommands:[["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["Incident","SELECT"],["PolicyAlert","UPDATE"],["ActionIdempotencyKey","SELECT"],["ActionIdempotencyKey","INSERT"],["ActionIdempotencyKey","UPDATE"]],context:"Links one same-tenant alert to the selected incident under step-up assurance and deterministic replay.",canonicalWorkflowIds:[],repositoryCallers:["backend/src/rls-waves/session-c/c03/c03PolicyRepository.ts:linkPolicyAlertToIncidentInTransaction"],inputAuthority:"capability-derived incident tenant; IDs cannot establish scope",outputColumns:["policy alert projection"],disposableProbes:["c03-incident-postgres18"],
  },
  {
    id: "c03-require-authenticated-actor", schema: "app_rls", name: "c03_require_authenticated_actor",
    signature: "text,text,text", returnType: "TABLE(session_id text, user_id text, role text, organization_id text, licensee_id text, assurance text)",
    identityArguments: "p_capability text, p_purpose text, p_request_id text",
    definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"]],
    context: "Verifies the opaque authenticated-session capability and installs only its database-derived C03 actor context for the operation transaction.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts:verifyCapability"],
    inputAuthority: "opaque authenticated-session capability; purpose and request ID are attribution only",
    outputColumns: ["session_id","user_id","role","organization_id","licensee_id","assurance"],
    disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-revalidate-compliance-pack-job-actor", schema: "app_rls", name: "c03_revalidate_compliance_pack_job_actor_scope",
    signature: "text,text,text,text", returnType: "TABLE(user_id text, role text, organization_id text, licensee_id text)",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_job_id text",
    definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.get, context: "Verifies the opaque authenticated-session capability, derives the live actor, locks scope to the selected compliance job and rejects inactive or cross-tenant scope.",
    canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts:withC03ResourceTransaction"], inputAuthority: "capability is authority; job ID is a selector only", outputColumns: ["user_id","role","organization_id","licensee_id"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-bind-sensitive-approval-actor", schema: "app_rls", name: "c03_bind_sensitive_approval_actor",
    signature: "text,text,text,text", returnType: "TABLE(user_id text, role text, organization_id text, licensee_id text)",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_approval_id text",
    definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: [["RefreshToken","SELECT"],["User","SELECT"],["Licensee","SELECT"],["Organization","SELECT"],["ManufacturerLicenseeLink","SELECT"],["SensitiveActionApproval","SELECT"]],
    context: "Verifies one fresh authenticated-session capability and narrows the transaction to the exact live tenant that owns the selected sensitive approval.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts:withC03ResourceTransaction"], inputAuthority: "capability and live actor state are authority; approval ID selects one row only", outputColumns: ["user_id","role","organization_id","licensee_id"], disposableProbes: ["c03-approval-postgres18"],
  },
  {
    id: "c03-start-compliance-pack-job", schema: "app_rls", name: "c03_start_compliance_pack_job",
    signature: "text,text,text,text,text,timestamp with time zone,timestamp with time zone", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_licensee_id text, p_trigger_type text, p_from timestamp with time zone, p_to timestamp with time zone",
    definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.start, context: "Capability-derived MFA actor and live licensee relationships authorize an idempotent manual job start; the requested licensee is selection-only.", canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts:startCompliancePackJobInTransaction"], inputAuthority: "capability plus live database scope", outputColumns: ["job","report"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-complete-compliance-pack-job", schema: "app_rls", name: "c03_complete_compliance_pack_job", signature: "text,text,text,text,jsonb", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_job_id text, p_result jsonb", definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.transition, context: "Locks the capability-visible job and permits only RUNNING to COMPLETED with a validated immutable artifact result.", canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts:completeCompliancePackJobInTransaction"], inputAuthority: "capability derives actor and job relationship; artifact fields are validated mutation input", outputColumns: ["jsonb job projection"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-fail-compliance-pack-job", schema: "app_rls", name: "c03_fail_compliance_pack_job", signature: "text,text,text,text,text", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_job_id text, p_error_code text", definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.transition, context: "Locks the capability-visible job and permits only RUNNING to FAILED with a bounded error code.", canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts:failCompliancePackJobInTransaction"], inputAuthority: "capability derives actor and job relationship", outputColumns: ["jsonb job projection"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-get-compliance-pack-job", schema: "app_rls", name: "c03_get_compliance_pack_job", signature: "text,text,text,text", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_job_id text", definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.get, context: "Capability-derived MFA actor and live scope authorize one job selector and its regenerated report.", canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts:loadCompliancePackJobInTransaction"], inputAuthority: "capability is authority; job ID is selection-only", outputColumns: ["job","report"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-complete-compliance-pack-rebuild", schema: "app_rls", name: "c03_complete_compliance_pack_rebuild", signature: "text,text,text,text,jsonb", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_job_id text, p_result jsonb", definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.transition, context: "Locks a capability-visible COMPLETED job and atomically replaces only validated artifact metadata.", canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts:completeCompliancePackRebuildInTransaction"], inputAuthority: "capability derives actor and job relationship", outputColumns: ["jsonb job projection"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "c03-get-incident-evidence-file", schema: "app_rls", name: "c03_get_incident_evidence_file_by_storage_key", signature: "text,text,text,text", returnType: "jsonb",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_storage_key text", definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.evidence, context: "Reads one storage-key candidate, rejects duplicates, then derives incident tenant scope from the verified actor before returning metadata.", canonicalWorkflowIds: [c03EvidenceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts:loadIncidentEvidenceFileInTransaction"], inputAuthority: "capability is authority; storage key is a bounded selector only", outputColumns: ["id","incidentId","fileUrl","storageKey","fileType","uploadedByUserId","uploadedBy","createdAt"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
  },
  {
    id: "b01-issue-authenticated-session", schema: "app_auth", name: "issue_authenticated_session_capability",
    signature: "text,text,text,text,timestamp without time zone", returnType: "TABLE(id text, expiresAt timestamp without time zone)",
    identityArguments: "p_refresh_token_id text, p_refresh_token_hash text, p_capability text, p_assurance text, p_expires_at timestamp without time zone",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"]],
    context: "Issues a capability only for the locked active refresh-session row after the caller presents its exact bearer-derived refresh hash; user and assurance are derived from that row.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/services/auth/authenticatedSessionCapabilityService.ts:createAuthenticatedSessionCapability"], inputAuthority: "refresh session identifier plus exact bearer-derived hash select a candidate; the raw capability is hashed in PostgreSQL", outputColumns: ["id", "expiresAt"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-require-authenticated-session", schema: "app_auth", name: "require_authenticated_session",
    signature: "text,text,text", returnType: "TABLE(sessionId text, userId text, role text, organizationId text, licenseeId text, assurance text)",
    identityArguments: "p_capability text, p_purpose text, p_request_id text",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken", "SELECT"], ["User", "SELECT"]],
    context: "Hashes the opaque capability in PostgreSQL, holds a shared lock on the linked active session so concurrent verification remains read-only while revocation stays serialized, derives live user authority, and overwrites transaction-local authenticated context before protected access.",
    canonicalWorkflowIds: [], repositoryCallers: [], inputAuthority: "opaque 256-bit bearer capability; purpose and request ID are attribution only", outputColumns: ["sessionId", "userId", "role", "organizationId", "licenseeId", "assurance"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-revoke-authenticated-session", schema: "app_auth", name: "revoke_authenticated_session_capability",
    signature: "text,text,text,text", returnType: "TABLE(revoked boolean)",
    identityArguments: "p_capability text, p_target_refresh_token_id text, p_reason text, p_request_id text",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"]],
    context: "Verifies the opaque capability before deriving its user and revoking only a capability row bound to that verified user.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/services/auth/authenticatedSessionCapabilityService.ts:revokeAuthenticatedSessionByRefreshToken"], inputAuthority: "target session ID is a candidate only; the verified capability derives the authoritative user", outputColumns: ["revoked"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-revoke-all-authenticated-sessions", schema: "app_auth", name: "revoke_all_authenticated_session_capabilities",
    signature: "text,text,text", returnType: "TABLE(revokedCount integer)",
    identityArguments: "p_capability text, p_reason text, p_request_id text",
    definitionLocation: authenticatedSessionSource, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: { ...b01Security, functionSource: authenticatedSessionSource, rollbackDefinition: authenticatedSessionRollback, runtimeExecuteGrantees: ["app"] },
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"]],
    context: "Verifies the opaque capability before deriving the only user whose active capabilities may be revoked.",
    canonicalWorkflowIds: [], repositoryCallers: ["backend/src/services/auth/authenticatedSessionCapabilityService.ts:revokeAuthenticatedSessionsForUser"], inputAuthority: "the caller supplies no user authority; the verified capability derives the target user", outputColumns: ["revokedCount"], disposableProbes: ["authenticated-session-capability-postgres18"],
  },
  {
    id: "b01-claim-refresh-token-rotation", schema: "app_auth", name: "claim_refresh_token_rotation",
    signature: "text[],timestamp without time zone,text", returnType: "TABLE(disposition text, tokenId text, userId text, role text, organizationId text, licenseeId text, manufacturerId text, authAssurance text, expiresAt timestamp without time zone, authenticatedAt timestamp without time zone, mfaVerifiedAt timestamp without time zone)",
    identityArguments: "p_hashes text[], p_checked_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.claim, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:claimRefreshTokenRotation"],
    inputAuthority: "1..3 validated bearer-token hashes and request metadata only", outputColumns: ["disposition", "tokenId", "userId", "role", "organizationId", "licenseeId", "manufacturerId", "authAssurance", "expiresAt", "authenticatedAt", "mfaVerifiedAt"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-load-refresh-session-state", schema: "app_auth", name: "load_refresh_session_state",
    signature: "text,text[],text,text,timestamp without time zone,text", returnType: "TABLE(userId text, email text, name text, role text, legacyLicenseeId text, legacyOrganizationId text, emailVerifiedAt timestamp without time zone, sessionLicenseeId text, sessionOrganizationId text, scopeVersion text, selectedLicenseeId text, selectedLicenseeName text, selectedLicenseePrefix text, selectedLicenseeBrandName text, selectedLicenseeOrganizationId text, linkedLicensees jsonb, mfaRequired boolean, mfaEnabled boolean, mfaEnrolled boolean, mfaLastUsedAt timestamp without time zone, mfaMethods text[], mfaPreferredMethod text)",
    identityArguments: "p_token_id text, p_hashes text[], p_requested_licensee_id text, p_requested_scope_version text, p_checked_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.state, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:loadRefreshSessionState"],
    inputAuthority: "claimed predecessor identity plus the original bearer hashes; requested manufacturer scope is selection-only", outputColumns: ["userId", "email", "name", "role", "legacyLicenseeId", "legacyOrganizationId", "emailVerifiedAt", "sessionLicenseeId", "sessionOrganizationId", "scopeVersion", "selectedLicenseeId", "selectedLicenseeName", "selectedLicenseePrefix", "selectedLicenseeBrandName", "selectedLicenseeOrganizationId", "linkedLicensees", "mfaRequired", "mfaEnabled", "mfaEnrolled", "mfaLastUsedAt", "mfaMethods", "mfaPreferredMethod"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-create-refresh-mfa-challenge", schema: "app_auth", name: "create_refresh_mfa_challenge",
    signature: "text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text", returnType: "TABLE(challengeId text, created boolean)",
    identityArguments: "p_token_id text, p_hashes text[], p_user_id text, p_ticket_hash text, p_session_binding_hash text, p_risk_score integer, p_risk_level text, p_reasons text[], p_ip_hash text, p_user_agent_hash text, p_max_attempts integer, p_expires_at timestamp without time zone, p_created_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.challenge, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:createRefreshMfaChallengeRecord"],
    inputAuthority: "claimed predecessor identity; challenge payload is validated but cannot select an actor", outputColumns: ["challengeId", "created"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-revoke-refresh-token-scope", schema: "app_auth", name: "revoke_refresh_token_scope",
    signature: "text,text[],text,text,text,timestamp without time zone,text", returnType: "TABLE(revokedCount integer)",
    identityArguments: "p_token_id text, p_hashes text[], p_user_id text, p_scope text, p_reason text, p_revoked_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.revoke, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:revokeRefreshTokenRotationScope"],
    inputAuthority: "claimed predecessor identity; scope is a fixed enum and target user is rebound to the predecessor", outputColumns: ["revokedCount"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
  {
    id: "b01-complete-refresh-token-rotation", schema: "app_auth", name: "complete_refresh_token_rotation",
    signature: "text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text", returnType: "TABLE(id text, expiresAt timestamp without time zone)",
    identityArguments: "p_token_id text, p_hashes text[], p_user_id text, p_organization_id text, p_token_hash text, p_expires_at timestamp without time zone, p_ip_hash text, p_user_agent text, p_authenticated_at timestamp without time zone, p_mfa_verified_at timestamp without time zone, p_rotated_at timestamp without time zone, p_request_id text",
    definitionLocation: b01Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed",
    security: b01Security, tableCommands: b01Tables.complete, context: b01Context, canonicalWorkflowIds: [b01Workflow],
    repositoryCallers: ["backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts:completeRefreshTokenRotation"],
    inputAuthority: "claimed predecessor identity; successor hash is supplied by the application and raw successor is never accepted or retained", outputColumns: ["id", "expiresAt"], disposableProbes: ["b01-refresh-rotation-real-schema"],
  },
]);

export const namedFunctionKey = ({ schema, name }) => `${schema}.${name}`;

export const validateNamedSqlFunctionContracts = (contracts = NAMED_SQL_FUNCTION_CONTRACTS) => {
  const ids = new Set();
  const keys = new Set();
  for (const contract of contracts) {
    assert.match(contract.id || "", /^[a-z0-9-]+$/, "named SQL function contract has an invalid ID");
    assert.match(contract.schema || "", /^[a-z_][a-z0-9_]*$/, "named SQL function contract has an invalid schema");
    assert.match(contract.name || "", /^[a-z_][a-z0-9_]*$/, "named SQL function contract has an invalid name");
    assert(contract.signature != null, "named SQL function contract has a missing signature");
    assert.match(contract.definitionLocation || "", /\.(?:sql|psql)$/, "named SQL function contract has no checked-in SQL definition location");
    assert(contract.definitionKind === "checked-in-disposable-certification-fixture" || contract.definitionKind === "checked-in-production-package", "named SQL function contract has an invalid definition kind");
    assert(contract.tableCommands?.length, "named SQL function contract has no reviewed table-command evidence");
    assert(contract.context?.trim(), "named SQL function contract has no context contract");
    assert(contract.returnType?.trim(), "named SQL function contract has no return type");
    assert(contract.identityArguments != null, "named SQL function contract has no identity arguments declaration");
    assert(contract.definitionStatus === "production-reviewed", "named SQL function contract has an unreviewed definition");
    assert(contract.security?.mode === "SECURITY DEFINER", "named SQL function contract has an unsafe security mode");
    assert(contract.security?.ownerIdentity && contract.security?.ownerRole, "named SQL function contract has no controlled owner");
    assert(contract.security?.searchPath === "pg_catalog,public", "named SQL function contract has an unsafe search path");
    assert(contract.security?.publicExecute === "revoked", "named SQL function contract leaves PUBLIC execution unresolved");
    assert(contract.internalOnly === true || contract.security?.runtimeExecuteGrantees?.length, "named SQL function contract has no runtime execute grantee");
    assert(!contract.internalOnly || contract.security.runtimeExecuteGrantees.length === 0, "internal-only named SQL function contract has a runtime execute grantee");
    assert(contract.security?.rollbackDefinition?.endsWith(".sql"), "named SQL function contract has no rollback SQL");
    assert(contract.disposableProbes?.length, "named SQL function contract has no disposable probe");
    for (const [table, command] of contract.tableCommands) {
      assert.match(table || "", /^[A-Za-z][A-Za-z0-9_]*$/, "named SQL function contract has malformed table evidence");
      assert(["SELECT", "INSERT", "UPDATE", "DELETE"].includes(command), "named SQL function contract has malformed command evidence");
    }
    assert(!ids.has(contract.id), `duplicate named SQL function contract ID: ${contract.id}`);
    assert(!keys.has(namedFunctionKey(contract)), `duplicate named SQL function contract: ${namedFunctionKey(contract)}`);
    ids.add(contract.id);
    keys.add(namedFunctionKey(contract));
  }
  return [...contracts].sort((a, b) => namedFunctionKey(a).localeCompare(namedFunctionKey(b)));
};

export const namedFunctionContractFor = (functionName, contracts = NAMED_SQL_FUNCTION_CONTRACTS) =>
  contracts.find((contract) => namedFunctionKey(contract) === functionName) || null;

export const namedFunctionDefinitionEvidenceFor = (functionName, evidence = NAMED_SQL_FUNCTION_DEFINITION_EVIDENCE) =>
  evidence.find((item) => namedFunctionKey(item) === functionName) || null;
