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
const preAuthSource = "backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql";
const preAuthRollback = "backend/src/rls-waves/session-b/b01/b01PreAuthSecurityRollback.sql";
const c03Source = "backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql";
const c03Rollback = "backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundariesRollback.sql";
const scheduledSource = "backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql";
const scheduledRollback = "backend/src/rls-waves/session-b/b03/scheduledJobIdentityRollback.sql";
const outboxSource = "backend/src/rls-waves/session-b/b03/b03OutboxFunctions.sql";
const outboxRollback = "backend/src/rls-waves/session-b/b03/b03OutboxRollback.sql";
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
    ["AuditLogOutbox", "INSERT", `(${preAuthOwner} AND ${preAuthUserId}<>'' AND payload->>'userId'=${preAuthUserId} AND payload->>'action' IN ('AUTH_PASSWORD_RESET_REQUESTED','AUTH_PASSWORD_RESET_COMPLETED','AUTH_EMAIL_VERIFIED','AUTH_EMAIL_CHANGE_CONFIRMED','AUTH_INVITE_ACCEPTED'))`],
  ],
});

const c03SessionBinding = `(current_user={{AUTH_OWNER}} AND current_setting('app.auth_session_verified',true)='1' AND current_setting('app.c03_session_id',true)=current_setting('app.auth_session_id',true) AND current_setting('app.c03_user_id',true)=current_setting('app.user_id',true) AND EXISTS (SELECT 1 FROM public."RefreshToken" c03_session WHERE c03_session.id=current_setting('app.c03_session_id',true) AND c03_session."userId"=current_setting('app.c03_user_id',true) AND c03_session."sessionCapabilityHash"=current_setting('app.auth_session_hash',true) AND c03_session."sessionCapabilityHashVersion"='sha256-v1' AND c03_session."sessionCapabilityRevokedAt" IS NULL AND c03_session."sessionCapabilityExpiresAt">clock_timestamp() AND c03_session."revokedAt" IS NULL AND c03_session."expiresAt">clock_timestamp()))`;
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
const auditQueueWorkflow = "workflow-internal-backend-src-services-audit-log-outbox-service-ts-queue-audit-log-outbox";
const auditFlushWorkflow = "workflow-worker-backend-src-services-audit-log-outbox-service-ts-flush-audit-log-outbox";
const securityQueueWorkflow = "workflow-internal-backend-src-services-siem-outbox-service-ts-queue-security-event";
const securityFlushWorkflow = "workflow-worker-backend-src-services-siem-outbox-service-ts-flush-security-event-outbox";

// A function is production-reviewed only when its deployable definition,
// contract, rollback and exact table-command evidence live together here.
export const NAMED_SQL_FUNCTION_CONTRACTS = Object.freeze([
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
    id: "c03-revalidate-compliance-pack-job-actor", schema: "app_rls", name: "c03_revalidate_compliance_pack_job_actor_scope",
    signature: "text,text,text,text", returnType: "TABLE(user_id text, role text, organization_id text, licensee_id text)",
    identityArguments: "p_capability text, p_purpose text, p_request_id text, p_job_id text",
    definitionLocation: c03Source, definitionKind: "checked-in-production-package", definitionStatus: "production-reviewed", security: c03Security,
    tableCommands: c03Commands.get, context: "Verifies the opaque authenticated-session capability, derives the live actor, locks scope to the selected compliance job and rejects inactive or cross-tenant scope.",
    canonicalWorkflowIds: [c03ComplianceWorkflow], repositoryCallers: ["backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts:withC03ResourceTransaction"], inputAuthority: "capability is authority; job ID is a selector only", outputColumns: ["user_id","role","organization_id","licensee_id"], disposableProbes: ["c03-authenticated-boundaries-postgres18"],
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
    tableCommands: [["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"]],
    context: "Hashes the opaque capability in PostgreSQL, derives live user authority from the linked active session, and overwrites transaction-local authenticated context before protected access.",
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
    assert(contract.identityArguments?.trim(), "named SQL function contract has no identity arguments");
    assert(contract.definitionStatus === "production-reviewed", "named SQL function contract has an unreviewed definition");
    assert(contract.security?.mode === "SECURITY DEFINER", "named SQL function contract has an unsafe security mode");
    assert(contract.security?.ownerIdentity && contract.security?.ownerRole, "named SQL function contract has no controlled owner");
    assert(contract.security?.searchPath === "pg_catalog,public", "named SQL function contract has an unsafe search path");
    assert(contract.security?.publicExecute === "revoked", "named SQL function contract leaves PUBLIC execution unresolved");
    assert(contract.security?.runtimeExecuteGrantees?.length, "named SQL function contract has no runtime execute grantee");
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
