\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'runtime grants requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'runtime grants is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='745d713cf284dde78b13e04a815d333cbf9eeed589e6662f98a0d97642dcd5b0'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:745d713cf284dde78b13e04a815d333cbf9eeed589e6662f98a0d97642dcd5b0'
    AND administrator_role='certification-administrator'
    AND phase='context-helpers-installed'
    AND NOT traffic_enabled) THEN RAISE EXCEPTION 'runtime grants lacks the exact clean-room package marker'; END IF;

  IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>9
     OR EXISTS (SELECT 1 FROM pg_roles r JOIN (VALUES ('mscqr_rls_cert_owner', false),
    ('mscqr_rls_cert_auth_owner', false),
    ('mscqr_rls_cert_app', true),
    ('mscqr_rls_cert_read', true),
    ('mscqr_rls_cert_preauth', true),
    ('mscqr_rls_cert_worker', true),
    ('mscqr_rls_cert_scheduled', true),
    ('mscqr_rls_cert_operator', true),
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:745d713cf284dde78b13e04a815d333cbf9eeed589e6662f98a0d97642dcd5b0')
  THEN RAISE EXCEPTION 'managed role attributes or package markers drifted'; END IF;

  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>18
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND (member.rolname<>'certification-administrator' OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND grantor.rolname='certification-administrator' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))
  THEN RAISE EXCEPTION 'managed role membership topology drifted'; END IF;
END $$;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
GRANT USAGE ON SCHEMA public,app_rls TO "mscqr_rls_cert_app";
GRANT USAGE ON SCHEMA public,app_rls TO "mscqr_rls_cert_read";
GRANT USAGE ON SCHEMA public,app_rls TO "mscqr_rls_cert_worker","mscqr_rls_cert_scheduled";
GRANT USAGE ON SCHEMA public,app_rls TO "mscqr_rls_cert_operator";
GRANT INSERT ("action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId") ON TABLE public."AuditLog" TO "mscqr_rls_cert_app";
GRANT SELECT ("action", "createdAt", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId") ON TABLE public."AuditLog" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "licenseeId", "manufacturerId", "name") ON TABLE public."Batch" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "licenseeId") ON TABLE public."Incident" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "isActive", "orgId", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_app";
GRANT SELECT ("licenseeId", "manufacturerId") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_app";
GRANT SELECT ("acknowledgedAt", "batchId", "id", "incidentId", "licenseeId", "manufacturerId", "policyRuleId", "qrCodeId") ON TABLE public."PolicyAlert" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "isActive", "licenseeId", "manufacturerId", "orgId") ON TABLE public."PolicyRule" TO "mscqr_rls_cert_app";
GRANT SELECT ("batchId", "id", "latitude", "licenseeId", "longitude", "qrCodeId", "scannedAt") ON TABLE public."QrScanLog" TO "mscqr_rls_cert_app";
GRANT SELECT ("geoDriftThresholdKm", "licenseeId", "multiScanThreshold", "velocitySpikeThresholdPerMin") ON TABLE public."SecurityPolicy" TO "mscqr_rls_cert_app";
GRANT SELECT ("batchId", "createdAt", "details", "eventType", "id", "licenseeId", "manufacturerId", "qrCodeId", "sourceAction", "userId") ON TABLE public."TraceEvent" TO "mscqr_rls_cert_app";
GRANT SELECT ("deletedAt", "disabledAt", "id", "isActive", "licenseeId", "name", "orgId", "role", "status") ON TABLE public."User" TO "mscqr_rls_cert_app";
GRANT USAGE ON TYPE public."TraceEventType" TO "mscqr_rls_cert_app";
GRANT USAGE ON TYPE public."UserRole" TO "mscqr_rls_cert_app";
GRANT USAGE ON TYPE public."UserStatus" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "orgId", "userId", "tokenHash", "expiresAt", "createdAt", "createdIpHash", "createdUserAgent", "authenticatedAt", "mfaVerifiedAt", "lastUsedAt", "revokedAt", "revokedReason", "replacedByTokenHash", "rotationRequestId", "rotationClaimedAt", "rotationCompletedAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityAssurance", "sessionCapabilityExpiresAt", "sessionCapabilityLastUsedAt", "sessionCapabilityRevokedAt", "sessionCapabilityRevokedReason") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "orgId", "userId", "tokenHash", "expiresAt", "createdAt", "createdIpHash", "createdUserAgent", "authenticatedAt", "mfaVerifiedAt", "lastUsedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("revokedAt", "revokedReason", "lastUsedAt", "replacedByTokenHash", "rotationRequestId", "rotationClaimedAt", "rotationCompletedAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityAssurance", "sessionCapabilityExpiresAt", "sessionCapabilityLastUsedAt", "sessionCapabilityRevokedAt", "sessionCapabilityRevokedReason") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt", "emailVerifiedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId", "isPrimary", "createdAt", "updatedAt") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "brandName", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "isEnabled", "lastUsedAt") ON TABLE public."AdminMfaCredential" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "lastUsedAt") ON TABLE public."AdminWebAuthnCredential" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "type", "lastUsedAt", "disabledAt") ON TABLE public."UserMfaFactor" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "usedAt") ON TABLE public."UserBackupCode" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "ticketHash", "sessionBindingHash", "purpose", "riskScore", "riskLevel", "reasons", "createdIpHash", "createdUserAgentHash", "maxAttempts", "createdAt", "updatedAt", "expiresAt") ON TABLE public."AuthMfaChallenge" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "payload", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "pendingEmail", "passwordHash", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt", "failedLoginAttempts", "lockedUntil", "lastLoginAt", "emailVerifiedAt", "pendingEmailRequestedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("email", "pendingEmail", "pendingEmailRequestedAt", "passwordHash", "name", "status", "failedLoginAttempts", "lockedUntil", "emailVerifiedAt", "updatedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "licenseeId", "email", "role", "manufacturerId", "tokenHash", "expiresAt", "usedAt") ON TABLE public."Invite" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("usedAt", "acceptedByUserId") ON TABLE public."Invite" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "userId", "tokenHash", "expiresAt", "usedAt") ON TABLE public."PasswordReset" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "orgId", "userId", "tokenHash", "expiresAt", "createdAt", "createdIpHash", "userAgentHash") ON TABLE public."PasswordReset" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("usedAt") ON TABLE public."PasswordReset" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "email", "pendingEmail", "purpose", "tokenHash", "expiresAt", "usedAt") ON TABLE public."EmailVerificationToken" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("usedAt") ON TABLE public."EmailVerificationToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "revokedAt", "sessionCapabilityRevokedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("revokedAt", "revokedReason", "lastUsedAt", "sessionCapabilityRevokedAt", "sessionCapabilityRevokedReason") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "payload", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "pendingEmail", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt", "emailVerifiedAt", "pendingEmailRequestedAt", "createdAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("passwordHash", "failedLoginAttempts", "lockedUntil", "lastLoginAt", "updatedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "orgId", "tokenHash", "expiresAt", "createdAt", "createdIpHash", "createdUserAgent", "authenticatedAt", "mfaVerifiedAt", "lastUsedAt", "revokedAt", "revokedReason", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityExpiresAt", "sessionCapabilityRevokedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "orgId", "userId", "tokenHash", "expiresAt", "createdAt", "createdIpHash", "createdUserAgent", "authenticatedAt", "mfaVerifiedAt", "lastUsedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("revokedAt", "revokedReason", "lastUsedAt", "sessionCapabilityRevokedAt", "sessionCapabilityRevokedReason") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "brandName", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "isEnabled", "lastUsedAt") ON TABLE public."AdminMfaCredential" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "lastUsedAt") ON TABLE public."AdminWebAuthnCredential" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "type", "lastUsedAt", "disabledAt") ON TABLE public."UserMfaFactor" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("userId", "usedAt") ON TABLE public."UserBackupCode" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "riskScore", "riskLevel", "reasons", "ipHash", "userAgentHash", "createdAt") ON TABLE public."AuthSessionRiskSignal" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "ticketHash", "purpose", "riskScore", "riskLevel", "reasons", "createdIpHash", "createdUserAgentHash", "attempts", "maxAttempts", "createdAt", "updatedAt", "expiresAt") ON TABLE public."MfaLoginChallenge" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "payload", "requestId", "organizationId", "initiatingUserId", "initiatingActorRoleSnapshot", "expiresAt", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "expiresAt", "revokedAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityExpiresAt", "sessionCapabilityRevokedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "status", "triggerType", "scheduledScheduleId", "periodFrom", "periodTo", "fileName", "storageKey", "integrityHash", "signatureAlgorithm", "summary", "errorMessage", "startedByUserId", "startedAt", "finishedAt", "createdAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "licenseeId", "status", "triggerType", "periodFrom", "periodTo", "startedByUserId", "startedAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "fileName", "storageKey", "integrityHash", "signatureAlgorithm", "summary", "errorMessage", "finishedAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "keyHash", "action", "scope", "requestHash", "statusCode", "responsePayload", "createdAt", "completedAt", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "keyHash", "action", "scope", "requestHash", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("statusCode", "responsePayload", "completedAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "status", "slaDueAt", "createdAt") ON TABLE public."Incident" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "incidentId", "fileUrl", "storageKey", "fileType", "uploadedByUserId", "uploadedBy", "createdAt") ON TABLE public."IncidentEvidence" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("incidentId", "currentStage") ON TABLE public."IncidentHandoff" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("licenseeId", "action", "createdAt") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("licenseeId", "retentionDays") ON TABLE public."EvidenceRetentionPolicy" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "payload", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt", "passwordHash", "location", "website", "createdAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "email", "passwordHash", "name", "role", "orgId", "licenseeId", "location", "website", "status", "isActive", "emailVerifiedAt", "updatedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("email", "passwordHash", "name", "orgId", "licenseeId", "location", "website", "status", "isActive", "disabledAt", "deletedAt", "updatedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT DELETE ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "name", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "name", "isActive", "updatedAt") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "description", "brandName", "location", "website", "supportEmail", "supportPhone", "isActive", "suspendedAt", "createdAt", "updatedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "orgId", "name", "prefix", "description", "brandName", "location", "website", "supportEmail", "supportPhone", "isActive", "updatedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("name", "description", "brandName", "location", "website", "supportEmail", "supportPhone", "isActive", "updatedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT DELETE ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId", "isPrimary", "createdAt") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("manufacturerId", "licenseeId", "isPrimary", "updatedAt") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("isPrimary", "updatedAt") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT DELETE ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "expiresAt", "revokedAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityExpiresAt", "sessionCapabilityRevokedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("revokedAt", "revokedReason", "sessionCapabilityRevokedAt", "sessionCapabilityRevokedReason") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "manufacturerId") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("manufacturerId", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId") ON TABLE public."QRRange" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("keyHash", "requestHash", "completedAt", "responsePayload") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "keyHash", "action", "scope", "requestHash", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("statusCode", "responsePayload", "completedAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details", "ipHash", "userAgent", "createdAt") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "eventType", "payload", "requestId", "organizationId", "licenseeId", "initiatingUserId", "updatedAt") ON TABLE public."SecurityEventOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "licenseeId", "email", "role", "manufacturerId", "tokenHash", "expiresAt", "usedAt", "createdByUserId", "createdAt") ON TABLE public."Invite" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "orgId", "licenseeId", "email", "role", "manufacturerId", "tokenHash", "expiresAt", "createdByUserId", "createdAt") ON TABLE public."Invite" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("usedAt") ON TABLE public."Invite" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "expiresAt", "revokedAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityExpiresAt", "sessionCapabilityRevokedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("sessionCapabilityLastUsedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "startCode", "endCode", "totalCodes", "usedCodes", "createdAt", "updatedAt") ON TABLE public."QRRange" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "licenseeId", "startCode", "endCode", "totalCodes", "usedCodes", "updatedAt") ON TABLE public."QRRange" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "code", "displayCode", "licenseeId", "batchId", "status", "scanCount", "createdAt", "updatedAt", "scannedAt", "printedAt", "blockedAt", "redeemedAt", "printJobId", "replayEpoch", "tokenNonce", "tokenIssuedAt", "tokenExpiresAt", "tokenHash") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "code", "displayCode", "licenseeId", "batchId", "status", "tokenNonce", "updatedAt") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("batchId", "status", "printJobId", "tokenNonce", "tokenIssuedAt", "tokenExpiresAt", "tokenHash", "issuanceMode", "customerVerifiableAt", "printedAt", "printedByUserId", "redeemedAt", "redeemedDeviceFingerprint", "updatedAt") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT DELETE ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "name", "manufacturerId", "parentBatchId", "rootBatchId", "startCode", "endCode", "totalCodes", "lifecycleState", "printedAt", "releasedAt", "createdAt", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "name", "licenseeId", "manufacturerId", "parentBatchId", "rootBatchId", "startCode", "endCode", "totalCodes", "lifecycleState", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("startCode", "endCode", "totalCodes", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT DELETE ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "requestedByUserId", "quantity", "startNumber", "endNumber", "batchName", "status") ON TABLE public."QrAllocationRequest" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "approvedByUserId", "approvedAt", "decisionNote", "startNumber", "endNumber", "quantity", "updatedAt") ON TABLE public."QrAllocationRequest" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "licenseeId", "createdByUserId", "requestId", "source", "startCode", "endCode", "totalCodes") ON TABLE public."AllocationEvent" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details", "createdAt") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "eventType", "payload", "requestId", "organizationId", "licenseeId", "initiatingUserId", "updatedAt") ON TABLE public."SecurityEventOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "eventType", "licenseeId", "batchId", "qrCodeId", "manufacturerId", "userId", "sourceAction", "details", "createdAt") ON TABLE public."TraceEvent" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "alertType", "severity", "message", "score", "batchId", "qrCodeId", "manufacturerId", "acknowledgedAt", "acknowledgedByUserId", "details", "createdAt") ON TABLE public."PolicyAlert" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("batchId", "licenseeId", "manufacturerId", "totalCodes", "dormant", "active", "activated", "allocated", "printed", "redeemed", "blocked", "scanned", "refreshedAt", "createdAt", "updatedAt") ON TABLE public."InventoryStatusRollup" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("batchId", "licenseeId", "manufacturerId", "totalCodes", "dormant", "active", "activated", "allocated", "printed", "redeemed", "blocked", "scanned", "refreshedAt", "createdAt", "updatedAt") ON TABLE public."InventoryStatusRollup" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("licenseeId", "manufacturerId", "totalCodes", "dormant", "active", "activated", "allocated", "printed", "redeemed", "blocked", "scanned", "refreshedAt", "updatedAt") ON TABLE public."InventoryStatusRollup" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("qrCodeId", "licenseeId", "batchId", "status", "scannedAt", "isFirstScan", "isTrustedOwnerContext", "device", "locationName", "locationCountry", "locationCity") ON TABLE public."QrScanLog" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "bucketKey", "hourBucket", "licenseeId", "batchId", "manufacturerId", "totalScanEvents", "firstScanEvents", "repeatScanEvents", "blockedEvents", "trustedOwnerEvents", "externalEvents", "namedLocationEvents", "knownDeviceEvents", "uniqueQrCodes", "firstScannedAt", "lastScannedAt", "createdAt", "updatedAt") ON TABLE public."ScanMetricsHourlyRollup" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("bucketKey", "totalScanEvents", "firstScanEvents", "repeatScanEvents", "blockedEvents", "trustedOwnerEvents", "externalEvents", "namedLocationEvents", "knownDeviceEvents", "uniqueQrCodes", "firstScannedAt", "lastScannedAt", "updatedAt") ON TABLE public."ScanMetricsHourlyRollup" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("totalScanEvents", "firstScanEvents", "repeatScanEvents", "blockedEvents", "trustedOwnerEvents", "externalEvents", "namedLocationEvents", "knownDeviceEvents", "uniqueQrCodes", "firstScannedAt", "lastScannedAt", "updatedAt") ON TABLE public."ScanMetricsHourlyRollup" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("key", "value") ON TABLE public."SystemCheckpoint" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("key", "value", "createdAt", "updatedAt") ON TABLE public."SystemCheckpoint" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("value", "updatedAt") ON TABLE public."SystemCheckpoint" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "name", "licenseeId", "manufacturerId", "startCode", "lifecycleState", "sampleScanPolicy", "metadata", "totalCodes", "printedAt", "releasedAt", "releasedByUserId", "suspendedAt", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("lifecycleState", "printedAt", "releasedAt", "releasedByUserId", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "code", "displayCode", "licenseeId", "batchId", "status", "printJobId", "replayEpoch", "tokenNonce", "tokenIssuedAt", "tokenExpiresAt", "tokenHash", "printedAt", "scannedAt", "scanCount") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "printJobId", "tokenNonce", "tokenIssuedAt", "tokenExpiresAt", "tokenHash", "issuanceMode", "printedAt", "printedByUserId", "customerVerifiableAt", "updatedAt") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "jobNumber", "batchId", "manufacturerId", "printerId", "status", "printMode", "pipelineState", "payloadType", "payloadHash", "quantity", "itemCount", "rangeStart", "rangeEnd", "sentAt", "completedAt", "failureReason", "reprintOfJobId", "approvedByUserId", "reprintReason", "printLockTokenHash", "confirmedAt", "createdAt", "updatedAt") ON TABLE public."PrintJob" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "jobNumber", "batchId", "manufacturerId", "printerId", "status", "printMode", "pipelineState", "payloadType", "quantity", "itemCount", "rangeStart", "rangeEnd", "printLockTokenHash", "reprintOfJobId", "approvedByUserId", "reprintReason", "createdAt", "updatedAt") ON TABLE public."PrintJob" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "pipelineState", "sentAt", "completedAt", "failureReason", "confirmedAt", "updatedAt") ON TABLE public."PrintJob" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "printJobId", "batchId", "manufacturerId", "printerRegistrationId", "printerId", "status", "totalItems", "issuedItems", "confirmedItems", "frozenItems", "failedReason", "startedAt", "completedAt", "createdAt", "updatedAt") ON TABLE public."PrintSession" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "printJobId", "batchId", "manufacturerId", "printerRegistrationId", "printerId", "status", "totalItems", "createdAt", "updatedAt") ON TABLE public."PrintSession" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "issuedItems", "confirmedItems", "failedReason", "completedAt", "updatedAt") ON TABLE public."PrintSession" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "printSessionId", "qrCodeId", "code", "state", "pipelineState", "issueSequence", "attemptCount", "currentRenderTokenHash", "deviceJobRef", "dispatchMetadata", "confirmationEvidence", "issuedAt", "dispatchedAt", "agentAckedAt", "confirmationDeadlineAt", "printConfirmedAt", "closedAt", "frozenAt", "failedAt", "failureReason", "deadLetterReason", "createdAt", "updatedAt") ON TABLE public."PrintItem" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "printSessionId", "qrCodeId", "code", "state", "pipelineState", "issueSequence", "createdAt", "updatedAt") ON TABLE public."PrintItem" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("printSessionId", "state", "pipelineState", "issueSequence", "attemptCount", "deviceJobRef", "dispatchMetadata", "confirmationEvidence", "issuedAt", "dispatchedAt", "agentAckedAt", "confirmationDeadlineAt", "printConfirmedAt", "failedAt", "failureReason", "updatedAt") ON TABLE public."PrintItem" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "printItemId", "eventType", "previousState", "nextState", "details", "actorUserId", "createdAt") ON TABLE public."PrintItemEvent" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "batchId", "printJobId", "qrCodeId", "eventType", "actorId", "metadata", "createdAt") ON TABLE public."PrintAuditEvent" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "batchId", "printJobId", "qrCodeId", "eventType", "actorId", "metadata", "createdAt") ON TABLE public."PrintAuditEvent" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "originalPrintJobId", "replacementPrintJobId", "requestedByUserId", "approvedByUserId", "licenseeId", "manufacturerId", "batchId", "requestedByRole", "targetApproverRole", "quantity", "affectedRangeStart", "affectedRangeEnd", "status", "reason", "decisionNote", "rejectionReason", "approvedAt", "rejectedAt", "executedAt", "createdAt", "updatedAt") ON TABLE public."PrintReissueRequest" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "originalPrintJobId", "requestedByUserId", "licenseeId", "manufacturerId", "batchId", "requestedByRole", "targetApproverRole", "quantity", "affectedRangeStart", "affectedRangeEnd", "status", "reason", "createdAt", "updatedAt") ON TABLE public."PrintReissueRequest" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("replacementPrintJobId", "targetApproverRole", "status", "approvedByUserId", "approvedAt", "rejectedAt", "executedAt", "decisionNote", "rejectionReason", "updatedAt") ON TABLE public."PrintReissueRequest" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "actionKey", "status", "requestedByUserId", "reviewedByUserId", "executedByUserId", "licenseeId", "entityType", "entityId", "payload", "summary", "expiresAt", "createdAt") ON TABLE public."SensitiveActionApproval" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "actionKey", "status", "requestedByUserId", "licenseeId", "entityType", "entityId", "payload", "summary", "expiresAt", "createdAt", "updatedAt") ON TABLE public."SensitiveActionApproval" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "reviewedByUserId", "reviewedAt", "executedByUserId", "executedAt", "updatedAt") ON TABLE public."SensitiveActionApproval" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "name", "vendor", "model", "connectionType", "commandLanguage", "printerRegistrationId", "orgId", "licenseeId", "assignedUserId", "createdByUserId", "isActive", "isDefault", "nativePrinterId", "agentId", "deviceFingerprint", "deliveryMode", "gatewayId", "gatewaySecretHash", "gatewayLastSeenAt", "gatewayStatus", "gatewayLastError", "ipAddress", "host", "port", "resourcePath", "tlsEnabled", "printerUri", "calibrationProfile", "capabilitySummary", "metadata", "lastSeenAt", "lastValidatedAt", "lastValidationStatus", "lastValidationMessage", "createdAt", "updatedAt") ON TABLE public."Printer" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "name", "vendor", "model", "connectionType", "commandLanguage", "ipAddress", "host", "port", "resourcePath", "tlsEnabled", "printerUri", "deliveryMode", "gatewayId", "gatewaySecretHash", "gatewayStatus", "gatewayLastError", "nativePrinterId", "agentId", "deviceFingerprint", "printerRegistrationId", "orgId", "licenseeId", "assignedUserId", "createdByUserId", "isActive", "isDefault", "lastSeenAt", "lastValidatedAt", "lastValidationStatus", "capabilitySummary", "calibrationProfile", "metadata", "createdAt", "updatedAt") ON TABLE public."Printer" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("name", "vendor", "model", "commandLanguage", "ipAddress", "host", "port", "resourcePath", "tlsEnabled", "printerUri", "deliveryMode", "gatewayId", "gatewaySecretHash", "gatewayLastSeenAt", "gatewayStatus", "gatewayLastError", "printerRegistrationId", "nativePrinterId", "agentId", "deviceFingerprint", "orgId", "licenseeId", "assignedUserId", "isActive", "isDefault", "capabilitySummary", "calibrationProfile", "metadata", "lastSeenAt", "lastValidatedAt", "lastValidationStatus", "lastValidationMessage", "updatedAt") ON TABLE public."Printer" TO "mscqr_rls_cert_auth_owner";
GRANT DELETE ON TABLE public."Printer" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "orgId", "licenseeId", "deviceFingerprint", "agentId", "publicKeyPem", "certFingerprint", "trustStatus", "trustReason", "approvedAt", "revokedAt", "lastSeenAt", "createdAt", "updatedAt") ON TABLE public."PrinterRegistration" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "orgId", "licenseeId", "deviceFingerprint", "agentId", "publicKeyPem", "certFingerprint", "trustStatus", "trustReason", "approvedAt", "lastSeenAt", "createdAt", "updatedAt") ON TABLE public."PrinterRegistration" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("orgId", "licenseeId", "agentId", "publicKeyPem", "certFingerprint", "trustStatus", "trustReason", "approvedAt", "revokedAt", "lastSeenAt", "updatedAt") ON TABLE public."PrinterRegistration" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "name", "email", "role", "location", "metadata") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "printerRegistrationId", "attestedAt", "expiresAt", "signatureValid", "trustValid", "rejectionReason", "metadata", "createdAt") ON TABLE public."PrinterAttestation" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "printerRegistrationId", "signedPayloadHash", "heartbeatNonce", "attestedAt", "expiresAt", "sourceIpHash", "userAgentHash", "mtlsFingerprint", "signatureValid", "trustValid", "rejectionReason", "metadata", "createdAt") ON TABLE public."PrinterAttestation" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "location", "metadata", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details", "createdAt") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "eventType", "payload", "requestId", "organizationId", "licenseeId", "initiatingUserId", "updatedAt") ON TABLE public."SecurityEventOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "keyHash", "action", "scope", "requestHash", "statusCode", "responsePayload", "createdAt", "completedAt", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "keyHash", "action", "scope", "requestHash", "createdAt", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("action", "scope", "requestHash", "statusCode", "responsePayload", "createdAt", "completedAt", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "identityName", "jobFamily", "scheduleId", "capabilityHash", "capabilityHashVersion", "expiresAt", "revokedAt", "revokedReason", "rotatedFromCredentialId", "lastUsedAt", "createdAt", "updatedAt") ON TABLE public."ScheduledJobCredential" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "identityName", "jobFamily", "scheduleId", "capabilityHash", "capabilityHashVersion", "expiresAt", "rotatedFromCredentialId", "updatedAt") ON TABLE public."ScheduledJobCredential" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("lastUsedAt", "revokedAt", "revokedReason", "updatedAt") ON TABLE public."ScheduledJobCredential" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "status", "triggerType", "scheduledScheduleId", "periodFrom", "periodTo", "fileName", "storageKey", "integrityHash", "signatureAlgorithm", "summary", "errorMessage", "startedByUserId", "startedAt", "finishedAt", "createdAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "licenseeId", "status", "triggerType", "scheduledScheduleId", "periodFrom", "periodTo", "startedByUserId", "startedAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "fileName", "storageKey", "integrityHash", "signatureAlgorithm", "summary", "errorMessage", "finishedAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "keyHash", "action", "scope", "requestHash", "statusCode", "responsePayload", "createdAt", "completedAt", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "keyHash", "action", "scope", "requestHash", "expiresAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("statusCode", "responsePayload", "completedAt") ON TABLE public."ActionIdempotencyKey" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "status", "slaDueAt", "createdAt") ON TABLE public."Incident" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("incidentId", "currentStage") ON TABLE public."IncidentHandoff" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("licenseeId", "action", "createdAt") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("licenseeId", "retentionDays") ON TABLE public."EvidenceRetentionPolicy" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "payload", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "payload", "jobType", "requestId", "payloadDigest", "idempotencyKey", "organizationId", "licenseeId", "manufacturerId", "initiatingUserId", "initiatingActorRoleSnapshot", "expiresAt", "claimedAt", "claimLeaseExpiresAt", "status", "attempts", "nextAttemptAt", "lastError", "flushedAuditLogId", "createdAt", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "payload", "jobType", "requestId", "payloadDigest", "idempotencyKey", "organizationId", "licenseeId", "manufacturerId", "initiatingUserId", "initiatingActorRoleSnapshot", "expiresAt", "lastError", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "attempts", "nextAttemptAt", "lastError", "flushedAuditLogId", "claimedAt", "claimLeaseExpiresAt", "updatedAt") ON TABLE public."AuditLogOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "eventType", "payload", "jobType", "requestId", "payloadDigest", "idempotencyKey", "organizationId", "licenseeId", "manufacturerId", "initiatingUserId", "expiresAt", "claimedAt", "claimLeaseExpiresAt", "sinkEventId", "status", "attempts", "nextAttemptAt", "lastError", "sentAt", "createdAt", "updatedAt") ON TABLE public."SecurityEventOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "eventType", "payload", "jobType", "requestId", "payloadDigest", "idempotencyKey", "organizationId", "licenseeId", "manufacturerId", "initiatingUserId", "expiresAt", "updatedAt") ON TABLE public."SecurityEventOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT UPDATE ("status", "attempts", "nextAttemptAt", "lastError", "sentAt", "claimedAt", "claimLeaseExpiresAt", "sinkEventId", "updatedAt") ON TABLE public."SecurityEventOutbox" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details", "ipAddress", "ipHash", "userAgent") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "brandName", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId", "isPrimary", "updatedAt") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "name", "licenseeId", "manufacturerId", "parentBatchId", "rootBatchId", "startCode", "endCode", "totalCodes", "lifecycleState", "sampleScanPolicy", "metadata", "releasedAt", "releasedByUserId", "printedAt", "suspendedAt", "suspendedReason", "printPackDownloadedAt", "printPackDownloadedByUserId", "createdAt", "updatedAt") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "code", "displayCode", "licenseeId", "batchId", "status", "printJobId") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("batchId", "licenseeId", "manufacturerId", "totalCodes", "dormant", "active", "activated", "allocated", "printed", "redeemed", "blocked", "scanned") ON TABLE public."InventoryStatusRollup" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "printSessionId", "qrCodeId", "state", "agentAckedAt", "dispatchedAt", "deviceJobRef", "printConfirmedAt", "confirmationEvidence", "deadLetterReason", "failureReason") ON TABLE public."PrintItem" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "printJobId", "batchId", "status") ON TABLE public."PrintSession" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "batchId", "status") ON TABLE public."PrintJob" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT INSERT ("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details") ON TABLE public."AuditLog" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "email", "name", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt", "createdAt", "location", "website") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "name", "prefix", "description", "brandName", "location", "website", "supportEmail", "supportPhone", "metadata", "isActive", "suspendedAt", "suspendedReason", "createdAt", "updatedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("manufacturerId", "licenseeId", "isPrimary", "createdAt", "updatedAt") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "email", "role", "expiresAt", "usedAt", "createdAt") ON TABLE public."Invite" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId") ON TABLE public."Batch" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId") ON TABLE public."QRCode" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "startCode", "endCode", "totalCodes", "usedCodes", "createdAt", "updatedAt") ON TABLE public."QRRange" TO "mscqr_rls_cert_auth_owner";
GRANT USAGE ON SCHEMA public TO "mscqr_rls_cert_auth_owner";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
GRANT USAGE ON SCHEMA app_auth TO "mscqr_rls_cert_preauth";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
GRANT USAGE ON SCHEMA app_rls TO "mscqr_rls_cert_preauth";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
GRANT EXECUTE ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
RESET ROLE;
UPDATE mscqr_rls_install.state SET phase='runtime-grants-installed' WHERE singleton;
COMMIT;
