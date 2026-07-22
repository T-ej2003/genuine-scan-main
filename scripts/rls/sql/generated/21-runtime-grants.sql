\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'runtime grants requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'runtime grants is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='0aa0de7979049ca489b8239148728dd16a38b4bb93b13a94a8f246d6716a79a3'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:0aa0de7979049ca489b8239148728dd16a38b4bb93b13a94a8f246d6716a79a3'
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
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:0aa0de7979049ca489b8239148728dd16a38b4bb93b13a94a8f246d6716a79a3')
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
GRANT USAGE ON SCHEMA public TO "mscqr_rls_cert_operator";
GRANT INSERT ("action", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId") ON TABLE public."AuditLog" TO "mscqr_rls_cert_app";
GRANT SELECT ("action", "createdAt", "details", "entityId", "entityType", "id", "licenseeId", "orgId", "userId") ON TABLE public."AuditLog" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "licenseeId", "manufacturerId", "name") ON TABLE public."Batch" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "licenseeId") ON TABLE public."Incident" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "isActive", "orgId", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_app";
GRANT SELECT ("licenseeId", "manufacturerId") ON TABLE public."ManufacturerLicenseeLink" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_app";
GRANT SELECT ("acknowledgedAt", "batchId", "id", "incidentId", "licenseeId", "manufacturerId", "policyRuleId", "qrCodeId") ON TABLE public."PolicyAlert" TO "mscqr_rls_cert_app";
GRANT SELECT ("id", "isActive", "licenseeId", "manufacturerId", "orgId") ON TABLE public."PolicyRule" TO "mscqr_rls_cert_app";
GRANT SELECT ("batchId", "id", "licenseeId", "scanCount") ON TABLE public."QRCode" TO "mscqr_rls_cert_app";
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
GRANT SELECT ("id", "userId", "expiresAt", "revokedAt", "sessionCapabilityHash", "sessionCapabilityHashVersion", "sessionCapabilityExpiresAt", "sessionCapabilityRevokedAt") ON TABLE public."RefreshToken" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "role", "orgId", "licenseeId", "status", "isActive", "disabledAt", "deletedAt") ON TABLE public."User" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "orgId", "isActive", "suspendedAt") ON TABLE public."Licensee" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "isActive") ON TABLE public."Organization" TO "mscqr_rls_cert_auth_owner";
GRANT SELECT ("id", "licenseeId", "status", "triggerType", "periodFrom", "periodTo", "fileName", "storageKey", "integrityHash", "signatureAlgorithm", "summary", "errorMessage", "startedByUserId", "startedAt", "finishedAt", "createdAt", "updatedAt") ON TABLE public."CompliancePackJob" TO "mscqr_rls_cert_auth_owner";
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
GRANT USAGE ON SCHEMA public TO "mscqr_rls_cert_auth_owner";
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
GRANT USAGE ON SCHEMA app_auth TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
GRANT EXECUTE ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone,text) TO "mscqr_rls_cert_preauth";
RESET ROLE;
UPDATE mscqr_rls_install.state SET phase='runtime-grants-installed' WHERE singleton;
COMMIT;
