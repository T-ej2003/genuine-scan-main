\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'policy package requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'policy package is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='2c1d2c305b7f788d56ac78a231597285cceaf1dae399302f090c4a6fa110319f'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:2c1d2c305b7f788d56ac78a231597285cceaf1dae399302f090c4a6fa110319f'
    AND administrator_role='certification-administrator'
    AND phase='runtime-grants-installed'
    AND NOT traffic_enabled) THEN RAISE EXCEPTION 'policy package lacks the exact clean-room package marker'; END IF;

  IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>9
     OR EXISTS (SELECT 1 FROM pg_roles r JOIN (VALUES ('mscqr_rls_cert_owner', false),
    ('mscqr_rls_cert_auth_owner', false),
    ('mscqr_rls_cert_app', true),
    ('mscqr_rls_cert_read', true),
    ('mscqr_rls_cert_preauth', true),
    ('mscqr_rls_cert_worker', true),
    ('mscqr_rls_cert_scheduled', true),
    ('mscqr_rls_cert_operator', true),
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:2c1d2c305b7f788d56ac78a231597285cceaf1dae399302f090c4a6fa110319f')
  THEN RAISE EXCEPTION 'managed role attributes or package markers drifted'; END IF;

  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>18
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND (member.rolname<>'certification-administrator' OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND grantor.rolname='certification-administrator' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))
  THEN RAISE EXCEPTION 'managed role membership topology drifted'; END IF;
END $$;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
  EXECUTE format('SET LOCAL ROLE %I','mscqr_rls_cert_owner');
END $$;
ALTER TABLE public."ActionIdempotencyKey" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ActionIdempotencyKey" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AdminMfaCredential" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AdminMfaCredential" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AdminWebAuthnCredential" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AdminWebAuthnCredential" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AllocationEvent" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AllocationEvent" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AuditLog" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AuditLog" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AuditLogOutbox" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AuditLogOutbox" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AuthMfaChallenge" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AuthMfaChallenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AuthSessionRiskSignal" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AuthSessionRiskSignal" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."AuthWebAuthnChallenge" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."AuthWebAuthnChallenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Batch" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Batch" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."CompliancePackJob" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."CompliancePackJob" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerTrustCredential" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerTrustCredential" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerTrustIntake" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerTrustIntake" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerVerificationSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerVerificationSession" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerWebAuthnChallenge" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerWebAuthnChallenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerWebAuthnCredential" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."CustomerWebAuthnCredential" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."DegradationEvent" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."DegradationEvent" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."EmailVerificationToken" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."EmailVerificationToken" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."EvidenceRetentionJob" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."EvidenceRetentionJob" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."EvidenceRetentionPolicy" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."EvidenceRetentionPolicy" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."ForensicEventChain" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ForensicEventChain" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Incident" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Incident" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentCommunication" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentCommunication" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentEvent" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentEvent" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentEvidence" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentEvidence" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentEvidenceFingerprint" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentEvidenceFingerprint" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentHandoff" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."IncidentHandoff" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."InventoryStatusRollup" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."InventoryStatusRollup" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Invite" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Invite" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Licensee" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Licensee" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."ManufacturerLicenseeLink" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ManufacturerLicenseeLink" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."MfaLoginChallenge" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."MfaLoginChallenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Notification" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Notification" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Organization" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Organization" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Ownership" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Ownership" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."OwnershipTransfer" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."OwnershipTransfer" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PasswordReset" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PasswordReset" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PolicyAlert" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PolicyAlert" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PolicyRule" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PolicyRule" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintAuditEvent" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintAuditEvent" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."Printer" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."Printer" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterAgentSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterAgentSession" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterAttestation" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterAttestation" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterProfile" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterProfile" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterProfileSnapshot" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterProfileSnapshot" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterRegistration" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrinterRegistration" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintItem" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintItem" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintItemEvent" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintItemEvent" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintJob" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintJob" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintJobChunk" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintJobChunk" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintReissueRequest" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintReissueRequest" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."PrintSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."PrintSession" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."QrAllocationRequest" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."QrAllocationRequest" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."QRCode" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."QRCode" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."QRRange" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."QRRange" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."QrScanLog" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."QrScanLog" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."RefreshToken" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."RefreshToken" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."ReplacementChain" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ReplacementChain" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."RequestAccess" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."RequestAccess" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."RouteTransitionMetric" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."RouteTransitionMetric" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."ScanMetricsHourlyRollup" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."ScanMetricsHourlyRollup" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SecurityEventOutbox" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SecurityEventOutbox" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SecurityPolicy" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SecurityPolicy" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SensitiveActionApproval" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SensitiveActionApproval" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SupportIssueReport" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SupportIssueReport" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SupportTicket" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SupportTicket" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SupportTicketMessage" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SupportTicketMessage" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."SystemCheckpoint" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."SystemCheckpoint" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."TenantFeatureFlag" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."TenantFeatureFlag" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."TraceEvent" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."TraceEvent" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."User" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."User" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."UserBackupCode" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."UserBackupCode" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."UserMfaFactor" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."UserMfaFactor" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."VerificationDecision" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."VerificationDecision" FORCE ROW LEVEL SECURITY;
ALTER TABLE public."VerificationEvidenceSnapshot" ENABLE ROW LEVEL SECURITY;
ALTER TABLE public."VerificationEvidenceSnapshot" FORCE ROW LEVEL SECURITY;
CREATE POLICY "full_rls_auditlog_insert_sql_profile_risk_analytics__fa8df9e7e5" ON public."AuditLog" AS PERMISSIVE FOR INSERT TO "mscqr_rls_cert_app" WITH CHECK ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND (("userId" = app_rls.current_user_id() AND "licenseeId" = app_rls.current_licensee_id() AND "orgId" = app_rls.current_organization_id()))));
COMMENT ON POLICY "full_rls_auditlog_insert_sql_profile_risk_analytics__fa8df9e7e5" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-insert-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_batch_select_sql_profile_risk_analytics_lic_c1a48aed58" ON public."Batch" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_batch_select_sql_profile_risk_analytics_lic_c1a48aed58" ON public."Batch" IS '{"sourceCommandRuleIds":["command-batch-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_incident_select_sql_profile_risk_analytics__5b7afba446" ON public."Incident" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_incident_select_sql_profile_risk_analytics__5b7afba446" ON public."Incident" IS '{"sourceCommandRuleIds":["command-incident-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_licensee_select_sql_profile_risk_analytics__196ec818f8" ON public."Licensee" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND (("id" = app_rls.current_licensee_id() AND "orgId" = app_rls.current_organization_id()))));
COMMENT ON POLICY "full_rls_licensee_select_sql_profile_risk_analytics__196ec818f8" ON public."Licensee" IS '{"sourceCommandRuleIds":["command-licensee-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_manufacturerlicenseelink_select_sql_profile_23bfa2d5a1" ON public."ManufacturerLicenseeLink" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_manufacturerlicenseelink_select_sql_profile_23bfa2d5a1" ON public."ManufacturerLicenseeLink" IS '{"sourceCommandRuleIds":["command-manufacturer-licensee-link-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_organization_select_sql_profile_risk_analyt_e01a17d3ed" ON public."Organization" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("id" = app_rls.current_organization_id())));
COMMENT ON POLICY "full_rls_organization_select_sql_profile_risk_analyt_e01a17d3ed" ON public."Organization" IS '{"sourceCommandRuleIds":["command-organization-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_policyalert_select_sql_profile_risk_analyti_d2f587dad6" ON public."PolicyAlert" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_policyalert_select_sql_profile_risk_analyti_d2f587dad6" ON public."PolicyAlert" IS '{"sourceCommandRuleIds":["command-policy-alert-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_policyrule_select_sql_profile_risk_analytic_9ad9712ac4" ON public."PolicyRule" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ((
    ("licenseeId" = app_rls.current_licensee_id() AND ("orgId" IS NULL OR "orgId"=app_rls.current_organization_id()) AND ("manufacturerId" IS NULL OR app_rls.manufacturer_scope_valid("manufacturerId")))
    OR ("licenseeId" IS NULL AND "orgId" = app_rls.current_organization_id() AND "manufacturerId" IS NULL)
    OR ("licenseeId" IS NULL AND "manufacturerId" IS NOT NULL AND ("orgId" IS NULL OR "orgId"=app_rls.current_organization_id()) AND app_rls.manufacturer_scope_valid("manufacturerId"))
  ) AND "isActive" = TRUE)));
COMMENT ON POLICY "full_rls_policyrule_select_sql_profile_risk_analytic_9ad9712ac4" ON public."PolicyRule" IS '{"sourceCommandRuleIds":["command-policy-rule-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_qrscanlog_select_sql_profile_risk_analytics_61c1729f27" ON public."QrScanLog" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_qrscanlog_select_sql_profile_risk_analytics_61c1729f27" ON public."QrScanLog" IS '{"sourceCommandRuleIds":["command-qr-scan-log-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_qrcode_select_sql_profile_risk_analytics_li_dd9f8b097c" ON public."QRCode" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_qrcode_select_sql_profile_risk_analytics_li_dd9f8b097c" ON public."QRCode" IS '{"sourceCommandRuleIds":["command-qrcode-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_securitypolicy_select_sql_profile_risk_anal_9b15f0bd9b" ON public."SecurityPolicy" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_securitypolicy_select_sql_profile_risk_anal_9b15f0bd9b" ON public."SecurityPolicy" IS '{"sourceCommandRuleIds":["command-security-policy-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_user_select_sql_profile_risk_analytics_lice_db5e477285" ON public."User" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND (("id"=app_rls.current_user_id() OR app_rls.manufacturer_scope_valid("id")))));
COMMENT ON POLICY "full_rls_user_select_sql_profile_risk_analytics_lice_db5e477285" ON public."User" IS '{"sourceCommandRuleIds":["command-user-select-509547f03abe"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["tenant-risk-analytics"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_auditlog_insert_sql_profile_risk_analytics__0f42474373" ON public."AuditLog" AS PERMISSIVE FOR INSERT TO "mscqr_rls_cert_app" WITH CHECK ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND (("userId"=app_rls.current_user_id() AND "licenseeId"=app_rls.current_licensee_id() AND EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="AuditLog"."orgId" AND scope_licensee."isActive"=TRUE AND scope_licensee."suspendedAt" IS NULL)))));
COMMENT ON POLICY "full_rls_auditlog_insert_sql_profile_risk_analytics__0f42474373" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-insert-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_batch_select_sql_profile_risk_analytics_pla_5cb898fc84" ON public."Batch" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_batch_select_sql_profile_risk_analytics_pla_5cb898fc84" ON public."Batch" IS '{"sourceCommandRuleIds":["command-batch-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_incident_select_sql_profile_risk_analytics__e0fb8de21b" ON public."Incident" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_incident_select_sql_profile_risk_analytics__e0fb8de21b" ON public."Incident" IS '{"sourceCommandRuleIds":["command-incident-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_licensee_select_sql_profile_risk_analytics__14d7456070" ON public."Licensee" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("id"=app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_licensee_select_sql_profile_risk_analytics__14d7456070" ON public."Licensee" IS '{"sourceCommandRuleIds":["command-licensee-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_manufacturerlicenseelink_select_sql_profile_f6bb844ebb" ON public."ManufacturerLicenseeLink" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_manufacturerlicenseelink_select_sql_profile_f6bb844ebb" ON public."ManufacturerLicenseeLink" IS '{"sourceCommandRuleIds":["command-manufacturer-licensee-link-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_organization_select_sql_profile_risk_analyt_287c51409b" ON public."Organization" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND (EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="Organization"."id" AND scope_licensee."isActive"=TRUE AND scope_licensee."suspendedAt" IS NULL))));
COMMENT ON POLICY "full_rls_organization_select_sql_profile_risk_analyt_287c51409b" ON public."Organization" IS '{"sourceCommandRuleIds":["command-organization-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_policyalert_select_sql_profile_risk_analyti_2b2fa413e6" ON public."PolicyAlert" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_policyalert_select_sql_profile_risk_analyti_2b2fa413e6" ON public."PolicyAlert" IS '{"sourceCommandRuleIds":["command-policy-alert-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_policyrule_select_sql_profile_risk_analytic_4843026076" ON public."PolicyRule" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ((
    ("licenseeId" = app_rls.current_licensee_id() AND ("orgId" IS NULL OR EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="PolicyRule"."orgId" AND scope_licensee."isActive"=TRUE AND scope_licensee."suspendedAt" IS NULL)) AND ("manufacturerId" IS NULL OR app_rls.manufacturer_scope_valid("manufacturerId")))
    OR ("licenseeId" IS NULL AND EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="PolicyRule"."orgId" AND scope_licensee."isActive"=TRUE AND scope_licensee."suspendedAt" IS NULL) AND "manufacturerId" IS NULL)
    OR ("licenseeId" IS NULL AND "manufacturerId" IS NOT NULL AND ("orgId" IS NULL OR EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="PolicyRule"."orgId" AND scope_licensee."isActive"=TRUE AND scope_licensee."suspendedAt" IS NULL)) AND app_rls.manufacturer_scope_valid("manufacturerId"))
  ) AND "isActive" = TRUE)));
COMMENT ON POLICY "full_rls_policyrule_select_sql_profile_risk_analytic_4843026076" ON public."PolicyRule" IS '{"sourceCommandRuleIds":["command-policy-rule-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_qrscanlog_select_sql_profile_risk_analytics_481880b778" ON public."QrScanLog" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_qrscanlog_select_sql_profile_risk_analytics_481880b778" ON public."QrScanLog" IS '{"sourceCommandRuleIds":["command-qr-scan-log-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_qrcode_select_sql_profile_risk_analytics_pl_1056ea6284" ON public."QRCode" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_qrcode_select_sql_profile_risk_analytics_pl_1056ea6284" ON public."QRCode" IS '{"sourceCommandRuleIds":["command-qrcode-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_securitypolicy_select_sql_profile_risk_anal_532f30156f" ON public."SecurityPolicy" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_securitypolicy_select_sql_profile_risk_anal_532f30156f" ON public."SecurityPolicy" IS '{"sourceCommandRuleIds":["command-security-policy-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_user_select_sql_profile_risk_analytics_plat_5fbcfb923c" ON public."User" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('tenant-risk-analytics') AND (("id"=app_rls.current_user_id() OR app_rls.manufacturer_scope_valid("id")))));
COMMENT ON POLICY "full_rls_user_select_sql_profile_risk_analytics_plat_5fbcfb923c" ON public."User" IS '{"sourceCommandRuleIds":["command-user-select-509547f03abe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["tenant-risk-analytics"],"scope":"database-validated-selected-licensee-organization","workflowId":"workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics"}';
CREATE POLICY "full_rls_auditlog_insert_sql_profile_audit_log_licen_94344ee5bf" ON public."AuditLog" AS PERMISSIVE FOR INSERT TO "mscqr_rls_cert_app" WITH CHECK ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('audit-log-read') AND (("userId" = app_rls.current_user_id() AND "licenseeId" = app_rls.current_licensee_id() AND "orgId" = app_rls.current_organization_id()))));
COMMENT ON POLICY "full_rls_auditlog_insert_sql_profile_audit_log_licen_94344ee5bf" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe"],"actors":["licensee-admin"],"assurance":"mfa-verified","purpose":["audit-log-read"],"scope":"canonical-licensee-organization","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_auditlog_select_sql_profile_audit_log_licen_9fc3407041" ON public."AuditLog" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('audit-log-read') AND (("licenseeId" = app_rls.current_licensee_id() AND ("orgId" IS NULL OR "orgId" = app_rls.current_organization_id())))));
COMMENT ON POLICY "full_rls_auditlog_select_sql_profile_audit_log_licen_9fc3407041" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-select-97535583a8fe"],"actors":["licensee-admin"],"assurance":"mfa-verified","purpose":["audit-log-read"],"scope":"canonical-licensee-organization","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_user_select_sql_profile_audit_log_licensee__cdc66ebebd" ON public."User" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('audit-log-read') AND ((("id" = app_rls.current_user_id() OR "licenseeId" = app_rls.current_licensee_id() OR app_rls.manufacturer_scope_valid("id")) AND ("orgId" IS NULL OR "orgId" = app_rls.current_organization_id())))));
COMMENT ON POLICY "full_rls_user_select_sql_profile_audit_log_licensee__cdc66ebebd" ON public."User" IS '{"sourceCommandRuleIds":["command-user-select-97535583a8fe"],"actors":["licensee-admin"],"assurance":"mfa-verified","purpose":["audit-log-read"],"scope":"canonical-licensee-organization","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_auditlog_insert_sql_profile_audit_log_manuf_05e750c2a3" ON public."AuditLog" AS PERMISSIVE FOR INSERT TO "mscqr_rls_cert_app" WITH CHECK ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('audit-log-read') AND (("userId" = app_rls.current_user_id() AND "licenseeId" = app_rls.current_licensee_id() AND "orgId" = app_rls.current_organization_id() AND app_rls.manufacturer_scope_valid(app_rls.current_user_id())))));
COMMENT ON POLICY "full_rls_auditlog_insert_sql_profile_audit_log_manuf_05e750c2a3" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe"],"actors":["manufacturer"],"assurance":"mfa-verified","purpose":["audit-log-read"],"scope":"canonical-manufacturer-linked-licensee","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_auditlog_select_sql_profile_audit_log_manuf_76949345a1" ON public."AuditLog" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('audit-log-read') AND (("userId" = app_rls.current_user_id() AND "licenseeId" = app_rls.current_licensee_id() AND "orgId" = app_rls.current_organization_id() AND app_rls.manufacturer_scope_valid(app_rls.current_user_id())))));
COMMENT ON POLICY "full_rls_auditlog_select_sql_profile_audit_log_manuf_76949345a1" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-select-97535583a8fe"],"actors":["manufacturer"],"assurance":"mfa-verified","purpose":["audit-log-read"],"scope":"canonical-manufacturer-linked-licensee","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_user_select_sql_profile_audit_log_manufactu_b86d2f2a12" ON public."User" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('audit-log-read') AND (("id" = app_rls.current_user_id() AND app_rls.manufacturer_scope_valid("id")))));
COMMENT ON POLICY "full_rls_user_select_sql_profile_audit_log_manufactu_b86d2f2a12" ON public."User" IS '{"sourceCommandRuleIds":["command-user-select-97535583a8fe"],"actors":["manufacturer"],"assurance":"mfa-verified","purpose":["audit-log-read"],"scope":"canonical-manufacturer-linked-licensee","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_auditlog_insert_sql_profile_audit_log_platf_7acd564b55" ON public."AuditLog" AS PERMISSIVE FOR INSERT TO "mscqr_rls_cert_app" WITH CHECK ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('platform-audit-log-read') AND (("userId"=app_rls.current_user_id() AND "licenseeId"=app_rls.current_licensee_id() AND EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="AuditLog"."orgId" AND scope_licensee."isActive"=TRUE AND scope_licensee."suspendedAt" IS NULL)))));
COMMENT ON POLICY "full_rls_auditlog_insert_sql_profile_audit_log_platf_7acd564b55" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["platform-audit-log-read"],"scope":"database-validated-selected-licensee","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_auditlog_select_sql_profile_audit_log_platf_0a07cbe1e0" ON public."AuditLog" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('PLATFORM_SUPER_ADMIN', 'SUPER_ADMIN') AND app_rls.current_assurance() IN ('mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('platform-audit-log-read') AND ("licenseeId"=app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_auditlog_select_sql_profile_audit_log_platf_0a07cbe1e0" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-select-97535583a8fe"],"actors":["platform-admin"],"assurance":"mfa-verified","purpose":["platform-audit-log-read"],"scope":"database-validated-selected-licensee","workflowId":"workflow-http-backend-src-controllers-audit-controller-ts-get-logs"}';
CREATE POLICY "full_rls_traceevent_select_sql_profile_trace_license_c5c782790d" ON public."TraceEvent" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('LICENSEE_ADMIN', 'ORG_ADMIN') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('trace-timeline-read') AND ("licenseeId" = app_rls.current_licensee_id())));
COMMENT ON POLICY "full_rls_traceevent_select_sql_profile_trace_license_c5c782790d" ON public."TraceEvent" IS '{"sourceCommandRuleIds":["command-trace-event-select-f571cd9ea8dd"],"actors":["licensee-admin"],"assurance":"password-verified","purpose":["trace-timeline-read"],"scope":"canonical-licensee-organization","workflowId":"workflow-internal-backend-src-services-trace-event-service-ts-get-trace-timeline"}';
CREATE POLICY "full_rls_traceevent_select_sql_profile_trace_manufac_9f66e24ac5" ON public."TraceEvent" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_app" USING ((app_rls.attributed_request() AND app_rls.actor_scope_valid() AND app_rls.current_role() IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') AND app_rls.current_assurance() IN ('password-verified', 'mfa-verified', 'step-up-verified', 'dual-approved-break-glass') AND app_rls.current_purpose() IN ('trace-timeline-read') AND (("licenseeId" = app_rls.current_licensee_id() AND "manufacturerId" = app_rls.current_user_id() AND app_rls.manufacturer_scope_valid(app_rls.current_user_id())))));
COMMENT ON POLICY "full_rls_traceevent_select_sql_profile_trace_manufac_9f66e24ac5" ON public."TraceEvent" IS '{"sourceCommandRuleIds":["command-trace-event-select-f571cd9ea8dd"],"actors":["manufacturer"],"assurance":"password-verified","purpose":["trace-timeline-read"],"scope":"canonical-manufacturer-linked-licensee","workflowId":"workflow-internal-backend-src-services-trace-event-service-ts-get-trace-timeline"}';
CREATE POLICY "full_rls_internal_actor_user" ON public."User" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_owner" USING (((("id"=app_rls.current_user_id() AND "role"::text=app_rls.current_role()) OR (((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_purpose()='tenant-risk-analytics') AND "role" IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')) OR (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND app_rls.current_purpose()='platform-audit-log-read' AND "licenseeId"=app_rls.current_licensee_id())) AND "isActive"=TRUE AND "status"='ACTIVE' AND "deletedAt" IS NULL AND "disabledAt" IS NULL));
COMMENT ON POLICY "full_rls_internal_actor_user" ON public."User" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe","command-audit-log-select-97535583a8fe","command-policy-rule-select-509547f03abe","command-trace-event-select-f571cd9ea8dd"],"actors":["licensee-admin","manufacturer","platform-admin"],"assurance":"source-rule-specific","purpose":["tenant-risk-analytics","audit-log-read","platform-audit-log-read","trace-timeline-read"],"scope":"internal-manufacturer-validation"}';
CREATE POLICY "full_rls_internal_manufacturer_link" ON public."ManufacturerLicenseeLink" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_owner" USING ("licenseeId"=app_rls.current_licensee_id() AND ((app_rls.current_role() IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND "manufacturerId"=app_rls.current_user_id()) OR ((app_rls.current_role() IN ('LICENSEE_ADMIN','ORG_ADMIN') OR app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')) AND app_rls.current_purpose()='tenant-risk-analytics')));
COMMENT ON POLICY "full_rls_internal_manufacturer_link" ON public."ManufacturerLicenseeLink" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe","command-audit-log-select-97535583a8fe","command-policy-rule-select-509547f03abe","command-trace-event-select-f571cd9ea8dd"],"actors":["licensee-admin","manufacturer","platform-admin"],"assurance":"source-rule-specific","purpose":["tenant-risk-analytics","audit-log-read","platform-audit-log-read","trace-timeline-read"],"scope":"internal-manufacturer-validation"}';
CREATE POLICY "full_rls_internal_manufacturer_licensee" ON public."Licensee" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_owner" USING ("id"=app_rls.current_licensee_id() AND (app_rls.current_organization_id() IS NULL OR "orgId"=app_rls.current_organization_id()) AND "isActive"=TRUE AND "suspendedAt" IS NULL);
COMMENT ON POLICY "full_rls_internal_manufacturer_licensee" ON public."Licensee" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe","command-audit-log-select-97535583a8fe","command-policy-rule-select-509547f03abe","command-trace-event-select-f571cd9ea8dd"],"actors":["licensee-admin","manufacturer","platform-admin"],"assurance":"source-rule-specific","purpose":["tenant-risk-analytics","audit-log-read","platform-audit-log-read","trace-timeline-read"],"scope":"internal-manufacturer-validation"}';
CREATE POLICY "full_rls_internal_manufacturer_org" ON public."Organization" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_owner" USING ((("id"=app_rls.current_organization_id()) OR (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND app_rls.current_purpose() IN ('tenant-risk-analytics','platform-audit-log-read') AND EXISTS (SELECT 1 FROM public."Licensee" scope_licensee WHERE scope_licensee."id"=app_rls.current_licensee_id() AND scope_licensee."orgId"="Organization"."id"))) AND "isActive"=TRUE);
COMMENT ON POLICY "full_rls_internal_manufacturer_org" ON public."Organization" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe","command-audit-log-select-97535583a8fe","command-policy-rule-select-509547f03abe","command-trace-event-select-f571cd9ea8dd"],"actors":["licensee-admin","manufacturer","platform-admin"],"assurance":"source-rule-specific","purpose":["tenant-risk-analytics","audit-log-read","platform-audit-log-read","trace-timeline-read"],"scope":"internal-manufacturer-validation"}';
CREATE POLICY "full_rls_internal_platform_audit_details" ON public."AuditLog" AS PERMISSIVE FOR SELECT TO "mscqr_rls_cert_owner" USING (app_rls.current_role() IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND app_rls.current_purpose()='platform-audit-log-read' AND "licenseeId"=app_rls.current_licensee_id());
COMMENT ON POLICY "full_rls_internal_platform_audit_details" ON public."AuditLog" IS '{"sourceCommandRuleIds":["command-audit-log-insert-97535583a8fe","command-audit-log-select-97535583a8fe","command-policy-rule-select-509547f03abe","command-trace-event-select-f571cd9ea8dd"],"actors":["licensee-admin","manufacturer","platform-admin"],"assurance":"source-rule-specific","purpose":["tenant-risk-analytics","audit-log-read","platform-audit-log-read","trace-timeline-read"],"scope":"internal-manufacturer-validation"}';
RESET ROLE;
INSERT INTO mscqr_rls_install.expected_policy(
  schema_name,table_name,policy_name,permissive,command_name,role_names,using_tree,with_check_tree,policy_comment
)
SELECT n.nspname,c.relname,p.polname,p.polpermissive,p.polcmd::text,
  ARRAY(SELECT COALESCE(role_name.rolname,'PUBLIC') FROM unnest(p.polroles) role_oid LEFT JOIN pg_roles role_name ON role_name.oid=role_oid ORDER BY COALESCE(role_name.rolname,'PUBLIC')),
  p.polqual::text,p.polwithcheck::text,obj_description(p.oid,'pg_policy')
FROM pg_policy p
JOIN pg_class c ON c.oid=p.polrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public';
UPDATE mscqr_rls_install.state SET phase='policies-installed' WHERE singleton;
COMMIT;
