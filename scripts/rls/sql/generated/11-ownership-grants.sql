\set ON_ERROR_STOP on
BEGIN;
DO $$ BEGIN

  IF current_user<>'certification-administrator' THEN RAISE EXCEPTION 'ownership package requires the reviewed brokered administrator'; END IF;
  IF current_database() !~ '^mscqr_full_rls_cert_[a-z0-9_]+$' THEN RAISE EXCEPTION 'ownership package is bound to the reviewed green database'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mscqr_rls_install.state WHERE singleton
    AND target_environment='certification'
    AND deployment_id='cert'
    AND green_database=current_database()
    AND source_contract_sha256='a670d69dee62735b86c0d92ce411922f7bebee11348223063e1136b611983666'
    AND package_role_marker='mscqr-full-rls-clean-room:certification:a670d69dee62735b86c0d92ce411922f7bebee11348223063e1136b611983666'
    AND administrator_role='certification-administrator'

    AND phase='roles-created'
    AND NOT traffic_enabled) THEN RAISE EXCEPTION 'ownership package lacks the exact clean-room package marker'; END IF;

  IF (SELECT count(*) FROM pg_roles WHERE rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>9
     OR EXISTS (SELECT 1 FROM pg_roles r JOIN (VALUES ('mscqr_rls_cert_owner', false),
    ('mscqr_rls_cert_auth_owner', false),
    ('mscqr_rls_cert_app', true),
    ('mscqr_rls_cert_read', true),
    ('mscqr_rls_cert_preauth', true),
    ('mscqr_rls_cert_worker', true),
    ('mscqr_rls_cert_scheduled', true),
    ('mscqr_rls_cert_operator', true),
    ('mscqr_rls_cert_migration', true)) spec(role_name,expected_login) ON spec.role_name=r.rolname WHERE r.rolcanlogin IS DISTINCT FROM spec.expected_login OR r.rolinherit OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR obj_description(r.oid,'pg_authid')<>'mscqr-full-rls-clean-room:certification:a670d69dee62735b86c0d92ce411922f7bebee11348223063e1136b611983666')
  THEN RAISE EXCEPTION 'managed role attributes or package markers drifted'; END IF;

  IF (SELECT count(*) FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))<>18
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND (member.rolname<>'certification-administrator' OR m.inherit_option OR (m.admin_option=m.set_option)))
     OR EXISTS (SELECT 1 FROM pg_roles parent WHERE parent.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration') AND ((SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)<>1 OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member JOIN pg_roles grantor ON grantor.oid=m.grantor WHERE m.roleid=parent.oid AND member.rolname='certification-administrator' AND grantor.rolname='certification-administrator' AND NOT m.admin_option AND NOT m.inherit_option AND m.set_option)<>1))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member WHERE member.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration'))
  THEN RAISE EXCEPTION 'managed role membership topology drifted'; END IF;

  IF EXISTS (
    (SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p') EXCEPT SELECT table_name FROM (VALUES ('ActionIdempotencyKey'),('AdminMfaCredential'),('AdminWebAuthnCredential'),('AllocationEvent'),('AuditLog'),('AuditLogOutbox'),('AuthMfaChallenge'),('AuthSessionRiskSignal'),('AuthWebAuthnChallenge'),('Batch'),('BatchPrintPackToken'),('CompliancePackJob'),('CustomerAuthSession'),('CustomerTrustCredential'),('CustomerTrustIntake'),('CustomerVerificationSession'),('CustomerWebAuthnChallenge'),('CustomerWebAuthnCredential'),('DegradationEvent'),('EmailVerificationToken'),('EvidenceRetentionJob'),('EvidenceRetentionPolicy'),('ForensicEventChain'),('Incident'),('IncidentCommunication'),('IncidentEvent'),('IncidentEvidence'),('IncidentEvidenceFingerprint'),('IncidentHandoff'),('InventoryStatusRollup'),('Invite'),('Licensee'),('ManufacturerLicenseeLink'),('MfaLoginChallenge'),('Notification'),('Organization'),('Ownership'),('OwnershipTransfer'),('PasswordReset'),('PolicyAlert'),('PolicyRule'),('PrintAuditEvent'),('PrintItem'),('PrintItemEvent'),('PrintJob'),('PrintJobChunk'),('PrintReissueRequest'),('PrintRenderToken'),('PrintSession'),('Printer'),('PrinterAgentSession'),('PrinterAttestation'),('PrinterProfile'),('PrinterProfileSnapshot'),('PrinterRegistration'),('QRCode'),('QRRange'),('QrAllocationRequest'),('QrScanLog'),('RefreshToken'),('ReplacementChain'),('RequestAccess'),('RouteTransitionMetric'),('ScanMetricsHourlyRollup'),('ScheduledJobCredential'),('SecurityEventOutbox'),('SecurityPolicy'),('SensitiveActionApproval'),('SupportIssueReport'),('SupportTicket'),('SupportTicketMessage'),('SystemCheckpoint'),('TenantFeatureFlag'),('TraceEvent'),('User'),('UserBackupCode'),('UserMfaFactor'),('VerificationDecision'),('VerificationEvidenceSnapshot'),('_prisma_migrations')) expected(table_name))
    UNION ALL
    (SELECT table_name FROM (VALUES ('ActionIdempotencyKey'),('AdminMfaCredential'),('AdminWebAuthnCredential'),('AllocationEvent'),('AuditLog'),('AuditLogOutbox'),('AuthMfaChallenge'),('AuthSessionRiskSignal'),('AuthWebAuthnChallenge'),('Batch'),('BatchPrintPackToken'),('CompliancePackJob'),('CustomerAuthSession'),('CustomerTrustCredential'),('CustomerTrustIntake'),('CustomerVerificationSession'),('CustomerWebAuthnChallenge'),('CustomerWebAuthnCredential'),('DegradationEvent'),('EmailVerificationToken'),('EvidenceRetentionJob'),('EvidenceRetentionPolicy'),('ForensicEventChain'),('Incident'),('IncidentCommunication'),('IncidentEvent'),('IncidentEvidence'),('IncidentEvidenceFingerprint'),('IncidentHandoff'),('InventoryStatusRollup'),('Invite'),('Licensee'),('ManufacturerLicenseeLink'),('MfaLoginChallenge'),('Notification'),('Organization'),('Ownership'),('OwnershipTransfer'),('PasswordReset'),('PolicyAlert'),('PolicyRule'),('PrintAuditEvent'),('PrintItem'),('PrintItemEvent'),('PrintJob'),('PrintJobChunk'),('PrintReissueRequest'),('PrintRenderToken'),('PrintSession'),('Printer'),('PrinterAgentSession'),('PrinterAttestation'),('PrinterProfile'),('PrinterProfileSnapshot'),('PrinterRegistration'),('QRCode'),('QRRange'),('QrAllocationRequest'),('QrScanLog'),('RefreshToken'),('ReplacementChain'),('RequestAccess'),('RouteTransitionMetric'),('ScanMetricsHourlyRollup'),('ScheduledJobCredential'),('SecurityEventOutbox'),('SecurityPolicy'),('SensitiveActionApproval'),('SupportIssueReport'),('SupportTicket'),('SupportTicketMessage'),('SystemCheckpoint'),('TenantFeatureFlag'),('TraceEvent'),('User'),('UserBackupCode'),('UserMfaFactor'),('VerificationDecision'),('VerificationEvidenceSnapshot'),('_prisma_migrations')) expected(table_name) EXCEPT SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p'))
  ) THEN RAISE EXCEPTION 'post-migration table inventory differs from the reviewed zero-based Prisma schema'; END IF;
  IF EXISTS (
    (SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e' EXCEPT SELECT type_name FROM (VALUES ('AlertSeverity'),('AuditLogOutboxStatus'),('AuthRiskLevel'),('BatchLifecycleState'),('CompliancePackJobStatus'),('CustomerTrustLevel'),('CustomerTrustReviewState'),('CustomerVerificationAuthState'),('CustomerVerificationEntryMethod'),('EvidenceRetentionJobStatus'),('ForensicEventType'),('IncidentActorType'),('IncidentCommChannel'),('IncidentCommDirection'),('IncidentCommStatus'),('IncidentContactMethod'),('IncidentEventType'),('IncidentHandoffStage'),('IncidentPriority'),('IncidentReportedBy'),('IncidentResolutionOutcome'),('IncidentSeverity'),('IncidentStatus'),('IncidentType'),('NotificationAudience'),('NotificationChannel'),('OwnershipTransferStatus'),('PolicyAlertType'),('PolicyRuleType'),('PrintDispatchMode'),('PrintItemEventType'),('PrintItemState'),('PrintJobStatus'),('PrintPayloadType'),('PrintPipelineState'),('PrintSessionStatus'),('PrinterCommandLanguage'),('PrinterConnectionType'),('PrinterDeliveryMode'),('PrinterLanguageKind'),('PrinterProfileSnapshotType'),('PrinterProfileStatus'),('PrinterTransportKind'),('PrinterTrustStatus'),('QRStatus'),('QrAllocationRequestStatus'),('ReissueRequestStatus'),('ReplacementChainStatus'),('SecurityEventDeliveryStatus'),('SupportTicketStatus'),('TraceEventType'),('UserRole'),('UserStatus'),('VerificationDecisionOutcome'),('VerificationDegradationMode'),('VerificationProofTier'),('VerificationReplacementStatus'),('VerificationRiskBand')) expected(type_name))
    UNION ALL
    (SELECT type_name FROM (VALUES ('AlertSeverity'),('AuditLogOutboxStatus'),('AuthRiskLevel'),('BatchLifecycleState'),('CompliancePackJobStatus'),('CustomerTrustLevel'),('CustomerTrustReviewState'),('CustomerVerificationAuthState'),('CustomerVerificationEntryMethod'),('EvidenceRetentionJobStatus'),('ForensicEventType'),('IncidentActorType'),('IncidentCommChannel'),('IncidentCommDirection'),('IncidentCommStatus'),('IncidentContactMethod'),('IncidentEventType'),('IncidentHandoffStage'),('IncidentPriority'),('IncidentReportedBy'),('IncidentResolutionOutcome'),('IncidentSeverity'),('IncidentStatus'),('IncidentType'),('NotificationAudience'),('NotificationChannel'),('OwnershipTransferStatus'),('PolicyAlertType'),('PolicyRuleType'),('PrintDispatchMode'),('PrintItemEventType'),('PrintItemState'),('PrintJobStatus'),('PrintPayloadType'),('PrintPipelineState'),('PrintSessionStatus'),('PrinterCommandLanguage'),('PrinterConnectionType'),('PrinterDeliveryMode'),('PrinterLanguageKind'),('PrinterProfileSnapshotType'),('PrinterProfileStatus'),('PrinterTransportKind'),('PrinterTrustStatus'),('QRStatus'),('QrAllocationRequestStatus'),('ReissueRequestStatus'),('ReplacementChainStatus'),('SecurityEventDeliveryStatus'),('SupportTicketStatus'),('TraceEventType'),('UserRole'),('UserStatus'),('VerificationDecisionOutcome'),('VerificationDegradationMode'),('VerificationProofTier'),('VerificationReplacementStatus'),('VerificationRiskBand')) expected(type_name) EXCEPT SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='public' AND t.typtype='e')
  ) THEN RAISE EXCEPTION 'post-migration enum inventory differs from the reviewed Prisma schema'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('S','v','m','f'))
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
  THEN RAISE EXCEPTION 'post-migration inventory contains an unreviewed public object class'; END IF;

  IF EXISTS (SELECT 1 FROM pg_policies) OR EXISTS (SELECT 1 FROM pg_publication) OR EXISTS (SELECT 1 FROM pg_subscription) THEN RAISE EXCEPTION 'post-migration inventory contains unreviewed security or replication state'; END IF;

  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p') AND r.rolname<>'mscqr_rls_cert_migration')
     OR EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace JOIN pg_roles r ON r.oid=t.typowner WHERE n.nspname='public' AND t.typtype='e' AND r.rolname<>'mscqr_rls_cert_migration')
  THEN RAISE EXCEPTION 'restricted migration identity does not own every zero-based Prisma object'; END IF;
END $$;
GRANT USAGE, CREATE ON SCHEMA public TO "mscqr_rls_cert_owner";
GRANT "mscqr_rls_cert_owner" TO "mscqr_rls_cert_migration" WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_migration','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_migration'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_migration";
ALTER TABLE public."ActionIdempotencyKey" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AdminMfaCredential" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AdminWebAuthnCredential" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AllocationEvent" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AuditLog" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AuditLogOutbox" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AuthMfaChallenge" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AuthSessionRiskSignal" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."AuthWebAuthnChallenge" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Batch" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."BatchPrintPackToken" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CompliancePackJob" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CustomerAuthSession" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CustomerTrustCredential" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CustomerTrustIntake" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CustomerVerificationSession" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CustomerWebAuthnChallenge" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."CustomerWebAuthnCredential" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."DegradationEvent" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."EmailVerificationToken" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."EvidenceRetentionJob" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."EvidenceRetentionPolicy" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."ForensicEventChain" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Incident" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."IncidentCommunication" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."IncidentEvent" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."IncidentEvidence" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."IncidentEvidenceFingerprint" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."IncidentHandoff" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."InventoryStatusRollup" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Invite" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Licensee" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."ManufacturerLicenseeLink" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."MfaLoginChallenge" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Notification" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Organization" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Ownership" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."OwnershipTransfer" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PasswordReset" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PolicyAlert" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PolicyRule" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintAuditEvent" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."Printer" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrinterAgentSession" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrinterAttestation" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrinterProfile" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrinterProfileSnapshot" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrinterRegistration" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintItem" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintItemEvent" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintJob" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintJobChunk" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintReissueRequest" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintRenderToken" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."PrintSession" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."QrAllocationRequest" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."QRCode" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."QRRange" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."QrScanLog" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."RefreshToken" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."ReplacementChain" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."RequestAccess" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."RouteTransitionMetric" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."ScanMetricsHourlyRollup" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."ScheduledJobCredential" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SecurityEventOutbox" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SecurityPolicy" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SensitiveActionApproval" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SupportIssueReport" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SupportTicket" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SupportTicketMessage" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."SystemCheckpoint" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."TenantFeatureFlag" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."TraceEvent" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."User" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."UserBackupCode" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."UserMfaFactor" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."VerificationDecision" OWNER TO "mscqr_rls_cert_owner";
ALTER TABLE public."VerificationEvidenceSnapshot" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."AlertSeverity" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."AuditLogOutboxStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."AuthRiskLevel" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."BatchLifecycleState" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."CompliancePackJobStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."CustomerTrustLevel" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."CustomerTrustReviewState" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."CustomerVerificationAuthState" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."CustomerVerificationEntryMethod" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."EvidenceRetentionJobStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."ForensicEventType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentActorType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentCommChannel" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentCommDirection" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentCommStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentContactMethod" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentEventType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentHandoffStage" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentPriority" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentReportedBy" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentResolutionOutcome" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentSeverity" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."IncidentType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."NotificationAudience" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."NotificationChannel" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."OwnershipTransferStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PolicyAlertType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PolicyRuleType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintDispatchMode" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintItemEventType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintItemState" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintJobStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintPayloadType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintPipelineState" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrintSessionStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterCommandLanguage" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterConnectionType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterDeliveryMode" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterLanguageKind" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterProfileSnapshotType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterProfileStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterTransportKind" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."PrinterTrustStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."QRStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."QrAllocationRequestStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."ReissueRequestStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."ReplacementChainStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."SecurityEventDeliveryStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."SupportTicketStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."TraceEventType" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."UserRole" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."UserStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."VerificationDecisionOutcome" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."VerificationDegradationMode" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."VerificationProofTier" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."VerificationReplacementStatus" OWNER TO "mscqr_rls_cert_owner";
ALTER TYPE public."VerificationRiskBand" OWNER TO "mscqr_rls_cert_owner";
RESET ROLE;
REVOKE "mscqr_rls_cert_owner" FROM "mscqr_rls_cert_migration";
ALTER SCHEMA public OWNER TO "mscqr_rls_cert_owner";
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
REVOKE ALL ON TABLE public."ActionIdempotencyKey" FROM PUBLIC;
REVOKE ALL ON TABLE public."AdminMfaCredential" FROM PUBLIC;
REVOKE ALL ON TABLE public."AdminWebAuthnCredential" FROM PUBLIC;
REVOKE ALL ON TABLE public."AllocationEvent" FROM PUBLIC;
REVOKE ALL ON TABLE public."AuditLog" FROM PUBLIC;
REVOKE ALL ON TABLE public."AuditLogOutbox" FROM PUBLIC;
REVOKE ALL ON TABLE public."AuthMfaChallenge" FROM PUBLIC;
REVOKE ALL ON TABLE public."AuthSessionRiskSignal" FROM PUBLIC;
REVOKE ALL ON TABLE public."AuthWebAuthnChallenge" FROM PUBLIC;
REVOKE ALL ON TABLE public."Batch" FROM PUBLIC;
REVOKE ALL ON TABLE public."BatchPrintPackToken" FROM PUBLIC;
REVOKE ALL ON TABLE public."CompliancePackJob" FROM PUBLIC;
REVOKE ALL ON TABLE public."CustomerAuthSession" FROM PUBLIC;
REVOKE ALL ON TABLE public."CustomerTrustCredential" FROM PUBLIC;
REVOKE ALL ON TABLE public."CustomerTrustIntake" FROM PUBLIC;
REVOKE ALL ON TABLE public."CustomerVerificationSession" FROM PUBLIC;
REVOKE ALL ON TABLE public."CustomerWebAuthnChallenge" FROM PUBLIC;
REVOKE ALL ON TABLE public."CustomerWebAuthnCredential" FROM PUBLIC;
REVOKE ALL ON TABLE public."DegradationEvent" FROM PUBLIC;
REVOKE ALL ON TABLE public."EmailVerificationToken" FROM PUBLIC;
REVOKE ALL ON TABLE public."EvidenceRetentionJob" FROM PUBLIC;
REVOKE ALL ON TABLE public."EvidenceRetentionPolicy" FROM PUBLIC;
REVOKE ALL ON TABLE public."ForensicEventChain" FROM PUBLIC;
REVOKE ALL ON TABLE public."Incident" FROM PUBLIC;
REVOKE ALL ON TABLE public."IncidentCommunication" FROM PUBLIC;
REVOKE ALL ON TABLE public."IncidentEvent" FROM PUBLIC;
REVOKE ALL ON TABLE public."IncidentEvidence" FROM PUBLIC;
REVOKE ALL ON TABLE public."IncidentEvidenceFingerprint" FROM PUBLIC;
REVOKE ALL ON TABLE public."IncidentHandoff" FROM PUBLIC;
REVOKE ALL ON TABLE public."InventoryStatusRollup" FROM PUBLIC;
REVOKE ALL ON TABLE public."Invite" FROM PUBLIC;
REVOKE ALL ON TABLE public."Licensee" FROM PUBLIC;
REVOKE ALL ON TABLE public."ManufacturerLicenseeLink" FROM PUBLIC;
REVOKE ALL ON TABLE public."MfaLoginChallenge" FROM PUBLIC;
REVOKE ALL ON TABLE public."Notification" FROM PUBLIC;
REVOKE ALL ON TABLE public."Organization" FROM PUBLIC;
REVOKE ALL ON TABLE public."Ownership" FROM PUBLIC;
REVOKE ALL ON TABLE public."OwnershipTransfer" FROM PUBLIC;
REVOKE ALL ON TABLE public."PasswordReset" FROM PUBLIC;
REVOKE ALL ON TABLE public."PolicyAlert" FROM PUBLIC;
REVOKE ALL ON TABLE public."PolicyRule" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintAuditEvent" FROM PUBLIC;
REVOKE ALL ON TABLE public."Printer" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrinterAgentSession" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrinterAttestation" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrinterProfile" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrinterProfileSnapshot" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrinterRegistration" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintItem" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintItemEvent" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintJob" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintJobChunk" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintReissueRequest" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintRenderToken" FROM PUBLIC;
REVOKE ALL ON TABLE public."PrintSession" FROM PUBLIC;
REVOKE ALL ON TABLE public."QrAllocationRequest" FROM PUBLIC;
REVOKE ALL ON TABLE public."QRCode" FROM PUBLIC;
REVOKE ALL ON TABLE public."QRRange" FROM PUBLIC;
REVOKE ALL ON TABLE public."QrScanLog" FROM PUBLIC;
REVOKE ALL ON TABLE public."RefreshToken" FROM PUBLIC;
REVOKE ALL ON TABLE public."ReplacementChain" FROM PUBLIC;
REVOKE ALL ON TABLE public."RequestAccess" FROM PUBLIC;
REVOKE ALL ON TABLE public."RouteTransitionMetric" FROM PUBLIC;
REVOKE ALL ON TABLE public."ScanMetricsHourlyRollup" FROM PUBLIC;
REVOKE ALL ON TABLE public."ScheduledJobCredential" FROM PUBLIC;
REVOKE ALL ON TABLE public."SecurityEventOutbox" FROM PUBLIC;
REVOKE ALL ON TABLE public."SecurityPolicy" FROM PUBLIC;
REVOKE ALL ON TABLE public."SensitiveActionApproval" FROM PUBLIC;
REVOKE ALL ON TABLE public."SupportIssueReport" FROM PUBLIC;
REVOKE ALL ON TABLE public."SupportTicket" FROM PUBLIC;
REVOKE ALL ON TABLE public."SupportTicketMessage" FROM PUBLIC;
REVOKE ALL ON TABLE public."SystemCheckpoint" FROM PUBLIC;
REVOKE ALL ON TABLE public."TenantFeatureFlag" FROM PUBLIC;
REVOKE ALL ON TABLE public."TraceEvent" FROM PUBLIC;
REVOKE ALL ON TABLE public."User" FROM PUBLIC;
REVOKE ALL ON TABLE public."UserBackupCode" FROM PUBLIC;
REVOKE ALL ON TABLE public."UserMfaFactor" FROM PUBLIC;
REVOKE ALL ON TABLE public."VerificationDecision" FROM PUBLIC;
REVOKE ALL ON TABLE public."VerificationEvidenceSnapshot" FROM PUBLIC;
REVOKE ALL ON TYPE public."AlertSeverity" FROM PUBLIC;
REVOKE ALL ON TYPE public."AuditLogOutboxStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."AuthRiskLevel" FROM PUBLIC;
REVOKE ALL ON TYPE public."BatchLifecycleState" FROM PUBLIC;
REVOKE ALL ON TYPE public."CompliancePackJobStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."CustomerTrustLevel" FROM PUBLIC;
REVOKE ALL ON TYPE public."CustomerTrustReviewState" FROM PUBLIC;
REVOKE ALL ON TYPE public."CustomerVerificationAuthState" FROM PUBLIC;
REVOKE ALL ON TYPE public."CustomerVerificationEntryMethod" FROM PUBLIC;
REVOKE ALL ON TYPE public."EvidenceRetentionJobStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."ForensicEventType" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentActorType" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentCommChannel" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentCommDirection" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentCommStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentContactMethod" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentEventType" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentHandoffStage" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentPriority" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentReportedBy" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentResolutionOutcome" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentSeverity" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."IncidentType" FROM PUBLIC;
REVOKE ALL ON TYPE public."NotificationAudience" FROM PUBLIC;
REVOKE ALL ON TYPE public."NotificationChannel" FROM PUBLIC;
REVOKE ALL ON TYPE public."OwnershipTransferStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."PolicyAlertType" FROM PUBLIC;
REVOKE ALL ON TYPE public."PolicyRuleType" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintDispatchMode" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintItemEventType" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintItemState" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintJobStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintPayloadType" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintPipelineState" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrintSessionStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterCommandLanguage" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterConnectionType" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterDeliveryMode" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterLanguageKind" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterProfileSnapshotType" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterProfileStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterTransportKind" FROM PUBLIC;
REVOKE ALL ON TYPE public."PrinterTrustStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."QRStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."QrAllocationRequestStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."ReissueRequestStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."ReplacementChainStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."SecurityEventDeliveryStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."SupportTicketStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."TraceEventType" FROM PUBLIC;
REVOKE ALL ON TYPE public."UserRole" FROM PUBLIC;
REVOKE ALL ON TYPE public."UserStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."VerificationDecisionOutcome" FROM PUBLIC;
REVOKE ALL ON TYPE public."VerificationDegradationMode" FROM PUBLIC;
REVOKE ALL ON TYPE public."VerificationProofTier" FROM PUBLIC;
REVOKE ALL ON TYPE public."VerificationReplacementStatus" FROM PUBLIC;
REVOKE ALL ON TYPE public."VerificationRiskBand" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM "mscqr_rls_cert_migration";
GRANT USAGE ON SCHEMA public TO "mscqr_rls_cert_migration";
GRANT USAGE ON SCHEMA public TO "mscqr_rls_cert_auth_owner";
RESET ROLE;
CREATE SCHEMA app_rls AUTHORIZATION "mscqr_rls_cert_owner";
CREATE SCHEMA app_auth AUTHORIZATION "mscqr_rls_cert_auth_owner";
CREATE SCHEMA app_public AUTHORIZATION "mscqr_rls_cert_auth_owner";
REVOKE SELECT ON TABLE mscqr_rls_install.state FROM "mscqr_rls_cert_migration";
REVOKE USAGE ON SCHEMA mscqr_rls_install FROM "mscqr_rls_cert_migration";
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_owner";
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" REVOKE ALL ON SCHEMAS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" REVOKE ALL ON LARGE OBJECTS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "public" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "public" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "public" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "public" REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "app_rls" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "app_rls" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "app_rls" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_owner" IN SCHEMA "app_rls" REVOKE ALL ON TYPES FROM PUBLIC;
RESET ROLE;
DO $$ BEGIN
  IF NOT pg_has_role(session_user,'mscqr_rls_cert_auth_owner','SET') THEN RAISE EXCEPTION 'administrative executor lacks SET authority for mscqr_rls_cert_auth_owner'; END IF;
END $$;
SET ROLE "mscqr_rls_cert_auth_owner";
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" REVOKE ALL ON SCHEMAS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" REVOKE ALL ON LARGE OBJECTS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_auth" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_auth" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_auth" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_auth" REVOKE ALL ON TYPES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_public" REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_public" REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_public" REVOKE ALL ON ROUTINES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE "mscqr_rls_cert_auth_owner" IN SCHEMA "app_public" REVOKE ALL ON TYPES FROM PUBLIC;
RESET ROLE;
UPDATE mscqr_rls_install.state SET phase='ownership-installed' WHERE singleton;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles p ON p.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE u.rolname IN ('mscqr_rls_cert_owner', 'mscqr_rls_cert_auth_owner', 'mscqr_rls_cert_app', 'mscqr_rls_cert_read', 'mscqr_rls_cert_preauth', 'mscqr_rls_cert_worker', 'mscqr_rls_cert_scheduled', 'mscqr_rls_cert_operator', 'mscqr_rls_cert_migration')) THEN RAISE EXCEPTION 'ownership package left a managed identity as a role member'; END IF;
END $$;
COMMIT;
