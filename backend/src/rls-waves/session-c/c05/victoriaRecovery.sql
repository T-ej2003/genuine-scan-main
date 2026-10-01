-- Fixed, source-owned recovery operation. Target and database have no inputs.
CREATE SCHEMA IF NOT EXISTS app_ops;

CREATE OR REPLACE FUNCTION app_ops.victoria_failed_onboarding_recovery_v1()
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET row_security = on
AS $recovery$
DECLARE
  target_email constant text := 'victoria@mscqr.com';
  user_id text;
  user_status text;
  user_role text;
  user_is_active boolean;
  last_login_at timestamp without time zone;
  email_verified boolean;
  disabled boolean;
  deleted boolean;
  user_count integer := 0;
  invite_ids text[] := ARRAY[]::text[];
  invite_count integer := 0;
  unused_invite_count integer := 0;
  valid_unused_invite boolean := false;
  expired_unused_invite boolean := false;
  active_sessions boolean := false;
  refresh_state boolean := false;
  mfa_credential boolean := false;
  activated boolean := false;
  dependencies jsonb;
  audit_rows_before jsonb;
  audit_rows_after jsonb;
  blockers integer := 0;
  business_state_conflicts integer := 0;
  shared_state_conflicts integer := 0;
  hard_blockers integer := 0;
  unknown_dependencies integer := 0;
  audit_history_conflicts integer := 0;
  audit_log_count bigint;
  audit_outbox_count bigint;
  deleted_challenges integer := 0;
  deleted_password_resets integer := 0;
  deleted_verification_tokens integer := 0;
  deleted_invites integer := 0;
  deleted_users integer := 0;
BEGIN
  IF current_database() IS DISTINCT FROM 'mscqr_production'
     OR session_user IS DISTINCT FROM 'mscqr_prod_victoria_recovery'
     OR current_setting('transaction_isolation') IS DISTINCT FROM 'serializable'
     OR current_setting('transaction_read_only') IS DISTINCT FROM 'off' THEN
    RAISE EXCEPTION 'VICTORIA_RECOVERY_EXECUTION_CONTEXT_INVALID' USING ERRCODE='42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended('platform:' || target_email, 0));
  PERFORM set_config('app.victoria_recovery_operation', 'VICTORIA_FAILED_ONBOARDING_RECOVERY_V1', true),
          set_config('app.victoria_recovery_target_email', target_email, true);

IF (SELECT count(*) FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relname IN ('User','Invite')
         AND c.relrowsecurity AND c.relforcerowsecurity) <> 2 THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail','victoria@mscqr.com',
      'targetDatabase','mscqr_production','pruneSafe',false,'pruneComplete',false,'reason','FORCED_RLS_STATE_INVALID');
  END IF;
IF EXISTS (
       SELECT 1 FROM pg_catalog.pg_constraint c
       WHERE c.contype='f' AND c.confrelid IN ('public."User"'::regclass,'public."Invite"'::regclass)
         AND (cardinality(c.conkey)<>1 OR cardinality(c.confkey)<>1)
     ) OR EXISTS (
       WITH expected(child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable) AS (VALUES
      ('public','ManufacturerLicenseeLink','manufacturerId','public','User','id','CASCADE',false),
      ('public','Batch','manufacturerId','public','User','id','SET NULL',true),
      ('public','Batch','printPackDownloadedByUserId','public','User','id','SET NULL',true),
      ('public','PrintJob','manufacturerId','public','User','id','RESTRICT',false),
      ('public','PrintJob','approvedByUserId','public','User','id','SET NULL',true),
      ('public','QRCode','printedByUserId','public','User','id','SET NULL',true),
      ('public','PrintSession','manufacturerId','public','User','id','CASCADE',false),
      ('public','PrintItemEvent','actorUserId','public','User','id','SET NULL',true),
      ('public','PrinterRegistration','userId','public','User','id','CASCADE',false),
      ('public','Printer','assignedUserId','public','User','id','SET NULL',true),
      ('public','Printer','createdByUserId','public','User','id','SET NULL',true),
      ('public','PrintReissueRequest','requestedByUserId','public','User','id','CASCADE',false),
      ('public','PrintReissueRequest','approvedByUserId','public','User','id','SET NULL',true),
      ('public','BatchPrintPackToken','createdByUserId','public','User','id','RESTRICT',false),
      ('public','Invite','createdByUserId','public','User','id','SET NULL',true),
      ('public','Invite','acceptedByUserId','public','User','id','SET NULL',true),
      ('public','InviteActivationChallenge','userId','public','User','id','CASCADE',false),
      ('public','PasswordReset','userId','public','User','id','CASCADE',false),
      ('public','EmailVerificationToken','userId','public','User','id','CASCADE',false),
      ('public','RefreshToken','userId','public','User','id','CASCADE',false),
      ('public','AdminMfaCredential','userId','public','User','id','CASCADE',false),
      ('public','AdminWebAuthnCredential','userId','public','User','id','CASCADE',false),
      ('public','UserMfaFactor','userId','public','User','id','CASCADE',false),
      ('public','UserBackupCode','userId','public','User','id','CASCADE',false),
      ('public','MfaLoginChallenge','userId','public','User','id','CASCADE',false),
      ('public','AuthMfaChallenge','userId','public','User','id','CASCADE',false),
      ('public','AuthWebAuthnChallenge','userId','public','User','id','CASCADE',false),
      ('public','AuthSessionRiskSignal','userId','public','User','id','CASCADE',false),
      ('public','SensitiveActionApproval','requestedByUserId','public','User','id','CASCADE',false),
      ('public','SensitiveActionApproval','reviewedByUserId','public','User','id','SET NULL',true),
      ('public','SensitiveActionApproval','executedByUserId','public','User','id','SET NULL',true),
      ('public','CompliancePackJob','startedByUserId','public','User','id','SET NULL',true),
      ('public','QrAllocationRequest','requestedByUserId','public','User','id','RESTRICT',false),
      ('public','QrAllocationRequest','approvedByUserId','public','User','id','SET NULL',true),
      ('public','QrAllocationRequest','rejectedByUserId','public','User','id','SET NULL',true),
      ('public','AllocationEvent','createdByUserId','public','User','id','SET NULL',true),
      ('public','TraceEvent','manufacturerId','public','User','id','SET NULL',true),
      ('public','TraceEvent','userId','public','User','id','SET NULL',true),
      ('public','PolicyRule','createdByUserId','public','User','id','SET NULL',true),
      ('public','PolicyAlert','manufacturerId','public','User','id','SET NULL',true),
      ('public','PolicyAlert','acknowledgedByUserId','public','User','id','SET NULL',true),
      ('public','Incident','assignedToUserId','public','User','id','SET NULL',true),
      ('public','IncidentEvent','actorUserId','public','User','id','SET NULL',true),
      ('public','IncidentEvidence','uploadedByUserId','public','User','id','SET NULL',true),
      ('public','SupportTicket','assignedToUserId','public','User','id','SET NULL',true),
      ('public','SupportTicketMessage','actorUserId','public','User','id','SET NULL',true),
      ('public','RequestAccess','assignedToUserId','public','User','id','SET NULL',true),
      ('public','RequestAccess','reviewedByUserId','public','User','id','SET NULL',true),
      ('public','SupportIssueReport','reporterUserId','public','User','id','SET NULL',true),
      ('public','SupportIssueReport','respondedByUserId','public','User','id','SET NULL',true),
      ('public','Notification','userId','public','User','id','SET NULL',true),
      ('public','TenantFeatureFlag','updatedByUserId','public','User','id','SET NULL',true),
      ('public','EvidenceRetentionPolicy','updatedByUserId','public','User','id','SET NULL',true),
      ('public','EvidenceRetentionJob','startedByUserId','public','User','id','SET NULL',true),
      ('public','RouteTransitionMetric','userId','public','User','id','SET NULL',true),
      ('public','InviteActivationChallenge','inviteId','public','Invite','id','CASCADE',false)
       ), actual AS (
         SELECT child_ns.nspname,child.relname,child_attr.attname,parent_ns.nspname,parent.relname,parent_attr.attname,
           CASE c.confdeltype WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL'
             WHEN 'r' THEN 'RESTRICT' WHEN 'a' THEN 'NO ACTION' ELSE 'UNKNOWN' END,
           NOT child_attr.attnotnull
         FROM pg_catalog.pg_constraint c
         JOIN pg_catalog.pg_class child ON child.oid=c.conrelid
         JOIN pg_catalog.pg_namespace child_ns ON child_ns.oid=child.relnamespace
         JOIN pg_catalog.pg_class parent ON parent.oid=c.confrelid
         JOIN pg_catalog.pg_namespace parent_ns ON parent_ns.oid=parent.relnamespace
         JOIN pg_catalog.pg_attribute child_attr ON child_attr.attrelid=child.oid AND child_attr.attnum=c.conkey[1]
         JOIN pg_catalog.pg_attribute parent_attr ON parent_attr.attrelid=parent.oid AND parent_attr.attnum=c.confkey[1]
         WHERE c.contype='f' AND c.confrelid IN ('public."User"'::regclass,'public."Invite"'::regclass)
           AND cardinality(c.conkey)=1 AND cardinality(c.confkey)=1
       ), differences AS (
         (SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM expected
          EXCEPT ALL
          SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM actual)
         UNION ALL
         (SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM actual
          EXCEPT ALL
          SELECT child_schema,child_table,child_column,parent_schema,parent_table,parent_column,delete_action,is_nullable FROM expected)
       )
       SELECT 1 FROM differences
     ) THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail','victoria@mscqr.com',
      'targetDatabase','mscqr_production','pruneSafe',false,'pruneComplete',false,'reason','SCHEMA_DEPENDENCY_DRIFT',
      'unknownDependencies',1,'dependencies',jsonb_build_array());
  END IF;
IF EXISTS (
       SELECT 1 FROM pg_catalog.pg_trigger t
       JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
       JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE NOT t.tgisinternal AND n.nspname='public'
         AND c.relname IN ('User','Invite','InviteActivationChallenge','PasswordReset','EmailVerificationToken')
     ) THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail','victoria@mscqr.com',
      'targetDatabase','mscqr_production','pruneSafe',false,'pruneComplete',false,'reason','SCHEMA_TRIGGER_DRIFT');
  END IF;

  SELECT count(*)::integer INTO user_count FROM public."User" u WHERE lower(btrim(u.email))=target_email;
  IF user_count > 1 THEN RAISE EXCEPTION 'VICTORIA_RECOVERY_DUPLICATE_USERS' USING ERRCODE='40001'; END IF;
  IF user_count = 1 THEN
    SELECT u.id,u.status::text,u.role::text,u."isActive",u."lastLoginAt",u."emailVerifiedAt" IS NOT NULL,
           u."disabledAt" IS NOT NULL,u."deletedAt" IS NOT NULL
      INTO user_id,user_status,user_role,user_is_active,last_login_at,email_verified,disabled,deleted
      FROM public."User" u WHERE lower(btrim(u.email))=target_email FOR UPDATE;
  END IF;
  PERFORM set_config('app.victoria_recovery_user_id', coalesce(user_id,''), true);

  PERFORM 1 FROM public."Invite" i WHERE lower(btrim(i.email))=target_email ORDER BY i.id FOR UPDATE;

  SELECT COALESCE(array_agg(i.id ORDER BY i.id),ARRAY[]::text[]),count(*)::integer,
         count(*) FILTER (WHERE i."usedAt" IS NULL)::integer,
         COALESCE(bool_or(i."usedAt" IS NULL AND i."expiresAt">transaction_timestamp()),false),
         COALESCE(bool_or(i."usedAt" IS NULL AND i."expiresAt"<=transaction_timestamp()),false)
    INTO invite_ids,invite_count,unused_invite_count,valid_unused_invite,expired_unused_invite
    FROM public."Invite" i WHERE lower(btrim(i.email))=target_email;
  PERFORM set_config('app.victoria_recovery_invite_ids', array_to_string(invite_ids,','), true);
  -- The shared invite advisory lock plus exact User/Invite row locks keep inspection and prune coherent.

  SELECT EXISTS (SELECT 1 FROM public."RefreshToken" r WHERE r."userId"=user_id
    AND r."revokedAt" IS NULL AND (r."expiresAt">transaction_timestamp()
      OR (r."sessionCapabilityRevokedAt" IS NULL AND r."sessionCapabilityExpiresAt">transaction_timestamp())))
    INTO active_sessions;
  SELECT EXISTS (SELECT 1 FROM public."RefreshToken" r WHERE r."userId"=user_id) INTO refresh_state;
  SELECT EXISTS (
      SELECT 1 FROM public."AdminMfaCredential" c WHERE c."userId"=user_id
      UNION ALL SELECT 1 FROM public."AdminWebAuthnCredential" c WHERE c."userId"=user_id
      UNION ALL SELECT 1 FROM public."UserMfaFactor" c WHERE c."userId"=user_id
      UNION ALL SELECT 1 FROM public."UserBackupCode" c WHERE c."userId"=user_id
    ) INTO mfa_credential;
  SELECT EXISTS (
      SELECT 1 FROM public."AuditLog" a WHERE a."userId"=user_id
        OR (a.action IN ('AUTH_INVITE_ACTIVATED','AUTH_EMAIL_VERIFIED','AUTH_LOGIN_SUCCESS','AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA')
          AND (a."entityId"=ANY(invite_ids) OR a."entityId"=user_id OR a.details->>'targetUserId'=user_id
            OR lower(coalesce(a.details->>'email',''))=target_email))
      UNION ALL
      SELECT 1 FROM public."AuditLogOutbox" a WHERE a."initiatingUserId"=user_id
        OR (a.payload->>'action' IN ('AUTH_INVITE_ACTIVATED','AUTH_EMAIL_VERIFIED','AUTH_LOGIN_SUCCESS','AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA')
          AND (a.payload->>'entityId'=ANY(invite_ids) OR a.payload->>'userId'=user_id
               OR a.payload->'details'->>'targetUserId'=user_id
               OR lower(coalesce(a.payload->'details'->>'email',''))=target_email))
    ) INTO activated;
  activated := activated OR last_login_at IS NOT NULL;

  -- Static SQL is generated from the reviewed dependency manifest. Runtime SQL is never constructed.
  SELECT jsonb_agg(jsonb_build_object('table',d.table_name,'column',d.column_name,
      'classification',d.classification,'count',d.row_count,'removable',d.removable) ORDER BY d.table_name,d.column_name)
    INTO dependencies
    FROM (
      SELECT 'ManufacturerLicenseeLink'::text AS table_name, 'manufacturerId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."ManufacturerLicenseeLink" d WHERE d."manufacturerId"=user_id
      UNION ALL
      SELECT 'Batch'::text AS table_name, 'manufacturerId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Batch" d WHERE d."manufacturerId"=user_id
      UNION ALL
      SELECT 'Batch'::text AS table_name, 'printPackDownloadedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Batch" d WHERE d."printPackDownloadedByUserId"=user_id
      UNION ALL
      SELECT 'PrintJob'::text AS table_name, 'manufacturerId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrintJob" d WHERE d."manufacturerId"=user_id
      UNION ALL
      SELECT 'PrintJob'::text AS table_name, 'approvedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrintJob" d WHERE d."approvedByUserId"=user_id
      UNION ALL
      SELECT 'QRCode'::text AS table_name, 'printedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."QRCode" d WHERE d."printedByUserId"=user_id
      UNION ALL
      SELECT 'PrintSession'::text AS table_name, 'manufacturerId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrintSession" d WHERE d."manufacturerId"=user_id
      UNION ALL
      SELECT 'PrintItemEvent'::text AS table_name, 'actorUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrintItemEvent" d WHERE d."actorUserId"=user_id
      UNION ALL
      SELECT 'PrinterRegistration'::text AS table_name, 'userId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrinterRegistration" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'Printer'::text AS table_name, 'assignedUserId'::text AS column_name, 'SHARED_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Printer" d WHERE d."assignedUserId"=user_id
      UNION ALL
      SELECT 'Printer'::text AS table_name, 'createdByUserId'::text AS column_name, 'SHARED_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Printer" d WHERE d."createdByUserId"=user_id
      UNION ALL
      SELECT 'PrintReissueRequest'::text AS table_name, 'requestedByUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrintReissueRequest" d WHERE d."requestedByUserId"=user_id
      UNION ALL
      SELECT 'PrintReissueRequest'::text AS table_name, 'approvedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PrintReissueRequest" d WHERE d."approvedByUserId"=user_id
      UNION ALL
      SELECT 'BatchPrintPackToken'::text AS table_name, 'createdByUserId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."BatchPrintPackToken" d WHERE d."createdByUserId"=user_id
      UNION ALL
      SELECT 'Invite'::text AS table_name, 'createdByUserId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Invite" d WHERE d."createdByUserId"=user_id AND NOT (d.id=ANY(invite_ids))
      UNION ALL
      SELECT 'Invite'::text AS table_name, 'acceptedByUserId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Invite" d WHERE d."acceptedByUserId"=user_id AND NOT (d.id=ANY(invite_ids))
      UNION ALL
      SELECT 'InviteActivationChallenge'::text AS table_name, 'userId'::text AS column_name, 'EPHEMERAL_ONBOARDING'::text AS classification, count(*)::integer AS row_count, true::boolean AS removable FROM public."InviteActivationChallenge" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'PasswordReset'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, COALESCE(bool_and(d."usedAt" IS NULL AND d."expiresAt"<=transaction_timestamp()),false)::boolean AS removable FROM public."PasswordReset" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'EmailVerificationToken'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, COALESCE(bool_and(d."usedAt" IS NULL AND d."expiresAt"<=transaction_timestamp()),false)::boolean AS removable FROM public."EmailVerificationToken" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'RefreshToken'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."RefreshToken" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'AdminMfaCredential'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."AdminMfaCredential" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'AdminWebAuthnCredential'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."AdminWebAuthnCredential" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'UserMfaFactor'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."UserMfaFactor" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'UserBackupCode'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."UserBackupCode" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'MfaLoginChallenge'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."MfaLoginChallenge" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'AuthMfaChallenge'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."AuthMfaChallenge" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'AuthWebAuthnChallenge'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."AuthWebAuthnChallenge" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'AuthSessionRiskSignal'::text AS table_name, 'userId'::text AS column_name, 'AUTHENTICATION_SECURITY'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."AuthSessionRiskSignal" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'SensitiveActionApproval'::text AS table_name, 'requestedByUserId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SensitiveActionApproval" d WHERE d."requestedByUserId"=user_id
      UNION ALL
      SELECT 'SensitiveActionApproval'::text AS table_name, 'reviewedByUserId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SensitiveActionApproval" d WHERE d."reviewedByUserId"=user_id
      UNION ALL
      SELECT 'SensitiveActionApproval'::text AS table_name, 'executedByUserId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SensitiveActionApproval" d WHERE d."executedByUserId"=user_id
      UNION ALL
      SELECT 'CompliancePackJob'::text AS table_name, 'startedByUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."CompliancePackJob" d WHERE d."startedByUserId"=user_id
      UNION ALL
      SELECT 'QrAllocationRequest'::text AS table_name, 'requestedByUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."QrAllocationRequest" d WHERE d."requestedByUserId"=user_id
      UNION ALL
      SELECT 'QrAllocationRequest'::text AS table_name, 'approvedByUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."QrAllocationRequest" d WHERE d."approvedByUserId"=user_id
      UNION ALL
      SELECT 'QrAllocationRequest'::text AS table_name, 'rejectedByUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."QrAllocationRequest" d WHERE d."rejectedByUserId"=user_id
      UNION ALL
      SELECT 'AllocationEvent'::text AS table_name, 'createdByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."AllocationEvent" d WHERE d."createdByUserId"=user_id
      UNION ALL
      SELECT 'TraceEvent'::text AS table_name, 'manufacturerId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."TraceEvent" d WHERE d."manufacturerId"=user_id
      UNION ALL
      SELECT 'TraceEvent'::text AS table_name, 'userId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."TraceEvent" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'PolicyRule'::text AS table_name, 'createdByUserId'::text AS column_name, 'SHARED_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PolicyRule" d WHERE d."createdByUserId"=user_id
      UNION ALL
      SELECT 'PolicyAlert'::text AS table_name, 'manufacturerId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PolicyAlert" d WHERE d."manufacturerId"=user_id
      UNION ALL
      SELECT 'PolicyAlert'::text AS table_name, 'acknowledgedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."PolicyAlert" d WHERE d."acknowledgedByUserId"=user_id
      UNION ALL
      SELECT 'Incident'::text AS table_name, 'assignedToUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Incident" d WHERE d."assignedToUserId"=user_id
      UNION ALL
      SELECT 'IncidentEvent'::text AS table_name, 'actorUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."IncidentEvent" d WHERE d."actorUserId"=user_id
      UNION ALL
      SELECT 'IncidentEvidence'::text AS table_name, 'uploadedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."IncidentEvidence" d WHERE d."uploadedByUserId"=user_id
      UNION ALL
      SELECT 'SupportTicket'::text AS table_name, 'assignedToUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SupportTicket" d WHERE d."assignedToUserId"=user_id
      UNION ALL
      SELECT 'SupportTicketMessage'::text AS table_name, 'actorUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SupportTicketMessage" d WHERE d."actorUserId"=user_id
      UNION ALL
      SELECT 'RequestAccess'::text AS table_name, 'assignedToUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."RequestAccess" d WHERE d."assignedToUserId"=user_id
      UNION ALL
      SELECT 'RequestAccess'::text AS table_name, 'reviewedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."RequestAccess" d WHERE d."reviewedByUserId"=user_id
      UNION ALL
      SELECT 'SupportIssueReport'::text AS table_name, 'reporterUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SupportIssueReport" d WHERE d."reporterUserId"=user_id
      UNION ALL
      SELECT 'SupportIssueReport'::text AS table_name, 'respondedByUserId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."SupportIssueReport" d WHERE d."respondedByUserId"=user_id
      UNION ALL
      SELECT 'Notification'::text AS table_name, 'userId'::text AS column_name, 'HARD_BLOCKER'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."Notification" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'TenantFeatureFlag'::text AS table_name, 'updatedByUserId'::text AS column_name, 'SHARED_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."TenantFeatureFlag" d WHERE d."updatedByUserId"=user_id
      UNION ALL
      SELECT 'EvidenceRetentionPolicy'::text AS table_name, 'updatedByUserId'::text AS column_name, 'SHARED_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."EvidenceRetentionPolicy" d WHERE d."updatedByUserId"=user_id
      UNION ALL
      SELECT 'EvidenceRetentionJob'::text AS table_name, 'startedByUserId'::text AS column_name, 'BUSINESS_STATE'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."EvidenceRetentionJob" d WHERE d."startedByUserId"=user_id
      UNION ALL
      SELECT 'RouteTransitionMetric'::text AS table_name, 'userId'::text AS column_name, 'IMMUTABLE_AUDIT'::text AS classification, count(*)::integer AS row_count, false::boolean AS removable FROM public."RouteTransitionMetric" d WHERE d."userId"=user_id
      UNION ALL
      SELECT 'InviteActivationChallenge'::text AS table_name, 'inviteId'::text AS column_name, 'EPHEMERAL_ONBOARDING'::text AS classification, count(*)::integer AS row_count, true::boolean AS removable FROM public."InviteActivationChallenge" d WHERE d."inviteId"=ANY(invite_ids)
    ) AS d;

  SELECT count(*)::integer INTO blockers
    FROM jsonb_array_elements(dependencies) AS dependency(value)
   WHERE (dependency.value->>'classification') IN ('BUSINESS_STATE','SHARED_STATE','HARD_BLOCKER','UNKNOWN','IMMUTABLE_AUDIT')
     AND (dependency.value->>'count')::integer>0;
  SELECT blockers + count(*)::integer INTO blockers FROM jsonb_array_elements(dependencies) AS dependency(value)
   WHERE dependency.value->>'classification'='AUTHENTICATION_SECURITY' AND (dependency.value->>'count')::integer>0
     AND dependency.value->>'removable' IS DISTINCT FROM 'true';
  SELECT count(*)::integer INTO hard_blockers FROM jsonb_array_elements(dependencies) AS dependency(value)
   WHERE dependency.value->>'classification'='HARD_BLOCKER' AND (dependency.value->>'count')::integer>0;
  SELECT count(*)::integer INTO unknown_dependencies FROM jsonb_array_elements(dependencies) AS dependency(value)
   WHERE dependency.value->>'classification'='UNKNOWN';
  SELECT COALESCE(sum((dependency.value->>'count')::integer),0)::integer INTO audit_history_conflicts
    FROM jsonb_array_elements(dependencies) AS dependency(value)
   WHERE dependency.value->>'classification'='IMMUTABLE_AUDIT';
  SELECT COALESCE(sum((dependency.value->>'count')::integer) FILTER (WHERE dependency.value->>'classification'='BUSINESS_STATE'),0)::integer,
         COALESCE(sum((dependency.value->>'count')::integer) FILTER (WHERE dependency.value->>'classification'='SHARED_STATE'),0)::integer
    INTO business_state_conflicts,shared_state_conflicts
    FROM jsonb_array_elements(dependencies) AS dependency(value);

  SELECT count(*)::bigint INTO audit_log_count FROM public."AuditLog";
  SELECT count(*)::bigint INTO audit_outbox_count FROM public."AuditLogOutbox";
  SELECT jsonb_object_agg(a.table_name,a.row_count) INTO audit_rows_before FROM (
    SELECT 'AllocationEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."AllocationEvent"
    UNION ALL
    SELECT 'AuditLog'::text AS table_name,count(*)::bigint AS row_count FROM public."AuditLog"
    UNION ALL
    SELECT 'AuditLogOutbox'::text AS table_name,count(*)::bigint AS row_count FROM public."AuditLogOutbox"
    UNION ALL
    SELECT 'Batch'::text AS table_name,count(*)::bigint AS row_count FROM public."Batch"
    UNION ALL
    SELECT 'IncidentEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."IncidentEvent"
    UNION ALL
    SELECT 'IncidentEvidence'::text AS table_name,count(*)::bigint AS row_count FROM public."IncidentEvidence"
    UNION ALL
    SELECT 'PolicyAlert'::text AS table_name,count(*)::bigint AS row_count FROM public."PolicyAlert"
    UNION ALL
    SELECT 'PrintItemEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."PrintItemEvent"
    UNION ALL
    SELECT 'PrintJob'::text AS table_name,count(*)::bigint AS row_count FROM public."PrintJob"
    UNION ALL
    SELECT 'PrintReissueRequest'::text AS table_name,count(*)::bigint AS row_count FROM public."PrintReissueRequest"
    UNION ALL
    SELECT 'QRCode'::text AS table_name,count(*)::bigint AS row_count FROM public."QRCode"
    UNION ALL
    SELECT 'RequestAccess'::text AS table_name,count(*)::bigint AS row_count FROM public."RequestAccess"
    UNION ALL
    SELECT 'RouteTransitionMetric'::text AS table_name,count(*)::bigint AS row_count FROM public."RouteTransitionMetric"
    UNION ALL
    SELECT 'SupportIssueReport'::text AS table_name,count(*)::bigint AS row_count FROM public."SupportIssueReport"
    UNION ALL
    SELECT 'SupportTicketMessage'::text AS table_name,count(*)::bigint AS row_count FROM public."SupportTicketMessage"
    UNION ALL
    SELECT 'TraceEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."TraceEvent"
  ) AS a;

  IF user_count=0 AND invite_count=0 THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail',target_email,
      'targetDatabase','mscqr_production','userExists',false,'activeAccountExists',false,'emailVerified',false,
      'inviteCount',0,'validUnusedInvite',false,'successfulActivationNotFound',NOT activated,
      'pruneSafe',NOT activated,'pruneComplete',NOT activated,
      'reason',CASE WHEN activated THEN 'ACTIVATION_EVIDENCE_PRESENT' ELSE 'FAILED_ONBOARDING_ALREADY_CLEAN' END,
      'otherUsersChanged',0,'otherInvitesChanged',0,'auditHistoryDeleted',0,'auditHistoryPreserved',true,
      'dependencies',dependencies);
  END IF;

  IF (user_count=1 AND (user_status<>'INVITED' OR user_role<>'SUPER_ADMIN' OR user_is_active IS DISTINCT FROM true
       OR email_verified OR disabled OR deleted))
     OR active_sessions OR refresh_state OR activated OR mfa_credential OR blockers>0 OR hard_blockers>0 OR unknown_dependencies>0
     OR (SELECT count(*) FROM public."Invite" i WHERE i.id=ANY(invite_ids) AND i.role<>'SUPER_ADMIN')>0
     OR EXISTS (SELECT 1 FROM public."Invite" i WHERE i.id=ANY(invite_ids)
          AND ((i."usedAt" IS NULL AND i."acceptedByUserId" IS NOT NULL)
            OR (i."usedAt" IS NOT NULL AND (user_id IS NULL OR i."acceptedByUserId" IS DISTINCT FROM user_id))))
     OR (SELECT count(*) FROM public."InviteActivationChallenge" c WHERE
          (c."inviteId"=ANY(invite_ids) OR (user_id IS NOT NULL AND c."userId"=user_id))
          AND NOT (c."inviteId"=ANY(invite_ids) AND user_id IS NOT NULL AND c."userId"=user_id))>0
     OR EXISTS (SELECT 1 FROM public."PasswordReset" p WHERE p."userId"=user_id
          AND (p."usedAt" IS NOT NULL OR p."expiresAt">transaction_timestamp()))
     OR EXISTS (SELECT 1 FROM public."EmailVerificationToken" t WHERE t."userId"=user_id
          AND (t."usedAt" IS NOT NULL OR t."expiresAt">transaction_timestamp())) THEN
    REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
    RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail',target_email,
      'targetDatabase','mscqr_production','userExists',user_count=1,'userId',user_id,'userStatus',user_status,
      'userRole',user_role,'userIsActive',user_is_active,'emailVerified',COALESCE(email_verified,false),
      'inviteCount',invite_count,'unusedInviteCount',unused_invite_count,'validUnusedInvite',valid_unused_invite,
      'expiredUnusedInvite',expired_unused_invite,'activeSessionsExist',active_sessions,'refreshStateExists',refresh_state,
      'mfaCredentialExists',mfa_credential,'successfulActivationNotFound',NOT activated,
      'businessStateConflicts',business_state_conflicts,'sharedStateConflicts',shared_state_conflicts,
      'hardBlockers',hard_blockers,'unknownDependencies',unknown_dependencies,
      'auditHistoryConflicts',audit_history_conflicts,'auditHistoryCanBePreserved',true,'pruneSafe',false,
      'pruneComplete',false,'reason',CASE
        WHEN user_count=1 AND (user_status<>'INVITED' OR user_role<>'SUPER_ADMIN' OR user_is_active IS DISTINCT FROM true OR disabled OR deleted) THEN 'USER_NOT_UNFINISHED_INVITATION'
        WHEN email_verified THEN 'EMAIL_VERIFIED'
        WHEN active_sessions THEN 'ACTIVE_SESSION_PRESENT'
        WHEN refresh_state THEN 'REFRESH_STATE_PRESENT'
        WHEN activated THEN 'ACTIVATION_EVIDENCE_PRESENT'
        WHEN mfa_credential THEN 'MFA_CREDENTIAL_PRESENT'
        WHEN business_state_conflicts>0 THEN 'BUSINESS_STATE_PRESENT'
        WHEN shared_state_conflicts>0 THEN 'SHARED_STATE_PRESENT'
        WHEN hard_blockers>0 THEN 'HARD_BLOCKER_PRESENT'
        WHEN unknown_dependencies>0 THEN 'UNKNOWN_DEPENDENCY_PRESENT'
        WHEN audit_history_conflicts>0 THEN 'IMMUTABLE_AUDIT_HISTORY_PRESENT'
        WHEN blockers>0 THEN 'AUTHENTICATION_SECURITY_STATE_PRESENT'
        ELSE 'INVITE_STATE_CONFLICT' END,'dependencies',dependencies);
  END IF;

  DELETE FROM public."InviteActivationChallenge" c
   WHERE user_id IS NOT NULL AND c."inviteId"=ANY(invite_ids) AND c."userId"=user_id;
  GET DIAGNOSTICS deleted_challenges=ROW_COUNT;
  DELETE FROM public."PasswordReset" p WHERE p."userId"=user_id;
  GET DIAGNOSTICS deleted_password_resets=ROW_COUNT;
  DELETE FROM public."EmailVerificationToken" t WHERE t."userId"=user_id;
  GET DIAGNOSTICS deleted_verification_tokens=ROW_COUNT;
  DELETE FROM public."Invite" i WHERE i.id=ANY(invite_ids);
  GET DIAGNOSTICS deleted_invites=ROW_COUNT;
  IF user_id IS NOT NULL THEN
    DELETE FROM public."User" u WHERE u.id=user_id AND lower(btrim(u.email))=target_email
      AND u.status='INVITED'::public."UserStatus" AND u.role='SUPER_ADMIN'::public."UserRole"
      AND u."isActive" AND u."emailVerifiedAt" IS NULL AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
    GET DIAGNOSTICS deleted_users=ROW_COUNT;
    IF deleted_users<>1 THEN RAISE EXCEPTION 'VICTORIA_RECOVERY_USER_COMPARE_AND_SET_FAILED' USING ERRCODE='40001'; END IF;
  END IF;

  IF EXISTS (SELECT 1 FROM public."User" u WHERE lower(btrim(u.email))=target_email)
     OR EXISTS (SELECT 1 FROM public."Invite" i WHERE lower(btrim(i.email))=target_email)
     OR EXISTS (SELECT 1 FROM public."InviteActivationChallenge" c WHERE c."inviteId"=ANY(invite_ids)
       OR (user_id IS NOT NULL AND c."userId"=user_id))
     OR EXISTS (SELECT 1 FROM public."PasswordReset" p WHERE p."userId"=user_id)
     OR EXISTS (SELECT 1 FROM public."EmailVerificationToken" t WHERE t."userId"=user_id)
     OR EXISTS (SELECT 1 FROM public."RefreshToken" r WHERE r."userId"=user_id)
     OR (SELECT count(*) FROM public."AuditLog")<>audit_log_count
     OR (SELECT count(*) FROM public."AuditLogOutbox")<>audit_outbox_count THEN
    RAISE EXCEPTION 'VICTORIA_RECOVERY_POSTCONDITION_FAILED' USING ERRCODE='40001';
  END IF;
  SELECT jsonb_object_agg(a.table_name,a.row_count) INTO audit_rows_after FROM (
    SELECT 'AllocationEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."AllocationEvent"
    UNION ALL
    SELECT 'AuditLog'::text AS table_name,count(*)::bigint AS row_count FROM public."AuditLog"
    UNION ALL
    SELECT 'AuditLogOutbox'::text AS table_name,count(*)::bigint AS row_count FROM public."AuditLogOutbox"
    UNION ALL
    SELECT 'Batch'::text AS table_name,count(*)::bigint AS row_count FROM public."Batch"
    UNION ALL
    SELECT 'IncidentEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."IncidentEvent"
    UNION ALL
    SELECT 'IncidentEvidence'::text AS table_name,count(*)::bigint AS row_count FROM public."IncidentEvidence"
    UNION ALL
    SELECT 'PolicyAlert'::text AS table_name,count(*)::bigint AS row_count FROM public."PolicyAlert"
    UNION ALL
    SELECT 'PrintItemEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."PrintItemEvent"
    UNION ALL
    SELECT 'PrintJob'::text AS table_name,count(*)::bigint AS row_count FROM public."PrintJob"
    UNION ALL
    SELECT 'PrintReissueRequest'::text AS table_name,count(*)::bigint AS row_count FROM public."PrintReissueRequest"
    UNION ALL
    SELECT 'QRCode'::text AS table_name,count(*)::bigint AS row_count FROM public."QRCode"
    UNION ALL
    SELECT 'RequestAccess'::text AS table_name,count(*)::bigint AS row_count FROM public."RequestAccess"
    UNION ALL
    SELECT 'RouteTransitionMetric'::text AS table_name,count(*)::bigint AS row_count FROM public."RouteTransitionMetric"
    UNION ALL
    SELECT 'SupportIssueReport'::text AS table_name,count(*)::bigint AS row_count FROM public."SupportIssueReport"
    UNION ALL
    SELECT 'SupportTicketMessage'::text AS table_name,count(*)::bigint AS row_count FROM public."SupportTicketMessage"
    UNION ALL
    SELECT 'TraceEvent'::text AS table_name,count(*)::bigint AS row_count FROM public."TraceEvent"
  ) AS a;
  IF audit_rows_after IS DISTINCT FROM audit_rows_before THEN
    RAISE EXCEPTION 'VICTORIA_RECOVERY_AUDIT_PRESERVATION_FAILED' USING ERRCODE='40001';
  END IF;
  REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
  RETURN jsonb_build_object('operation','VICTORIA_FAILED_ONBOARDING_RECOVERY_V1','targetEmail',target_email,
    'targetDatabase','mscqr_production','userExists',false,'activeAccountExists',false,'emailVerified',false,
    'userExistsBefore',user_count=1,'userIdBefore',user_id,'userStatusBefore',user_status,
    'userIsActiveBefore',user_is_active,'emailVerifiedBefore',COALESCE(email_verified,false),
    'inviteCountBefore',invite_count,'unusedInviteCountBefore',unused_invite_count,
    'validUnusedInviteBefore',valid_unused_invite,'expiredUnusedInviteBefore',expired_unused_invite,
    'activeSessionsExistBefore',active_sessions,'refreshStateExistsBefore',refresh_state,
    'mfaCredentialExistsBefore',mfa_credential,'successfulActivationNotFound',true,
    'validUnusedInvite',false,'pruneSafe',true,'pruneComplete',true,'reason','FAILED_ONBOARDING_PRUNED',
    'deletedRows',jsonb_build_object('InviteActivationChallenge',deleted_challenges,'PasswordReset',deleted_password_resets,
      'EmailVerificationToken',deleted_verification_tokens,'Invite',deleted_invites,'User',deleted_users),
    'otherUsersChanged',0,'otherInvitesChanged',0,'auditHistoryDeleted',0,'auditHistoryPreserved',true,'dependencies',dependencies);
END
$recovery$;

ALTER FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() OWNER TO {{AUTH_OWNER}};
REVOKE ALL ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() TO "mscqr_prod_victoria_recovery";

CREATE OR REPLACE FUNCTION app_ops.victoria_failed_onboarding_recovery_v1_cleanup()
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $cleanup$
BEGIN
  IF current_database() IS DISTINCT FROM 'mscqr_production'
     OR session_user IS DISTINCT FROM 'mscqr_prod_victoria_recovery' THEN
    RAISE EXCEPTION 'VICTORIA_RECOVERY_CLEANUP_CONTEXT_INVALID' USING ERRCODE='42501';
  END IF;
  REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() FROM "mscqr_prod_victoria_recovery";
  REVOKE EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1_cleanup() FROM "mscqr_prod_victoria_recovery";
  RETURN true;
END
$cleanup$;

ALTER FUNCTION app_ops.victoria_failed_onboarding_recovery_v1_cleanup() OWNER TO {{AUTH_OWNER}};
REVOKE ALL ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1_cleanup() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1_cleanup() TO "mscqr_prod_victoria_recovery";
