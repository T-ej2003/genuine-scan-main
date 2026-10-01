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

{{FORCED_RLS_CHECK}}
{{DEPENDENCY_CATALOG_CHECK}}
{{MUTATION_TRIGGER_CHECK}}

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
{{DEPENDENCY_COUNTS}}
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
{{AUDIT_ROW_COUNTS}}
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
{{AUDIT_ROW_COUNTS}}
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
GRANT EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1() TO {{VICTORIA_RECOVERY_ROLE}};

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
GRANT EXECUTE ON FUNCTION app_ops.victoria_failed_onboarding_recovery_v1_cleanup() TO {{VICTORIA_RECOVERY_ROLE}};
