-- Canonical GREEN C04 account-onboarding diagnostic boundary.  The package
-- generator creates the owner-only app_ops schema and replaces only the exact
-- operator role and target environment.

CREATE OR REPLACE FUNCTION app_ops.session_c04_assert_diagnostic_context()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  login_role text := session_user;
  environment text := current_setting('app.operator_environment', true);
BEGIN
  IF current_setting('app.context_installed', true) IS DISTINCT FROM '1'
     OR current_setting('app.purpose', true) IS DISTINCT FROM 'operator-account-onboarding-diagnostic'
     OR current_setting('app.auth_assurance', true) IS DISTINCT FROM 'operator-approved'
     OR current_setting('app.request_id', true) IS NULL
     OR current_setting('app.request_id', true) !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR (login_role = '{{OPERATOR_ROLE}}' AND environment <> '{{TARGET_ENVIRONMENT}}')
     OR (login_role = 'mscqr_rls_wave_c_operator' AND environment NOT IN ('development','staging','production'))
     OR (login_role <> '{{OPERATOR_ROLE}}' AND login_role <> 'mscqr_rls_wave_c_operator') THEN
    RAISE EXCEPTION 'SESSION_C04_INVALID_CONTEXT';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION app_ops.diagnose_account_onboarding(p_normalized_email text)
RETURNS TABLE(
  invite_count bigint,
  latest_created_at timestamp without time zone,
  latest_expires_at timestamp without time zone,
  latest_used_at timestamp without time zone,
  latest_expired boolean,
  latest_role text,
  latest_tenant_binding jsonb,
  latest_accepted_by_present boolean,
  account_exists boolean,
  account_status text,
  account_active boolean,
  account_email_verified boolean,
  password_configured boolean,
  account_role text,
  account_tenant_binding jsonb,
  mfa_configured boolean,
  invite_created_present boolean,
  invite_accepted_present boolean,
  mfa_enrolled_present boolean,
  state_classification text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  normalized_email text := lower(btrim(coalesce(p_normalized_email,'')));
  local_part text;
  domain_part text;
  latest_exists boolean := false;
  latest_created timestamp without time zone;
  latest_expires timestamp without time zone;
  latest_used timestamp without time zone;
  latest_invite_email text;
  latest_invite_role text;
  latest_org_id text;
  latest_licensee_id text;
  latest_manufacturer_id text;
  latest_accepted_by_id text;
  target_id text;
  target_email text;
  target_status text;
  target_is_active boolean;
  target_disabled_at timestamp without time zone;
  target_deleted_at timestamp without time zone;
  target_password_hash text;
  target_email_verified_at timestamp without time zone;
  target_user_role text;
  target_org_id text;
  target_licensee_id text;
  target_count integer := 0;
  target_exists boolean := false;
  target_active boolean := false;
  target_password_configured boolean := false;
  target_email_verified boolean := false;
  target_mfa_configured boolean := false;
  target_unactivated boolean := false;
  latest_invite_acceptable boolean := false;
  observed_at timestamp without time zone := clock_timestamp();
  accepted_invite_for_target boolean := false;
  invite_created boolean := false;
  invite_accepted boolean := false;
  mfa_enrolled boolean := false;
  classification text := 'E_INCONSISTENT_STATE_REQUIRING_REPAIR';
BEGIN
  PERFORM app_ops.session_c04_assert_diagnostic_context();

  -- normalizeEmailAddress performs IDNA conversion before this fixed SQL
  -- selector. The database repeats its ASCII-domain/local-part safety checks
  -- for direct broker calls without widening the application contract.
  local_part := split_part(normalized_email,'@',1);
  domain_part := split_part(normalized_email,'@',2);
  IF normalized_email = '' OR char_length(normalized_email) > 254
     OR length(normalized_email)-length(replace(normalized_email,'@','')) <> 1
     OR normalized_email ~ '[[:cntrl:]]'
     OR char_length(local_part) > 64
     OR domain_part !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
     OR (local_part ~ '^"' AND local_part !~ '^"(?:[\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\x20-\x7E])+"$')
     OR (local_part !~ '^"' AND (local_part !~ '^[A-Za-z0-9!#$%&''*+/=?^_`{|}~.-]+$'
       OR left(local_part,1)='.' OR right(local_part,1)='.' OR local_part LIKE '%..%')) THEN
    RAISE EXCEPTION 'SESSION_C04_INVALID_NORMALIZED_EMAIL';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public."User" actor
     WHERE actor.id=current_setting('app.user_id',true)
       AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
       AND actor."isActive" AND actor.status='ACTIVE'::public."UserStatus"
       AND actor."deletedAt" IS NULL AND actor."disabledAt" IS NULL
  ) THEN
    RAISE EXCEPTION 'SESSION_C04_PLATFORM_ACTOR_REQUIRED';
  END IF;

  SELECT count(*) INTO invite_count FROM public."Invite" i WHERE lower(i.email)=normalized_email;
  SELECT i."createdAt",i."expiresAt",i."usedAt",i.email,i.role::text,i."orgId",i."licenseeId",i."manufacturerId",i."acceptedByUserId"
    INTO latest_created,latest_expires,latest_used,latest_invite_email,latest_invite_role,latest_org_id,latest_licensee_id,latest_manufacturer_id,latest_accepted_by_id
    FROM public."Invite" i
   WHERE lower(i.email)=normalized_email
   ORDER BY i."createdAt" DESC,i.id DESC
   LIMIT 1;
  latest_exists := FOUND;
  SELECT count(*) INTO target_count FROM public."User" u WHERE lower(u.email)=normalized_email;
  IF target_count > 1 THEN
    RAISE EXCEPTION 'SESSION_C04_AMBIGUOUS_NORMALIZED_EMAIL';
  END IF;
  SELECT u.id,u.email,u.status::text,u."isActive",u."disabledAt",u."deletedAt",u."passwordHash",u."emailVerifiedAt",u.role::text,u."orgId",u."licenseeId"
    INTO target_id,target_email,target_status,target_is_active,target_disabled_at,target_deleted_at,target_password_hash,target_email_verified_at,target_user_role,target_org_id,target_licensee_id
    FROM public."User" u
   WHERE lower(u.email)=normalized_email;
  target_exists := FOUND;

  IF target_exists THEN
    target_active := target_is_active AND target_status='ACTIVE' AND target_disabled_at IS NULL AND target_deleted_at IS NULL;
    target_password_configured := target_password_hash IS NOT NULL;
    target_email_verified := target_email_verified_at IS NOT NULL;
    target_unactivated := target_is_active AND target_status='INVITED' AND target_disabled_at IS NULL AND target_deleted_at IS NULL AND target_password_hash IS NULL;
    accepted_invite_for_target := EXISTS (
      SELECT 1 FROM public."Invite" i
       WHERE lower(i.email)=normalized_email AND i."usedAt" IS NOT NULL AND i."acceptedByUserId"=target_id
    );
    target_mfa_configured := EXISTS (
      SELECT 1 FROM public."AdminMfaCredential" c WHERE c."userId"=target_id AND c."isEnabled"
    ) OR EXISTS (
      SELECT 1 FROM public."AdminWebAuthnCredential" c WHERE c."userId"=target_id
    ) OR EXISTS (
      SELECT 1 FROM public."UserMfaFactor" f
       WHERE f."userId"=target_id AND f."disabledAt" IS NULL
         AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING'
         AND (f.type='WEBAUTHN' OR (f.type='TOTP' AND (f."lastUsedAt" IS NOT NULL OR f."legacySource"='AdminMfaCredential')))
    );
  END IF;

  latest_invite_acceptable := latest_exists
    AND EXISTS (SELECT 1 FROM public."Organization" o WHERE o.id=latest_org_id AND o."isActive")
    AND (latest_licensee_id IS NULL OR EXISTS (
      SELECT 1 FROM public."Licensee" l
       WHERE l.id=latest_licensee_id AND l."orgId"=latest_org_id AND l."isActive" AND l."suspendedAt" IS NULL
    ))
    AND (NOT target_exists OR (
      target_unactivated
      AND target_email=latest_invite_email
      AND (CASE WHEN target_user_role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
                WHEN target_user_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
                ELSE target_user_role END)
          IS NOT DISTINCT FROM
          (CASE WHEN latest_invite_role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
                WHEN latest_invite_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
                ELSE latest_invite_role END)
      AND (latest_invite_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
           AND target_org_id IS NULL AND target_licensee_id IS NULL
           OR latest_invite_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
           AND target_org_id IS NOT DISTINCT FROM latest_org_id
           AND target_licensee_id IS NOT DISTINCT FROM latest_licensee_id)
      AND (latest_manufacturer_id IS NULL OR target_id IS NOT DISTINCT FROM latest_manufacturer_id)
    ));

  invite_created := EXISTS (
    SELECT 1 FROM public."AuditLog" a
     WHERE a.action='AUTH_INVITE_CREATED' AND a."entityType"='Invite'
       AND a."entityId" IN (SELECT i.id FROM public."Invite" i WHERE lower(i.email)=normalized_email)
  ) OR EXISTS (
    SELECT 1 FROM public."AuditLogOutbox" o
     WHERE o.payload->>'action'='AUTH_INVITE_CREATED'
       AND o.payload->>'entityType'='Invite'
       AND o.payload->>'entityId' IN (SELECT i.id FROM public."Invite" i WHERE lower(i.email)=normalized_email)
  );
  invite_accepted := EXISTS (
    SELECT 1 FROM public."AuditLog" a
     WHERE a.action='AUTH_INVITE_ACCEPTED' AND (
       (a."entityType"='Invite' AND a."entityId" IN (SELECT i.id FROM public."Invite" i WHERE lower(i.email)=normalized_email))
       OR (target_exists AND a."entityType"='User' AND a."entityId"=target_id)
     )
  ) OR EXISTS (
    SELECT 1 FROM public."AuditLogOutbox" o
     WHERE o.payload->>'action'='AUTH_INVITE_ACCEPTED' AND (
       (o.payload->>'entityType'='Invite' AND o.payload->>'entityId' IN (SELECT i.id FROM public."Invite" i WHERE lower(i.email)=normalized_email))
       OR (target_exists AND o.payload->>'entityType'='User' AND o.payload->>'entityId'=target_id)
     )
  );
  mfa_enrolled := target_exists AND (EXISTS (
    SELECT 1 FROM public."AuditLog" a
     WHERE a.action IN ('AUTH_MFA_ENROLLED','AUTH_WEBAUTHN_ENROLLED') AND a."entityType"='User' AND a."entityId"=target_id
  ) OR EXISTS (
    SELECT 1 FROM public."AuditLogOutbox" o
     WHERE o.payload->>'action' IN ('AUTH_MFA_ENROLLED','AUTH_WEBAUTHN_ENROLLED') AND o.payload->>'entityType'='User' AND o.payload->>'entityId'=target_id
  ));

  IF NOT target_exists AND latest_exists AND latest_used IS NULL AND latest_expires <= observed_at THEN
    classification := 'A_EXPIRED_UNUSED_INVITE_NO_ACCOUNT';
  ELSIF target_unactivated AND latest_exists AND latest_used IS NULL AND latest_expires <= observed_at THEN
    classification := 'B_EXPIRED_UNUSED_INVITE_EXISTING_UNACTIVATED_ACCOUNT';
  ELSIF target_exists AND target_active AND target_password_configured AND target_email_verified AND accepted_invite_for_target AND NOT target_mfa_configured THEN
    classification := 'C_ACTIVATED_ACCOUNT_MFA_INCOMPLETE';
  ELSIF target_exists AND target_active AND target_password_configured AND target_email_verified AND accepted_invite_for_target AND target_mfa_configured THEN
    classification := 'D_ACTIVATED_ACCOUNT_MFA_COMPLETE';
  ELSIF NOT target_exists AND latest_invite_acceptable AND latest_used IS NULL AND latest_expires > observed_at THEN
    classification := 'F_VALID_UNUSED_INVITE_NO_ACCOUNT';
  ELSIF target_unactivated AND latest_invite_acceptable AND latest_used IS NULL AND latest_expires > observed_at THEN
    classification := 'F_VALID_UNUSED_INVITE_EXISTING_UNACTIVATED_ACCOUNT';
  END IF;

  RETURN QUERY SELECT
    invite_count,latest_created,latest_expires,latest_used,
    CASE WHEN latest_exists THEN latest_expires <= observed_at ELSE NULL END,
    latest_invite_role,
    CASE WHEN latest_exists THEN jsonb_build_object('organizationId',latest_org_id,'licenseeId',latest_licensee_id) ELSE NULL END,
    CASE WHEN latest_exists THEN latest_accepted_by_id IS NOT NULL ELSE NULL END,
    target_exists,
    CASE WHEN target_exists THEN target_status ELSE NULL END,
    CASE WHEN target_exists THEN target_active ELSE NULL END,
    CASE WHEN target_exists THEN target_email_verified ELSE NULL END,
    CASE WHEN target_exists THEN target_password_configured ELSE NULL END,
    CASE WHEN target_exists THEN target_user_role ELSE NULL END,
    CASE WHEN target_exists THEN jsonb_build_object('organizationId',target_org_id,'licenseeId',target_licensee_id) ELSE NULL END,
    CASE WHEN target_exists THEN target_mfa_configured ELSE NULL END,
    invite_created,invite_accepted,mfa_enrolled,classification;
END;
$$;

REVOKE ALL ON FUNCTION app_ops.session_c04_assert_diagnostic_context() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_ops.diagnose_account_onboarding(text) FROM PUBLIC;
REVOKE ALL ON SCHEMA app_ops FROM PUBLIC;
