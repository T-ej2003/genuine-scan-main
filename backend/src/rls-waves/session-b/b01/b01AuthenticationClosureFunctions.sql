-- Release Fix 1: exact login, logout, /auth/me, recent-MFA and risk boundaries.
-- Authenticated functions consume only context installed by the reviewed
-- app_auth.require_authenticated_session boundary in the same transaction.
-- Login functions consume the subject bound by app_auth.lookup_password_user;
-- they never inspect caller-selected tenant/user context.

CREATE OR REPLACE FUNCTION app_rls.b01_authenticated_actor(
  p_expected_user_id text,p_expected_session_id text,p_request_id text
) RETURNS TABLE(
  "sessionId" text,"userId" text,"role" text,"organizationId" text,
  "licenseeId" text,"manufacturerId" text,"authAssurance" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF current_setting('app.auth_session_verified',true)<>'1'
     OR current_setting('app.auth_session_id',true) IS DISTINCT FROM p_expected_session_id
     OR current_setting('app.user_id',true) IS DISTINCT FROM p_expected_user_id
     OR current_setting('app.request_id',true) IS DISTINCT FROM p_request_id THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT u.id,u.role::text AS role,u."orgId",u."licenseeId",rt.id AS session_id,
         rt."sessionCapabilityAssurance" AS assurance
    INTO actor
    FROM public."RefreshToken" rt JOIN public."User" u ON u.id=rt."userId"
   WHERE rt.id=p_expected_session_id AND rt."userId"=p_expected_user_id
     AND rt."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
     AND rt."sessionCapabilityHashVersion"='sha256-v1'
     AND rt."sessionCapabilityRevokedAt" IS NULL AND rt."sessionCapabilityExpiresAt">clock_timestamp()
     AND rt."revokedAt" IS NULL AND rt."expiresAt">clock_timestamp()
     AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
     AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_closure_operation','actor',true),
          set_config('app.auth_closure_session_id',actor.session_id,true),
          set_config('app.auth_closure_user_id',actor.id,true),
          set_config('app.auth_closure_role',actor.role,true),
          set_config('app.auth_closure_organization_id',coalesce(actor."orgId",''),true),
          set_config('app.auth_closure_licensee_id',coalesce(actor."licenseeId",''),true);
  RETURN QUERY SELECT actor.session_id::text,actor.id::text,actor.role::text,actor."orgId"::text,
    actor."licenseeId"::text,CASE WHEN actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN actor.id::text END,
    CASE actor.assurance WHEN 'ADMIN_MFA' THEN 'mfa-verified' ELSE 'password-verified' END;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revalidate_authenticated_actor(
  p_user_id text,p_session_id text,p_requested_licensee_id text,p_requested_organization_id text,
  p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE("userId" text,"role" text,"organizationId" text,"licenseeId" text,"manufacturerId" text,"authAssurance" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(p_user_id,p_session_id,p_request_id);
  IF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF p_requested_licensee_id IS NOT NULL OR p_requested_organization_id IS NOT NULL THEN RETURN; END IF;
  ELSIF actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF p_requested_licensee_id IS DISTINCT FROM actor."licenseeId" OR p_requested_organization_id IS DISTINCT FROM actor."organizationId"
       OR NOT EXISTS (SELECT 1 FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
         WHERE l.id=actor."licenseeId" AND l."orgId"=actor."organizationId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RETURN; END IF;
  ELSIF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    IF p_requested_licensee_id IS NULL OR p_requested_organization_id IS NULL OR NOT EXISTS (
      SELECT 1 FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId"
      JOIN public."Organization" o ON o.id=l."orgId" WHERE ml."manufacturerId"=actor."userId"
        AND ml."licenseeId"=p_requested_licensee_id AND l."orgId"=p_requested_organization_id
        AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive") THEN RETURN; END IF;
  END IF;
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,actor."organizationId"::text,
    CASE WHEN actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN p_requested_licensee_id ELSE actor."licenseeId" END,
    actor."manufacturerId"::text,actor."authAssurance"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_actor()
RETURNS TABLE(
  "id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text,
  "emailVerifiedAt" timestamp without time zone,"pendingEmail" text,"pendingEmailRequestedAt" timestamp without time zone,
  "isActive" boolean,"status" text,"deletedAt" timestamp without time zone,"disabledAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"licenseeRecordId" text,"licenseeName" text,
  "licenseePrefix" text,"licenseeBrandName" text,"licenseeOrgId" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(current_setting('app.user_id',true),current_setting('app.auth_session_id',true),current_setting('app.request_id',true));
  RETURN QUERY SELECT u.id::text,u.email::text,u.name::text,u.role::text,u."licenseeId"::text,u."orgId"::text,
    u."emailVerifiedAt",u."pendingEmail"::text,u."pendingEmailRequestedAt",u."isActive",u.status::text,u."deletedAt",u."disabledAt",u."createdAt",
    l.id::text,l.name::text,l.prefix::text,l."brandName"::text,l."orgId"::text
  FROM public."User" u LEFT JOIN public."Licensee" l ON l.id=u."licenseeId"
  WHERE u.id=actor."userId" AND u."isActive" AND u.status='ACTIVE'::public."UserStatus" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_manufacturer_scope(
  p_requested_licensee_id text,p_requested_org_id text,p_requested_scope_version text,
  p_purpose text,p_write_audit boolean
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; selected record; link_count integer; primary_count integer; links jsonb; audit_id text;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor.role <> 'MANUFACTURER_ADMIN'
     OR p_purpose NOT IN ('manufacturer-bootstrap','manufacturer-scope-switch')
     OR (p_requested_licensee_id IS NOT NULL AND p_requested_licensee_id !~* '^[0-9a-f-]{36}$')
     OR (p_requested_org_id IS NOT NULL AND p_requested_org_id !~* '^[0-9a-f-]{36}$')
     OR (p_requested_licensee_id IS NOT NULL AND p_requested_scope_version IS NULL)
  THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.auth_closure_operation','manufacturer-scope-read',true),
          set_config('app.auth_closure_user_id',actor."userId",true);
  SELECT count(*) INTO link_count
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
    AND l."suspendedAt" IS NULL AND o."isActive";
  IF link_count=0 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_REQUIRED' USING ERRCODE='42501'; END IF;
  IF link_count>100 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_SET_TOO_LARGE' USING ERRCODE='54000'; END IF;
  SELECT count(*) INTO primary_count
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND ml."isPrimary"
    AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  IF primary_count>1 THEN RAISE EXCEPTION 'MANUFACTURER_MEMBERSHIP_AMBIGUOUS' USING ERRCODE='42501'; END IF;

  SELECT ml."licenseeId",ml."isPrimary",ml."updatedAt",l.id,l.name,l.prefix,l."brandName",l."orgId"
  INTO selected
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
    AND l."suspendedAt" IS NULL AND o."isActive"
    AND (p_requested_licensee_id IS NULL OR ml."licenseeId"=p_requested_licensee_id)
    AND (p_requested_org_id IS NULL OR l."orgId"=p_requested_org_id)
  ORDER BY
    CASE WHEN p_requested_licensee_id IS NOT NULL OR p_requested_org_id IS NOT NULL THEN 0 ELSE 1 END,
    ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"
  LIMIT 1;
  IF NOT FOUND AND (p_requested_licensee_id IS NOT NULL OR p_requested_org_id IS NOT NULL) THEN
    RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED' USING ERRCODE='42501';
  END IF;
  IF p_requested_scope_version IS NOT NULL
     AND to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') IS DISTINCT FROM p_requested_scope_version
  THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_STALE' USING ERRCODE='42501'; END IF;
  IF p_requested_licensee_id IS NULL AND p_requested_org_id IS NULL
     AND link_count>1
     AND NOT EXISTS (
       SELECT 1 FROM public."ManufacturerLicenseeLink" ml
       WHERE ml."manufacturerId"=actor."userId" AND ml."isPrimary"
     )
  THEN selected:=NULL; END IF;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",
    'orgId',l."orgId",'isPrimary',ml."isPrimary",
    'scopeVersion',to_char(ml."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"),'[]'::jsonb)
  INTO links
  FROM public."ManufacturerLicenseeLink" ml
  JOIN public."Licensee" l ON l.id=ml."licenseeId"
  JOIN public."Organization" o ON o.id=l."orgId"
  WHERE ml."manufacturerId"=actor."userId" AND l."isActive"
    AND l."suspendedAt" IS NULL AND o."isActive";

  IF p_write_audit THEN
    audit_id:=gen_random_uuid()::text;
    PERFORM set_config('app.auth_closure_audit_id',audit_id,true);
    INSERT INTO public."AuditLogOutbox"(
      id,payload,"requestId","organizationId","licenseeId","initiatingUserId",
      "initiatingActorRoleSnapshot","expiresAt","updatedAt"
    ) VALUES (
      audit_id,jsonb_build_object(
        'userId',actor."userId",'orgId',selected."orgId",'licenseeId',selected.id,
        'action',CASE WHEN p_purpose='manufacturer-scope-switch' THEN 'MANUFACTURER_SCOPE_SWITCH' ELSE 'MANUFACTURER_BOOTSTRAP_READ' END,
        'entityType','ManufacturerLicenseeLink',
        'entityId',CASE WHEN selected.id IS NULL THEN actor."userId" ELSE actor."userId"||':'||selected.id END,
        'details',jsonb_build_object('requestId',current_setting('app.request_id',true),
          'selectedLicenseeId',selected.id,'selectedOrganizationId',selected."orgId",
          'scopeVersion',CASE WHEN selected.id IS NULL THEN NULL ELSE to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
          'assurance',actor."authAssurance",'purpose',p_purpose,
          'outcome',CASE WHEN selected.id IS NULL THEN 'SCOPE_SELECTION_REQUIRED' ELSE 'SELECTED' END)
      ),current_setting('app.request_id',true),selected."orgId",selected.id,actor."userId",actor.role,
      clock_timestamp()+interval '1 day',clock_timestamp()
    );
  END IF;

  RETURN jsonb_build_object(
    'manufacturerId',actor."userId",
    'selectedLicensee',CASE WHEN selected.id IS NULL THEN NULL ELSE jsonb_build_object(
      'id',selected.id,'name',selected.name,'prefix',selected.prefix,'brandName',selected."brandName",
      'orgId',selected."orgId",'isPrimary',selected."isPrimary",
      'scopeVersion',to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    ) END,
    'linkedLicensees',links
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.find_refresh_token_by_id(p_session_id text,p_user_id text)
RETURNS TABLE("id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,"createdAt" timestamp without time zone,
  "createdIpHash" text,"createdUserAgent" text,"authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
BEGIN
  PERFORM app_rls.b01_authenticated_actor(p_user_id,p_session_id,current_setting('app.request_id',true));
  RETURN QUERY SELECT rt.id::text,rt."userId"::text,rt."orgId"::text,rt."expiresAt",rt."createdAt",rt."createdIpHash"::text,
    rt."createdUserAgent"::text,rt."authenticatedAt",rt."mfaVerifiedAt",rt."lastUsedAt",rt."revokedAt",rt."revokedReason"::text
  FROM public."RefreshToken" rt WHERE rt.id=p_session_id AND rt."userId"=p_user_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_refresh_token_by_id(
  p_session_id text,p_user_id text,p_reason text,p_revoked_at timestamp without time zone
) RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE changed integer;
BEGIN
  IF p_reason NOT IN ('SESSION_REVOKED_BY_USER','LOGOUT','STEP_UP_REPLACED') OR p_revoked_at IS NULL
     OR abs(extract(epoch FROM (p_revoked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_REVOCATION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM app_rls.b01_authenticated_actor(p_user_id,p_session_id,current_setting('app.request_id',true));
  PERFORM set_config('app.auth_session_operation','revoke-one',true),set_config('app.auth_session_target_id',p_session_id,true);
  UPDATE public."RefreshToken" rt SET "revokedAt"=clock_timestamp(),"revokedReason"=p_reason,"lastUsedAt"=clock_timestamp(),
    "sessionCapabilityRevokedAt"=clock_timestamp(),"sessionCapabilityRevokedReason"=p_reason
  WHERE rt.id=p_session_id AND rt."userId"=p_user_id AND rt."revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.require_recent_mfa_session(
  p_session_id text,p_checked_at timestamp without time zone,p_max_age_minutes integer
) RETURNS TABLE("verifiedAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 OR p_max_age_minutes NOT BETWEEN 1 AND 1440 THEN
    RAISE EXCEPTION 'RECENT_MFA_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(current_setting('app.user_id',true),p_session_id,current_setting('app.request_id',true));
  IF actor."authAssurance" NOT IN ('mfa-verified','step-up-verified') THEN RETURN; END IF;
  RETURN QUERY SELECT rt."mfaVerifiedAt" FROM public."RefreshToken" rt WHERE rt.id=p_session_id AND rt."userId"=actor."userId"
    AND rt."revokedAt" IS NULL AND rt."expiresAt">p_checked_at
    AND rt."mfaVerifiedAt" BETWEEN p_checked_at-(p_max_age_minutes*interval '1 minute') AND p_checked_at+interval '5 minutes';
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_recent_auth_session_risk_inputs(p_limit integer)
RETURNS TABLE("createdIpHash" text,"createdUserAgent" text,"createdAt" timestamp without time zone,"actorState" jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE user_id text := current_setting('app.b01_preauth_user_id',true); actor record; selected record; links jsonb; methods text[]; mfa_enabled boolean; mfa_last timestamp without time zone; actor_state jsonb;
BEGIN
  IF user_id='' OR p_limit NOT BETWEEN 1 AND 5 THEN RAISE EXCEPTION 'AUTH_LOGIN_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  SELECT NULL::text AS id,NULL::text AS name,NULL::text AS prefix,NULL::text AS "brandName",NULL::text AS "orgId",NULL::timestamp AS "updatedAt" INTO selected;
  PERFORM set_config('app.auth_closure_operation','login-risk-read',true),set_config('app.auth_closure_user_id',user_id,true);
  SELECT u.id,u.email,u.name,u.role::text AS role,u."orgId",u."licenseeId",u."emailVerifiedAt"
    INTO actor FROM public."User" u WHERE u.id=user_id AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
      AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL AND u."emailVerifiedAt" IS NOT NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_closure_organization_id',coalesce(actor."orgId",''),true),
          set_config('app.auth_closure_licensee_id',coalesce(actor."licenseeId",''),true);
  SELECT coalesce(bool_or(x.enabled),false),max(x."lastUsedAt"),coalesce(array_agg(DISTINCT x.method) FILTER (WHERE x.enabled),'{}'::text[])
    INTO mfa_enabled,mfa_last,methods FROM (
      SELECT "isEnabled" AS enabled,"lastUsedAt",'TOTP'::text AS method FROM public."AdminMfaCredential" WHERE "userId"=user_id
      UNION ALL SELECT TRUE,"lastUsedAt",'WEBAUTHN' FROM public."AdminWebAuthnCredential" WHERE "userId"=user_id
      UNION ALL SELECT TRUE,"lastUsedAt",type FROM public."UserMfaFactor" WHERE "userId"=user_id AND "disabledAt" IS NULL AND type IN ('TOTP','WEBAUTHN')
    ) x;
  IF EXISTS (SELECT 1 FROM public."UserBackupCode" WHERE "userId"=user_id AND "usedAt" IS NULL) AND 'TOTP'=ANY(methods) THEN methods:=array_append(methods,'BACKUP_CODE'); END IF;
  IF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT l.id,l.name,l.prefix,l."brandName",l."orgId",ml."updatedAt" INTO selected
      FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=user_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive"
      ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId" LIMIT 1;
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",'orgId',l."orgId",'isPrimary',ml."isPrimary",'scopeVersion',to_char(ml."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"),'[]'::jsonb)
      INTO links FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=user_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
  ELSE
    IF actor."licenseeId" IS NOT NULL THEN
      SELECT l.id,l.name,l.prefix,l."brandName",l."orgId",NULL::timestamp AS "updatedAt" INTO selected
        FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
        WHERE l.id=actor."licenseeId" AND l."orgId"=actor."orgId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
      IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_BOUNDARY_DENIED' USING ERRCODE='42501'; END IF;
    END IF;
    links:='[]'::jsonb;
  END IF;
  actor_state:=jsonb_build_object(
    'userId',actor.id,'email',actor.email,'name',actor.name,'role',actor.role,'legacyLicenseeId',actor."licenseeId",'legacyOrganizationId',actor."orgId",
    'emailVerifiedAt',actor."emailVerifiedAt",'sessionLicenseeId',selected.id,'sessionOrganizationId',CASE WHEN selected.id IS NULL THEN actor."orgId" ELSE selected."orgId" END,
    'scopeVersion',CASE WHEN actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'selectedLicenseeId',selected.id,'selectedLicenseeName',selected.name,'selectedLicenseePrefix',selected.prefix,'selectedLicenseeBrandName',selected."brandName",'selectedLicenseeOrganizationId',selected."orgId",
    'linkedLicensees',links,'mfaRequired',actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN','MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'),
    'mfaEnabled',mfa_enabled,'mfaEnrolled',mfa_enabled,'mfaLastUsedAt',mfa_last,'mfaMethods',methods,
    'mfaPreferredMethod',CASE WHEN 'WEBAUTHN'=ANY(methods) THEN 'WEBAUTHN' WHEN 'TOTP'=ANY(methods) THEN 'TOTP' ELSE NULL END);
  RETURN QUERY SELECT recent."createdIpHash",recent."createdUserAgent",recent."createdAt",actor_state FROM (
    SELECT rt."createdIpHash"::text,rt."createdUserAgent"::text,rt."createdAt" FROM public."RefreshToken" rt
      WHERE rt."userId"=user_id ORDER BY rt."createdAt" DESC,rt.id LIMIT p_limit
  ) recent;
  IF NOT FOUND THEN RETURN QUERY SELECT NULL::text,NULL::text,NULL::timestamp,actor_state; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.record_auth_session_risk_signal(
  p_risk_score integer,p_risk_level text,p_reasons text[],p_ip_hash text,p_user_agent_hash text,p_recorded_at timestamp without time zone,
  p_password_hash text,p_challenge_ticket_hash text,p_challenge_session_hash text,p_challenge_expires_at timestamp without time zone,
  p_challenge_max_attempts integer,p_request_id text
) RETURNS TABLE("recorded" boolean,"challengeCreated" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE user_id text := current_setting('app.b01_preauth_user_id',true); challenge_id text; wants_challenge boolean := p_challenge_ticket_hash IS NOT NULL;
BEGIN
  IF user_id='' OR p_risk_score NOT BETWEEN 0 AND 100 OR p_risk_level NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR cardinality(p_reasons)>12 OR p_recorded_at IS NULL OR abs(extract(epoch FROM (p_recorded_at-clock_timestamp())))>300
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR (p_password_hash IS NOT NULL AND p_password_hash !~ '^\$argon2(id|i|d)\$')
     OR wants_challenge IS DISTINCT FROM (p_challenge_session_hash IS NOT NULL AND p_challenge_expires_at IS NOT NULL AND p_challenge_max_attempts IS NOT NULL)
     OR (wants_challenge AND (p_challenge_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_challenge_session_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
       OR p_challenge_max_attempts NOT BETWEEN 1 AND 10 OR p_challenge_expires_at<=p_recorded_at OR p_challenge_expires_at>p_recorded_at+interval '15 minutes')) THEN
    RAISE EXCEPTION 'AUTH_LOGIN_RISK_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation','login-risk-write',true),set_config('app.auth_closure_user_id',user_id,true);
  PERFORM set_config('app.auth_closure_request_id',p_request_id,true);
  UPDATE public."User" u SET "failedLoginAttempts"=0,"lockedUntil"=NULL,"lastLoginAt"=p_recorded_at,"updatedAt"=p_recorded_at,
    "passwordHash"=coalesce(p_password_hash,u."passwordHash")
    WHERE u.id=user_id AND u."isActive" AND u.status='ACTIVE'::public."UserStatus" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_RISK_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."AuthSessionRiskSignal"(id,"userId","riskScore","riskLevel",reasons,"ipHash","userAgentHash","createdAt")
  VALUES (gen_random_uuid()::text,user_id,p_risk_score,p_risk_level::public."AuthRiskLevel",p_reasons,p_ip_hash,p_user_agent_hash,p_recorded_at);
  IF wants_challenge THEN
    challenge_id:=gen_random_uuid()::text;
    PERFORM set_config('app.auth_closure_operation','login-mfa-challenge',true),set_config('app.auth_closure_challenge_id',challenge_id,true),
            set_config('app.auth_closure_challenge_hash',p_challenge_ticket_hash,true);
    INSERT INTO public."MfaLoginChallenge"(id,"userId","ticketHash",purpose,"riskScore","riskLevel",reasons,"createdIpHash","createdUserAgentHash",attempts,"maxAttempts","createdAt","updatedAt","expiresAt")
      VALUES (challenge_id,user_id,p_challenge_ticket_hash,'admin_login',p_risk_score,p_risk_level::public."AuthRiskLevel",p_reasons,p_ip_hash,p_user_agent_hash,0,p_challenge_max_attempts,p_recorded_at,p_recorded_at,p_challenge_expires_at);
    INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","initiatingUserId","expiresAt","updatedAt") VALUES (
      gen_random_uuid()::text,jsonb_build_object('userId',user_id,'action','AUTH_MFA_CHALLENGE_ISSUED','entityType','MfaLoginChallenge','entityId',challenge_id,'details',jsonb_build_object('purpose','admin_login','riskScore',p_risk_score,'riskLevel',p_risk_level)),
      p_request_id,user_id,p_recorded_at+interval '1 day',p_recorded_at);
  END IF;
  RETURN QUERY SELECT true,wants_challenge;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_refresh_token(
  p_user_id text,p_organization_id text,p_token_hash text,p_expires_at timestamp without time zone,p_ip_hash text,p_user_agent text,
  p_authenticated_at timestamp without time zone,p_mfa_verified_at timestamp without time zone,p_created_at timestamp without time zone
) RETURNS TABLE("id" text,"expiresAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE token_id text := gen_random_uuid()::text; actor record;
        authenticated_call boolean := current_setting('app.auth_session_verified',true)='1';
BEGIN
  IF p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_expires_at<=p_created_at
     OR p_expires_at>p_created_at+interval '31 days' THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  IF authenticated_call THEN
    SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
      current_setting('app.user_id',true),current_setting('app.auth_session_id',true),current_setting('app.request_id',true)
    );
    IF p_user_id IS DISTINCT FROM actor."userId"
       OR (actor.role<>'MANUFACTURER_ADMIN'
           AND p_organization_id IS DISTINCT FROM nullif(current_setting('app.organization_id',true),''))
    THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  ELSIF p_user_id IS DISTINCT FROM current_setting('app.b01_preauth_user_id',true) THEN
    RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation',CASE WHEN authenticated_call THEN 'authenticated-session-create' ELSE 'login-session-create' END,true),
          set_config('app.auth_closure_user_id',p_user_id,true),
          set_config('app.auth_closure_organization_id',coalesce(p_organization_id,''),true),set_config('app.auth_closure_token_id',token_id,true),
          set_config('app.auth_closure_token_hash',p_token_hash,true);
  SELECT u.id,u.role::text AS role,u."orgId",u."licenseeId" INTO actor FROM public."User" u WHERE u.id=p_user_id AND u."isActive"
    AND u.status='ACTIVE'::public."UserStatus" AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL AND u."emailVerifiedAt" IS NOT NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  IF actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') AND p_organization_id IS NOT NULL THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501';
  ELSIF actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') AND p_organization_id IS DISTINCT FROM actor."orgId" THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501';
  ELSIF actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') AND NOT EXISTS (
    SELECT 1 FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
    WHERE ml."manufacturerId"=actor.id AND l."orgId"=p_organization_id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive")
  THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."RefreshToken"(id,"orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt")
  VALUES (token_id,p_organization_id,p_user_id,p_token_hash,p_expires_at,p_created_at,p_ip_hash,p_user_agent,p_authenticated_at,p_mfa_verified_at,p_created_at);
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt") VALUES (
    gen_random_uuid()::text,jsonb_build_object('userId',p_user_id,'orgId',p_organization_id,'action',CASE WHEN p_mfa_verified_at IS NULL THEN 'AUTH_LOGIN_SUCCESS' ELSE 'AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA' END,'entityType','User','entityId',p_user_id),
    nullif(current_setting('app.auth_closure_request_id',true),''),p_organization_id,p_user_id,actor.role,p_created_at+interval '1 day',p_created_at);
  RETURN QUERY SELECT token_id,p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_password_actor()
RETURNS TABLE(
  "id" text,"passwordHash" text,"role" text,"status" text,"isActive" boolean,
  "disabledAt" timestamp without time zone,"deletedAt" timestamp without time zone
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','password-actor-read',true);
  RETURN QUERY
  SELECT u.id::text,u."passwordHash"::text,u.role::text,u.status::text,u."isActive",u."disabledAt",u."deletedAt"
    FROM public."User" u
   WHERE u.id=actor."userId"
     AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
     AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.list_active_refresh_tokens(
  p_user_id text,p_checked_at timestamp without time zone
) RETURNS TABLE(
  "id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"createdIpHash" text,"createdUserAgent" text,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_LIST_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor."userId" IS DISTINCT FROM p_user_id THEN
    RAISE EXCEPTION 'AUTH_SESSION_LIST_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation','session-list',true);
  RETURN QUERY
  SELECT rt.id::text,rt."userId"::text,rt."orgId"::text,rt."expiresAt",rt."createdAt",
    rt."createdIpHash"::text,rt."createdUserAgent"::text,rt."authenticatedAt",rt."mfaVerifiedAt",
    rt."lastUsedAt",rt."revokedAt",rt."revokedReason"::text
    FROM public."RefreshToken" rt
   WHERE rt."userId"=actor."userId" AND rt."revokedAt" IS NULL AND rt."expiresAt">p_checked_at
   ORDER BY coalesce(rt."lastUsedAt",rt."createdAt") DESC,rt.id
   LIMIT 200;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_all_refresh_tokens(
  p_user_id text,p_reason text,p_revoked_at timestamp without time zone
) RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer;
BEGIN
  IF p_reason NOT IN ('ALL_SESSIONS_REVOKED_BY_USER','PASSWORD_CHANGED','MFA_DISABLED')
     OR p_revoked_at IS NULL OR abs(extract(epoch FROM (p_revoked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_SESSION_REVOCATION_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor."userId" IS DISTINCT FROM p_user_id THEN
    RAISE EXCEPTION 'AUTH_SESSION_REVOCATION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.auth_closure_operation','session-revoke-all',true);
  UPDATE public."RefreshToken" rt
     SET "revokedAt"=p_revoked_at,"revokedReason"=p_reason,"lastUsedAt"=p_revoked_at,
         "sessionCapabilityRevokedAt"=p_revoked_at,"sessionCapabilityRevokedReason"=p_reason
   WHERE rt."userId"=actor."userId" AND rt."revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.prove_authenticated_password_step_up(
  p_session_id text,p_expected_password_hash text,p_verified_at timestamp without time zone
) RETURNS TABLE("authorized" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_expected_password_hash IS NULL OR p_verified_at IS NULL
     OR abs(extract(epoch FROM (p_verified_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_PASSWORD_STEP_UP_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),p_session_id,current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','password-step-up',true);
  IF NOT EXISTS (
    SELECT 1 FROM public."User" u
     WHERE u.id=actor."userId" AND u."passwordHash"=p_expected_password_hash
       AND u."isActive" AND u.status='ACTIVE'::public."UserStatus"
       AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL
  ) THEN RETURN QUERY SELECT false; RETURN; END IF;
  UPDATE public."RefreshToken" rt SET "authenticatedAt"=p_verified_at,"lastUsedAt"=p_verified_at
   WHERE rt.id=p_session_id AND rt."userId"=actor."userId" AND rt."revokedAt" IS NULL;
  RETURN QUERY SELECT FOUND;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.require_recent_sensitive_session(
  p_session_id text,p_checked_at timestamp without time zone,
  p_max_password_age_minutes integer,p_max_mfa_age_minutes integer
) RETURNS TABLE("authorized" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; session_row record;
BEGIN
  IF p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300
     OR p_max_password_age_minutes NOT BETWEEN 1 AND 1440
     OR p_max_mfa_age_minutes NOT BETWEEN 1 AND 1440 THEN
    RAISE EXCEPTION 'AUTH_SENSITIVE_SESSION_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),p_session_id,current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','sensitive-session-read',true);
  SELECT rt."authenticatedAt",rt."mfaVerifiedAt" INTO session_row
    FROM public."RefreshToken" rt
   WHERE rt.id=p_session_id AND rt."userId"=actor."userId"
     AND rt."revokedAt" IS NULL AND rt."expiresAt">p_checked_at;
  RETURN QUERY SELECT FOUND
    AND session_row."authenticatedAt">=p_checked_at-(p_max_password_age_minutes*interval '1 minute')
    AND (
      actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN')
      OR session_row."mfaVerifiedAt">=p_checked_at-(p_max_mfa_age_minutes*interval '1 minute')
    );
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.request_authenticated_email_change(
  p_next_email text,p_token_hash text,p_secret_version text,
  p_expires_at timestamp without time zone,p_requested_at timestamp without time zone,
  p_ip_hash text,p_user_agent_hash text
) RETURNS TABLE(
  "changed" boolean,"verificationRequired" boolean,"userId" text,"currentEmail" text,
  "pendingEmail" text,"orgId" text,"licenseeId" text,"expiresAt" timestamp without time zone
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; user_row record; token_id text := gen_random_uuid()::text; normalized_email text := lower(btrim(p_next_email));
BEGIN
  IF normalized_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
     OR length(normalized_email)>320
     OR p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_secret_version IS NULL OR length(p_secret_version) NOT BETWEEN 1 AND 64
     OR p_requested_at IS NULL OR abs(extract(epoch FROM (p_requested_at-clock_timestamp())))>300
     OR p_expires_at<=p_requested_at OR p_expires_at>p_requested_at+interval '48 hours' THEN
    RAISE EXCEPTION 'AUTH_EMAIL_CHANGE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','email-change',true),
          set_config('app.auth_closure_pending_email',normalized_email,true),
          set_config('app.auth_closure_token_hash',p_token_hash,true);
  SELECT u.id,u.email,u."orgId",u."licenseeId" INTO user_row
    FROM public."User" u WHERE u.id=actor."userId" FOR UPDATE;
  IF lower(user_row.email)=normalized_email THEN
    RETURN QUERY SELECT false,false,user_row.id::text,user_row.email::text,NULL::text,
      user_row."orgId"::text,user_row."licenseeId"::text,NULL::timestamp;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM public."User" u WHERE lower(u.email)=normalized_email AND u.id<>actor."userId") THEN
    RAISE EXCEPTION 'AUTH_EMAIL_CHANGE_CONFLICT' USING ERRCODE='23505';
  END IF;
  UPDATE public."EmailVerificationToken" t SET "usedAt"=p_requested_at
   WHERE t."userId"=actor."userId" AND t.purpose='EMAIL_CHANGE' AND t."usedAt" IS NULL;
  INSERT INTO public."EmailVerificationToken"(
    id,"userId",email,"pendingEmail",purpose,"tokenHash","secretVersion","expiresAt","createdAt","createdIpHash","userAgentHash"
  ) VALUES (
    token_id,actor."userId",user_row.email,normalized_email,'EMAIL_CHANGE',p_token_hash,p_secret_version,
    p_expires_at,p_requested_at,p_ip_hash,p_user_agent_hash
  );
  UPDATE public."User" u SET "pendingEmail"=normalized_email,"pendingEmailRequestedAt"=p_requested_at,"updatedAt"=p_requested_at
   WHERE u.id=actor."userId";
  PERFORM set_config('app.auth_closure_pending_email',normalized_email,true);
  RETURN QUERY SELECT false,true,user_row.id::text,user_row.email::text,normalized_email,
    user_row."orgId"::text,user_row."licenseeId"::text,p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.update_authenticated_profile(
  p_name text,p_email_change_requested boolean,p_audit_pending_email text,
  p_changed_at timestamp without time zone
) RETURNS TABLE(
  "id" text,"email" text,"name" text,"role" text,"licenseeId" text,"orgId" text,
  "emailVerifiedAt" timestamp without time zone,"pendingEmail" text,"pendingEmailRequestedAt" timestamp without time zone,
  "isActive" boolean,"status" text,"deletedAt" timestamp without time zone,"disabledAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"licenseeRecordId" text,"licenseeName" text,
  "licenseePrefix" text,"licenseeBrandName" text,"licenseeOrgId" text
)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; audit_id text := gen_random_uuid()::text;
BEGIN
  IF p_changed_at IS NULL OR abs(extract(epoch FROM (p_changed_at-clock_timestamp())))>300
     OR (p_name IS NOT NULL AND length(btrim(p_name)) NOT BETWEEN 2 AND 80)
     OR (p_email_change_requested AND NOT EXISTS (
       SELECT 1 FROM public."User" pending_actor
        WHERE pending_actor.id=current_setting('app.user_id',true)
          AND lower(pending_actor."pendingEmail")=lower(btrim(coalesce(p_audit_pending_email,'')))
     )) THEN
    RAISE EXCEPTION 'AUTH_PROFILE_UPDATE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','profile-update',true);
  UPDATE public."User" u SET name=coalesce(btrim(p_name),u.name),"updatedAt"=p_changed_at
   WHERE u.id=actor."userId";
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_PROFILE_UPDATE_DENIED' USING ERRCODE='42501'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (
    audit_id,
    jsonb_build_object('userId',actor."userId",'action','AUTH_PROFILE_UPDATED','entityType','User','entityId',actor."userId",
      'details',jsonb_build_object('nameChanged',p_name IS NOT NULL,'emailChangeRequested',p_email_change_requested)),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_changed_at+interval '1 day',p_changed_at
  );
  RETURN QUERY SELECT a.* FROM app_rls.load_authenticated_actor() a;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.change_authenticated_password(
  p_expected_password_hash text,p_password_hash text,p_changed_at timestamp without time zone
) RETURNS TABLE("changed" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer;
BEGIN
  IF p_expected_password_hash IS NULL OR p_password_hash !~ '^\$argon2(id|i|d)\$'
     OR p_changed_at IS NULL OR abs(extract(epoch FROM (p_changed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'AUTH_PASSWORD_CHANGE_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  PERFORM set_config('app.auth_closure_operation','password-change',true);
  UPDATE public."User" u SET "passwordHash"=p_password_hash,"updatedAt"=p_changed_at
   WHERE u.id=actor."userId" AND u."passwordHash"=p_expected_password_hash;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RETURN QUERY SELECT false; RETURN; END IF;
  UPDATE public."RefreshToken" rt
     SET "revokedAt"=p_changed_at,"revokedReason"='PASSWORD_CHANGED',
         "sessionCapabilityRevokedAt"=p_changed_at,"sessionCapabilityRevokedReason"='PASSWORD_CHANGED'
   WHERE rt."userId"=actor."userId" AND rt."revokedAt" IS NULL;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (
    gen_random_uuid()::text,
    jsonb_build_object('userId',actor."userId",'action','AUTH_PASSWORD_CHANGED','entityType','User','entityId',actor."userId"),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_changed_at+interval '1 day',p_changed_at
  );
  RETURN QUERY SELECT true;
END
$fn$;

-- RF7 compatibility closure: admin MFA persistence remains application-crypto
-- driven, while every protected row is selected or mutated by an actor-bound
-- capability. Raw MFA secrets and bearer material are never written to audit.
CREATE OR REPLACE FUNCTION app_rls.b01_admin_mfa_actor()
RETURNS TABLE("userId" text,"role" text,"organizationId" text,"licenseeId" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_authenticated_actor(
    current_setting('app.user_id',true),
    current_setting('app.auth_session_id',true),
    current_setting('app.request_id',true)
  );
  IF actor.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN') THEN
    RAISE EXCEPTION 'AUTH_MFA_ROLE_DENIED' USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT actor."userId"::text,actor.role::text,actor."organizationId"::text,actor."licenseeId"::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_mfa_state()
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-state-read',true);
  SELECT jsonb_build_object(
    'legacyTotp',(SELECT to_jsonb(x) FROM (
      SELECT c.id,c."isEnabled",c."verifiedAt",c."lastUsedAt",c."backupCodesHash",c."createdAt",c."updatedAt"
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    ) x),
    'legacyWebAuthn',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT c.id,c.label,c."credentialId",c.transports,c."lastUsedAt",c."createdAt",c."updatedAt"
      FROM public."AdminWebAuthnCredential" c WHERE c."userId"=actor."userId"
    ) x),'[]'::jsonb),
    'factors',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT f.id,f.type,f.label,f."credentialId",f.transports,f."legacySource",f."lastUsedAt",f."createdAt",f."updatedAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f."disabledAt" IS NULL
    ) x),'[]'::jsonb),
    'backupCodesRemaining',(SELECT count(*) FROM public."UserBackupCode" b WHERE b."userId"=actor."userId" AND b."usedAt" IS NULL)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.begin_admin_totp_enrollment(
  p_mode text,p_secret_ciphertext text,p_secret_iv text,p_secret_tag text,p_backup_hashes text[],
  p_pending_cutoff timestamp without time zone,p_created_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; enrolled boolean; pending_count integer; credential_id text; factor_id text;
BEGIN
  IF p_mode NOT IN ('FIRST_ENROLLMENT','REPLACEMENT') OR p_secret_ciphertext IS NULL OR p_secret_iv IS NULL
     OR p_secret_tag IS NULL OR cardinality(p_backup_hashes) NOT BETWEEN 1 AND 20
     OR p_pending_cutoff IS NULL OR p_created_at IS NULL
     OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300
     OR p_pending_cutoff>p_created_at OR p_pending_cutoff<p_created_at-interval '30 minutes' THEN
    RAISE EXCEPTION 'MFA_ENROLLMENT_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-enrollment-begin',true);

  SELECT coalesce(bool_or(v),false) INTO enrolled FROM (
    SELECT c."isEnabled" OR c."verifiedAt" IS NOT NULL AS v FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    UNION ALL SELECT true FROM public."AdminWebAuthnCredential" w WHERE w."userId"=actor."userId"
    UNION ALL SELECT true FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f."disabledAt" IS NULL
      AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING'
      AND (f.type='WEBAUTHN' OR (f.type='TOTP' AND (f."lastUsedAt" IS NOT NULL OR f."legacySource"='AdminMfaCredential')))
  ) q;
  IF p_mode='FIRST_ENROLLMENT' AND enrolled THEN RAISE EXCEPTION 'MFA_ALREADY_ENROLLED' USING ERRCODE='23505'; END IF;
  IF p_mode='REPLACEMENT' AND NOT enrolled THEN RAISE EXCEPTION 'MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR' USING ERRCODE='23514'; END IF;

  SELECT count(*) INTO pending_count FROM public."UserMfaFactor" f
   WHERE f."userId"=actor."userId" AND f.type='TOTP' AND f."disabledAt" IS NULL
     AND f."legacySource"='MFA_ENROLLMENT_PENDING' AND f."createdAt">p_pending_cutoff;
  IF pending_count>0 THEN RAISE EXCEPTION 'MFA_SETUP_ALREADY_STARTED' USING ERRCODE='23505'; END IF;
  DELETE FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
    AND f."legacySource"='MFA_ENROLLMENT_PENDING';

  IF p_mode='REPLACEMENT' THEN
    INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","lastUsedAt","createdAt","updatedAt")
    SELECT 'legacy-totp-'||actor."userId",actor."userId",'TOTP','Authenticator app',c."secretCiphertext",c."secretIv",c."secretTag",
           'AdminMfaCredential',actor."userId",coalesce(c."lastUsedAt",c."verifiedAt"),p_created_at,p_created_at
      FROM public."AdminMfaCredential" c
     WHERE c."userId"=actor."userId" AND c."isEnabled"
       AND NOT EXISTS (SELECT 1 FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
         AND f."disabledAt" IS NULL AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING')
    ON CONFLICT (id) DO UPDATE SET "disabledAt"=NULL,"lastUsedAt"=excluded."lastUsedAt","updatedAt"=p_created_at;
    INSERT INTO public."UserBackupCode"(id,"userId","codeHash","createdAt")
    SELECT gen_random_uuid()::text,actor."userId",h,p_created_at
      FROM public."AdminMfaCredential" c,unnest(c."backupCodesHash") h
     WHERE c."userId"=actor."userId" AND c."isEnabled"
    ON CONFLICT ("codeHash") DO NOTHING;
  END IF;

  SELECT c.id INTO credential_id FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId" FOR UPDATE;
  IF credential_id IS NULL THEN
    credential_id:=gen_random_uuid()::text;
    INSERT INTO public."AdminMfaCredential"(id,"userId","secretCiphertext","secretIv","secretTag","backupCodesHash","isEnabled","verifiedAt","lastUsedAt","createdAt","updatedAt")
    VALUES (credential_id,actor."userId",p_secret_ciphertext,p_secret_iv,p_secret_tag,p_backup_hashes,false,NULL,NULL,p_created_at,p_created_at);
  ELSE
    UPDATE public."AdminMfaCredential" SET "secretCiphertext"=p_secret_ciphertext,"secretIv"=p_secret_iv,"secretTag"=p_secret_tag,
      "backupCodesHash"=p_backup_hashes,"isEnabled"=false,"verifiedAt"=NULL,"lastUsedAt"=NULL,"updatedAt"=p_created_at
      WHERE id=credential_id;
  END IF;
  factor_id:=gen_random_uuid()::text;
  INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"secretCiphertext","secretIv","secretTag","legacySource","legacyCredentialId","createdAt","updatedAt")
  VALUES (factor_id,actor."userId",'TOTP','Authenticator app',p_secret_ciphertext,p_secret_iv,p_secret_tag,
          'MFA_ENROLLMENT_PENDING',actor."userId",p_created_at,p_created_at);
  RETURN jsonb_build_object('factorId',factor_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_totp_enrollment(
  p_mode text,p_pending_cutoff timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb; enrolled boolean;
BEGIN
  IF p_mode NOT IN ('FIRST_ENROLLMENT','REPLACEMENT') OR p_pending_cutoff IS NULL THEN
    RAISE EXCEPTION 'MFA_ENROLLMENT_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-enrollment-load',true);
  SELECT coalesce(bool_or(v),false) INTO enrolled FROM (
    SELECT c."isEnabled" OR c."verifiedAt" IS NOT NULL AS v FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    UNION ALL SELECT true FROM public."AdminWebAuthnCredential" w WHERE w."userId"=actor."userId"
    UNION ALL SELECT true FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f."disabledAt" IS NULL
      AND f."legacySource" IS DISTINCT FROM 'MFA_ENROLLMENT_PENDING'
      AND (f.type='WEBAUTHN' OR (f.type='TOTP' AND (f."lastUsedAt" IS NOT NULL OR f."legacySource"='AdminMfaCredential')))
  ) q;
  IF p_mode='FIRST_ENROLLMENT' AND enrolled THEN RAISE EXCEPTION 'MFA_ALREADY_ENROLLED' USING ERRCODE='23505'; END IF;
  IF p_mode='REPLACEMENT' AND NOT enrolled THEN RAISE EXCEPTION 'MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR' USING ERRCODE='23514'; END IF;
  SELECT jsonb_build_object(
    'credential',(SELECT to_jsonb(x) FROM (
      SELECT c.id,c."secretCiphertext",c."secretIv",c."secretTag",c."backupCodesHash",c."isEnabled",c."verifiedAt"
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    ) x),
    'pending',coalesce((SELECT jsonb_agg(to_jsonb(x)) FROM (
      SELECT f.id,f."secretCiphertext",f."secretIv",f."secretTag",f."createdAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
        AND f."disabledAt" IS NULL AND f."legacySource"='MFA_ENROLLMENT_PENDING' AND f."createdAt">p_pending_cutoff
    ) x),'[]'::jsonb)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_totp_enrollment(
  p_mode text,p_factor_id text,p_secret_ciphertext text,p_secret_iv text,p_secret_tag text,
  p_completed_at timestamp without time zone,p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; hashes text[]; changed integer;
BEGIN
  IF p_mode NOT IN ('FIRST_ENROLLMENT','REPLACEMENT') OR p_factor_id IS NULL OR p_secret_ciphertext IS NULL
     OR p_secret_iv IS NULL OR p_secret_tag IS NULL OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_ENROLLMENT_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-enrollment-complete',true);
  SELECT c."backupCodesHash" INTO hashes FROM public."AdminMfaCredential" c
   WHERE c."userId"=actor."userId" AND NOT c."isEnabled" AND c."verifiedAt" IS NULL
     AND c."secretCiphertext"=p_secret_ciphertext AND c."secretIv"=p_secret_iv AND c."secretTag"=p_secret_tag FOR UPDATE;
  IF NOT FOUND OR NOT EXISTS (
    SELECT 1 FROM public."UserMfaFactor" f WHERE f.id=p_factor_id AND f."userId"=actor."userId"
      AND f.type='TOTP' AND f."disabledAt" IS NULL AND f."legacySource"='MFA_ENROLLMENT_PENDING'
      AND f."secretCiphertext"=p_secret_ciphertext AND f."secretIv"=p_secret_iv AND f."secretTag"=p_secret_tag
  ) THEN RAISE EXCEPTION 'MFA_SETUP_NOT_STARTED' USING ERRCODE='23514'; END IF;
  UPDATE public."UserMfaFactor" SET "disabledAt"=p_completed_at,"updatedAt"=p_completed_at
    WHERE "userId"=actor."userId" AND type='TOTP' AND "disabledAt" IS NULL AND id<>p_factor_id;
  UPDATE public."UserMfaFactor" SET "legacySource"=NULL,"legacyCredentialId"=NULL,"lastUsedAt"=p_completed_at,
    "disabledAt"=NULL,"updatedAt"=p_completed_at WHERE id=p_factor_id AND "userId"=actor."userId";
  UPDATE public."AdminMfaCredential" SET "isEnabled"=true,"verifiedAt"=p_completed_at,"lastUsedAt"=p_completed_at,"updatedAt"=p_completed_at
    WHERE "userId"=actor."userId" AND NOT "isEnabled" AND "verifiedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'MFA_SETUP_NOT_STARTED' USING ERRCODE='23514'; END IF;
  DELETE FROM public."UserBackupCode" WHERE "userId"=actor."userId" AND "usedAt" IS NULL;
  INSERT INTO public."UserBackupCode"(id,"userId","codeHash","createdAt")
    SELECT gen_random_uuid()::text,actor."userId",h,p_completed_at FROM unnest(hashes) h;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action',
    CASE WHEN p_mode='REPLACEMENT' THEN 'AUTH_MFA_REPLACED' ELSE 'AUTH_MFA_ENROLLED' END,
    'entityType','User','entityId',actor."userId",'details',jsonb_build_object('source',
    CASE WHEN p_mode='REPLACEMENT' THEN 'ACTIVE_SESSION' ELSE 'LOGIN_BOOTSTRAP' END),
    'ipHash',p_ip_hash,'userAgent',p_user_agent),current_setting('app.request_id',true),
    nullif(actor."organizationId",''),nullif(actor."licenseeId",''),actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  RETURN jsonb_build_object('enabled',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_mfa_verifiers()
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-verifier-read',true);
  SELECT jsonb_build_object(
    'factors',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."createdAt" DESC) FROM (
      SELECT f.id,f."secretCiphertext",f."secretIv",f."secretTag",f."legacySource",f."lastUsedAt",f."createdAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='TOTP'
        AND f."disabledAt" IS NULL AND f."secretCiphertext" IS NOT NULL
    ) x),'[]'::jsonb),
    'backupCodes',coalesce((SELECT jsonb_agg(jsonb_build_object('id',b.id,'codeHash',b."codeHash")) FROM public."UserBackupCode" b
      WHERE b."userId"=actor."userId" AND b."usedAt" IS NULL),'[]'::jsonb),
    'legacy',(SELECT to_jsonb(x) FROM (
      SELECT c."isEnabled",c."secretCiphertext",c."secretIv",c."secretTag",c."backupCodesHash"
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId"
    ) x)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.consume_admin_mfa_verifier(
  p_method text,p_record_id text,p_expected_legacy_hashes text[],p_next_legacy_hashes text[],
  p_used_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer;
BEGIN
  IF p_method NOT IN ('TOTP_FACTOR','TOTP_LEGACY','BACKUP_CODE','BACKUP_LEGACY') OR p_used_at IS NULL
     OR abs(extract(epoch FROM (p_used_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_VERIFIER_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-verifier-consume',true);
  changed:=0;
  IF p_method='TOTP_FACTOR' THEN
    UPDATE public."UserMfaFactor" SET "lastUsedAt"=p_used_at,"updatedAt"=p_used_at
     WHERE id=p_record_id AND "userId"=actor."userId" AND type='TOTP' AND "disabledAt" IS NULL;
    GET DIAGNOSTICS changed=ROW_COUNT;
  ELSIF p_method='TOTP_LEGACY' THEN
    UPDATE public."AdminMfaCredential" SET "lastUsedAt"=p_used_at,"updatedAt"=p_used_at
     WHERE "userId"=actor."userId" AND "isEnabled";
    GET DIAGNOSTICS changed=ROW_COUNT;
    IF changed=1 THEN
      INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"secretCiphertext","secretIv","secretTag",
        "legacySource","legacyCredentialId","lastUsedAt","createdAt","updatedAt")
      SELECT 'legacy-totp-'||actor."userId",actor."userId",'TOTP','Authenticator app',
        c."secretCiphertext",c."secretIv",c."secretTag",'AdminMfaCredential',actor."userId",
        p_used_at,p_used_at,p_used_at
      FROM public."AdminMfaCredential" c WHERE c."userId"=actor."userId" AND c."isEnabled"
      ON CONFLICT (id) DO UPDATE SET "disabledAt"=NULL,"lastUsedAt"=p_used_at,"updatedAt"=p_used_at;
    END IF;
  ELSIF p_method='BACKUP_CODE' THEN
    UPDATE public."UserBackupCode" SET "usedAt"=p_used_at
     WHERE id=p_record_id AND "userId"=actor."userId" AND "usedAt" IS NULL;
    GET DIAGNOSTICS changed=ROW_COUNT;
  ELSE
    UPDATE public."AdminMfaCredential" SET "backupCodesHash"=p_next_legacy_hashes,"lastUsedAt"=p_used_at,"updatedAt"=p_used_at
     WHERE "userId"=actor."userId" AND "isEnabled" AND "backupCodesHash"=p_expected_legacy_hashes;
    GET DIAGNOSTICS changed=ROW_COUNT;
  END IF;
  RETURN jsonb_build_object('consumed',changed=1);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.replace_admin_backup_codes(
  p_hashes text[],p_replaced_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF cardinality(p_hashes) NOT BETWEEN 1 AND 20 OR p_replaced_at IS NULL
     OR abs(extract(epoch FROM (p_replaced_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_BACKUP_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-backup-replace',true);
  DELETE FROM public."UserBackupCode" WHERE "userId"=actor."userId" AND "usedAt" IS NULL;
  INSERT INTO public."UserBackupCode"(id,"userId","codeHash","createdAt")
    SELECT gen_random_uuid()::text,actor."userId",h,p_replaced_at FROM unnest(p_hashes) h;
  UPDATE public."AdminMfaCredential" SET "backupCodesHash"=p_hashes,"lastUsedAt"=p_replaced_at,"updatedAt"=p_replaced_at
    WHERE "userId"=actor."userId";
  RETURN jsonb_build_object('replaced',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.disable_admin_mfa(
  p_disabled_at timestamp without time zone,p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record;
BEGIN
  IF p_disabled_at IS NULL OR abs(extract(epoch FROM (p_disabled_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_DISABLE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-disable',true);
  UPDATE public."AdminMfaCredential" SET "backupCodesHash"='{}',"isEnabled"=false,"verifiedAt"=NULL,"lastUsedAt"=NULL,"updatedAt"=p_disabled_at
    WHERE "userId"=actor."userId";
  UPDATE public."UserMfaFactor" SET "disabledAt"=p_disabled_at,"updatedAt"=p_disabled_at
    WHERE "userId"=actor."userId" AND "disabledAt" IS NULL;
  DELETE FROM public."AdminWebAuthnCredential" WHERE "userId"=actor."userId";
  DELETE FROM public."UserBackupCode" WHERE "userId"=actor."userId" AND "usedAt" IS NULL;
  UPDATE public."RefreshToken" SET "revokedAt"=p_disabled_at,"revokedReason"='MFA_DISABLED',"lastUsedAt"=p_disabled_at,
    "sessionCapabilityRevokedAt"=p_disabled_at,"sessionCapabilityRevokedReason"='MFA_DISABLED'
    WHERE "userId"=actor."userId" AND "revokedAt" IS NULL;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_MFA_DISABLED','entityType','User',
    'entityId',actor."userId",'details',jsonb_build_object('actorUserId',actor."userId"),'ipHash',p_ip_hash,'userAgent',p_user_agent),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_disabled_at+interval '1 day',p_disabled_at);
  RETURN jsonb_build_object('enabled',false);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_admin_mfa_challenge(
  p_kind text,p_ticket_hash text,p_session_binding_hash text,p_purpose text,p_risk_score integer,p_risk_level text,
  p_reasons text[],p_ip_hash text,p_user_agent_hash text,p_max_attempts integer,
  p_created_at timestamp without time zone,p_expires_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; challenge_id text:=gen_random_uuid()::text;
BEGIN
  IF p_kind NOT IN ('LOGIN','SESSION') OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_purpose NOT IN ('admin_login','high_risk_action')
     OR (p_kind='LOGIN') IS DISTINCT FROM (p_purpose='admin_login')
     OR (p_kind='SESSION') IS DISTINCT FROM (p_session_binding_hash IS NOT NULL)
     OR (p_session_binding_hash IS NOT NULL AND p_session_binding_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$')
     OR p_risk_score NOT BETWEEN 0 AND 100 OR p_risk_level NOT IN ('LOW','MEDIUM','HIGH','CRITICAL')
     OR cardinality(p_reasons)>12 OR p_max_attempts NOT BETWEEN 1 AND 10 OR p_created_at IS NULL
     OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '15 minutes'
     OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-create',true),
          set_config('app.auth_closure_challenge_id',challenge_id,true),
          set_config('app.auth_closure_challenge_hash',p_ticket_hash,true);
  IF p_kind='LOGIN' THEN
    INSERT INTO public."MfaLoginChallenge"(id,"userId","ticketHash",purpose,"riskScore","riskLevel",reasons,
      "createdIpHash","createdUserAgentHash",attempts,"maxAttempts","createdAt","updatedAt","expiresAt")
    VALUES (challenge_id,actor."userId",p_ticket_hash,p_purpose,p_risk_score,p_risk_level::public."AuthRiskLevel",
      p_reasons,p_ip_hash,p_user_agent_hash,0,p_max_attempts,p_created_at,p_created_at,p_expires_at);
  ELSE
    UPDATE public."AuthMfaChallenge" SET "supersededAt"=p_created_at,"updatedAt"=p_created_at
     WHERE "userId"=actor."userId" AND purpose=p_purpose AND "sessionBindingHash"=p_session_binding_hash
       AND "consumedAt" IS NULL AND "supersededAt" IS NULL AND "expiresAt">p_created_at;
    INSERT INTO public."AuthMfaChallenge"(id,"userId","ticketHash","sessionBindingHash",purpose,"riskScore","riskLevel",reasons,
      "createdIpHash","createdUserAgentHash",attempts,"maxAttempts","createdAt","updatedAt","expiresAt")
    VALUES (challenge_id,actor."userId",p_ticket_hash,p_session_binding_hash,p_purpose,p_risk_score,p_risk_level::public."AuthRiskLevel",
      p_reasons,p_ip_hash,p_user_agent_hash,0,p_max_attempts,p_created_at,p_created_at,p_expires_at);
  END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_MFA_CHALLENGE_ISSUED',
    'entityType','MfaChallenge','entityId',challenge_id,'details',jsonb_build_object('purpose',p_purpose,
    'riskScore',p_risk_score,'riskLevel',p_risk_level,'sessionBound',p_kind='SESSION',
    'ttlMs',round(extract(epoch FROM (p_expires_at-p_created_at))*1000),
    'ttlMinutes',round(extract(epoch FROM (p_expires_at-p_created_at))/60))),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_created_at+interval '1 day',p_created_at);
  RETURN jsonb_build_object('challengeId',challenge_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_mfa_challenge(
  p_ticket_hashes text[],p_session_binding_hashes text[],p_checked_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  IF cardinality(p_ticket_hashes) NOT BETWEEN 1 AND 3 OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-read',true);
  SELECT to_jsonb(x) INTO result FROM (
    SELECT 'LOGIN'::text AS kind,c.id,c."userId",c.purpose,c."riskScore",c."riskLevel"::text AS "riskLevel",
      c.reasons,c.attempts,c."maxAttempts",c."createdIpHash",c."createdUserAgentHash",
      c."expiresAt" AT TIME ZONE 'UTC' AS "expiresAt",
      c."consumedAt" AT TIME ZONE 'UTC' AS "consumedAt",NULL::timestamp with time zone AS "supersededAt"
    FROM public."MfaLoginChallenge" c WHERE c."userId"=actor."userId" AND c."ticketHash"=ANY(p_ticket_hashes)
    UNION ALL
    SELECT 'SESSION',c.id,c."userId",c.purpose,c."riskScore",c."riskLevel"::text,c.reasons,c.attempts,c."maxAttempts",
      c."createdIpHash",c."createdUserAgentHash",c."expiresAt" AT TIME ZONE 'UTC',
      c."consumedAt" AT TIME ZONE 'UTC',c."supersededAt" AT TIME ZONE 'UTC'
    FROM public."AuthMfaChallenge" c WHERE c."userId"=actor."userId" AND c."ticketHash"=ANY(p_ticket_hashes)
      AND c."sessionBindingHash"=ANY(p_session_binding_hashes)
  ) x LIMIT 1;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.record_admin_mfa_challenge_failure(
  p_kind text,p_challenge_id text,p_action text,p_expected_attempts integer,p_failed_at timestamp without time zone,
  p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer; next_attempts integer:=p_expected_attempts;
BEGIN
  IF p_kind NOT IN ('LOGIN','SESSION') OR p_action NOT IN ('AUTH_MFA_CHALLENGE_EXPIRED','AUTH_MFA_FAILURE','AUTH_MFA_TOO_MANY_ATTEMPTS')
     OR p_expected_attempts NOT BETWEEN 0 AND 10 OR p_failed_at IS NULL
     OR abs(extract(epoch FROM (p_failed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-fail',true);
  IF p_kind='LOGIN' THEN
    UPDATE public."MfaLoginChallenge" SET attempts=p_expected_attempts,"updatedAt"=p_failed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND attempts<=p_expected_attempts;
  ELSE
    UPDATE public."AuthMfaChallenge" SET attempts=p_expected_attempts,"updatedAt"=p_failed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "supersededAt" IS NULL AND attempts<=p_expected_attempts;
  END IF;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'MFA_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action',p_action,'entityType','MfaChallenge',
    'entityId',p_challenge_id,'details',jsonb_build_object('attempts',next_attempts),'ipHash',p_ip_hash,'userAgent',p_user_agent),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_failed_at+interval '1 day',p_failed_at);
  RETURN jsonb_build_object('recorded',true,'attempts',next_attempts);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_mfa_challenge(
  p_kind text,p_challenge_id text,p_method text,p_completed_at timestamp without time zone,p_ip_hash text,p_user_agent text
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; challenge record;
BEGIN
  IF p_kind NOT IN ('LOGIN','SESSION') OR p_method NOT IN ('TOTP','BACKUP_CODE') OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'MFA_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-challenge-complete',true);
  IF p_kind='LOGIN' THEN
    UPDATE public."MfaLoginChallenge" SET "consumedAt"=p_completed_at,"updatedAt"=p_completed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "expiresAt">p_completed_at
    RETURNING "riskScore","riskLevel",reasons INTO challenge;
  ELSE
    UPDATE public."AuthMfaChallenge" SET "consumedAt"=p_completed_at,"updatedAt"=p_completed_at
     WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "supersededAt" IS NULL AND "expiresAt">p_completed_at
    RETURNING "riskScore","riskLevel",reasons INTO challenge;
  END IF;
  IF NOT FOUND THEN RAISE EXCEPTION 'MFA_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action',
    CASE WHEN p_method='BACKUP_CODE' THEN 'AUTH_MFA_BACKUP_CODE_USED' ELSE 'AUTH_MFA_SUCCESS' END,
    'entityType','MfaChallenge','entityId',p_challenge_id,'details',jsonb_build_object('method',p_method),
    'ipHash',p_ip_hash,'userAgent',p_user_agent),current_setting('app.request_id',true),
    nullif(actor."organizationId",''),nullif(actor."licenseeId",''),actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_MFA_LOGIN_COMPLETE',
    'entityType','User','entityId',actor."userId",'details',jsonb_build_object('riskScore',challenge."riskScore",
    'riskLevel',challenge."riskLevel",'reasons',challenge.reasons),'ipHash',p_ip_hash,'userAgent',p_user_agent),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  RETURN jsonb_build_object('completed',true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_webauthn_credentials()
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-read',true);
  SELECT jsonb_build_object(
    'factors',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT f.id,f.label,f."credentialId",f."publicKey",f.counter,f.transports,f."lastUsedAt",f."createdAt",f."updatedAt"
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='WEBAUTHN'
        AND f."disabledAt" IS NULL AND f."credentialId" IS NOT NULL AND f."publicKey" IS NOT NULL
    ) x),'[]'::jsonb),
    'legacy',coalesce((SELECT jsonb_agg(to_jsonb(x) ORDER BY x."lastUsedAt" DESC NULLS LAST,x."createdAt" DESC) FROM (
      SELECT c.id,c.label,c."credentialId",c."publicKeySpki",c."publicKeyAlgorithm",c.counter,c.transports,
        c."lastUsedAt",c."createdAt",c."updatedAt"
      FROM public."AdminWebAuthnCredential" c WHERE c."userId"=actor."userId"
    ) x),'[]'::jsonb)
  ) INTO result;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_admin_webauthn_challenge(
  p_purpose text,p_ticket_hash text,p_challenge_hash text,p_ip_hash text,p_user_agent_hash text,
  p_origin text,p_rp_id text,p_created_at timestamp without time zone,p_expires_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; challenge_id text:=gen_random_uuid()::text; credential_ids text[];
BEGIN
  IF p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP') OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_challenge_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR length(coalesce(p_origin,''))>512
     OR length(coalesce(p_rp_id,'')) NOT BETWEEN 1 AND 253 OR p_created_at IS NULL
     OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '15 minutes'
     OR abs(extract(epoch FROM (p_created_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-challenge-create',true),
          set_config('app.auth_closure_challenge_id',challenge_id,true),
          set_config('app.auth_closure_challenge_hash',p_ticket_hash,true);
  SELECT coalesce(array_agg(id ORDER BY id),'{}'::text[]) INTO credential_ids FROM (
    SELECT f."credentialId" AS id FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId"
      AND f.type='WEBAUTHN' AND f."disabledAt" IS NULL AND f."credentialId" IS NOT NULL AND f."publicKey" IS NOT NULL
    UNION SELECT c."credentialId" FROM public."AdminWebAuthnCredential" c WHERE c."userId"=actor."userId"
  ) q;
  IF p_purpose IN ('LOGIN','STEP_UP') AND cardinality(credential_ids)=0 THEN
    RAISE EXCEPTION 'WEBAUTHN_NOT_ENROLLED' USING ERRCODE='P0002';
  END IF;
  INSERT INTO public."AuthWebAuthnChallenge"(id,"userId",purpose,"ticketHash","challengeHash","credentialIds",
    "createdIpHash","createdUserAgentHash",origin,"rpId","createdAt","expiresAt")
  VALUES (challenge_id,actor."userId",p_purpose,p_ticket_hash,p_challenge_hash,credential_ids,
    p_ip_hash,p_user_agent_hash,p_origin,p_rp_id,p_created_at,p_expires_at);
  RETURN jsonb_build_object('challengeId',challenge_id,'credentialIds',to_jsonb(credential_ids));
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_admin_webauthn_challenge(
  p_ticket_hashes text[],p_purpose text,p_credential_id text,p_checked_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; result jsonb;
BEGIN
  IF cardinality(p_ticket_hashes) NOT BETWEEN 1 AND 3 OR p_purpose NOT IN ('ENROLLMENT','LOGIN','STEP_UP')
     OR p_checked_at IS NULL OR abs(extract(epoch FROM (p_checked_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-challenge-read',true);
  SELECT jsonb_build_object(
    'challenge',jsonb_build_object(
      'id',c.id,'userId',c."userId",'challengeHash',c."challengeHash",
      'origin',c.origin,'rpId',c."rpId"
    ),
    'factor',(SELECT to_jsonb(x) FROM (
      SELECT f.id,f."credentialId",f."publicKey",f.counter,f.transports
      FROM public."UserMfaFactor" f WHERE f."userId"=actor."userId" AND f.type='WEBAUTHN'
        AND f."disabledAt" IS NULL AND f."credentialId"=p_credential_id
    ) x),
    'legacy',(SELECT to_jsonb(x) FROM (
      SELECT w.id,w."credentialId",w."publicKeySpki",w."publicKeyAlgorithm",w.counter,w.transports
      FROM public."AdminWebAuthnCredential" w WHERE w."userId"=actor."userId" AND w."credentialId"=p_credential_id
    ) x)
  ) INTO result
  FROM public."AuthWebAuthnChallenge" c WHERE c."userId"=actor."userId" AND c."ticketHash"=ANY(p_ticket_hashes)
    AND c.purpose=p_purpose AND c."consumedAt" IS NULL AND c."expiresAt">p_checked_at;
  RETURN result;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_webauthn_registration(
  p_challenge_id text,p_credential_id text,p_label text,p_public_key text,p_counter integer,p_transports text[],
  p_device_type text,p_backed_up boolean,p_completed_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; factor_id text;
BEGIN
  IF p_credential_id IS NULL OR length(p_credential_id)>1024 OR p_public_key IS NULL OR length(p_public_key)>16384
     OR length(coalesce(p_label,''))>128 OR p_counter<0 OR cardinality(p_transports)>16 OR p_completed_at IS NULL
     OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_REGISTRATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-registration-complete',true);
  IF NOT EXISTS (SELECT 1 FROM public."AuthWebAuthnChallenge" c WHERE c.id=p_challenge_id AND c."userId"=actor."userId"
    AND c.purpose='ENROLLMENT' AND c."consumedAt" IS NULL AND c."expiresAt">p_completed_at) THEN
    RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002';
  END IF;
  IF EXISTS (SELECT 1 FROM public."UserMfaFactor" f WHERE f."credentialId"=p_credential_id AND f."userId"<>actor."userId")
     OR EXISTS (SELECT 1 FROM public."AdminWebAuthnCredential" w WHERE w."credentialId"=p_credential_id AND w."userId"<>actor."userId") THEN
    RAISE EXCEPTION 'WEBAUTHN_CREDENTIAL_CONFLICT' USING ERRCODE='23505';
  END IF;
  SELECT f.id INTO factor_id FROM public."UserMfaFactor" f WHERE f."credentialId"=p_credential_id FOR UPDATE;
  IF factor_id IS NULL THEN
    factor_id:=gen_random_uuid()::text;
    INSERT INTO public."UserMfaFactor"(id,"userId",type,label,"credentialId","publicKey",counter,transports,
      "credentialDeviceType","credentialBackedUp","lastUsedAt","createdAt","updatedAt")
    VALUES (factor_id,actor."userId",'WEBAUTHN',coalesce(nullif(trim(p_label),''),'Passkey'),p_credential_id,p_public_key,
      p_counter,p_transports,p_device_type,p_backed_up,p_completed_at,p_completed_at,p_completed_at);
  ELSE
    UPDATE public."UserMfaFactor" SET "userId"=actor."userId",type='WEBAUTHN',label=coalesce(nullif(trim(p_label),''),'Passkey'),
      "publicKey"=p_public_key,counter=p_counter,transports=p_transports,"credentialDeviceType"=p_device_type,
      "credentialBackedUp"=p_backed_up,"lastUsedAt"=p_completed_at,"disabledAt"=NULL,"updatedAt"=p_completed_at
      WHERE id=factor_id AND "userId"=actor."userId";
  END IF;
  UPDATE public."AuthWebAuthnChallenge" SET "consumedAt"=p_completed_at
   WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "expiresAt">p_completed_at;
  IF NOT FOUND THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
  VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_WEBAUTHN_ENROLLED',
    'entityType','User','entityId',actor."userId",'details',jsonb_build_object('label',coalesce(nullif(trim(p_label),''),'Passkey'))),
    current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
    actor."userId",actor.role,p_completed_at+interval '1 day',p_completed_at);
  RETURN jsonb_build_object('ok',true,'credentialId',p_credential_id);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.complete_admin_webauthn_authentication(
  p_challenge_id text,p_credential_kind text,p_credential_row_id text,p_expected_counter integer,p_next_counter integer,
  p_device_type text,p_backed_up boolean,p_completed_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer; purpose text;
BEGIN
  IF p_credential_kind NOT IN ('FACTOR','LEGACY') OR p_expected_counter<0 OR p_next_counter<0
     OR (p_next_counter>0 AND p_expected_counter>0 AND p_next_counter<=p_expected_counter)
     OR p_completed_at IS NULL OR abs(extract(epoch FROM (p_completed_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_AUTHENTICATION_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-authentication-complete',true);
  SELECT c.purpose INTO purpose FROM public."AuthWebAuthnChallenge" c WHERE c.id=p_challenge_id AND c."userId"=actor."userId"
    AND c.purpose IN ('LOGIN','STEP_UP') AND c."consumedAt" IS NULL AND c."expiresAt">p_completed_at FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  IF p_credential_kind='FACTOR' THEN
    UPDATE public."UserMfaFactor" SET counter=greatest(counter,p_next_counter),"credentialDeviceType"=p_device_type,
      "credentialBackedUp"=p_backed_up,"lastUsedAt"=p_completed_at,"updatedAt"=p_completed_at
      WHERE id=p_credential_row_id AND "userId"=actor."userId" AND type='WEBAUTHN' AND "disabledAt" IS NULL
        AND counter=p_expected_counter;
  ELSE
    UPDATE public."AdminWebAuthnCredential" SET counter=greatest(counter,p_next_counter),"lastUsedAt"=p_completed_at,"updatedAt"=p_completed_at
      WHERE id=p_credential_row_id AND "userId"=actor."userId" AND counter=p_expected_counter;
  END IF;
  GET DIAGNOSTICS changed=ROW_COUNT;
  IF changed<>1 THEN RAISE EXCEPTION 'WEBAUTHN_COUNTER_REPLAY' USING ERRCODE='40001'; END IF;
  UPDATE public."AuthWebAuthnChallenge" SET "consumedAt"=p_completed_at
    WHERE id=p_challenge_id AND "userId"=actor."userId" AND "consumedAt" IS NULL AND "expiresAt">p_completed_at;
  IF NOT FOUND THEN RAISE EXCEPTION 'WEBAUTHN_CHALLENGE_NOT_FOUND' USING ERRCODE='P0002'; END IF;
  RETURN jsonb_build_object('ok',true,'purpose',purpose);
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.delete_admin_webauthn_credential(
  p_credential_row_id text,p_deleted_at timestamp without time zone
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor record; changed integer:=0; delta integer;
BEGIN
  IF p_credential_row_id IS NULL OR p_deleted_at IS NULL
     OR abs(extract(epoch FROM (p_deleted_at-clock_timestamp())))>300 THEN
    RAISE EXCEPTION 'WEBAUTHN_DELETE_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT * INTO actor FROM app_rls.b01_admin_mfa_actor();
  PERFORM pg_advisory_xact_lock(hashtextextended('mfa_state:'||actor."userId",0));
  PERFORM set_config('app.auth_closure_operation','mfa-webauthn-delete',true);
  UPDATE public."UserMfaFactor" SET "disabledAt"=p_deleted_at,"updatedAt"=p_deleted_at
    WHERE id=p_credential_row_id AND "userId"=actor."userId" AND type='WEBAUTHN' AND "disabledAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  DELETE FROM public."AdminWebAuthnCredential" WHERE id=p_credential_row_id AND "userId"=actor."userId";
  GET DIAGNOSTICS delta=ROW_COUNT;
  IF changed+delta>0 THEN
    INSERT INTO public."AuditLogOutbox"(id,payload,"requestId","organizationId","licenseeId","initiatingUserId","initiatingActorRoleSnapshot","expiresAt","updatedAt")
    VALUES (gen_random_uuid()::text,jsonb_build_object('userId',actor."userId",'action','AUTH_WEBAUTHN_CREDENTIAL_REMOVED',
      'entityType','User','entityId',actor."userId",'details',jsonb_build_object('credentialId',p_credential_row_id)),
      current_setting('app.request_id',true),nullif(actor."organizationId",''),nullif(actor."licenseeId",''),
      actor."userId",actor.role,p_deleted_at+interval '1 day',p_deleted_at);
  END IF;
  RETURN jsonb_build_object('deleted',changed+delta>0);
END
$fn$;

REVOKE ALL ON FUNCTION app_rls.b01_authenticated_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_manufacturer_scope(text,text,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.find_refresh_token_by_id(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.require_recent_mfa_session(text,timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_recent_auth_session_risk_inputs(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_password_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.list_active_refresh_tokens(text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.prove_authenticated_password_step_up(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.require_recent_sensitive_session(text,timestamp without time zone,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.request_authenticated_email_change(text,text,text,timestamp without time zone,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.update_authenticated_profile(text,boolean,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.change_authenticated_password(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.b01_admin_mfa_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_mfa_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.begin_admin_totp_enrollment(text,text,text,text,text[],timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_totp_enrollment(text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_totp_enrollment(text,text,text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_mfa_verifiers() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.consume_admin_mfa_verifier(text,text,text[],text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.replace_admin_backup_codes(text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.disable_admin_mfa(timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_admin_mfa_challenge(text,text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_mfa_challenge(text[],text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.record_admin_mfa_challenge_failure(text,text,text,integer,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_mfa_challenge(text,text,text,timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_webauthn_credentials() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_admin_webauthn_challenge(text,text,text,text,text,text,text,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_admin_webauthn_challenge(text[],text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_webauthn_registration(text,text,text,text,integer,text[],text,boolean,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.complete_admin_webauthn_authentication(text,text,text,integer,integer,text,boolean,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.delete_admin_webauthn_credential(text,timestamp without time zone) FROM PUBLIC;
