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
BEGIN
  IF p_user_id IS DISTINCT FROM current_setting('app.b01_preauth_user_id',true)
     OR p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_expires_at<=p_created_at
     OR p_expires_at>p_created_at+interval '31 days' THEN RAISE EXCEPTION 'AUTH_LOGIN_SESSION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_closure_operation','login-session-create',true),set_config('app.auth_closure_user_id',p_user_id,true),
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

REVOKE ALL ON FUNCTION app_rls.b01_authenticated_actor(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.find_refresh_token_by_id(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.require_recent_mfa_session(text,timestamp without time zone,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_recent_auth_session_risk_inputs(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.record_auth_session_risk_signal(integer,text,text[],text,text,timestamp without time zone,text,text,text,timestamp without time zone,integer,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
