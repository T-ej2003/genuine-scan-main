-- Reviewed production B01 refresh boundary.  The caller only supplies bearer
-- hash candidates; every other scope is derived from the locked predecessor.
-- {{AUTH_OWNER}} is substituted by the clean-room package generator.

CREATE OR REPLACE FUNCTION app_auth.b01_bind_bearer(p_hashes text[], p_request_id text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF coalesce(array_length(p_hashes, 1), 0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_hashes) AS h WHERE h !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$')
     OR (SELECT count(DISTINCT h) FROM unnest(p_hashes) AS h) <> array_length(p_hashes, 1)
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128 OR p_request_id !~ '^[!-~]+$' THEN
    RAISE EXCEPTION 'B01_REFRESH_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  -- Reset all derived values before the first protected read.  A pre-auth
  -- caller can set arbitrary custom GUCs, but cannot retain them across this
  -- reviewed function boundary.
  PERFORM set_config('app.b01_user_id','',true),
          set_config('app.b01_organization_id','',true),
          set_config('app.b01_predecessor_id','',true),
          set_config('app.b01_successor_id','',true),
          set_config('app.b01_operation','',true),
          set_config('app.b01_token_hashes', array_to_string(p_hashes, ','), true),
          set_config('app.b01_request_id', p_request_id, true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.b01_bind_predecessor(
  p_token_id text, p_user_id text, p_organization_id text, p_operation text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
BEGIN
  IF p_token_id IS NULL THEN RAISE EXCEPTION 'B01_REFRESH_TOKEN_CONTEXT_DENIED' USING ERRCODE='42501'; END IF;
  IF p_user_id IS NULL THEN RAISE EXCEPTION 'B01_REFRESH_USER_CONTEXT_DENIED' USING ERRCODE='42501'; END IF;
  IF p_operation NOT IN ('claim','load-state','create-mfa','revoke-scope','complete-rotation','reuse-revoke','account-unavailable','stale-membership') THEN
    RAISE EXCEPTION 'B01_REFRESH_OPERATION_DENIED' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.b01_predecessor_id',p_token_id,true),
          set_config('app.b01_user_id',p_user_id,true),
          set_config('app.b01_organization_id',coalesce(p_organization_id,''),true),
          set_config('app.b01_operation',p_operation,true);
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.b01_audit(p_action text, p_token_id text, p_at timestamp without time zone)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
BEGIN
  INSERT INTO public."AuditLogOutbox" ("id",payload,"updatedAt") VALUES (
    gen_random_uuid()::text,
    jsonb_build_object('userId',current_setting('app.b01_user_id',true),'action',p_action,
      'entityType','RefreshToken','entityId',p_token_id,'details',jsonb_build_object(
        'requestId',current_setting('app.b01_request_id',true),'boundary','b01-refresh-rotation')),
    p_at
  );
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.claim_refresh_token_rotation(
  p_hashes text[], p_checked_at timestamp without time zone, p_request_id text
) RETURNS TABLE("disposition" text,"tokenId" text,"userId" text,"role" text,"organizationId" text,
  "licenseeId" text,"manufacturerId" text,"authAssurance" text,"expiresAt" timestamp without time zone,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; u record; selected_licensee text; selected_manufacturer text; candidate_count integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  IF p_checked_at IS NULL OR abs(extract(epoch FROM p_checked_at-clock_timestamp())) > 300 THEN
    RAISE EXCEPTION 'B01_REFRESH_INPUT_DENIED' USING ERRCODE='22023';
  END IF;
  SELECT count(*) INTO candidate_count FROM public."RefreshToken" rt WHERE rt."tokenHash"=ANY(p_hashes);
  IF candidate_count=0 THEN RETURN; END IF;
  IF candidate_count<>1 THEN RAISE EXCEPTION 'B01_REFRESH_CLAIM_AMBIGUOUS' USING ERRCODE='42501'; END IF;
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'claim');
  SELECT usr.id,usr.email,usr.name,usr.role,usr."orgId",usr."licenseeId",usr.status,usr."isActive",usr."disabledAt",usr."deletedAt",usr."emailVerifiedAt" INTO u FROM public."User" usr WHERE usr.id=t."userId";
  IF NOT FOUND OR NOT u."isActive" OR u."status"::text<>'ACTIVE' OR u."disabledAt" IS NOT NULL OR u."deletedAt" IS NOT NULL THEN
    PERFORM set_config('app.b01_operation','account-unavailable',true);
    UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='ACCOUNT_UNAVAILABLE',"lastUsedAt"=p_checked_at
      WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL;
    PERFORM app_auth.b01_audit('AUTH_REFRESH_DISABLED_DENIED',t.id,p_checked_at);
    RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
  END IF;
  IF t."revokedAt" IS NOT NULL THEN
    IF t."replacedByTokenHash" IS NOT NULL THEN
      PERFORM set_config('app.b01_operation','reuse-revoke',true);
      UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='REUSE_DETECTED',"lastUsedAt"=p_checked_at
        WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL;
      PERFORM app_auth.b01_audit('AUTH_REFRESH_REUSE_DETECTED',t.id,p_checked_at);
      RETURN QUERY SELECT 'REUSE_DETECTED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt";
    ELSE RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; END IF;
    RETURN;
  END IF;
  IF t."expiresAt"<=p_checked_at THEN
    UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='EXPIRED',"lastUsedAt"=p_checked_at WHERE rt.id=t.id;
    PERFORM app_auth.b01_audit('AUTH_REFRESH_EXPIRED',t.id,p_checked_at);
    RETURN QUERY SELECT 'EXPIRED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
  END IF;
  IF t."rotationRequestId" IS NOT NULL AND t."rotationRequestId" IS DISTINCT FROM p_request_id THEN
    RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
  END IF;
  IF u.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT l.id INTO selected_licensee FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=u.id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive" ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId" LIMIT 1;
    IF selected_licensee IS NULL THEN
      PERFORM set_config('app.b01_operation','stale-membership',true);
      UPDATE public."RefreshToken" rt SET "revokedAt"=p_checked_at,"revokedReason"='STALE_MEMBERSHIP',"lastUsedAt"=p_checked_at WHERE rt."userId"=u.id AND rt."revokedAt" IS NULL;
      PERFORM app_auth.b01_audit('AUTH_REFRESH_STALE_MEMBERSHIP_DENIED',t.id,p_checked_at);
      RETURN QUERY SELECT 'REVOKED',t.id,t."userId",NULL,NULL,NULL,NULL,NULL,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt"; RETURN;
    END IF;
    selected_manufacturer:=u.id;
  ELSIF u.role::text IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    SELECT l.id INTO selected_licensee FROM public."Licensee" l JOIN public."Organization" o ON o.id=l."orgId"
      WHERE l.id=u."licenseeId" AND l."orgId" IS NOT DISTINCT FROM t."orgId" AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF selected_licensee IS NULL THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  ELSIF u."orgId" IS DISTINCT FROM t."orgId" THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501';
  ELSE selected_licensee:=u."licenseeId"; selected_manufacturer:=NULL; END IF;
  UPDATE public."RefreshToken" rt SET "rotationRequestId"=p_request_id,"rotationClaimedAt"=coalesce(rt."rotationClaimedAt",p_checked_at) WHERE rt.id=t.id;
  RETURN QUERY SELECT 'ACTIVE',t.id,u.id,u.role::text,t."orgId",selected_licensee,selected_manufacturer,
    CASE WHEN t."mfaVerifiedAt" IS NULL THEN 'password-verified' ELSE 'mfa-verified' END,t."expiresAt",t."authenticatedAt",t."mfaVerifiedAt";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.load_refresh_session_state(
  p_token_id text,p_hashes text[],p_requested_licensee_id text,p_requested_scope_version text,p_checked_at timestamp without time zone,p_request_id text
) RETURNS TABLE("userId" text,"email" text,"name" text,"role" text,"legacyLicenseeId" text,"legacyOrganizationId" text,"emailVerifiedAt" timestamp without time zone,"sessionLicenseeId" text,"sessionOrganizationId" text,"scopeVersion" text,"selectedLicenseeId" text,"selectedLicenseeName" text,"selectedLicenseePrefix" text,"selectedLicenseeBrandName" text,"selectedLicenseeOrganizationId" text,"linkedLicensees" jsonb,"mfaRequired" boolean,"mfaEnabled" boolean,"mfaEnrolled" boolean,"mfaLastUsedAt" timestamp without time zone,"mfaMethods" text[],"mfaPreferredMethod" text)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; u record; selected record; links jsonb; mfa_enabled boolean; mfa_last timestamp without time zone; methods text[];
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'load-state');
  IF t."revokedAt" IS NOT NULL OR t."expiresAt"<=p_checked_at OR t."rotationRequestId" IS DISTINCT FROM p_request_id THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  SELECT usr.id,usr.email,usr.name,usr.role,usr."orgId",usr."licenseeId",usr.status,usr."isActive",usr."disabledAt",usr."deletedAt",usr."emailVerifiedAt" INTO u FROM public."User" usr WHERE usr.id=t."userId" AND usr."isActive" AND usr."status"::text='ACTIVE' AND usr."disabledAt" IS NULL AND usr."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED' USING ERRCODE='42501'; END IF;
  SELECT coalesce(bool_or(x.enabled),false),max(x."lastUsedAt"),coalesce(array_agg(DISTINCT x.method) FILTER (WHERE x.enabled),'{}'::text[]) INTO mfa_enabled,mfa_last,methods FROM (
    SELECT "isEnabled" AS enabled,"lastUsedAt",'TOTP'::text AS method FROM public."AdminMfaCredential" WHERE "userId"=u.id
    UNION ALL SELECT TRUE,"lastUsedAt",'WEBAUTHN' FROM public."AdminWebAuthnCredential" WHERE "userId"=u.id
    UNION ALL SELECT TRUE,"lastUsedAt",type FROM public."UserMfaFactor" WHERE "userId"=u.id AND "disabledAt" IS NULL AND type IN ('TOTP','WEBAUTHN')
  ) x;
  IF EXISTS (SELECT 1 FROM public."UserBackupCode" WHERE "userId"=u.id AND "usedAt" IS NULL) AND 'TOTP'=ANY(methods) THEN methods:=array_append(methods,'BACKUP_CODE'); END IF;
  IF u.role::text IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT l.id,l.name,l.prefix,l."brandName",l."orgId",ml."isPrimary",ml."updatedAt" INTO selected FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId"
      WHERE ml."manufacturerId"=u.id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive" AND (p_requested_licensee_id IS NULL OR l.id=p_requested_licensee_id) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId" LIMIT 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED' USING ERRCODE='42501'; END IF;
    IF p_requested_licensee_id IS NOT NULL AND (p_requested_scope_version IS NULL OR to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')<>p_requested_scope_version) THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_STALE' USING ERRCODE='42501'; END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',l.id,'name',l.name,'prefix',l.prefix,'brandName',l."brandName",'orgId',l."orgId",'isPrimary',ml."isPrimary",'scopeVersion',to_char(ml."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) ORDER BY ml."isPrimary" DESC,ml."createdAt",ml."licenseeId"),'[]'::jsonb) INTO links FROM public."ManufacturerLicenseeLink" ml JOIN public."Licensee" l ON l.id=ml."licenseeId" JOIN public."Organization" o ON o.id=l."orgId" WHERE ml."manufacturerId"=u.id AND l."isActive" AND l."suspendedAt" IS NULL AND o."isActive";
    IF p_requested_licensee_id IS NOT NULL THEN PERFORM app_auth.b01_audit('MANUFACTURER_SCOPE_SWITCH',t.id,p_checked_at); END IF;
    RETURN QUERY SELECT u.id,u.email,u.name,u.role::text,u."licenseeId",u."orgId",u."emailVerifiedAt",selected.id,selected."orgId",to_char(selected."updatedAt" AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),selected.id,selected.name,selected.prefix,selected."brandName",selected."orgId",links,TRUE,mfa_enabled,mfa_enabled,mfa_last,methods,CASE WHEN 'WEBAUTHN'=ANY(methods) THEN 'WEBAUTHN' WHEN 'TOTP'=ANY(methods) THEN 'TOTP' ELSE NULL END;
  ELSE
    IF p_requested_licensee_id IS NOT NULL OR p_requested_scope_version IS NOT NULL THEN RAISE EXCEPTION 'B01_SCOPE_SWITCH_ROLE_DENIED' USING ERRCODE='42501'; END IF;
    RETURN QUERY SELECT u.id,u.email,u.name,u.role::text,u."licenseeId",u."orgId",u."emailVerifiedAt",u."licenseeId",u."orgId",NULL,NULL,NULL,NULL,NULL,NULL,'[]'::jsonb,(u.role::text IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN')),mfa_enabled,mfa_enabled,mfa_last,methods,CASE WHEN 'WEBAUTHN'=ANY(methods) THEN 'WEBAUTHN' WHEN 'TOTP'=ANY(methods) THEN 'TOTP' ELSE NULL END;
  END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.create_refresh_mfa_challenge(p_token_id text,p_hashes text[],p_user_id text,p_ticket_hash text,p_session_binding_hash text,p_risk_score integer,p_risk_level text,p_reasons text[],p_ip_hash text,p_user_agent_hash text,p_max_attempts integer,p_expires_at timestamp without time zone,p_created_at timestamp without time zone,p_request_id text)
RETURNS TABLE("challengeId" text,"created" boolean) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; challenge_id text;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_MFA_CHALLENGE_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'create-mfa');
  IF t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."expiresAt"<=p_created_at OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR p_max_attempts NOT BETWEEN 1 AND 10 OR p_risk_score NOT BETWEEN 0 AND 100 OR p_risk_level NOT IN ('LOW','MEDIUM','HIGH','CRITICAL') OR coalesce(array_length(p_reasons,1),0) NOT BETWEEN 1 AND 12 OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_session_binding_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '15 minutes' THEN RAISE EXCEPTION 'B01_REFRESH_MFA_CHALLENGE_DENIED' USING ERRCODE='42501'; END IF;
  challenge_id:=gen_random_uuid()::text;
  INSERT INTO public."AuthMfaChallenge" (id,"userId","ticketHash","sessionBindingHash",purpose,"riskScore","riskLevel",reasons,"createdIpHash","createdUserAgentHash","maxAttempts","createdAt","updatedAt","expiresAt") VALUES (challenge_id,t."userId",p_ticket_hash,p_session_binding_hash,'admin_login',p_risk_score,p_risk_level::public."AuthRiskLevel",p_reasons,p_ip_hash,p_user_agent_hash,p_max_attempts,p_created_at,p_created_at,p_expires_at);
  PERFORM app_auth.b01_audit('AUTH_REFRESH_MFA_CHALLENGE_REQUIRED',t.id,p_created_at);
  RETURN QUERY SELECT challenge_id,TRUE;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_refresh_token_scope(p_token_id text,p_hashes text[],p_user_id text,p_scope text,p_reason text,p_revoked_at timestamp without time zone,p_request_id text)
RETURNS TABLE("revokedCount" integer) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; changed integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'revoke-scope');
  IF t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR t."rotationCompletedAt" IS NOT NULL OR p_scope NOT IN ('token','password-only','all') OR p_reason NOT IN ('ACCOUNT_UNAVAILABLE','MFA_STATE_CHANGED','MFA_REQUIRED_AFTER_POLICY_CHANGE') THEN RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED' USING ERRCODE='42501'; END IF;
  UPDATE public."RefreshToken" rt SET "revokedAt"=p_revoked_at,"revokedReason"=p_reason,"lastUsedAt"=p_revoked_at WHERE rt."userId"=t."userId" AND rt."revokedAt" IS NULL AND (p_scope<>'token' OR rt.id=p_token_id) AND (p_scope<>'password-only' OR rt."mfaVerifiedAt" IS NULL);
  GET DIAGNOSTICS changed=ROW_COUNT; PERFORM app_auth.b01_audit('AUTH_REFRESH_REVOKED',t.id,p_revoked_at); RETURN QUERY SELECT changed;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.complete_refresh_token_rotation(p_token_id text,p_hashes text[],p_user_id text,p_organization_id text,p_token_hash text,p_expires_at timestamp without time zone,p_ip_hash text,p_user_agent text,p_authenticated_at timestamp without time zone,p_mfa_verified_at timestamp without time zone,p_rotated_at timestamp without time zone,p_request_id text)
RETURNS TABLE("id" text,"expiresAt" timestamp without time zone) LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path=pg_catalog,public AS $fn$
DECLARE t public."RefreshToken"%ROWTYPE; successor_id text; changed integer;
BEGIN
  PERFORM app_auth.b01_bind_bearer(p_hashes,p_request_id);
  SELECT rt.* INTO t FROM public."RefreshToken" rt WHERE rt.id=p_token_id AND rt."tokenHash"=ANY(p_hashes) FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_ROTATION_CLAIM_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM app_auth.b01_bind_predecessor(t.id,t."userId",t."orgId",'complete-rotation');
  IF p_rotated_at IS NULL OR abs(extract(epoch FROM p_rotated_at-clock_timestamp())) > 300
     OR p_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$' OR p_token_hash=ANY(p_hashes)
     OR p_expires_at<=p_rotated_at OR p_expires_at>p_rotated_at+interval '31 days'
     OR t."userId" IS DISTINCT FROM p_user_id OR t."revokedAt" IS NOT NULL OR t."expiresAt"<=p_rotated_at
     OR t."rotationRequestId" IS DISTINCT FROM p_request_id OR t."rotationCompletedAt" IS NOT NULL
     OR (t."authenticatedAt" IS NOT NULL AND p_authenticated_at IS DISTINCT FROM t."authenticatedAt")
     OR p_mfa_verified_at IS DISTINCT FROM t."mfaVerifiedAt" OR p_organization_id IS DISTINCT FROM t."orgId"
  THEN RAISE EXCEPTION 'B01_REFRESH_ROTATION_CONTEXT_DENIED' USING ERRCODE='42501'; END IF;
  successor_id:=gen_random_uuid()::text;
  PERFORM set_config('app.b01_successor_id',successor_id,true);
  INSERT INTO public."RefreshToken" (id,"orgId","userId","tokenHash","expiresAt","createdAt","createdIpHash","createdUserAgent","authenticatedAt","mfaVerifiedAt","lastUsedAt") VALUES (successor_id,t."orgId",t."userId",p_token_hash,p_expires_at,p_rotated_at,p_ip_hash,p_user_agent,coalesce(t."authenticatedAt",p_rotated_at),t."mfaVerifiedAt",p_rotated_at);
  UPDATE public."RefreshToken" rt SET "revokedAt"=p_rotated_at,"revokedReason"='ROTATED',"replacedByTokenHash"=p_token_hash,"rotationCompletedAt"=p_rotated_at,"lastUsedAt"=p_rotated_at WHERE rt.id=t.id AND rt."revokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT; IF changed<>1 THEN RAISE EXCEPTION 'REFRESH_TOKEN_ROTATION_LOST' USING ERRCODE='40001'; END IF;
  PERFORM app_auth.b01_audit('AUTH_REFRESH_ROTATED',t.id,p_rotated_at); RETURN QUERY SELECT successor_id,p_expires_at;
END
$fn$;

REVOKE ALL ON FUNCTION app_auth.b01_bind_bearer(text[],text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.b01_bind_predecessor(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.b01_audit(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
