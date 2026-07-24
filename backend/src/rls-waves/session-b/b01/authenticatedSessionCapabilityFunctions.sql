-- Database-verifiable authenticated session capability. {{AUTH_OWNER}} is
-- substituted only by the clean-room generator. Raw capabilities are accepted
-- only by the exact issue/verify/revocation boundaries and are never persisted
-- or returned by PostgreSQL.

CREATE OR REPLACE FUNCTION app_auth.auth_session_prepare(
  p_capability text,
  p_purpose text,
  p_request_id text
) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE capability_hash text;
BEGIN
  IF p_capability !~ '^[A-Za-z0-9_-]{43}$'
     OR p_purpose IS NULL OR length(btrim(p_purpose)) NOT BETWEEN 1 AND 240
     OR p_request_id IS NULL OR length(btrim(p_request_id)) NOT BETWEEN 1 AND 128
  THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;

  -- This deliberately overwrites all values that can influence an authenticated
  -- policy before the first protected read. Runtime callers may set app.* but
  -- cannot retain it through this reviewed function boundary.
  capability_hash := encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  PERFORM set_config('app.auth_session_hash',capability_hash,true),
          set_config('app.auth_session_id','',true),
          set_config('app.user_id','',true), set_config('app.role','',true),
          set_config('app.organization_id','',true), set_config('app.licensee_id','',true),
          set_config('app.manufacturer_id','',true), set_config('app.auth_assurance','',true),
          set_config('app.request_id',p_request_id,true), set_config('app.purpose',p_purpose,true),
          set_config('app.auth_session_verified','',true), set_config('app.auth_session_operation','verify',true),
          set_config('app.auth_session_target_id','',true);
  RETURN capability_hash;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.issue_authenticated_session_capability(
  p_refresh_token_id text,
  p_refresh_token_hash text,
  p_capability text,
  p_assurance text,
  p_expires_at timestamp without time zone
) RETURNS TABLE("id" text,"expiresAt" timestamp without time zone)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE session_row public."RefreshToken"%ROWTYPE; capability_hash text;
BEGIN
  IF p_refresh_token_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_refresh_token_hash !~ '^([0-9a-f]{12}:)?[a-f0-9]{64}$'
     OR p_capability !~ '^[A-Za-z0-9_-]{43}$' OR p_assurance NOT IN ('PASSWORD','ADMIN_MFA')
     OR p_expires_at IS NULL THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  -- Reuse the reviewed B01 bearer binder before the first protected read.
  -- The identifier stays a selector; the existing refresh bearer hash is the
  -- only pre-auth proof that can make that selector visible.
  PERFORM app_auth.b01_bind_bearer(ARRAY[p_refresh_token_hash], 'auth-session-issue');
  capability_hash := encode(sha256(convert_to(p_capability,'UTF8')),'hex');
  PERFORM set_config('app.auth_session_hash',capability_hash,true), set_config('app.auth_session_id',p_refresh_token_id,true),
          set_config('app.auth_session_refresh_hash',p_refresh_token_hash,true), set_config('app.b01_token_hashes',p_refresh_token_hash,true),
          set_config('app.auth_session_operation','issue',true), set_config('app.auth_session_verified','',true);
  -- Lock the bearer-bound refresh row using an innocuous, reviewed lifecycle
  -- update.  The lock lives for this transaction; validation failures roll it
  -- back.  This avoids a second, user-scoped lookup and serializes competing
  -- issuers for the same refresh credential.
  UPDATE public."RefreshToken" rt
     SET "sessionCapabilityLastUsedAt"=clock_timestamp()
   WHERE rt.id=p_refresh_token_id
     AND rt."tokenHash"=p_refresh_token_hash
     AND rt."revokedAt" IS NULL
     AND rt."expiresAt">clock_timestamp()
  RETURNING rt.* INTO session_row;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED_SESSION' USING ERRCODE='42501';
  END IF;
  IF session_row."sessionCapabilityHash" IS NOT NULL
     OR p_expires_at<=clock_timestamp() OR p_expires_at>session_row."expiresAt"
     OR (p_assurance='ADMIN_MFA') IS DISTINCT FROM (session_row."mfaVerifiedAt" IS NOT NULL) THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED_LIFECYCLE' USING ERRCODE='42501';
  END IF;
  UPDATE public."RefreshToken" rt SET "sessionCapabilityHash"=capability_hash,
    "sessionCapabilityHashVersion"='sha256-v1',"sessionCapabilityAssurance"=p_assurance,
    "sessionCapabilityExpiresAt"=p_expires_at,"sessionCapabilityLastUsedAt"=clock_timestamp(),
    "sessionCapabilityRevokedAt"=NULL,"sessionCapabilityRevokedReason"=NULL
    WHERE rt.id=session_row.id AND rt."sessionCapabilityHash" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED_SESSION' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT session_row.id::text,session_row."expiresAt";
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.require_authenticated_session(
  p_capability text,
  p_purpose text,
  p_request_id text
) RETURNS TABLE("sessionId" text,"userId" text,"role" text,"organizationId" text,"licenseeId" text,"assurance" text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE session_row record; actor_row record; capability_hash text;
BEGIN
  -- auth_session_prepare performs input validation.  Its SET LOCAL values are
  -- intentionally not relied on across a nested SECURITY DEFINER boundary;
  -- install every security-relevant setting again in this outer boundary so
  -- the protected query below is bound to this exact invocation.
  capability_hash := app_auth.auth_session_prepare(p_capability,p_purpose,p_request_id);
  PERFORM set_config('app.auth_session_hash',capability_hash,true),
          set_config('app.auth_session_id','',true),
          set_config('app.user_id','',true), set_config('app.role','',true),
          set_config('app.organization_id','',true), set_config('app.licensee_id','',true),
          set_config('app.manufacturer_id','',true), set_config('app.auth_assurance','',true),
          set_config('app.request_id',p_request_id,true), set_config('app.purpose',p_purpose,true),
          set_config('app.auth_session_verified','',true), set_config('app.auth_session_operation','verify',true),
          set_config('app.auth_session_target_id','',true);
  SELECT s.id,s."userId",s."sessionCapabilityAssurance" AS assurance
    INTO session_row
    FROM public."RefreshToken" s
   WHERE s."sessionCapabilityHash"=current_setting('app.auth_session_hash',true)
     AND s."sessionCapabilityHashVersion"='sha256-v1'
     AND s."sessionCapabilityRevokedAt" IS NULL AND s."sessionCapabilityExpiresAt">clock_timestamp()
     AND s."revokedAt" IS NULL AND s."expiresAt">clock_timestamp()
   FOR SHARE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;

  -- The user selector is derived from the locked, capability-bound refresh
  -- row.  It is never a caller-provided authority value.
  PERFORM set_config('app.user_id',session_row."userId",true);
  SELECT u.id,u.role::text AS role,u."orgId",u."licenseeId"
    INTO actor_row
    FROM public."User" u
   WHERE u.id=session_row."userId" AND u."isActive"
     AND u.status='ACTIVE'::public."UserStatus"
     AND u."disabledAt" IS NULL AND u."deletedAt" IS NULL;
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;

  PERFORM set_config('app.auth_session_id',session_row.id,true),
          set_config('app.user_id',actor_row.id,true), set_config('app.role',actor_row.role,true),
          set_config('app.organization_id',coalesce(actor_row."orgId",''),true),
          set_config('app.licensee_id',coalesce(actor_row."licenseeId",''),true),
          set_config('app.auth_assurance',CASE session_row.assurance WHEN 'ADMIN_MFA' THEN 'mfa-verified' WHEN 'PASSWORD' THEN 'password-verified' ELSE '' END,true),
          set_config('app.auth_session_verified','1',true);
  IF current_setting('app.auth_assurance',true)='' THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  RETURN QUERY SELECT session_row.id::text,actor_row.id::text,actor_row.role::text,
    actor_row."orgId"::text,actor_row."licenseeId"::text,session_row.assurance::text;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_authenticated_session_capability(
  p_capability text,
  p_target_refresh_token_id text,
  p_reason text,
  p_request_id text
) RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor_row record; changed integer;
BEGIN
  IF p_target_refresh_token_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_reason !~ '^[A-Z0-9_:-]{1,128}$' THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor_row FROM app_auth.require_authenticated_session(p_capability,'auth-session-revoke',p_request_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_session_operation','revoke-one',true), set_config('app.auth_session_target_id',p_target_refresh_token_id,true);
  UPDATE public."RefreshToken" rt
     SET "sessionCapabilityRevokedAt"=clock_timestamp(),"sessionCapabilityRevokedReason"=p_reason
   WHERE rt.id=p_target_refresh_token_id AND rt."userId"=actor_row."userId"
     AND rt."sessionCapabilityHash" IS NOT NULL AND rt."sessionCapabilityRevokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed=1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_all_authenticated_session_capabilities(
  p_capability text,
  p_reason text,
  p_request_id text
) RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,public AS $fn$
DECLARE actor_row record; changed integer;
BEGIN
  IF p_reason !~ '^[A-Z0-9_:-]{1,128}$' THEN
    RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501';
  END IF;
  SELECT * INTO actor_row FROM app_auth.require_authenticated_session(p_capability,'auth-session-revoke-all',p_request_id);
  IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_SESSION_CAPABILITY_DENIED' USING ERRCODE='42501'; END IF;
  PERFORM set_config('app.auth_session_operation','revoke-user',true);
  UPDATE public."RefreshToken" rt
     SET "sessionCapabilityRevokedAt"=clock_timestamp(),"sessionCapabilityRevokedReason"=p_reason
   WHERE rt."userId"=actor_row."userId" AND rt."sessionCapabilityHash" IS NOT NULL
     AND rt."sessionCapabilityRevokedAt" IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN QUERY SELECT changed;
END
$fn$;

REVOKE ALL ON FUNCTION app_auth.auth_session_prepare(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.issue_authenticated_session_capability(text,text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.require_authenticated_session(text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_authenticated_session_capability(text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_all_authenticated_session_capabilities(text,text,text) FROM PUBLIC;
