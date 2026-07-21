DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mscqr_dev_preauth') THEN
    CREATE ROLE mscqr_dev_preauth LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mscqr_dev_app') THEN
    CREATE ROLE mscqr_dev_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mscqr_dev_rls_function_owner') THEN
    CREATE ROLE mscqr_dev_rls_function_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
END
$roles$;

DROP SCHEMA IF EXISTS b01_refresh_wave CASCADE;
CREATE SCHEMA IF NOT EXISTS app_auth;
CREATE SCHEMA IF NOT EXISTS app_rls;
CREATE SCHEMA b01_refresh_wave;

DROP FUNCTION IF EXISTS app_auth.load_refresh_session_state(text,text,text,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.create_refresh_mfa_challenge(text,text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text);
DROP FUNCTION IF EXISTS app_auth.revoke_refresh_token_scope(text,text,text,text,timestamp without time zone);
DROP FUNCTION IF EXISTS app_auth.complete_refresh_token_rotation(text,text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone);

REVOKE ALL ON SCHEMA b01_refresh_wave FROM PUBLIC;
GRANT USAGE ON SCHEMA app_auth TO mscqr_dev_preauth;
GRANT USAGE ON SCHEMA app_rls TO mscqr_dev_app;
GRANT USAGE ON SCHEMA app_auth, app_rls, b01_refresh_wave TO mscqr_dev_rls_function_owner;

CREATE TABLE b01_refresh_wave.actor (
  id text PRIMARY KEY,
  email text NOT NULL,
  name text NOT NULL,
  role text NOT NULL,
  organization_id text,
  licensee_id text,
  manufacturer_id text,
  active boolean NOT NULL DEFAULT true,
  email_verified_at timestamp without time zone,
  mfa_required boolean NOT NULL DEFAULT false,
  mfa_enabled boolean NOT NULL DEFAULT false,
  mfa_last_used_at timestamp without time zone
);

CREATE TABLE b01_refresh_wave.membership (
  user_id text NOT NULL REFERENCES b01_refresh_wave.actor(id),
  licensee_id text NOT NULL,
  organization_id text NOT NULL,
  licensee_name text NOT NULL,
  licensee_prefix text NOT NULL,
  brand_name text,
  is_primary boolean NOT NULL DEFAULT false,
  scope_version text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  PRIMARY KEY (user_id, licensee_id)
);

CREATE TABLE b01_refresh_wave.refresh_token (
  id text PRIMARY KEY,
  user_id text NOT NULL REFERENCES b01_refresh_wave.actor(id),
  organization_id text,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamp without time zone NOT NULL,
  created_at timestamp without time zone NOT NULL,
  created_ip_hash text,
  created_user_agent text,
  authenticated_at timestamp without time zone,
  mfa_verified_at timestamp without time zone,
  last_used_at timestamp without time zone,
  revoked_at timestamp without time zone,
  revoked_reason text,
  replaced_by_token_hash text,
  rotation_request_id text
);

CREATE TABLE b01_refresh_wave.mfa_challenge (
  id text PRIMARY KEY,
  token_id text NOT NULL REFERENCES b01_refresh_wave.refresh_token(id),
  user_id text NOT NULL REFERENCES b01_refresh_wave.actor(id),
  ticket_hash text NOT NULL UNIQUE,
  session_binding_hash text NOT NULL,
  risk_score integer NOT NULL,
  risk_level text NOT NULL,
  reasons text[] NOT NULL,
  ip_hash text,
  user_agent_hash text,
  max_attempts integer NOT NULL,
  expires_at timestamp without time zone NOT NULL,
  created_at timestamp without time zone NOT NULL
);

CREATE TABLE b01_refresh_wave.audit_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  user_id text,
  action text NOT NULL,
  token_id text,
  request_id text NOT NULL,
  created_at timestamp without time zone NOT NULL
);

CREATE TABLE b01_refresh_wave.app_audit_outbox (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  payload jsonb NOT NULL,
  payload_digest text NOT NULL,
  idempotency_key text NOT NULL UNIQUE,
  request_id text NOT NULL,
  organization_id text,
  licensee_id text,
  manufacturer_id text,
  initiating_user_id text,
  initiating_actor_role text,
  expires_at timestamp without time zone NOT NULL,
  initial_error_code text,
  created_at timestamp without time zone NOT NULL DEFAULT (clock_timestamp() AT TIME ZONE 'UTC')
);

ALTER TABLE b01_refresh_wave.actor ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.actor FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.membership FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.refresh_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.refresh_token FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.mfa_challenge ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.mfa_challenge FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.audit_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.app_audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_refresh_wave.app_audit_outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY b01_actor_function_access ON b01_refresh_wave.actor
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_membership_function_access ON b01_refresh_wave.membership
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_refresh_token_function_access ON b01_refresh_wave.refresh_token
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_mfa_challenge_function_access ON b01_refresh_wave.mfa_challenge
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_audit_outbox_function_access ON b01_refresh_wave.audit_outbox
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_app_audit_outbox_function_access ON b01_refresh_wave.app_audit_outbox
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);

GRANT SELECT (
  id,email,name,role,organization_id,licensee_id,manufacturer_id,active,email_verified_at,
  mfa_required,mfa_enabled,mfa_last_used_at
) ON b01_refresh_wave.actor TO mscqr_dev_rls_function_owner;
GRANT UPDATE (id) ON b01_refresh_wave.actor TO mscqr_dev_rls_function_owner;
GRANT SELECT (
  user_id,licensee_id,organization_id,licensee_name,licensee_prefix,brand_name,is_primary,scope_version,active
) ON b01_refresh_wave.membership TO mscqr_dev_rls_function_owner;
GRANT UPDATE (user_id) ON b01_refresh_wave.membership TO mscqr_dev_rls_function_owner;
GRANT SELECT (
  id,user_id,organization_id,token_hash,expires_at,created_at,created_ip_hash,created_user_agent,
  authenticated_at,mfa_verified_at,last_used_at,revoked_at,revoked_reason,replaced_by_token_hash,rotation_request_id
) ON b01_refresh_wave.refresh_token TO mscqr_dev_rls_function_owner;
GRANT INSERT (
  id,user_id,organization_id,token_hash,expires_at,created_at,created_ip_hash,created_user_agent,
  authenticated_at,mfa_verified_at,last_used_at
) ON b01_refresh_wave.refresh_token TO mscqr_dev_rls_function_owner;
GRANT UPDATE (
  last_used_at,revoked_at,revoked_reason,replaced_by_token_hash,rotation_request_id
) ON b01_refresh_wave.refresh_token TO mscqr_dev_rls_function_owner;
GRANT INSERT (
  id,token_id,user_id,ticket_hash,session_binding_hash,risk_score,risk_level,reasons,ip_hash,
  user_agent_hash,max_attempts,expires_at,created_at
) ON b01_refresh_wave.mfa_challenge TO mscqr_dev_rls_function_owner;
GRANT INSERT (idempotency_key,user_id,action,token_id,request_id,created_at)
  ON b01_refresh_wave.audit_outbox TO mscqr_dev_rls_function_owner;
GRANT SELECT (idempotency_key)
  ON b01_refresh_wave.audit_outbox TO mscqr_dev_rls_function_owner;
GRANT INSERT (
  payload,payload_digest,idempotency_key,request_id,organization_id,licensee_id,manufacturer_id,
  initiating_user_id,initiating_actor_role,expires_at,initial_error_code
) ON b01_refresh_wave.app_audit_outbox TO mscqr_dev_rls_function_owner;
GRANT SELECT (id,idempotency_key,payload_digest)
  ON b01_refresh_wave.app_audit_outbox TO mscqr_dev_rls_function_owner;
GRANT USAGE, SELECT ON SEQUENCE b01_refresh_wave.audit_outbox_id_seq TO mscqr_dev_rls_function_owner;

CREATE OR REPLACE FUNCTION b01_refresh_wave.require_refresh_bearer(
  p_token_id text,
  p_user_id text,
  p_hashes text[],
  p_checked_at timestamp without time zone,
  p_action text,
  p_request_id text
)
RETURNS TABLE(
  user_id text,
  role text,
  organization_id text,
  licensee_id text,
  manufacturer_id text,
  auth_assurance text,
  mfa_required boolean,
  mfa_enabled boolean,
  request_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_token b01_refresh_wave.refresh_token%ROWTYPE;
  v_actor b01_refresh_wave.actor%ROWTYPE;
  v_membership b01_refresh_wave.membership%ROWTYPE;
  v_licensee_id text;
  v_manufacturer_id text;
  v_assurance text;
BEGIN
  IF session_user <> 'mscqr_dev_preauth'
     OR p_action NOT IN ('load', 'challenge', 'revoke', 'complete')
     OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at - (clock_timestamp() AT TIME ZONE 'UTC')))) > 300
     OR coalesce(array_length(p_hashes, 1), 0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_hashes) AS hash WHERE hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT hash) FROM unnest(p_hashes) AS hash) <> array_length(p_hashes, 1) THEN
    RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED';
  END IF;

  SELECT token.* INTO v_token
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.id = p_token_id
    AND (p_user_id IS NULL OR token.user_id = p_user_id)
    AND token.token_hash = ANY (p_hashes)
  FOR UPDATE;
  IF NOT FOUND OR v_token.revoked_at IS NOT NULL OR v_token.expires_at <= p_checked_at THEN
    RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED';
  END IF;
  IF v_token.rotation_request_id IS NULL
     OR (p_action IN ('load', 'challenge') AND p_request_id IS DISTINCT FROM v_token.rotation_request_id) THEN
    RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED';
  END IF;

  SELECT actor.* INTO v_actor
  FROM b01_refresh_wave.actor AS actor
  WHERE actor.id = v_token.user_id AND actor.active
  FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED'; END IF;

  IF v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') THEN
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.organization_id = v_token.organization_id
      AND membership.active
    ORDER BY membership.is_primary DESC, membership.licensee_id
    LIMIT 1
    FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED'; END IF;
    v_licensee_id := v_membership.licensee_id;
    v_manufacturer_id := v_actor.id;
  ELSIF v_actor.role IN ('LICENSEE_ADMIN', 'ORG_ADMIN') THEN
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.licensee_id = v_actor.licensee_id
      AND membership.organization_id = v_token.organization_id
      AND membership.active
    FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED'; END IF;
    v_licensee_id := v_membership.licensee_id;
    v_manufacturer_id := NULL;
  ELSE
    IF v_token.organization_id IS DISTINCT FROM v_actor.organization_id THEN
      RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED';
    END IF;
    v_licensee_id := v_actor.licensee_id;
    v_manufacturer_id := v_actor.manufacturer_id;
  END IF;

  v_assurance := CASE WHEN v_token.mfa_verified_at IS NULL THEN 'password-verified' ELSE 'mfa-verified' END;
  IF (p_action = 'challenge' AND (NOT v_actor.mfa_required OR NOT v_actor.mfa_enabled OR v_token.mfa_verified_at IS NOT NULL))
     OR (p_action = 'complete' AND v_actor.mfa_required AND (NOT v_actor.mfa_enabled OR v_token.mfa_verified_at IS NULL)) THEN
    RAISE EXCEPTION 'B01_REFRESH_BEARER_DENIED';
  END IF;

  RETURN QUERY SELECT
    v_actor.id,
    v_actor.role,
    v_token.organization_id,
    v_licensee_id,
    v_manufacturer_id,
    v_assurance,
    v_actor.mfa_required,
    v_actor.mfa_enabled,
    v_token.rotation_request_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.claim_refresh_token_rotation(
  p_hashes text[],
  p_checked_at timestamp without time zone,
  p_request_id text
)
RETURNS TABLE(
  "disposition" text,
  "tokenId" text,
  "userId" text,
  "role" text,
  "organizationId" text,
  "licenseeId" text,
  "manufacturerId" text,
  "authAssurance" text,
  "expiresAt" timestamp without time zone,
  "authenticatedAt" timestamp without time zone,
  "mfaVerifiedAt" timestamp without time zone
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_matches integer;
  v_token b01_refresh_wave.refresh_token%ROWTYPE;
  v_actor b01_refresh_wave.actor%ROWTYPE;
  v_membership b01_refresh_wave.membership%ROWTYPE;
BEGIN
  IF session_user <> 'mscqr_dev_preauth' THEN
    RAISE EXCEPTION 'B01_PREAUTH_IDENTITY_REQUIRED';
  END IF;
  IF coalesce(array_length(p_hashes, 1), 0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_hashes) AS hash WHERE hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT hash) FROM unnest(p_hashes) AS hash) <> array_length(p_hashes, 1)
     OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at - (clock_timestamp() AT TIME ZONE 'UTC')))) > 300
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR p_request_id !~ '^[!-~]+$' THEN
    RAISE EXCEPTION 'B01_REFRESH_CLAIM_INPUT_INVALID';
  END IF;

  SELECT count(*) INTO v_matches
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.token_hash = ANY (p_hashes);
  IF v_matches = 0 THEN RETURN; END IF;
  IF v_matches <> 1 THEN RAISE EXCEPTION 'B01_REFRESH_CLAIM_AMBIGUOUS'; END IF;

  SELECT token.* INTO STRICT v_token
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.token_hash = ANY (p_hashes);

  IF NOT pg_try_advisory_xact_lock(hashtextextended(v_token.id, 0)) THEN
    INSERT INTO b01_refresh_wave.audit_outbox(
      idempotency_key, user_id, action, token_id, request_id, created_at
    ) VALUES (
      'rotation-lost:' || v_token.id || ':' || p_request_id,
      v_token.user_id,
      'AUTH_REFRESH_ROTATION_LOST',
      v_token.id,
      p_request_id,
      p_checked_at
    ) ON CONFLICT (idempotency_key) DO NOTHING;
    RETURN QUERY SELECT 'REVOKED', v_token.id, v_token.user_id, NULL::text, NULL::text, NULL::text,
      NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
    RETURN;
  END IF;

  SELECT token.* INTO STRICT v_token
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.id = v_token.id
  FOR UPDATE;
  SELECT actor.* INTO STRICT v_actor
  FROM b01_refresh_wave.actor AS actor
  WHERE actor.id = v_token.user_id
  FOR SHARE;

  IF NOT v_actor.active THEN
    UPDATE b01_refresh_wave.refresh_token
    SET revoked_at = p_checked_at, revoked_reason = 'ACCOUNT_UNAVAILABLE', last_used_at = p_checked_at
    WHERE user_id = v_actor.id AND revoked_at IS NULL;
    INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
    VALUES ('disabled:' || v_token.id, v_actor.id, 'AUTH_REFRESH_DISABLED_DENIED', v_token.id, p_request_id, p_checked_at)
    ON CONFLICT (idempotency_key) DO NOTHING;
    RETURN QUERY SELECT 'REVOKED', v_token.id, v_actor.id, NULL::text, NULL::text, NULL::text,
      NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
    RETURN;
  END IF;

  IF v_token.revoked_at IS NOT NULL THEN
    IF v_token.replaced_by_token_hash IS NOT NULL THEN
      UPDATE b01_refresh_wave.refresh_token
      SET revoked_at = p_checked_at, revoked_reason = 'REUSE_DETECTED', last_used_at = p_checked_at
      WHERE user_id = v_actor.id AND revoked_at IS NULL;
      INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
      VALUES ('reuse:' || v_token.id, v_actor.id, 'AUTH_REFRESH_REUSE_DETECTED', v_token.id, p_request_id, p_checked_at)
      ON CONFLICT (idempotency_key) DO NOTHING;
      RETURN QUERY SELECT 'REUSE_DETECTED', v_token.id, v_actor.id, NULL::text, NULL::text, NULL::text,
        NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
    ELSE
      RETURN QUERY SELECT 'REVOKED', v_token.id, v_actor.id, NULL::text, NULL::text, NULL::text,
        NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
    END IF;
    RETURN;
  END IF;

  IF v_token.expires_at <= p_checked_at THEN
    UPDATE b01_refresh_wave.refresh_token
    SET revoked_at = p_checked_at, revoked_reason = 'EXPIRED', last_used_at = p_checked_at
    WHERE id = v_token.id AND revoked_at IS NULL;
    INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
    VALUES ('expired:' || v_token.id, v_actor.id, 'AUTH_REFRESH_EXPIRED', v_token.id, p_request_id, p_checked_at)
    ON CONFLICT (idempotency_key) DO NOTHING;
    RETURN QUERY SELECT 'EXPIRED', v_token.id, v_actor.id, NULL::text, NULL::text, NULL::text,
      NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
    RETURN;
  END IF;

  IF v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') THEN
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.organization_id = v_token.organization_id
      AND membership.active
    ORDER BY membership.is_primary DESC, membership.licensee_id
    LIMIT 1
    FOR SHARE;
    IF NOT FOUND THEN
      UPDATE b01_refresh_wave.refresh_token
      SET revoked_at = p_checked_at, revoked_reason = 'STALE_MEMBERSHIP', last_used_at = p_checked_at
      WHERE user_id = v_actor.id AND revoked_at IS NULL;
      INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
      VALUES ('stale:' || v_token.id, v_actor.id, 'AUTH_REFRESH_STALE_MEMBERSHIP_DENIED', v_token.id, p_request_id, p_checked_at)
      ON CONFLICT (idempotency_key) DO NOTHING;
      RETURN QUERY SELECT 'REVOKED', v_token.id, v_actor.id, NULL::text, NULL::text, NULL::text,
        NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
      RETURN;
    END IF;
  ELSIF v_actor.role IN ('LICENSEE_ADMIN', 'ORG_ADMIN') THEN
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.licensee_id = v_actor.licensee_id
      AND membership.organization_id = v_token.organization_id
      AND membership.active
    FOR SHARE;
    IF NOT FOUND THEN
      UPDATE b01_refresh_wave.refresh_token
      SET revoked_at = p_checked_at, revoked_reason = 'STALE_MEMBERSHIP', last_used_at = p_checked_at
      WHERE user_id = v_actor.id AND revoked_at IS NULL;
      INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
      VALUES ('stale:' || v_token.id, v_actor.id, 'AUTH_REFRESH_STALE_MEMBERSHIP_DENIED', v_token.id, p_request_id, p_checked_at)
      ON CONFLICT (idempotency_key) DO NOTHING;
      RETURN QUERY SELECT 'REVOKED', v_token.id, v_actor.id, NULL::text, NULL::text, NULL::text,
        NULL::text, NULL::text, v_token.expires_at, v_token.authenticated_at, v_token.mfa_verified_at;
      RETURN;
    END IF;
  END IF;

  UPDATE b01_refresh_wave.refresh_token
  SET rotation_request_id = p_request_id
  WHERE id = v_token.id;

  RETURN QUERY SELECT
    'ACTIVE'::text,
    v_token.id,
    v_actor.id,
    v_actor.role,
    v_token.organization_id,
    CASE WHEN v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER')
      THEN v_membership.licensee_id ELSE v_actor.licensee_id END,
    CASE WHEN v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER')
      THEN v_actor.id ELSE v_actor.manufacturer_id END,
    CASE WHEN v_token.mfa_verified_at IS NULL THEN 'password-verified' ELSE 'mfa-verified' END,
    v_token.expires_at,
    v_token.authenticated_at,
    v_token.mfa_verified_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.load_refresh_session_state(
  p_token_id text,
  p_hashes text[],
  p_requested_licensee_id text,
  p_requested_scope_version text,
  p_checked_at timestamp without time zone,
  p_request_id text
)
RETURNS TABLE(
  "userId" text,
  "email" text,
  "name" text,
  "role" text,
  "legacyLicenseeId" text,
  "legacyOrganizationId" text,
  "emailVerifiedAt" timestamp without time zone,
  "sessionLicenseeId" text,
  "sessionOrganizationId" text,
  "scopeVersion" text,
  "selectedLicenseeId" text,
  "selectedLicenseeName" text,
  "selectedLicenseePrefix" text,
  "selectedLicenseeBrandName" text,
  "selectedLicenseeOrganizationId" text,
  "linkedLicensees" jsonb,
  "mfaRequired" boolean,
  "mfaEnabled" boolean,
  "mfaEnrolled" boolean,
  "mfaLastUsedAt" timestamp without time zone,
  "mfaMethods" text[],
  "mfaPreferredMethod" text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_token b01_refresh_wave.refresh_token%ROWTYPE;
  v_actor b01_refresh_wave.actor%ROWTYPE;
  v_selected b01_refresh_wave.membership%ROWTYPE;
  v_links jsonb;
  v_authority record;
BEGIN
  SELECT * INTO STRICT v_authority
  FROM b01_refresh_wave.require_refresh_bearer(
    p_token_id, NULL, p_hashes, p_checked_at, 'load', p_request_id
  );
  SELECT token.* INTO STRICT v_token FROM b01_refresh_wave.refresh_token AS token WHERE token.id = p_token_id FOR UPDATE;
  SELECT actor.* INTO STRICT v_actor
  FROM b01_refresh_wave.actor AS actor
  WHERE actor.id = v_token.user_id AND actor.active
  FOR SHARE;

  IF v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') THEN
    IF p_requested_licensee_id IS NOT NULL THEN
      SELECT membership.* INTO v_selected
      FROM b01_refresh_wave.membership AS membership
      WHERE membership.user_id = v_actor.id AND membership.licensee_id = p_requested_licensee_id AND membership.active
      FOR SHARE;
      IF NOT FOUND THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_DENIED'; END IF;
      IF p_requested_scope_version IS NULL THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_VERSION_REQUIRED'; END IF;
      IF v_selected.scope_version <> p_requested_scope_version THEN RAISE EXCEPTION 'MANUFACTURER_SCOPE_STALE'; END IF;
    ELSE
      SELECT membership.* INTO v_selected
      FROM b01_refresh_wave.membership AS membership
      WHERE membership.user_id = v_actor.id AND membership.organization_id = v_token.organization_id AND membership.active
      ORDER BY membership.is_primary DESC, membership.licensee_id
      LIMIT 1
      FOR SHARE;
      IF NOT FOUND THEN RAISE EXCEPTION 'SCOPE_SELECTION_REQUIRED'; END IF;
    END IF;
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'brandName', membership.brand_name,
      'id', membership.licensee_id,
      'isPrimary', membership.is_primary,
      'name', membership.licensee_name,
      'orgId', membership.organization_id,
      'prefix', membership.licensee_prefix,
      'scopeVersion', membership.scope_version
    ) ORDER BY membership.is_primary DESC, membership.licensee_id), '[]'::jsonb)
    INTO v_links
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id AND membership.active;
  ELSIF v_actor.role IN ('LICENSEE_ADMIN', 'ORG_ADMIN') THEN
    IF p_requested_licensee_id IS NOT NULL OR p_requested_scope_version IS NOT NULL THEN
      RAISE EXCEPTION 'B01_SCOPE_SWITCH_ROLE_DENIED';
    END IF;
    SELECT membership.* INTO v_selected
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.licensee_id = v_actor.licensee_id
      AND membership.organization_id = v_token.organization_id
      AND membership.active
    FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'B01_REFRESH_MEMBERSHIP_STALE'; END IF;
    v_links := '[]'::jsonb;
  ELSE
    IF p_requested_licensee_id IS NOT NULL OR p_requested_scope_version IS NOT NULL THEN
      RAISE EXCEPTION 'B01_SCOPE_SWITCH_ROLE_DENIED';
    END IF;
    v_links := '[]'::jsonb;
  END IF;

  IF v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER')
     AND p_requested_licensee_id IS NOT NULL THEN
    INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
    VALUES ('scope:' || p_token_id || ':' || p_request_id, v_actor.id, 'MANUFACTURER_SCOPE_SWITCH', p_token_id, p_request_id, p_checked_at)
    ON CONFLICT (idempotency_key) DO NOTHING;
  END IF;

  RETURN QUERY SELECT
    v_actor.id, v_actor.email, v_actor.name, v_actor.role, v_actor.licensee_id, v_actor.organization_id,
    v_actor.email_verified_at, v_selected.licensee_id, v_selected.organization_id,
    CASE WHEN v_actor.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER')
      THEN v_selected.scope_version ELSE NULL::text END,
    v_selected.licensee_id, v_selected.licensee_name, v_selected.licensee_prefix, v_selected.brand_name,
    v_selected.organization_id, v_links, v_actor.mfa_required, v_actor.mfa_enabled, v_actor.mfa_enabled,
    v_actor.mfa_last_used_at,
    CASE WHEN v_actor.mfa_enabled THEN ARRAY['TOTP','BACKUP_CODE']::text[] ELSE ARRAY[]::text[] END,
    CASE WHEN v_actor.mfa_enabled THEN 'TOTP'::text ELSE NULL::text END;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.create_refresh_mfa_challenge(
  p_token_id text, p_hashes text[], p_user_id text, p_ticket_hash text, p_session_binding_hash text,
  p_risk_score integer, p_risk_level text, p_reasons text[], p_ip_hash text,
  p_user_agent_hash text, p_max_attempts integer, p_expires_at timestamp without time zone,
  p_created_at timestamp without time zone, p_request_id text
)
RETURNS TABLE("challengeId" text, "created" boolean)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE v_id text := gen_random_uuid()::text; v_authority record;
BEGIN
  SELECT * INTO STRICT v_authority
  FROM b01_refresh_wave.require_refresh_bearer(
    p_token_id, p_user_id, p_hashes, p_created_at, 'challenge', p_request_id
  );
  IF p_max_attempts NOT BETWEEN 1 AND 10
     OR p_risk_score NOT BETWEEN 0 AND 100
     OR p_risk_level NOT IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
     OR coalesce(array_length(p_reasons, 1), 0) NOT BETWEEN 1 AND 12
     OR p_ticket_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR p_session_binding_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR p_expires_at <= p_created_at
     OR p_expires_at > p_created_at + interval '15 minutes' THEN
    RAISE EXCEPTION 'B01_REFRESH_MFA_CHALLENGE_DENIED';
  END IF;
  INSERT INTO b01_refresh_wave.mfa_challenge(
    id, token_id, user_id, ticket_hash, session_binding_hash, risk_score, risk_level,
    reasons, ip_hash, user_agent_hash, max_attempts, expires_at, created_at
  ) VALUES (
    v_id, p_token_id, p_user_id, p_ticket_hash, p_session_binding_hash, p_risk_score,
    p_risk_level, p_reasons, p_ip_hash, p_user_agent_hash, p_max_attempts, p_expires_at, p_created_at
  );
  INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
  VALUES ('challenge:' || p_token_id || ':' || p_request_id, p_user_id, 'AUTH_REFRESH_MFA_CHALLENGE_REQUIRED', p_token_id, p_request_id, p_created_at)
  ON CONFLICT (idempotency_key) DO NOTHING;
  RETURN QUERY SELECT v_id, true;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.revoke_refresh_token_scope(
  p_token_id text, p_hashes text[], p_user_id text, p_scope text, p_reason text,
  p_revoked_at timestamp without time zone
)
RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE v_count integer; v_authority record;
BEGIN
  IF p_scope NOT IN ('token', 'password-only', 'all')
     OR p_reason NOT IN ('ACCOUNT_UNAVAILABLE', 'MFA_STATE_CHANGED', 'MFA_REQUIRED_AFTER_POLICY_CHANGE') THEN
    RAISE EXCEPTION 'B01_REFRESH_REVOCATION_DENIED';
  END IF;
  SELECT * INTO STRICT v_authority
  FROM b01_refresh_wave.require_refresh_bearer(
    p_token_id, p_user_id, p_hashes, p_revoked_at, 'revoke', NULL
  );
  UPDATE b01_refresh_wave.refresh_token
  SET revoked_at = p_revoked_at, revoked_reason = p_reason, last_used_at = p_revoked_at
  WHERE user_id = p_user_id AND revoked_at IS NULL
    AND (p_scope <> 'token' OR id = p_token_id)
    AND (p_scope <> 'password-only' OR mfa_verified_at IS NULL);
  GET DIAGNOSTICS v_count = ROW_COUNT;
  INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
  VALUES ('revoke:' || p_token_id || ':' || p_reason, p_user_id, 'AUTH_REFRESH_REVOKED', p_token_id,
    v_authority.request_id, p_revoked_at)
  ON CONFLICT (idempotency_key) DO NOTHING;
  RETURN QUERY SELECT v_count;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.complete_refresh_token_rotation(
  p_token_id text, p_hashes text[], p_user_id text, p_organization_id text, p_token_hash text,
  p_expires_at timestamp without time zone, p_ip_hash text, p_user_agent text,
  p_authenticated_at timestamp without time zone, p_mfa_verified_at timestamp without time zone,
  p_rotated_at timestamp without time zone
)
RETURNS TABLE("id" text, "expiresAt" timestamp without time zone)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_id text := gen_random_uuid()::text;
  v_count integer;
  v_authority record;
  v_original b01_refresh_wave.refresh_token%ROWTYPE;
BEGIN
  SELECT * INTO STRICT v_authority
  FROM b01_refresh_wave.require_refresh_bearer(
    p_token_id, p_user_id, p_hashes, p_rotated_at, 'complete', NULL
  );
  SELECT token.* INTO STRICT v_original
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.id = p_token_id
  FOR UPDATE;
  IF p_token_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR p_token_hash = ANY (p_hashes)
     OR p_expires_at <= p_rotated_at
     OR p_expires_at > p_rotated_at + interval '31 days'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent, '')) > 300
     OR p_authenticated_at IS DISTINCT FROM coalesce(v_original.authenticated_at, p_rotated_at)
     OR p_mfa_verified_at IS DISTINCT FROM v_original.mfa_verified_at THEN
    RAISE EXCEPTION 'B01_REFRESH_ROTATION_CONTEXT_DENIED';
  END IF;
  IF v_authority.role IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER') THEN
    IF NOT EXISTS (
      SELECT 1 FROM b01_refresh_wave.membership AS membership
      WHERE membership.user_id = p_user_id
        AND membership.organization_id = p_organization_id
        AND membership.active
    ) THEN
      RAISE EXCEPTION 'B01_REFRESH_ROTATION_CONTEXT_DENIED';
    END IF;
  ELSIF p_organization_id IS DISTINCT FROM v_authority.organization_id THEN
    RAISE EXCEPTION 'B01_REFRESH_ROTATION_CONTEXT_DENIED';
  END IF;

  INSERT INTO b01_refresh_wave.refresh_token(
    id, user_id, organization_id, token_hash, expires_at, created_at, created_ip_hash,
    created_user_agent, authenticated_at, mfa_verified_at, last_used_at
  ) VALUES (
    v_id, p_user_id, p_organization_id, p_token_hash, p_expires_at, p_rotated_at,
    p_ip_hash, p_user_agent, p_authenticated_at, p_mfa_verified_at, p_rotated_at
  );
  UPDATE b01_refresh_wave.refresh_token AS token
  SET revoked_at = p_rotated_at, revoked_reason = 'ROTATED', replaced_by_token_hash = p_token_hash, last_used_at = p_rotated_at
  WHERE token.id = p_token_id AND token.user_id = p_user_id AND token.revoked_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  IF v_count <> 1 THEN RAISE EXCEPTION 'REFRESH_TOKEN_ROTATION_LOST'; END IF;
  INSERT INTO b01_refresh_wave.audit_outbox(idempotency_key, user_id, action, token_id, request_id, created_at)
  VALUES ('rotate:' || p_token_id, p_user_id, 'AUTH_REFRESH_ROTATED', p_token_id,
    v_authority.request_id, p_rotated_at)
  ON CONFLICT (idempotency_key) DO NOTHING;
  RETURN QUERY SELECT v_id, p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revalidate_authenticated_actor(
  p_user_id text,
  p_session_id text,
  p_requested_licensee_id text,
  p_requested_organization_id text,
  p_checked_at timestamp without time zone,
  p_request_id text
)
RETURNS TABLE(
  "userId" text,
  "role" text,
  "organizationId" text,
  "licenseeId" text,
  "manufacturerId" text,
  "authAssurance" text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_actor b01_refresh_wave.actor%ROWTYPE;
  v_token b01_refresh_wave.refresh_token%ROWTYPE;
  v_membership b01_refresh_wave.membership%ROWTYPE;
BEGIN
  IF session_user <> 'mscqr_dev_app'
     OR p_user_id IS NULL OR p_session_id IS NULL
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR p_request_id !~ '^[!-~]+$'
     OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at - (clock_timestamp() AT TIME ZONE 'UTC')))) > 300 THEN
    RAISE EXCEPTION 'B01_ACTOR_REVALIDATION_DENIED';
  END IF;

  SELECT token.* INTO v_token
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.id = p_session_id
    AND token.user_id = p_user_id
    AND token.revoked_at IS NULL
    AND token.expires_at > p_checked_at
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT actor.* INTO v_actor
  FROM b01_refresh_wave.actor AS actor
  WHERE actor.id = p_user_id
    AND actor.active
    AND actor.email_verified_at IS NOT NULL
    AND actor.role IN (
      'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN',
      'MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'
    )
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;

  IF v_actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.licensee_id = p_requested_licensee_id
      AND membership.organization_id = p_requested_organization_id
      AND membership.organization_id = v_token.organization_id
      AND membership.active
    FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
  ELSIF v_actor.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id = v_actor.id
      AND membership.licensee_id = v_actor.licensee_id
      AND membership.licensee_id = p_requested_licensee_id
      AND membership.organization_id = v_token.organization_id
      AND membership.organization_id = p_requested_organization_id
      AND membership.active
    FOR SHARE;
    IF NOT FOUND THEN RETURN; END IF;
  ELSIF p_requested_licensee_id IS NOT NULL
     OR p_requested_organization_id IS DISTINCT FROM v_token.organization_id
     OR v_actor.organization_id IS DISTINCT FROM v_token.organization_id THEN
    RETURN;
  END IF;

  RETURN QUERY SELECT
    v_actor.id,
    v_actor.role,
    v_token.organization_id,
    CASE WHEN v_actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN NULL::text
      WHEN v_actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN v_membership.licensee_id
      ELSE v_actor.licensee_id END,
    CASE WHEN v_actor.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN v_actor.id
      ELSE v_actor.manufacturer_id END,
    CASE WHEN v_token.mfa_verified_at IS NULL THEN 'password-verified' ELSE 'mfa-verified' END;
END
$fn$;

CREATE OR REPLACE FUNCTION b01_refresh_wave.require_authenticated_context(
  p_user_id text, p_allowed_purposes text[], p_allowed_assurances text[]
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $fn$
DECLARE v_actor b01_refresh_wave.actor%ROWTYPE;
BEGIN
  IF session_user <> 'mscqr_dev_app'
     OR current_setting('app.user_id', true) <> p_user_id
     OR current_setting('app.purpose', true) <> ALL (p_allowed_purposes)
     OR current_setting('app.auth_assurance', true) <> ALL (p_allowed_assurances) THEN
    RAISE EXCEPTION 'B01_AUTHENTICATED_CONTEXT_DENIED';
  END IF;
  SELECT actor.* INTO STRICT v_actor FROM b01_refresh_wave.actor actor WHERE actor.id = p_user_id AND actor.active;
  IF current_setting('app.role', true) <> v_actor.role THEN RAISE EXCEPTION 'B01_AUTHENTICATED_ROLE_STALE'; END IF;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.load_authenticated_actor()
RETURNS TABLE(
  "id" text,
  "email" text,
  "name" text,
  "role" text,
  "licenseeId" text,
  "orgId" text,
  "emailVerifiedAt" timestamp without time zone,
  "pendingEmail" text,
  "pendingEmailRequestedAt" timestamp without time zone,
  "isActive" boolean,
  "status" text,
  "deletedAt" timestamp without time zone,
  "disabledAt" timestamp without time zone,
  "createdAt" timestamp without time zone,
  "licenseeRecordId" text,
  "licenseeName" text,
  "licenseePrefix" text,
  "licenseeBrandName" text,
  "licenseeOrgId" text
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_user_id text := current_setting('app.user_id', true);
  v_actor b01_refresh_wave.actor%ROWTYPE;
  v_membership b01_refresh_wave.membership%ROWTYPE;
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    v_user_id,
    ARRAY['auth-session-hydration'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  SELECT actor.* INTO STRICT v_actor
  FROM b01_refresh_wave.actor AS actor
  WHERE actor.id=v_user_id AND actor.active;
  SELECT membership.* INTO v_membership
  FROM b01_refresh_wave.membership AS membership
  WHERE membership.user_id=v_actor.id
    AND membership.organization_id=current_setting('app.organization_id', true)
    AND membership.active
  ORDER BY membership.is_primary DESC,membership.licensee_id
  LIMIT 1;
  RETURN QUERY SELECT
    v_actor.id,v_actor.email,v_actor.name,v_actor.role,v_actor.licensee_id,v_actor.organization_id,
    v_actor.email_verified_at,NULL::text,NULL::timestamp without time zone,v_actor.active,'ACTIVE'::text,
    NULL::timestamp without time zone,NULL::timestamp without time zone,
    (clock_timestamp() AT TIME ZONE 'UTC'),v_membership.licensee_id,v_membership.licensee_name,
    v_membership.licensee_prefix,v_membership.brand_name,v_membership.organization_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.enqueue_audit_log_outbox(
  p_payload jsonb,
  p_payload_digest text,
  p_idempotency_key text,
  p_request_id text,
  p_organization_id text,
  p_licensee_id text,
  p_manufacturer_id text,
  p_initiating_user_id text,
  p_initiating_actor_role text,
  p_expires_at timestamp without time zone,
  p_initial_error_code text
)
RETURNS TABLE("id" text)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE v_id text;
BEGIN
  IF session_user <> 'mscqr_dev_app'
     OR current_setting('app.user_id', true) IS DISTINCT FROM p_initiating_user_id
     OR current_setting('app.role', true) IS DISTINCT FROM p_initiating_actor_role
     OR current_setting('app.request_id', true) IS DISTINCT FROM p_request_id
     OR current_setting('app.organization_id', true) IS DISTINCT FROM coalesce(p_organization_id, '')
     OR current_setting('app.licensee_id', true) IS DISTINCT FROM coalesce(p_licensee_id, '')
     OR current_setting('app.manufacturer_id', true) IS DISTINCT FROM coalesce(p_manufacturer_id, '')
     OR current_setting('app.purpose', true) NOT IN ('auth-logout','auth-session-revoke','auth-session-revoke-all')
     OR jsonb_typeof(p_payload) <> 'object'
     OR p_payload_digest !~ '^[0-9a-f]{64}$'
     OR p_idempotency_key !~ '^[0-9a-f]{64}$'
     OR p_expires_at <= (clock_timestamp() AT TIME ZONE 'UTC')
     OR p_expires_at > (clock_timestamp() AT TIME ZONE 'UTC') + interval '2 days' THEN
    RAISE EXCEPTION 'B01_AUDIT_OUTBOX_DENIED';
  END IF;

  INSERT INTO b01_refresh_wave.app_audit_outbox AS inserted(
    payload,payload_digest,idempotency_key,request_id,organization_id,licensee_id,
    manufacturer_id,initiating_user_id,initiating_actor_role,expires_at,initial_error_code
  ) VALUES (
    p_payload,p_payload_digest,p_idempotency_key,p_request_id,p_organization_id,p_licensee_id,
    p_manufacturer_id,p_initiating_user_id,p_initiating_actor_role,p_expires_at,p_initial_error_code
  ) ON CONFLICT (idempotency_key) DO NOTHING
  RETURNING inserted.id INTO v_id;

  IF v_id IS NULL THEN
    SELECT outbox.id INTO v_id
    FROM b01_refresh_wave.app_audit_outbox AS outbox
    WHERE outbox.idempotency_key = p_idempotency_key
      AND outbox.payload_digest = p_payload_digest;
    IF NOT FOUND THEN RAISE EXCEPTION 'B01_AUDIT_OUTBOX_REPLAY_MISMATCH'; END IF;
  END IF;
  RETURN QUERY SELECT v_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.create_refresh_token(
  p_user_id text, p_organization_id text, p_token_hash text, p_expires_at timestamp without time zone,
  p_ip_hash text, p_user_agent text, p_authenticated_at timestamp without time zone,
  p_mfa_verified_at timestamp without time zone, p_created_at timestamp without time zone
)
RETURNS TABLE("id" text, "expiresAt" timestamp without time zone)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog
AS $fn$
DECLARE v_id text := gen_random_uuid()::text;
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    p_user_id,
    ARRAY['auth-password-login-session','auth-password-step-up','admin-mfa-step-up','admin-webauthn-challenge-complete','manufacturer-bootstrap'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  INSERT INTO b01_refresh_wave.refresh_token(
    id,user_id,organization_id,token_hash,expires_at,created_at,created_ip_hash,created_user_agent,
    authenticated_at,mfa_verified_at,last_used_at
  ) VALUES (
    v_id,p_user_id,p_organization_id,p_token_hash,p_expires_at,p_created_at,p_ip_hash,p_user_agent,
    p_authenticated_at,p_mfa_verified_at,p_created_at
  );
  RETURN QUERY SELECT v_id,p_expires_at;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.find_refresh_token_by_hashes(p_hashes text[])
RETURNS TABLE(
  "id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"createdIpHash" text,"createdUserAgent" text,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text
)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog
AS $fn$
DECLARE v_user_id text := current_setting('app.user_id', true);
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    v_user_id, ARRAY['auth-me','auth-session-list','auth-session-revoke','auth-logout'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  RETURN QUERY SELECT token.id,token.user_id,token.organization_id,token.expires_at,token.created_at,
    token.created_ip_hash,token.created_user_agent,token.authenticated_at,token.mfa_verified_at,
    token.last_used_at,token.revoked_at,token.revoked_reason
  FROM b01_refresh_wave.refresh_token token
  WHERE token.user_id = v_user_id AND token.token_hash = ANY(p_hashes)
  LIMIT 1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.find_refresh_token_by_id(p_session_id text,p_user_id text)
RETURNS TABLE(
  "id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"createdIpHash" text,"createdUserAgent" text,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text
)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog
AS $fn$
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    p_user_id, ARRAY['auth-me','auth-session-list','auth-session-revoke','auth-logout'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  RETURN QUERY SELECT token.id,token.user_id,token.organization_id,token.expires_at,token.created_at,
    token.created_ip_hash,token.created_user_agent,token.authenticated_at,token.mfa_verified_at,
    token.last_used_at,token.revoked_at,token.revoked_reason
  FROM b01_refresh_wave.refresh_token token
  WHERE token.id = p_session_id AND token.user_id = p_user_id
  LIMIT 1;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.list_active_refresh_tokens(p_user_id text,p_checked_at timestamp without time zone)
RETURNS TABLE(
  "id" text,"userId" text,"orgId" text,"expiresAt" timestamp without time zone,
  "createdAt" timestamp without time zone,"createdIpHash" text,"createdUserAgent" text,
  "authenticatedAt" timestamp without time zone,"mfaVerifiedAt" timestamp without time zone,
  "lastUsedAt" timestamp without time zone,"revokedAt" timestamp without time zone,"revokedReason" text
)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path = pg_catalog
AS $fn$
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    p_user_id, ARRAY['auth-session-list'], ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  RETURN QUERY SELECT token.id,token.user_id,token.organization_id,token.expires_at,token.created_at,
    token.created_ip_hash,token.created_user_agent,token.authenticated_at,token.mfa_verified_at,
    token.last_used_at,token.revoked_at,token.revoked_reason
  FROM b01_refresh_wave.refresh_token token
  WHERE token.user_id = p_user_id AND token.revoked_at IS NULL AND token.expires_at > p_checked_at
  ORDER BY token.created_at DESC,token.id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_refresh_token_by_hashes(
  p_hashes text[],p_reason text,p_revoked_at timestamp without time zone
)
RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog
AS $fn$
DECLARE v_user_id text := current_setting('app.user_id', true); v_count integer;
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    v_user_id,ARRAY['auth-logout','auth-password-step-up','admin-mfa-step-up','admin-webauthn-challenge-complete'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  IF p_reason NOT IN ('LOGOUT','STEP_UP_REPLACED') THEN RAISE EXCEPTION 'B01_REFRESH_REASON_DENIED'; END IF;
  UPDATE b01_refresh_wave.refresh_token SET revoked_at=p_revoked_at,revoked_reason=p_reason,last_used_at=p_revoked_at
  WHERE user_id=v_user_id AND token_hash=ANY(p_hashes) AND revoked_at IS NULL;
  GET DIAGNOSTICS v_count=ROW_COUNT;
  RETURN QUERY SELECT v_count;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_all_refresh_tokens(
  p_user_id text,p_reason text,p_revoked_at timestamp without time zone
)
RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog
AS $fn$
DECLARE v_count integer;
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    p_user_id,ARRAY['auth-session-revoke-all','admin-mfa-disable','account-disable'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  IF p_reason NOT IN ('ALL_SESSIONS_REVOKED_BY_USER','MFA_DISABLED','ACCOUNT_DISABLED') THEN
    RAISE EXCEPTION 'B01_REFRESH_REASON_DENIED';
  END IF;
  UPDATE b01_refresh_wave.refresh_token SET revoked_at=p_revoked_at,revoked_reason=p_reason,last_used_at=p_revoked_at
  WHERE user_id=p_user_id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_count=ROW_COUNT;
  RETURN QUERY SELECT v_count;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_password_only_refresh_tokens(
  p_user_id text,p_reason text,p_revoked_at timestamp without time zone
)
RETURNS TABLE("revokedCount" integer)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog
AS $fn$
DECLARE v_count integer;
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    p_user_id,ARRAY['auth-refresh-policy-change'],ARRAY['mfa-verified','step-up-verified']
  );
  IF p_reason <> 'MFA_REQUIRED_AFTER_POLICY_CHANGE' THEN RAISE EXCEPTION 'B01_REFRESH_REASON_DENIED'; END IF;
  UPDATE b01_refresh_wave.refresh_token SET revoked_at=p_revoked_at,revoked_reason=p_reason,last_used_at=p_revoked_at
  WHERE user_id=p_user_id AND revoked_at IS NULL AND mfa_verified_at IS NULL;
  GET DIAGNOSTICS v_count=ROW_COUNT;
  RETURN QUERY SELECT v_count;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.revoke_refresh_token_by_id(
  p_session_id text,p_user_id text,p_reason text,p_revoked_at timestamp without time zone
)
RETURNS TABLE("revoked" boolean)
LANGUAGE plpgsql SECURITY DEFINER VOLATILE SET search_path = pg_catalog
AS $fn$
DECLARE v_count integer;
BEGIN
  PERFORM b01_refresh_wave.require_authenticated_context(
    p_user_id,
    ARRAY['auth-session-revoke','auth-logout','auth-password-step-up','admin-mfa-step-up','admin-webauthn-challenge-complete'],
    ARRAY['password-verified','mfa-verified','step-up-verified']
  );
  IF p_reason NOT IN ('SESSION_REVOKED_BY_USER','LOGOUT','STEP_UP_REPLACED') THEN
    RAISE EXCEPTION 'B01_REFRESH_REASON_DENIED';
  END IF;
  UPDATE b01_refresh_wave.refresh_token SET revoked_at=p_revoked_at,revoked_reason=p_reason,last_used_at=p_revoked_at
  WHERE id=p_session_id AND user_id=p_user_id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_count=ROW_COUNT;
  RETURN QUERY SELECT v_count=1;
END
$fn$;

ALTER FUNCTION b01_refresh_wave.require_refresh_bearer(text,text,text[],timestamp without time zone,text,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION b01_refresh_wave.require_authenticated_context(text,text[],text[])
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.load_authenticated_actor()
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.find_refresh_token_by_hashes(text[])
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.find_refresh_token_by_id(text,text)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.list_active_refresh_tokens(text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.revoke_refresh_token_by_hashes(text[],text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.revoke_password_only_refresh_tokens(text,text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;

REVOKE ALL ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.find_refresh_token_by_hashes(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.find_refresh_token_by_id(text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.list_active_refresh_tokens(text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_refresh_token_by_hashes(text[],text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_password_only_refresh_tokens(text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION b01_refresh_wave.require_authenticated_context(text,text[],text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION b01_refresh_wave.require_refresh_bearer(text,text,text[],timestamp without time zone,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.load_authenticated_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_auth.claim_refresh_token_rotation(text[],timestamp without time zone,text) TO mscqr_dev_preauth;
GRANT EXECUTE ON FUNCTION app_auth.load_refresh_session_state(text,text[],text,text,timestamp without time zone,text) TO mscqr_dev_preauth;
GRANT EXECUTE ON FUNCTION app_auth.create_refresh_mfa_challenge(text,text[],text,text,text,integer,text,text[],text,text,integer,timestamp without time zone,timestamp without time zone,text) TO mscqr_dev_preauth;
GRANT EXECUTE ON FUNCTION app_auth.revoke_refresh_token_scope(text,text[],text,text,text,timestamp without time zone) TO mscqr_dev_preauth;
GRANT EXECUTE ON FUNCTION app_auth.complete_refresh_token_rotation(text,text[],text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) TO mscqr_dev_preauth;

GRANT EXECUTE ON FUNCTION app_rls.revalidate_authenticated_actor(text,text,text,text,timestamp without time zone,text) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.load_authenticated_actor() TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.enqueue_audit_log_outbox(jsonb,text,text,text,text,text,text,text,text,timestamp without time zone,text) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.create_refresh_token(text,text,text,timestamp without time zone,text,text,timestamp without time zone,timestamp without time zone,timestamp without time zone) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.find_refresh_token_by_hashes(text[]) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.find_refresh_token_by_id(text,text) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.list_active_refresh_tokens(text,timestamp without time zone) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.revoke_refresh_token_by_hashes(text[],text,timestamp without time zone) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.revoke_all_refresh_tokens(text,text,timestamp without time zone) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.revoke_password_only_refresh_tokens(text,text,timestamp without time zone) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_rls.revoke_refresh_token_by_id(text,text,text,timestamp without time zone) TO mscqr_dev_app;
