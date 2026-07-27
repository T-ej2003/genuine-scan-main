\ir refreshSessionPostgres18.fixture.sql

DROP SCHEMA IF EXISTS b01_invite_wave CASCADE;
DO $drop_obsolete_invitation_overloads$
DECLARE
  function_signature text;
BEGIN
  FOR function_signature IN
    SELECT procedure.oid::regprocedure::text
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
    WHERE (namespace.nspname='app_rls' AND procedure.proname='prepare_invitation')
       OR (namespace.nspname='app_auth' AND procedure.proname IN (
         'lookup_invitation_token','consume_invitation_token'
       ))
  LOOP
    EXECUTE 'DROP FUNCTION ' || function_signature;
  END LOOP;
END
$drop_obsolete_invitation_overloads$;

CREATE SCHEMA b01_invite_wave;
REVOKE ALL ON SCHEMA b01_invite_wave FROM PUBLIC;
GRANT USAGE ON SCHEMA b01_invite_wave TO mscqr_dev_rls_function_owner;

-- These six tables intentionally mirror the production Organization, Licensee,
-- User, ManufacturerLicenseeLink, Invite and AuditLogOutbox column shapes used
-- by this function family. Test-only names keep the persistent database intact.
CREATE TABLE b01_invite_wave.organization (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name text NOT NULL,
  active boolean NOT NULL DEFAULT true
);

CREATE TABLE b01_invite_wave.licensee (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  organization_id text NOT NULL UNIQUE REFERENCES b01_invite_wave.organization(id),
  name text NOT NULL,
  active boolean NOT NULL DEFAULT true
);

CREATE TABLE b01_invite_wave.invite_user (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  email text NOT NULL UNIQUE,
  name text NOT NULL,
  role text NOT NULL,
  licensee_id text REFERENCES b01_invite_wave.licensee(id),
  organization_id text REFERENCES b01_invite_wave.organization(id),
  status text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  disabled_at timestamp without time zone,
  deleted_at timestamp without time zone,
  password_hash text,
  email_verified_at timestamp without time zone,
  failed_login_attempts integer NOT NULL DEFAULT 0,
  locked_until timestamp without time zone,
  updated_at timestamp without time zone NOT NULL DEFAULT (clock_timestamp() AT TIME ZONE 'UTC')
);

CREATE TABLE b01_invite_wave.manufacturer_link (
  manufacturer_id text NOT NULL REFERENCES b01_invite_wave.invite_user(id),
  licensee_id text NOT NULL REFERENCES b01_invite_wave.licensee(id),
  is_primary boolean NOT NULL DEFAULT false,
  created_at timestamp without time zone NOT NULL,
  updated_at timestamp without time zone NOT NULL,
  PRIMARY KEY (manufacturer_id, licensee_id)
);

CREATE TABLE b01_invite_wave.invite (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  organization_id text NOT NULL REFERENCES b01_invite_wave.organization(id),
  licensee_id text REFERENCES b01_invite_wave.licensee(id),
  email text NOT NULL,
  role text NOT NULL,
  manufacturer_id text,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamp without time zone NOT NULL,
  used_at timestamp without time zone,
  created_by_user_id text,
  accepted_by_user_id text,
  created_at timestamp without time zone NOT NULL
);

CREATE TABLE b01_invite_wave.audit_outbox (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'QUEUED',
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamp without time zone NOT NULL,
  last_error text,
  flushed_audit_log_id text,
  created_at timestamp without time zone NOT NULL,
  updated_at timestamp without time zone NOT NULL
);

CREATE OR REPLACE FUNCTION b01_invite_wave.reject_test_outbox_failure()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
  IF NEW.payload->>'requestId'='force-outbox-failure' THEN
    RAISE EXCEPTION 'B01_TEST_AUDIT_OUTBOX_FAILURE';
  END IF;
  RETURN NEW;
END
$fn$;
CREATE TRIGGER b01_invite_test_outbox_failure
  BEFORE INSERT ON b01_invite_wave.audit_outbox
  FOR EACH ROW EXECUTE FUNCTION b01_invite_wave.reject_test_outbox_failure();

ALTER TABLE b01_invite_wave.organization ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.organization FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.licensee ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.licensee FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.invite_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.invite_user FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.manufacturer_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.manufacturer_link FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.invite ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.invite FORCE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE b01_invite_wave.audit_outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY b01_invite_organization_function_access ON b01_invite_wave.organization
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_invite_licensee_function_access ON b01_invite_wave.licensee
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_invite_user_function_access ON b01_invite_wave.invite_user
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_invite_link_function_access ON b01_invite_wave.manufacturer_link
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_invite_record_function_access ON b01_invite_wave.invite
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);
CREATE POLICY b01_invite_outbox_function_access ON b01_invite_wave.audit_outbox
  FOR ALL TO mscqr_dev_rls_function_owner USING (true) WITH CHECK (true);

GRANT SELECT (id,name,active), INSERT (id,name,active)
  ON b01_invite_wave.organization TO mscqr_dev_rls_function_owner;
GRANT SELECT (id,organization_id,name,active)
  ON b01_invite_wave.licensee TO mscqr_dev_rls_function_owner;
-- PostgreSQL requires one UPDATE column privilege for SELECT ... FOR SHARE.
GRANT UPDATE (id) ON b01_invite_wave.licensee TO mscqr_dev_rls_function_owner;
GRANT SELECT (
  id,email,name,role,licensee_id,organization_id,status,active,disabled_at,deleted_at,
  password_hash,email_verified_at,failed_login_attempts,locked_until,updated_at
) ON b01_invite_wave.invite_user TO mscqr_dev_rls_function_owner;
GRANT INSERT (
  id,email,name,role,licensee_id,organization_id,status,active,password_hash,updated_at
) ON b01_invite_wave.invite_user TO mscqr_dev_rls_function_owner;
GRANT UPDATE (
  name,status,password_hash,email_verified_at,failed_login_attempts,locked_until,updated_at
) ON b01_invite_wave.invite_user TO mscqr_dev_rls_function_owner;
GRANT SELECT (manufacturer_id,licensee_id,is_primary)
  ON b01_invite_wave.manufacturer_link TO mscqr_dev_rls_function_owner;
GRANT INSERT (manufacturer_id,licensee_id,is_primary,created_at,updated_at)
  ON b01_invite_wave.manufacturer_link TO mscqr_dev_rls_function_owner;
GRANT SELECT (
  id,organization_id,licensee_id,email,role,manufacturer_id,token_hash,expires_at,
  used_at,created_by_user_id,accepted_by_user_id,created_at
) ON b01_invite_wave.invite TO mscqr_dev_rls_function_owner;
GRANT INSERT (
  id,organization_id,licensee_id,email,role,manufacturer_id,token_hash,expires_at,
  created_by_user_id,created_at
) ON b01_invite_wave.invite TO mscqr_dev_rls_function_owner;
GRANT UPDATE (used_at,accepted_by_user_id)
  ON b01_invite_wave.invite TO mscqr_dev_rls_function_owner;
GRANT SELECT (payload) ON b01_invite_wave.audit_outbox TO mscqr_dev_rls_function_owner;
GRANT INSERT (
  id,payload,status,attempts,next_attempt_at,last_error,flushed_audit_log_id,created_at,updated_at
) ON b01_invite_wave.audit_outbox TO mscqr_dev_rls_function_owner;

CREATE OR REPLACE FUNCTION b01_invite_wave.require_actor(
  p_actor_user_id text,
  p_actor_session_id text,
  p_request_id text,
  p_purpose text,
  p_checked_at timestamp without time zone
)
RETURNS TABLE(
  actor_email text,
  actor_name text,
  actor_role text,
  actor_organization_id text,
  actor_licensee_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_actor b01_refresh_wave.actor%ROWTYPE;
  v_session b01_refresh_wave.refresh_token%ROWTYPE;
  v_membership b01_refresh_wave.membership%ROWTYPE;
  v_assurance text := current_setting('app.auth_assurance', true);
BEGIN
  IF session_user <> 'mscqr_dev_app'
     OR p_purpose NOT IN ('auth-invite-create','licensee-admin-invite-resend')
     OR p_actor_user_id IS NULL OR p_actor_session_id IS NULL
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128
     OR p_request_id !~ '^[!-~]+$'
     OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at - (clock_timestamp() AT TIME ZONE 'UTC')))) > 300
     OR current_setting('app.user_id', true) IS DISTINCT FROM p_actor_user_id
     OR current_setting('app.request_id', true) IS DISTINCT FROM p_request_id
     OR current_setting('app.purpose', true) IS DISTINCT FROM p_purpose
     OR v_assurance NOT IN ('mfa-verified','step-up-verified') THEN
    RAISE EXCEPTION 'B01_INVITE_ACTOR_DENIED';
  END IF;

  SELECT actor.* INTO v_actor
  FROM b01_refresh_wave.actor AS actor
  WHERE actor.id=p_actor_user_id
    AND actor.active
    AND actor.email_verified_at IS NOT NULL
    AND actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN')
  FOR SHARE;
  IF NOT FOUND
     OR current_setting('app.role', true) IS DISTINCT FROM v_actor.role THEN
    RAISE EXCEPTION 'B01_INVITE_ACTOR_DENIED';
  END IF;

  SELECT token.* INTO v_session
  FROM b01_refresh_wave.refresh_token AS token
  WHERE token.id=p_actor_session_id
    AND token.user_id=v_actor.id
    AND token.revoked_at IS NULL
    AND token.expires_at>p_checked_at
    AND token.mfa_verified_at IS NOT NULL
    AND token.mfa_verified_at>p_checked_at-interval '30 minutes'
    AND token.mfa_verified_at<=p_checked_at+interval '5 minutes'
  FOR SHARE;
  IF NOT FOUND OR NOT v_actor.mfa_enabled THEN
    RAISE EXCEPTION 'B01_INVITE_ACTOR_DENIED';
  END IF;

  IF v_actor.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF v_session.organization_id IS NOT NULL
       OR nullif(current_setting('app.organization_id', true),'') IS NOT NULL
       OR nullif(current_setting('app.licensee_id', true),'') IS NOT NULL
       OR nullif(current_setting('app.manufacturer_id', true),'') IS NOT NULL THEN
      RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED';
    END IF;
  ELSE
    SELECT membership.* INTO v_membership
    FROM b01_refresh_wave.membership AS membership
    WHERE membership.user_id=v_actor.id
      AND membership.licensee_id=v_actor.licensee_id
      AND membership.organization_id=v_actor.organization_id
      AND membership.organization_id=v_session.organization_id
      AND membership.licensee_id=nullif(current_setting('app.licensee_id', true),'')
      AND membership.organization_id=nullif(current_setting('app.organization_id', true),'')
      AND membership.active
    FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED'; END IF;
    IF nullif(current_setting('app.manufacturer_id', true),'') IS NOT NULL THEN
      RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED';
    END IF;
  END IF;

  RETURN QUERY SELECT v_actor.email,v_actor.name,v_actor.role,v_actor.organization_id,v_actor.licensee_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_rls.prepare_invitation(
  p_actor_user_id text,
  p_actor_session_id text,
  p_request_id text,
  p_purpose text,
  p_requested_email text,
  p_requested_name text,
  p_requested_role text,
  p_requested_licensee_id text,
  p_requested_manufacturer_id text,
  p_allow_existing_invited_user boolean,
  p_require_existing_user boolean,
  p_token_hash text,
  p_created_at timestamp without time zone,
  p_expires_at timestamp without time zone,
  p_ip_hash text,
  p_user_agent text
)
RETURNS TABLE(
  "actorDisplayName" text,
  "actorEmail" text,
  "actorUserId" text,
  "inviteEmail" text,
  "inviteExpiresAt" timestamp without time zone,
  "inviteId" text,
  "inviteRole" text,
  "licenseeName" text,
  "linkAction" text,
  "userEmail" text,
  "userId" text,
  "userLicenseeId" text,
  "userName" text,
  "userOrganizationId" text,
  "userRole" text,
  "userStatus" text,
  "workspaceOrganizationId" text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_actor record;
  v_licensee b01_invite_wave.licensee%ROWTYPE;
  v_user b01_invite_wave.invite_user%ROWTYPE;
  v_existing b01_invite_wave.invite%ROWTYPE;
  v_invite b01_invite_wave.invite%ROWTYPE;
  v_retry_payload jsonb;
  v_email text := lower(btrim(coalesce(p_requested_email,'')));
  v_name text := btrim(coalesce(p_requested_name,''));
  v_link_action text;
  v_matches integer;
  v_inserted integer;
  v_organization_id text;
BEGIN
  SELECT * INTO STRICT v_actor
  FROM b01_invite_wave.require_actor(
    p_actor_user_id,p_actor_session_id,p_request_id,p_purpose,p_created_at
  );

  IF v_name='' OR length(v_name)>120
     OR v_name ~ '[[:cntrl:]]'
     OR p_requested_role IS NULL OR p_requested_role NOT IN (
       'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN',
       'MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'
     )
     OR p_allow_existing_invited_user IS NULL OR p_require_existing_user IS NULL
     OR (v_email<>'' AND (length(v_email)>320 OR v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'))
     OR (NOT p_require_existing_user AND v_email='')
     OR p_token_hash IS NULL OR p_token_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$'
     OR p_expires_at IS NULL OR p_expires_at<=p_created_at OR p_expires_at>p_created_at+interval '24 hours'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent,''))>512
     OR coalesce(p_user_agent,'') ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'B01_INVITE_INPUT_DENIED';
  END IF;

  IF p_requested_licensee_id IS NOT NULL THEN
    SELECT licensee.* INTO v_licensee
    FROM b01_invite_wave.licensee AS licensee
    WHERE licensee.id=p_requested_licensee_id AND licensee.active
    FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED'; END IF;
    v_organization_id := v_licensee.organization_id;
  ELSE
    v_organization_id := '00000000-0000-0000-0000-000000000000';
    INSERT INTO b01_invite_wave.organization(id,name,active)
    VALUES (v_organization_id,'Platform',true)
    ON CONFLICT (id) DO NOTHING;
    IF NOT EXISTS (
      SELECT 1 FROM b01_invite_wave.organization AS organization
      WHERE organization.id=v_organization_id AND organization.active
    ) THEN
      RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED';
    END IF;
  END IF;

  IF p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
    IF p_requested_licensee_id IS NOT NULL OR p_requested_manufacturer_id IS NOT NULL THEN
      RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED';
    END IF;
  ELSIF p_requested_licensee_id IS NULL THEN
    RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED';
  END IF;

  IF p_purpose='licensee-admin-invite-resend' THEN
    IF v_actor.actor_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
       OR NOT p_allow_existing_invited_user OR NOT p_require_existing_user
       OR p_requested_licensee_id IS NULL
       OR p_requested_role NOT IN ('LICENSEE_ADMIN','ORG_ADMIN')
       OR p_requested_manufacturer_id IS NOT NULL THEN
      RAISE EXCEPTION 'B01_INVITE_RESEND_DENIED';
    END IF;
  ELSIF v_actor.actor_role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN
    IF p_requested_licensee_id IS DISTINCT FROM v_actor.actor_licensee_id
       OR v_organization_id IS DISTINCT FROM v_actor.actor_organization_id
       OR p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN
      RAISE EXCEPTION 'B01_INVITE_SCOPE_DENIED';
    END IF;
  END IF;

  IF p_requested_manufacturer_id IS NOT NULL
     AND (p_requested_role NOT IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
       OR NOT p_allow_existing_invited_user) THEN
    RAISE EXCEPTION 'B01_INVITE_MANUFACTURER_DENIED';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
    coalesce(p_requested_licensee_id,'platform') || ':' || coalesce(nullif(v_email,''),p_requested_role),0
  ));

  SELECT audit_outbox.payload INTO v_retry_payload
  FROM b01_invite_wave.audit_outbox AS audit_outbox
  WHERE audit_outbox.payload->>'requestId'=p_request_id
    AND audit_outbox.payload->>'action'='AUTH_INVITE_CREATED'
    AND audit_outbox.payload->>'userId'=p_actor_user_id
  ORDER BY audit_outbox.payload->>'entityId'
  LIMIT 1;
  IF FOUND THEN
    SELECT invite.* INTO STRICT v_existing
    FROM b01_invite_wave.invite AS invite
    WHERE invite.id=v_retry_payload->>'entityId';
    IF v_existing.used_at IS NOT NULL
       OR v_existing.token_hash IS DISTINCT FROM p_token_hash
       OR v_existing.email IS DISTINCT FROM v_email
       OR v_existing.role IS DISTINCT FROM p_requested_role
       OR v_existing.licensee_id IS DISTINCT FROM p_requested_licensee_id THEN
      RAISE EXCEPTION 'B01_INVITE_REQUEST_REPLAY_MISMATCH';
    END IF;
    SELECT invite_user.* INTO STRICT v_user
    FROM b01_invite_wave.invite_user AS invite_user
    WHERE invite_user.email=v_existing.email;
    RETURN QUERY SELECT
      v_actor.actor_name,v_actor.actor_email,p_actor_user_id,v_existing.email,v_existing.expires_at,
      v_existing.id,v_existing.role,v_licensee.name,NULL::text,v_user.email,v_user.id,v_user.licensee_id,
      v_user.name,v_user.organization_id,v_user.role,v_user.status,v_existing.organization_id;
    RETURN;
  END IF;

  IF p_require_existing_user THEN
    SELECT count(*)::integer INTO v_matches
    FROM b01_invite_wave.invite_user AS invite_user
    WHERE invite_user.licensee_id=p_requested_licensee_id
      AND invite_user.role IN ('LICENSEE_ADMIN','ORG_ADMIN')
      AND (v_email='' OR invite_user.email=v_email);
    IF v_matches<>1 THEN RAISE EXCEPTION 'B01_INVITE_TARGET_AMBIGUOUS'; END IF;
    SELECT invite_user.* INTO STRICT v_user
    FROM b01_invite_wave.invite_user AS invite_user
    WHERE invite_user.licensee_id=p_requested_licensee_id
      AND invite_user.role IN ('LICENSEE_ADMIN','ORG_ADMIN')
      AND (v_email='' OR invite_user.email=v_email)
    FOR UPDATE;
    IF NOT v_user.active OR v_user.status<>'INVITED' OR v_user.password_hash IS NOT NULL
       OR v_user.disabled_at IS NOT NULL OR v_user.deleted_at IS NOT NULL THEN
      RAISE EXCEPTION 'B01_INVITE_TARGET_DENIED';
    END IF;
    v_email := v_user.email;
  ELSIF p_requested_manufacturer_id IS NOT NULL THEN
    SELECT invite_user.* INTO v_user
    FROM b01_invite_wave.invite_user AS invite_user
    WHERE invite_user.id=p_requested_manufacturer_id
      AND invite_user.email=v_email
      AND invite_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
      AND invite_user.status='ACTIVE' AND invite_user.active
      AND invite_user.disabled_at IS NULL AND invite_user.deleted_at IS NULL
    FOR UPDATE;
    IF NOT FOUND OR p_requested_licensee_id IS NULL THEN
      RAISE EXCEPTION 'B01_INVITE_MANUFACTURER_DENIED';
    END IF;
  ELSE
    SELECT invite_user.* INTO v_user
    FROM b01_invite_wave.invite_user AS invite_user
    WHERE invite_user.email=v_email
    FOR UPDATE;
    IF FOUND THEN
      IF NOT p_allow_existing_invited_user THEN
        RAISE EXCEPTION 'B01_INVITE_ACCOUNT_EXISTS';
      ELSIF v_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
         AND p_requested_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
         AND v_user.status='ACTIVE' AND v_user.active
         AND v_user.disabled_at IS NULL AND v_user.deleted_at IS NULL
         AND p_requested_licensee_id IS NOT NULL THEN
        NULL;
      ELSIF NOT p_allow_existing_invited_user OR v_user.status<>'INVITED'
         OR NOT v_user.active OR v_user.disabled_at IS NOT NULL OR v_user.deleted_at IS NOT NULL
         OR v_user.password_hash IS NOT NULL
         OR (CASE
               WHEN v_user.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
               WHEN v_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
               ELSE v_user.role
             END) IS DISTINCT FROM
             (CASE
               WHEN p_requested_role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
               WHEN p_requested_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
               ELSE p_requested_role
             END)
         OR v_user.licensee_id IS DISTINCT FROM p_requested_licensee_id
         OR (
           p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
           AND v_user.organization_id IS NOT NULL
         )
         OR (
           p_requested_role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
           AND v_user.organization_id IS DISTINCT FROM v_organization_id
         ) THEN
        RAISE EXCEPTION 'B01_INVITE_ACCOUNT_EXISTS';
      END IF;
    ELSE
      INSERT INTO b01_invite_wave.invite_user(
        email,name,role,licensee_id,organization_id,status,active,password_hash,updated_at
      ) VALUES (
        v_email,v_name,p_requested_role,p_requested_licensee_id,
        CASE WHEN p_requested_role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN') THEN NULL ELSE v_organization_id END,
        'INVITED',true,NULL,p_created_at
      ) RETURNING * INTO v_user;
    END IF;
  END IF;

  IF v_user.status='INVITED'
     AND v_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    INSERT INTO b01_invite_wave.manufacturer_link(
      manufacturer_id,licensee_id,is_primary,created_at,updated_at
    )
    SELECT v_user.id,p_requested_licensee_id,
      NOT EXISTS (
        SELECT 1 FROM b01_invite_wave.manufacturer_link AS link
        WHERE link.manufacturer_id=v_user.id AND link.is_primary
      ),
      p_created_at,p_created_at
    ON CONFLICT (manufacturer_id,licensee_id) DO NOTHING;
  END IF;

  IF v_user.status='ACTIVE'
     AND v_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN
    INSERT INTO b01_invite_wave.manufacturer_link(
      manufacturer_id,licensee_id,is_primary,created_at,updated_at
    )
    SELECT v_user.id,p_requested_licensee_id,
      NOT EXISTS (
        SELECT 1 FROM b01_invite_wave.manufacturer_link AS link
        WHERE link.manufacturer_id=v_user.id AND link.is_primary
      ),
      p_created_at,p_created_at
    ON CONFLICT (manufacturer_id,licensee_id) DO NOTHING;
    GET DIAGNOSTICS v_inserted=ROW_COUNT;
    v_link_action := CASE WHEN v_inserted=1 THEN 'LINKED_EXISTING' ELSE 'ALREADY_LINKED' END;
    INSERT INTO b01_invite_wave.audit_outbox(
      payload,status,attempts,next_attempt_at,created_at,updated_at
    ) VALUES (
      jsonb_build_object(
        'userId',p_actor_user_id,'orgId',v_organization_id,'licenseeId',p_requested_licensee_id,
        'action','MANUFACTURER_LICENSEE_LINKED','entityType','User','entityId',v_user.id,
        'requestId',p_request_id,'details',jsonb_build_object(
          'targetUserId',v_user.id,'email',v_user.email,'linkAction',v_link_action
        ),'ipHash',p_ip_hash,'userAgent',p_user_agent
      ),'QUEUED',0,p_created_at,p_created_at,p_created_at
    );
    RETURN QUERY SELECT
      v_actor.actor_name,v_actor.actor_email,p_actor_user_id,v_user.email,NULL::timestamp without time zone,
      NULL::text,p_requested_role,v_licensee.name,v_link_action,v_user.email,v_user.id,v_user.licensee_id,
      v_user.name,v_user.organization_id,v_user.role,v_user.status,v_organization_id;
    RETURN;
  END IF;

  SELECT invite.* INTO v_existing
  FROM b01_invite_wave.invite AS invite
  WHERE invite.email=v_user.email
    AND invite.licensee_id IS NOT DISTINCT FROM p_requested_licensee_id
    AND (CASE
      WHEN invite.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite.role
    END)=(CASE
      WHEN p_requested_role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN p_requested_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE p_requested_role
    END)
    AND invite.used_at IS NULL
  ORDER BY invite.created_at DESC,invite.id
  LIMIT 1
  FOR UPDATE;
  IF FOUND AND v_existing.created_at>=p_created_at-interval '5 seconds' THEN
    RAISE EXCEPTION 'B01_INVITE_ALREADY_ACTIVE';
  END IF;

  UPDATE b01_invite_wave.invite AS invite
  SET used_at=p_created_at
  WHERE invite.email=v_user.email
    AND invite.licensee_id IS NOT DISTINCT FROM p_requested_licensee_id
    AND (CASE
      WHEN invite.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite.role
    END)=(CASE
      WHEN p_requested_role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN p_requested_role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE p_requested_role
    END)
    AND invite.used_at IS NULL;

  INSERT INTO b01_invite_wave.invite(
    organization_id,licensee_id,email,role,manufacturer_id,token_hash,expires_at,
    created_by_user_id,created_at
  ) VALUES (
    v_organization_id,p_requested_licensee_id,v_email,p_requested_role,p_requested_manufacturer_id,
    p_token_hash,p_expires_at,p_actor_user_id,p_created_at
  ) RETURNING * INTO v_invite;

  INSERT INTO b01_invite_wave.audit_outbox(
    payload,status,attempts,next_attempt_at,created_at,updated_at
  ) VALUES (
    jsonb_build_object(
      'userId',p_actor_user_id,'orgId',v_organization_id,'licenseeId',p_requested_licensee_id,
      'action','AUTH_INVITE_CREATED','entityType','Invite','entityId',v_invite.id,
      'requestId',p_request_id,'details',jsonb_build_object(
        'targetUserId',v_user.id,'email',v_email,'role',p_requested_role,
        'expiresAt',p_expires_at,'manufacturerId',p_requested_manufacturer_id
      ),'ipHash',p_ip_hash,'userAgent',p_user_agent
    ),'QUEUED',0,p_created_at,p_created_at,p_created_at
  );

  IF p_purpose='licensee-admin-invite-resend' THEN
    INSERT INTO b01_invite_wave.audit_outbox(
      payload,status,attempts,next_attempt_at,created_at,updated_at
    ) VALUES (
      jsonb_build_object(
        'userId',p_actor_user_id,'orgId',v_organization_id,'licenseeId',p_requested_licensee_id,
        'action','RESEND_LICENSEE_ADMIN_INVITE','entityType','Invite','entityId',v_invite.id,
        'requestId',p_request_id,'details',jsonb_build_object(
          'targetUserId',v_user.id,'email',v_email,'role',p_requested_role
        ),'ipHash',p_ip_hash,'userAgent',p_user_agent
      ),'QUEUED',0,p_created_at,p_created_at,p_created_at
    );
  END IF;

  RETURN QUERY SELECT
    v_actor.actor_name,v_actor.actor_email,p_actor_user_id,v_email,p_expires_at,v_invite.id,
    p_requested_role,v_licensee.name,NULL::text,v_user.email,v_user.id,v_user.licensee_id,
    v_user.name,v_user.organization_id,v_user.role,v_user.status,v_organization_id;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.lookup_invitation_token(
  p_token_hashes text[],
  p_checked_at timestamp without time zone
)
RETURNS TABLE(
  "email" text,
  "role" text,
  "expiresAt" timestamp without time zone,
  "licenseeName" text,
  "requiresConnector" boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_count integer;
BEGIN
  IF session_user<>'mscqr_dev_preauth'
     OR p_checked_at IS NULL
     OR abs(extract(epoch FROM (p_checked_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR coalesce(array_length(p_token_hashes,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hashes) AS candidate(hash) WHERE hash IS NULL OR hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT hash) FROM unnest(p_token_hashes) AS candidate(hash))<>array_length(p_token_hashes,1) THEN
    RAISE EXCEPTION 'B01_INVITE_TOKEN_DENIED';
  END IF;

  SELECT count(*)::integer INTO v_count
  FROM b01_invite_wave.invite AS invite
  JOIN b01_invite_wave.invite_user AS invite_user ON invite_user.email=invite.email
  LEFT JOIN b01_invite_wave.licensee AS licensee ON licensee.id=invite.licensee_id
  JOIN b01_invite_wave.organization AS organization ON organization.id=invite.organization_id
  WHERE invite.token_hash=ANY(p_token_hashes)
    AND invite.used_at IS NULL AND invite.expires_at>p_checked_at
    AND invite.role IN (
      'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN',
      'MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'
    )
    AND (CASE
      WHEN invite_user.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite_user.role
    END)=(CASE
      WHEN invite.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite.role
    END)
    AND invite_user.password_hash IS NULL
    AND (
      (
        invite.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        AND invite.organization_id='00000000-0000-0000-0000-000000000000'
        AND invite.licensee_id IS NULL AND invite.manufacturer_id IS NULL
        AND invite_user.organization_id IS NULL AND invite_user.licensee_id IS NULL
        AND organization.active
      ) OR (
        invite.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        AND invite.licensee_id IS NOT NULL
        AND invite_user.licensee_id=invite.licensee_id
        AND invite_user.organization_id=invite.organization_id
        AND licensee.active AND licensee.organization_id=invite.organization_id
        AND organization.active
      )
    )
    AND (
      invite.manufacturer_id IS NULL OR (
        invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
        AND invite.manufacturer_id=invite_user.id
      )
    )
    AND invite_user.status='INVITED' AND invite_user.active
    AND invite_user.disabled_at IS NULL AND invite_user.deleted_at IS NULL;
  IF v_count<>1 THEN RETURN; END IF;

  RETURN QUERY
  SELECT invite.email,invite.role,invite.expires_at,licensee.name,
    invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
  FROM b01_invite_wave.invite AS invite
  JOIN b01_invite_wave.invite_user AS invite_user ON invite_user.email=invite.email
  LEFT JOIN b01_invite_wave.licensee AS licensee ON licensee.id=invite.licensee_id
  JOIN b01_invite_wave.organization AS organization ON organization.id=invite.organization_id
  WHERE invite.token_hash=ANY(p_token_hashes)
    AND invite.used_at IS NULL AND invite.expires_at>p_checked_at
    AND invite.role IN (
      'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN',
      'MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'
    )
    AND (CASE
      WHEN invite_user.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite_user.role
    END)=(CASE
      WHEN invite.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite.role
    END)
    AND invite_user.password_hash IS NULL
    AND (
      (
        invite.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        AND invite.organization_id='00000000-0000-0000-0000-000000000000'
        AND invite.licensee_id IS NULL AND invite.manufacturer_id IS NULL
        AND invite_user.organization_id IS NULL AND invite_user.licensee_id IS NULL
        AND organization.active
      ) OR (
        invite.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        AND invite.licensee_id IS NOT NULL
        AND invite_user.licensee_id=invite.licensee_id
        AND invite_user.organization_id=invite.organization_id
        AND licensee.active AND licensee.organization_id=invite.organization_id
        AND organization.active
      )
    )
    AND (
      invite.manufacturer_id IS NULL OR (
        invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
        AND invite.manufacturer_id=invite_user.id
      )
    )
    AND invite_user.status='INVITED' AND invite_user.active
    AND invite_user.disabled_at IS NULL AND invite_user.deleted_at IS NULL;
END
$fn$;

CREATE OR REPLACE FUNCTION app_auth.consume_invitation_token(
  p_token_hashes text[],
  p_password_hash text,
  p_requested_name text,
  p_consumed_at timestamp without time zone,
  p_request_id text,
  p_ip_hash text,
  p_user_agent text
)
RETURNS TABLE(
  "inviteId" text,
  "id" text,
  "email" text,
  "name" text,
  "role" text,
  "licenseeId" text,
  "orgId" text,
  "status" text
)
LANGUAGE plpgsql
SECURITY DEFINER
VOLATILE
SET search_path = pg_catalog
AS $fn$
DECLARE
  v_ids text[];
  v_invite b01_invite_wave.invite%ROWTYPE;
  v_user b01_invite_wave.invite_user%ROWTYPE;
  v_name text := nullif(btrim(coalesce(p_requested_name,'')),'');
  v_updated integer;
BEGIN
  IF session_user<>'mscqr_dev_preauth'
     OR p_consumed_at IS NULL
     OR abs(extract(epoch FROM (p_consumed_at-(clock_timestamp() AT TIME ZONE 'UTC'))))>300
     OR coalesce(array_length(p_token_hashes,1),0) NOT BETWEEN 1 AND 3
     OR EXISTS (SELECT 1 FROM unnest(p_token_hashes) AS candidate(hash) WHERE hash IS NULL OR hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR (SELECT count(DISTINCT hash) FROM unnest(p_token_hashes) AS candidate(hash))<>array_length(p_token_hashes,1)
     OR p_password_hash IS NULL OR p_password_hash NOT LIKE '$argon2id$%' OR length(p_password_hash)>512
     OR (v_name IS NOT NULL AND (length(v_name)>120 OR v_name ~ '[[:cntrl:]]'))
     OR p_request_id IS NULL OR length(p_request_id) NOT BETWEEN 1 AND 128 OR p_request_id !~ '^[!-~]+$'
     OR (p_ip_hash IS NOT NULL AND p_ip_hash !~ '^([0-9a-f]{12}:)?[0-9a-f]{64}$')
     OR length(coalesce(p_user_agent,''))>512 OR coalesce(p_user_agent,'') ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'B01_INVITE_CONSUME_DENIED';
  END IF;

  SELECT array_agg(candidate.id ORDER BY candidate.id) INTO v_ids
  FROM (
    SELECT invite.id
    FROM b01_invite_wave.invite AS invite
    WHERE invite.token_hash=ANY(p_token_hashes)
      AND invite.used_at IS NULL AND invite.expires_at>p_consumed_at
    FOR UPDATE OF invite
  ) AS candidate;
  IF coalesce(array_length(v_ids,1),0)<>1 THEN RETURN; END IF;

  SELECT invite.* INTO v_invite
  FROM b01_invite_wave.invite AS invite
  WHERE invite.id=v_ids[1] AND invite.used_at IS NULL AND invite.expires_at>p_consumed_at
  FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;

  SELECT invite_user.* INTO v_user
  FROM b01_invite_wave.invite_user AS invite_user
  WHERE invite_user.email=v_invite.email
    AND v_invite.role IN (
      'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','ORG_ADMIN',
      'MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER'
    )
    AND (CASE
      WHEN invite_user.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN invite_user.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE invite_user.role
    END)=(CASE
      WHEN v_invite.role IN ('LICENSEE_ADMIN','ORG_ADMIN') THEN 'LICENSEE_ADMIN'
      WHEN v_invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER') THEN 'MANUFACTURER'
      ELSE v_invite.role
    END)
    AND invite_user.password_hash IS NULL
    AND (
      (
        v_invite.role IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        AND v_invite.organization_id='00000000-0000-0000-0000-000000000000'
        AND v_invite.licensee_id IS NULL AND v_invite.manufacturer_id IS NULL
        AND invite_user.organization_id IS NULL AND invite_user.licensee_id IS NULL
      ) OR (
        v_invite.role NOT IN ('SUPER_ADMIN','PLATFORM_SUPER_ADMIN')
        AND v_invite.licensee_id IS NOT NULL
        AND invite_user.licensee_id=v_invite.licensee_id
        AND invite_user.organization_id=v_invite.organization_id
      )
    )
    AND (
      v_invite.manufacturer_id IS NULL OR (
        v_invite.role IN ('MANUFACTURER','MANUFACTURER_ADMIN','MANUFACTURER_USER')
        AND v_invite.manufacturer_id=invite_user.id
      )
    )
    AND invite_user.status='INVITED' AND invite_user.active
    AND invite_user.disabled_at IS NULL AND invite_user.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND
     OR NOT EXISTS (
      SELECT 1 FROM b01_invite_wave.organization AS organization
      WHERE organization.id=v_invite.organization_id AND organization.active
    )
     OR (
    v_invite.licensee_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM b01_invite_wave.licensee AS licensee
      WHERE licensee.id=v_invite.licensee_id
        AND licensee.organization_id=v_invite.organization_id
        AND licensee.active
    )
  ) THEN RETURN; END IF;

  UPDATE b01_invite_wave.invite_user AS invite_user
  SET password_hash=p_password_hash,name=coalesce(v_name,invite_user.name),status='ACTIVE',
      email_verified_at=p_consumed_at,failed_login_attempts=0,locked_until=NULL,updated_at=p_consumed_at
  WHERE invite_user.id=v_user.id AND invite_user.status='INVITED'
    AND invite_user.password_hash IS NULL AND invite_user.active
    AND invite_user.disabled_at IS NULL AND invite_user.deleted_at IS NULL;
  GET DIAGNOSTICS v_updated=ROW_COUNT;
  IF v_updated<>1 THEN RETURN; END IF;

  UPDATE b01_invite_wave.invite AS invite
  SET used_at=p_consumed_at,accepted_by_user_id=v_user.id
  WHERE invite.id=v_invite.id AND invite.used_at IS NULL;
  GET DIAGNOSTICS v_updated=ROW_COUNT;
  IF v_updated<>1 THEN RAISE EXCEPTION 'B01_INVITE_CONSUME_LOST'; END IF;

  INSERT INTO b01_invite_wave.audit_outbox(
    payload,status,attempts,next_attempt_at,created_at,updated_at
  ) VALUES (
    jsonb_build_object(
      'userId',v_user.id,'orgId',v_user.organization_id,'licenseeId',v_invite.licensee_id,
      'action','AUTH_INVITE_ACCEPTED','entityType','Invite','entityId',v_invite.id,
      'requestId',p_request_id,'details',jsonb_build_object(
        'targetUserId',v_user.id,'email',v_user.email,'role',v_user.role
      ),'ipHash',p_ip_hash,'userAgent',p_user_agent
    ),'QUEUED',0,p_consumed_at,p_consumed_at,p_consumed_at
  );

  SELECT invite_user.* INTO STRICT v_user
  FROM b01_invite_wave.invite_user AS invite_user WHERE invite_user.id=v_user.id;
  RETURN QUERY SELECT v_invite.id,v_user.id,v_user.email,v_user.name,v_user.role,
    v_user.licensee_id,v_user.organization_id,v_user.status;
END
$fn$;

ALTER FUNCTION b01_invite_wave.require_actor(text,text,text,text,timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_rls.prepare_invitation(
  text,text,text,text,text,text,text,text,text,boolean,boolean,text,
  timestamp without time zone,timestamp without time zone,text,text
) OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.lookup_invitation_token(text[],timestamp without time zone)
  OWNER TO mscqr_dev_rls_function_owner;
ALTER FUNCTION app_auth.consume_invitation_token(
  text[],text,text,timestamp without time zone,text,text,text
) OWNER TO mscqr_dev_rls_function_owner;

REVOKE ALL ON FUNCTION b01_invite_wave.require_actor(text,text,text,text,timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.prepare_invitation(
  text,text,text,text,text,text,text,text,text,boolean,boolean,text,
  timestamp without time zone,timestamp without time zone,text,text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.lookup_invitation_token(text[],timestamp without time zone) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.consume_invitation_token(
  text[],text,text,timestamp without time zone,text,text,text
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.prepare_invitation(
  text,text,text,text,text,text,text,text,text,boolean,boolean,text,
  timestamp without time zone,timestamp without time zone,text,text
) TO mscqr_dev_app;
GRANT EXECUTE ON FUNCTION app_auth.lookup_invitation_token(text[],timestamp without time zone)
  TO mscqr_dev_preauth;
GRANT EXECUTE ON FUNCTION app_auth.consume_invitation_token(
  text[],text,text,timestamp without time zone,text,text,text
) TO mscqr_dev_preauth;
