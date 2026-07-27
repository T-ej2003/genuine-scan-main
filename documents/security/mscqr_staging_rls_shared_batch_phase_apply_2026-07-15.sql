-- MSCQR STAGING-ONLY SHARED BATCH RLS PHASE APPLY.
--
-- MANUAL EXECUTION ONLY. DO NOT place under Prisma migrations and do not run
-- from CI/CD, Terraform, application startup, or an ECS service deployment.
-- This file changes only Organization, Licensee, User, ManufacturerLicenseeLink
-- and the reviewed app_auth password-bootstrap boundary.

\set ON_ERROR_STOP on

\echo 'BLOCKED: stable revision 7 has contextless User access, while the reviewed User policies do not authorize legacy admin INSERT, DELETE, or cross-user UPDATE.'
\echo 'A separately reviewed shared-table compatibility revision is required before this apply may be enabled.'
DO $$
BEGIN
  RAISE EXCEPTION 'Shared batch RLS apply blocked pending a reviewed shared-table compatibility revision';
END
$$;

\if :{?mscqr_app_role}
\else
\echo 'Missing required psql variable: mscqr_app_role'
\set mscqr_app_role __mscqr_missing__
\endif
\if :{?mscqr_rls_read_role}
\else
\echo 'Missing required psql variable: mscqr_rls_read_role'
\set mscqr_rls_read_role __mscqr_missing__
\endif
\if :{?mscqr_auth_owner_role}
\else
\echo 'Missing required psql variable: mscqr_auth_owner_role'
\set mscqr_auth_owner_role __mscqr_missing__
\endif

BEGIN;
SET LOCAL lock_timeout = '10s';
SET LOCAL statement_timeout = '5min';
SET LOCAL idle_in_transaction_session_timeout = '6min';

SELECT set_config('app_rls.shared_phase_app_role', :'mscqr_app_role', true);
SELECT set_config('app_rls.shared_phase_read_role', :'mscqr_rls_read_role', true);
SELECT set_config('app_rls.shared_phase_auth_owner_role', :'mscqr_auth_owner_role', true);

DO $$
DECLARE
  app_role_name text := current_setting('app_rls.shared_phase_app_role');
  read_role_name text := current_setting('app_rls.shared_phase_read_role');
  auth_owner_role_name text := current_setting('app_rls.shared_phase_auth_owner_role');
  app_role pg_roles%ROWTYPE;
  read_role pg_roles%ROWTYPE;
  auth_owner_role pg_roles%ROWTYPE;
BEGIN
  IF current_database() <> 'mscqr_staging' THEN
    RAISE EXCEPTION 'Shared batch RLS phase may run only against mscqr_staging';
  END IF;
  IF current_user <> 'mscqr_staging_admin' OR current_role <> 'mscqr_staging_admin' THEN
    RAISE EXCEPTION 'Shared batch RLS phase requires mscqr_staging_admin as the execution role';
  END IF;
  IF ARRAY[app_role_name, read_role_name, auth_owner_role_name] <>
     ARRAY['mscqr_staging_app', 'mscqr_staging_rls_read', 'mscqr_staging_auth_owner'] THEN
    RAISE EXCEPTION 'Shared batch RLS phase received unreviewed role names';
  END IF;
  IF '__mscqr_missing__' = ANY(ARRAY[app_role_name, read_role_name, auth_owner_role_name]) THEN
    RAISE EXCEPTION 'Missing one or more required shared batch RLS psql variables';
  END IF;

  SELECT * INTO app_role FROM pg_roles WHERE rolname = app_role_name;
  IF NOT FOUND OR NOT app_role.rolcanlogin OR app_role.rolsuper OR app_role.rolbypassrls
     OR app_role.rolcreatedb OR app_role.rolcreaterole OR app_role.rolreplication THEN
    RAISE EXCEPTION 'Application role is missing or has unsafe attributes';
  END IF;
  SELECT * INTO read_role FROM pg_roles WHERE rolname = read_role_name;
  IF NOT FOUND OR NOT read_role.rolcanlogin OR read_role.rolsuper OR read_role.rolbypassrls
     OR read_role.rolcreatedb OR read_role.rolcreaterole OR read_role.rolreplication THEN
    RAISE EXCEPTION 'RLS read role is missing or has unsafe attributes';
  END IF;
  SELECT * INTO auth_owner_role FROM pg_roles WHERE rolname = auth_owner_role_name;
  IF NOT FOUND OR auth_owner_role.rolcanlogin OR auth_owner_role.rolsuper
     OR auth_owner_role.rolbypassrls OR auth_owner_role.rolinherit
     OR auth_owner_role.rolcreatedb OR auth_owner_role.rolcreaterole
     OR auth_owner_role.rolreplication THEN
    RAISE EXCEPTION 'Auth owner role is missing or has unsafe attributes';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE roleid = auth_owner_role.oid OR member = auth_owner_role.oid
  ) OR pg_has_role(app_role.oid, auth_owner_role.oid, 'SET')
     OR pg_has_role(read_role.oid, auth_owner_role.oid, 'SET') THEN
    RAISE EXCEPTION 'Auth owner role has forbidden memberships or SET ROLE reachability';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_roles owner ON owner.oid = c.relowner
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY[
        'Organization','Licensee','User','ManufacturerLicenseeLink',
        'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
      ])
      AND owner.rolname <> 'mscqr_staging_owner'
  ) OR (
    SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY[
      'Organization','Licensee','User','ManufacturerLicenseeLink',
      'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
    ])
  ) <> 10 THEN
    RAISE EXCEPTION 'Required batch-read tables must exist and be owned by mscqr_staging_owner';
  END IF;
END
$$;

-- Block concurrent policy or table-protection changes for the complete proof
-- graph while this atomic transition is inspected and applied.
LOCK TABLE "Organization", "Licensee", "User", "ManufacturerLicenseeLink" IN ACCESS EXCLUSIVE MODE;
LOCK TABLE "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem" IN SHARE MODE;

CREATE TEMP TABLE batch_policy_before ON COMMIT DROP AS
SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles,
       p.polqual::text AS polqual, p.polwithcheck::text AS polwithcheck
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem']);

CREATE TEMP TABLE shared_policy_before ON COMMIT DROP AS
SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles,
       p.polqual::text AS polqual, p.polwithcheck::text AS polwithcheck
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink']);

CREATE TEMP TABLE printer_posture_before ON COMMIT DROP AS
SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot']);

CREATE TEMP TABLE printer_policy_before ON COMMIT DROP AS
SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles,
       p.polqual::text AS polqual, p.polwithcheck::text AS polwithcheck
FROM pg_policy p
JOIN pg_class c ON c.oid = p.polrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot']);

DO $$
DECLARE
  app_role_name text := current_setting('app_rls.shared_phase_app_role');
  read_role_name text := current_setting('app_rls.shared_phase_read_role');
  auth_owner_role_name text := current_setting('app_rls.shared_phase_auth_owner_role');
  shared_policy_count integer;
  auth_column_grant_count integer;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY['Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'])
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'All six existing batch-domain tables must retain ENABLE and FORCE RLS';
  END IF;
  IF (SELECT count(*) FROM batch_policy_before) <> 6 OR EXISTS (
    SELECT 1
    FROM batch_policy_before p
    JOIN pg_roles role ON role.oid = ANY(p.polroles)
    WHERE p.polcmd <> 'r' OR NOT p.polpermissive OR p.polwithcheck IS NOT NULL
       OR role.rolname <> read_role_name
  ) OR EXISTS (
    SELECT 1 FROM batch_policy_before p
    WHERE cardinality(p.polroles) <> 1
  ) OR EXISTS (
    SELECT expected.table_name, expected.policy_name
    FROM (VALUES
      ('Batch','rls_candidate_batch_select'),
      ('InventoryStatusRollup','rls_candidate_inventory_status_rollup_select'),
      ('QRCode','rls_candidate_qrcode_select'),
      ('PrintJob','rls_candidate_print_job_select'),
      ('PrintSession','rls_candidate_print_session_select'),
      ('PrintItem','rls_candidate_print_item_select')
    ) expected(table_name, policy_name)
    EXCEPT
    SELECT c.relname, p.polname
    FROM batch_policy_before p JOIN pg_class c ON c.oid = p.polrelid
  ) THEN
    RAISE EXCEPTION 'The six existing batch policies are not the reviewed read-role-only set';
  END IF;

  IF EXISTS (SELECT 1 FROM printer_posture_before WHERE relrowsecurity OR relforcerowsecurity)
     OR EXISTS (SELECT 1 FROM printer_policy_before WHERE polname LIKE 'rls_candidate_%') THEN
    RAISE EXCEPTION 'Printer-domain tables must remain outside this RLS phase';
  END IF;

  SELECT count(*) INTO shared_policy_count
  FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink']);
  IF shared_policy_count NOT IN (0, 7) THEN
    RAISE EXCEPTION 'Shared tables contain a partial or unexpected policy set';
  END IF;
  IF shared_policy_count = 0 AND EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
      AND (c.relrowsecurity OR c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'First apply requires all four shared tables to have RLS disabled';
  END IF;
  IF shared_policy_count = 7 AND EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'Idempotent reapply requires all four shared tables to be fully protected';
  END IF;
  IF shared_policy_count = 7 AND (
    EXISTS (
      SELECT 1
      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public'
        AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
        AND p.polname NOT IN (
          'rls_candidate_organization_select','rls_candidate_licensee_select','rls_candidate_user_select',
          'rls_candidate_user_auth_update','rls_candidate_user_auth_owner_read',
          'rls_candidate_user_auth_owner_update','rls_candidate_manufacturer_licensee_link_select'
        )
    ) OR EXISTS (
      SELECT 1
      FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND (
        (c.relname IN ('Organization','Licensee','ManufacturerLicenseeLink') AND
          (p.polcmd <> 'r' OR (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <>
            ARRAY[app_role_name, read_role_name]))
        OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_select' AND
          (p.polcmd <> 'r' OR (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <>
            ARRAY[app_role_name, read_role_name]))
        OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_update' AND
          (p.polcmd <> 'w' OR (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <>
            ARRAY[app_role_name]))
        OR (c.relname = 'User' AND p.polname IN ('rls_candidate_user_auth_owner_read','rls_candidate_user_auth_owner_update') AND
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <>
            ARRAY[auth_owner_role_name])
      )
    )
  ) THEN
    RAISE EXCEPTION 'Idempotent reapply found shared policies with unexpected names, commands, or roles';
  END IF;

  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'app_auth') AND (
    (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'app_auth') <> 2
    OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_auth' AND p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text')
    OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_auth' AND p.proname = 'record_password_failure'
        AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer')
  ) THEN
    RAISE EXCEPTION 'Existing app_auth schema is outside the exact reviewed boundary';
  END IF;
  SELECT count(*) INTO auth_column_grant_count
  FROM pg_attribute a
  CROSS JOIN LATERAL aclexplode(a.attacl) acl
  JOIN pg_roles grantee ON grantee.oid = acl.grantee
  WHERE a.attrelid = 'public."User"'::regclass AND a.attacl IS NOT NULL
    AND grantee.rolname = auth_owner_role_name;
  IF auth_column_grant_count NOT IN (0, 18) THEN
    RAISE EXCEPTION 'Auth owner has a partial or unexpected User column grant set';
  END IF;

  IF EXISTS (
    SELECT 1 FROM (VALUES
      ('is_platform_admin',''), ('current_user_id',''), ('current_role',''),
      ('current_licensee_id',''), ('current_manufacturer_id',''),
      ('can_access_organization','text'), ('can_access_licensee','text'),
      ('can_access_batch','text'), ('can_access_print_job','text')
    ) required(proname, argument_types)
    WHERE NOT EXISTS (
      SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_rls' AND p.proname = required.proname
        AND oidvectortypes(p.proargtypes) = required.argument_types
    )
  ) THEN
    RAISE EXCEPTION 'Required reviewed app_rls helpers are missing';
  END IF;
END
$$;

-- The temporary membership is required only to assign and replace functions
-- owned by the NOLOGIN boundary role. It is revoked before commit.
DO $$
BEGIN
  EXECUTE format(
    'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
    current_setting('app_rls.shared_phase_auth_owner_role'), current_user
  );
END
$$;

CREATE SCHEMA IF NOT EXISTS app_auth;
REVOKE ALL ON SCHEMA app_auth FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA app_auth TO :"mscqr_auth_owner_role";

GRANT SELECT (
  "id", "email", "passwordHash", "name", "role", "licenseeId", "orgId",
  "status", "isActive", "disabledAt", "deletedAt", "failedLoginAttempts",
  "lockedUntil", "lastLoginAt", "emailVerifiedAt"
) ON TABLE "User" TO :"mscqr_auth_owner_role";
GRANT UPDATE ("failedLoginAttempts", "lockedUntil", "updatedAt")
  ON TABLE "User" TO :"mscqr_auth_owner_role";

-- Exact reviewed definitions from
-- mscqr_staging_rls_candidate_templates_2026-07-09.sql.
CREATE OR REPLACE FUNCTION app_auth.lookup_password_user(requested_email text)
RETURNS TABLE (
  "id" text,
  "email" text,
  "passwordHash" text,
  "name" text,
  "role" text,
  "licenseeId" text,
  "orgId" text,
  "status" text,
  "isActive" boolean,
  "disabledAt" timestamp without time zone,
  "deletedAt" timestamp without time zone,
  "failedLoginAttempts" integer,
  "lockedUntil" timestamp without time zone,
  "lastLoginAt" timestamp without time zone,
  "emailVerifiedAt" timestamp without time zone
)
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
  WITH matches AS MATERIALIZED (
    SELECT
      u."id", u."email", u."passwordHash", u."name", u."role",
      u."licenseeId", u."orgId", u."status", u."isActive",
      u."disabledAt", u."deletedAt", u."failedLoginAttempts",
      u."lockedUntil", u."lastLoginAt", u."emailVerifiedAt"
    FROM public."User" u
    WHERE pg_catalog.lower(u."email") = requested_email
    LIMIT 2
  )
  SELECT
    u."id", u."email", u."passwordHash", u."name", u."role"::text,
    u."licenseeId", u."orgId", u."status"::text, u."isActive",
    u."disabledAt", u."deletedAt", u."failedLoginAttempts",
    u."lockedUntil", u."lastLoginAt", u."emailVerifiedAt"
  FROM matches u
  WHERE requested_email = pg_catalog.lower(pg_catalog.btrim(requested_email))
    AND pg_catalog.char_length(requested_email) BETWEEN 3 AND 320
    AND (SELECT pg_catalog.count(*) FROM matches) = 1
$$;

CREATE OR REPLACE FUNCTION app_auth.record_password_failure(
  requested_email text,
  attempted_at timestamp without time zone,
  max_attempts integer,
  lockout_minutes integer
)
RETURNS TABLE (
  "failedLoginAttempts" integer,
  "lockedUntil" timestamp without time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $$
BEGIN
  IF requested_email IS NULL
     OR requested_email <> pg_catalog.lower(pg_catalog.btrim(requested_email))
     OR pg_catalog.char_length(requested_email) NOT BETWEEN 3 AND 320
     OR attempted_at IS NULL
     OR max_attempts IS NULL
     OR lockout_minutes IS NULL
     OR max_attempts NOT BETWEEN 1 AND 100
     OR lockout_minutes NOT BETWEEN 1 AND 1440 THEN
    RETURN;
  END IF;

  RETURN QUERY
    UPDATE public."User" u
    SET
      "failedLoginAttempts" = u."failedLoginAttempts" + 1,
      "lockedUntil" = CASE
        WHEN u."failedLoginAttempts" + 1 >= max_attempts
          THEN attempted_at + pg_catalog.make_interval(mins => lockout_minutes)
        ELSE u."lockedUntil"
      END,
      "updatedAt" = attempted_at
    WHERE u."id" = (
      SELECT pg_catalog.min(candidate."id")
      FROM public."User" candidate
      WHERE pg_catalog.lower(candidate."email") = requested_email
      HAVING pg_catalog.count(*) = 1
    )
    RETURNING u."failedLoginAttempts", u."lockedUntil";
END
$$;

REVOKE ALL ON FUNCTION app_auth.lookup_password_user(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer) FROM PUBLIC;
ALTER FUNCTION app_auth.lookup_password_user(text) OWNER TO :"mscqr_auth_owner_role";
ALTER FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer) OWNER TO :"mscqr_auth_owner_role";
ALTER SCHEMA app_auth OWNER TO :"mscqr_auth_owner_role";
REVOKE CREATE ON SCHEMA app_auth FROM :"mscqr_auth_owner_role";
GRANT USAGE ON SCHEMA app_auth TO :"mscqr_app_role";
REVOKE ALL ON SCHEMA app_auth FROM :"mscqr_rls_read_role";
GRANT EXECUTE ON FUNCTION app_auth.lookup_password_user(text) TO :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer) TO :"mscqr_app_role";
REVOKE ALL ON FUNCTION app_auth.lookup_password_user(text) FROM :"mscqr_rls_read_role";
REVOKE ALL ON FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer) FROM :"mscqr_rls_read_role";

DROP POLICY IF EXISTS rls_candidate_organization_select ON "Organization";
DROP POLICY IF EXISTS rls_candidate_licensee_select ON "Licensee";
DROP POLICY IF EXISTS rls_candidate_user_select ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_update ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_owner_read ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_owner_update ON "User";
DROP POLICY IF EXISTS rls_candidate_manufacturer_licensee_link_select ON "ManufacturerLicenseeLink";

CREATE POLICY rls_candidate_organization_select ON "Organization"
  FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"
  USING (app_rls.can_access_organization("id"));

CREATE POLICY rls_candidate_licensee_select ON "Licensee"
  FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"
  USING (app_rls.can_access_licensee("id"));

CREATE POLICY rls_candidate_user_select ON "User"
  FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"
  USING (
    app_rls.is_platform_admin()
    OR (
      app_rls.current_role() IN ('super_admin', 'platform_super_admin', 'licensee_admin', 'manufacturer')
      AND "id" = app_rls.current_user_id()
    )
    OR (
      app_rls.current_role() = 'licensee_admin'
      AND "licenseeId" = app_rls.current_licensee_id()
    )
    OR EXISTS (
      SELECT 1 FROM "Batch" b
      WHERE b."manufacturerId" = "User"."id"
        AND app_rls.can_access_batch(b."id")
    )
    OR EXISTS (
      SELECT 1 FROM "PrintJob" pj
      WHERE pj."manufacturerId" = "User"."id"
        AND app_rls.can_access_print_job(pj."id")
    )
  );

CREATE POLICY rls_candidate_user_auth_update ON "User"
  FOR UPDATE TO :"mscqr_app_role"
  USING (
    "id" = app_rls.current_user_id()
    AND lower("role"::text) = app_rls.current_role()
    AND app_rls.current_role() IN ('super_admin', 'platform_super_admin', 'licensee_admin', 'manufacturer')
  )
  WITH CHECK (
    "id" = app_rls.current_user_id()
    AND lower("role"::text) = app_rls.current_role()
    AND app_rls.current_role() IN ('super_admin', 'platform_super_admin', 'licensee_admin', 'manufacturer')
  );

CREATE POLICY rls_candidate_user_auth_owner_read ON "User"
  FOR SELECT TO :"mscqr_auth_owner_role"
  USING (true);

CREATE POLICY rls_candidate_user_auth_owner_update ON "User"
  FOR UPDATE TO :"mscqr_auth_owner_role"
  USING (true)
  WITH CHECK (true);

-- Deliberately non-recursive: can_access_licensee() reads this table.
CREATE POLICY rls_candidate_manufacturer_licensee_link_select ON "ManufacturerLicenseeLink"
  FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"
  USING (
    app_rls.is_platform_admin()
    OR (
      app_rls.current_role() = 'manufacturer'
      AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
      AND "manufacturerId" = app_rls.current_manufacturer_id()
    )
    OR (
      app_rls.current_role() = 'licensee_admin'
      AND "licenseeId" = app_rls.current_licensee_id()
    )
  );

-- Protection is enabled only after the auth boundary, grants, and all policies
-- exist in this same transaction.
ALTER TABLE "Organization" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Organization" FORCE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" FORCE ROW LEVEL SECURITY;
ALTER TABLE "User" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "User" FORCE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" FORCE ROW LEVEL SECURITY;

REVOKE :"mscqr_auth_owner_role" FROM CURRENT_USER;

DO $$
DECLARE
  app_role_name text := current_setting('app_rls.shared_phase_app_role');
  read_role_name text := current_setting('app_rls.shared_phase_read_role');
  auth_owner_role_name text := current_setting('app_rls.shared_phase_auth_owner_role');
  auth_owner_oid oid := (SELECT oid FROM pg_roles WHERE rolname = current_setting('app_rls.shared_phase_auth_owner_role'));
  lookup_oid oid := (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'app_auth' AND p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text');
  failure_oid oid := (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'app_auth' AND p.proname = 'record_password_failure'
      AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer');
  auth_owned_count integer;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY[
        'Organization','Licensee','User','ManufacturerLicenseeLink',
        'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
      ]) AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'Postcondition failed: all 10 batch-read tables must have ENABLE and FORCE RLS';
  END IF;

  IF (
    SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND p.polcmd = 'r' AND p.polname IN (
      'rls_candidate_organization_select','rls_candidate_licensee_select','rls_candidate_user_select',
      'rls_candidate_manufacturer_licensee_link_select','rls_candidate_batch_select',
      'rls_candidate_inventory_status_rollup_select','rls_candidate_qrcode_select',
      'rls_candidate_print_job_select','rls_candidate_print_session_select','rls_candidate_print_item_select'
    )
      AND c.relname = ANY(ARRAY[
        'Organization','Licensee','User','ManufacturerLicenseeLink',
        'Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'
      ])
  ) <> 10 THEN
    RAISE EXCEPTION 'Postcondition failed: exactly 10 candidate SELECT policies are required';
  END IF;
  IF (
    SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
  ) <> 7 THEN
    RAISE EXCEPTION 'Postcondition failed: exact seven-policy shared set is required';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND (
      (c.relname IN ('Organization','Licensee','ManufacturerLicenseeLink') AND
        (p.polcmd <> 'r' OR (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <>
          ARRAY[app_role_name, read_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_select' AND
        (p.polcmd <> 'r' OR (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <>
          ARRAY[app_role_name, read_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_update' AND
        (p.polcmd <> 'w' OR p.polwithcheck IS NULL OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[app_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_owner_read' AND
        (p.polcmd <> 'r' OR (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[auth_owner_role_name]))
      OR (c.relname = 'User' AND p.polname = 'rls_candidate_user_auth_owner_update' AND
        (p.polcmd <> 'w' OR p.polwithcheck IS NULL OR
          (SELECT array_agg(r.rolname::text ORDER BY r.rolname) FROM pg_roles r WHERE r.oid = ANY(p.polroles)) <> ARRAY[auth_owner_role_name]))
    )
  ) THEN
    RAISE EXCEPTION 'Postcondition failed: shared policy roles or commands are not exact';
  END IF;
  IF (SELECT count(*) FROM shared_policy_before) = 7 AND EXISTS (
    (SELECT * FROM shared_policy_before EXCEPT
      SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT polrelid FROM shared_policy_before))
    UNION ALL
    (SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT polrelid FROM shared_policy_before)
      EXCEPT SELECT * FROM shared_policy_before)
  ) THEN
    RAISE EXCEPTION 'Postcondition failed: idempotent reapply requires the exact reviewed shared policy definitions';
  END IF;

  IF EXISTS (
    (SELECT * FROM batch_policy_before EXCEPT
      SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT polrelid FROM batch_policy_before))
    UNION ALL
    (SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT polrelid FROM batch_policy_before)
      EXCEPT SELECT * FROM batch_policy_before)
  ) THEN
    RAISE EXCEPTION 'Postcondition failed: existing batch policies changed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM batch_policy_before p JOIN pg_roles r ON r.oid = ANY(p.polroles)
    WHERE cardinality(p.polroles) <> 1 OR r.rolname <> read_role_name
  ) THEN
    RAISE EXCEPTION 'Postcondition failed: batch policies are not read-role-only';
  END IF;

  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_auth' AND (
        (p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text')
        OR (p.proname = 'record_password_failure' AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer')
      )) <> 2 OR EXISTS (
       SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles owner ON owner.oid = p.proowner
       WHERE n.nspname = 'app_auth' AND (
         owner.rolname <> auth_owner_role_name OR NOT p.prosecdef OR p.proconfig <> ARRAY['search_path=pg_catalog']::text[]
         OR (p.proname = 'lookup_password_user' AND (p.provolatile <> 's' OR p.proparallel <> 's'))
         OR (p.proname = 'record_password_failure' AND (p.provolatile <> 'v' OR p.proparallel <> 'u'))
       )
     ) THEN
    RAISE EXCEPTION 'Postcondition failed: auth functions are absent or have unsafe security properties';
  END IF;
  IF has_function_privilege('public', lookup_oid, 'EXECUTE')
     OR has_function_privilege('public', failure_oid, 'EXECUTE')
     OR NOT has_function_privilege(app_role_name, lookup_oid, 'EXECUTE')
     OR NOT has_function_privilege(app_role_name, failure_oid, 'EXECUTE')
     OR has_function_privilege(read_role_name, lookup_oid, 'EXECUTE')
     OR has_function_privilege(read_role_name, failure_oid, 'EXECUTE') THEN
    RAISE EXCEPTION 'Postcondition failed: auth function EXECUTE grants are unsafe';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
    WHERE n.nspname = 'app_auth'
      AND (acl.privilege_type <> 'EXECUTE'
        OR acl.grantee NOT IN (p.proowner, (SELECT oid FROM pg_roles WHERE rolname = app_role_name))
        OR (acl.grantee <> p.proowner AND acl.is_grantable))
  ) OR EXISTS (
    SELECT 1
    FROM pg_namespace n
    CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl
    WHERE n.nspname = 'app_auth'
      AND (acl.privilege_type <> 'USAGE'
        OR acl.grantee NOT IN (n.nspowner, (SELECT oid FROM pg_roles WHERE rolname = app_role_name))
        OR (acl.grantee <> n.nspowner AND acl.is_grantable))
  ) OR EXISTS (
    (SELECT column_name, privilege_type, is_grantable
     FROM information_schema.column_privileges
     WHERE table_schema = 'public' AND table_name = 'User' AND grantee = auth_owner_role_name
     EXCEPT
     SELECT column_name, privilege_type, 'NO'
     FROM (VALUES
       ('id','SELECT'),('email','SELECT'),('passwordHash','SELECT'),('name','SELECT'),
       ('role','SELECT'),('licenseeId','SELECT'),('orgId','SELECT'),('status','SELECT'),
       ('isActive','SELECT'),('disabledAt','SELECT'),('deletedAt','SELECT'),
       ('failedLoginAttempts','SELECT'),('lockedUntil','SELECT'),('lastLoginAt','SELECT'),
       ('emailVerifiedAt','SELECT'),('failedLoginAttempts','UPDATE'),
       ('lockedUntil','UPDATE'),('updatedAt','UPDATE')
     ) expected(column_name, privilege_type))
    UNION ALL
    (SELECT column_name, privilege_type, 'NO'
     FROM (VALUES
       ('id','SELECT'),('email','SELECT'),('passwordHash','SELECT'),('name','SELECT'),
       ('role','SELECT'),('licenseeId','SELECT'),('orgId','SELECT'),('status','SELECT'),
       ('isActive','SELECT'),('disabledAt','SELECT'),('deletedAt','SELECT'),
       ('failedLoginAttempts','SELECT'),('lockedUntil','SELECT'),('lastLoginAt','SELECT'),
       ('emailVerifiedAt','SELECT'),('failedLoginAttempts','UPDATE'),
       ('lockedUntil','UPDATE'),('updatedAt','UPDATE')
     ) expected(column_name, privilege_type)
     EXCEPT
     SELECT column_name, privilege_type, is_grantable
     FROM information_schema.column_privileges
     WHERE table_schema = 'public' AND table_name = 'User' AND grantee = auth_owner_role_name)
  ) OR EXISTS (
    SELECT 1 FROM information_schema.table_privileges
    WHERE table_schema = 'public' AND table_name = 'User' AND grantee = auth_owner_role_name
  ) THEN
    RAISE EXCEPTION 'Postcondition failed: auth schema, function, or User column grants exceed the exact boundary';
  END IF;
  SELECT count(*) INTO auth_owned_count FROM (
    SELECT n.oid FROM pg_namespace n WHERE n.nspowner = auth_owner_oid
    UNION ALL SELECT p.oid FROM pg_proc p WHERE p.proowner = auth_owner_oid
    UNION ALL SELECT c.oid FROM pg_class c WHERE c.relowner = auth_owner_oid
  ) owned;
  IF auth_owned_count <> 3
     OR NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'app_auth' AND nspowner = auth_owner_oid)
     OR (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE p.proowner = auth_owner_oid AND n.nspname = 'app_auth'
           AND p.proname IN ('lookup_password_user','record_password_failure')) <> 2
     OR EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = auth_owner_oid OR member = auth_owner_oid)
     OR pg_has_role((SELECT oid FROM pg_roles WHERE rolname = app_role_name), auth_owner_oid, 'SET') THEN
    RAISE EXCEPTION 'Postcondition failed: auth owner exceeds the exact three-object boundary';
  END IF;

  IF EXISTS (
    (SELECT * FROM printer_posture_before EXCEPT
      SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c WHERE c.oid IN (SELECT oid FROM printer_posture_before))
    UNION ALL
    (SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c WHERE c.oid IN (SELECT oid FROM printer_posture_before)
      EXCEPT SELECT * FROM printer_posture_before)
  ) OR EXISTS (
    (SELECT * FROM printer_policy_before EXCEPT
      SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT oid FROM printer_posture_before))
    UNION ALL
    (SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT oid FROM printer_posture_before)
      EXCEPT SELECT * FROM printer_policy_before)
  ) OR EXISTS (SELECT 1 FROM printer_posture_before WHERE relrowsecurity OR relforcerowsecurity) THEN
    RAISE EXCEPTION 'Postcondition failed: printer-domain posture or policies changed';
  END IF;
END
$$;

COMMIT;

SELECT json_build_object(
  'status', 'staging_shared_batch_rls_applied',
  'protectedTableCount', 10,
  'candidateSelectPolicyCount', 10,
  'sharedPolicyCount', 7,
  'authFunctionCount', 2,
  'printerTablesChanged', false,
  'batchPoliciesChanged', false
);
