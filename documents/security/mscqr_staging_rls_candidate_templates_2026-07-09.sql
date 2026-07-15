-- MSCQR STAGING-ONLY RLS CANDIDATE TEMPLATE.
--
-- DO NOT RUN IN PRODUCTION.
-- DO NOT place this file under backend/prisma/migrations.
-- DO NOT run automatically from CI/CD, Prisma, Terraform, or application startup.
--
-- Purpose:
--   Manually reviewable policy template for the first staging RLS validation
--   candidates and the narrow password-login bootstrap boundary required when
--   User FORCE RLS is active:
--     - GET /api/qr/batches
--     - GET /api/qr/batches/:id/allocation-map
--     - GET /api/manufacturer/printers
--
-- Phase-one application-role boundary:
--   active: SUPER_ADMIN, PLATFORM_SUPER_ADMIN, LICENSEE_ADMIN, MANUFACTURER
--   dormant and denied: ORG_ADMIN, MANUFACTURER_ADMIN, MANUFACTURER_USER
-- Keep dormant enum values for compatibility, but do not add them to a policy
-- without a separately reviewed activation decision and role-matrix proof.
--
-- Operator note:
--   This template enables and forces RLS on the listed tables. It is intended
--   only for a deliberate staging validation window after baseline capture,
--   review, snapshot/backup confirmation, and rollback readiness.
--
-- Required psql variable:
--   -v mscqr_app_role=<reviewed_staging_application_role>
--   -v mscqr_rls_read_role=<reviewed_staging_rls_read_role>
--   -v mscqr_auth_owner_role=<dedicated_nologin_auth_function_owner_role>
--   -v mscqr_enable_shared_force_rls=false
--   -v mscqr_enable_batch_force_rls=true
--   -v mscqr_enable_printer_force_rls=false
--
-- The role must be the exact non-owner staging runtime database role reviewed
-- for this validation window. Do not use PUBLIC or the migration/owner role.

\set ON_ERROR_STOP on

\if :{?mscqr_app_role}
\else
\echo 'Missing required psql variable: -v mscqr_app_role=<reviewed_staging_application_role>'
\set mscqr_app_role __mscqr_missing__
\endif

\if :{?mscqr_rls_read_role}
\else
\echo 'Missing required psql variable: -v mscqr_rls_read_role=<reviewed_staging_rls_read_role>'
\set mscqr_rls_read_role __mscqr_missing__
\endif

\if :{?mscqr_auth_owner_role}
\else
\echo 'Missing required psql variable: -v mscqr_auth_owner_role=<dedicated_nologin_auth_function_owner_role>'
\set mscqr_auth_owner_role __mscqr_missing__
\endif

\if :{?mscqr_enable_shared_force_rls}
\else
\echo 'Missing required psql variable: -v mscqr_enable_shared_force_rls=<true|false>'
\set mscqr_enable_shared_force_rls __mscqr_missing__
\endif
\if :{?mscqr_enable_batch_force_rls}
\else
\echo 'Missing required psql variable: -v mscqr_enable_batch_force_rls=<true|false>'
\set mscqr_enable_batch_force_rls __mscqr_missing__
\endif
\if :{?mscqr_enable_printer_force_rls}
\else
\echo 'Missing required psql variable: -v mscqr_enable_printer_force_rls=<true|false>'
\set mscqr_enable_printer_force_rls __mscqr_missing__
\endif

BEGIN;

-- The migration/DDL connection owns these tables. The runtime role is a
-- separate, least-privileged role and is the only role used for policy probes.
SELECT set_config('app_rls.candidate_app_role', :'mscqr_app_role', false);
SELECT set_config('app_rls.candidate_read_role', :'mscqr_rls_read_role', false);
SELECT set_config('app_rls.candidate_auth_owner_role', :'mscqr_auth_owner_role', false);
SELECT set_config('app_rls.candidate_shared_phase', :'mscqr_enable_shared_force_rls', false);
SELECT set_config('app_rls.candidate_batch_phase', :'mscqr_enable_batch_force_rls', false);
SELECT set_config('app_rls.candidate_printer_phase', :'mscqr_enable_printer_force_rls', false);

DO $$
DECLARE
  app_role_name text := current_setting('app_rls.candidate_app_role', true);
  read_role_name text := current_setting('app_rls.candidate_read_role', true);
  auth_owner_role_name text := current_setting('app_rls.candidate_auth_owner_role', true);
  app_role pg_roles%ROWTYPE;
  read_role pg_roles%ROWTYPE;
  auth_owner_role pg_roles%ROWTYPE;
  auth_owner_marker constant text := 'mscqr-staging-auth-owner-v1';
  owned_tables text[];
BEGIN
  IF '__mscqr_missing__' = ANY(ARRAY[
    app_role_name, read_role_name, auth_owner_role_name,
    current_setting('app_rls.candidate_shared_phase', true),
    current_setting('app_rls.candidate_batch_phase', true),
    current_setting('app_rls.candidate_printer_phase', true)
  ]) THEN
    RAISE EXCEPTION 'Missing one or more required candidate psql variables';
  END IF;

  IF EXISTS (
    SELECT 1 FROM unnest(ARRAY[app_role_name, read_role_name, auth_owner_role_name]) name
    WHERE name !~ '^[a-z_][a-z0-9_]{0,62}$' OR name IN ('public', 'postgres', current_user)
  ) OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[app_role_name, read_role_name, auth_owner_role_name]))) <> 3 THEN
    RAISE EXCEPTION 'Candidate roles must be distinct safe non-reserved identifiers';
  END IF;

  IF EXISTS (
    SELECT 1 FROM unnest(ARRAY[
      current_setting('app_rls.candidate_shared_phase', true),
      current_setting('app_rls.candidate_batch_phase', true),
      current_setting('app_rls.candidate_printer_phase', true)
    ]) value WHERE value NOT IN ('true', 'false')
  ) THEN
    RAISE EXCEPTION 'Candidate phase variables must be literal true or false';
  END IF;

  SELECT * INTO app_role FROM pg_roles WHERE rolname = app_role_name;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Candidate application role % does not exist', app_role_name;
  END IF;
  SELECT * INTO read_role FROM pg_roles WHERE rolname = read_role_name;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Candidate RLS read role % does not exist', read_role_name;
  END IF;

  IF NOT app_role.rolcanlogin OR app_role.rolsuper OR app_role.rolbypassrls OR app_role.rolcreaterole
     OR app_role.rolcreatedb OR app_role.rolreplication OR app_role.rolinherit THEN
    RAISE EXCEPTION 'Candidate application role % has forbidden attributes', app_role_name;
  END IF;
  IF NOT read_role.rolcanlogin OR read_role.rolsuper OR read_role.rolbypassrls OR read_role.rolcreaterole
     OR read_role.rolcreatedb OR read_role.rolreplication OR read_role.rolinherit THEN
    RAISE EXCEPTION 'Candidate RLS read role % has forbidden attributes', read_role_name;
  END IF;

  IF lower(COALESCE(auth_owner_role_name, '')) = 'public'
     OR auth_owner_role_name IN (app_role_name, read_role_name, current_user) THEN
    RAISE EXCEPTION 'Auth function owner must be a distinct dedicated role';
  END IF;

  SELECT * INTO auth_owner_role FROM pg_roles WHERE rolname = auth_owner_role_name;
  IF NOT FOUND THEN
    EXECUTE format(
      'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT',
      auth_owner_role_name
    );
    SELECT * INTO auth_owner_role FROM pg_roles WHERE rolname = auth_owner_role_name;
    EXECUTE format('COMMENT ON ROLE %I IS %L', auth_owner_role_name, auth_owner_marker);
  ELSIF COALESCE(shobj_description(auth_owner_role.oid, 'pg_authid'), '') <> auth_owner_marker THEN
    RAISE EXCEPTION 'Auth function owner % is not candidate-managed', auth_owner_role_name;
  END IF;

  IF auth_owner_role.rolcanlogin OR auth_owner_role.rolsuper OR auth_owner_role.rolbypassrls
     OR auth_owner_role.rolcreaterole OR auth_owner_role.rolcreatedb OR auth_owner_role.rolreplication
     OR auth_owner_role.rolinherit THEN
    RAISE EXCEPTION 'Auth function owner % has forbidden attributes', auth_owner_role_name;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member = auth_owner_role.oid) THEN
    RAISE EXCEPTION 'Auth function owner % must not inherit any database role', auth_owner_role_name;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = auth_owner_role.oid) THEN
    RAISE EXCEPTION 'No database role may be a member of auth function owner %', auth_owner_role_name;
  END IF;

  IF EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN (app_role.oid, read_role.oid)) THEN
    RAISE EXCEPTION 'Candidate application and RLS read roles must not inherit any database role';
  END IF;

  IF has_schema_privilege(app_role_name, 'public', 'CREATE')
     OR has_schema_privilege(read_role_name, 'public', 'CREATE') THEN
    RAISE EXCEPTION 'Candidate runtime roles must not CREATE objects in public';
  END IF;

  IF NOT has_schema_privilege(app_role_name, 'public', 'USAGE')
     OR NOT has_schema_privilege(read_role_name, 'public', 'USAGE') THEN
    RAISE EXCEPTION 'Candidate runtime roles require public schema USAGE';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM (VALUES
      ('User', 'SELECT'), ('User', 'INSERT'), ('User', 'UPDATE'), ('User', 'DELETE'),
      ('Licensee', 'SELECT'), ('Licensee', 'INSERT'), ('Licensee', 'UPDATE'), ('Licensee', 'DELETE'),
      ('RefreshToken', 'SELECT'), ('RefreshToken', 'INSERT'), ('RefreshToken', 'UPDATE'),
      ('ManufacturerLicenseeLink', 'SELECT'), ('ManufacturerLicenseeLink', 'INSERT'), ('ManufacturerLicenseeLink', 'UPDATE'), ('ManufacturerLicenseeLink', 'DELETE'),
      ('Batch', 'SELECT'), ('Batch', 'INSERT'), ('Batch', 'UPDATE'), ('Batch', 'DELETE'),
      ('Printer', 'SELECT'), ('Printer', 'INSERT'), ('Printer', 'UPDATE'), ('Printer', 'DELETE')
    ) required(table_name, privilege_name)
    WHERE NOT has_table_privilege(app_role_name, format('public.%I', required.table_name), required.privilege_name)
  ) THEN
    RAISE EXCEPTION 'Candidate application role does not match the reviewed operational baseline';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink','Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem','PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot'])
      AND (NOT has_table_privilege(read_role_name, c.oid, 'SELECT')
        OR has_table_privilege(read_role_name, c.oid, 'INSERT,UPDATE,DELETE'))
  ) THEN
    RAISE EXCEPTION 'Candidate RLS read role does not match the reviewed SELECT-only baseline';
  END IF;

  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('app_rls', 'app_auth'))
     OR EXISTS (SELECT 1 FROM pg_policy WHERE polname LIKE 'rls_candidate_%') THEN
    RAISE EXCEPTION 'Candidate objects already exist; rollback before reapply';
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink','Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem','PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot'])
      AND (c.relrowsecurity OR c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'Candidate requires the reviewed pre-apply baseline with RLS disabled on all candidate tables';
  END IF;

  SELECT array_agg(c.relname ORDER BY c.relname) INTO owned_tables
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public'
    AND c.relname = ANY(ARRAY[
      'Organization', 'Licensee', 'User', 'ManufacturerLicenseeLink',
      'Batch', 'InventoryStatusRollup', 'QRCode', 'PrintJob', 'PrintSession',
      'PrintItem', 'PrinterRegistration', 'Printer', 'PrinterAttestation',
      'PrinterAgentSession', 'PrinterProfile', 'PrinterProfileSnapshot'
    ])
    AND (pg_has_role(app_role.oid, c.relowner, 'USAGE') OR pg_has_role(read_role.oid, c.relowner, 'USAGE'));

  IF owned_tables IS NOT NULL THEN
    RAISE EXCEPTION 'Candidate runtime role owns or inherits ownership of protected tables: %', owned_tables;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Shared context helpers
-- ---------------------------------------------------------------------------
-- These helpers read transaction-local settings written by the staged RLS
-- wrappers with set_config(..., true). Empty or missing settings return NULL,
-- which makes downstream predicates fail closed unless app.is_platform_admin is
-- explicitly true.

CREATE SCHEMA IF NOT EXISTS app_rls;
REVOKE ALL ON SCHEMA app_rls FROM PUBLIC;

CREATE OR REPLACE FUNCTION app_rls.setting(name text)
RETURNS text
LANGUAGE sql
STABLE
AS $$
  SELECT NULLIF(current_setting(name, true), '')
$$;

CREATE OR REPLACE FUNCTION app_rls.current_user_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT app_rls.setting('app.user_id') $$;

CREATE OR REPLACE FUNCTION app_rls.current_role()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT lower(COALESCE(app_rls.setting('app.role'), '')) $$;

CREATE OR REPLACE FUNCTION app_rls.current_licensee_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT app_rls.setting('app.licensee_id') $$;

CREATE OR REPLACE FUNCTION app_rls.current_manufacturer_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT app_rls.setting('app.manufacturer_id') $$;

CREATE OR REPLACE FUNCTION app_rls.current_organization_id()
RETURNS text
LANGUAGE sql
STABLE
AS $$ SELECT app_rls.setting('app.organization_id') $$;

CREATE OR REPLACE FUNCTION app_rls.is_platform_admin()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT app_rls.current_role() IN ('super_admin', 'platform_super_admin')
    AND lower(COALESCE(app_rls.setting('app.is_platform_admin'), 'false')) = 'true'
$$;

-- PostgreSQL grants EXECUTE on new functions to PUBLIC by default. Revoke that
-- implicit access for every exact helper signature before granting the runtime
-- role below.
REVOKE ALL ON FUNCTION app_rls.setting(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.current_user_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.current_role() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.current_licensee_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.current_manufacturer_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.current_organization_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.is_platform_admin() FROM PUBLIC;

-- Schema usage is granted only to the explicitly reviewed staging runtime
-- role supplied by psql. Helper execution grants below are exact signatures.
GRANT USAGE ON SCHEMA app_rls TO :"mscqr_rls_read_role", :"mscqr_app_role";

-- ---------------------------------------------------------------------------
-- Password-login bootstrap boundary
-- ---------------------------------------------------------------------------
-- The dedicated NOLOGIN owner receives only the User columns needed by these
-- two SECURITY DEFINER functions. The runtime role can execute the functions
-- but cannot assume or inherit their owner role.

DO $$
BEGIN
  EXECUTE format(
    'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
    current_setting('app_rls.candidate_auth_owner_role', true),
    current_user
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
GRANT EXECUTE ON FUNCTION app_auth.lookup_password_user(text) TO :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer)
  TO :"mscqr_app_role";

REVOKE :"mscqr_auth_owner_role" FROM CURRENT_USER;

DO $$
DECLARE
  auth_owner_oid oid := (SELECT oid FROM pg_roles WHERE rolname = current_setting('app_rls.candidate_auth_owner_role', true));
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class WHERE relowner = auth_owner_oid)
     OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = auth_owner_oid OR roleid = auth_owner_oid)
     OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner = auth_owner_oid AND nspname <> 'app_auth')
     OR EXISTS (
       SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       WHERE p.proowner = auth_owner_oid
         AND NOT (n.nspname = 'app_auth' AND p.proname IN ('lookup_password_user', 'record_password_failure'))
     )
     OR (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE p.proowner = auth_owner_oid AND n.nspname = 'app_auth') <> 2 THEN
    RAISE EXCEPTION 'Auth function owner owns objects outside the exact app_auth boundary';
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Non-recursive access helpers
-- ---------------------------------------------------------------------------
-- Design rule:
--   Helpers may read parent tables, but a table policy must not call a helper
--   that reads the same table and then depends back on that table policy. In
--   particular, ManufacturerLicenseeLink policies do not call can_access_licensee
--   because can_access_licensee reads ManufacturerLicenseeLink.

CREATE OR REPLACE FUNCTION app_rls.can_access_licensee(target_licensee_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_licensee_id IS NOT NULL
    AND (
      app_rls.is_platform_admin()
      OR (
        app_rls.current_role() = 'licensee_admin'
        AND target_licensee_id = app_rls.current_licensee_id()
      )
      OR EXISTS (
        SELECT 1
        FROM "ManufacturerLicenseeLink" mll
        WHERE app_rls.current_role() = 'manufacturer'
          AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
          AND mll."manufacturerId" = app_rls.current_manufacturer_id()
          AND mll."licenseeId" = target_licensee_id
      )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_organization(target_org_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_org_id IS NOT NULL
    AND (
      app_rls.is_platform_admin()
      OR (
        app_rls.current_role() IN ('licensee_admin', 'manufacturer')
        AND target_org_id = app_rls.current_organization_id()
      )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_batch(target_batch_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_batch_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "Batch" b
      WHERE b."id" = target_batch_id
        AND (
          app_rls.can_access_licensee(b."licenseeId")
          OR (
            app_rls.current_role() = 'manufacturer'
            AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
            AND b."manufacturerId" = app_rls.current_manufacturer_id()
          )
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_qr(target_qr_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_qr_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "QRCode" q
      WHERE q."id" = target_qr_id
        AND (
          app_rls.can_access_licensee(q."licenseeId")
          OR app_rls.can_access_batch(q."batchId")
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_printer_registration(target_registration_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_registration_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "PrinterRegistration" pr
      WHERE pr."id" = target_registration_id
        AND (
          app_rls.is_platform_admin()
          OR (
            app_rls.current_role() IN ('licensee_admin', 'manufacturer')
            AND pr."userId" = app_rls.current_user_id()
          )
          OR app_rls.can_access_licensee(pr."licenseeId")
          OR app_rls.can_access_organization(pr."orgId")
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_printer(target_printer_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_printer_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "Printer" p
      WHERE p."id" = target_printer_id
        AND (
          app_rls.is_platform_admin()
          OR app_rls.can_access_licensee(p."licenseeId")
          OR app_rls.can_access_organization(p."orgId")
          OR (
            app_rls.current_role() IN ('licensee_admin', 'manufacturer')
            AND (
              p."assignedUserId" = app_rls.current_user_id()
              OR p."createdByUserId" = app_rls.current_user_id()
            )
          )
          OR app_rls.can_access_printer_registration(p."printerRegistrationId")
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_print_job(target_print_job_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_print_job_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "PrintJob" pj
      WHERE pj."id" = target_print_job_id
        AND (
          app_rls.is_platform_admin()
          OR (
            app_rls.current_role() = 'manufacturer'
            AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
            AND pj."manufacturerId" = app_rls.current_manufacturer_id()
          )
          OR app_rls.can_access_batch(pj."batchId")
          OR app_rls.can_access_printer(pj."printerId")
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_print_session(target_print_session_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_print_session_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "PrintSession" ps
      WHERE ps."id" = target_print_session_id
        AND (
          app_rls.is_platform_admin()
          OR (
            app_rls.current_role() = 'manufacturer'
            AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
            AND ps."manufacturerId" = app_rls.current_manufacturer_id()
          )
          OR app_rls.can_access_batch(ps."batchId")
          OR app_rls.can_access_print_job(ps."printJobId")
          OR app_rls.can_access_printer(ps."printerId")
          OR app_rls.can_access_printer_registration(ps."printerRegistrationId")
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_print_item(target_print_item_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_print_item_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "PrintItem" pi
      WHERE pi."id" = target_print_item_id
        AND (
          app_rls.can_access_qr(pi."qrCodeId")
          OR app_rls.can_access_print_session(pi."printSessionId")
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_printer_profile(target_profile_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    target_profile_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "PrinterProfile" pp
      WHERE pp."id" = target_profile_id
        AND app_rls.can_access_printer(pp."printerId")
    )
$$;

-- Exact helper execution grants. Do not use blanket function grants: staging
-- may already have unrelated helpers in app_rls.
REVOKE ALL ON FUNCTION app_rls.can_access_licensee(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_organization(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_batch(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_qr(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_printer_registration(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_printer(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_print_job(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_print_session(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_print_item(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app_rls.can_access_printer_profile(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION app_rls.setting(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_user_id() TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_role() TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_licensee_id() TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_manufacturer_id() TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_organization_id() TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.is_platform_admin() TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_licensee(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_organization(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_batch(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_qr(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_printer_registration(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_printer(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_print_job(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_print_session(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_print_item(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_printer_profile(text) TO :"mscqr_rls_read_role", :"mscqr_app_role";

-- Candidate apply never rewrites the application or read-role table baseline.
-- Rollback therefore removes candidate grants without reconstructing operational
-- CRUD from an incomplete list.

-- ---------------------------------------------------------------------------
-- Idempotent policy reset for this candidate template only
-- ---------------------------------------------------------------------------

DROP POLICY IF EXISTS rls_candidate_organization_select ON "Organization";
DROP POLICY IF EXISTS rls_candidate_licensee_select ON "Licensee";
DROP POLICY IF EXISTS rls_candidate_user_select ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_update ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_owner_read ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_owner_update ON "User";
DROP POLICY IF EXISTS rls_candidate_manufacturer_licensee_link_select ON "ManufacturerLicenseeLink";
DROP POLICY IF EXISTS rls_candidate_batch_select ON "Batch";
DROP POLICY IF EXISTS rls_candidate_inventory_status_rollup_select ON "InventoryStatusRollup";
DROP POLICY IF EXISTS rls_candidate_qrcode_select ON "QRCode";
DROP POLICY IF EXISTS rls_candidate_print_job_select ON "PrintJob";
DROP POLICY IF EXISTS rls_candidate_print_session_select ON "PrintSession";
DROP POLICY IF EXISTS rls_candidate_print_item_select ON "PrintItem";
DROP POLICY IF EXISTS rls_candidate_printer_select ON "Printer";
DROP POLICY IF EXISTS rls_candidate_printer_registration_select ON "PrinterRegistration";
DROP POLICY IF EXISTS rls_candidate_printer_attestation_select ON "PrinterAttestation";
DROP POLICY IF EXISTS rls_candidate_printer_agent_session_select ON "PrinterAgentSession";
DROP POLICY IF EXISTS rls_candidate_printer_profile_select ON "PrinterProfile";
DROP POLICY IF EXISTS rls_candidate_printer_profile_snapshot_select ON "PrinterProfileSnapshot";

-- ---------------------------------------------------------------------------
-- Shared tenant tables for all candidate routes
-- ---------------------------------------------------------------------------

\if :mscqr_enable_shared_force_rls
ALTER TABLE "Organization" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Organization" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_organization_select ON "Organization"
  FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_organization("id")
  );

ALTER TABLE "Licensee" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_licensee_select ON "Licensee"
  FOR SELECT TO :"mscqr_app_role", :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_licensee("id")
  );

ALTER TABLE "User" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "User" FORCE ROW LEVEL SECURITY;

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
      SELECT 1
      FROM "Batch" b
      WHERE b."manufacturerId" = "User"."id"
        AND app_rls.can_access_batch(b."id")
    )
    OR EXISTS (
      SELECT 1
      FROM "PrintJob" pj
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

-- The NOLOGIN function owner is the only role allowed to cross the pre-auth
-- User boundary, and only through the exact SECURITY DEFINER functions above.
CREATE POLICY rls_candidate_user_auth_owner_read ON "User"
  FOR SELECT TO :"mscqr_auth_owner_role"
  USING (true);

CREATE POLICY rls_candidate_user_auth_owner_update ON "User"
  FOR UPDATE TO :"mscqr_auth_owner_role"
  USING (true)
  WITH CHECK (true);

ALTER TABLE "ManufacturerLicenseeLink" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" FORCE ROW LEVEL SECURITY;

-- Non-recursive by design. This policy must not call can_access_licensee()
-- because can_access_licensee() reads ManufacturerLicenseeLink.
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
\endif

-- ---------------------------------------------------------------------------
-- Route: GET /api/qr/batches
-- Route: GET /api/qr/batches/:id/allocation-map
-- Tables: Batch, InventoryStatusRollup, QRCode, PrintJob, PrintSession, PrintItem
-- ---------------------------------------------------------------------------

\if :mscqr_enable_batch_force_rls
ALTER TABLE "Batch" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Batch" FORCE ROW LEVEL SECURITY;

-- The licensee path intentionally supports linked-licensee access for
-- allocation-map lineage. The app-layer focus-batch check still controls which
-- allocation map is requested.
CREATE POLICY rls_candidate_batch_select ON "Batch"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR (
      app_rls.current_role() = 'manufacturer'
      AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
      AND "manufacturerId" = app_rls.current_manufacturer_id()
    )
  );

ALTER TABLE "InventoryStatusRollup" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "InventoryStatusRollup" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_inventory_status_rollup_select ON "InventoryStatusRollup"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR (
      app_rls.current_role() = 'manufacturer'
      AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
      AND "manufacturerId" = app_rls.current_manufacturer_id()
    )
    OR app_rls.can_access_batch("batchId")
  );

ALTER TABLE "QRCode" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" FORCE ROW LEVEL SECURITY;

-- QRCode is the base table for groupBy and reservable-summary raw SQL. It must
-- remain aligned with Batch visibility.
CREATE POLICY rls_candidate_qrcode_select ON "QRCode"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_batch("batchId")
    OR app_rls.can_access_print_job("printJobId")
  );

ALTER TABLE "PrintJob" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_print_job_select ON "PrintJob"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.is_platform_admin()
    OR (
      app_rls.current_role() = 'manufacturer'
      AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
      AND "manufacturerId" = app_rls.current_manufacturer_id()
    )
    OR app_rls.can_access_batch("batchId")
    OR app_rls.can_access_printer("printerId")
  );

ALTER TABLE "PrintSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintSession" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_print_session_select ON "PrintSession"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.is_platform_admin()
    OR (
      app_rls.current_role() = 'manufacturer'
      AND app_rls.current_manufacturer_id() = app_rls.current_user_id()
      AND "manufacturerId" = app_rls.current_manufacturer_id()
    )
    OR app_rls.can_access_batch("batchId")
    OR app_rls.can_access_print_job("printJobId")
    OR app_rls.can_access_printer("printerId")
    OR app_rls.can_access_printer_registration("printerRegistrationId")
  );

ALTER TABLE "PrintItem" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintItem" FORCE ROW LEVEL SECURITY;

-- PrintItem is left-joined from QRCode in raw reservable summaries. Any visible
-- QR row must expose its PrintItem row so counts do not drift.
CREATE POLICY rls_candidate_print_item_select ON "PrintItem"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_qr("qrCodeId")
    OR app_rls.can_access_print_session("printSessionId")
  );
\endif

-- ---------------------------------------------------------------------------
-- Route: GET /api/manufacturer/printers
-- Tables: Printer, PrinterRegistration, PrinterAttestation,
--         PrinterAgentSession, PrinterProfile, PrinterProfileSnapshot
-- ---------------------------------------------------------------------------

\if :mscqr_enable_printer_force_rls
ALTER TABLE "PrinterRegistration" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterRegistration" FORCE ROW LEVEL SECURITY;

-- Registration is the non-recursive parent for local-agent status tables.
-- Avoid depending on Printer here so Printer can safely depend on Registration.
CREATE POLICY rls_candidate_printer_registration_select ON "PrinterRegistration"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.is_platform_admin()
    OR (
      app_rls.current_role() IN ('licensee_admin', 'manufacturer')
      AND "userId" = app_rls.current_user_id()
    )
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
  );

ALTER TABLE "Printer" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Printer" FORCE ROW LEVEL SECURITY;

-- No isActive predicate belongs here. Inactive printer behavior remains an
-- application query-filter concern, not a global RLS visibility rule.
CREATE POLICY rls_candidate_printer_select ON "Printer"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.is_platform_admin()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
    OR (
      app_rls.current_role() IN ('licensee_admin', 'manufacturer')
      AND (
        "assignedUserId" = app_rls.current_user_id()
        OR "createdByUserId" = app_rls.current_user_id()
      )
    )
    OR app_rls.can_access_printer_registration("printerRegistrationId")
  );

ALTER TABLE "PrinterAttestation" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAttestation" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_attestation_select ON "PrinterAttestation"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_printer_registration("printerRegistrationId")
  );

ALTER TABLE "PrinterAgentSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAgentSession" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_agent_session_select ON "PrinterAgentSession"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_printer_registration("registrationId")
    OR app_rls.can_access_print_job("activePrintJobId")
  );

ALTER TABLE "PrinterProfile" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfile" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_profile_select ON "PrinterProfile"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_printer("printerId")
  );

ALTER TABLE "PrinterProfileSnapshot" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfileSnapshot" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_profile_snapshot_select ON "PrinterProfileSnapshot"
  FOR SELECT TO :"mscqr_rls_read_role"
  USING (
    app_rls.can_access_printer_profile("printerProfileId")
  );
\endif

COMMIT;

SELECT set_config('app_rls.candidate_runtime_role', '', false);
