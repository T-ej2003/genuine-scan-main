-- MSCQR STAGING-ONLY SHARED BATCH RLS PHASE ROLLBACK.
--
-- MANUAL EXECUTION ONLY. This reverses only the 2026-07-15 shared-table phase.
-- It intentionally preserves the six batch-domain tables, their policies,
-- app_rls helpers, runtime table grants, and every printer-domain object.

\set ON_ERROR_STOP on

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
  auth_owner pg_roles%ROWTYPE;
BEGIN
  IF current_database() <> 'mscqr_staging' THEN
    RAISE EXCEPTION 'Shared batch RLS rollback may run only against mscqr_staging';
  END IF;
  IF current_user <> 'mscqr_staging_admin' OR current_role <> 'mscqr_staging_admin' THEN
    RAISE EXCEPTION 'Shared batch RLS rollback requires mscqr_staging_admin as the execution role';
  END IF;
  IF ARRAY[app_role_name, read_role_name, auth_owner_role_name] <>
     ARRAY['mscqr_staging_app', 'mscqr_staging_rls_read', 'mscqr_staging_auth_owner']
     OR '__mscqr_missing__' = ANY(ARRAY[app_role_name, read_role_name, auth_owner_role_name]) THEN
    RAISE EXCEPTION 'Shared batch RLS rollback received missing or unreviewed role names';
  END IF;
  SELECT * INTO auth_owner FROM pg_roles WHERE rolname = auth_owner_role_name;
  IF NOT FOUND OR auth_owner.rolcanlogin OR auth_owner.rolsuper OR auth_owner.rolbypassrls
     OR auth_owner.rolinherit OR auth_owner.rolcreatedb OR auth_owner.rolcreaterole
     OR auth_owner.rolreplication THEN
    RAISE EXCEPTION 'Auth owner role is missing or unsafe';
  END IF;
  IF pg_has_role((SELECT oid FROM pg_roles WHERE rolname = app_role_name), auth_owner.oid, 'SET')
     OR pg_has_role((SELECT oid FROM pg_roles WHERE rolname = read_role_name), auth_owner.oid, 'SET') THEN
    RAISE EXCEPTION 'Runtime role can SET ROLE to the auth owner';
  END IF;
END
$$;

LOCK TABLE "Organization", "Licensee", "User", "ManufacturerLicenseeLink" IN ACCESS EXCLUSIVE MODE;
LOCK TABLE "Batch", "InventoryStatusRollup", "QRCode", "PrintJob", "PrintSession", "PrintItem" IN SHARE MODE;

CREATE TEMP TABLE batch_policy_before ON COMMIT DROP AS
SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles,
       p.polqual::text AS polqual, p.polwithcheck::text AS polwithcheck
FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem']);

CREATE TEMP TABLE printer_posture_before ON COMMIT DROP AS
SELECT c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot']);

CREATE TEMP TABLE printer_policy_before ON COMMIT DROP AS
SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles,
       p.polqual::text AS polqual, p.polwithcheck::text AS polwithcheck
FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relname = ANY(ARRAY['PrinterRegistration','Printer','PrinterAttestation','PrinterAgentSession','PrinterProfile','PrinterProfileSnapshot']);

CREATE TEMP TABLE runtime_grants_before ON COMMIT DROP AS
SELECT role_name, table_name, privilege_name, allowed
FROM (VALUES
  ('mscqr_staging_app','Organization','SELECT'),('mscqr_staging_app','Organization','INSERT'),('mscqr_staging_app','Organization','UPDATE'),('mscqr_staging_app','Organization','DELETE'),
  ('mscqr_staging_app','Licensee','SELECT'),('mscqr_staging_app','Licensee','INSERT'),('mscqr_staging_app','Licensee','UPDATE'),('mscqr_staging_app','Licensee','DELETE'),
  ('mscqr_staging_app','User','SELECT'),('mscqr_staging_app','User','INSERT'),('mscqr_staging_app','User','UPDATE'),('mscqr_staging_app','User','DELETE'),
  ('mscqr_staging_app','ManufacturerLicenseeLink','SELECT'),('mscqr_staging_app','ManufacturerLicenseeLink','INSERT'),('mscqr_staging_app','ManufacturerLicenseeLink','UPDATE'),('mscqr_staging_app','ManufacturerLicenseeLink','DELETE'),
  ('mscqr_staging_rls_read','Organization','SELECT'),('mscqr_staging_rls_read','Organization','INSERT'),('mscqr_staging_rls_read','Organization','UPDATE'),('mscqr_staging_rls_read','Organization','DELETE'),
  ('mscqr_staging_rls_read','Licensee','SELECT'),('mscqr_staging_rls_read','Licensee','INSERT'),('mscqr_staging_rls_read','Licensee','UPDATE'),('mscqr_staging_rls_read','Licensee','DELETE'),
  ('mscqr_staging_rls_read','User','SELECT'),('mscqr_staging_rls_read','User','INSERT'),('mscqr_staging_rls_read','User','UPDATE'),('mscqr_staging_rls_read','User','DELETE'),
  ('mscqr_staging_rls_read','ManufacturerLicenseeLink','SELECT'),('mscqr_staging_rls_read','ManufacturerLicenseeLink','INSERT'),('mscqr_staging_rls_read','ManufacturerLicenseeLink','UPDATE'),('mscqr_staging_rls_read','ManufacturerLicenseeLink','DELETE')
) required(role_name, table_name, privilege_name)
CROSS JOIN LATERAL (
  SELECT has_table_privilege(role_name, format('public.%I', table_name), privilege_name) AS allowed
) privilege;

DO $$
DECLARE
  app_role_name text := current_setting('app_rls.shared_phase_app_role');
  read_role_name text := current_setting('app_rls.shared_phase_read_role');
  auth_owner_role_name text := current_setting('app_rls.shared_phase_auth_owner_role');
  lookup_oid oid := (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'app_auth' AND p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text');
  failure_oid oid := (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'app_auth' AND p.proname = 'record_password_failure'
      AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer');
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'Rollback requires all four shared tables to be fully protected';
  END IF;
  IF (
    SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
  ) <> 7 OR EXISTS (
    SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
      AND p.polname NOT IN (
        'rls_candidate_organization_select','rls_candidate_licensee_select','rls_candidate_user_select',
        'rls_candidate_user_auth_update','rls_candidate_user_auth_owner_read',
        'rls_candidate_user_auth_owner_update','rls_candidate_manufacturer_licensee_link_select'
      )
  ) THEN
    RAISE EXCEPTION 'Rollback requires the exact shared candidate policy set';
  END IF;
  IF (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'app_auth' AND (
        (p.proname = 'lookup_password_user' AND oidvectortypes(p.proargtypes) = 'text')
        OR (p.proname = 'record_password_failure' AND oidvectortypes(p.proargtypes) = 'text, timestamp without time zone, integer, integer')
      )) <> 2 OR NOT has_function_privilege(app_role_name, lookup_oid, 'EXECUTE')
     OR NOT has_function_privilege(app_role_name, failure_oid, 'EXECUTE')
     OR has_function_privilege(read_role_name, lookup_oid, 'EXECUTE')
     OR has_function_privilege(read_role_name, failure_oid, 'EXECUTE')
     OR has_function_privilege('public', lookup_oid, 'EXECUTE')
     OR has_function_privilege('public', failure_oid, 'EXECUTE')
     OR EXISTS (
       SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_roles owner ON owner.oid = p.proowner
       WHERE n.nspname = 'app_auth' AND (
         owner.rolname <> auth_owner_role_name OR NOT p.prosecdef OR p.proconfig <> ARRAY['search_path=pg_catalog']::text[]
         OR (p.proname = 'lookup_password_user' AND (p.provolatile <> 's' OR p.proparallel <> 's'))
         OR (p.proname = 'record_password_failure' AND (p.provolatile <> 'v' OR p.proparallel <> 'u'))
       )
     ) THEN
    RAISE EXCEPTION 'Rollback requires the exact reviewed auth bootstrap boundary';
  END IF;
  IF (SELECT count(*) FROM batch_policy_before) <> 6 OR EXISTS (
    SELECT 1 FROM batch_policy_before p JOIN pg_roles r ON r.oid = ANY(p.polroles)
    WHERE p.polcmd <> 'r' OR cardinality(p.polroles) <> 1 OR r.rolname <> read_role_name
  ) THEN
    RAISE EXCEPTION 'Rollback refuses a changed batch policy baseline';
  END IF;
  IF EXISTS (SELECT 1 FROM printer_posture_before WHERE relrowsecurity OR relforcerowsecurity)
     OR EXISTS (SELECT 1 FROM printer_policy_before WHERE polname LIKE 'rls_candidate_%') THEN
    RAISE EXCEPTION 'Rollback refuses a changed printer-domain baseline';
  END IF;
  IF EXISTS (
    SELECT 1 FROM runtime_grants_before
    WHERE (role_name = app_role_name AND NOT allowed)
       OR (role_name = read_role_name AND privilege_name = 'SELECT' AND NOT allowed)
       OR (role_name = read_role_name AND privilege_name <> 'SELECT' AND allowed)
  ) THEN
    RAISE EXCEPTION 'Runtime table grants do not match the reviewed baseline';
  END IF;

  EXECUTE format(
    'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
    auth_owner_role_name, current_user
  );
END
$$;

-- Only the seven policies introduced by the shared phase are removed.
DROP POLICY rls_candidate_organization_select ON "Organization";
DROP POLICY rls_candidate_licensee_select ON "Licensee";
DROP POLICY rls_candidate_user_select ON "User";
DROP POLICY rls_candidate_user_auth_update ON "User";
DROP POLICY rls_candidate_user_auth_owner_read ON "User";
DROP POLICY rls_candidate_user_auth_owner_update ON "User";
DROP POLICY rls_candidate_manufacturer_licensee_link_select ON "ManufacturerLicenseeLink";

ALTER TABLE "Organization" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "Organization" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "User" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "User" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" DISABLE ROW LEVEL SECURITY;

REVOKE EXECUTE ON FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer)
  FROM :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_auth.lookup_password_user(text) FROM :"mscqr_app_role";
REVOKE USAGE ON SCHEMA app_auth FROM :"mscqr_app_role";
DROP FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer);
DROP FUNCTION app_auth.lookup_password_user(text);
REVOKE SELECT (
  "id", "email", "passwordHash", "name", "role", "licenseeId", "orgId",
  "status", "isActive", "disabledAt", "deletedAt", "failedLoginAttempts",
  "lockedUntil", "lastLoginAt", "emailVerifiedAt"
) ON TABLE "User" FROM :"mscqr_auth_owner_role";
REVOKE UPDATE ("failedLoginAttempts", "lockedUntil", "updatedAt")
  ON TABLE "User" FROM :"mscqr_auth_owner_role";
DROP SCHEMA app_auth;
REVOKE :"mscqr_auth_owner_role" FROM CURRENT_USER;

DO $$
DECLARE
  auth_owner_oid oid := (SELECT oid FROM pg_roles WHERE rolname = current_setting('app_rls.shared_phase_auth_owner_role'));
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
      AND (c.relrowsecurity OR c.relforcerowsecurity)
  ) OR EXISTS (
    SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Organization','Licensee','User','ManufacturerLicenseeLink'])
  ) THEN
    RAISE EXCEPTION 'Rollback postcondition failed: shared RLS or policies remain';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'app_auth')
     OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'app_auth')
     OR EXISTS (SELECT 1 FROM pg_class WHERE relowner = auth_owner_oid)
     OR EXISTS (SELECT 1 FROM pg_namespace WHERE nspowner = auth_owner_oid)
     OR EXISTS (SELECT 1 FROM pg_proc WHERE proowner = auth_owner_oid)
     OR EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = auth_owner_oid OR member = auth_owner_oid) THEN
    RAISE EXCEPTION 'Rollback postcondition failed: auth boundary ownership or membership remains';
  END IF;
  IF EXISTS (
    (SELECT * FROM batch_policy_before EXCEPT
      SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT polrelid FROM batch_policy_before))
    UNION ALL
    (SELECT p.polrelid, p.polname, p.polcmd, p.polpermissive, p.polroles, p.polqual::text, p.polwithcheck::text
      FROM pg_policy p WHERE p.polrelid IN (SELECT polrelid FROM batch_policy_before)
      EXCEPT SELECT * FROM batch_policy_before)
  ) OR EXISTS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = ANY(ARRAY['Batch','InventoryStatusRollup','QRCode','PrintJob','PrintSession','PrintItem'])
      AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity)
  ) THEN
    RAISE EXCEPTION 'Rollback postcondition failed: batch-domain RLS changed';
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
  ) THEN
    RAISE EXCEPTION 'Rollback postcondition failed: printer-domain posture changed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM runtime_grants_before before
    WHERE before.allowed <> has_table_privilege(before.role_name, format('public.%I', before.table_name), before.privilege_name)
  ) THEN
    RAISE EXCEPTION 'Rollback postcondition failed: app or read-role baseline table grants changed';
  END IF;
END
$$;

COMMIT;

SELECT json_build_object(
  'status', 'staging_shared_batch_rls_rolled_back',
  'sharedProtectedTableCount', 0,
  'preservedBatchProtectedTableCount', 6,
  'preservedBatchPolicyCount', 6,
  'printerTablesChanged', false,
  'runtimeTableGrantsChanged', false
);
