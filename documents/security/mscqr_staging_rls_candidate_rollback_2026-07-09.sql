-- MSCQR STAGING-ONLY RLS CANDIDATE ROLLBACK TEMPLATE.
--
-- DO NOT RUN IN PRODUCTION.
-- DO NOT place this file under backend/prisma/migrations.
-- DO NOT run automatically from CI/CD, Prisma, Terraform, or application startup.
--
-- Purpose:
--   Reverse documents/security/mscqr_staging_rls_candidate_templates_2026-07-09.sql.
--   This rollback drops every candidate policy and helper, revokes helper
--   grants introduced by the template, disables FORCE RLS, and disables table
--   RLS for the candidate table set.
--
-- Operator note:
--   Run with the same reviewed non-owner staging runtime database role used for the
--   candidate template:
--     -v mscqr_app_role=<reviewed_staging_application_role>
--     -v mscqr_rls_read_role=<reviewed_staging_rls_read_role>
--     -v mscqr_auth_owner_role=<dedicated_nologin_auth_function_owner_role>
--
--   Do not use PUBLIC.

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

BEGIN;

SELECT set_config('app_rls.rollback_app_role', :'mscqr_app_role', false);
SELECT set_config('app_rls.rollback_read_role', :'mscqr_rls_read_role', false);
SELECT set_config('app_rls.rollback_auth_owner_role', :'mscqr_auth_owner_role', false);

DO $$
DECLARE
  auth_owner_role text := current_setting('app_rls.rollback_auth_owner_role', true);
  app_role text := current_setting('app_rls.rollback_app_role', true);
  read_role text := current_setting('app_rls.rollback_read_role', true);
  auth_owner_oid oid;
BEGIN
  IF '__mscqr_missing__' = ANY(ARRAY[app_role, read_role, auth_owner_role]) THEN
    RAISE EXCEPTION 'Missing one or more required rollback psql variables';
  END IF;

  IF EXISTS (
    SELECT 1 FROM unnest(ARRAY[app_role, read_role, auth_owner_role]) name
    WHERE name !~ '^[a-z_][a-z0-9_]{0,62}$' OR name IN ('public', 'postgres', current_user)
  ) OR cardinality(ARRAY(SELECT DISTINCT unnest(ARRAY[app_role, read_role, auth_owner_role]))) <> 3 THEN
    RAISE EXCEPTION 'Rollback roles must be distinct safe non-reserved identifiers';
  END IF;

  SELECT oid INTO auth_owner_oid FROM pg_roles WHERE rolname = auth_owner_role;
  IF auth_owner_oid IS NULL
     OR COALESCE(shobj_description(auth_owner_oid, 'pg_authid'), '') <> 'mscqr-staging-auth-owner-v1'
     OR to_regnamespace('app_auth') IS NULL
     OR to_regprocedure('app_auth.lookup_password_user(text)') IS NULL
     OR to_regprocedure('app_auth.record_password_failure(text,timestamp without time zone,integer,integer)') IS NULL
     OR NOT has_function_privilege(app_role, 'app_auth.lookup_password_user(text)', 'EXECUTE')
     OR has_function_privilege(read_role, 'app_auth.lookup_password_user(text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'Candidate auth boundary is absent or does not match the reviewed roles; rollback made no changes';
  END IF;

  EXECUTE format(
    'GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE',
    auth_owner_role,
    current_user
  );
END
$$;

-- ---------------------------------------------------------------------------
-- Drop candidate SELECT policies
-- ---------------------------------------------------------------------------

DROP POLICY IF EXISTS rls_candidate_printer_profile_snapshot_select ON "PrinterProfileSnapshot";
DROP POLICY IF EXISTS rls_candidate_printer_profile_select ON "PrinterProfile";
DROP POLICY IF EXISTS rls_candidate_printer_agent_session_select ON "PrinterAgentSession";
DROP POLICY IF EXISTS rls_candidate_printer_attestation_select ON "PrinterAttestation";
DROP POLICY IF EXISTS rls_candidate_printer_select ON "Printer";
DROP POLICY IF EXISTS rls_candidate_printer_registration_select ON "PrinterRegistration";
DROP POLICY IF EXISTS rls_candidate_print_item_select ON "PrintItem";
DROP POLICY IF EXISTS rls_candidate_print_session_select ON "PrintSession";
DROP POLICY IF EXISTS rls_candidate_print_job_select ON "PrintJob";
DROP POLICY IF EXISTS rls_candidate_qrcode_select ON "QRCode";
DROP POLICY IF EXISTS rls_candidate_inventory_status_rollup_select ON "InventoryStatusRollup";
DROP POLICY IF EXISTS rls_candidate_batch_select ON "Batch";
DROP POLICY IF EXISTS rls_candidate_manufacturer_licensee_link_select ON "ManufacturerLicenseeLink";
DROP POLICY IF EXISTS rls_candidate_user_select ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_update ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_owner_read ON "User";
DROP POLICY IF EXISTS rls_candidate_user_auth_owner_update ON "User";
DROP POLICY IF EXISTS rls_candidate_licensee_select ON "Licensee";
DROP POLICY IF EXISTS rls_candidate_organization_select ON "Organization";

-- ---------------------------------------------------------------------------
-- Reverse FORCE RLS and table RLS enablement introduced by the candidate
-- ---------------------------------------------------------------------------

ALTER TABLE "PrinterProfileSnapshot" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfileSnapshot" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfile" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfile" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAgentSession" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAgentSession" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAttestation" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAttestation" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Printer" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "Printer" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterRegistration" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrinterRegistration" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintItem" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrintItem" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintSession" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrintSession" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "InventoryStatusRollup" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "InventoryStatusRollup" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Batch" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "Batch" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "User" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "User" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Organization" NO FORCE ROW LEVEL SECURITY;
ALTER TABLE "Organization" DISABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Revoke candidate helper grants and drop helpers
-- ---------------------------------------------------------------------------

REVOKE EXECUTE ON FUNCTION app_auth.record_password_failure(text, timestamp without time zone, integer, integer)
  FROM :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_auth.lookup_password_user(text) FROM :"mscqr_app_role";
REVOKE USAGE ON SCHEMA app_auth FROM :"mscqr_app_role";
DROP FUNCTION IF EXISTS app_auth.record_password_failure(text, timestamp without time zone, integer, integer);
DROP FUNCTION IF EXISTS app_auth.lookup_password_user(text);
REVOKE SELECT (
  "id", "email", "passwordHash", "name", "role", "licenseeId", "orgId",
  "status", "isActive", "disabledAt", "deletedAt", "failedLoginAttempts",
  "lockedUntil", "lastLoginAt", "emailVerifiedAt"
) ON TABLE "User" FROM :"mscqr_auth_owner_role";
REVOKE UPDATE ("failedLoginAttempts", "lockedUntil", "updatedAt")
  ON TABLE "User" FROM :"mscqr_auth_owner_role";
DROP SCHEMA IF EXISTS app_auth;
REVOKE :"mscqr_auth_owner_role" FROM CURRENT_USER;
DROP ROLE IF EXISTS :"mscqr_auth_owner_role";

-- Exact reversals for the candidate helper signatures only. Do not use blanket
-- function revokes: staging may have unrelated app_rls helpers.
REVOKE EXECUTE ON FUNCTION app_rls.can_access_printer_profile(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_print_item(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_print_session(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_print_job(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_qr(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_printer(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_printer_registration(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_batch(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_organization(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_licensee(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.is_platform_admin() FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_organization_id() FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_manufacturer_id() FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_licensee_id() FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_role() FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_user_id() FROM :"mscqr_rls_read_role", :"mscqr_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.setting(text) FROM :"mscqr_rls_read_role", :"mscqr_app_role";

DROP FUNCTION IF EXISTS app_rls.can_access_printer_profile(text);
DROP FUNCTION IF EXISTS app_rls.can_access_print_item(text);
DROP FUNCTION IF EXISTS app_rls.can_access_print_session(text);
DROP FUNCTION IF EXISTS app_rls.can_access_print_job(text);
DROP FUNCTION IF EXISTS app_rls.can_access_qr(text);
DROP FUNCTION IF EXISTS app_rls.can_access_printer(text);
DROP FUNCTION IF EXISTS app_rls.can_access_printer_registration(text);
DROP FUNCTION IF EXISTS app_rls.can_access_batch(text);
DROP FUNCTION IF EXISTS app_rls.can_access_organization(text);
DROP FUNCTION IF EXISTS app_rls.can_access_licensee(text);
DROP FUNCTION IF EXISTS app_rls.is_platform_admin();
DROP FUNCTION IF EXISTS app_rls.current_organization_id();
DROP FUNCTION IF EXISTS app_rls.current_manufacturer_id();
DROP FUNCTION IF EXISTS app_rls.current_licensee_id();
DROP FUNCTION IF EXISTS app_rls.current_role();
DROP FUNCTION IF EXISTS app_rls.current_user_id();
DROP FUNCTION IF EXISTS app_rls.setting(text);

REVOKE USAGE ON SCHEMA app_rls FROM :"mscqr_rls_read_role", :"mscqr_app_role";
DROP SCHEMA app_rls;

COMMIT;
