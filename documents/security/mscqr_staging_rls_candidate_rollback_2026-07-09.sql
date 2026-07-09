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
--   Run with the same reviewed staging application database role used for the
--   candidate template:
--     -v mscqr_staging_app_role=<reviewed_staging_app_db_role>
--
--   Do not use PUBLIC.

\if :{?mscqr_staging_app_role}
\else
\echo 'Missing required psql variable: -v mscqr_staging_app_role=<reviewed_staging_app_db_role>'
\quit 3
\endif

BEGIN;

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

-- Exact reversals for the candidate helper signatures only. Do not use blanket
-- function revokes: staging may have unrelated app_rls helpers.
REVOKE EXECUTE ON FUNCTION app_rls.can_access_printer_profile(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_print_item(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_print_session(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_print_job(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_qr(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_printer(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_printer_registration(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_batch(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_organization(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.can_access_licensee(text) FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.is_platform_admin() FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_organization_id() FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_manufacturer_id() FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_licensee_id() FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_role() FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.current_user_id() FROM :"mscqr_staging_app_role";
REVOKE EXECUTE ON FUNCTION app_rls.setting(text) FROM :"mscqr_staging_app_role";

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

-- Drop app_rls only if this rollback leaves it empty. If a reviewer has added
-- other staging-reviewed objects to the schema, leave the schema in place.
SELECT set_config('app_rls.rollback_target_role', :'mscqr_staging_app_role', false);

DO $$
DECLARE
  target_role text := current_setting('app_rls.rollback_target_role', true);
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_namespace
    WHERE nspname = 'app_rls'
  ) AND NOT EXISTS (
    SELECT 1
    FROM pg_depend d
    JOIN pg_namespace n ON n.oid = d.refobjid
    WHERE n.nspname = 'app_rls'
      AND d.deptype = 'n'
  ) THEN
    EXECUTE format('REVOKE USAGE ON SCHEMA app_rls FROM %I', target_role);
    DROP SCHEMA app_rls;
  END IF;
END
$$;

SELECT set_config('app_rls.rollback_target_role', '', false);

COMMIT;
