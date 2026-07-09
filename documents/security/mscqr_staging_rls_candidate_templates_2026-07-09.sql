-- MSCQR STAGING-ONLY RLS CANDIDATE TEMPLATE.
--
-- DO NOT RUN IN PRODUCTION.
-- DO NOT place this file under backend/prisma/migrations.
-- DO NOT run automatically from CI/CD, Prisma, Terraform, or application startup.
--
-- Purpose:
--   Manually reviewable SELECT policy template for the first staging RLS
--   validation candidates:
--     - GET /api/qr/batches
--     - GET /api/qr/batches/:id/allocation-map
--     - GET /api/manufacturer/printers
--
-- Operator note:
--   This template enables and forces RLS on the listed tables. It is intended
--   only for a deliberate staging validation window after baseline capture,
--   review, snapshot/backup confirmation, and rollback readiness.
--
-- Required psql variable:
--   -v mscqr_staging_app_role=<reviewed_staging_app_db_role>
--
-- The role must be the exact staging application database role reviewed for
-- this validation window. Do not use PUBLIC.

\if :{?mscqr_staging_app_role}
\else
\echo 'Missing required psql variable: -v mscqr_staging_app_role=<reviewed_staging_app_db_role>'
\quit 3
\endif

BEGIN;

-- ---------------------------------------------------------------------------
-- Shared context helpers
-- ---------------------------------------------------------------------------
-- These helpers read transaction-local settings written by the staged RLS
-- wrappers with set_config(..., true). Empty or missing settings return NULL,
-- which makes downstream predicates fail closed unless app.is_platform_admin is
-- explicitly true.

CREATE SCHEMA IF NOT EXISTS app_rls;

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
  SELECT lower(COALESCE(app_rls.setting('app.is_platform_admin'), 'false')) = 'true'
$$;

-- Schema usage is granted only to the explicitly reviewed staging application
-- role supplied by psql. Helper execution grants below are exact signatures.
GRANT USAGE ON SCHEMA app_rls TO :"mscqr_staging_app_role";

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
      OR target_licensee_id = app_rls.current_licensee_id()
      OR EXISTS (
        SELECT 1
        FROM "ManufacturerLicenseeLink" mll
        WHERE mll."manufacturerId" = app_rls.current_manufacturer_id()
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
      OR target_org_id = app_rls.current_organization_id()
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
          OR b."manufacturerId" = app_rls.current_manufacturer_id()
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
          OR pr."userId" = app_rls.current_user_id()
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
          OR p."assignedUserId" = app_rls.current_user_id()
          OR p."createdByUserId" = app_rls.current_user_id()
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
          OR pj."manufacturerId" = app_rls.current_manufacturer_id()
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
          OR ps."manufacturerId" = app_rls.current_manufacturer_id()
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
GRANT EXECUTE ON FUNCTION app_rls.setting(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_user_id() TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_role() TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_licensee_id() TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_manufacturer_id() TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.current_organization_id() TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.is_platform_admin() TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_licensee(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_organization(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_batch(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_qr(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_printer_registration(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_printer(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_print_job(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_print_session(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_print_item(text) TO :"mscqr_staging_app_role";
GRANT EXECUTE ON FUNCTION app_rls.can_access_printer_profile(text) TO :"mscqr_staging_app_role";

-- ---------------------------------------------------------------------------
-- Idempotent policy reset for this candidate template only
-- ---------------------------------------------------------------------------

DROP POLICY IF EXISTS rls_candidate_organization_select ON "Organization";
DROP POLICY IF EXISTS rls_candidate_licensee_select ON "Licensee";
DROP POLICY IF EXISTS rls_candidate_user_select ON "User";
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

ALTER TABLE "Organization" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Organization" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_organization_select ON "Organization"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "id" = app_rls.current_organization_id()
  );

ALTER TABLE "Licensee" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_licensee_select ON "Licensee"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("id")
    OR "orgId" = app_rls.current_organization_id()
  );

ALTER TABLE "User" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "User" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_user_select ON "User"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "id" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
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

ALTER TABLE "ManufacturerLicenseeLink" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "ManufacturerLicenseeLink" FORCE ROW LEVEL SECURITY;

-- Non-recursive by design. This policy must not call can_access_licensee()
-- because can_access_licensee() reads ManufacturerLicenseeLink.
CREATE POLICY rls_candidate_manufacturer_licensee_link_select ON "ManufacturerLicenseeLink"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR "licenseeId" = app_rls.current_licensee_id()
  );

-- ---------------------------------------------------------------------------
-- Route: GET /api/qr/batches
-- Route: GET /api/qr/batches/:id/allocation-map
-- Tables: Batch, InventoryStatusRollup, QRCode, PrintJob, PrintSession, PrintItem
-- ---------------------------------------------------------------------------

ALTER TABLE "Batch" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Batch" FORCE ROW LEVEL SECURITY;

-- The licensee path intentionally supports linked-licensee access for
-- allocation-map lineage. The app-layer focus-batch check still controls which
-- allocation map is requested.
CREATE POLICY rls_candidate_batch_select ON "Batch"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR "manufacturerId" = app_rls.current_manufacturer_id()
  );

ALTER TABLE "InventoryStatusRollup" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "InventoryStatusRollup" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_inventory_status_rollup_select ON "InventoryStatusRollup"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR app_rls.can_access_batch("batchId")
  );

ALTER TABLE "QRCode" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" FORCE ROW LEVEL SECURITY;

-- QRCode is the base table for groupBy and reservable-summary raw SQL. It must
-- remain aligned with Batch visibility.
CREATE POLICY rls_candidate_qrcode_select ON "QRCode"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_batch("batchId")
    OR app_rls.can_access_print_job("printJobId")
  );

ALTER TABLE "PrintJob" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_print_job_select ON "PrintJob"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR app_rls.can_access_batch("batchId")
    OR app_rls.can_access_printer("printerId")
  );

ALTER TABLE "PrintSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintSession" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_print_session_select ON "PrintSession"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "manufacturerId" = app_rls.current_manufacturer_id()
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
  FOR SELECT
  USING (
    app_rls.can_access_qr("qrCodeId")
    OR app_rls.can_access_print_session("printSessionId")
  );

-- ---------------------------------------------------------------------------
-- Route: GET /api/manufacturer/printers
-- Tables: Printer, PrinterRegistration, PrinterAttestation,
--         PrinterAgentSession, PrinterProfile, PrinterProfileSnapshot
-- ---------------------------------------------------------------------------

ALTER TABLE "PrinterRegistration" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterRegistration" FORCE ROW LEVEL SECURITY;

-- Registration is the non-recursive parent for local-agent status tables.
-- Avoid depending on Printer here so Printer can safely depend on Registration.
CREATE POLICY rls_candidate_printer_registration_select ON "PrinterRegistration"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "userId" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
  );

ALTER TABLE "Printer" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Printer" FORCE ROW LEVEL SECURITY;

-- No isActive predicate belongs here. Inactive printer behavior remains an
-- application query-filter concern, not a global RLS visibility rule.
CREATE POLICY rls_candidate_printer_select ON "Printer"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
    OR "assignedUserId" = app_rls.current_user_id()
    OR "createdByUserId" = app_rls.current_user_id()
    OR app_rls.can_access_printer_registration("printerRegistrationId")
  );

ALTER TABLE "PrinterAttestation" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAttestation" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_attestation_select ON "PrinterAttestation"
  FOR SELECT
  USING (
    app_rls.can_access_printer_registration("printerRegistrationId")
  );

ALTER TABLE "PrinterAgentSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterAgentSession" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_agent_session_select ON "PrinterAgentSession"
  FOR SELECT
  USING (
    app_rls.can_access_printer_registration("registrationId")
    OR app_rls.can_access_print_job("activePrintJobId")
  );

ALTER TABLE "PrinterProfile" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfile" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_profile_select ON "PrinterProfile"
  FOR SELECT
  USING (
    app_rls.can_access_printer("printerId")
  );

ALTER TABLE "PrinterProfileSnapshot" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrinterProfileSnapshot" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_candidate_printer_profile_snapshot_select ON "PrinterProfileSnapshot"
  FOR SELECT
  USING (
    app_rls.can_access_printer_profile("printerProfileId")
  );

COMMIT;
