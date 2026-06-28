-- MSCQR PostgreSQL RLS staging-only prototype.
--
-- DO NOT APPLY TO PRODUCTION.
-- DO NOT place this file under backend/prisma/migrations.
-- Apply manually only to a staging/disposable database after reviewing the
-- paired design document and rollback SQL.

BEGIN;

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
AS $$ SELECT lower(COALESCE(app_rls.setting('app.is_platform_admin'), 'false')) = 'true' $$;

CREATE OR REPLACE FUNCTION app_rls.is_public_verification()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$ SELECT app_rls.current_role() = 'public_verification' $$;

CREATE OR REPLACE FUNCTION app_rls.is_worker()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$ SELECT app_rls.current_role() IN ('background_worker', 'system_worker') $$;

CREATE OR REPLACE FUNCTION app_rls.can_access_licensee(licensee_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    licensee_id IS NOT NULL
    AND (
      app_rls.is_platform_admin()
      OR licensee_id = app_rls.current_licensee_id()
      OR EXISTS (
        SELECT 1
        FROM "ManufacturerLicenseeLink" mll
        WHERE mll."manufacturerId" = app_rls.current_manufacturer_id()
          AND mll."licenseeId" = licensee_id
      )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_organization(org_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    org_id IS NOT NULL
    AND (
      app_rls.is_platform_admin()
      OR org_id = app_rls.current_organization_id()
      OR EXISTS (
        SELECT 1
        FROM "Licensee" l
        WHERE l."orgId" = org_id
          AND app_rls.can_access_licensee(l."id")
      )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_batch(batch_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    batch_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "Batch" b
      WHERE b."id" = batch_id
        AND (
          app_rls.can_access_licensee(b."licenseeId")
          OR b."manufacturerId" = app_rls.current_manufacturer_id()
          OR app_rls.is_worker()
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.can_access_qr(qr_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT
    qr_id IS NOT NULL
    AND EXISTS (
      SELECT 1
      FROM "QRCode" q
      WHERE q."id" = qr_id
        AND (
          app_rls.can_access_licensee(q."licenseeId")
          OR app_rls.can_access_batch(q."batchId")
          OR app_rls.is_worker()
        )
    )
$$;

CREATE OR REPLACE FUNCTION app_rls.public_verify_qr_safe(public_code text)
RETURNS TABLE (
  code text,
  status text,
  customer_verifiable_at timestamp without time zone,
  scan_count integer,
  latest_outcome text,
  latest_risk_band text,
  latest_replacement_status text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
  SELECT
    q."code",
    q."status"::text,
    q."customerVerifiableAt",
    q."scanCount",
    vd."outcome"::text AS latest_outcome,
    vd."riskBand"::text AS latest_risk_band,
    vd."replacementStatus"::text AS latest_replacement_status
  FROM "QRCode" q
  LEFT JOIN LATERAL (
    SELECT d."outcome", d."riskBand", d."replacementStatus"
    FROM "VerificationDecision" d
    WHERE d."qrCodeId" = q."id"
       OR d."code" = q."code"
    ORDER BY d."createdAt" DESC
    LIMIT 1
  ) vd ON true
  WHERE app_rls.is_public_verification()
    AND q."code" = public_code
    AND q."customerVerifiableAt" IS NOT NULL
  LIMIT 1
$$;

-- Remove prior prototype policies before recreating them. This keeps manual
-- staging iteration deterministic without relying on CREATE POLICY IF NOT EXISTS.
DROP POLICY IF EXISTS rls_org_select ON "Organization";
DROP POLICY IF EXISTS rls_org_write ON "Organization";
DROP POLICY IF EXISTS rls_licensee_select ON "Licensee";
DROP POLICY IF EXISTS rls_licensee_write ON "Licensee";
DROP POLICY IF EXISTS rls_user_select ON "User";
DROP POLICY IF EXISTS rls_user_write ON "User";
DROP POLICY IF EXISTS rls_batch_select ON "Batch";
DROP POLICY IF EXISTS rls_batch_write ON "Batch";
DROP POLICY IF EXISTS rls_qrcode_select ON "QRCode";
DROP POLICY IF EXISTS rls_qrcode_write ON "QRCode";
DROP POLICY IF EXISTS rls_printjob_select ON "PrintJob";
DROP POLICY IF EXISTS rls_printjob_write ON "PrintJob";
DROP POLICY IF EXISTS rls_printitem_select ON "PrintItem";
DROP POLICY IF EXISTS rls_printitem_write ON "PrintItem";
DROP POLICY IF EXISTS rls_qrscanlog_select ON "QrScanLog";
DROP POLICY IF EXISTS rls_qrscanlog_write ON "QrScanLog";
DROP POLICY IF EXISTS rls_incident_select ON "Incident";
DROP POLICY IF EXISTS rls_incident_write ON "Incident";
DROP POLICY IF EXISTS rls_auditlog_select ON "AuditLog";
DROP POLICY IF EXISTS rls_auditlog_insert ON "AuditLog";
DROP POLICY IF EXISTS rls_printer_select ON "Printer";
DROP POLICY IF EXISTS rls_printer_write ON "Printer";
DROP POLICY IF EXISTS rls_tenantfeatureflag_select ON "TenantFeatureFlag";
DROP POLICY IF EXISTS rls_tenantfeatureflag_write ON "TenantFeatureFlag";
DROP POLICY IF EXISTS rls_verificationdecision_select ON "VerificationDecision";
DROP POLICY IF EXISTS rls_verificationdecision_write ON "VerificationDecision";
DROP POLICY IF EXISTS rls_printreissuerequest_select ON "PrintReissueRequest";
DROP POLICY IF EXISTS rls_printreissuerequest_write ON "PrintReissueRequest";
DROP POLICY IF EXISTS rls_batchprintpacktoken_select ON "BatchPrintPackToken";
DROP POLICY IF EXISTS rls_batchprintpacktoken_write ON "BatchPrintPackToken";
DROP POLICY IF EXISTS rls_customerverificationsession_select ON "CustomerVerificationSession";
DROP POLICY IF EXISTS rls_customerverificationsession_write ON "CustomerVerificationSession";
DROP POLICY IF EXISTS rls_supportticket_select ON "SupportTicket";
DROP POLICY IF EXISTS rls_supportticket_write ON "SupportTicket";

ALTER TABLE "Organization" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Organization" FORCE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" FORCE ROW LEVEL SECURITY;
ALTER TABLE "User" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "User" FORCE ROW LEVEL SECURITY;
ALTER TABLE "Batch" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Batch" FORCE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrintItem" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintItem" FORCE ROW LEVEL SECURITY;
ALTER TABLE "QrScanLog" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "QrScanLog" FORCE ROW LEVEL SECURITY;
ALTER TABLE "Incident" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Incident" FORCE ROW LEVEL SECURITY;
ALTER TABLE "AuditLog" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "AuditLog" FORCE ROW LEVEL SECURITY;
ALTER TABLE "Printer" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "Printer" FORCE ROW LEVEL SECURITY;
ALTER TABLE "TenantFeatureFlag" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "TenantFeatureFlag" FORCE ROW LEVEL SECURITY;
ALTER TABLE "VerificationDecision" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "VerificationDecision" FORCE ROW LEVEL SECURITY;
ALTER TABLE "PrintReissueRequest" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintReissueRequest" FORCE ROW LEVEL SECURITY;
ALTER TABLE "BatchPrintPackToken" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "BatchPrintPackToken" FORCE ROW LEVEL SECURITY;
ALTER TABLE "CustomerVerificationSession" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "CustomerVerificationSession" FORCE ROW LEVEL SECURITY;
ALTER TABLE "SupportTicket" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "SupportTicket" FORCE ROW LEVEL SECURITY;

CREATE POLICY rls_org_select ON "Organization"
  FOR SELECT
  USING (app_rls.can_access_organization("id"));

CREATE POLICY rls_org_write ON "Organization"
  FOR ALL
  USING (app_rls.is_platform_admin())
  WITH CHECK (app_rls.is_platform_admin());

CREATE POLICY rls_licensee_select ON "Licensee"
  FOR SELECT
  USING (app_rls.can_access_licensee("id"));

CREATE POLICY rls_licensee_write ON "Licensee"
  FOR ALL
  USING (app_rls.is_platform_admin())
  WITH CHECK (app_rls.is_platform_admin());

CREATE POLICY rls_user_select ON "User"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "id" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
  );

CREATE POLICY rls_user_write ON "User"
  FOR ALL
  USING (
    app_rls.is_platform_admin()
    OR "id" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
  )
  WITH CHECK (
    app_rls.is_platform_admin()
    OR "id" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
  );

CREATE POLICY rls_batch_select ON "Batch"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR app_rls.is_worker()
  );

CREATE POLICY rls_batch_write ON "Batch"
  FOR ALL
  USING (app_rls.is_platform_admin() OR app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.is_platform_admin() OR app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker());

CREATE POLICY rls_qrcode_select ON "QRCode"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_batch("batchId")
    OR app_rls.is_worker()
  );

CREATE POLICY rls_qrcode_write ON "QRCode"
  FOR ALL
  USING (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker());

CREATE POLICY rls_printjob_select ON "PrintJob"
  FOR SELECT
  USING (
    "manufacturerId" = app_rls.current_manufacturer_id()
    OR app_rls.can_access_batch("batchId")
    OR app_rls.is_worker()
  );

CREATE POLICY rls_printjob_write ON "PrintJob"
  FOR ALL
  USING ("manufacturerId" = app_rls.current_manufacturer_id() OR app_rls.can_access_batch("batchId") OR app_rls.is_worker())
  WITH CHECK ("manufacturerId" = app_rls.current_manufacturer_id() OR app_rls.can_access_batch("batchId") OR app_rls.is_worker());

CREATE POLICY rls_printitem_select ON "PrintItem"
  FOR SELECT
  USING (
    app_rls.can_access_qr("qrCodeId")
    OR EXISTS (
      SELECT 1
      FROM "PrintSession" ps
      WHERE ps."id" = "PrintItem"."printSessionId"
        AND (app_rls.can_access_batch(ps."batchId") OR ps."manufacturerId" = app_rls.current_manufacturer_id())
    )
    OR app_rls.is_worker()
  );

CREATE POLICY rls_printitem_write ON "PrintItem"
  FOR ALL
  USING (app_rls.can_access_qr("qrCodeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.can_access_qr("qrCodeId") OR app_rls.is_worker());

CREATE POLICY rls_qrscanlog_select ON "QrScanLog"
  FOR SELECT
  USING (app_rls.can_access_licensee("licenseeId") OR app_rls.can_access_batch("batchId") OR app_rls.is_worker());

CREATE POLICY rls_qrscanlog_write ON "QrScanLog"
  FOR ALL
  USING (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker());

CREATE POLICY rls_incident_select ON "Incident"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_qr("qrCodeId")
    OR app_rls.is_worker()
  );

CREATE POLICY rls_incident_write ON "Incident"
  FOR ALL
  USING (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker());

CREATE POLICY rls_auditlog_select ON "AuditLog"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR "userId" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
  );

CREATE POLICY rls_auditlog_insert ON "AuditLog"
  FOR INSERT
  WITH CHECK (
    "userId" = app_rls.current_user_id()
    OR app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
    OR app_rls.is_worker()
  );

CREATE POLICY rls_printer_select ON "Printer"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
    OR "assignedUserId" = app_rls.current_user_id()
    OR "createdByUserId" = app_rls.current_user_id()
    OR app_rls.is_worker()
  );

CREATE POLICY rls_printer_write ON "Printer"
  FOR ALL
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
    OR "assignedUserId" = app_rls.current_user_id()
    OR "createdByUserId" = app_rls.current_user_id()
    OR app_rls.is_worker()
  )
  WITH CHECK (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_organization("orgId")
    OR "assignedUserId" = app_rls.current_user_id()
    OR "createdByUserId" = app_rls.current_user_id()
    OR app_rls.is_worker()
  );

CREATE POLICY rls_tenantfeatureflag_select ON "TenantFeatureFlag"
  FOR SELECT
  USING (app_rls.can_access_licensee("licenseeId"));

CREATE POLICY rls_tenantfeatureflag_write ON "TenantFeatureFlag"
  FOR ALL
  USING (app_rls.is_platform_admin())
  WITH CHECK (app_rls.is_platform_admin());

CREATE POLICY rls_verificationdecision_select ON "VerificationDecision"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR app_rls.can_access_batch("batchId")
    OR app_rls.can_access_qr("qrCodeId")
    OR app_rls.is_worker()
  );

CREATE POLICY rls_verificationdecision_write ON "VerificationDecision"
  FOR ALL
  USING (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.can_access_licensee("licenseeId") OR app_rls.is_worker());

CREATE POLICY rls_printreissuerequest_select ON "PrintReissueRequest"
  FOR SELECT
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR "requestedByUserId" = app_rls.current_user_id()
    OR "approvedByUserId" = app_rls.current_user_id()
    OR app_rls.can_access_batch("batchId")
    OR EXISTS (
      SELECT 1
      FROM "PrintJob" pj
      WHERE pj."id" = "PrintReissueRequest"."originalPrintJobId"
        AND ("PrintReissueRequest"."manufacturerId" = app_rls.current_manufacturer_id() OR app_rls.can_access_batch(pj."batchId"))
    )
    OR app_rls.is_worker()
  );

CREATE POLICY rls_printreissuerequest_write ON "PrintReissueRequest"
  FOR ALL
  USING (
    app_rls.can_access_licensee("licenseeId")
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR "requestedByUserId" = app_rls.current_user_id()
    OR app_rls.is_worker()
  )
  WITH CHECK (
    app_rls.can_access_licensee("licenseeId")
    OR "manufacturerId" = app_rls.current_manufacturer_id()
    OR "requestedByUserId" = app_rls.current_user_id()
    OR app_rls.is_worker()
  );

CREATE POLICY rls_batchprintpacktoken_select ON "BatchPrintPackToken"
  FOR SELECT
  USING ("createdByUserId" = app_rls.current_user_id() OR app_rls.can_access_batch("batchId") OR app_rls.is_worker());

CREATE POLICY rls_batchprintpacktoken_write ON "BatchPrintPackToken"
  FOR ALL
  USING ("createdByUserId" = app_rls.current_user_id() OR app_rls.can_access_batch("batchId") OR app_rls.is_worker())
  WITH CHECK ("createdByUserId" = app_rls.current_user_id() OR app_rls.can_access_batch("batchId") OR app_rls.is_worker());

CREATE POLICY rls_customerverificationsession_select ON "CustomerVerificationSession"
  FOR SELECT
  USING (
    app_rls.can_access_qr("qrCodeId")
    OR EXISTS (
      SELECT 1
      FROM "VerificationDecision" vd
      WHERE vd."id" = "CustomerVerificationSession"."verificationDecisionId"
        AND (app_rls.can_access_licensee(vd."licenseeId") OR app_rls.can_access_batch(vd."batchId"))
    )
    OR app_rls.is_worker()
  );

CREATE POLICY rls_customerverificationsession_write ON "CustomerVerificationSession"
  FOR ALL
  USING (app_rls.can_access_qr("qrCodeId") OR app_rls.is_worker())
  WITH CHECK (app_rls.can_access_qr("qrCodeId") OR app_rls.is_worker());

CREATE POLICY rls_supportticket_select ON "SupportTicket"
  FOR SELECT
  USING (
    app_rls.is_platform_admin()
    OR app_rls.can_access_licensee("licenseeId")
    OR "assignedToUserId" = app_rls.current_user_id()
    OR EXISTS (
      SELECT 1
      FROM "Incident" i
      WHERE i."id" = "SupportTicket"."incidentId"
        AND app_rls.can_access_licensee(i."licenseeId")
    )
  );

CREATE POLICY rls_supportticket_write ON "SupportTicket"
  FOR ALL
  USING (
    app_rls.is_platform_admin()
    OR app_rls.can_access_licensee("licenseeId")
    OR "assignedToUserId" = app_rls.current_user_id()
  )
  WITH CHECK (
    app_rls.is_platform_admin()
    OR app_rls.can_access_licensee("licenseeId")
    OR "assignedToUserId" = app_rls.current_user_id()
  );

COMMIT;
