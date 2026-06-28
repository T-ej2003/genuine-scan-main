-- MSCQR PostgreSQL RLS staging-only prototype rollback.
--
-- DO NOT APPLY TO PRODUCTION without an approved production rollback plan.
-- This file reverses documents/security/mscqr_staging_rls_prototype.sql
-- for staging/disposable databases.

BEGIN;

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

ALTER TABLE "Organization" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Licensee" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "User" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Batch" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "QRCode" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintJob" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintItem" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "QrScanLog" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Incident" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "AuditLog" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "Printer" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "TenantFeatureFlag" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "VerificationDecision" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "PrintReissueRequest" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "BatchPrintPackToken" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "CustomerVerificationSession" DISABLE ROW LEVEL SECURITY;
ALTER TABLE "SupportTicket" DISABLE ROW LEVEL SECURITY;

DROP FUNCTION IF EXISTS app_rls.can_access_qr(text);
DROP FUNCTION IF EXISTS app_rls.public_verify_qr_safe(text);
DROP FUNCTION IF EXISTS app_rls.can_access_batch(text);
DROP FUNCTION IF EXISTS app_rls.can_access_organization(text);
DROP FUNCTION IF EXISTS app_rls.can_access_licensee(text);
DROP FUNCTION IF EXISTS app_rls.is_worker();
DROP FUNCTION IF EXISTS app_rls.is_public_verification();
DROP FUNCTION IF EXISTS app_rls.is_platform_admin();
DROP FUNCTION IF EXISTS app_rls.current_organization_id();
DROP FUNCTION IF EXISTS app_rls.current_manufacturer_id();
DROP FUNCTION IF EXISTS app_rls.current_licensee_id();
DROP FUNCTION IF EXISTS app_rls.current_role();
DROP FUNCTION IF EXISTS app_rls.current_user_id();
DROP FUNCTION IF EXISTS app_rls.setting(text);

DROP SCHEMA IF EXISTS app_rls;

COMMIT;
