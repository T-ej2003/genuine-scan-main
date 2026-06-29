-- MSCQR RLS index recommendations - non-applied prototype artifact.
--
-- DO NOT apply this file automatically.
-- DO NOT place this file under backend/prisma/migrations.
-- DO NOT run this against production without a separate CONCURRENTLY rollout,
-- lock analysis, staging EXPLAIN ANALYZE evidence, and rollback plan.
--
-- These recommendations support the staging-only RLS prototype in:
-- documents/security/mscqr_staging_rls_prototype.sql

-- Batch list/read candidates under tenant and manufacturer RLS contexts.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "Batch_licenseeId_updatedAt_createdAt_id_rls_rec_idx"
  ON "Batch"("licenseeId", "updatedAt" DESC, "createdAt" DESC, "id");

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Batch_manufacturerId_updatedAt_createdAt_id_rls_rec_idx"
  ON "Batch"("manufacturerId", "updatedAt" DESC, "createdAt" DESC, "id")
  WHERE "manufacturerId" IS NOT NULL;

-- Batch allocation-map and QR relation predicates.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "QRCode_batchId_createdAt_id_rls_rec_idx"
  ON "QRCode"("batchId", "createdAt", "id")
  WHERE "batchId" IS NOT NULL;

-- Incident read candidates under RLS.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "Incident_licenseeId_createdAt_id_rls_rec_idx"
  ON "Incident"("licenseeId", "createdAt" DESC, "id")
  WHERE "licenseeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Incident_licenseeId_status_createdAt_id_rls_rec_idx"
  ON "Incident"("licenseeId", "status", "createdAt" DESC, "id")
  WHERE "licenseeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Incident_qrCodeId_createdAt_id_rls_rec_idx"
  ON "Incident"("qrCodeId", "createdAt" DESC, "id")
  WHERE "qrCodeId" IS NOT NULL;

-- Support ticket metadata joins from incident reads and future support lists.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "SupportTicket_licenseeId_createdAt_id_rls_rec_idx"
  ON "SupportTicket"("licenseeId", "createdAt" DESC, "id")
  WHERE "licenseeId" IS NOT NULL;

-- Latest verification-decision lookups used by app_rls.public_verify_qr_safe(public_code).
CREATE INDEX CONCURRENTLY IF NOT EXISTS "VerificationDecision_qrCodeId_createdAt_desc_rls_rec_idx"
  ON "VerificationDecision"("qrCodeId", "createdAt" DESC)
  WHERE "qrCodeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "VerificationDecision_code_createdAt_desc_rls_rec_idx"
  ON "VerificationDecision"("code", "createdAt" DESC)
  WHERE "code" IS NOT NULL;

-- Printer policy branch for creator-owned rows. Current first-candidate reads mostly use
-- licensee/org/assigned-user branches, but the RLS policy also permits createdByUserId.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "Printer_createdByUserId_isActive_rls_rec_idx"
  ON "Printer"("createdByUserId", "isActive")
  WHERE "createdByUserId" IS NOT NULL;
