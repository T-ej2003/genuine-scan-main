-- MSCQR RLS index rollout candidates - reviewed, non-applied artifact.
--
-- DO NOT apply this file automatically.
-- DO NOT place this file under backend/prisma/migrations.
-- DO NOT reference this file from deploy scripts, package scripts, or CI release automation.
-- DO NOT run directly in production without DBA/release approval.
--
-- Production indexes should use CONCURRENTLY where PostgreSQL supports it.
-- Production needs a lock/timeout plan, statement timeout, monitoring, and invalid-index cleanup plan.
-- Staging EXPLAIN ANALYZE with realistic row counts is required first.
--
-- Rollout plan:
-- documents/security/MSCQR_RLS_INDEX_ROLLOUT_PLAN_2026-06-29.md

-- Phase 1 safe candidates for staging validation before wrapping GET /qr/batches.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "Batch_licenseeId_updatedAt_createdAt_id_rls_rollout_idx"
  ON "Batch"("licenseeId", "updatedAt" DESC, "createdAt" DESC, "id");

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Batch_manufacturerId_updatedAt_createdAt_id_rls_rollout_idx"
  ON "Batch"("manufacturerId", "updatedAt" DESC, "createdAt" DESC, "id")
  WHERE "manufacturerId" IS NOT NULL;

-- Validate only after the Batch list plan shows QR relation/count enrichment remains material.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "QRCode_batchId_createdAt_id_rls_rollout_idx"
  ON "QRCode"("batchId", "createdAt", "id")
  WHERE "batchId" IS NOT NULL;

-- Evidence-gated candidates. Do not include these in the first index rollout without
-- route-specific staging EXPLAIN ANALYZE and DBA/release approval.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "VerificationDecision_qrCodeId_createdAt_desc_rls_rollout_idx"
  ON "VerificationDecision"("qrCodeId", "createdAt" DESC)
  WHERE "qrCodeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "VerificationDecision_code_createdAt_desc_rls_rollout_idx"
  ON "VerificationDecision"("code", "createdAt" DESC)
  WHERE "code" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Printer_createdByUserId_isActive_rls_rollout_idx"
  ON "Printer"("createdByUserId", "isActive")
  WHERE "createdByUserId" IS NOT NULL;

-- Deferred until incident/support route wiring is split to narrow read-only paths and
-- measured under staging-only RLS context.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "Incident_licenseeId_createdAt_id_rls_rollout_idx"
  ON "Incident"("licenseeId", "createdAt" DESC, "id")
  WHERE "licenseeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Incident_licenseeId_status_createdAt_id_rls_rollout_idx"
  ON "Incident"("licenseeId", "status", "createdAt" DESC, "id")
  WHERE "licenseeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "Incident_qrCodeId_createdAt_id_rls_rollout_idx"
  ON "Incident"("qrCodeId", "createdAt" DESC, "id")
  WHERE "qrCodeId" IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS "SupportTicket_licenseeId_createdAt_id_rls_rollout_idx"
  ON "SupportTicket"("licenseeId", "createdAt" DESC, "id")
  WHERE "licenseeId" IS NOT NULL;
