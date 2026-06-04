ALTER TABLE "Batch"
  ADD COLUMN IF NOT EXISTS "printPackDownloadedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "printPackDownloadedByUserId" TEXT;

CREATE INDEX IF NOT EXISTS "Batch_printPackDownloadedAt_idx" ON "Batch"("printPackDownloadedAt");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Batch_printPackDownloadedByUserId_fkey'
  ) THEN
    ALTER TABLE "Batch"
      ADD CONSTRAINT "Batch_printPackDownloadedByUserId_fkey"
      FOREIGN KEY ("printPackDownloadedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS "BatchPrintPackToken" (
  "id" TEXT NOT NULL,
  "tokenHash" TEXT NOT NULL,
  "batchId" TEXT NOT NULL,
  "createdByUserId" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "usedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "BatchPrintPackToken_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "BatchPrintPackToken_tokenHash_key" ON "BatchPrintPackToken"("tokenHash");
CREATE INDEX IF NOT EXISTS "BatchPrintPackToken_batchId_idx" ON "BatchPrintPackToken"("batchId");
CREATE INDEX IF NOT EXISTS "BatchPrintPackToken_expiresAt_idx" ON "BatchPrintPackToken"("expiresAt");

DO $$
BEGIN
  IF to_regclass('"PrintPackToken"') IS NOT NULL AND to_regclass('"ProductBatch"') IS NOT NULL THEN
    INSERT INTO "BatchPrintPackToken" (
      "id",
      "tokenHash",
      "batchId",
      "createdByUserId",
      "expiresAt",
      "usedAt",
      "createdAt"
    )
    SELECT
      ppt."id",
      ppt."tokenHash",
      pb."parentBatchId",
      ppt."createdByUserId",
      ppt."expiresAt",
      ppt."usedAt",
      ppt."createdAt"
    FROM "PrintPackToken" ppt
    JOIN "ProductBatch" pb ON pb."id" = ppt."productBatchId"
    WHERE pb."parentBatchId" IS NOT NULL
    ON CONFLICT DO NOTHING;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'BatchPrintPackToken_batchId_fkey'
  ) THEN
    ALTER TABLE "BatchPrintPackToken"
      ADD CONSTRAINT "BatchPrintPackToken_batchId_fkey"
      FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'BatchPrintPackToken_createdByUserId_fkey'
  ) THEN
    ALTER TABLE "BatchPrintPackToken"
      ADD CONSTRAINT "BatchPrintPackToken_createdByUserId_fkey"
      FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
  END IF;
END $$;

ALTER TABLE "QRCode" DROP CONSTRAINT IF EXISTS "QRCode_productBatchId_fkey";
DROP INDEX IF EXISTS "QRCode_productBatchId_idx";
ALTER TABLE "QRCode" DROP COLUMN IF EXISTS "productBatchId";

DROP TABLE IF EXISTS "PrintPackToken";
DROP TABLE IF EXISTS "ProductBatch";

ALTER TYPE "QRStatus" ADD VALUE IF NOT EXISTS 'ACTIVATED';
ALTER TYPE "QRStatus" ADD VALUE IF NOT EXISTS 'REDEEMED';
ALTER TYPE "QRStatus" ADD VALUE IF NOT EXISTS 'BLOCKED';

ALTER TABLE "Licensee"
  ADD COLUMN IF NOT EXISTS "brandName" TEXT,
  ADD COLUMN IF NOT EXISTS "location" TEXT,
  ADD COLUMN IF NOT EXISTS "supportEmail" TEXT,
  ADD COLUMN IF NOT EXISTS "supportPhone" TEXT,
  ADD COLUMN IF NOT EXISTS "website" TEXT;

ALTER TABLE "User"
  ADD COLUMN IF NOT EXISTS "location" TEXT,
  ADD COLUMN IF NOT EXISTS "website" TEXT;

ALTER TABLE "QRCode"
  ADD COLUMN IF NOT EXISTS "blockedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "lastScanDevice" TEXT,
  ADD COLUMN IF NOT EXISTS "lastScanIp" TEXT,
  ADD COLUMN IF NOT EXISTS "lastScanUserAgent" TEXT,
  ADD COLUMN IF NOT EXISTS "printedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "printedByUserId" TEXT,
  ADD COLUMN IF NOT EXISTS "redeemedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "redeemedDeviceFingerprint" TEXT,
  ADD COLUMN IF NOT EXISTS "tokenExpiresAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "tokenHash" TEXT,
  ADD COLUMN IF NOT EXISTS "tokenIssuedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "tokenNonce" TEXT;

CREATE INDEX IF NOT EXISTS "QRCode_tokenHash_idx" ON "QRCode"("tokenHash");
CREATE INDEX IF NOT EXISTS "PrintItem_pipelineState_updatedAt_idx" ON "PrintItem"("pipelineState", "updatedAt");
CREATE INDEX IF NOT EXISTS "PrintJob_pipelineState_idx" ON "PrintJob"("pipelineState");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'QRCode_printedByUserId_fkey'
  ) THEN
    ALTER TABLE "QRCode"
      ADD CONSTRAINT "QRCode_printedByUserId_fkey"
      FOREIGN KEY ("printedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

ALTER TABLE "PrintJob" DROP CONSTRAINT IF EXISTS "PrintJob_batchId_fkey";
ALTER TABLE "PrintJob"
  ADD CONSTRAINT "PrintJob_batchId_fkey"
  FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "PrintJob" DROP CONSTRAINT IF EXISTS "PrintJob_manufacturerId_fkey";
ALTER TABLE "PrintJob"
  ADD CONSTRAINT "PrintJob_manufacturerId_fkey"
  FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "Ownership" DROP CONSTRAINT IF EXISTS "Ownership_qrCodeId_fkey";
ALTER TABLE "Ownership"
  ADD CONSTRAINT "Ownership_qrCodeId_fkey"
  FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "AdminWebAuthnCredential" ALTER COLUMN "transports" DROP DEFAULT;
ALTER TABLE "AuditLogOutbox" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "AuthWebAuthnChallenge" ALTER COLUMN "credentialIds" DROP DEFAULT;
ALTER TABLE "CustomerTrustCredential" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "Incident" ALTER COLUMN "photos" DROP DEFAULT;
ALTER TABLE "Incident" ALTER COLUMN "tags" DROP DEFAULT;
ALTER TABLE "InventoryStatusRollup" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "ManufacturerLicenseeLink" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "Notification" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "PrintJob" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "PrintReissueRequest" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "Printer" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "PrinterProfile" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "ScanMetricsHourlyRollup" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "SystemCheckpoint" ALTER COLUMN "updatedAt" DROP DEFAULT;
ALTER TABLE "VerificationDecision" ALTER COLUMN "reasonCodes" DROP DEFAULT;

DO $$
BEGIN
  IF to_regclass('"CustomerVerificationSession_verificationDecisionId_createdAt_id"') IS NOT NULL
     AND to_regclass('"CustomerVerificationSession_verificationDecisionId_createdA_idx"') IS NULL THEN
    ALTER INDEX "CustomerVerificationSession_verificationDecisionId_createdAt_id"
      RENAME TO "CustomerVerificationSession_verificationDecisionId_createdA_idx";
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('"PrinterProfileSnapshot_printerProfileId_snapshotType_capturedAt"') IS NOT NULL
     AND to_regclass('"PrinterProfileSnapshot_printerProfileId_snapshotType_captur_idx"') IS NULL THEN
    ALTER INDEX "PrinterProfileSnapshot_printerProfileId_snapshotType_capturedAt"
      RENAME TO "PrinterProfileSnapshot_printerProfileId_snapshotType_captur_idx";
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('"SensitiveActionApproval_actionKey_entityType_entityId_status_id"') IS NOT NULL
     AND to_regclass('"SensitiveActionApproval_actionKey_entityType_entityId_statu_idx"') IS NULL THEN
    ALTER INDEX "SensitiveActionApproval_actionKey_entityType_entityId_status_id"
      RENAME TO "SensitiveActionApproval_actionKey_entityType_entityId_statu_idx";
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('"VerificationEvidenceSnapshot_verificationDecisionId_createdAt_i"') IS NOT NULL
     AND to_regclass('"VerificationEvidenceSnapshot_verificationDecisionId_created_idx"') IS NULL THEN
    ALTER INDEX "VerificationEvidenceSnapshot_verificationDecisionId_createdAt_i"
      RENAME TO "VerificationEvidenceSnapshot_verificationDecisionId_created_idx";
  END IF;
END $$;
