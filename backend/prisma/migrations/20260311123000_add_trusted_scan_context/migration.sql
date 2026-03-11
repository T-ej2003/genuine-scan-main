ALTER TABLE "QrScanLog"
ADD COLUMN IF NOT EXISTS "customerUserId" TEXT,
ADD COLUMN IF NOT EXISTS "ownershipId" TEXT,
ADD COLUMN IF NOT EXISTS "ownershipMatchMethod" TEXT,
ADD COLUMN IF NOT EXISTS "isTrustedOwnerContext" BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS "QrScanLog_qrCodeId_scannedAt_idx" ON "QrScanLog"("qrCodeId", "scannedAt");
CREATE INDEX IF NOT EXISTS "QrScanLog_qrCodeId_isTrustedOwnerContext_scannedAt_idx"
ON "QrScanLog"("qrCodeId", "isTrustedOwnerContext", "scannedAt");
