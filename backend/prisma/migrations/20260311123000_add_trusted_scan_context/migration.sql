ALTER TABLE "QrScanLog"
ADD COLUMN "customerUserId" TEXT,
ADD COLUMN "ownershipId" TEXT,
ADD COLUMN "ownershipMatchMethod" TEXT,
ADD COLUMN "isTrustedOwnerContext" BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX "QrScanLog_qrCodeId_scannedAt_idx" ON "QrScanLog"("qrCodeId", "scannedAt");
CREATE INDEX "QrScanLog_qrCodeId_isTrustedOwnerContext_scannedAt_idx"
ON "QrScanLog"("qrCodeId", "isTrustedOwnerContext", "scannedAt");
