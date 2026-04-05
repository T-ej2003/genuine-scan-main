-- CreateTable
CREATE TABLE "InventoryStatusRollup" (
    "batchId" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "manufacturerId" TEXT,
    "totalCodes" INTEGER NOT NULL DEFAULT 0,
    "dormant" INTEGER NOT NULL DEFAULT 0,
    "active" INTEGER NOT NULL DEFAULT 0,
    "activated" INTEGER NOT NULL DEFAULT 0,
    "allocated" INTEGER NOT NULL DEFAULT 0,
    "printed" INTEGER NOT NULL DEFAULT 0,
    "redeemed" INTEGER NOT NULL DEFAULT 0,
    "blocked" INTEGER NOT NULL DEFAULT 0,
    "scanned" INTEGER NOT NULL DEFAULT 0,
    "refreshedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "InventoryStatusRollup_pkey" PRIMARY KEY ("batchId")
);

-- CreateTable
CREATE TABLE "SystemCheckpoint" (
    "key" TEXT NOT NULL,
    "value" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SystemCheckpoint_pkey" PRIMARY KEY ("key")
);

-- CreateTable
CREATE TABLE "ScanMetricsHourlyRollup" (
    "id" TEXT NOT NULL,
    "bucketKey" TEXT NOT NULL,
    "hourBucket" TIMESTAMP(3) NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "batchId" TEXT,
    "manufacturerId" TEXT,
    "totalScanEvents" INTEGER NOT NULL DEFAULT 0,
    "firstScanEvents" INTEGER NOT NULL DEFAULT 0,
    "repeatScanEvents" INTEGER NOT NULL DEFAULT 0,
    "blockedEvents" INTEGER NOT NULL DEFAULT 0,
    "trustedOwnerEvents" INTEGER NOT NULL DEFAULT 0,
    "externalEvents" INTEGER NOT NULL DEFAULT 0,
    "namedLocationEvents" INTEGER NOT NULL DEFAULT 0,
    "knownDeviceEvents" INTEGER NOT NULL DEFAULT 0,
    "uniqueQrCodes" INTEGER NOT NULL DEFAULT 0,
    "firstScannedAt" TIMESTAMP(3),
    "lastScannedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanMetricsHourlyRollup_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "InventoryStatusRollup_licenseeId_refreshedAt_idx" ON "InventoryStatusRollup"("licenseeId", "refreshedAt");

-- CreateIndex
CREATE INDEX "InventoryStatusRollup_manufacturerId_refreshedAt_idx" ON "InventoryStatusRollup"("manufacturerId", "refreshedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ScanMetricsHourlyRollup_bucketKey_key" ON "ScanMetricsHourlyRollup"("bucketKey");

-- CreateIndex
CREATE INDEX "ScanMetricsHourlyRollup_licenseeId_hourBucket_idx" ON "ScanMetricsHourlyRollup"("licenseeId", "hourBucket");

-- CreateIndex
CREATE INDEX "ScanMetricsHourlyRollup_batchId_hourBucket_idx" ON "ScanMetricsHourlyRollup"("batchId", "hourBucket");

-- CreateIndex
CREATE INDEX "ScanMetricsHourlyRollup_manufacturerId_hourBucket_idx" ON "ScanMetricsHourlyRollup"("manufacturerId", "hourBucket");

-- CreateIndex
CREATE INDEX "QRCode_licenseeId_batchId_status_idx" ON "QRCode"("licenseeId", "batchId", "status");

-- CreateIndex
CREATE INDEX "QRCode_licenseeId_status_updatedAt_idx" ON "QRCode"("licenseeId", "status", "updatedAt");

-- CreateIndex
CREATE INDEX "QrScanLog_licenseeId_batchId_scannedAt_idx" ON "QrScanLog"("licenseeId", "batchId", "scannedAt");

-- CreateIndex
CREATE INDEX "AuditLog_licenseeId_createdAt_id_idx" ON "AuditLog"("licenseeId", "createdAt", "id");

-- CreateIndex
CREATE INDEX "TraceEvent_licenseeId_createdAt_id_idx" ON "TraceEvent"("licenseeId", "createdAt", "id");

-- CreateIndex
CREATE INDEX "Notification_userId_createdAt_id_idx" ON "Notification"("userId", "createdAt", "id");

-- AddForeignKey
ALTER TABLE "InventoryStatusRollup"
ADD CONSTRAINT "InventoryStatusRollup_batchId_fkey"
FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE CASCADE ON UPDATE CASCADE;
