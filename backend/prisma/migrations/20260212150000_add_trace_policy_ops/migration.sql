-- CreateEnum
CREATE TYPE "TraceEventType" AS ENUM ('COMMISSIONED', 'ASSIGNED', 'PRINTED', 'REDEEMED', 'BLOCKED');

-- CreateEnum
CREATE TYPE "PolicyAlertType" AS ENUM ('MULTI_SCAN', 'GEO_DRIFT', 'VELOCITY_SPIKE', 'STUCK_BATCH', 'AUTO_BLOCK_QR', 'AUTO_BLOCK_BATCH');

-- CreateEnum
CREATE TYPE "AlertSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateTable
CREATE TABLE "TraceEvent" (
    "id" TEXT NOT NULL,
    "eventType" "TraceEventType" NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "batchId" TEXT,
    "qrCodeId" TEXT,
    "manufacturerId" TEXT,
    "userId" TEXT,
    "sourceAction" TEXT,
    "details" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "TraceEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityPolicy" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT,
    "autoBlockEnabled" BOOLEAN NOT NULL DEFAULT true,
    "autoBlockBatchOnVelocity" BOOLEAN NOT NULL DEFAULT false,
    "multiScanThreshold" INTEGER NOT NULL DEFAULT 2,
    "geoDriftThresholdKm" DOUBLE PRECISION NOT NULL DEFAULT 300,
    "velocitySpikeThresholdPerMin" INTEGER NOT NULL DEFAULT 80,
    "stuckBatchHours" INTEGER NOT NULL DEFAULT 24,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PolicyAlert" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "alertType" "PolicyAlertType" NOT NULL,
    "severity" "AlertSeverity" NOT NULL DEFAULT 'MEDIUM',
    "message" TEXT NOT NULL,
    "score" INTEGER NOT NULL DEFAULT 0,
    "batchId" TEXT,
    "qrCodeId" TEXT,
    "manufacturerId" TEXT,
    "acknowledgedAt" TIMESTAMP(3),
    "acknowledgedByUserId" TEXT,
    "details" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PolicyAlert_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TraceEvent_licenseeId_idx" ON "TraceEvent"("licenseeId");
CREATE INDEX "TraceEvent_eventType_idx" ON "TraceEvent"("eventType");
CREATE INDEX "TraceEvent_batchId_idx" ON "TraceEvent"("batchId");
CREATE INDEX "TraceEvent_manufacturerId_idx" ON "TraceEvent"("manufacturerId");
CREATE INDEX "TraceEvent_qrCodeId_idx" ON "TraceEvent"("qrCodeId");
CREATE INDEX "TraceEvent_createdAt_idx" ON "TraceEvent"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "SecurityPolicy_licenseeId_key" ON "SecurityPolicy"("licenseeId");
CREATE INDEX "SecurityPolicy_licenseeId_idx" ON "SecurityPolicy"("licenseeId");

-- CreateIndex
CREATE INDEX "PolicyAlert_licenseeId_idx" ON "PolicyAlert"("licenseeId");
CREATE INDEX "PolicyAlert_alertType_idx" ON "PolicyAlert"("alertType");
CREATE INDEX "PolicyAlert_severity_idx" ON "PolicyAlert"("severity");
CREATE INDEX "PolicyAlert_batchId_idx" ON "PolicyAlert"("batchId");
CREATE INDEX "PolicyAlert_manufacturerId_idx" ON "PolicyAlert"("manufacturerId");
CREATE INDEX "PolicyAlert_qrCodeId_idx" ON "PolicyAlert"("qrCodeId");
CREATE INDEX "PolicyAlert_acknowledgedAt_idx" ON "PolicyAlert"("acknowledgedAt");
CREATE INDEX "PolicyAlert_createdAt_idx" ON "PolicyAlert"("createdAt");

-- AddForeignKey
ALTER TABLE "TraceEvent" ADD CONSTRAINT "TraceEvent_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "TraceEvent" ADD CONSTRAINT "TraceEvent_batchId_fkey" FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "TraceEvent" ADD CONSTRAINT "TraceEvent_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "TraceEvent" ADD CONSTRAINT "TraceEvent_manufacturerId_fkey" FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "TraceEvent" ADD CONSTRAINT "TraceEvent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityPolicy" ADD CONSTRAINT "SecurityPolicy_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PolicyAlert" ADD CONSTRAINT "PolicyAlert_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "PolicyAlert" ADD CONSTRAINT "PolicyAlert_batchId_fkey" FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "PolicyAlert" ADD CONSTRAINT "PolicyAlert_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "PolicyAlert" ADD CONSTRAINT "PolicyAlert_manufacturerId_fkey" FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "PolicyAlert" ADD CONSTRAINT "PolicyAlert_acknowledgedByUserId_fkey" FOREIGN KEY ("acknowledgedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
