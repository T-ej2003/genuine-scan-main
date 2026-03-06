-- CreateEnum
CREATE TYPE "OwnershipTransferStatus" AS ENUM ('PENDING', 'ACCEPTED', 'CANCELLED', 'EXPIRED');

-- AlterTable
ALTER TABLE "Batch"
ADD COLUMN "parentBatchId" TEXT,
ADD COLUMN "rootBatchId" TEXT;

-- CreateTable
CREATE TABLE "OwnershipTransfer" (
    "id" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "ownershipId" TEXT NOT NULL,
    "initiatedByCustomerId" TEXT NOT NULL,
    "initiatedByEmail" TEXT,
    "recipientEmail" TEXT,
    "tokenHash" TEXT NOT NULL,
    "status" "OwnershipTransferStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "acceptedAt" TIMESTAMP(3),
    "cancelledAt" TIMESTAMP(3),
    "lastViewedAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OwnershipTransfer_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Batch_parentBatchId_idx" ON "Batch"("parentBatchId");

-- CreateIndex
CREATE INDEX "Batch_rootBatchId_idx" ON "Batch"("rootBatchId");

-- CreateIndex
CREATE UNIQUE INDEX "OwnershipTransfer_tokenHash_key" ON "OwnershipTransfer"("tokenHash");

-- CreateIndex
CREATE INDEX "OwnershipTransfer_qrCodeId_status_idx" ON "OwnershipTransfer"("qrCodeId", "status");

-- CreateIndex
CREATE INDEX "OwnershipTransfer_ownershipId_status_idx" ON "OwnershipTransfer"("ownershipId", "status");

-- CreateIndex
CREATE INDEX "OwnershipTransfer_initiatedByCustomerId_status_idx" ON "OwnershipTransfer"("initiatedByCustomerId", "status");

-- CreateIndex
CREATE INDEX "OwnershipTransfer_recipientEmail_status_idx" ON "OwnershipTransfer"("recipientEmail", "status");

-- CreateIndex
CREATE INDEX "OwnershipTransfer_expiresAt_idx" ON "OwnershipTransfer"("expiresAt");

-- AddForeignKey
ALTER TABLE "Batch"
ADD CONSTRAINT "Batch_parentBatchId_fkey"
FOREIGN KEY ("parentBatchId") REFERENCES "Batch"("id")
ON DELETE SET NULL
ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Batch"
ADD CONSTRAINT "Batch_rootBatchId_fkey"
FOREIGN KEY ("rootBatchId") REFERENCES "Batch"("id")
ON DELETE SET NULL
ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OwnershipTransfer"
ADD CONSTRAINT "OwnershipTransfer_qrCodeId_fkey"
FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OwnershipTransfer"
ADD CONSTRAINT "OwnershipTransfer_ownershipId_fkey"
FOREIGN KEY ("ownershipId") REFERENCES "Ownership"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;
