-- CreateEnum
CREATE TYPE "QrAllocationRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- AlterTable
ALTER TABLE "ProductBatch" ADD COLUMN     "printPackDownloadedAt" TIMESTAMP(3),
ADD COLUMN     "printPackDownloadedByUserId" TEXT;

-- CreateTable
CREATE TABLE "QrAllocationRequest" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "requestedByUserId" TEXT NOT NULL,
    "quantity" INTEGER,
    "startNumber" INTEGER,
    "endNumber" INTEGER,
    "status" "QrAllocationRequestStatus" NOT NULL DEFAULT 'PENDING',
    "note" TEXT,
    "approvedByUserId" TEXT,
    "approvedAt" TIMESTAMP(3),
    "rejectedByUserId" TEXT,
    "rejectedAt" TIMESTAMP(3),
    "decisionNote" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "QrAllocationRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AllocationEvent" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "createdByUserId" TEXT,
    "requestId" TEXT,
    "source" TEXT,
    "startCode" TEXT NOT NULL,
    "endCode" TEXT NOT NULL,
    "totalCodes" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AllocationEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrintPackToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "productBatchId" TEXT NOT NULL,
    "createdByUserId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PrintPackToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "QrAllocationRequest_licenseeId_idx" ON "QrAllocationRequest"("licenseeId");

-- CreateIndex
CREATE INDEX "QrAllocationRequest_status_idx" ON "QrAllocationRequest"("status");

-- CreateIndex
CREATE INDEX "AllocationEvent_licenseeId_idx" ON "AllocationEvent"("licenseeId");

-- CreateIndex
CREATE INDEX "AllocationEvent_requestId_idx" ON "AllocationEvent"("requestId");

-- CreateIndex
CREATE UNIQUE INDEX "PrintPackToken_tokenHash_key" ON "PrintPackToken"("tokenHash");

-- CreateIndex
CREATE INDEX "PrintPackToken_productBatchId_idx" ON "PrintPackToken"("productBatchId");

-- CreateIndex
CREATE INDEX "PrintPackToken_expiresAt_idx" ON "PrintPackToken"("expiresAt");

-- CreateIndex
CREATE INDEX "ProductBatch_printPackDownloadedAt_idx" ON "ProductBatch"("printPackDownloadedAt");

-- AddForeignKey
ALTER TABLE "ProductBatch" ADD CONSTRAINT "ProductBatch_printPackDownloadedByUserId_fkey" FOREIGN KEY ("printPackDownloadedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "QrAllocationRequest" ADD CONSTRAINT "QrAllocationRequest_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "QrAllocationRequest" ADD CONSTRAINT "QrAllocationRequest_requestedByUserId_fkey" FOREIGN KEY ("requestedByUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "QrAllocationRequest" ADD CONSTRAINT "QrAllocationRequest_approvedByUserId_fkey" FOREIGN KEY ("approvedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "QrAllocationRequest" ADD CONSTRAINT "QrAllocationRequest_rejectedByUserId_fkey" FOREIGN KEY ("rejectedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AllocationEvent" ADD CONSTRAINT "AllocationEvent_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AllocationEvent" ADD CONSTRAINT "AllocationEvent_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AllocationEvent" ADD CONSTRAINT "AllocationEvent_requestId_fkey" FOREIGN KEY ("requestId") REFERENCES "QrAllocationRequest"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintPackToken" ADD CONSTRAINT "PrintPackToken_productBatchId_fkey" FOREIGN KEY ("productBatchId") REFERENCES "ProductBatch"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintPackToken" ADD CONSTRAINT "PrintPackToken_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
