-- DropIndex
DROP INDEX "Licensee_prefix_idx";

-- DropIndex
DROP INDEX "QRCode_code_idx";

-- AlterTable
ALTER TABLE "QRCode" ADD COLUMN     "productBatchId" TEXT;

-- CreateTable
CREATE TABLE "ProductBatch" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "parentBatchId" TEXT NOT NULL,
    "productName" TEXT NOT NULL,
    "productCode" TEXT NOT NULL,
    "description" TEXT,
    "serialStart" INTEGER NOT NULL,
    "serialEnd" INTEGER NOT NULL,
    "serialFormat" TEXT NOT NULL,
    "startCode" TEXT NOT NULL,
    "endCode" TEXT NOT NULL,
    "totalCodes" INTEGER NOT NULL,
    "manufacturerId" TEXT,
    "printedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProductBatch_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ProductBatch_licenseeId_idx" ON "ProductBatch"("licenseeId");

-- CreateIndex
CREATE INDEX "ProductBatch_parentBatchId_idx" ON "ProductBatch"("parentBatchId");

-- CreateIndex
CREATE INDEX "ProductBatch_manufacturerId_idx" ON "ProductBatch"("manufacturerId");

-- CreateIndex
CREATE INDEX "ProductBatch_printedAt_idx" ON "ProductBatch"("printedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ProductBatch_parentBatchId_productCode_key" ON "ProductBatch"("parentBatchId", "productCode");

-- CreateIndex
CREATE INDEX "Batch_printedAt_idx" ON "Batch"("printedAt");

-- CreateIndex
CREATE INDEX "Licensee_isActive_idx" ON "Licensee"("isActive");

-- CreateIndex
CREATE INDEX "QRCode_productBatchId_idx" ON "QRCode"("productBatchId");

-- AddForeignKey
ALTER TABLE "ProductBatch" ADD CONSTRAINT "ProductBatch_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProductBatch" ADD CONSTRAINT "ProductBatch_parentBatchId_fkey" FOREIGN KEY ("parentBatchId") REFERENCES "Batch"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProductBatch" ADD CONSTRAINT "ProductBatch_manufacturerId_fkey" FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "QRCode" ADD CONSTRAINT "QRCode_productBatchId_fkey" FOREIGN KEY ("productBatchId") REFERENCES "ProductBatch"("id") ON DELETE SET NULL ON UPDATE CASCADE;
