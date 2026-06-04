DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrintJobStatus') THEN
    CREATE TYPE "PrintJobStatus" AS ENUM ('PENDING', 'CONFIRMED', 'CANCELLED');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS "PrintJob" (
    "id" TEXT NOT NULL,
    "batchId" TEXT NOT NULL,
    "manufacturerId" TEXT NOT NULL,
    "status" "PrintJobStatus" NOT NULL DEFAULT 'PENDING',
    "quantity" INTEGER NOT NULL,
    "rangeStart" TEXT,
    "rangeEnd" TEXT,
    "printLockTokenHash" TEXT NOT NULL,
    "confirmedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PrintJob_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "PrintJob_printLockTokenHash_key" ON "PrintJob"("printLockTokenHash");
CREATE INDEX IF NOT EXISTS "PrintJob_batchId_idx" ON "PrintJob"("batchId");
CREATE INDEX IF NOT EXISTS "PrintJob_manufacturerId_idx" ON "PrintJob"("manufacturerId");
CREATE INDEX IF NOT EXISTS "PrintJob_status_idx" ON "PrintJob"("status");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintJob_batchId_fkey'
  ) THEN
    ALTER TABLE "PrintJob"
      ADD CONSTRAINT "PrintJob_batchId_fkey"
      FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintJob_manufacturerId_fkey'
  ) THEN
    ALTER TABLE "PrintJob"
      ADD CONSTRAINT "PrintJob_manufacturerId_fkey"
      FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

ALTER TABLE "QRCode"
  ADD COLUMN IF NOT EXISTS "printJobId" TEXT;

CREATE INDEX IF NOT EXISTS "QRCode_printJobId_idx" ON "QRCode"("printJobId");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'QRCode_printJobId_fkey'
  ) THEN
    ALTER TABLE "QRCode"
      ADD CONSTRAINT "QRCode_printJobId_fkey"
      FOREIGN KEY ("printJobId") REFERENCES "PrintJob"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

-- CreateTable
CREATE TABLE "PrintRenderToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "printJobId" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PrintRenderToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PrintRenderToken_tokenHash_key" ON "PrintRenderToken"("tokenHash");

-- CreateIndex
CREATE INDEX "PrintRenderToken_printJobId_createdAt_idx" ON "PrintRenderToken"("printJobId", "createdAt");

-- CreateIndex
CREATE INDEX "PrintRenderToken_qrCodeId_createdAt_idx" ON "PrintRenderToken"("qrCodeId", "createdAt");

-- CreateIndex
CREATE INDEX "PrintRenderToken_expiresAt_idx" ON "PrintRenderToken"("expiresAt");

-- CreateIndex
CREATE INDEX "PrintRenderToken_usedAt_idx" ON "PrintRenderToken"("usedAt");

-- AddForeignKey
ALTER TABLE "PrintRenderToken" ADD CONSTRAINT "PrintRenderToken_printJobId_fkey" FOREIGN KEY ("printJobId") REFERENCES "PrintJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintRenderToken" ADD CONSTRAINT "PrintRenderToken_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
