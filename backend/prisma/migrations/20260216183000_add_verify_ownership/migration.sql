-- CreateTable
CREATE TABLE "Ownership" (
    "id" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "claimedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Ownership_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Ownership_qrCodeId_key" ON "Ownership"("qrCodeId");
CREATE INDEX "Ownership_userId_idx" ON "Ownership"("userId");

-- AddForeignKey
ALTER TABLE "Ownership"
ADD CONSTRAINT "Ownership_qrCodeId_fkey"
FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE CASCADE ON UPDATE CASCADE;
