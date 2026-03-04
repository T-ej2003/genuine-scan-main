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
