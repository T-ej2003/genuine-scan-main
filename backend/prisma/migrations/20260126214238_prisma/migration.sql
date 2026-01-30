-- AlterTable
ALTER TABLE "AuditLog" ADD COLUMN     "licenseeId" TEXT;

-- CreateIndex
CREATE INDEX "AuditLog_licenseeId_idx" ON "AuditLog"("licenseeId");
