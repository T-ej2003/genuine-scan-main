CREATE TABLE IF NOT EXISTS "PrintAuditEvent" (
  "id" TEXT NOT NULL,
  "batchId" TEXT NOT NULL,
  "printJobId" TEXT,
  "qrCodeId" TEXT,
  "eventType" TEXT NOT NULL,
  "actorId" TEXT,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "PrintAuditEvent_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "PrintAuditEvent_batchId_createdAt_idx" ON "PrintAuditEvent"("batchId", "createdAt");
CREATE INDEX IF NOT EXISTS "PrintAuditEvent_printJobId_createdAt_idx" ON "PrintAuditEvent"("printJobId", "createdAt");
CREATE INDEX IF NOT EXISTS "PrintAuditEvent_qrCodeId_createdAt_idx" ON "PrintAuditEvent"("qrCodeId", "createdAt");
CREATE INDEX IF NOT EXISTS "PrintAuditEvent_eventType_createdAt_idx" ON "PrintAuditEvent"("eventType", "createdAt");
CREATE INDEX IF NOT EXISTS "PrintAuditEvent_actorId_createdAt_idx" ON "PrintAuditEvent"("actorId", "createdAt");
