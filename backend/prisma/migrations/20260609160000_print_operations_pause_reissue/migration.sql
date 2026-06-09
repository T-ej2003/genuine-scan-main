ALTER TYPE "PrintJobStatus" ADD VALUE IF NOT EXISTS 'PAUSED';
ALTER TYPE "PrintJobStatus" ADD VALUE IF NOT EXISTS 'PARTIALLY_COMPLETED';
ALTER TYPE "PrintJobStatus" ADD VALUE IF NOT EXISTS 'STOPPED';

ALTER TYPE "PrintSessionStatus" ADD VALUE IF NOT EXISTS 'PAUSED';
ALTER TYPE "PrintSessionStatus" ADD VALUE IF NOT EXISTS 'RESUME_PENDING';
ALTER TYPE "PrintSessionStatus" ADD VALUE IF NOT EXISTS 'RETRY_WAITING';
ALTER TYPE "PrintSessionStatus" ADD VALUE IF NOT EXISTS 'STOPPING';
ALTER TYPE "PrintSessionStatus" ADD VALUE IF NOT EXISTS 'STOPPED';

ALTER TYPE "PrintItemState" ADD VALUE IF NOT EXISTS 'CANCELLED';

ALTER TYPE "PrintPipelineState" ADD VALUE IF NOT EXISTS 'PAUSED';
ALTER TYPE "PrintPipelineState" ADD VALUE IF NOT EXISTS 'RESUME_PENDING';
ALTER TYPE "PrintPipelineState" ADD VALUE IF NOT EXISTS 'RETRY_WAITING';
ALTER TYPE "PrintPipelineState" ADD VALUE IF NOT EXISTS 'STOPPING';
ALTER TYPE "PrintPipelineState" ADD VALUE IF NOT EXISTS 'STOPPED';

ALTER TYPE "PrintItemEventType" ADD VALUE IF NOT EXISTS 'CANCELLED';
ALTER TYPE "PrintItemEventType" ADD VALUE IF NOT EXISTS 'PAUSED';
ALTER TYPE "PrintItemEventType" ADD VALUE IF NOT EXISTS 'RESUMED';

ALTER TABLE "PrintReissueRequest"
  ADD COLUMN IF NOT EXISTS "licenseeId" TEXT,
  ADD COLUMN IF NOT EXISTS "manufacturerId" TEXT,
  ADD COLUMN IF NOT EXISTS "batchId" TEXT,
  ADD COLUMN IF NOT EXISTS "requestedByRole" TEXT,
  ADD COLUMN IF NOT EXISTS "targetApproverRole" TEXT,
  ADD COLUMN IF NOT EXISTS "quantity" INTEGER,
  ADD COLUMN IF NOT EXISTS "affectedRangeStart" TEXT,
  ADD COLUMN IF NOT EXISTS "affectedRangeEnd" TEXT,
  ADD COLUMN IF NOT EXISTS "decisionNote" TEXT,
  ADD COLUMN IF NOT EXISTS "approvalReferenceId" TEXT;

CREATE INDEX IF NOT EXISTS "PrintReissueRequest_licenseeId_status_createdAt_idx"
  ON "PrintReissueRequest"("licenseeId", "status", "createdAt");

CREATE INDEX IF NOT EXISTS "PrintReissueRequest_manufacturerId_status_createdAt_idx"
  ON "PrintReissueRequest"("manufacturerId", "status", "createdAt");

CREATE INDEX IF NOT EXISTS "PrintReissueRequest_batchId_status_createdAt_idx"
  ON "PrintReissueRequest"("batchId", "status", "createdAt");

CREATE INDEX IF NOT EXISTS "PrintReissueRequest_targetApproverRole_status_createdAt_idx"
  ON "PrintReissueRequest"("targetApproverRole", "status", "createdAt");
