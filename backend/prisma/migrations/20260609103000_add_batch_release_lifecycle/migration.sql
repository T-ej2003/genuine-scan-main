DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'BatchLifecycleState') THEN
    CREATE TYPE "BatchLifecycleState" AS ENUM (
      'DRAFT',
      'CODES_GENERATED',
      'PRINT_ACKNOWLEDGED',
      'PRINT_CONFIRMED',
      'SAMPLE_VERIFIED',
      'RELEASED',
      'FAILED',
      'VOIDED'
    );
  END IF;
END $$;

ALTER TABLE "Batch"
  ADD COLUMN IF NOT EXISTS "lifecycleState" "BatchLifecycleState" NOT NULL DEFAULT 'DRAFT',
  ADD COLUMN IF NOT EXISTS "sampleScanPolicy" JSONB,
  ADD COLUMN IF NOT EXISTS "releasedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "releasedByUserId" TEXT;

CREATE INDEX IF NOT EXISTS "Batch_lifecycleState_idx" ON "Batch"("lifecycleState");
CREATE INDEX IF NOT EXISTS "Batch_releasedAt_idx" ON "Batch"("releasedAt");
