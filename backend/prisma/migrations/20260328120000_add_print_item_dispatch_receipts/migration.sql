ALTER TABLE "PrintItem"
  ADD COLUMN IF NOT EXISTS "deviceJobRef" TEXT,
  ADD COLUMN IF NOT EXISTS "dispatchMetadata" JSONB,
  ADD COLUMN IF NOT EXISTS "confirmationEvidence" JSONB,
  ADD COLUMN IF NOT EXISTS "dispatchedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "confirmationDeadlineAt" TIMESTAMP(3);

CREATE INDEX IF NOT EXISTS "PrintItem_deviceJobRef_idx" ON "PrintItem"("deviceJobRef");
CREATE INDEX IF NOT EXISTS "PrintItem_confirmationDeadlineAt_state_idx"
  ON "PrintItem"("confirmationDeadlineAt", "state");
