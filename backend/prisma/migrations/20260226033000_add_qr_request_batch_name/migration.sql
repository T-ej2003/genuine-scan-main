-- Add optional batch name on QR allocation requests so licensees can request a labeled received batch.
ALTER TABLE "QrAllocationRequest"
  ADD COLUMN IF NOT EXISTS "batchName" TEXT;
