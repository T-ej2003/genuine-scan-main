-- Restore migration: add updatedAt to QRRange safely
ALTER TABLE "QRRange"
ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Ensure default exists even if column was created earlier
ALTER TABLE "QRRange"
ALTER COLUMN "updatedAt" SET DEFAULT CURRENT_TIMESTAMP;

