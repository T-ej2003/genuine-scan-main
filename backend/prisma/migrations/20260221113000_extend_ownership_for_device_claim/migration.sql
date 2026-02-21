-- Make user ownership optional and support device/IP claim evidence.
ALTER TABLE "Ownership"
  ALTER COLUMN "userId" DROP NOT NULL;

ALTER TABLE "Ownership"
  ADD COLUMN IF NOT EXISTS "deviceTokenHash" TEXT,
  ADD COLUMN IF NOT EXISTS "ipHash" TEXT,
  ADD COLUMN IF NOT EXISTS "userAgentHash" TEXT,
  ADD COLUMN IF NOT EXISTS "claimSource" TEXT NOT NULL DEFAULT 'USER',
  ADD COLUMN IF NOT EXISTS "linkedAt" TIMESTAMP(3);

CREATE INDEX IF NOT EXISTS "Ownership_deviceTokenHash_idx" ON "Ownership"("deviceTokenHash");
CREATE INDEX IF NOT EXISTS "Ownership_ipHash_idx" ON "Ownership"("ipHash");
