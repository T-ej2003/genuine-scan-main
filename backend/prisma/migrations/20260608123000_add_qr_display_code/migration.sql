ALTER TABLE "QRCode"
ADD COLUMN IF NOT EXISTS "displayCode" TEXT;

UPDATE "QRCode"
SET "displayCode" = "code"
WHERE "displayCode" IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS "QRCode_displayCode_key" ON "QRCode"("displayCode");
CREATE INDEX IF NOT EXISTS "QRCode_displayCode_idx" ON "QRCode"("displayCode");
