-- Add Notification.updatedAt so partition cutover can safely replay late updates.
ALTER TABLE "Notification"
ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

UPDATE "Notification"
SET "updatedAt" = COALESCE("updatedAt", "createdAt")
WHERE "updatedAt" IS NULL;

CREATE INDEX IF NOT EXISTS "Notification_updatedAt_idx" ON "Notification"("updatedAt");
CREATE INDEX IF NOT EXISTS "SecurityEventOutbox_updatedAt_idx" ON "SecurityEventOutbox"("updatedAt");
