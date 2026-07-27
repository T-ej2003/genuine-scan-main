-- A durable, database-verifiable capability is deliberately separate from the
-- rotating refresh bearer. Existing sessions remain valid until the
-- application creates a capability during their next authentication event.
-- PostgreSQL 18's built-in pg_catalog.sha256(bytea) is used by the reviewed
-- SQL boundary, so this restricted Prisma migration never needs CREATE
-- EXTENSION authority.

ALTER TABLE "RefreshToken"
  ADD COLUMN "sessionCapabilityHash" TEXT,
  ADD COLUMN "sessionCapabilityHashVersion" TEXT,
  ADD COLUMN "sessionCapabilityAssurance" TEXT,
  ADD COLUMN "sessionCapabilityExpiresAt" TIMESTAMP(3),
  ADD COLUMN "sessionCapabilityLastUsedAt" TIMESTAMP(3),
  ADD COLUMN "sessionCapabilityRevokedAt" TIMESTAMP(3),
  ADD COLUMN "sessionCapabilityRevokedReason" TEXT;

CREATE UNIQUE INDEX "RefreshToken_sessionCapabilityHash_key" ON "RefreshToken"("sessionCapabilityHash") WHERE "sessionCapabilityHash" IS NOT NULL;
CREATE INDEX "RefreshToken_sessionCapabilityExpiresAt_idx" ON "RefreshToken"("sessionCapabilityExpiresAt");
