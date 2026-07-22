ALTER TABLE "AuditLogOutbox"
  ADD COLUMN "jobType" TEXT NOT NULL DEFAULT 'AUDIT_LOG_RECOVERY',
  ADD COLUMN "requestId" TEXT,
  ADD COLUMN "payloadDigest" TEXT,
  ADD COLUMN "idempotencyKey" TEXT,
  ADD COLUMN "organizationId" TEXT,
  ADD COLUMN "licenseeId" TEXT,
  ADD COLUMN "manufacturerId" TEXT,
  ADD COLUMN "initiatingUserId" TEXT,
  ADD COLUMN "initiatingActorRoleSnapshot" TEXT,
  ADD COLUMN "expiresAt" TIMESTAMP(3),
  ADD COLUMN "claimedAt" TIMESTAMP(3),
  ADD COLUMN "claimLeaseExpiresAt" TIMESTAMP(3);

ALTER TABLE "SecurityEventOutbox"
  ADD COLUMN "jobType" TEXT,
  ADD COLUMN "requestId" TEXT,
  ADD COLUMN "payloadDigest" TEXT,
  ADD COLUMN "idempotencyKey" TEXT,
  ADD COLUMN "organizationId" TEXT,
  ADD COLUMN "licenseeId" TEXT,
  ADD COLUMN "manufacturerId" TEXT,
  ADD COLUMN "initiatingUserId" TEXT,
  ADD COLUMN "expiresAt" TIMESTAMP(3),
  ADD COLUMN "claimedAt" TIMESTAMP(3),
  ADD COLUMN "claimLeaseExpiresAt" TIMESTAMP(3),
  ADD COLUMN "sinkEventId" TEXT;

CREATE UNIQUE INDEX "AuditLogOutbox_idempotencyKey_key" ON "AuditLogOutbox"("idempotencyKey");
CREATE INDEX "AuditLogOutbox_jobType_status_nextAttemptAt_idx" ON "AuditLogOutbox"("jobType","status","nextAttemptAt");
CREATE INDEX "AuditLogOutbox_claimLeaseExpiresAt_idx" ON "AuditLogOutbox"("claimLeaseExpiresAt");
CREATE UNIQUE INDEX "SecurityEventOutbox_idempotencyKey_key" ON "SecurityEventOutbox"("idempotencyKey");
CREATE INDEX "SecurityEventOutbox_jobType_status_nextAttemptAt_idx" ON "SecurityEventOutbox"("jobType","status","nextAttemptAt");
CREATE INDEX "SecurityEventOutbox_claimLeaseExpiresAt_idx" ON "SecurityEventOutbox"("claimLeaseExpiresAt");

ALTER TABLE "AuditLogOutbox"
  ADD CONSTRAINT "AuditLogOutbox_jobType_check" CHECK ("jobType" = 'AUDIT_LOG_RECOVERY'),
  ADD CONSTRAINT "AuditLogOutbox_payloadDigest_check" CHECK ("payloadDigest" IS NULL OR "payloadDigest" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "AuditLogOutbox_idempotencyKey_check" CHECK ("idempotencyKey" IS NULL OR "idempotencyKey" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "AuditLogOutbox_claimLease_check" CHECK ("claimLeaseExpiresAt" IS NULL OR "claimedAt" IS NOT NULL);

ALTER TABLE "SecurityEventOutbox"
  ADD CONSTRAINT "SecurityEventOutbox_jobType_check" CHECK ("jobType" IS NULL OR "jobType" IN ('AUDIT_LOG','CSP_VIOLATION')),
  ADD CONSTRAINT "SecurityEventOutbox_payloadDigest_check" CHECK ("payloadDigest" IS NULL OR "payloadDigest" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "SecurityEventOutbox_idempotencyKey_check" CHECK ("idempotencyKey" IS NULL OR "idempotencyKey" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "SecurityEventOutbox_claimLease_check" CHECK ("claimLeaseExpiresAt" IS NULL OR "claimedAt" IS NOT NULL);
