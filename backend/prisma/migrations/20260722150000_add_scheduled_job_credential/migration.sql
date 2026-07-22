-- Hash-only database-verifiable identity for scheduled jobs. The raw
-- capability is provisioned to the scheduled runtime outside PostgreSQL and
-- is never stored in this table.
CREATE TABLE "ScheduledJobCredential" (
    "id" TEXT NOT NULL,
    "identityName" TEXT NOT NULL,
    "jobFamily" TEXT NOT NULL,
    "scheduleId" TEXT NOT NULL,
    "capabilityHash" TEXT NOT NULL,
    "capabilityHashVersion" TEXT NOT NULL DEFAULT 'sha256-v1',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "revokedReason" TEXT,
    "rotatedFromCredentialId" TEXT,
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "ScheduledJobCredential_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "ScheduledJobCredential_hash_version_check"
      CHECK ("capabilityHashVersion" = 'sha256-v1'),
    CONSTRAINT "ScheduledJobCredential_hash_check"
      CHECK ("capabilityHash" ~ '^[0-9a-f]{64}$'),
    CONSTRAINT "ScheduledJobCredential_identity_check"
      CHECK ("identityName" = 'identity-scheduled-job'),
    CONSTRAINT "ScheduledJobCredential_family_check"
      CHECK ("jobFamily" = 'compliance-pack'),
    CONSTRAINT "ScheduledJobCredential_revocation_check"
      CHECK (("revokedAt" IS NULL AND "revokedReason" IS NULL)
          OR ("revokedAt" IS NOT NULL AND "revokedReason" IS NOT NULL))
);

CREATE UNIQUE INDEX "ScheduledJobCredential_capabilityHash_key"
  ON "ScheduledJobCredential"("capabilityHash");
CREATE INDEX "ScheduledJobCredential_identityName_jobFamily_scheduleId_idx"
  ON "ScheduledJobCredential"("identityName", "jobFamily", "scheduleId");
CREATE INDEX "ScheduledJobCredential_jobFamily_scheduleId_expiresAt_idx"
  ON "ScheduledJobCredential"("jobFamily", "scheduleId", "expiresAt");
CREATE INDEX "ScheduledJobCredential_expiresAt_revokedAt_idx"
  ON "ScheduledJobCredential"("expiresAt", "revokedAt");
CREATE UNIQUE INDEX "ScheduledJobCredential_one_active_schedule"
  ON "ScheduledJobCredential"("identityName", "jobFamily", "scheduleId")
  WHERE "revokedAt" IS NULL;

-- Scheduled compliance rows retain their non-human authority partition. This
-- is nullable for migration compatibility with existing manual and historical
-- jobs, but every reviewed scheduled claim writes it atomically.
ALTER TABLE "CompliancePackJob" ADD COLUMN "scheduledScheduleId" TEXT;
CREATE INDEX "CompliancePackJob_scheduledScheduleId_status_startedAt_idx"
  ON "CompliancePackJob"("scheduledScheduleId", "status", "startedAt");
