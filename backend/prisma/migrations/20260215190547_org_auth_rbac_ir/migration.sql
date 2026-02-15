/*
  Org Auth + RBAC + Incident Response extensions

  Notes:
  - We backfill Organization rows from existing Licensee rows.
  - Licensee.orgId is introduced as NOT NULL, but added nullable first for safe backfill.
  - user/org scoping: we align orgId with existing licenseeId (1:1 org<->licensee).
*/

-- CreateEnum
CREATE TYPE "UserStatus" AS ENUM ('INVITED', 'ACTIVE', 'DISABLED');

-- CreateEnum
CREATE TYPE "PolicyRuleType" AS ENUM ('DISTINCT_DEVICES', 'MULTI_COUNTRY', 'BURST_SCANS', 'TOO_MANY_REPORTS');

-- CreateEnum
CREATE TYPE "IncidentPriority" AS ENUM ('P1', 'P2', 'P3', 'P4');

-- AlterEnum (UserRole)
ALTER TYPE "UserRole" ADD VALUE 'PLATFORM_SUPER_ADMIN';
ALTER TYPE "UserRole" ADD VALUE 'ORG_ADMIN';
ALTER TYPE "UserRole" ADD VALUE 'MANUFACTURER_ADMIN';
ALTER TYPE "UserRole" ADD VALUE 'MANUFACTURER_USER';

-- AlterEnum (PolicyAlertType)
ALTER TYPE "PolicyAlertType" ADD VALUE 'POLICY_RULE';

-- AlterEnum (IncidentStatus)
ALTER TYPE "IncidentStatus" ADD VALUE 'TRIAGE';
ALTER TYPE "IncidentStatus" ADD VALUE 'CONTAINMENT';
ALTER TYPE "IncidentStatus" ADD VALUE 'ERADICATION';
ALTER TYPE "IncidentStatus" ADD VALUE 'RECOVERY';
ALTER TYPE "IncidentStatus" ADD VALUE 'REOPENED';

-- CreateTable
CREATE TABLE "Organization" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Organization_isActive_idx" ON "Organization"("isActive");

-- AlterTable (Licensee)
ALTER TABLE "Licensee"
  ADD COLUMN "orgId" TEXT,
  ADD COLUMN "suspendedAt" TIMESTAMP(3),
  ADD COLUMN "suspendedReason" TEXT;

-- Backfill Organizations from existing Licensees (1:1 mapping; org.id == licensee.id)
INSERT INTO "Organization" ("id", "name", "isActive", "createdAt", "updatedAt")
SELECT l."id", l."name", l."isActive", l."createdAt", l."updatedAt"
FROM "Licensee" l
ON CONFLICT ("id") DO NOTHING;

-- Backfill Licensee.orgId to reference its Organization
UPDATE "Licensee"
SET "orgId" = "id"
WHERE "orgId" IS NULL;

-- Enforce NOT NULL now that the backfill is done
ALTER TABLE "Licensee" ALTER COLUMN "orgId" SET NOT NULL;

-- AlterTable (User)
ALTER TABLE "User"
  ADD COLUMN "disabledAt" TIMESTAMP(3),
  ADD COLUMN "disabledReason" TEXT,
  ADD COLUMN "failedLoginAttempts" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "lastLoginAt" TIMESTAMP(3),
  ADD COLUMN "lockedUntil" TIMESTAMP(3),
  ADD COLUMN "orgId" TEXT,
  ADD COLUMN "status" "UserStatus" NOT NULL DEFAULT 'ACTIVE',
  ALTER COLUMN "passwordHash" DROP NOT NULL;

-- Backfill User.orgId from licenseeId (org.id == licensee.id)
UPDATE "User"
SET "orgId" = "licenseeId"
WHERE "orgId" IS NULL AND "licenseeId" IS NOT NULL;

-- Backfill User.status based on legacy flags
UPDATE "User"
SET "status" = 'DISABLED'
WHERE ("isActive" = false OR "deletedAt" IS NOT NULL) AND "status" <> 'DISABLED';

-- AlterTable (Batch)
ALTER TABLE "Batch"
  ADD COLUMN "suspendedAt" TIMESTAMP(3),
  ADD COLUMN "suspendedReason" TEXT;

-- AlterTable (QRCode)
ALTER TABLE "QRCode"
  ADD COLUMN "underInvestigationAt" TIMESTAMP(3),
  ADD COLUMN "underInvestigationReason" TEXT;

-- AlterTable (AuditLog)
ALTER TABLE "AuditLog"
  ADD COLUMN "ipHash" TEXT,
  ADD COLUMN "orgId" TEXT,
  ADD COLUMN "userAgent" TEXT;

-- Backfill AuditLog.orgId from legacy licenseeId (org.id == licensee.id)
UPDATE "AuditLog"
SET "orgId" = "licenseeId"
WHERE "orgId" IS NULL AND "licenseeId" IS NOT NULL;

-- AlterTable (PolicyAlert)
ALTER TABLE "PolicyAlert"
  ADD COLUMN "incidentId" TEXT,
  ADD COLUMN "policyRuleId" TEXT;

-- AlterTable (Incident)
ALTER TABLE "Incident"
  ADD COLUMN "priority" "IncidentPriority" NOT NULL DEFAULT 'P3';

-- CreateTable
CREATE TABLE "Invite" (
  "id" TEXT NOT NULL,
  "orgId" TEXT NOT NULL,
  "licenseeId" TEXT,
  "email" TEXT NOT NULL,
  "role" "UserRole" NOT NULL,
  "manufacturerId" TEXT,
  "tokenHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "usedAt" TIMESTAMP(3),
  "createdByUserId" TEXT,
  "acceptedByUserId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "Invite_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PasswordReset" (
  "id" TEXT NOT NULL,
  "orgId" TEXT,
  "userId" TEXT NOT NULL,
  "tokenHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "usedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdIpHash" TEXT,
  "userAgentHash" TEXT,

  CONSTRAINT "PasswordReset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefreshToken" (
  "id" TEXT NOT NULL,
  "orgId" TEXT,
  "userId" TEXT NOT NULL,
  "tokenHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdIpHash" TEXT,
  "createdUserAgent" TEXT,
  "lastUsedAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "revokedReason" TEXT,
  "replacedByTokenHash" TEXT,

  CONSTRAINT "RefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PolicyRule" (
  "id" TEXT NOT NULL,
  "orgId" TEXT,
  "licenseeId" TEXT,
  "manufacturerId" TEXT,
  "createdByUserId" TEXT,
  "name" TEXT NOT NULL,
  "description" TEXT,
  "ruleType" "PolicyRuleType" NOT NULL,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "threshold" INTEGER NOT NULL,
  "windowMinutes" INTEGER NOT NULL,
  "severity" "AlertSeverity" NOT NULL DEFAULT 'MEDIUM',
  "autoCreateIncident" BOOLEAN NOT NULL DEFAULT false,
  "incidentSeverity" "IncidentSeverity",
  "incidentPriority" "IncidentPriority",
  "actionConfig" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "PolicyRule_pkey" PRIMARY KEY ("id")
);

-- Indexes (Invite)
CREATE UNIQUE INDEX "Invite_tokenHash_key" ON "Invite"("tokenHash");
CREATE INDEX "Invite_email_idx" ON "Invite"("email");
CREATE INDEX "Invite_orgId_idx" ON "Invite"("orgId");
CREATE INDEX "Invite_licenseeId_idx" ON "Invite"("licenseeId");
CREATE INDEX "Invite_expiresAt_idx" ON "Invite"("expiresAt");
CREATE INDEX "Invite_usedAt_idx" ON "Invite"("usedAt");

-- Indexes (PasswordReset)
CREATE UNIQUE INDEX "PasswordReset_tokenHash_key" ON "PasswordReset"("tokenHash");
CREATE INDEX "PasswordReset_userId_idx" ON "PasswordReset"("userId");
CREATE INDEX "PasswordReset_orgId_idx" ON "PasswordReset"("orgId");
CREATE INDEX "PasswordReset_expiresAt_idx" ON "PasswordReset"("expiresAt");
CREATE INDEX "PasswordReset_usedAt_idx" ON "PasswordReset"("usedAt");

-- Indexes (RefreshToken)
CREATE UNIQUE INDEX "RefreshToken_tokenHash_key" ON "RefreshToken"("tokenHash");
CREATE INDEX "RefreshToken_userId_idx" ON "RefreshToken"("userId");
CREATE INDEX "RefreshToken_orgId_idx" ON "RefreshToken"("orgId");
CREATE INDEX "RefreshToken_expiresAt_idx" ON "RefreshToken"("expiresAt");
CREATE INDEX "RefreshToken_revokedAt_idx" ON "RefreshToken"("revokedAt");

-- Indexes (PolicyRule)
CREATE INDEX "PolicyRule_orgId_idx" ON "PolicyRule"("orgId");
CREATE INDEX "PolicyRule_licenseeId_idx" ON "PolicyRule"("licenseeId");
CREATE INDEX "PolicyRule_manufacturerId_idx" ON "PolicyRule"("manufacturerId");
CREATE INDEX "PolicyRule_isActive_idx" ON "PolicyRule"("isActive");
CREATE INDEX "PolicyRule_ruleType_idx" ON "PolicyRule"("ruleType");

-- Indexes (new columns)
CREATE INDEX "User_orgId_idx" ON "User"("orgId");
CREATE INDEX "User_status_idx" ON "User"("status");
CREATE INDEX "User_lockedUntil_idx" ON "User"("lockedUntil");
CREATE UNIQUE INDEX "Licensee_orgId_key" ON "Licensee"("orgId");
CREATE INDEX "Licensee_orgId_idx" ON "Licensee"("orgId");
CREATE INDEX "Batch_suspendedAt_idx" ON "Batch"("suspendedAt");
CREATE INDEX "QRCode_underInvestigationAt_idx" ON "QRCode"("underInvestigationAt");
CREATE INDEX "AuditLog_orgId_idx" ON "AuditLog"("orgId");
CREATE INDEX "PolicyAlert_policyRuleId_idx" ON "PolicyAlert"("policyRuleId");
CREATE INDEX "PolicyAlert_incidentId_idx" ON "PolicyAlert"("incidentId");
CREATE INDEX "Incident_priority_idx" ON "Incident"("priority");

-- Foreign Keys
ALTER TABLE "User"
  ADD CONSTRAINT "User_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "Licensee"
  ADD CONSTRAINT "Licensee_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "AuditLog"
  ADD CONSTRAINT "AuditLog_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "Invite"
  ADD CONSTRAINT "Invite_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "Invite_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "Invite_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "Invite_acceptedByUserId_fkey" FOREIGN KEY ("acceptedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "PasswordReset"
  ADD CONSTRAINT "PasswordReset_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "PasswordReset_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "RefreshToken"
  ADD CONSTRAINT "RefreshToken_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "RefreshToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PolicyRule"
  ADD CONSTRAINT "PolicyRule_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "PolicyRule_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "PolicyRule_createdByUserId_fkey" FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "PolicyAlert"
  ADD CONSTRAINT "PolicyAlert_policyRuleId_fkey" FOREIGN KEY ("policyRuleId") REFERENCES "PolicyRule"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "PolicyAlert_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE SET NULL ON UPDATE CASCADE;

