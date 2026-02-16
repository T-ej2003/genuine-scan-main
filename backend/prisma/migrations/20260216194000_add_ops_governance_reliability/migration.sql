-- CreateEnum
CREATE TYPE "IncidentHandoffStage" AS ENUM ('INTAKE', 'REVIEW', 'CONTAINMENT', 'DOCUMENTATION', 'RESOLUTION', 'COMPLETE');

-- CreateEnum
CREATE TYPE "SupportTicketStatus" AS ENUM ('OPEN', 'IN_PROGRESS', 'WAITING_CUSTOMER', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "NotificationChannel" AS ENUM ('WEB', 'EMAIL');

-- CreateEnum
CREATE TYPE "NotificationAudience" AS ENUM ('SUPER_ADMIN', 'LICENSEE_ADMIN', 'MANUFACTURER', 'ALL');

-- CreateEnum
CREATE TYPE "EvidenceRetentionJobStatus" AS ENUM ('RUNNING', 'COMPLETED', 'FAILED', 'PREVIEW');

-- CreateTable
CREATE TABLE "IncidentHandoff" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "currentStage" "IncidentHandoffStage" NOT NULL DEFAULT 'INTAKE',
    "intakeAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reviewAt" TIMESTAMP(3),
    "containmentAt" TIMESTAMP(3),
    "documentationAt" TIMESTAMP(3),
    "resolutionAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "slaDueAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "IncidentHandoff_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SupportTicket" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "referenceCode" TEXT NOT NULL,
    "licenseeId" TEXT,
    "customerEmail" TEXT,
    "subject" TEXT NOT NULL,
    "status" "SupportTicketStatus" NOT NULL DEFAULT 'OPEN',
    "priority" "IncidentPriority" NOT NULL DEFAULT 'P3',
    "assignedToUserId" TEXT,
    "slaDueAt" TIMESTAMP(3),
    "firstResponseAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SupportTicket_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SupportTicketMessage" (
    "id" TEXT NOT NULL,
    "ticketId" TEXT NOT NULL,
    "actorType" "IncidentActorType" NOT NULL DEFAULT 'CUSTOMER',
    "actorUserId" TEXT,
    "message" TEXT NOT NULL,
    "isInternal" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SupportTicketMessage_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "orgId" TEXT,
    "licenseeId" TEXT,
    "incidentId" TEXT,
    "audience" "NotificationAudience" NOT NULL DEFAULT 'ALL',
    "channel" "NotificationChannel" NOT NULL DEFAULT 'WEB',
    "type" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "data" JSONB,
    "readAt" TIMESTAMP(3),
    "emailedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TenantFeatureFlag" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT false,
    "config" JSONB,
    "updatedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TenantFeatureFlag_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EvidenceRetentionPolicy" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "retentionDays" INTEGER NOT NULL DEFAULT 180,
    "purgeEnabled" BOOLEAN NOT NULL DEFAULT false,
    "exportBeforePurge" BOOLEAN NOT NULL DEFAULT true,
    "legalHoldTags" TEXT[],
    "updatedByUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EvidenceRetentionPolicy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EvidenceRetentionJob" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT,
    "status" "EvidenceRetentionJobStatus" NOT NULL DEFAULT 'PREVIEW',
    "mode" TEXT NOT NULL,
    "cutoffAt" TIMESTAMP(3) NOT NULL,
    "recordsEvaluated" INTEGER NOT NULL DEFAULT 0,
    "recordsPurged" INTEGER NOT NULL DEFAULT 0,
    "recordsExported" INTEGER NOT NULL DEFAULT 0,
    "summary" JSONB,
    "startedByUserId" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),

    CONSTRAINT "EvidenceRetentionJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentEvidenceFingerprint" (
    "id" TEXT NOT NULL,
    "incidentEvidenceId" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "sha256" TEXT NOT NULL,
    "fileSize" INTEGER NOT NULL,
    "mimeType" TEXT NOT NULL,
    "ext" TEXT,
    "duplicateCount" INTEGER NOT NULL DEFAULT 0,
    "seenInOtherIncidents" INTEGER NOT NULL DEFAULT 0,
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "checks" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentEvidenceFingerprint_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RouteTransitionMetric" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "licenseeId" TEXT,
    "routeFrom" TEXT,
    "routeTo" TEXT NOT NULL,
    "source" TEXT,
    "role" "UserRole",
    "deviceType" TEXT,
    "networkType" TEXT,
    "online" BOOLEAN NOT NULL DEFAULT true,
    "transitionMs" INTEGER NOT NULL,
    "verifyCodePresent" BOOLEAN NOT NULL DEFAULT false,
    "verifyResult" TEXT,
    "dropped" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RouteTransitionMetric_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "IncidentHandoff_incidentId_key" ON "IncidentHandoff"("incidentId");
CREATE INDEX "IncidentHandoff_currentStage_idx" ON "IncidentHandoff"("currentStage");
CREATE INDEX "IncidentHandoff_slaDueAt_idx" ON "IncidentHandoff"("slaDueAt");

-- CreateIndex
CREATE UNIQUE INDEX "SupportTicket_incidentId_key" ON "SupportTicket"("incidentId");
CREATE UNIQUE INDEX "SupportTicket_referenceCode_key" ON "SupportTicket"("referenceCode");
CREATE INDEX "SupportTicket_licenseeId_idx" ON "SupportTicket"("licenseeId");
CREATE INDEX "SupportTicket_status_idx" ON "SupportTicket"("status");
CREATE INDEX "SupportTicket_priority_idx" ON "SupportTicket"("priority");
CREATE INDEX "SupportTicket_assignedToUserId_idx" ON "SupportTicket"("assignedToUserId");
CREATE INDEX "SupportTicket_createdAt_idx" ON "SupportTicket"("createdAt");

-- CreateIndex
CREATE INDEX "SupportTicketMessage_ticketId_idx" ON "SupportTicketMessage"("ticketId");
CREATE INDEX "SupportTicketMessage_actorUserId_idx" ON "SupportTicketMessage"("actorUserId");
CREATE INDEX "SupportTicketMessage_createdAt_idx" ON "SupportTicketMessage"("createdAt");

-- CreateIndex
CREATE INDEX "Notification_userId_readAt_idx" ON "Notification"("userId", "readAt");
CREATE INDEX "Notification_licenseeId_createdAt_idx" ON "Notification"("licenseeId", "createdAt");
CREATE INDEX "Notification_orgId_createdAt_idx" ON "Notification"("orgId", "createdAt");
CREATE INDEX "Notification_incidentId_idx" ON "Notification"("incidentId");
CREATE INDEX "Notification_channel_createdAt_idx" ON "Notification"("channel", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "TenantFeatureFlag_licenseeId_key_key" ON "TenantFeatureFlag"("licenseeId", "key");
CREATE INDEX "TenantFeatureFlag_key_idx" ON "TenantFeatureFlag"("key");
CREATE INDEX "TenantFeatureFlag_updatedByUserId_idx" ON "TenantFeatureFlag"("updatedByUserId");

-- CreateIndex
CREATE UNIQUE INDEX "EvidenceRetentionPolicy_licenseeId_key" ON "EvidenceRetentionPolicy"("licenseeId");
CREATE INDEX "EvidenceRetentionPolicy_updatedByUserId_idx" ON "EvidenceRetentionPolicy"("updatedByUserId");

-- CreateIndex
CREATE INDEX "EvidenceRetentionJob_licenseeId_startedAt_idx" ON "EvidenceRetentionJob"("licenseeId", "startedAt");
CREATE INDEX "EvidenceRetentionJob_status_idx" ON "EvidenceRetentionJob"("status");
CREATE INDEX "EvidenceRetentionJob_startedByUserId_idx" ON "EvidenceRetentionJob"("startedByUserId");

-- CreateIndex
CREATE UNIQUE INDEX "IncidentEvidenceFingerprint_incidentEvidenceId_key" ON "IncidentEvidenceFingerprint"("incidentEvidenceId");
CREATE INDEX "IncidentEvidenceFingerprint_incidentId_idx" ON "IncidentEvidenceFingerprint"("incidentId");
CREATE INDEX "IncidentEvidenceFingerprint_sha256_idx" ON "IncidentEvidenceFingerprint"("sha256");

-- CreateIndex
CREATE INDEX "RouteTransitionMetric_routeTo_createdAt_idx" ON "RouteTransitionMetric"("routeTo", "createdAt");
CREATE INDEX "RouteTransitionMetric_licenseeId_createdAt_idx" ON "RouteTransitionMetric"("licenseeId", "createdAt");
CREATE INDEX "RouteTransitionMetric_role_createdAt_idx" ON "RouteTransitionMetric"("role", "createdAt");

-- AddForeignKey
ALTER TABLE "IncidentHandoff"
ADD CONSTRAINT "IncidentHandoff_incidentId_fkey"
FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicket"
ADD CONSTRAINT "SupportTicket_incidentId_fkey"
FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicket"
ADD CONSTRAINT "SupportTicket_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicket"
ADD CONSTRAINT "SupportTicket_assignedToUserId_fkey"
FOREIGN KEY ("assignedToUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicketMessage"
ADD CONSTRAINT "SupportTicketMessage_ticketId_fkey"
FOREIGN KEY ("ticketId") REFERENCES "SupportTicket"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SupportTicketMessage"
ADD CONSTRAINT "SupportTicketMessage_actorUserId_fkey"
FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification"
ADD CONSTRAINT "Notification_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification"
ADD CONSTRAINT "Notification_orgId_fkey"
FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification"
ADD CONSTRAINT "Notification_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification"
ADD CONSTRAINT "Notification_incidentId_fkey"
FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantFeatureFlag"
ADD CONSTRAINT "TenantFeatureFlag_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TenantFeatureFlag"
ADD CONSTRAINT "TenantFeatureFlag_updatedByUserId_fkey"
FOREIGN KEY ("updatedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidenceRetentionPolicy"
ADD CONSTRAINT "EvidenceRetentionPolicy_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidenceRetentionPolicy"
ADD CONSTRAINT "EvidenceRetentionPolicy_updatedByUserId_fkey"
FOREIGN KEY ("updatedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidenceRetentionJob"
ADD CONSTRAINT "EvidenceRetentionJob_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EvidenceRetentionJob"
ADD CONSTRAINT "EvidenceRetentionJob_startedByUserId_fkey"
FOREIGN KEY ("startedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentEvidenceFingerprint"
ADD CONSTRAINT "IncidentEvidenceFingerprint_incidentEvidenceId_fkey"
FOREIGN KEY ("incidentEvidenceId") REFERENCES "IncidentEvidence"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentEvidenceFingerprint"
ADD CONSTRAINT "IncidentEvidenceFingerprint_incidentId_fkey"
FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RouteTransitionMetric"
ADD CONSTRAINT "RouteTransitionMetric_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RouteTransitionMetric"
ADD CONSTRAINT "RouteTransitionMetric_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;
