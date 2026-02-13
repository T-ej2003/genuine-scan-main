-- CreateEnum
CREATE TYPE "IncidentReportedBy" AS ENUM ('CUSTOMER', 'LICENSEE', 'ADMIN');

-- CreateEnum
CREATE TYPE "IncidentContactMethod" AS ENUM ('EMAIL', 'PHONE', 'WHATSAPP', 'NONE');

-- CreateEnum
CREATE TYPE "IncidentType" AS ENUM ('COUNTERFEIT_SUSPECTED', 'DUPLICATE_SCAN', 'TAMPERED_LABEL', 'WRONG_PRODUCT', 'OTHER');

-- CreateEnum
CREATE TYPE "IncidentSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "IncidentStatus" AS ENUM ('NEW', 'TRIAGED', 'INVESTIGATING', 'AWAITING_CUSTOMER', 'AWAITING_LICENSEE', 'MITIGATED', 'RESOLVED', 'CLOSED', 'REJECTED_SPAM');

-- CreateEnum
CREATE TYPE "IncidentResolutionOutcome" AS ENUM ('CONFIRMED_FRAUD', 'NOT_FRAUD', 'INCONCLUSIVE');

-- CreateEnum
CREATE TYPE "IncidentActorType" AS ENUM ('CUSTOMER', 'ADMIN', 'SYSTEM');

-- CreateEnum
CREATE TYPE "IncidentEventType" AS ENUM ('CREATED', 'UPDATED_FIELDS', 'STATUS_CHANGED', 'ASSIGNED', 'EMAIL_SENT', 'NOTE_ADDED', 'EVIDENCE_ADDED', 'EXPORTED');

-- CreateEnum
CREATE TYPE "IncidentCommDirection" AS ENUM ('OUTBOUND', 'INBOUND');

-- CreateEnum
CREATE TYPE "IncidentCommChannel" AS ENUM ('EMAIL');

-- CreateEnum
CREATE TYPE "IncidentCommStatus" AS ENUM ('QUEUED', 'SENT', 'FAILED');

-- AlterTable
ALTER TABLE "QrScanLog"
ADD COLUMN "locationName" TEXT,
ADD COLUMN "locationCountry" TEXT,
ADD COLUMN "locationRegion" TEXT,
ADD COLUMN "locationCity" TEXT;

-- CreateTable
CREATE TABLE "Incident" (
    "id" TEXT NOT NULL,
    "qrCodeId" TEXT,
    "qrCodeValue" TEXT NOT NULL,
    "scanEventId" TEXT,
    "licenseeId" TEXT,
    "reportedBy" "IncidentReportedBy" NOT NULL DEFAULT 'CUSTOMER',
    "customerName" TEXT,
    "customerEmail" TEXT,
    "customerPhone" TEXT,
    "customerCountry" TEXT,
    "preferredContactMethod" "IncidentContactMethod" NOT NULL DEFAULT 'NONE',
    "consentToContact" BOOLEAN NOT NULL DEFAULT false,
    "incidentType" "IncidentType" NOT NULL,
    "severity" "IncidentSeverity" NOT NULL DEFAULT 'MEDIUM',
    "severityOverridden" BOOLEAN NOT NULL DEFAULT false,
    "description" TEXT NOT NULL,
    "photos" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "purchasePlace" TEXT,
    "purchaseDate" TIMESTAMP(3),
    "productBatchNo" TEXT,
    "locationLat" DOUBLE PRECISION,
    "locationLng" DOUBLE PRECISION,
    "locationName" TEXT,
    "locationCountry" TEXT,
    "locationRegion" TEXT,
    "locationCity" TEXT,
    "ipHash" TEXT,
    "userAgentHash" TEXT,
    "deviceFingerprintHash" TEXT,
    "status" "IncidentStatus" NOT NULL DEFAULT 'NEW',
    "assignedToUserId" TEXT,
    "slaDueAt" TIMESTAMP(3),
    "tags" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "internalNotes" TEXT,
    "resolutionSummary" TEXT,
    "resolutionOutcome" "IncidentResolutionOutcome",
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Incident_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentEvent" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "actorType" "IncidentActorType" NOT NULL,
    "actorUserId" TEXT,
    "eventType" "IncidentEventType" NOT NULL,
    "eventPayload" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentCommunication" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "direction" "IncidentCommDirection" NOT NULL,
    "channel" "IncidentCommChannel" NOT NULL DEFAULT 'EMAIL',
    "toAddress" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "bodyPreview" TEXT NOT NULL,
    "providerMessageId" TEXT,
    "status" "IncidentCommStatus" NOT NULL DEFAULT 'QUEUED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentCommunication_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IncidentEvidence" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "fileUrl" TEXT,
    "storageKey" TEXT,
    "fileType" TEXT,
    "uploadedByUserId" TEXT,
    "uploadedBy" "IncidentActorType" NOT NULL DEFAULT 'CUSTOMER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "IncidentEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Incident_qrCodeId_idx" ON "Incident"("qrCodeId");
CREATE INDEX "Incident_qrCodeValue_idx" ON "Incident"("qrCodeValue");
CREATE INDEX "Incident_scanEventId_idx" ON "Incident"("scanEventId");
CREATE INDEX "Incident_licenseeId_idx" ON "Incident"("licenseeId");
CREATE INDEX "Incident_status_idx" ON "Incident"("status");
CREATE INDEX "Incident_severity_idx" ON "Incident"("severity");
CREATE INDEX "Incident_createdAt_idx" ON "Incident"("createdAt");
CREATE INDEX "Incident_assignedToUserId_idx" ON "Incident"("assignedToUserId");

-- CreateIndex
CREATE INDEX "IncidentEvent_incidentId_idx" ON "IncidentEvent"("incidentId");
CREATE INDEX "IncidentEvent_actorType_idx" ON "IncidentEvent"("actorType");
CREATE INDEX "IncidentEvent_eventType_idx" ON "IncidentEvent"("eventType");
CREATE INDEX "IncidentEvent_createdAt_idx" ON "IncidentEvent"("createdAt");
CREATE INDEX "IncidentEvent_actorUserId_idx" ON "IncidentEvent"("actorUserId");

-- CreateIndex
CREATE INDEX "IncidentCommunication_incidentId_idx" ON "IncidentCommunication"("incidentId");
CREATE INDEX "IncidentCommunication_status_idx" ON "IncidentCommunication"("status");
CREATE INDEX "IncidentCommunication_createdAt_idx" ON "IncidentCommunication"("createdAt");

-- CreateIndex
CREATE INDEX "IncidentEvidence_incidentId_idx" ON "IncidentEvidence"("incidentId");
CREATE INDEX "IncidentEvidence_uploadedByUserId_idx" ON "IncidentEvidence"("uploadedByUserId");
CREATE INDEX "IncidentEvidence_createdAt_idx" ON "IncidentEvidence"("createdAt");

-- AddForeignKey
ALTER TABLE "Incident" ADD CONSTRAINT "Incident_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Incident" ADD CONSTRAINT "Incident_scanEventId_fkey" FOREIGN KEY ("scanEventId") REFERENCES "QrScanLog"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Incident" ADD CONSTRAINT "Incident_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "Incident" ADD CONSTRAINT "Incident_assignedToUserId_fkey" FOREIGN KEY ("assignedToUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentEvent" ADD CONSTRAINT "IncidentEvent_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentEvent" ADD CONSTRAINT "IncidentEvent_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentCommunication" ADD CONSTRAINT "IncidentCommunication_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentEvidence" ADD CONSTRAINT "IncidentEvidence_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "IncidentEvidence" ADD CONSTRAINT "IncidentEvidence_uploadedByUserId_fkey" FOREIGN KEY ("uploadedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
