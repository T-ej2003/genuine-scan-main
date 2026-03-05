-- CreateEnum
CREATE TYPE "PrintSessionStatus" AS ENUM ('ACTIVE', 'FAILED', 'COMPLETED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "PrintItemState" AS ENUM ('RESERVED', 'ISSUED', 'AGENT_ACKED', 'PRINT_CONFIRMED', 'CLOSED', 'FROZEN', 'FAILED');

-- CreateEnum
CREATE TYPE "PrintItemEventType" AS ENUM ('RESERVED', 'ISSUED', 'AGENT_ACKED', 'PRINT_CONFIRMED', 'CLOSED', 'FROZEN', 'FAILED', 'INCIDENT_RAISED');

-- CreateEnum
CREATE TYPE "PrinterTrustStatus" AS ENUM ('PENDING', 'TRUSTED', 'REVOKED', 'FAILED');

-- CreateEnum
CREATE TYPE "ForensicEventType" AS ENUM ('PRINT_ISSUANCE', 'PRINT_CONFIRM', 'SCAN_VERIFY', 'SECURITY_BLOCK');

-- CreateTable
CREATE TABLE "PrinterRegistration" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "orgId" TEXT,
    "licenseeId" TEXT,
    "deviceFingerprint" TEXT NOT NULL,
    "agentId" TEXT NOT NULL,
    "publicKeyPem" TEXT NOT NULL,
    "certFingerprint" TEXT,
    "trustStatus" "PrinterTrustStatus" NOT NULL DEFAULT 'PENDING',
    "trustReason" TEXT,
    "approvedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "lastSeenAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PrinterRegistration_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrintSession" (
    "id" TEXT NOT NULL,
    "printJobId" TEXT NOT NULL,
    "batchId" TEXT NOT NULL,
    "manufacturerId" TEXT NOT NULL,
    "printerRegistrationId" TEXT,
    "status" "PrintSessionStatus" NOT NULL DEFAULT 'ACTIVE',
    "totalItems" INTEGER NOT NULL,
    "issuedItems" INTEGER NOT NULL DEFAULT 0,
    "confirmedItems" INTEGER NOT NULL DEFAULT 0,
    "frozenItems" INTEGER NOT NULL DEFAULT 0,
    "failedReason" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PrintSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrintItem" (
    "id" TEXT NOT NULL,
    "printSessionId" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "state" "PrintItemState" NOT NULL DEFAULT 'RESERVED',
    "issueSequence" INTEGER,
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "currentRenderTokenHash" TEXT,
    "issuedAt" TIMESTAMP(3),
    "agentAckedAt" TIMESTAMP(3),
    "printConfirmedAt" TIMESTAMP(3),
    "closedAt" TIMESTAMP(3),
    "frozenAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "failureReason" TEXT,
    "deadLetterReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "PrintItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrintItemEvent" (
    "id" TEXT NOT NULL,
    "printItemId" TEXT NOT NULL,
    "eventType" "PrintItemEventType" NOT NULL,
    "previousState" "PrintItemState",
    "nextState" "PrintItemState",
    "details" JSONB,
    "actorUserId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PrintItemEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "PrinterAttestation" (
    "id" TEXT NOT NULL,
    "printerRegistrationId" TEXT NOT NULL,
    "signedPayloadHash" TEXT NOT NULL,
    "heartbeatNonce" TEXT NOT NULL,
    "attestedAt" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "sourceIpHash" TEXT,
    "userAgentHash" TEXT,
    "mtlsFingerprint" TEXT,
    "signatureValid" BOOLEAN NOT NULL DEFAULT false,
    "trustValid" BOOLEAN NOT NULL DEFAULT false,
    "rejectionReason" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "PrinterAttestation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ForensicEventChain" (
    "id" TEXT NOT NULL,
    "eventType" "ForensicEventType" NOT NULL,
    "chainScope" TEXT NOT NULL DEFAULT 'GLOBAL',
    "previousHash" TEXT NOT NULL,
    "payloadHash" TEXT NOT NULL,
    "eventHash" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "auditLogId" TEXT,
    "licenseeId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ForensicEventChain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ActionIdempotencyKey" (
    "id" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "scope" TEXT,
    "requestHash" TEXT,
    "statusCode" INTEGER,
    "responsePayload" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ActionIdempotencyKey_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "PrinterRegistration_userId_deviceFingerprint_key" ON "PrinterRegistration"("userId", "deviceFingerprint");

-- CreateIndex
CREATE INDEX "PrinterRegistration_agentId_idx" ON "PrinterRegistration"("agentId");

-- CreateIndex
CREATE INDEX "PrinterRegistration_trustStatus_lastSeenAt_idx" ON "PrinterRegistration"("trustStatus", "lastSeenAt");

-- CreateIndex
CREATE INDEX "PrinterRegistration_licenseeId_trustStatus_idx" ON "PrinterRegistration"("licenseeId", "trustStatus");

-- CreateIndex
CREATE INDEX "PrinterRegistration_orgId_trustStatus_idx" ON "PrinterRegistration"("orgId", "trustStatus");

-- CreateIndex
CREATE UNIQUE INDEX "PrintSession_printJobId_key" ON "PrintSession"("printJobId");

-- CreateIndex
CREATE INDEX "PrintSession_manufacturerId_status_idx" ON "PrintSession"("manufacturerId", "status");

-- CreateIndex
CREATE INDEX "PrintSession_batchId_status_idx" ON "PrintSession"("batchId", "status");

-- CreateIndex
CREATE INDEX "PrintSession_printerRegistrationId_idx" ON "PrintSession"("printerRegistrationId");

-- CreateIndex
CREATE UNIQUE INDEX "PrintItem_qrCodeId_key" ON "PrintItem"("qrCodeId");

-- CreateIndex
CREATE INDEX "PrintItem_printSessionId_state_issueSequence_idx" ON "PrintItem"("printSessionId", "state", "issueSequence");

-- CreateIndex
CREATE INDEX "PrintItem_state_updatedAt_idx" ON "PrintItem"("state", "updatedAt");

-- CreateIndex
CREATE INDEX "PrintItem_currentRenderTokenHash_idx" ON "PrintItem"("currentRenderTokenHash");

-- CreateIndex
CREATE INDEX "PrintItemEvent_printItemId_createdAt_idx" ON "PrintItemEvent"("printItemId", "createdAt");

-- CreateIndex
CREATE INDEX "PrintItemEvent_eventType_createdAt_idx" ON "PrintItemEvent"("eventType", "createdAt");

-- CreateIndex
CREATE INDEX "PrintItemEvent_actorUserId_createdAt_idx" ON "PrintItemEvent"("actorUserId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "PrinterAttestation_printerRegistrationId_heartbeatNonce_key" ON "PrinterAttestation"("printerRegistrationId", "heartbeatNonce");

-- CreateIndex
CREATE INDEX "PrinterAttestation_printerRegistrationId_createdAt_idx" ON "PrinterAttestation"("printerRegistrationId", "createdAt");

-- CreateIndex
CREATE INDEX "PrinterAttestation_expiresAt_idx" ON "PrinterAttestation"("expiresAt");

-- CreateIndex
CREATE INDEX "PrinterAttestation_trustValid_createdAt_idx" ON "PrinterAttestation"("trustValid", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ForensicEventChain_eventHash_key" ON "ForensicEventChain"("eventHash");

-- CreateIndex
CREATE INDEX "ForensicEventChain_chainScope_createdAt_idx" ON "ForensicEventChain"("chainScope", "createdAt");

-- CreateIndex
CREATE INDEX "ForensicEventChain_eventType_createdAt_idx" ON "ForensicEventChain"("eventType", "createdAt");

-- CreateIndex
CREATE INDEX "ForensicEventChain_licenseeId_createdAt_idx" ON "ForensicEventChain"("licenseeId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ActionIdempotencyKey_keyHash_key" ON "ActionIdempotencyKey"("keyHash");

-- CreateIndex
CREATE INDEX "ActionIdempotencyKey_action_scope_createdAt_idx" ON "ActionIdempotencyKey"("action", "scope", "createdAt");

-- CreateIndex
CREATE INDEX "ActionIdempotencyKey_expiresAt_idx" ON "ActionIdempotencyKey"("expiresAt");

-- AddForeignKey
ALTER TABLE "PrinterRegistration" ADD CONSTRAINT "PrinterRegistration_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrinterRegistration" ADD CONSTRAINT "PrinterRegistration_orgId_fkey" FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrinterRegistration" ADD CONSTRAINT "PrinterRegistration_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintSession" ADD CONSTRAINT "PrintSession_printJobId_fkey" FOREIGN KEY ("printJobId") REFERENCES "PrintJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintSession" ADD CONSTRAINT "PrintSession_batchId_fkey" FOREIGN KEY ("batchId") REFERENCES "Batch"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintSession" ADD CONSTRAINT "PrintSession_manufacturerId_fkey" FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintSession" ADD CONSTRAINT "PrintSession_printerRegistrationId_fkey" FOREIGN KEY ("printerRegistrationId") REFERENCES "PrinterRegistration"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintItem" ADD CONSTRAINT "PrintItem_printSessionId_fkey" FOREIGN KEY ("printSessionId") REFERENCES "PrintSession"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintItem" ADD CONSTRAINT "PrintItem_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintItemEvent" ADD CONSTRAINT "PrintItemEvent_printItemId_fkey" FOREIGN KEY ("printItemId") REFERENCES "PrintItem"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrintItemEvent" ADD CONSTRAINT "PrintItemEvent_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "PrinterAttestation" ADD CONSTRAINT "PrinterAttestation_printerRegistrationId_fkey" FOREIGN KEY ("printerRegistrationId") REFERENCES "PrinterRegistration"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ForensicEventChain" ADD CONSTRAINT "ForensicEventChain_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;
