-- CreateEnum
CREATE TYPE "VerificationDecisionOutcome" AS ENUM (
  'AUTHENTIC',
  'SUSPICIOUS_DUPLICATE',
  'BLOCKED',
  'NOT_READY',
  'NOT_FOUND',
  'INVALID_SIGNATURE',
  'INVALID_PAYLOAD',
  'EXPIRED',
  'TOKEN_MISMATCH',
  'UNAVAILABLE'
);

-- CreateEnum
CREATE TYPE "VerificationProofTier" AS ENUM (
  'SIGNED_LABEL',
  'MANUAL_REGISTRY_LOOKUP',
  'DEGRADED'
);

-- CreateEnum
CREATE TYPE "VerificationRiskBand" AS ENUM (
  'LOW',
  'ELEVATED',
  'HIGH',
  'CRITICAL'
);

-- CreateEnum
CREATE TYPE "VerificationReplacementStatus" AS ENUM (
  'NONE',
  'ACTIVE_REPLACEMENT',
  'REPLACED_LABEL'
);

-- CreateEnum
CREATE TYPE "VerificationDegradationMode" AS ENUM (
  'NORMAL',
  'QUEUE_AND_RETRY',
  'FAIL_CLOSED'
);

-- CreateEnum
CREATE TYPE "CustomerTrustLevel" AS ENUM (
  'ANONYMOUS',
  'DEVICE_TRUSTED',
  'ACCOUNT_TRUSTED',
  'OPERATOR_REVIEWED'
);

-- CreateEnum
CREATE TYPE "ReplacementChainStatus" AS ENUM (
  'ACTIVE',
  'SUPERSEDED'
);

-- CreateEnum
CREATE TYPE "AuditLogOutboxStatus" AS ENUM (
  'QUEUED',
  'SENT',
  'FAILED'
);

-- CreateTable
CREATE TABLE "VerificationDecision" (
  "id" TEXT NOT NULL,
  "decisionVersion" INTEGER NOT NULL DEFAULT 1,
  "qrCodeId" TEXT,
  "code" TEXT,
  "licenseeId" TEXT,
  "batchId" TEXT,
  "proofSource" TEXT,
  "proofTier" "VerificationProofTier" NOT NULL,
  "outcome" "VerificationDecisionOutcome" NOT NULL,
  "classification" TEXT,
  "reasonCodes" TEXT[] DEFAULT ARRAY[]::TEXT[],
  "riskBand" "VerificationRiskBand" NOT NULL DEFAULT 'LOW',
  "replacementStatus" "VerificationReplacementStatus" NOT NULL DEFAULT 'NONE',
  "degradationMode" "VerificationDegradationMode" NOT NULL DEFAULT 'NORMAL',
  "customerTrustLevel" "CustomerTrustLevel" NOT NULL DEFAULT 'ANONYMOUS',
  "isAuthentic" BOOLEAN NOT NULL DEFAULT false,
  "scanCount" INTEGER,
  "riskScore" INTEGER,
  "actorIpHash" TEXT,
  "actorDeviceHash" TEXT,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "VerificationDecision_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationEvidenceSnapshot" (
  "id" TEXT NOT NULL,
  "verificationDecisionId" TEXT NOT NULL,
  "scanSummary" JSONB,
  "ownershipSnapshot" JSONB,
  "riskSignals" JSONB,
  "policySnapshot" JSONB,
  "lifecycleSnapshot" JSONB,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "VerificationEvidenceSnapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ReplacementChain" (
  "id" TEXT NOT NULL,
  "status" "ReplacementChainStatus" NOT NULL DEFAULT 'ACTIVE',
  "originalQrCodeId" TEXT NOT NULL,
  "replacementQrCodeId" TEXT NOT NULL,
  "originalPrintJobId" TEXT,
  "replacementPrintJobId" TEXT,
  "reissueRequestId" TEXT,
  "reason" TEXT,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "supersededAt" TIMESTAMP(3),

  CONSTRAINT "ReplacementChain_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DegradationEvent" (
  "id" TEXT NOT NULL,
  "dependencyKey" TEXT NOT NULL,
  "mode" "VerificationDegradationMode" NOT NULL,
  "code" TEXT NOT NULL,
  "message" TEXT NOT NULL,
  "context" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "resolvedAt" TIMESTAMP(3),

  CONSTRAINT "DegradationEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CustomerTrustCredential" (
  "id" TEXT NOT NULL,
  "qrCodeId" TEXT NOT NULL,
  "customerUserId" TEXT,
  "customerEmail" TEXT,
  "deviceTokenHash" TEXT,
  "trustLevel" "CustomerTrustLevel" NOT NULL,
  "source" TEXT NOT NULL,
  "metadata" JSONB,
  "lastVerifiedAt" TIMESTAMP(3),
  "claimedAt" TIMESTAMP(3),
  "linkedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "CustomerTrustCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLogOutbox" (
  "id" TEXT NOT NULL,
  "payload" JSONB NOT NULL,
  "status" "AuditLogOutboxStatus" NOT NULL DEFAULT 'QUEUED',
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastError" TEXT,
  "flushedAuditLogId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "AuditLogOutbox_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "VerificationDecision_qrCodeId_createdAt_idx" ON "VerificationDecision"("qrCodeId", "createdAt");
CREATE INDEX "VerificationDecision_code_createdAt_idx" ON "VerificationDecision"("code", "createdAt");
CREATE INDEX "VerificationDecision_licenseeId_createdAt_idx" ON "VerificationDecision"("licenseeId", "createdAt");
CREATE INDEX "VerificationDecision_outcome_createdAt_idx" ON "VerificationDecision"("outcome", "createdAt");
CREATE INDEX "VerificationDecision_riskBand_createdAt_idx" ON "VerificationDecision"("riskBand", "createdAt");

-- CreateIndex
CREATE INDEX "VerificationEvidenceSnapshot_verificationDecisionId_createdAt_idx"
  ON "VerificationEvidenceSnapshot"("verificationDecisionId", "createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "ReplacementChain_replacementQrCodeId_key" ON "ReplacementChain"("replacementQrCodeId");
CREATE UNIQUE INDEX "ReplacementChain_reissueRequestId_key" ON "ReplacementChain"("reissueRequestId");
CREATE INDEX "ReplacementChain_originalQrCodeId_createdAt_idx" ON "ReplacementChain"("originalQrCodeId", "createdAt");
CREATE INDEX "ReplacementChain_replacementQrCodeId_createdAt_idx" ON "ReplacementChain"("replacementQrCodeId", "createdAt");
CREATE INDEX "ReplacementChain_replacementPrintJobId_createdAt_idx" ON "ReplacementChain"("replacementPrintJobId", "createdAt");

-- CreateIndex
CREATE INDEX "DegradationEvent_dependencyKey_createdAt_idx" ON "DegradationEvent"("dependencyKey", "createdAt");
CREATE INDEX "DegradationEvent_mode_createdAt_idx" ON "DegradationEvent"("mode", "createdAt");

-- CreateIndex
CREATE INDEX "CustomerTrustCredential_qrCodeId_trustLevel_updatedAt_idx"
  ON "CustomerTrustCredential"("qrCodeId", "trustLevel", "updatedAt");
CREATE INDEX "CustomerTrustCredential_customerUserId_updatedAt_idx"
  ON "CustomerTrustCredential"("customerUserId", "updatedAt");
CREATE INDEX "CustomerTrustCredential_deviceTokenHash_updatedAt_idx"
  ON "CustomerTrustCredential"("deviceTokenHash", "updatedAt");

-- CreateIndex
CREATE INDEX "AuditLogOutbox_status_nextAttemptAt_idx" ON "AuditLogOutbox"("status", "nextAttemptAt");
CREATE INDEX "AuditLogOutbox_createdAt_idx" ON "AuditLogOutbox"("createdAt");

-- AddForeignKey
ALTER TABLE "VerificationEvidenceSnapshot"
  ADD CONSTRAINT "VerificationEvidenceSnapshot_verificationDecisionId_fkey"
  FOREIGN KEY ("verificationDecisionId") REFERENCES "VerificationDecision"("id") ON DELETE CASCADE ON UPDATE CASCADE;
