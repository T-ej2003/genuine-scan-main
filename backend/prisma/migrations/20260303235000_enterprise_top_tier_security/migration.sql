-- CreateEnum
CREATE TYPE "AuthRiskLevel" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "SecurityEventDeliveryStatus" AS ENUM ('QUEUED', 'SENT', 'FAILED');

-- CreateEnum
CREATE TYPE "CompliancePackJobStatus" AS ENUM ('RUNNING', 'COMPLETED', 'FAILED');

-- CreateTable
CREATE TABLE "AdminMfaCredential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "secretCiphertext" TEXT NOT NULL,
    "secretIv" TEXT NOT NULL,
    "secretTag" TEXT NOT NULL,
    "backupCodesHash" TEXT[],
    "isEnabled" BOOLEAN NOT NULL DEFAULT false,
    "verifiedAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AdminMfaCredential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthMfaChallenge" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "ticketHash" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "riskLevel" "AuthRiskLevel" NOT NULL DEFAULT 'LOW',
    "reasons" TEXT[],
    "createdIpHash" TEXT,
    "createdUserAgentHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "AuthMfaChallenge_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthSessionRiskSignal" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "riskLevel" "AuthRiskLevel" NOT NULL,
    "reasons" TEXT[],
    "ipHash" TEXT,
    "userAgentHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthSessionRiskSignal_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityEventOutbox" (
    "id" TEXT NOT NULL,
    "eventType" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "status" "SecurityEventDeliveryStatus" NOT NULL DEFAULT 'QUEUED',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "nextAttemptAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastError" TEXT,
    "sentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityEventOutbox_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CompliancePackJob" (
    "id" TEXT NOT NULL,
    "licenseeId" TEXT,
    "status" "CompliancePackJobStatus" NOT NULL DEFAULT 'RUNNING',
    "triggerType" TEXT NOT NULL,
    "periodFrom" TIMESTAMP(3),
    "periodTo" TIMESTAMP(3),
    "fileName" TEXT,
    "storageKey" TEXT,
    "integrityHash" TEXT,
    "signatureAlgorithm" TEXT,
    "summary" JSONB,
    "errorMessage" TEXT,
    "startedByUserId" TEXT,
    "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CompliancePackJob_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AdminMfaCredential_userId_key" ON "AdminMfaCredential"("userId");

-- CreateIndex
CREATE INDEX "AdminMfaCredential_isEnabled_idx" ON "AdminMfaCredential"("isEnabled");

-- CreateIndex
CREATE INDEX "AdminMfaCredential_verifiedAt_idx" ON "AdminMfaCredential"("verifiedAt");

-- CreateIndex
CREATE UNIQUE INDEX "AuthMfaChallenge_ticketHash_key" ON "AuthMfaChallenge"("ticketHash");

-- CreateIndex
CREATE INDEX "AuthMfaChallenge_userId_createdAt_idx" ON "AuthMfaChallenge"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "AuthMfaChallenge_expiresAt_idx" ON "AuthMfaChallenge"("expiresAt");

-- CreateIndex
CREATE INDEX "AuthMfaChallenge_consumedAt_idx" ON "AuthMfaChallenge"("consumedAt");

-- CreateIndex
CREATE INDEX "AuthSessionRiskSignal_userId_createdAt_idx" ON "AuthSessionRiskSignal"("userId", "createdAt");

-- CreateIndex
CREATE INDEX "AuthSessionRiskSignal_riskLevel_createdAt_idx" ON "AuthSessionRiskSignal"("riskLevel", "createdAt");

-- CreateIndex
CREATE INDEX "SecurityEventOutbox_status_nextAttemptAt_idx" ON "SecurityEventOutbox"("status", "nextAttemptAt");

-- CreateIndex
CREATE INDEX "SecurityEventOutbox_createdAt_idx" ON "SecurityEventOutbox"("createdAt");

-- CreateIndex
CREATE INDEX "CompliancePackJob_licenseeId_startedAt_idx" ON "CompliancePackJob"("licenseeId", "startedAt");

-- CreateIndex
CREATE INDEX "CompliancePackJob_status_startedAt_idx" ON "CompliancePackJob"("status", "startedAt");

-- CreateIndex
CREATE INDEX "CompliancePackJob_triggerType_startedAt_idx" ON "CompliancePackJob"("triggerType", "startedAt");

-- CreateIndex
CREATE INDEX "CompliancePackJob_startedByUserId_idx" ON "CompliancePackJob"("startedByUserId");

-- AddForeignKey
ALTER TABLE "AdminMfaCredential" ADD CONSTRAINT "AdminMfaCredential_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthMfaChallenge" ADD CONSTRAINT "AuthMfaChallenge_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthSessionRiskSignal" ADD CONSTRAINT "AuthSessionRiskSignal_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CompliancePackJob" ADD CONSTRAINT "CompliancePackJob_licenseeId_fkey" FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CompliancePackJob" ADD CONSTRAINT "CompliancePackJob_startedByUserId_fkey" FOREIGN KEY ("startedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

