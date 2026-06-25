CREATE TABLE IF NOT EXISTS "PrinterAgentSession" (
  "id" TEXT NOT NULL,
  "connectionId" TEXT NOT NULL,
  "registrationId" TEXT NOT NULL,
  "printerProfileId" TEXT,
  "agentId" TEXT NOT NULL,
  "deviceFingerprint" TEXT NOT NULL,
  "publicKeyFingerprint" TEXT NOT NULL,
  "selectedPrinterId" TEXT NOT NULL,
  "selectedPrinterName" TEXT,
  "connectionState" TEXT NOT NULL DEFAULT 'CONNECTED',
  "trustMode" TEXT NOT NULL DEFAULT 'SIGNED_ATTESTATION',
  "connectorVersion" TEXT,
  "printerHealth" JSONB,
  "activePrintJobId" TEXT,
  "connectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "disconnectedAt" TIMESTAMP(3),
  "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "lastSignedHeartbeatAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMP(3),
  "revokedAt" TIMESTAMP(3),
  "closeReason" TEXT,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "PrinterAgentSession_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "PrintJobChunk" (
  "id" TEXT NOT NULL,
  "printJobId" TEXT NOT NULL,
  "printSessionId" TEXT NOT NULL,
  "agentSessionId" TEXT,
  "registrationId" TEXT NOT NULL,
  "printerId" TEXT,
  "idempotencyKey" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'CREATED',
  "startSequence" INTEGER NOT NULL,
  "endSequence" INTEGER NOT NULL,
  "itemCount" INTEGER NOT NULL,
  "acknowledgedCount" INTEGER NOT NULL DEFAULT 0,
  "confirmedCount" INTEGER NOT NULL DEFAULT 0,
  "failedCount" INTEGER NOT NULL DEFAULT 0,
  "itemIds" JSONB NOT NULL,
  "rangeStartCode" TEXT,
  "rangeEndCode" TEXT,
  "assignedAt" TIMESTAMP(3),
  "sentAt" TIMESTAMP(3),
  "acknowledgedAt" TIMESTAMP(3),
  "confirmedAt" TIMESTAMP(3),
  "failedAt" TIMESTAMP(3),
  "failureReason" TEXT,
  "lastMessageSeq" INTEGER NOT NULL DEFAULT 0,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "PrintJobChunk_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "PrinterAgentSession_connectionId_key"
  ON "PrinterAgentSession"("connectionId");
CREATE INDEX IF NOT EXISTS "PrinterAgentSession_registrationId_connectionState_lastSeen_idx"
  ON "PrinterAgentSession"("registrationId", "connectionState", "lastSeenAt");
CREATE INDEX IF NOT EXISTS "PrinterAgentSession_agentId_deviceFingerprint_idx"
  ON "PrinterAgentSession"("agentId", "deviceFingerprint");
CREATE INDEX IF NOT EXISTS "PrinterAgentSession_selectedPrinterId_connectionState_idx"
  ON "PrinterAgentSession"("selectedPrinterId", "connectionState");
CREATE INDEX IF NOT EXISTS "PrinterAgentSession_activePrintJobId_idx"
  ON "PrinterAgentSession"("activePrintJobId");
CREATE INDEX IF NOT EXISTS "PrinterAgentSession_expiresAt_idx"
  ON "PrinterAgentSession"("expiresAt");

CREATE UNIQUE INDEX IF NOT EXISTS "PrintJobChunk_idempotencyKey_key"
  ON "PrintJobChunk"("idempotencyKey");
CREATE INDEX IF NOT EXISTS "PrintJobChunk_printJobId_status_createdAt_idx"
  ON "PrintJobChunk"("printJobId", "status", "createdAt");
CREATE INDEX IF NOT EXISTS "PrintJobChunk_printSessionId_status_startSequence_idx"
  ON "PrintJobChunk"("printSessionId", "status", "startSequence");
CREATE INDEX IF NOT EXISTS "PrintJobChunk_agentSessionId_status_idx"
  ON "PrintJobChunk"("agentSessionId", "status");
CREATE INDEX IF NOT EXISTS "PrintJobChunk_registrationId_status_createdAt_idx"
  ON "PrintJobChunk"("registrationId", "status", "createdAt");

ALTER TABLE "PrinterAgentSession"
  ADD CONSTRAINT "PrinterAgentSession_registrationId_fkey"
  FOREIGN KEY ("registrationId") REFERENCES "PrinterRegistration"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PrintJobChunk"
  ADD CONSTRAINT "PrintJobChunk_printJobId_fkey"
  FOREIGN KEY ("printJobId") REFERENCES "PrintJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PrintJobChunk"
  ADD CONSTRAINT "PrintJobChunk_printSessionId_fkey"
  FOREIGN KEY ("printSessionId") REFERENCES "PrintSession"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "PrintJobChunk"
  ADD CONSTRAINT "PrintJobChunk_agentSessionId_fkey"
  FOREIGN KEY ("agentSessionId") REFERENCES "PrinterAgentSession"("id") ON DELETE SET NULL ON UPDATE CASCADE;
