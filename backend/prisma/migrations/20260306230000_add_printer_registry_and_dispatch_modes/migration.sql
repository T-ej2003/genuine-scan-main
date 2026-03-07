-- Add enum values required by the unified print dispatcher.
ALTER TYPE "PrintJobStatus" ADD VALUE IF NOT EXISTS 'SENT';
ALTER TYPE "PrintJobStatus" ADD VALUE IF NOT EXISTS 'FAILED';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrinterConnectionType') THEN
    CREATE TYPE "PrinterConnectionType" AS ENUM ('LOCAL_AGENT', 'NETWORK_DIRECT');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrinterCommandLanguage') THEN
    CREATE TYPE "PrinterCommandLanguage" AS ENUM ('AUTO', 'ZPL', 'TSPL', 'SBPL', 'EPL', 'CPCL', 'ESC_POS', 'OTHER');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrintDispatchMode') THEN
    CREATE TYPE "PrintDispatchMode" AS ENUM ('LOCAL_AGENT', 'NETWORK_DIRECT');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrintPayloadType') THEN
    CREATE TYPE "PrintPayloadType" AS ENUM ('ZPL', 'TSPL', 'SBPL', 'EPL', 'CPCL', 'ESC_POS', 'JSON', 'OTHER');
  END IF;
END $$;

ALTER TABLE "PrintJob"
  ADD COLUMN IF NOT EXISTS "jobNumber" TEXT,
  ADD COLUMN IF NOT EXISTS "printerId" TEXT,
  ADD COLUMN IF NOT EXISTS "printMode" "PrintDispatchMode" NOT NULL DEFAULT 'LOCAL_AGENT',
  ADD COLUMN IF NOT EXISTS "payloadType" "PrintPayloadType",
  ADD COLUMN IF NOT EXISTS "payloadHash" TEXT,
  ADD COLUMN IF NOT EXISTS "itemCount" INTEGER,
  ADD COLUMN IF NOT EXISTS "sentAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "completedAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "failureReason" TEXT,
  ADD COLUMN IF NOT EXISTS "reprintOfJobId" TEXT,
  ADD COLUMN IF NOT EXISTS "approvedByUserId" TEXT,
  ADD COLUMN IF NOT EXISTS "reprintReason" TEXT,
  ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "PrintSession"
  ADD COLUMN IF NOT EXISTS "printerId" TEXT;

CREATE TABLE IF NOT EXISTS "Printer" (
  "id" TEXT NOT NULL,
  "name" TEXT NOT NULL,
  "vendor" TEXT,
  "model" TEXT,
  "connectionType" "PrinterConnectionType" NOT NULL,
  "commandLanguage" "PrinterCommandLanguage" NOT NULL DEFAULT 'AUTO',
  "ipAddress" TEXT,
  "port" INTEGER,
  "nativePrinterId" TEXT,
  "agentId" TEXT,
  "deviceFingerprint" TEXT,
  "printerRegistrationId" TEXT,
  "orgId" TEXT,
  "licenseeId" TEXT,
  "assignedUserId" TEXT,
  "createdByUserId" TEXT,
  "isActive" BOOLEAN NOT NULL DEFAULT true,
  "isDefault" BOOLEAN NOT NULL DEFAULT false,
  "lastSeenAt" TIMESTAMP(3),
  "lastValidatedAt" TIMESTAMP(3),
  "lastValidationStatus" TEXT,
  "lastValidationMessage" TEXT,
  "capabilitySummary" JSONB,
  "calibrationProfile" JSONB,
  "metadata" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Printer_pkey" PRIMARY KEY ("id")
);

UPDATE "PrintJob"
SET
  "jobNumber" = COALESCE("jobNumber", CONCAT('PJ-', UPPER(SUBSTRING(REPLACE("id", '-', ''), 1, 12)))),
  "itemCount" = COALESCE("itemCount", "quantity"),
  "sentAt" = COALESCE("sentAt", CASE WHEN "status"::text IN ('SENT', 'CONFIRMED', 'FAILED', 'CANCELLED') THEN "createdAt" ELSE NULL END),
  "completedAt" = COALESCE("completedAt", CASE WHEN "status"::text = 'CONFIRMED' THEN COALESCE("confirmedAt", "createdAt") ELSE NULL END),
  "updatedAt" = COALESCE("updatedAt", "createdAt");

CREATE UNIQUE INDEX IF NOT EXISTS "PrintJob_jobNumber_key" ON "PrintJob"("jobNumber");
CREATE INDEX IF NOT EXISTS "PrintJob_printerId_idx" ON "PrintJob"("printerId");
CREATE INDEX IF NOT EXISTS "PrintJob_printMode_status_idx" ON "PrintJob"("printMode", "status");
CREATE INDEX IF NOT EXISTS "PrintJob_reprintOfJobId_idx" ON "PrintJob"("reprintOfJobId");

CREATE INDEX IF NOT EXISTS "PrintSession_printerId_idx" ON "PrintSession"("printerId");

CREATE UNIQUE INDEX IF NOT EXISTS "Printer_printerRegistrationId_nativePrinterId_key"
  ON "Printer"("printerRegistrationId", "nativePrinterId");
CREATE UNIQUE INDEX IF NOT EXISTS "Printer_licenseeId_ipAddress_port_key"
  ON "Printer"("licenseeId", "ipAddress", "port");
CREATE INDEX IF NOT EXISTS "Printer_connectionType_isActive_idx" ON "Printer"("connectionType", "isActive");
CREATE INDEX IF NOT EXISTS "Printer_orgId_isActive_idx" ON "Printer"("orgId", "isActive");
CREATE INDEX IF NOT EXISTS "Printer_licenseeId_isActive_idx" ON "Printer"("licenseeId", "isActive");
CREATE INDEX IF NOT EXISTS "Printer_assignedUserId_isActive_idx" ON "Printer"("assignedUserId", "isActive");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintJob_printerId_fkey'
  ) THEN
    ALTER TABLE "PrintJob"
      ADD CONSTRAINT "PrintJob_printerId_fkey"
      FOREIGN KEY ("printerId") REFERENCES "Printer"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintJob_reprintOfJobId_fkey'
  ) THEN
    ALTER TABLE "PrintJob"
      ADD CONSTRAINT "PrintJob_reprintOfJobId_fkey"
      FOREIGN KEY ("reprintOfJobId") REFERENCES "PrintJob"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintJob_approvedByUserId_fkey'
  ) THEN
    ALTER TABLE "PrintJob"
      ADD CONSTRAINT "PrintJob_approvedByUserId_fkey"
      FOREIGN KEY ("approvedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintSession_printerId_fkey'
  ) THEN
    ALTER TABLE "PrintSession"
      ADD CONSTRAINT "PrintSession_printerId_fkey"
      FOREIGN KEY ("printerId") REFERENCES "Printer"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Printer_printerRegistrationId_fkey'
  ) THEN
    ALTER TABLE "Printer"
      ADD CONSTRAINT "Printer_printerRegistrationId_fkey"
      FOREIGN KEY ("printerRegistrationId") REFERENCES "PrinterRegistration"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Printer_orgId_fkey'
  ) THEN
    ALTER TABLE "Printer"
      ADD CONSTRAINT "Printer_orgId_fkey"
      FOREIGN KEY ("orgId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Printer_licenseeId_fkey'
  ) THEN
    ALTER TABLE "Printer"
      ADD CONSTRAINT "Printer_licenseeId_fkey"
      FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Printer_assignedUserId_fkey'
  ) THEN
    ALTER TABLE "Printer"
      ADD CONSTRAINT "Printer_assignedUserId_fkey"
      FOREIGN KEY ("assignedUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'Printer_createdByUserId_fkey'
  ) THEN
    ALTER TABLE "Printer"
      ADD CONSTRAINT "Printer_createdByUserId_fkey"
      FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;
