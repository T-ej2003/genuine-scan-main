DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrinterTransportKind') THEN
    CREATE TYPE "PrinterTransportKind" AS ENUM ('RAW_TCP', 'USB_RAW', 'SERIAL_RAW', 'DRIVER_QUEUE', 'SITE_GATEWAY', 'VENDOR_SDK', 'WEB_API');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrinterLanguageKind') THEN
    CREATE TYPE "PrinterLanguageKind" AS ENUM ('AUTO', 'ZPL', 'EPL', 'TSPL', 'DPL', 'SBPL', 'HONEYWELL_DP', 'HONEYWELL_FINGERPRINT', 'IPL', 'ZSIM', 'PDF', 'OTHER');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrinterProfileStatus') THEN
    CREATE TYPE "PrinterProfileStatus" AS ENUM ('DRAFT', 'CERTIFIED', 'NEEDS_REVIEW', 'BLOCKED');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrinterProfileSnapshotType') THEN
    CREATE TYPE "PrinterProfileSnapshotType" AS ENUM ('ONBOARDING', 'LIVE_DISCOVERY', 'CERTIFICATION_TEST');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'PrintPipelineState') THEN
    CREATE TYPE "PrintPipelineState" AS ENUM ('QUEUED', 'PREFLIGHT_OK', 'SENT_TO_PRINTER', 'PRINTER_ACKNOWLEDGED', 'PRINT_CONFIRMED', 'LOCKED', 'FAILED', 'NEEDS_OPERATOR_ACTION');
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'ReissueRequestStatus') THEN
    CREATE TYPE "ReissueRequestStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'EXECUTED', 'CANCELLED');
  END IF;
END $$;

ALTER TYPE "PrinterCommandLanguage" ADD VALUE IF NOT EXISTS 'DPL';
ALTER TYPE "PrinterCommandLanguage" ADD VALUE IF NOT EXISTS 'HONEYWELL_DP';
ALTER TYPE "PrinterCommandLanguage" ADD VALUE IF NOT EXISTS 'HONEYWELL_FINGERPRINT';
ALTER TYPE "PrinterCommandLanguage" ADD VALUE IF NOT EXISTS 'IPL';
ALTER TYPE "PrinterCommandLanguage" ADD VALUE IF NOT EXISTS 'ZSIM';

ALTER TYPE "PrintPayloadType" ADD VALUE IF NOT EXISTS 'DPL';
ALTER TYPE "PrintPayloadType" ADD VALUE IF NOT EXISTS 'HONEYWELL_DP';
ALTER TYPE "PrintPayloadType" ADD VALUE IF NOT EXISTS 'HONEYWELL_FINGERPRINT';
ALTER TYPE "PrintPayloadType" ADD VALUE IF NOT EXISTS 'IPL';

ALTER TABLE "PrintJob"
  ADD COLUMN IF NOT EXISTS "pipelineState" "PrintPipelineState" NOT NULL DEFAULT 'QUEUED';

ALTER TABLE "PrintItem"
  ADD COLUMN IF NOT EXISTS "pipelineState" "PrintPipelineState" NOT NULL DEFAULT 'QUEUED';

CREATE TABLE IF NOT EXISTS "PrinterProfileSnapshot" (
  "id" TEXT NOT NULL,
  "printerProfileId" TEXT NOT NULL,
  "snapshotType" "PrinterProfileSnapshotType" NOT NULL,
  "summary" TEXT,
  "warnings" JSONB,
  "data" JSONB NOT NULL,
  "capturedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "PrinterProfileSnapshot_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "PrinterProfile" (
  "id" TEXT NOT NULL,
  "printerId" TEXT NOT NULL,
  "status" "PrinterProfileStatus" NOT NULL DEFAULT 'NEEDS_REVIEW',
  "transportKind" "PrinterTransportKind" NOT NULL,
  "activeLanguage" "PrinterLanguageKind" NOT NULL DEFAULT 'AUTO',
  "nativeLanguage" TEXT NOT NULL,
  "supportedLanguages" JSONB NOT NULL,
  "emulationMode" TEXT,
  "languageVersion" TEXT,
  "jobMode" TEXT NOT NULL,
  "spoolFormat" TEXT,
  "preferredTransport" TEXT,
  "connectionTypes" JSONB,
  "brand" TEXT,
  "modelName" TEXT,
  "modelFamily" TEXT,
  "firmwareVersion" TEXT,
  "serialNumber" TEXT,
  "dpi" INTEGER,
  "statusConfig" JSONB,
  "mediaConstraints" JSONB,
  "installedOptions" JSONB,
  "renderingCapabilities" JSONB,
  "securityPosture" JSONB,
  "latestSeenCapabilities" JSONB,
  "notes" TEXT,
  "lastVerifiedAt" TIMESTAMP(3),
  "lastCertifiedAt" TIMESTAMP(3),
  "onboardingSnapshotId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "PrinterProfile_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "PrinterProfile_printerId_key" ON "PrinterProfile"("printerId");
CREATE INDEX IF NOT EXISTS "PrinterProfile_status_activeLanguage_idx" ON "PrinterProfile"("status", "activeLanguage");
CREATE INDEX IF NOT EXISTS "PrinterProfile_transportKind_status_idx" ON "PrinterProfile"("transportKind", "status");
CREATE INDEX IF NOT EXISTS "PrinterProfile_modelFamily_idx" ON "PrinterProfile"("modelFamily");

CREATE INDEX IF NOT EXISTS "PrinterProfileSnapshot_printerProfileId_snapshotType_capturedAt_idx"
  ON "PrinterProfileSnapshot"("printerProfileId", "snapshotType", "capturedAt");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrinterProfile_printerId_fkey'
  ) THEN
    ALTER TABLE "PrinterProfile"
      ADD CONSTRAINT "PrinterProfile_printerId_fkey"
      FOREIGN KEY ("printerId") REFERENCES "Printer"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrinterProfile_onboardingSnapshotId_fkey'
  ) THEN
    ALTER TABLE "PrinterProfile"
      ADD CONSTRAINT "PrinterProfile_onboardingSnapshotId_fkey"
      FOREIGN KEY ("onboardingSnapshotId") REFERENCES "PrinterProfileSnapshot"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrinterProfileSnapshot_printerProfileId_fkey'
  ) THEN
    ALTER TABLE "PrinterProfileSnapshot"
      ADD CONSTRAINT "PrinterProfileSnapshot_printerProfileId_fkey"
      FOREIGN KEY ("printerProfileId") REFERENCES "PrinterProfile"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS "PrintReissueRequest" (
  "id" TEXT NOT NULL,
  "originalPrintJobId" TEXT NOT NULL,
  "replacementPrintJobId" TEXT,
  "requestedByUserId" TEXT NOT NULL,
  "approvedByUserId" TEXT,
  "status" "ReissueRequestStatus" NOT NULL DEFAULT 'PENDING',
  "reason" TEXT NOT NULL,
  "rejectionReason" TEXT,
  "approvedAt" TIMESTAMP(3),
  "rejectedAt" TIMESTAMP(3),
  "executedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "PrintReissueRequest_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "PrintReissueRequest_replacementPrintJobId_key" ON "PrintReissueRequest"("replacementPrintJobId");
CREATE INDEX IF NOT EXISTS "PrintReissueRequest_originalPrintJobId_status_createdAt_idx"
  ON "PrintReissueRequest"("originalPrintJobId", "status", "createdAt");
CREATE INDEX IF NOT EXISTS "PrintReissueRequest_requestedByUserId_createdAt_idx"
  ON "PrintReissueRequest"("requestedByUserId", "createdAt");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintReissueRequest_originalPrintJobId_fkey'
  ) THEN
    ALTER TABLE "PrintReissueRequest"
      ADD CONSTRAINT "PrintReissueRequest_originalPrintJobId_fkey"
      FOREIGN KEY ("originalPrintJobId") REFERENCES "PrintJob"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintReissueRequest_replacementPrintJobId_fkey'
  ) THEN
    ALTER TABLE "PrintReissueRequest"
      ADD CONSTRAINT "PrintReissueRequest_replacementPrintJobId_fkey"
      FOREIGN KEY ("replacementPrintJobId") REFERENCES "PrintJob"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintReissueRequest_requestedByUserId_fkey'
  ) THEN
    ALTER TABLE "PrintReissueRequest"
      ADD CONSTRAINT "PrintReissueRequest_requestedByUserId_fkey"
      FOREIGN KEY ("requestedByUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'PrintReissueRequest_approvedByUserId_fkey'
  ) THEN
    ALTER TABLE "PrintReissueRequest"
      ADD CONSTRAINT "PrintReissueRequest_approvedByUserId_fkey"
      FOREIGN KEY ("approvedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;
