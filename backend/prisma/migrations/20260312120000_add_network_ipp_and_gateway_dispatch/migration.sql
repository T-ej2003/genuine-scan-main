DO $$
BEGIN
  ALTER TYPE "PrinterConnectionType" ADD VALUE IF NOT EXISTS 'NETWORK_IPP';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER TYPE "PrintDispatchMode" ADD VALUE IF NOT EXISTS 'NETWORK_IPP';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  ALTER TYPE "PrintPayloadType" ADD VALUE IF NOT EXISTS 'PDF';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE TYPE "PrinterDeliveryMode" AS ENUM ('DIRECT', 'SITE_GATEWAY');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE "Printer"
  ADD COLUMN IF NOT EXISTS "host" TEXT,
  ADD COLUMN IF NOT EXISTS "resourcePath" TEXT,
  ADD COLUMN IF NOT EXISTS "tlsEnabled" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS "printerUri" TEXT,
  ADD COLUMN IF NOT EXISTS "deliveryMode" "PrinterDeliveryMode" NOT NULL DEFAULT 'DIRECT',
  ADD COLUMN IF NOT EXISTS "gatewayId" TEXT,
  ADD COLUMN IF NOT EXISTS "gatewaySecretHash" TEXT,
  ADD COLUMN IF NOT EXISTS "gatewayLastSeenAt" TIMESTAMP(3),
  ADD COLUMN IF NOT EXISTS "gatewayStatus" TEXT,
  ADD COLUMN IF NOT EXISTS "gatewayLastError" TEXT;

CREATE INDEX IF NOT EXISTS "Printer_connectionType_deliveryMode_isActive_idx"
  ON "Printer"("connectionType", "deliveryMode", "isActive");

CREATE INDEX IF NOT EXISTS "Printer_licenseeId_host_port_idx"
  ON "Printer"("licenseeId", "host", "port");

CREATE INDEX IF NOT EXISTS "Printer_gatewayId_isActive_idx"
  ON "Printer"("gatewayId", "isActive");
