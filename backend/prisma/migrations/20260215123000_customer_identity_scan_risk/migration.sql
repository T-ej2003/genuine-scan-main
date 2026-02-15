-- Create customer auth enums
CREATE TYPE "CustomerAuthProvider" AS ENUM ('GOOGLE', 'EMAIL_OTP');
CREATE TYPE "ScanRiskClassification" AS ENUM ('FIRST_SCAN', 'LEGIT_REPEAT', 'SUSPICIOUS_DUPLICATE');

-- Customer identity table (public/consumer side; separate from admin User)
CREATE TABLE "CustomerUser" (
  "id" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "name" TEXT,
  "provider" "CustomerAuthProvider" NOT NULL DEFAULT 'EMAIL_OTP',
  "providerId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "CustomerUser_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "CustomerUser_email_key" ON "CustomerUser"("email");
CREATE UNIQUE INDEX "CustomerUser_provider_providerId_key" ON "CustomerUser"("provider", "providerId");
CREATE INDEX "CustomerUser_createdAt_idx" ON "CustomerUser"("createdAt");

-- Email OTP login flow
CREATE TABLE "CustomerOtpCode" (
  "id" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "codeHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "customerUserId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "CustomerOtpCode_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "CustomerOtpCode_email_idx" ON "CustomerOtpCode"("email");
CREATE INDEX "CustomerOtpCode_expiresAt_idx" ON "CustomerOtpCode"("expiresAt");
CREATE INDEX "CustomerOtpCode_customerUserId_idx" ON "CustomerOtpCode"("customerUserId");
CREATE INDEX "CustomerOtpCode_createdAt_idx" ON "CustomerOtpCode"("createdAt");

ALTER TABLE "CustomerOtpCode"
  ADD CONSTRAINT "CustomerOtpCode_customerUserId_fkey"
  FOREIGN KEY ("customerUserId") REFERENCES "CustomerUser"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

-- Ownership claim records
CREATE TABLE "ProductOwnership" (
  "id" TEXT NOT NULL,
  "qrCodeId" TEXT NOT NULL,
  "customerUserId" TEXT NOT NULL,
  "claimedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ProductOwnership_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ProductOwnership_qrCodeId_key" ON "ProductOwnership"("qrCodeId");
CREATE INDEX "ProductOwnership_customerUserId_idx" ON "ProductOwnership"("customerUserId");
CREATE INDEX "ProductOwnership_claimedAt_idx" ON "ProductOwnership"("claimedAt");

ALTER TABLE "ProductOwnership"
  ADD CONSTRAINT "ProductOwnership_qrCodeId_fkey"
  FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ProductOwnership"
  ADD CONSTRAINT "ProductOwnership_customerUserId_fkey"
  FOREIGN KEY ("customerUserId") REFERENCES "CustomerUser"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

-- Structured fraud report records linked to incident workflow
CREATE TABLE "FraudReport" (
  "id" TEXT NOT NULL,
  "qrCodeId" TEXT,
  "qrCodeValue" TEXT NOT NULL,
  "customerUserId" TEXT,
  "anonVisitorId" TEXT,
  "reason" TEXT NOT NULL,
  "details" JSONB,
  "status" TEXT NOT NULL DEFAULT 'NEW',
  "incidentId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "FraudReport_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "FraudReport_qrCodeId_idx" ON "FraudReport"("qrCodeId");
CREATE INDEX "FraudReport_qrCodeValue_idx" ON "FraudReport"("qrCodeValue");
CREATE INDEX "FraudReport_customerUserId_idx" ON "FraudReport"("customerUserId");
CREATE INDEX "FraudReport_anonVisitorId_idx" ON "FraudReport"("anonVisitorId");
CREATE INDEX "FraudReport_status_idx" ON "FraudReport"("status");
CREATE INDEX "FraudReport_createdAt_idx" ON "FraudReport"("createdAt");

ALTER TABLE "FraudReport"
  ADD CONSTRAINT "FraudReport_qrCodeId_fkey"
  FOREIGN KEY ("qrCodeId") REFERENCES "QRCode"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "FraudReport"
  ADD CONSTRAINT "FraudReport_customerUserId_fkey"
  FOREIGN KEY ("customerUserId") REFERENCES "CustomerUser"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

-- Enrich scan log with customer identity + risk outputs
ALTER TABLE "QrScanLog"
  ADD COLUMN "customerUserId" TEXT,
  ADD COLUMN "anonVisitorId" TEXT,
  ADD COLUMN "visitorFingerprint" TEXT,
  ADD COLUMN "ipHash" TEXT,
  ADD COLUMN "riskClassification" "ScanRiskClassification",
  ADD COLUMN "riskReasons" JSONB;

CREATE INDEX "QrScanLog_customerUserId_idx" ON "QrScanLog"("customerUserId");
CREATE INDEX "QrScanLog_anonVisitorId_idx" ON "QrScanLog"("anonVisitorId");
CREATE INDEX "QrScanLog_riskClassification_idx" ON "QrScanLog"("riskClassification");

ALTER TABLE "QrScanLog"
  ADD CONSTRAINT "QrScanLog_customerUserId_fkey"
  FOREIGN KEY ("customerUserId") REFERENCES "CustomerUser"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
