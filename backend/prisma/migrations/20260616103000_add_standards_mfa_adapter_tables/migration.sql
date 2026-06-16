CREATE TABLE "UserMfaFactor" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "type" TEXT NOT NULL,
  "label" TEXT,
  "credentialId" TEXT,
  "publicKey" TEXT,
  "counter" INTEGER NOT NULL DEFAULT 0,
  "transports" TEXT[],
  "credentialDeviceType" TEXT,
  "credentialBackedUp" BOOLEAN,
  "secretCiphertext" TEXT,
  "secretIv" TEXT,
  "secretTag" TEXT,
  "legacySource" TEXT,
  "legacyCredentialId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "lastUsedAt" TIMESTAMP(3),
  "disabledAt" TIMESTAMP(3),

  CONSTRAINT "UserMfaFactor_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "UserBackupCode" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "codeHash" TEXT NOT NULL,
  "usedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "UserBackupCode_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "MfaLoginChallenge" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "ticketHash" TEXT NOT NULL,
  "purpose" TEXT NOT NULL DEFAULT 'admin_login',
  "riskScore" INTEGER NOT NULL DEFAULT 0,
  "riskLevel" "AuthRiskLevel" NOT NULL DEFAULT 'LOW',
  "reasons" TEXT[],
  "createdIpHash" TEXT,
  "createdUserAgentHash" TEXT,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "maxAttempts" INTEGER NOT NULL DEFAULT 5,
  "retryAfterSeconds" INTEGER,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),

  CONSTRAINT "MfaLoginChallenge_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "UserMfaFactor_credentialId_key" ON "UserMfaFactor"("credentialId");
CREATE INDEX "UserMfaFactor_userId_type_disabledAt_idx" ON "UserMfaFactor"("userId", "type", "disabledAt");
CREATE INDEX "UserMfaFactor_lastUsedAt_idx" ON "UserMfaFactor"("lastUsedAt");
CREATE INDEX "UserMfaFactor_legacySource_legacyCredentialId_idx" ON "UserMfaFactor"("legacySource", "legacyCredentialId");

CREATE UNIQUE INDEX "UserBackupCode_codeHash_key" ON "UserBackupCode"("codeHash");
CREATE INDEX "UserBackupCode_userId_usedAt_idx" ON "UserBackupCode"("userId", "usedAt");

CREATE UNIQUE INDEX "MfaLoginChallenge_ticketHash_key" ON "MfaLoginChallenge"("ticketHash");
CREATE INDEX "MfaLoginChallenge_userId_purpose_createdAt_idx" ON "MfaLoginChallenge"("userId", "purpose", "createdAt");
CREATE INDEX "MfaLoginChallenge_expiresAt_idx" ON "MfaLoginChallenge"("expiresAt");
CREATE INDEX "MfaLoginChallenge_consumedAt_idx" ON "MfaLoginChallenge"("consumedAt");

ALTER TABLE "UserMfaFactor" ADD CONSTRAINT "UserMfaFactor_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "UserBackupCode" ADD CONSTRAINT "UserBackupCode_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "MfaLoginChallenge" ADD CONSTRAINT "MfaLoginChallenge_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
