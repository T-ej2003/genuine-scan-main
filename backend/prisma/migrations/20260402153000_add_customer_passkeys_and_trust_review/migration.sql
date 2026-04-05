ALTER TYPE "CustomerTrustLevel" ADD VALUE IF NOT EXISTS 'PASSKEY_VERIFIED';

CREATE TYPE "CustomerTrustReviewState" AS ENUM ('UNREVIEWED', 'VERIFIED', 'DISPUTED', 'REVOKED');

ALTER TABLE "CustomerTrustCredential"
ADD COLUMN "reviewState" "CustomerTrustReviewState" NOT NULL DEFAULT 'UNREVIEWED',
ADD COLUMN "reviewNote" TEXT,
ADD COLUMN "reviewedByUserId" TEXT,
ADD COLUMN "reviewedAt" TIMESTAMP(3),
ADD COLUMN "revokedAt" TIMESTAMP(3),
ADD COLUMN "revokedReason" TEXT,
ADD COLUMN "lastAssertionAt" TIMESTAMP(3);

CREATE TABLE "CustomerWebAuthnCredential" (
    "id" TEXT NOT NULL,
    "customerUserId" TEXT NOT NULL,
    "customerEmail" TEXT,
    "label" TEXT,
    "credentialId" TEXT NOT NULL,
    "publicKeySpki" TEXT NOT NULL,
    "publicKeyAlgorithm" INTEGER NOT NULL,
    "counter" INTEGER NOT NULL DEFAULT 0,
    "transports" TEXT[],
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CustomerWebAuthnCredential_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "CustomerWebAuthnChallenge" (
    "id" TEXT NOT NULL,
    "customerUserId" TEXT NOT NULL,
    "customerEmail" TEXT,
    "purpose" TEXT NOT NULL,
    "ticketHash" TEXT NOT NULL,
    "challengeHash" TEXT NOT NULL,
    "credentialIds" TEXT[],
    "createdIpHash" TEXT,
    "createdUserAgentHash" TEXT,
    "origin" TEXT,
    "rpId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "consumedAt" TIMESTAMP(3),

    CONSTRAINT "CustomerWebAuthnChallenge_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "CustomerWebAuthnCredential_credentialId_key" ON "CustomerWebAuthnCredential"("credentialId");
CREATE UNIQUE INDEX "CustomerWebAuthnChallenge_ticketHash_key" ON "CustomerWebAuthnChallenge"("ticketHash");

CREATE INDEX "CustomerTrustCredential_qrCodeId_reviewState_updatedAt_idx" ON "CustomerTrustCredential"("qrCodeId", "reviewState", "updatedAt");
CREATE INDEX "CustomerWebAuthnCredential_customerUserId_createdAt_idx" ON "CustomerWebAuthnCredential"("customerUserId", "createdAt");
CREATE INDEX "CustomerWebAuthnCredential_lastUsedAt_idx" ON "CustomerWebAuthnCredential"("lastUsedAt");
CREATE INDEX "CustomerWebAuthnChallenge_customerUserId_purpose_createdAt_idx" ON "CustomerWebAuthnChallenge"("customerUserId", "purpose", "createdAt");
CREATE INDEX "CustomerWebAuthnChallenge_expiresAt_idx" ON "CustomerWebAuthnChallenge"("expiresAt");
CREATE INDEX "CustomerWebAuthnChallenge_consumedAt_idx" ON "CustomerWebAuthnChallenge"("consumedAt");
