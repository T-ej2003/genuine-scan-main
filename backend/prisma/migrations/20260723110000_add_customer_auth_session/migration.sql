CREATE TABLE "CustomerAuthSession" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "customerUserId" TEXT NOT NULL,
    "customerEmail" TEXT NOT NULL,
    "authStrength" TEXT NOT NULL,
    "authProvider" TEXT,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CustomerAuthSession_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "CustomerAuthSession_tokenHash_key" ON "CustomerAuthSession"("tokenHash");
CREATE INDEX "CustomerAuthSession_customerUserId_expiresAt_idx" ON "CustomerAuthSession"("customerUserId", "expiresAt");
CREATE INDEX "CustomerAuthSession_expiresAt_idx" ON "CustomerAuthSession"("expiresAt");
CREATE INDEX "CustomerAuthSession_revokedAt_idx" ON "CustomerAuthSession"("revokedAt");
CREATE INDEX "VerificationEvidenceSnapshot_publicSessionStart_tokenHash_idx"
    ON "VerificationEvidenceSnapshot" ((metadata #>> '{publicSessionStart,tokenHash}'))
    WHERE (metadata #>> '{publicSessionStart,tokenHash}') IS NOT NULL;
