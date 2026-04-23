CREATE TYPE "CustomerVerificationEntryMethod" AS ENUM ('SIGNED_SCAN', 'MANUAL_CODE');

CREATE TYPE "CustomerVerificationAuthState" AS ENUM ('PENDING', 'VERIFIED');

CREATE TABLE "CustomerVerificationSession" (
    "id" TEXT NOT NULL,
    "verificationDecisionId" TEXT NOT NULL,
    "qrCodeId" TEXT,
    "code" TEXT,
    "entryMethod" "CustomerVerificationEntryMethod" NOT NULL,
    "authState" "CustomerVerificationAuthState" NOT NULL DEFAULT 'PENDING',
    "customerUserId" TEXT,
    "customerEmail" TEXT,
    "intakeCompletedAt" TIMESTAMP(3),
    "revealedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CustomerVerificationSession_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "CustomerTrustIntake" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "customerUserId" TEXT,
    "customerEmail" TEXT,
    "purchaseChannel" TEXT NOT NULL,
    "sourceCategory" TEXT,
    "platformName" TEXT,
    "sellerName" TEXT,
    "listingUrl" TEXT,
    "orderReference" TEXT,
    "storeName" TEXT,
    "purchaseCity" TEXT,
    "purchaseCountry" TEXT,
    "purchaseDate" TIMESTAMP(3),
    "packagingState" TEXT,
    "packagingConcern" TEXT,
    "scanReason" TEXT NOT NULL,
    "ownershipIntent" TEXT NOT NULL,
    "notes" TEXT,
    "answers" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CustomerTrustIntake_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "CustomerTrustIntake_sessionId_key" ON "CustomerTrustIntake"("sessionId");

CREATE INDEX "CustomerVerificationSession_verificationDecisionId_createdAt_idx" ON "CustomerVerificationSession"("verificationDecisionId", "createdAt");
CREATE INDEX "CustomerVerificationSession_qrCodeId_createdAt_idx" ON "CustomerVerificationSession"("qrCodeId", "createdAt");
CREATE INDEX "CustomerVerificationSession_customerUserId_createdAt_idx" ON "CustomerVerificationSession"("customerUserId", "createdAt");
CREATE INDEX "CustomerVerificationSession_authState_createdAt_idx" ON "CustomerVerificationSession"("authState", "createdAt");
CREATE INDEX "CustomerVerificationSession_revealedAt_idx" ON "CustomerVerificationSession"("revealedAt");
CREATE INDEX "CustomerTrustIntake_customerUserId_createdAt_idx" ON "CustomerTrustIntake"("customerUserId", "createdAt");
CREATE INDEX "CustomerTrustIntake_purchaseChannel_createdAt_idx" ON "CustomerTrustIntake"("purchaseChannel", "createdAt");

ALTER TABLE "CustomerVerificationSession"
ADD CONSTRAINT "CustomerVerificationSession_verificationDecisionId_fkey"
FOREIGN KEY ("verificationDecisionId") REFERENCES "VerificationDecision"("id")
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "CustomerTrustIntake"
ADD CONSTRAINT "CustomerTrustIntake_sessionId_fkey"
FOREIGN KEY ("sessionId") REFERENCES "CustomerVerificationSession"("id")
ON DELETE CASCADE ON UPDATE CASCADE;
