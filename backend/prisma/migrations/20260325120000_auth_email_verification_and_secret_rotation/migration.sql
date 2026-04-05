ALTER TABLE "User"
ADD COLUMN "pendingEmail" TEXT,
ADD COLUMN "emailVerifiedAt" TIMESTAMP(3),
ADD COLUMN "pendingEmailRequestedAt" TIMESTAMP(3);

CREATE UNIQUE INDEX "User_pendingEmail_key" ON "User"("pendingEmail");
CREATE INDEX "User_emailVerifiedAt_idx" ON "User"("emailVerifiedAt");

CREATE TABLE "EmailVerificationToken" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "pendingEmail" TEXT,
  "purpose" TEXT NOT NULL,
  "tokenHash" TEXT NOT NULL,
  "secretVersion" TEXT,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "usedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "createdIpHash" TEXT,
  "userAgentHash" TEXT,

  CONSTRAINT "EmailVerificationToken_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "EmailVerificationToken_tokenHash_key" ON "EmailVerificationToken"("tokenHash");
CREATE INDEX "EmailVerificationToken_userId_idx" ON "EmailVerificationToken"("userId");
CREATE INDEX "EmailVerificationToken_email_idx" ON "EmailVerificationToken"("email");
CREATE INDEX "EmailVerificationToken_pendingEmail_idx" ON "EmailVerificationToken"("pendingEmail");
CREATE INDEX "EmailVerificationToken_purpose_idx" ON "EmailVerificationToken"("purpose");
CREATE INDEX "EmailVerificationToken_expiresAt_idx" ON "EmailVerificationToken"("expiresAt");
CREATE INDEX "EmailVerificationToken_usedAt_idx" ON "EmailVerificationToken"("usedAt");

ALTER TABLE "EmailVerificationToken"
ADD CONSTRAINT "EmailVerificationToken_userId_fkey"
FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

UPDATE "User"
SET "emailVerifiedAt" = COALESCE("emailVerifiedAt", NOW())
WHERE "isActive" = TRUE
  AND "deletedAt" IS NULL
  AND "status" = 'ACTIVE'
  AND "email" IS NOT NULL;
