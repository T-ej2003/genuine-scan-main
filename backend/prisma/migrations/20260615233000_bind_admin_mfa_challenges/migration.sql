ALTER TABLE "AuthMfaChallenge"
  ADD COLUMN "sessionBindingHash" TEXT,
  ADD COLUMN "purpose" TEXT NOT NULL DEFAULT 'admin_login',
  ADD COLUMN "attempts" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "maxAttempts" INTEGER NOT NULL DEFAULT 5,
  ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN "supersededAt" TIMESTAMP(3);

CREATE INDEX "AuthMfaChallenge_userId_purpose_sessionBindingHash_idx"
  ON "AuthMfaChallenge"("userId", "purpose", "sessionBindingHash");

CREATE INDEX "AuthMfaChallenge_supersededAt_idx"
  ON "AuthMfaChallenge"("supersededAt");
