CREATE TABLE "InviteActivationChallenge" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "inviteId" TEXT NOT NULL,
  "email" TEXT NOT NULL,
  "purpose" TEXT NOT NULL DEFAULT 'INVITE_ACTIVATION',
  "codeVerifier" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "attemptCount" INTEGER NOT NULL DEFAULT 0,
  "maxAttempts" INTEGER NOT NULL DEFAULT 5,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "consumedAt" TIMESTAMP(3),
  "supersededAt" TIMESTAMP(3),
  CONSTRAINT "InviteActivationChallenge_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "InviteActivationChallenge_purpose_check" CHECK ("purpose" = 'INVITE_ACTIVATION'),
  CONSTRAINT "InviteActivationChallenge_attempts_check" CHECK ("attemptCount" BETWEEN 0 AND 5 AND "maxAttempts" = 5),
  CONSTRAINT "InviteActivationChallenge_verifier_check" CHECK ("codeVerifier" ~ '^[0-9a-f]{12}:[0-9a-f]{64}$'),
  CONSTRAINT "InviteActivationChallenge_email_check" CHECK ("email" = lower(btrim("email")))
);

CREATE INDEX "InviteActivationChallenge_userId_createdAt_idx" ON "InviteActivationChallenge"("userId", "createdAt");
CREATE INDEX "InviteActivationChallenge_inviteId_createdAt_idx" ON "InviteActivationChallenge"("inviteId", "createdAt");
CREATE INDEX "InviteActivationChallenge_expiresAt_idx" ON "InviteActivationChallenge"("expiresAt");
CREATE UNIQUE INDEX "InviteActivationChallenge_one_live_invite_idx" ON "InviteActivationChallenge"("inviteId")
  WHERE "consumedAt" IS NULL AND "supersededAt" IS NULL;

ALTER TABLE "InviteActivationChallenge"
  ADD CONSTRAINT "InviteActivationChallenge_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT "InviteActivationChallenge_inviteId_fkey" FOREIGN KEY ("inviteId") REFERENCES "Invite"("id") ON DELETE CASCADE ON UPDATE CASCADE;
