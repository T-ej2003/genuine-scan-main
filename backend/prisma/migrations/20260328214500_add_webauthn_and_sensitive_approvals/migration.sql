CREATE TABLE IF NOT EXISTS "AdminWebAuthnCredential" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "label" TEXT,
  "credentialId" TEXT NOT NULL,
  "publicKeySpki" TEXT NOT NULL,
  "publicKeyAlgorithm" INTEGER NOT NULL,
  "counter" INTEGER NOT NULL DEFAULT 0,
  "transports" TEXT[] DEFAULT ARRAY[]::TEXT[],
  "lastUsedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AdminWebAuthnCredential_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "AuthWebAuthnChallenge" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "purpose" TEXT NOT NULL,
  "ticketHash" TEXT NOT NULL,
  "challengeHash" TEXT NOT NULL,
  "credentialIds" TEXT[] DEFAULT ARRAY[]::TEXT[],
  "createdIpHash" TEXT,
  "createdUserAgentHash" TEXT,
  "origin" TEXT,
  "rpId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "consumedAt" TIMESTAMP(3),
  CONSTRAINT "AuthWebAuthnChallenge_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "SensitiveActionApproval" (
  "id" TEXT NOT NULL,
  "actionKey" TEXT NOT NULL,
  "status" TEXT NOT NULL DEFAULT 'PENDING',
  "requestedByUserId" TEXT NOT NULL,
  "reviewedByUserId" TEXT,
  "executedByUserId" TEXT,
  "orgId" TEXT,
  "licenseeId" TEXT,
  "entityType" TEXT,
  "entityId" TEXT,
  "payload" JSONB NOT NULL,
  "summary" JSONB,
  "requestIpHash" TEXT,
  "requestUserAgentHash" TEXT,
  "reviewNote" TEXT,
  "executionError" TEXT,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "reviewedAt" TIMESTAMP(3),
  "executedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "SensitiveActionApproval_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "AdminWebAuthnCredential_credentialId_key" ON "AdminWebAuthnCredential"("credentialId");
CREATE INDEX IF NOT EXISTS "AdminWebAuthnCredential_userId_createdAt_idx" ON "AdminWebAuthnCredential"("userId", "createdAt");
CREATE INDEX IF NOT EXISTS "AdminWebAuthnCredential_lastUsedAt_idx" ON "AdminWebAuthnCredential"("lastUsedAt");

CREATE UNIQUE INDEX IF NOT EXISTS "AuthWebAuthnChallenge_ticketHash_key" ON "AuthWebAuthnChallenge"("ticketHash");
CREATE INDEX IF NOT EXISTS "AuthWebAuthnChallenge_userId_purpose_createdAt_idx" ON "AuthWebAuthnChallenge"("userId", "purpose", "createdAt");
CREATE INDEX IF NOT EXISTS "AuthWebAuthnChallenge_expiresAt_idx" ON "AuthWebAuthnChallenge"("expiresAt");
CREATE INDEX IF NOT EXISTS "AuthWebAuthnChallenge_consumedAt_idx" ON "AuthWebAuthnChallenge"("consumedAt");

CREATE INDEX IF NOT EXISTS "SensitiveActionApproval_status_expiresAt_createdAt_idx" ON "SensitiveActionApproval"("status", "expiresAt", "createdAt");
CREATE INDEX IF NOT EXISTS "SensitiveActionApproval_requestedByUserId_createdAt_idx" ON "SensitiveActionApproval"("requestedByUserId", "createdAt");
CREATE INDEX IF NOT EXISTS "SensitiveActionApproval_reviewedByUserId_createdAt_idx" ON "SensitiveActionApproval"("reviewedByUserId", "createdAt");
CREATE INDEX IF NOT EXISTS "SensitiveActionApproval_licenseeId_status_createdAt_idx" ON "SensitiveActionApproval"("licenseeId", "status", "createdAt");
CREATE INDEX IF NOT EXISTS "SensitiveActionApproval_actionKey_entityType_entityId_status_idx" ON "SensitiveActionApproval"("actionKey", "entityType", "entityId", "status");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'AdminWebAuthnCredential_userId_fkey'
  ) THEN
    ALTER TABLE "AdminWebAuthnCredential"
      ADD CONSTRAINT "AdminWebAuthnCredential_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'AuthWebAuthnChallenge_userId_fkey'
  ) THEN
    ALTER TABLE "AuthWebAuthnChallenge"
      ADD CONSTRAINT "AuthWebAuthnChallenge_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'SensitiveActionApproval_requestedByUserId_fkey'
  ) THEN
    ALTER TABLE "SensitiveActionApproval"
      ADD CONSTRAINT "SensitiveActionApproval_requestedByUserId_fkey"
      FOREIGN KEY ("requestedByUserId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'SensitiveActionApproval_reviewedByUserId_fkey'
  ) THEN
    ALTER TABLE "SensitiveActionApproval"
      ADD CONSTRAINT "SensitiveActionApproval_reviewedByUserId_fkey"
      FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE constraint_name = 'SensitiveActionApproval_executedByUserId_fkey'
  ) THEN
    ALTER TABLE "SensitiveActionApproval"
      ADD CONSTRAINT "SensitiveActionApproval_executedByUserId_fkey"
      FOREIGN KEY ("executedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;
