ALTER TABLE "RefreshToken"
ADD COLUMN "authenticatedAt" TIMESTAMP(3),
ADD COLUMN "mfaVerifiedAt" TIMESTAMP(3);
