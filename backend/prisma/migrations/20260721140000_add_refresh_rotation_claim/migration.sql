ALTER TABLE "RefreshToken"
  ADD COLUMN "rotationRequestId" TEXT,
  ADD COLUMN "rotationClaimedAt" TIMESTAMP(3),
  ADD COLUMN "rotationCompletedAt" TIMESTAMP(3);

CREATE INDEX "RefreshToken_rotationRequestId_idx" ON "RefreshToken"("rotationRequestId");
