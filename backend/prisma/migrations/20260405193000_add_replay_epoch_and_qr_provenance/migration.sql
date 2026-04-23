ALTER TABLE "QRCode"
  ADD COLUMN "replayEpoch" INTEGER NOT NULL DEFAULT 1,
  ADD COLUMN "issuanceMode" TEXT NOT NULL DEFAULT 'LEGACY_UNSPECIFIED',
  ADD COLUMN "customerVerifiableAt" TIMESTAMP(3),
  ADD COLUMN "signedFirstSeenAt" TIMESTAMP(3),
  ADD COLUMN "lastSignedVerificationAt" TIMESTAMP(3),
  ADD COLUMN "lastSignedVerificationIpHash" TEXT,
  ADD COLUMN "lastSignedVerificationDeviceHash" TEXT;

ALTER TABLE "CustomerVerificationSession"
  ADD COLUMN "proofBindingTokenHash" TEXT,
  ADD COLUMN "proofBindingIssuedAt" TIMESTAMP(3),
  ADD COLUMN "proofBindingExpiresAt" TIMESTAMP(3),
  ADD COLUMN "proofBindingReplayEpoch" INTEGER;

CREATE INDEX "QRCode_issuanceMode_customerVerifiableAt_idx"
  ON "QRCode"("issuanceMode", "customerVerifiableAt");

CREATE INDEX "QRCode_lastSignedVerificationAt_idx"
  ON "QRCode"("lastSignedVerificationAt");

CREATE INDEX "CustomerVerificationSession_proofBindingExpiresAt_idx"
  ON "CustomerVerificationSession"("proofBindingExpiresAt");
