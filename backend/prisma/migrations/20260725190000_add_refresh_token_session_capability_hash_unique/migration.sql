DROP INDEX "RefreshToken_sessionCapabilityHash_key";

CREATE UNIQUE INDEX "RefreshToken_sessionCapabilityHash_key"
ON "RefreshToken"("sessionCapabilityHash");
