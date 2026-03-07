-- CreateTable
CREATE TABLE "ManufacturerLicenseeLink" (
    "manufacturerId" TEXT NOT NULL,
    "licenseeId" TEXT NOT NULL,
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ManufacturerLicenseeLink_pkey" PRIMARY KEY ("manufacturerId","licenseeId")
);

-- CreateIndex
CREATE INDEX "ManufacturerLicenseeLink_licenseeId_idx" ON "ManufacturerLicenseeLink"("licenseeId");

-- CreateIndex
CREATE INDEX "ManufacturerLicenseeLink_manufacturerId_isPrimary_idx" ON "ManufacturerLicenseeLink"("manufacturerId", "isPrimary");

-- AddForeignKey
ALTER TABLE "ManufacturerLicenseeLink" ADD CONSTRAINT "ManufacturerLicenseeLink_manufacturerId_fkey"
FOREIGN KEY ("manufacturerId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ManufacturerLicenseeLink" ADD CONSTRAINT "ManufacturerLicenseeLink_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Backfill existing manufacturer-to-licensee associations from the legacy direct column.
INSERT INTO "ManufacturerLicenseeLink" (
  "manufacturerId",
  "licenseeId",
  "isPrimary",
  "createdAt",
  "updatedAt"
)
SELECT
  u."id",
  u."licenseeId",
  true,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM "User" u
WHERE
  u."licenseeId" IS NOT NULL
  AND u."role" IN ('MANUFACTURER', 'MANUFACTURER_ADMIN', 'MANUFACTURER_USER')
ON CONFLICT ("manufacturerId", "licenseeId") DO NOTHING;
