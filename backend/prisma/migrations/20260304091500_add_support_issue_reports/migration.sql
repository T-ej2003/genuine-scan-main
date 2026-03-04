CREATE TABLE "SupportIssueReport" (
    "id" TEXT NOT NULL,
    "reporterUserId" TEXT,
    "reporterRole" "UserRole",
    "licenseeId" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "sourcePath" TEXT,
    "pageUrl" TEXT,
    "autoDetected" BOOLEAN NOT NULL DEFAULT false,
    "screenshotPath" TEXT,
    "screenshotMime" TEXT,
    "screenshotSize" INTEGER,
    "diagnostics" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SupportIssueReport_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "SupportIssueReport_licenseeId_createdAt_idx" ON "SupportIssueReport"("licenseeId", "createdAt");
CREATE INDEX "SupportIssueReport_reporterUserId_createdAt_idx" ON "SupportIssueReport"("reporterUserId", "createdAt");
CREATE INDEX "SupportIssueReport_status_idx" ON "SupportIssueReport"("status");

ALTER TABLE "SupportIssueReport"
ADD CONSTRAINT "SupportIssueReport_reporterUserId_fkey"
FOREIGN KEY ("reporterUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "SupportIssueReport"
ADD CONSTRAINT "SupportIssueReport_licenseeId_fkey"
FOREIGN KEY ("licenseeId") REFERENCES "Licensee"("id") ON DELETE SET NULL ON UPDATE CASCADE;
