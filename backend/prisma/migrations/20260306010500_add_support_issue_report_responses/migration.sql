ALTER TABLE "SupportIssueReport"
ADD COLUMN "responseMessage" TEXT,
ADD COLUMN "respondedAt" TIMESTAMP(3),
ADD COLUMN "respondedByUserId" TEXT;

CREATE INDEX "SupportIssueReport_respondedByUserId_respondedAt_idx"
ON "SupportIssueReport"("respondedByUserId", "respondedAt");

ALTER TABLE "SupportIssueReport"
ADD CONSTRAINT "SupportIssueReport_respondedByUserId_fkey"
FOREIGN KEY ("respondedByUserId") REFERENCES "User"("id")
ON DELETE SET NULL
ON UPDATE CASCADE;
