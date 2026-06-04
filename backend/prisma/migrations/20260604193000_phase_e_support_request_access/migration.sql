-- Phase E public support and request-access intake.
-- Forward-only migration; no historical migration edits.

CREATE TABLE "RequestAccess" (
    "id" TEXT NOT NULL,
    "referenceCode" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "workEmail" TEXT NOT NULL,
    "companyName" TEXT NOT NULL,
    "roleTitle" TEXT NOT NULL,
    "country" TEXT NOT NULL,
    "monthlyGarmentVolume" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "sourcePage" TEXT,
    "referrer" TEXT,
    "status" TEXT NOT NULL DEFAULT 'NEW',
    "internalNote" TEXT,
    "assignedToUserId" TEXT,
    "reviewedByUserId" TEXT,
    "reviewedAt" TIMESTAMP(3),
    "adminEmailDeliveryStatus" TEXT NOT NULL DEFAULT 'NOT_ATTEMPTED',
    "adminEmailErrorCode" TEXT,
    "acknowledgementEmailDeliveryStatus" TEXT NOT NULL DEFAULT 'NOT_ATTEMPTED',
    "acknowledgementEmailErrorCode" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RequestAccess_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "RequestAccess_referenceCode_key" ON "RequestAccess"("referenceCode");
CREATE INDEX "RequestAccess_status_createdAt_idx" ON "RequestAccess"("status", "createdAt");
CREATE INDEX "RequestAccess_workEmail_idx" ON "RequestAccess"("workEmail");
CREATE INDEX "RequestAccess_companyName_idx" ON "RequestAccess"("companyName");
CREATE INDEX "RequestAccess_assignedToUserId_idx" ON "RequestAccess"("assignedToUserId");
CREATE INDEX "RequestAccess_reviewedByUserId_reviewedAt_idx" ON "RequestAccess"("reviewedByUserId", "reviewedAt");

ALTER TABLE "RequestAccess" ADD CONSTRAINT "RequestAccess_assignedToUserId_fkey"
  FOREIGN KEY ("assignedToUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "RequestAccess" ADD CONSTRAINT "RequestAccess_reviewedByUserId_fkey"
  FOREIGN KEY ("reviewedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "SupportIssueReport" ADD COLUMN "referenceCode" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "publicName" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "publicEmail" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "issueType" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "verificationCode" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "productReference" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "priority" TEXT NOT NULL DEFAULT 'P3';
ALTER TABLE "SupportIssueReport" ADD COLUMN "internalNote" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "emailDeliveryStatus" TEXT NOT NULL DEFAULT 'NOT_ATTEMPTED';
ALTER TABLE "SupportIssueReport" ADD COLUMN "emailErrorCode" TEXT;
ALTER TABLE "SupportIssueReport" ADD COLUMN "acknowledgementEmailDeliveryStatus" TEXT NOT NULL DEFAULT 'NOT_ATTEMPTED';
ALTER TABLE "SupportIssueReport" ADD COLUMN "acknowledgementEmailErrorCode" TEXT;

CREATE UNIQUE INDEX "SupportIssueReport_referenceCode_key" ON "SupportIssueReport"("referenceCode");
CREATE INDEX "SupportIssueReport_publicEmail_createdAt_idx" ON "SupportIssueReport"("publicEmail", "createdAt");
CREATE INDEX "SupportIssueReport_priority_createdAt_idx" ON "SupportIssueReport"("priority", "createdAt");
CREATE INDEX "SupportIssueReport_issueType_createdAt_idx" ON "SupportIssueReport"("issueType", "createdAt");
