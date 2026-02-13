ALTER TABLE "IncidentCommunication"
  ADD COLUMN "attemptedFrom" TEXT,
  ADD COLUMN "usedFrom" TEXT,
  ADD COLUMN "replyTo" TEXT,
  ADD COLUMN "errorMessage" TEXT;
