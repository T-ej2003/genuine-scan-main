import "dotenv/config";
import path from "path";
import dotenv from "dotenv";

import prisma from "../src/config/database";
import { backfillTraceEventsFromAuditLogs } from "../src/services/traceEventService";

dotenv.config({ path: path.resolve(__dirname, "../.env") });

const parseArg = (flag: string) => {
  const index = process.argv.findIndex((arg) => arg === flag);
  if (index < 0) return undefined;
  return process.argv[index + 1];
};

const run = async () => {
  const licenseeId = parseArg("--licenseeId");
  const limit = Number(parseArg("--limit") || "5000");

  await backfillTraceEventsFromAuditLogs({
    licenseeId,
    limit: Number.isFinite(limit) ? limit : 5000,
    force: true,
  });

  console.log(
    JSON.stringify(
      {
        success: true,
        licenseeId: licenseeId || null,
        limit: Number.isFinite(limit) ? limit : 5000,
      },
      null,
      2
    )
  );
};

void run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
