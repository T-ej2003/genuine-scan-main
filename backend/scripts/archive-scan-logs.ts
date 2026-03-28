import "dotenv/config";
import path from "path";
import dotenv from "dotenv";

import prisma from "../src/config/database";
import { refreshAnalyticsRollups } from "../src/services/analyticsRollupService";
import {
  ensureQrScanLogArchiveInfrastructure,
  runQrScanLogArchiveBatch,
} from "../src/services/hotEventPartitionService";

dotenv.config({ path: path.resolve(__dirname, "../.env") });

const parseFlag = (flag: string) => process.argv.includes(flag);

const parseArg = (flag: string) => {
  const index = process.argv.findIndex((arg) => arg === flag);
  if (index < 0) return undefined;
  return process.argv[index + 1];
};

const parseNumberArg = (flag: string, fallback: number) => {
  const parsed = Number(parseArg(flag));
  return Number.isFinite(parsed) ? parsed : fallback;
};

const run = async () => {
  const execute = parseFlag("--execute");
  const refreshRollupsFirst = parseFlag("--refresh-rollups");
  const olderThanDays = parseNumberArg("--older-than-days", 180);
  const batchSize = parseNumberArg("--batch-size", 5000);
  const maxBatches = Math.max(1, parseNumberArg("--max-batches", 1));

  if (!execute) {
    console.log(
      JSON.stringify(
        {
          execute: false,
          message:
            "Dry run only. Re-run with --execute to provision the archive table and move cold scan-log rows.",
          olderThanDays,
          batchSize,
          maxBatches,
        },
        null,
        2
      )
    );
    return;
  }

  await ensureQrScanLogArchiveInfrastructure({
    historicMonths: 24,
    futureMonths: 3,
  });

  if (refreshRollupsFirst) {
    await refreshAnalyticsRollups();
  }

  let totalMoved = 0;
  let batches = 0;
  let lastCutoff: string | null = null;

  while (batches < maxBatches) {
    const result = await runQrScanLogArchiveBatch({
      olderThanDays,
      batchSize,
    });
    lastCutoff = result.cutoff;
    if (!result.archiveReady || result.moved <= 0) break;
    totalMoved += result.moved;
    batches += 1;
  }

  console.log(
    JSON.stringify(
      {
        success: true,
        execute: true,
        olderThanDays,
        batchSize,
        maxBatches,
        batches,
        moved: totalMoved,
        cutoff: lastCutoff,
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
