import "dotenv/config";
import path from "path";
import dotenv from "dotenv";

import prisma from "../src/config/database";
import {
  ensureFutureHotEventPartitions,
  ensureQrScanLogArchiveInfrastructure,
} from "../src/services/hotEventPartitionService";

dotenv.config({ path: path.resolve(__dirname, "../.env") });

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
  const futureMonths = parseNumberArg("--future-months", 3);
  const historicMonths = parseNumberArg("--historic-months", 24);

  const [partitions, archive] = await Promise.all([
    ensureFutureHotEventPartitions({ futureMonths }),
    ensureQrScanLogArchiveInfrastructure({ historicMonths, futureMonths }),
  ]);

  console.log(
    JSON.stringify(
      {
        success: true,
        futureMonths,
        historicMonths,
        partitions,
        archive,
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
