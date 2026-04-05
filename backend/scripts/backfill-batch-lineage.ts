import path from "path";

import dotenv from "dotenv";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

import prisma from "../src/config/database";
import { backfillBatchLineageFromAuditLogs } from "../src/services/batchAllocationService";

const readArg = (name: string) => {
  const flag = `--${name}`;
  const index = process.argv.findIndex((entry) => entry === flag);
  if (index < 0) return "";
  return String(process.argv[index + 1] || "").trim();
};

const run = async () => {
  const licenseeId = readArg("licenseeId") || undefined;
  const limit = Number(readArg("limit") || "5000");
  await backfillBatchLineageFromAuditLogs({
    licenseeId,
    limit: Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 5000,
    force: true,
  });
  console.log(`Batch lineage backfill completed${licenseeId ? ` for licensee ${licenseeId}` : ""}.`);
};

run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect().catch(() => undefined);
  });
