import path from "path";
import dotenv from "dotenv";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

import prisma from "../src/config/database";
import { backfillHistoricalQrProvenance } from "../src/services/qrProvenanceBackfillService";

const readArg = (name: string) => {
  const flag = `--${name}`;
  const index = process.argv.findIndex((entry) => entry === flag);
  if (index === -1) return null;
  return process.argv[index + 1] || null;
};

const hasFlag = (name: string) => process.argv.includes(`--${name}`);

const run = async () => {
  const licenseeId = readArg("licenseeId") || undefined;
  const limit = Number(readArg("limit") || "1000");
  const execute = hasFlag("execute");
  const json = hasFlag("json");

  const result = await backfillHistoricalQrProvenance({
    licenseeId,
    limit: Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 1000,
    dryRun: !execute,
  });

  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(
      [
        `QR provenance backfill ${result.dryRun ? "dry-run" : "execution"} completed.`,
        `Scanned: ${result.scanned}`,
        `Actionable: ${result.actionable}`,
        `Upgraded governed print: ${result.upgradedGovernedPrint}`,
        `Repaired governed readiness: ${result.repairedGovernedReadyAt}`,
        `Left unknown historical: ${result.leftUnknownHistorical}`,
      ].join("\n")
    );
  }
};

run()
  .catch((error) => {
    console.error("QR provenance backfill failed", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
