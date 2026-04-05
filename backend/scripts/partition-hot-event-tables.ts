import "dotenv/config";
import path from "path";
import dotenv from "dotenv";

import prisma from "../src/config/database";
import {
  buildHotEventPartitionPlan,
  buildOfflineHotEventPartitionSqlPreview,
  buildHotEventPartitionSqlPreview,
  executeHotEventPartitionCutover,
  ensureQrScanLogArchiveInfrastructure,
  getHotEventPartitionTables,
  type HotEventPartitionTableName,
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

const parseTables = (): HotEventPartitionTableName[] | undefined => {
  const raw = String(parseArg("--tables") || "").trim();
  if (!raw) return undefined;
  const allowed = new Set(getHotEventPartitionTables());
  const values = raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean) as HotEventPartitionTableName[];

  for (const value of values) {
    if (!allowed.has(value)) {
      throw new Error(`Unsupported table in --tables: ${value}`);
    }
  }

  return values;
};

const run = async () => {
  const execute = parseFlag("--execute");
  const offline = parseFlag("--offline");
  const printSql = parseFlag("--print-sql") || !execute;
  const tables = parseTables();
  const historicMonths = parseNumberArg("--historic-months", 24);
  const futureMonths = parseNumberArg("--future-months", 3);
  const deltaGraceHours = parseNumberArg("--delta-grace-hours", 24);

  let plan = null;
  let sqlPreview = buildOfflineHotEventPartitionSqlPreview({
    tables,
    historicMonths,
    futureMonths,
  });

  if (!offline) {
    try {
      plan = await buildHotEventPartitionPlan({
        tables,
        historicMonths,
        futureMonths,
      });

      sqlPreview = await buildHotEventPartitionSqlPreview({
        tables,
        historicMonths,
        futureMonths,
      });
    } catch (error) {
      if (execute) throw error;
      sqlPreview = buildOfflineHotEventPartitionSqlPreview({
        tables,
        historicMonths,
        futureMonths,
      });
      console.warn("Falling back to offline SQL preview because the database is not reachable.");
    }
  } else {
    sqlPreview = buildOfflineHotEventPartitionSqlPreview({
      tables,
      historicMonths,
      futureMonths,
    });
  }

  if (printSql) {
    console.log("# Hot event partition SQL preview");
    for (const [tableName, statements] of Object.entries(sqlPreview)) {
      console.log(`\n-- ${tableName}`);
      console.log(statements.join("\n"));
    }
  }

  if (!execute) {
    console.log(
      JSON.stringify(
        {
          execute: false,
          offlinePreview: offline || !plan,
          plan,
        },
        null,
        2
      )
    );
    return;
  }

  const archive = await ensureQrScanLogArchiveInfrastructure({
    historicMonths,
    futureMonths,
  });
  const results = await executeHotEventPartitionCutover({
    tables,
    historicMonths,
    futureMonths,
    deltaGraceHours,
  });

  console.log(
    JSON.stringify(
      {
        execute: true,
        archive,
        results,
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
