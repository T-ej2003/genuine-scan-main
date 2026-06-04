const { execFileSync } = require("child_process");
const path = require("path");

const { P2TestDbSkip, dropP2TestDatabase, resolveP2TestDatabase } = require("./helpers/p2TestDb");

const backendRoot = path.resolve(__dirname, "..");
const emptyMigrationOutput = "-- This is an empty migration.";

const runPrismaDiff = (shadowDatabaseUrl) =>
  execFileSync(
    "npx",
    [
      "prisma",
      "migrate",
      "diff",
      "--from-migrations",
      "prisma/migrations",
      "--to-schema-datamodel",
      "prisma/schema.prisma",
      "--script",
      "--shadow-database-url",
      shadowDatabaseUrl,
    ],
    {
      cwd: backendRoot,
      encoding: "utf8",
      env: { ...process.env, NODE_ENV: "test" },
      stdio: ["ignore", "pipe", "inherit"],
    },
  );

(async () => {
  let databaseInfo = null;
  try {
    databaseInfo = resolveP2TestDatabase();
    const diff = runPrismaDiff(databaseInfo.databaseUrl).trim();
    if (diff && diff !== emptyMigrationOutput) {
      console.error("p3 migration drift gate failed: migration history does not match schema.prisma.");
      console.error(diff);
      process.exit(1);
    }
    console.log("p3 migration drift gate passed");
  } catch (error) {
    if (error instanceof P2TestDbSkip && process.env.P2_TEST_DATABASE_REQUIRED !== "true") {
      console.log(`p3 migration drift gate skipped: ${error.message}`);
      return;
    }
    console.error(error);
    process.exit(1);
  } finally {
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
})();
