const { P2TestDbSkip, dropP2TestDatabase, resolveP2TestDatabase, runPrismaSchemaSetup } = require("./helpers/p2TestDb");

(async () => {
  let databaseInfo = null;
  try {
    databaseInfo = resolveP2TestDatabase();
    runPrismaSchemaSetup(databaseInfo.databaseUrl);
    console.log("p3 migration replay gate passed");
  } catch (error) {
    if (error instanceof P2TestDbSkip && process.env.P2_TEST_DATABASE_REQUIRED !== "true") {
      console.log(`p3 migration replay gate skipped: ${error.message}`);
      return;
    }
    console.error(error);
    process.exit(1);
  } finally {
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
})();
