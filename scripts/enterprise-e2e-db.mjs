import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const {
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runGeneratedRlsSchemaSetup,
} = require("../backend/tests/helpers/p2TestDb");

const mode = process.argv[2];
if (!["prepare", "cleanup"].includes(mode)) throw new Error("Usage: enterprise-e2e-db.mjs prepare|cleanup");

if (mode === "prepare") {
  const databaseInfo = resolveP2TestDatabase();
  try {
    const urls = runGeneratedRlsSchemaSetup(databaseInfo);
    const output = String(process.env.GITHUB_ENV || "").trim();
    if (!output) throw new Error("GITHUB_ENV is required for enterprise E2E database preparation");
    fs.appendFileSync(output, [
      `DATABASE_URL=${urls.runtimeUrl}`,
      `AUTHENTICATED_APP_DATABASE_URL=${urls.runtimeUrl}`,
      `PREAUTH_DATABASE_URL=${urls.preauthUrl}`,
      `E2E_SEED_DATABASE_URL=${urls.seedUrl}`,
      `E2E_DISPOSABLE_DATABASE_NAME=${databaseInfo.createdDatabaseName}`,
      `E2E_CERT_ADMIN_CREATED=${databaseInfo.createdCertificationAdministrator ? "true" : "false"}`,
      "",
    ].join("\n"));
  } catch (error) {
    dropP2TestDatabase(databaseInfo);
    throw error;
  }
} else {
  const createdDatabaseName = String(process.env.E2E_DISPOSABLE_DATABASE_NAME || "").trim();
  if (createdDatabaseName) {
    dropP2TestDatabase({
      adminUrl: String(process.env.P2_TEST_DATABASE_ADMIN_URL || ""),
      createdDatabaseName,
      createdCertificationAdministrator: process.env.E2E_CERT_ADMIN_CREATED === "true",
      packageBootstrapStarted: true,
    });
  }
}
