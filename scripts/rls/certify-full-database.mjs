import { pathToFileURL } from "node:url";
import { DATABASE_ENV, runCertification } from "./certify-clean-room-database.mjs";

export * from "./certify-clean-room-database.mjs";

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  try { console.log(JSON.stringify(runCertification(process.env[DATABASE_ENV] || ""))); }
  catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
