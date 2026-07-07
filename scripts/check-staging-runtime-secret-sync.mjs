#!/usr/bin/env node
import process from "node:process";
import { pathToFileURL } from "node:url";

import { runSyncWorkflow, usage } from "./sync-staging-runtime-secrets.mjs";

export function main(argv = process.argv.slice(2), env = process.env) {
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(`Usage: node scripts/check-staging-runtime-secret-sync.mjs

Non-mutating validation wrapper for staging runtime secret sync.

${usage()}`);
    return 0;
  }

  const result = runSyncWorkflow({ argv: ["--validate-only"], env });
  const payload = {
    ...result.payload,
    validationOnly: true,
    mutatesAws: false,
  };
  console.log(JSON.stringify(payload, null, 2));
  return result.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
