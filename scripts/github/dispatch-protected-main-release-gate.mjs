#!/usr/bin/env node

import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { dispatchProtectedMainReleaseGate } from "./dispatch-source-bound-workflow.mjs";

const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;

function parseArgs(args) {
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!key?.startsWith("--") || args[index + 1] === undefined || values[key]) throw new Error("Expected each dispatch option exactly once.");
    values[key] = args[index + 1];
  }
  if (Object.keys(values).length !== 3 || !values["--target-ref"] || !values["--target-sha"] || !values["--inputs-file"]) throw new Error("Usage: dispatch-protected-main-release-gate.mjs --target-ref <main|refs/tags/release-*|refs/tags/v*> --target-sha <sha> --inputs-file <private-json-file>");
  return values;
}

if (isMain) {
  try {
    const values = parseArgs(process.argv.slice(2));
    const stat = fs.lstatSync(values["--inputs-file"]);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) throw new Error("Release Gate dispatch inputs file must be a private regular file.");
    const run = await dispatchProtectedMainReleaseGate({
      repository: process.env.GITHUB_REPOSITORY,
      token: process.env.GH_TOKEN || process.env.GITHUB_TOKEN,
      targetRef: values["--target-ref"],
      targetSha: values["--target-sha"],
      inputs: JSON.parse(fs.readFileSync(values["--inputs-file"], "utf8")),
    });
    process.stdout.write(`PROTECTED_MAIN_RELEASE_GATE_RUN_ID=${run.id}\nPROTECTED_MAIN_RELEASE_GATE_RUN_URL=${run.html_url || ""}\nPROTECTED_MAIN_CONTROL_PLANE_SHA=${run.head_sha}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exit(1);
  }
}
