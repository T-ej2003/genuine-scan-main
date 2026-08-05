#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runStageBAdminPreflightLifecycle } from "./stage-b-admin-preflight-lifecycle.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readOption = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = readOption(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

const argv = process.argv.slice(2);
const outputPath = required(argv, "--output");
const signaturePath = required(argv, "--signature-output");
const lifecycleDirectory = required(argv, "--lifecycle-directory");
const producerPath = path.join(root, "scripts/aws/run-production-green-stage-b-preflight.mjs");
const result = await runStageBAdminPreflightLifecycle({
  lifecycleDirectory,
  outputPath,
  signaturePath,
  producerPath,
  producerArgs: ["--identity", "administrator", "--output", outputPath, "--signature-output", signaturePath],
  cwd: root,
  repositoryRoot: root,
  retry: argv.includes("--retry"),
});
process.stdout.write(`${JSON.stringify(result)}\n`);
if (result.state !== "SUCCEEDED") process.exitCode = 1;
