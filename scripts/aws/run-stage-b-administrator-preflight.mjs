#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runStageBAdminPreflightLifecycle } from "./stage-b-admin-preflight-lifecycle.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const readOption = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = readOption(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

const argv = process.argv.slice(2);
const phase = required(argv, "--phase");
if (!["initial", "plan-bound"].includes(phase)) throw new Error("--phase must be initial or plan-bound.");
const outputPath = required(argv, "--output");
const signaturePath = required(argv, "--signature-output");
const lifecycleDirectory = required(argv, "--lifecycle-directory");
const launcherOnly = new Set(["--phase", "--output", "--signature-output", "--lifecycle-directory", "--retry"]);
const planBoundOnly = new Set(["--report-generator-caller-arn", "--simulated-role-arn", "--plan-json", "--canonical-plan-json", "--saved-plan", "--plan-approval-report", "--plan-approval-report-sha256", "--manifest", "--expected-account", "--expected-region", "--policy-published-at", "--cloudtrail-session-name", "--reference-audit", "--refresh-report"]);
if (phase === "initial" && [...planBoundOnly].some((name) => argv.includes(name))) throw new Error("Initial administrator capability preflight does not accept plan-bound arguments.");
const forwarded = argv.filter((argument, index) => !launcherOnly.has(argument) && (index === 0 || !launcherOnly.has(argv[index - 1])));
const producerPath = phase === "initial"
  ? path.join(root, "scripts/aws/run-production-green-stage-b-preflight.mjs")
  : path.join(root, "scripts/aws/validate-production-green-stage-b-permissions.mjs");
const producerArgs = phase === "initial"
  ? ["--identity", "administrator", "--phase", "initial", "--output", outputPath, "--signature-output", signaturePath]
  : [...forwarded, "--output", outputPath, "--signature-output", signaturePath];
const result = await runStageBAdminPreflightLifecycle({
  lifecycleDirectory,
  phase,
  outputPath,
  signaturePath,
  producerPath,
  producerArgs,
  cwd: root,
  repositoryRoot: root,
  retry: argv.includes("--retry"),
});
process.stdout.write(`${JSON.stringify(result)}\n`);
if (result.state !== "SUCCEEDED") process.exitCode = 1;
