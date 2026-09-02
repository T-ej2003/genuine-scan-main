#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runStageBAdminPreflightLifecycle } from "./stage-b-admin-preflight-lifecycle.mjs";
import { parseStageBAdministratorPreflightArgs } from "./stage-b-administrator-preflight-args.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const { phase, outputPath, signaturePath, lifecycleDirectory, sourceSha, imageAuthorizationPath, imageAuthorizationSha256, retry, forwarded } = parseStageBAdministratorPreflightArgs(process.argv.slice(2));
const producerPath = phase === "initial"
  ? path.join(root, "scripts/aws/run-production-green-stage-b-preflight.mjs")
  : path.join(root, "scripts/aws/validate-production-green-stage-b-permissions.mjs");
const producerArgs = phase === "initial"
  ? ["--identity", "administrator", "--phase", "initial", "--source-sha", sourceSha, "--image-authorization", imageAuthorizationPath, "--image-authorization-sha256", imageAuthorizationSha256, "--output", outputPath, "--signature-output", signaturePath]
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
  retry,
});
process.stdout.write(`${JSON.stringify(result)}\n`);
if (result.state !== "SUCCEEDED") process.exitCode = 1;
