import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";
import { parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { collectAppOnlyDeploymentPreparation } from "./production-app-only-preparation.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
export function parseAppOnlyDeploymentPreparationArgs(args, env = process.env) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: { "source-sha": { type: "string" }, "compatibility-reference": { type: "string" } } });
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main");
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, "T-ej2003/genuine-scan-main/.github/workflows/prepare-production-app-only-deployment.yml@refs/heads/main");
  assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.equal(values["source-sha"], env.GITHUB_SHA);
  const compatibilityReference = parseAppOnlyArtifactReference(values["compatibility-reference"]);
  assert.equal(compatibilityReference.sourceSha, values["source-sha"]);
  return { sourceSha: values["source-sha"], compatibilityReference };
}
async function main() {
  const input = parseAppOnlyDeploymentPreparationArgs(process.argv.slice(2));
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION,
    exec: (command, args, options) => execFileSync(command, args, { ...options, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_VERIFIER.roleName}/[^/]+$`));
  const result = await collectAppOnlyDeploymentPreparation({ ...input, repositoryRoot, run });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-preparation-")); fs.chmodSync(directory, 0o700);
  const file = writeStageBPrivateFileExclusive({ repositoryRoot, filePath: path.join(directory, "app-only-preparation.json"), bytes: Buffer.from(`${JSON.stringify(result)}\n`) });
  assert.ok(process.env.GITHUB_OUTPUT); fs.appendFileSync(process.env.GITHUB_OUTPUT, `path=${file.path}\nsha256=${file.sha256}\n`);
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${JSON.stringify(result.preparation, null, 2)}\n`);
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("App-only deployment preparation failed closed; no application was deployed.\n"); process.exitCode = 1; });
