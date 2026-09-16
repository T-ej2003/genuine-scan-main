import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";
import { collectAppOnlyVerifierPreparation } from "./production-app-only-preparation.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
export function parseAppOnlyVerifierPreparationArgs(args, env = process.env) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: Object.fromEntries(["source-sha", "candidate-digest", "publication-reference", "image-authorization-reference", "requirements-reference"].map((key) => [key, { type: "string" }])) });
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main");
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch"); assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_WORKFLOW_REF, "T-ej2003/genuine-scan-main/.github/workflows/prepare-production-app-only-verifier.yml@refs/heads/main");
  assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.equal(values["source-sha"], env.GITHUB_SHA);
  assert.match(values["candidate-digest"] || "", /^sha256:[a-f0-9]{64}$/);
  const reference = (name) => parseAppOnlyArtifactReference(values[name]);
  return { sourceSha: values["source-sha"], candidateDigest: values["candidate-digest"], publicationReference: reference("publication-reference"),
    authorizationReference: reference("image-authorization-reference"), requirementsReference: reference("requirements-reference") };
}

async function main() {
  const input = parseAppOnlyVerifierPreparationArgs(process.argv.slice(2));
  // Reuse the canonical sanitized checker-session transport. Workflow OIDC
  // provenance is required above; STS below pins the separate verifier role.
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION,
    exec: (command, args, options) => execFileSync(command, args, { ...options, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_VERIFIER.roleName}/[^/]+$`));
  const result = await collectAppOnlyVerifierPreparation({ ...input, repositoryRoot, run });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-verifier-preparation-")); fs.chmodSync(directory, 0o700);
  const output = writeStageBPrivateFileExclusive({ filePath: path.join(directory, "app-only-verifier-preparation.json"),
    bytes: Buffer.from(`${JSON.stringify(result)}\n`), repositoryRoot });
  process.stdout.write(`${JSON.stringify({ artifactPath: output.path, artifactSha256: output.sha256,
    preparationSha256: result.preparation.preparationSha256, predecessorTaskDefinition: result.preparation.predecessor.taskDefinitionArn,
    predecessorDigest: result.preparation.predecessor.backendDigest, candidateDigest: input.candidateDigest })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(() => { process.stderr.write("App-only verifier preparation failed closed; no verifier was launched and no deployment authorized.\n"); process.exitCode = 1; });
}
