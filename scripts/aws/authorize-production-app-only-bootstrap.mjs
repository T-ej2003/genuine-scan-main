import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createAppOnlyBootstrapPreparation } from "./production-app-only-bootstrap-contract.mjs";
import { createAppOnlyAuthorization } from "./production-app-only-authorization.mjs";
import { fetchProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
export function appOnlyBootstrapApprovalSubject(env = process.env) {
  const preparation = createAppOnlyBootstrapPreparation({ repositoryRoot, sourceSha: env.SOURCE_SHA,
    generatedAt: env.PREPARED_AT, callerArn: env.CALLER_ARN, planSha256: env.PLAN_SHA256, planJsonSha256: env.PLAN_JSON_SHA256 });
  assert.equal(preparation.preparationSha256, env.PREPARATION_SHA256);
  assert.equal(preparation.sourceSha, env.GITHUB_SHA); assert.equal(env.GITHUB_REF, "refs/heads/main");
  assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch"); assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main");
  assert.equal(env.GITHUB_WORKFLOW_REF, "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-app-only-bootstrap.yml@refs/heads/main");
  return preparation;
}

async function main() {
  assert.ok(process.argv.length === 2 || process.argv.length === 3 && process.argv[2] === "--preview");
  const preparation = appOnlyBootstrapApprovalSubject();
  assertProtectedCheckout({ sourceSha: preparation.sourceSha, repositoryRoot });
  const githubRun = createProductionGithubCommandRunner();
  const main = JSON.parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
  assert.equal(main.protected, true); assert.equal(main.commit?.sha, preparation.sourceSha);
  if (process.argv[2] === "--preview") {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${JSON.stringify(preparation, null, 2)}\n`);
    return;
  }
  const env = process.env;
  const approval = await fetchProductionEnvironmentApprovalEvidence({ token: env.GITHUB_TOKEN, repository: env.GITHUB_REPOSITORY,
    environment: "production", sourceSha: preparation.sourceSha, workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME,
    workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, requireActualApproval: true });
  const authorization = createAppOnlyAuthorization({ phase: "BOOTSTRAP", preparation, approval, env });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-bootstrap-approval-")); fs.chmodSync(directory, 0o700);
  const file = writeStageBPrivateFileExclusive({ repositoryRoot, filePath: path.join(directory, "app-only-bootstrap-authorization.json"),
    bytes: Buffer.from(`${JSON.stringify({ preparation, approval, authorization })}\n`) });
  fs.appendFileSync(env.GITHUB_OUTPUT, `path=${file.path}\nsha256=${file.sha256}\n`);
}
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("App-only bootstrap authorization failed closed.\n"); process.exitCode = 1; });
