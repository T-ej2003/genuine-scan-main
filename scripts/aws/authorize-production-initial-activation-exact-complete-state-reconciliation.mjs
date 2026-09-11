#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { EXACT_COMPLETE_STATE_RECONCILIATION as CONTRACT, createExactCompleteStateReconciliationAuthorization } from "./production-initial-activation-reconciler-exact-complete-state-reconciliation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
export function runAuthorizeExactCompleteStateReconciliation(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--authorize")) throw new Error("Exact-complete state reconciliation authorization requires --authorize.");
  const sourceSha = required(argv, "--source-sha"); const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "Exact-complete state reconciliation preparation" }); const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-file-sha256"), repositoryRoot: root, label: "Exact-complete state reconciliation approval" }); const env = deps.env || process.env;
  assertProductionEnvironmentApprovalEvidence(approval, { sourceSha, repository: CONTRACT.repository, environment: CONTRACT.environment, workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS });
  const authorization = createExactCompleteStateReconciliationAuthorization({ preparation, approval, now: deps.now || new Date() }); const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Exact-complete state reconciliation authorization", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Exact-complete state reconciliation authorization directory" }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Exact-complete state reconciliation authorization" }); return authorization;
}
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runAuthorizeExactCompleteStateReconciliation(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }
