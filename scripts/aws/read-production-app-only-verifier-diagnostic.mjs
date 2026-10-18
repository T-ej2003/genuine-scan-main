#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";
import { parseAppOnlyArtifactReference, parseAppOnlyVerifierDiagnosticReference,
  downloadAppOnlyArtifact, downloadAppOnlyVerifierJournals } from "./production-app-only-artifacts.mjs";
import { authenticateFailedAppOnlyVerifierTask, readFailedAppOnlyVerifierDiagnostic } from "./production-app-only-verifier-diagnostic.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence,
  assertProductionEnvironmentActualReviewer } from "./production-github-environment-approval.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner,
  PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const repository = "T-ej2003/genuine-scan-main";

export function parseAppOnlyDiagnosticArgs(args, env = process.env) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: Object.fromEntries(["source-sha", "preparation-reference", "diagnostic-journal-reference",
      "approval", "approval-sha256"].map((name) => [name, { type: "string" }])) });
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, repository);
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyVerifierWorkflowRef);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1"); assert.match(env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.equal(values["source-sha"], env.GITHUB_SHA);
  const preparationReference = parseAppOnlyArtifactReference(values["preparation-reference"]);
  const journalReference = parseAppOnlyVerifierDiagnosticReference(values["diagnostic-journal-reference"]);
  assert.equal(preparationReference.sourceSha, journalReference.sourceSha);
  assert.ok(path.isAbsolute(values.approval || "")); assert.match(values["approval-sha256"] || "", /^[a-f0-9]{64}$/);
  return { ...values, preparationReference, journalReference };
}

export function diagnosticReadOnlyAws(run) {
  const actions = new Set(["sts get-caller-identity", "ecs describe-task-definition", "ecs describe-tasks", "logs get-log-events"]);
  return (args) => {
    assert.ok(actions.has(`${args[0]} ${args[1]}`), "Diagnostic has no AWS mutation capability");
    return run(args);
  };
}

async function main() {
  const options = parseAppOnlyDiagnosticArgs(process.argv.slice(2));
  const currentSourceSha = options["source-sha"], sourceSha = options.preparationReference.sourceSha;
  const githubRun = createProductionGithubCommandRunner();
  const source = () => {
    assertProtectedCheckout({ sourceSha: currentSourceSha, repositoryRoot });
    const main = JSON.parse(githubRun("gh", ["api", `repos/${repository}/branches/main`]));
    assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, currentSourceSha);
    execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, currentSourceSha], { cwd: repositoryRoot, timeout: 10000 });
  };
  source();
  const artifact = downloadAppOnlyArtifact({ kind: "verifierPreparation", reference: options.preparationReference,
    repositoryRoot, githubRun });
  const inputs = JSON.parse(artifact.bytes);
  const journals = downloadAppOnlyVerifierJournals({ reference: options.journalReference, includeExecution: true, githubRun });
  const approval = readBoundStageBPrivateJson({ filePath: options.approval,
    expectedSha256: options["approval-sha256"], repositoryRoot });
  const context = { sourceSha: currentSourceSha, repository, environment: "production",
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyVerifierWorkflowRef,
    eventName: process.env.GITHUB_EVENT_NAME, workflowRunId: process.env.GITHUB_RUN_ID,
    workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT, executionActor: process.env.GITHUB_ACTOR,
    githubActions: process.env.GITHUB_ACTIONS };
  const authorize = () => {
    source(); assertProductionEnvironmentApprovalEvidence(approval, context);
    assertProductionEnvironmentActualReviewer(approval, context);
  };
  const originalApprovals = JSON.parse(githubRun("gh", ["api", `repos/${repository}/actions/runs/${options.journalReference.runId}/approvals`]));
  assert.ok(originalApprovals.some(({ state, environments, user }) => state === "approved"
    && Number.isSafeInteger(user?.id) && user.id > 0
    && environments?.some(({ id, name }) => name === "production" && id === approval.environmentId)),
  "Original verifier approval is absent");
  authorize();
  const aws = diagnosticReadOnlyAws(createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION,
    exec: (command, args, opts) => execFileSync(command, args, { ...opts, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) }));
  const caller = JSON.parse(aws(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_VERIFIER.roleName}/[^/]+$`));
  const authenticated = authenticateFailedAppOnlyVerifierTask({ inputs, registration: journals.registration,
    permission: journals.permission, execution: journals.execution, taskArn: options.journalReference.taskArn,
    run: aws, repositoryRoot });
  assert.equal(authenticated.registrationJournalSha256, options.journalReference.registrationJournalSha256);
  assert.equal(authenticated.permissionJournalSha256, options.journalReference.permissionJournalSha256);
  assert.equal(authenticated.executionJournalSha256, options.journalReference.executionJournalSha256);
  authorize();
  const diagnostic = readFailedAppOnlyVerifierDiagnostic({ run: aws, authenticated, inputs });
  authorize();
  const body = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_FAILED_TASK_DIAGNOSTIC", sourceSha,
    currentSourceSha, originalRunId: String(options.journalReference.runId),
    taskArn: options.journalReference.taskArn, taskDefinitionArn: authenticated.task.taskDefinitionArn,
    verifierImageDigest: inputs.preparation.identity.verifierImageDigest, exitCode: 1,
    preparationSha256: inputs.preparation.preparationSha256,
    registrationJournalSha256: authenticated.registrationJournalSha256,
    permissionJournalSha256: authenticated.permissionJournalSha256,
    executionJournalSha256: authenticated.executionJournalSha256,
    logGroup: authenticated.logGroup, logStream: authenticated.stream,
    approvalSha256: approval.evidenceSha256, diagnostic };
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-verifier-diagnostic-")); fs.chmodSync(directory, 0o700);
  const result = { ...body, resultSha256: canonicalSha256(body) };
  const file = writeStageBPrivateFileExclusive({ filePath: path.join(directory, "app-only-verifier-diagnostic.json"),
    repositoryRoot, bytes: Buffer.from(`${JSON.stringify(result)}\n`) });
  assert.ok(process.env.GITHUB_OUTPUT);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `path=${file.path}\nsha256=${file.sha256}\n`);
  process.stdout.write(`${JSON.stringify({ status: "FAILED_VERIFIER_DIAGNOSTIC_AUTHENTICATED", phase: diagnostic.phase,
    operation: diagnostic.operation, resultSha256: result.resultSha256 })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("APP_ONLY_VERIFIER_DIAGNOSTIC_RECOVERY_FAILED; do not relaunch the verifier.\n"); process.exitCode = 1; });
