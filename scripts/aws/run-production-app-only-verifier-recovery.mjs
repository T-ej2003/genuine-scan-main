#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY, assertAppOnlyCas, captureAppOnlyPredecessor } from "./production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { parseAppOnlyArtifactReference, downloadAppOnlyArtifact, downloadAppOnlyVerifierJournals,
  createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence,
  assertProductionEnvironmentActualReviewer } from "./production-github-environment-approval.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner,
  PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createAppOnlyEcsReaders, executeAppOnlyVerifierTask, readAppOnlyVerifierResult } from "./production-app-only-adapters.mjs";
import { verifyAppOnlyEffectivePermissions } from "./production-app-only-provisioning.mjs";
import { recoverCompletedAppOnlyVerifierRegistration, assertRecoveredAppOnlyVerifierRegistration } from "./production-app-only-verifier-recovery.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const repository = "T-ej2003/genuine-scan-main";
let failureStage = "ARGS";

export function parseAppOnlyVerifierRecoveryArgs(args, env = process.env) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: Object.fromEntries(["mode", "source-sha", "preparation-reference", "journal-reference", "approval",
      "approval-sha256", "recovery", "recovery-sha256"].map((name) => [name, { type: "string" }])) });
  assert.ok(["recover", "verify-recovered"].includes(values.mode));
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, repository);
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyVerifierWorkflowRef);
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1"); assert.match(env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.equal(values["source-sha"], env.GITHUB_SHA);
  const reference = parseAppOnlyArtifactReference(values["preparation-reference"]);
  assert.match(values["approval-sha256"] || "", /^[a-f0-9]{64}$/); assert.ok(path.isAbsolute(values.approval || ""));
  assert.ok(typeof values["journal-reference"] === "string" && Buffer.byteLength(values["journal-reference"]) <= 2048);
  const journal = JSON.parse(values["journal-reference"]);
  assert.deepEqual(Object.keys(journal || {}).sort(), ["sourceSha", "runId", "artifactId", "artifactDigest",
    "registrationJournalSha256", "permissionJournalSha256"].sort());
  assert.equal(journal.sourceSha, reference.sourceSha);
  if (values.mode === "verify-recovered") {
    assert.ok(path.isAbsolute(values.recovery || "")); assert.match(values["recovery-sha256"] || "", /^[a-f0-9]{64}$/);
  } else { assert.equal(values.recovery, undefined); assert.equal(values["recovery-sha256"], undefined); }
  return { ...values, reference, journal };
}

function output(name, value) {
  assert.match(name, /^[a-z_]+$/); assert.ok(typeof value === "string" && !/[\r\n]/.test(value));
  assert.ok(process.env.GITHUB_OUTPUT); fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

async function main() {
  const options = parseAppOnlyVerifierRecoveryArgs(process.argv.slice(2));
  failureStage = "SOURCE";
  const currentSourceSha = options["source-sha"], sourceSha = options.reference.sourceSha;
  const githubRun = createProductionGithubCommandRunner();
  const source = () => {
    assertProtectedCheckout({ sourceSha: currentSourceSha, repositoryRoot });
    const main = JSON.parse(githubRun("gh", ["api", `repos/${repository}/branches/main`]));
    assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, currentSourceSha);
    execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, currentSourceSha], { cwd: repositoryRoot, timeout: 10000 });
    return true;
  };
  source();
  failureStage = "ORIGINAL_EVIDENCE";
  const original = downloadAppOnlyArtifact({ kind: "verifierPreparation", reference: options.reference, repositoryRoot, githubRun });
  const inputs = JSON.parse(original.bytes);
  const journals = downloadAppOnlyVerifierJournals({ reference: options.journal, githubRun });
  const approval = readBoundStageBPrivateJson({ filePath: options.approval,
    expectedSha256: options["approval-sha256"], repositoryRoot });
  const context = { sourceSha: currentSourceSha, repository, environment: "production",
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.appOnlyVerifierWorkflowRef,
    eventName: process.env.GITHUB_EVENT_NAME, workflowRunId: process.env.GITHUB_RUN_ID,
    workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT, executionActor: process.env.GITHUB_ACTOR,
    githubActions: process.env.GITHUB_ACTIONS };
  const authorization = () => {
    source(); assertProductionEnvironmentApprovalEvidence(approval, context);
    assertProductionEnvironmentActualReviewer(approval, context);
    assertAppOnlyCas(inputs.preparation.predecessor, captureAppOnlyPredecessor(createAppOnlyEcsReaders(run).readLive()));
  };
  const previousApprovals = JSON.parse(githubRun("gh", ["api", `repos/${repository}/actions/runs/${options.journal.runId}/approvals`]));
  assert.ok(previousApprovals.some(({ state, environments, user }) => state === "approved"
    && Number.isSafeInteger(user?.id) && user.id > 0
    && environments?.some(({ id, name }) => name === "production" && id === approval.environmentId)),
  "Original protected verifier approval is absent");
  failureStage = "CURRENT_AUTHORIZATION";
  const credentialSource = options.mode === "recover"
    ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER
    : PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION;
  const run = createProductionAwsCommandRunner({ credentialSource,
    exec: (command, args, opts) => execFileSync(command, args, { ...opts, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  const role = options.mode === "recover" ? APP_ONLY_PROVISIONING.roleName : APP_ONLY_VERIFIER.roleName;
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${role}/[^/]+$`));
  authorization();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-verifier-recovery-")); fs.chmodSync(directory, 0o700);
  const publish = (name, body) => {
    const result = { ...body, resultSha256: canonicalSha256(body) };
    const file = writeStageBPrivateFileExclusive({ filePath: path.join(directory, name), repositoryRoot,
      bytes: Buffer.from(`${JSON.stringify(result)}\n`) });
    output("path", file.path); output("sha256", file.sha256);
  };
  if (options.mode === "recover") {
    failureStage = "LIVE_REGISTRATION_AND_IAM";
    const result = recoverCompletedAppOnlyVerifierRegistration({ inputs, sourceSha, currentSourceSha,
      registrationJournal: journals.registration, permissionJournal: journals.permission, run, repositoryRoot,
      isProtectedAncestor: source, originalRunId: options.journal.runId });
    authorization();
    publish("app-only-verifier-registration-recovery.json", result);
    return;
  }
  const recovered = readBoundStageBPrivateJson({ filePath: options.recovery,
    expectedSha256: options["recovery-sha256"], repositoryRoot });
  assertRecoveredAppOnlyVerifierRegistration({ result: recovered, inputs, sourceSha, currentSourceSha,
    originalRunId: options.journal.runId, registrationJournal: journals.registration,
    permissionJournal: journals.permission, run, repositoryRoot });
  const effective = verifyAppOnlyEffectivePermissions({ run, verifierArn: recovered.taskDefinitionArn,
    predecessorArn: inputs.preparation.predecessor.taskDefinitionArn, phase: "VERIFIER" });
  assert.deepEqual(effective, journals.permission[2].event.effective);
  failureStage = "VERIFIER_EXECUTION";
  const verifier = { requirements: inputs.requirements, identity: inputs.preparation.identity, repositoryRoot,
    databaseSecretArn: inputs.preparation.databaseSecretArn };
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha: currentSourceSha,
    preparationSha256: inputs.preparation.preparationSha256 });
  output("journal", journal.directory);
  const clientToken = canonicalSha256({ sourceSha, preparationSha256: inputs.preparation.preparationSha256 });
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: recovered.taskDefinitionArn, launchType: "FARGATE", count: 1,
    enableExecuteCommand: false, clientToken, networkConfiguration: appOnlyVerifierNetwork() };
  const execution = await executeAppOnlyVerifierTask({ run, taskDefinitionArn: recovered.taskDefinitionArn,
    clientToken, request, verifier, authenticate: authorization, writeEvidence: journal.writeEvidence });
  const database = await readAppOnlyVerifierResult({ run, execution, verifier });
  failureStage = "DATABASE_RESULT";
  authorization();
  await journal.writeEvidence({ status: "COMPATIBILITY_VERIFIED", taskArn: execution.task.taskArn,
    databaseEvidenceSha256: database.evidenceSha256 });
  publish("app-only-compatibility-recovered.json", { schemaVersion: 1, kind: "APP_ONLY_VERIFIED_COMPATIBILITY_RECOVERED",
    sourceSha, currentSourceSha, generatedAt: new Date().toISOString(), inputs, recovery: recovered,
    approvalSha256: approval.evidenceSha256, taskArn: execution.task.taskArn,
    taskDefinitionArn: recovered.taskDefinitionArn, database });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write(`APP_ONLY_VERIFIER_RECOVERY_${failureStage}_FAILED; preserve journals and inspect live state before retry.\n`); process.exitCode = 1; });
