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
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { authenticateAppOnlyVerifierInputs } from "./production-app-only-preparation.mjs";
import { parseAppOnlyArtifactReference, downloadAppOnlyArtifact, createAppOnlyEvidenceWriter } from "./production-app-only-artifacts.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { createAppOnlyAuthorization, assertAppOnlyAuthorization } from "./production-app-only-authorization.mjs";
import { createAppOnlyEcsReaders, registerAppOnlyVerifier, executeAppOnlyVerifierTask, readAppOnlyVerifierResult } from "./production-app-only-adapters.mjs";
import { prepareAppOnlyProvisioning, executeAppOnlyProvisioning, verifyAppOnlyEffectivePermissions } from "./production-app-only-provisioning.mjs";

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
export function parseAppOnlyVerifierExecutionArgs(args, env = process.env) {
  const { values } = parseArgs({ args, strict: true, allowPositionals: false,
    options: Object.fromEntries(["mode", "source-sha", "preparation-reference", "approval", "approval-sha256", "registration", "registration-sha256"].map((name) => [name, { type: "string" }])) });
  assert.ok(["register", "verify"].includes(values.mode));
  assert.equal(env.GITHUB_ACTIONS, "true"); assert.equal(env.GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main");
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_EVENT_NAME, "workflow_dispatch");
  assert.equal(env.GITHUB_WORKFLOW_REF, "T-ej2003/genuine-scan-main/.github/workflows/verify-production-app-only-compatibility.yml@refs/heads/main");
  assert.equal(env.GITHUB_RUN_ATTEMPT, "1"); assert.match(env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  assert.match(values["source-sha"] || "", /^[a-f0-9]{40}$/); assert.equal(values["source-sha"], env.GITHUB_SHA);
  const reference = parseAppOnlyArtifactReference(values["preparation-reference"]);
  assert.equal(reference.sourceSha, values["source-sha"]);
  assert.match(values["approval-sha256"] || "", /^[a-f0-9]{64}$/); assert.ok(path.isAbsolute(values.approval || ""));
  if (values.mode === "verify") {
    assert.match(values["registration-sha256"] || "", /^[a-f0-9]{64}$/); assert.ok(path.isAbsolute(values.registration || ""));
  } else { assert.equal(values.registration, undefined); assert.equal(values["registration-sha256"], undefined); }
  return { ...values, reference };
}

function output(name, value) {
  assert.match(name, /^[a-z_]+$/); assert.ok(typeof value === "string" && !/[\r\n]/.test(value));
  assert.ok(process.env.GITHUB_OUTPUT, "GitHub output channel required");
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

async function main() {
  const options = parseAppOnlyVerifierExecutionArgs(process.argv.slice(2));
  const sourceSha = options["source-sha"], githubRun = createProductionGithubCommandRunner();
  const source = () => {
    assertProtectedCheckout({ sourceSha, repositoryRoot });
    const main = JSON.parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
    assert.equal(main.name, "main"); assert.equal(main.protected, true); assert.equal(main.commit?.sha, sourceSha);
  };
  source();
  const artifact = downloadAppOnlyArtifact({ kind: "verifierPreparation", reference: options.reference, repositoryRoot, githubRun });
  const inputs = JSON.parse(artifact.bytes), preparation = inputs.preparation;
  const approval = readBoundStageBPrivateJson({ filePath: options.approval, expectedSha256: options["approval-sha256"], repositoryRoot });
  const authorization = createAppOnlyAuthorization({ phase: "VERIFIER", preparation, approval, env: process.env });
  const credentialSource = options.mode === "register" ? PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER : PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION;
  const run = createProductionAwsCommandRunner({ credentialSource,
    exec: (command, args, opts) => execFileSync(command, args, { ...opts, timeout: 30000, maxBuffer: 8 * 1024 * 1024 }) });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(caller.Account, APP_ONLY.account);
  const role = options.mode === "register" ? APP_ONLY_PROVISIONING.roleName : APP_ONLY_VERIFIER.roleName;
  assert.match(caller.Arn || "", new RegExp(`^arn:aws:sts::${APP_ONLY.account}:assumed-role/${role}/[^/]+$`));
  const readers = createAppOnlyEcsReaders(run);
  const authenticate = () => {
    source();
    assertAppOnlyAuthorization({ authorization, phase: "VERIFIER", preparation, approval, env: process.env });
    return authenticateAppOnlyVerifierInputs({ inputs, sourceSha, live: readers.readLive(), repositoryRoot });
  };
  const verifier = authenticate();
  const journal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: preparation.preparationSha256 });
  output("journal", journal.directory); // Published before any mutation for always-upload.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-app-only-verifier-result-")); fs.chmodSync(directory, 0o700);
  const publish = (name, body) => {
    const result = { ...body, resultSha256: canonicalSha256(body) };
    const file = writeStageBPrivateFileExclusive({ filePath: path.join(directory, name), repositoryRoot, bytes: Buffer.from(`${JSON.stringify(result)}\n`) });
    output("path", file.path); output("sha256", file.sha256);
  };
  if (options.mode === "register") {
    const registration = await registerAppOnlyVerifier({ run, preparation, verifier, authenticate, writeEvidence: journal.writeEvidence });
    const permissionPreparation = prepareAppOnlyProvisioning({ sourceSha, verifierArn: registration.taskDefinitionArn, phase: "VERIFIER", run });
    const permissionJournal = createAppOnlyEvidenceWriter({ repositoryRoot, sourceSha, preparationSha256: permissionPreparation.preparationSha256 });
    output("permission_journal", permissionJournal.directory);
    const permissions = await executeAppOnlyProvisioning({ preparation: permissionPreparation, sourceSha, run, authenticate,
      writeEvidence: permissionJournal.writeEvidence,
      verifyEffective: (phase) => verifyAppOnlyEffectivePermissions({ run, verifierArn: registration.taskDefinitionArn,
        predecessorArn: preparation.predecessor.taskDefinitionArn, phase }) });
    authenticate();
    publish("app-only-verifier-registration.json", { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_REGISTERED", sourceSha,
      workflowRunId: process.env.GITHUB_RUN_ID, workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT,
      preparationSha256: preparation.preparationSha256, registration, permissionPreparation, permissions, authorization });
    return;
  }
  const result = readBoundStageBPrivateJson({ filePath: options.registration, expectedSha256: options["registration-sha256"], repositoryRoot });
  const { resultSha256, ...registered } = result;
  assert.equal(resultSha256, canonicalSha256(registered));
  assert.equal(registered.kind, "APP_ONLY_VERIFIER_REGISTERED"); assert.equal(registered.schemaVersion, 1);
  assert.equal(registered.sourceSha, sourceSha); assert.equal(registered.workflowRunId, process.env.GITHUB_RUN_ID);
  assert.equal(registered.workflowRunAttempt, process.env.GITHUB_RUN_ATTEMPT);
  assert.equal(registered.preparationSha256, preparation.preparationSha256);
  assertAppOnlyAuthorization({ authorization: registered.authorization, phase: "VERIFIER", preparation, approval, env: process.env });
  assert.equal(registered.permissions.status, "VERIFIED"); assert.equal(registered.permissions.effective.verified, true);
  const taskDefinitionArn = registered.registration.taskDefinitionArn;
  assert.equal(registered.permissionPreparation.verifierArn, taskDefinitionArn);
  const clientToken = canonicalSha256({ sourceSha, preparationSha256: preparation.preparationSha256 });
  const request = { cluster: APP_ONLY.clusterArn, taskDefinition: taskDefinitionArn, launchType: "FARGATE", count: 1,
    enableExecuteCommand: false, clientToken, networkConfiguration: appOnlyVerifierNetwork() };
  const execution = await executeAppOnlyVerifierTask({ run, taskDefinitionArn, clientToken, request, verifier, authenticate, writeEvidence: journal.writeEvidence });
  const database = await readAppOnlyVerifierResult({ run, execution, verifier });
  authenticate(); assertAppOnlyCas(preparation.predecessor, captureAppOnlyPredecessor(readers.readLive()));
  await journal.writeEvidence({ status: "COMPATIBILITY_VERIFIED", taskArn: execution.task.taskArn, databaseEvidenceSha256: database.evidenceSha256 });
  publish("app-only-compatibility.json", { schemaVersion: 1, kind: "APP_ONLY_VERIFIED_COMPATIBILITY", sourceSha,
    generatedAt: new Date().toISOString(), inputs, authorization, registration: registered.registration,
    taskArn: execution.task.taskArn, taskDefinitionArn, database });
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url)
  main().catch(() => { process.stderr.write("App-only verifier stopped; retain journals and do not retry an ambiguous operation.\n"); process.exitCode = 1; });
