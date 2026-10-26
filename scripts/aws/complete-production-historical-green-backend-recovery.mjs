#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { APP_ONLY, appOnlyDefinitionSha256, assertRegisteredAppOnlyCandidate } from "./production-app-only-contract.mjs";
import { downloadAppOnlyArtifact, parseAppOnlyArtifactReference } from "./production-app-only-artifacts.mjs";
import { authenticateAppOnlyVerifierResult } from "./production-app-only-verifier-command.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { commitBackendRecoveryComponentState } from "./commit-production-component-recovery-state.mjs";
import { createProductionComponentDeploymentStateClient } from "./production-component-deployment-state.mjs";
import { createProductionAwsCredentialEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentActualReviewer, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";
import { assertGreenRecoveryAlbTargets, runGreenRecoveryCommand } from "./recover-production-green-backend-health.mjs";
import { verifyProductionBackendHealth } from "./recover-production-backend-health.mjs";
import { GREEN_BACKEND_TASK_ARN, assertGreenBackendRecoveryAuthorization } from "./production-green-backend-health-recovery.mjs";
import { completeHistoricalGreenBackendRecovery } from "./production-green-backend-historical-completion.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { createReleaseCoordinatorStore } from "./production-release-evidence-store.mjs";
import { PRODUCTION_CLIENT_IP_TRUST } from "./production-client-ip-trust-runtime.mjs";
import { NORMAL_DEPLOYER_POLICY, readNormalDeployerPolicyState } from "./converge-production-normal-deployer-policy.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const at = argv.indexOf(name); const value = at < 0 ? null : argv[at + 1]; assert.ok(value && !value.startsWith("--"), `${name} is required`); return value; };
const ancestor = (sha) => { try { execFileSync("git", ["merge-base", "--is-ancestor", sha, "origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; } };

export async function runHistoricalGreenCompletionCli(argv = process.argv.slice(2), deps = {}) {
  const names = ["--current-source-sha", "--operation-id", "--original-source-sha", "--original-run-id", "--ticket",
    "--original-task-definition", "--target-task-definition", "--image-digest", "--cloudtrail-event-id",
    "--expected-component-generation", "--environment-approval", "--environment-approval-sha256", "--evidence-out"];
  assert.equal(argv.length, names.length * 2);
  assert.deepEqual([...new Set(argv.filter((_, index) => index % 2 === 0))].sort(), [...names].sort());
  const env = deps.env || process.env;
  const currentSourceSha = required(argv, "--current-source-sha");
  const protectedMain = (deps.readProtectedMain || readFreshProtectedMainIdentity)({ cwd: root, expectedSourceSha: currentSourceSha });
  assert.equal(protectedMain.headSha, currentSourceSha);
  assert.equal(protectedMain.freshRemoteMainSha, currentSourceSha);
  assert.equal(env.GITHUB_WORKFLOW_REF, PRODUCTION_ENVIRONMENT_APPROVAL.historicalGreenCompletionWorkflowRef);
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.equal(env.MSCQR_AWS_CREDENTIAL_SOURCE, PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_NORMAL_DEPLOYER);
  createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_NORMAL_DEPLOYER, env });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_NORMAL_DEPLOYER, region: APP_ONLY.region });
  const aws = (args) => JSON.parse(run([...args, "--region", APP_ONLY.region, "--output", "json", "--no-cli-pager"]));
  const caller = aws(["sts", "get-caller-identity"]);
  assert.equal(String(caller.Account), APP_ONLY.account);
  assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-normal-deployer\/GitHubActions$/);
  assert.equal(readNormalDeployerPolicyState({ run }).policySha256, NORMAL_DEPLOYER_POLICY.targetSha256,
    "Normal-deployer policy does not match the reviewed historical-completion authority");
  const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")),
    expectedSha256: required(argv, "--environment-approval-sha256"), repositoryRoot: root, label: "Historical recovery approval" });
  const approvalContext = { sourceSha: currentSourceSha, repository: env.GITHUB_REPOSITORY,
    environment: "production-normal-deploy", workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME,
    workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT,
    executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS };
  const verifyFreshApproval = () => {
    assertProductionEnvironmentApprovalEvidence(approval, { ...approvalContext, now: new Date() });
    assertProductionEnvironmentActualReviewer(approval, { sourceSha: currentSourceSha,
      repository: env.GITHUB_REPOSITORY, executionActor: env.GITHUB_ACTOR });
  };
  verifyFreshApproval();
  const input = { operationId: required(argv, "--operation-id"), originalSourceSha: required(argv, "--original-source-sha"),
    originalRunId: required(argv, "--original-run-id"), ticket: required(argv, "--ticket"),
    originalTaskDefinitionArn: required(argv, "--original-task-definition"),
    targetTaskDefinitionArn: required(argv, "--target-task-definition"), imageDigest: required(argv, "--image-digest"),
    cloudTrailEventId: required(argv, "--cloudtrail-event-id"),
    expectedComponentGeneration: Number(required(argv, "--expected-component-generation")) };
  assert.equal(Number.isSafeInteger(input.expectedComponentGeneration), true);
  const originalRunResponse = await (deps.fetchImpl || fetch)(`https://api.github.com/repos/${env.GITHUB_REPOSITORY}/actions/runs/${input.originalRunId}`, {
    headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28" },
  });
  assert.equal(originalRunResponse.ok, true, "Original Release Gate run is unavailable");
  const originalRun = await originalRunResponse.json();
  assert.equal(originalRun.id, Number(input.originalRunId));
  assert.equal(originalRun.head_sha, input.originalSourceSha);
  assert.equal(originalRun.path, ".github/workflows/release-gate.yml");
  assert.equal(originalRun.event, "workflow_dispatch");
  assert.equal(originalRun.head_branch, "main");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-historical-green-completion-"));
  fs.chmodSync(directory, 0o700);
  try {
    const store = (deps.createStore || createReleaseCoordinatorStore)({ run, directory, repositoryRoot: root, namespace: "green-backend-recovery" });
    const readers = createAppOnlyEcsReaders(run, { assertDefinitionArn: (arn) => assert.match(arn, GREEN_BACKEND_TASK_ARN) });
    const client = createProductionComponentDeploymentStateClient({ run });
    const imageVerifier = (value) => verifyImageEvidenceSignature({ ...value, verify: createPinnedRootAttestationVerifier() });
    const verifyOriginalAuthorization = async (record, dispatchAt) => {
      const reference = parseAppOnlyArtifactReference(JSON.stringify(record.databaseReference));
      const artifact = downloadAppOnlyArtifact({ kind: "compatibility", reference, repositoryRoot: root });
      const database = JSON.parse(artifact.bytes);
      assert.equal(database.resultSha256, record.input.databaseCompatibility.resultSha256);
      assert.equal(database.sourceSha, input.originalSourceSha);
      assert.equal(database.database?.identity?.candidateDigest, input.imageDigest);
      authenticateAppOnlyVerifierResult({ message: JSON.stringify(database.database), identity: database.database.identity,
        requirementsSha256: database.inputs.requirements.requirementsSha256,
        verificationContractSha256: database.inputs.preparation.verificationContractSha256,
        now: Date.parse(database.database.generatedAt) });
      assertGreenBackendRecoveryAuthorization(record.input, { now: dispatchAt, verifyImageEvidence: imageVerifier,
        githubContext: record.githubContext });
    };
    const verifyCurrent = (_input, service) => {
      const live = readers.readLive();
      assert.equal(live.service.taskDefinition, input.targetTaskDefinitionArn);
      assert.deepEqual(live.service.deployments, service.deployments, "Backend deployment changed during health readback");
      assert.equal(live.tasks.length, 2);
      assert.equal(appOnlyDefinitionSha256(live.definition), store.readOperation(input.operationId, "BACKEND:PREDECESSOR").candidateFingerprint);
      for (const task of live.tasks) {
        assert.equal(task.lastStatus, "RUNNING");
        assert.equal(task.healthStatus, "HEALTHY");
        assert.equal(task.taskDefinitionArn, input.targetTaskDefinitionArn);
        assert.equal(task.containers?.find(({ name }) => name === "backend")?.imageDigest, input.imageDigest);
      }
      assertGreenRecoveryAlbTargets(live, aws(["elbv2", "describe-target-health", "--target-group-arn", PRODUCTION_CLIENT_IP_TRUST.targetGroupArn]));
      return verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready",
        (command, args) => runGreenRecoveryCommand(command, args, { environment: env }), input.originalSourceSha);
    };
    const result = await completeHistoricalGreenBackendRecovery(input, {
      store, verifyOriginalSource: async (sha) => {
        assert.equal(ancestor(sha), true, "Historical recovery source is not protected-main ancestry");
        assert.equal(ancestor(currentSourceSha), true);
      },
      verifyOriginalAuthorization, verifyFreshApproval,
      verifyRegisteredRevision: async (registration) => {
        const original = readers.readDefinition(input.originalTaskDefinitionArn);
        const target = readers.readDefinition(input.targetTaskDefinitionArn);
        assertRegisteredAppOnlyCandidate(original, target, input.imageDigest);
        assert.equal(registration.taskDefinitionArn, target.taskDefinitionArn);
        assert.match(target.registeredBy || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
        assert.ok(Date.parse(target.registeredAt) >= Date.parse(store.readOperationCommittedAt(input.operationId, "BACKEND:REGISTER:DISPATCH")) - 1000,
          "Registered task definition predates its original dispatch");
      },
      readCloudTrailEvent: async (id) => {
        const result = aws(["cloudtrail", "lookup-events", "--lookup-attributes", `AttributeKey=EventId,AttributeValue=${id}`]);
        assert.equal(result.Events?.length, 1, "Historical UpdateService CloudTrail event is missing or ambiguous");
        return JSON.parse(result.Events[0].CloudTrailEvent);
      },
      readService: readers.readService, verifyCurrent, readComponentState: client.read,
      commitComponentState: (evidence) => commitBackendRecoveryComponentState({ evidence, run, readers, store,
        client: { read: client.read, advance: (current, next) => {
          verifyFreshApproval();
          verifyCurrent(input, readers.readService());
          return client.advance(current, next);
        } },
        isProtectedMainAncestor: ancestor, writerContext: { updatedByWorkflow: env.GITHUB_WORKFLOW_REF, githubRunId: env.GITHUB_RUN_ID } }),
    });
    const evidenceOut = path.resolve(required(argv, "--evidence-out"));
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false,
      files: [{ filePath: evidenceOut, bytes: Buffer.from(`${JSON.stringify(result.evidence)}\n`), label: "Historical green recovery completion" }] });
    return { status: "HISTORICAL_GREEN_RECOVERY_COMPLETE", operationId: result.operationId,
      generation: result.componentState.generation, taskDefinitionArn: result.taskDefinitionArn,
      evidenceSha256: result.evidence.evidenceSha256 };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href)
  runHistoricalGreenCompletionCli().then((value) => process.stdout.write(`${JSON.stringify(value)}\n`))
    .catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
