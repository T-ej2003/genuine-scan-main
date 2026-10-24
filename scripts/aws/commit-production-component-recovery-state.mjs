#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "./production-component-deployment-state.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { captureBackendServiceSnapshot } from "./production-app-only-contract.mjs";
import { BACKEND_HEALTH_RECOVERY, assertBackendHealthRecoveryTaskArn, assertLegacyBackendRecoveryEvidence } from "./production-backend-health-recovery-contract.mjs";
import { GREEN_BACKEND_TASK_ARN } from "./production-green-backend-health-recovery.mjs";
import { appOnlyDefinitionSha256 } from "./production-app-only-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { createReleaseCoordinatorStore } from "./production-release-evidence-store.mjs";
import { taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

export function assertCompletedBackendRecoveryEvidence(value) {
  if (value?.kind === "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE") {
    const { evidenceSha256, ...body } = value;
    assert.equal(value.schemaVersion, 1); assert.equal(evidenceSha256, canonicalSha256(body));
    assert.match(value.sourceSha || "", /^[a-f0-9]{40}$/);
    assert.match(value.imageDigest || "", /^sha256:[a-f0-9]{64}$/);
    assert.match(value.originalTaskDefinitionArn || "", GREEN_BACKEND_TASK_ARN);
    assert.match(value.targetTaskDefinitionArn || "", GREEN_BACKEND_TASK_ARN);
    assert.match(value.operationId || "", /^[a-f0-9]{64}$/);
    assert.equal(value.operationId, canonicalSha256({ kind: "BACKEND_HEALTH_RECOVERY_GREEN_CANDIDATE",
      sourceSha: value.sourceSha, taskDefinitionArn: value.originalTaskDefinitionArn, imageDigest: value.imageDigest }));
    assert.equal(value.completionSha256, canonicalSha256(value.completion));
    assert.equal(value.completion?.sourceSha, value.sourceSha);
    assert.equal(value.completion?.sourceTaskDefinitionArn, value.originalTaskDefinitionArn);
    assert.equal(value.completion?.targetTaskDefinitionArn, value.targetTaskDefinitionArn);
    assert.equal(value.completion?.imageDigest, value.imageDigest);
    assert.equal(value.completion?.operationId, value.operationId);
    assert.equal(value.completion?.candidateFingerprint, value.candidateFingerprint);
    assert.equal(value.completion?.health?.healthy, true);
    return value;
  }
  assertLegacyBackendRecoveryEvidence(value, { ...value, account: BACKEND_HEALTH_RECOVERY.account, region: BACKEND_HEALTH_RECOVERY.region });
  assert.equal(value.status, "RECOVERY_COMPLETE");
  assertBackendHealthRecoveryTaskArn(value.targetArn);
  return value;
}
export const readEvidence = (file) => assertCompletedBackendRecoveryEvidence(JSON.parse(fs.readFileSync(file, "utf8")));

export function authenticatedBackendRecoveryComponent(live, evidence) {
  assertCompletedBackendRecoveryEvidence(evidence);
  assert.equal(live.backendDigest, evidence.recoveryImageDigest); assert.equal(live.taskDefinitionArn, evidence.targetArn);
  return { sourceSha: evidence.imageReleaseSha, establishedThroughSha: evidence.sourceSha, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: live.desiredCount };
}

export function commitBackendRecoveryComponentState({ evidence, client, run, readers, store, isProtectedMainAncestor, writerContext } = {}) {
  assertCompletedBackendRecoveryEvidence(evidence);
  const green = evidence.kind === "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE";
  readers ||= createAppOnlyEcsReaders(run, { assertDefinitionArn: green ? (arn) => assert.match(arn, GREEN_BACKEND_TASK_ARN) : assertBackendHealthRecoveryTaskArn });
  let authorizedConfiguration;
  let authorizedDesiredCount;
  if (green) {
    assert.ok(store && typeof store.readOperation === "function", "Green recovery requires authoritative durable journal readback");
    const complete = store.readOperation(evidence.operationId, "BACKEND:RECOVERY:COMPLETE");
    assert.deepEqual(complete, evidence.completion, "Green recovery artifact differs from durable completion");
    const predecessor = store.readOperation(evidence.operationId, "BACKEND:PREDECESSOR");
    assert.equal(predecessor?.sourceSha, evidence.sourceSha);
    assert.equal(predecessor?.taskDefinitionArn, evidence.originalTaskDefinitionArn);
    assert.equal(predecessor?.candidateFingerprint, evidence.candidateFingerprint);
    assert.equal(predecessor?.failureProofSha256, canonicalSha256(predecessor.failureProof));
    authorizedConfiguration = predecessor.serviceConfigurationSha256;
    authorizedDesiredCount = predecessor.failureProof.desiredCount;
    assert.match(authorizedConfiguration || "", /^[a-f0-9]{64}$/, "Durable recovery service fingerprint is missing");
    assert.equal(authorizedDesiredCount, 2, "Durable recovery desired count is not authorized");
    assert.equal(complete.serviceConfigurationSha256, authorizedConfiguration);
    for (const phase of ["BACKEND:REGISTER", "BACKEND:UPDATE"]) {
      const dispatch = store.readOperation(evidence.operationId, `${phase}:DISPATCH`);
      assert.equal(dispatch?.sourceSha, evidence.sourceSha); assert.equal(dispatch?.imageDigest, evidence.imageDigest);
      assert.match(dispatch?.authorizationSha256 || "", /^[a-f0-9]{64}$/);
      assert.equal(dispatch?.operationId, evidence.operationId);
      assert.equal(dispatch?.candidateFingerprint, evidence.candidateFingerprint);
      assert.equal(dispatch?.serviceConfigurationSha256, authorizedConfiguration);
      const authorization = store.readOperation(evidence.operationId, `BACKEND:AUTHORIZATION:${phase}:${dispatch.authorizationSha256}`);
      assert.equal(authorization?.phase, phase);
      assert.equal(authorization?.input?.approval?.authorizationSha256, dispatch.authorizationSha256);
      assert.equal(authorization?.input?.sourceSha, evidence.sourceSha);
      assert.equal(authorization?.input?.recoveryImageDigest, evidence.imageDigest);
      assert.equal(authorization?.input?.serviceConfigurationSha256, authorizedConfiguration);
      assert.equal(authorization?.input?.approval?.serviceConfigurationSha256, authorizedConfiguration);
      const native = store.readOperation(evidence.operationId, `${phase}:COMPLETED`);
      assert.ok(native, `${phase} native completion is missing`);
      assert.equal(native.taskDefinitionArn, evidence.targetTaskDefinitionArn);
      assert.equal(native.intent?.operationId, evidence.operationId);
      assert.equal(native.intent?.candidateFingerprint, evidence.candidateFingerprint);
      assert.equal(native.intent?.serviceConfigurationSha256, authorizedConfiguration);
    }
  }
  const assertAuthorizedGreenSnapshot = (snapshot) => {
    const live = captureBackendServiceSnapshot(snapshot, evidence.imageDigest);
    assert.equal(live.taskDefinitionArn, evidence.targetTaskDefinitionArn, "Recovered backend task definition changed");
    assert.equal(live.desiredCount, authorizedDesiredCount, "Recovered backend desired count changed");
    assert.equal(live.serviceConfigurationSha256, authorizedConfiguration, "Recovered backend service configuration changed");
    assert.equal(live.definitionSha256, evidence.candidateFingerprint, "Recovered backend definition changed");
    return live;
  };
  const state = client.read(); assert.ok(state, "Production component deployment state is not bootstrapped.");
  if (green) assert.ok(state.components?.backend, "Green recovery requires a bootstrapped backend component");
  const snapshot = readers.readLive();
  if (green) assert.match(snapshot.definition.taskDefinitionArn, GREEN_BACKEND_TASK_ARN);
  else assertBackendHealthRecoveryTaskArn(snapshot.definition.taskDefinitionArn);
  assert.equal(snapshot.definition.family, green ? "mscqr-production-rls-green-backend-candidate" : BACKEND_HEALTH_RECOVERY.family);
  assert.equal(snapshot.definition.status, "ACTIVE");
  assert.equal(green ? appOnlyDefinitionSha256(snapshot.definition) : taskDefinitionFingerprint(snapshot.definition),
    evidence.candidateFingerprint, "Recovered task definition differs from authenticated candidate");
  const containers = snapshot.definition.containerDefinitions.filter(({ name }) => name === BACKEND_HEALTH_RECOVERY.container);
  assert.equal(containers.length, 1);
  const digest = green ? evidence.imageDigest : evidence.recoveryImageDigest;
  assert.equal(containers[0].image, `${BACKEND_HEALTH_RECOVERY.account}.dkr.ecr.${BACKEND_HEALTH_RECOVERY.region}.amazonaws.com/${BACKEND_HEALTH_RECOVERY.repository}@${digest}`);
  const live = green ? assertAuthorizedGreenSnapshot(snapshot) : captureBackendServiceSnapshot(snapshot, digest);
  const sourceSha = readers.readBackendImageSource(live.backendDigest);
  assert.equal(sourceSha, green ? evidence.sourceSha : evidence.imageReleaseSha);
  const component = green ? { sourceSha, establishedThroughSha: evidence.sourceSha, imageDigest: digest,
    taskDefinitionArn: evidence.targetTaskDefinitionArn, desiredCount: live.desiredCount } : authenticatedBackendRecoveryComponent(live, evidence);
  assert.equal(live.taskDefinitionArn, component.taskDefinitionArn);
  assert.equal(isProtectedMainAncestor(sourceSha), true, "Recovered backend source is not protected-main history."); assert.equal(isProtectedMainAncestor(evidence.sourceSha), true, "Recovery completion source is not protected-main history.");
  return advanceProductionComponentDeploymentStateWithRetry({ client, current: state, lane: "EMERGENCY_RECOVERY", recovery: true,
    changes: { backend: component },
    emergencyCompletion: { mode: "backend-health-recovery", sourceSha: evidence.sourceSha, evidenceSha256: evidence.evidenceSha256 },
    authenticateRecovery: ({ next }) => {
      assert.equal(next.sourceSha, sourceSha); assert.equal(next.establishedThroughSha, evidence.sourceSha);
      if (green) assertAuthorizedGreenSnapshot(readers.readLive());
    }, ...writerContext });
}

function main() {
  const evidencePath = process.argv.slice(2).find((value) => value.startsWith("--evidence="))?.slice("--evidence=".length);
  assert.ok(evidencePath && path.isAbsolute(evidencePath)); assert.deepEqual(process.argv.slice(2), [`--evidence=${evidencePath}`]);
  assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/release-gate\.yml@refs\/heads\/main$/); assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: PRODUCTION_COMPONENT_STATE.region });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  assert.equal(String(caller.Account), PRODUCTION_COMPONENT_STATE.account); assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.."); const evidence = readEvidence(evidencePath);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-green-recovery-commit-")); fs.chmodSync(directory, 0o700);
  const store = evidence.kind === "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE" ? createReleaseCoordinatorStore({ run, directory, repositoryRoot: root }) : undefined;
  const result = commitBackendRecoveryComponentState({ evidence, run, store, client: createProductionComponentDeploymentStateClient({ run }), writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID }, isProtectedMainAncestor: (sourceSha) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  fs.rmSync(directory, { recursive: true, force: true });
  process.stdout.write(`${JSON.stringify({ generation: result.state.generation, component: "backend", sourceSha: result.state.components.backend.sourceSha, establishedThroughSha: result.state.components.backend.establishedThroughSha })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
