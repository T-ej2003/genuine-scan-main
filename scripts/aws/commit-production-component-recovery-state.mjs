#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "./production-component-deployment-state.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { captureBackendServiceSnapshot } from "./production-app-only-contract.mjs";
import { BACKEND_HEALTH_RECOVERY, assertBackendHealthRecoveryTaskArn, assertLegacyBackendRecoveryEvidence } from "./production-backend-health-recovery-contract.mjs";
import { taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

export function assertCompletedBackendRecoveryEvidence(value) {
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

export function commitBackendRecoveryComponentState({ evidence, client, run, readers = createAppOnlyEcsReaders(run, { assertDefinitionArn: assertBackendHealthRecoveryTaskArn }), isProtectedMainAncestor, writerContext } = {}) {
  assertCompletedBackendRecoveryEvidence(evidence);
  const state = client.read(); assert.ok(state, "Production component deployment state is not bootstrapped.");
  const snapshot = readers.readLive();
  assertBackendHealthRecoveryTaskArn(snapshot.definition.taskDefinitionArn);
  assert.equal(snapshot.definition.family, BACKEND_HEALTH_RECOVERY.family);
  assert.equal(snapshot.definition.status, "ACTIVE");
  assert.equal(taskDefinitionFingerprint(snapshot.definition), evidence.candidateFingerprint, "Recovered task definition differs from authenticated candidate");
  const containers = snapshot.definition.containerDefinitions.filter(({ name }) => name === BACKEND_HEALTH_RECOVERY.container);
  assert.equal(containers.length, 1);
  assert.equal(containers[0].image, `${BACKEND_HEALTH_RECOVERY.account}.dkr.ecr.${BACKEND_HEALTH_RECOVERY.region}.amazonaws.com/${BACKEND_HEALTH_RECOVERY.repository}@${evidence.recoveryImageDigest}`);
  const live = captureBackendServiceSnapshot(snapshot, evidence.recoveryImageDigest);
  const sourceSha = readers.readBackendImageSource(live.backendDigest);
  assert.equal(sourceSha, evidence.imageReleaseSha); const component = authenticatedBackendRecoveryComponent(live, evidence); assert.equal(isProtectedMainAncestor(sourceSha), true, "Recovered backend source is not protected-main history."); assert.equal(isProtectedMainAncestor(evidence.sourceSha), true, "Recovery completion source is not protected-main history.");
  return advanceProductionComponentDeploymentStateWithRetry({ client, current: state, lane: "EMERGENCY_RECOVERY", recovery: true,
    changes: { backend: component },
    emergencyCompletion: { mode: "backend-health-recovery", sourceSha: evidence.sourceSha, evidenceSha256: evidence.evidenceSha256 },
    authenticateRecovery: ({ next }) => { assert.equal(next.sourceSha, sourceSha); assert.equal(next.establishedThroughSha, evidence.sourceSha); }, ...writerContext });
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
  const result = commitBackendRecoveryComponentState({ evidence, run, client: createProductionComponentDeploymentStateClient({ run }), writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID }, isProtectedMainAncestor: (sourceSha) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  process.stdout.write(`${JSON.stringify({ generation: result.state.generation, component: "backend", sourceSha: result.state.components.backend.sourceSha, establishedThroughSha: result.state.components.backend.establishedThroughSha })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
