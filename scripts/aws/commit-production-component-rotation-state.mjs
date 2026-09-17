#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { advanceProductionComponentDeploymentStateWithRetry, createProductionComponentDeploymentStateClient, PRODUCTION_COMPONENT_STATE } from "./production-component-deployment-state.mjs";
import { readAndAssertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";
import { readBoundStageBPrivateJson } from "./stage-b-artifact-contract.mjs";
import { createAppOnlyEcsReaders } from "./production-app-only-adapters.mjs";
import { APP_ONLY, captureAppOnlyPredecessor } from "./production-app-only-contract.mjs";
import { assertGithubOidcReleaseDeployerEnvironment, createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const SHA = /^[a-f0-9]{40}$/, HASH = /^[a-f0-9]{64}$/;
const hash = (value) => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");

export function commitRotationComponentState({ mode, sourceSha, rotationId, rotationStateSha256, readinessFile, readinessSha256, deployment, readers, client, isProtectedMainAncestor, writerContext } = {}) {
  assert.ok(["rotation-overlap", "rotation-cleanup"].includes(mode)); assert.match(sourceSha || "", SHA); assert.match(rotationStateSha256 || "", HASH); assert.match(readinessSha256 || "", HASH);
  const readiness = readAndAssertReadyForOverlapDeployment({ filePath: readinessFile, evidenceSha256: readinessSha256, sourceSha, rotationId, rotationStateSha256 });
  assert.equal(isProtectedMainAncestor(sourceSha), true, "Rotation source is not protected-main history.");
  assert.match(writerContext?.githubRunId || "", /^[1-9][0-9]*$/);
  assert.match(writerContext?.githubRunAttempt || "", /^[1-9][0-9]*$/);
  const current = client.read(); assert.ok(current, "Production component deployment state is not bootstrapped.");
  for (const [key, expected] of Object.entries({ sourceSha, transitionMode: mode, rotationId, rotationStateSha256, readinessSha256, workflowRunId: writerContext.githubRunId, workflowRunAttempt: writerContext.githubRunAttempt }))
    assert.equal(deployment?.[key], expected, `Rotation deployment ${key} mismatch`);
  assert.equal(deployment.terminalState, mode === "rotation-overlap" ? "DEPLOYED_PENDING_VERIFICATION" : "DEPLOYED");
  assert.equal(deployment.updateServiceCount, 1);
  const live = captureAppOnlyPredecessor(readers.readLive());
  const metadata = deployment.metadata;
  assert.equal(deployment.taskDefinitionArn, readiness.evidence.overlapTaskDefinition.identityBindings.taskDefinitionArn);
  assert.equal(live.taskDefinitionArn, deployment.taskDefinitionArn);
  for (const [key, expected] of Object.entries({ mode: "existing-task-definition", clusterName: APP_ONLY.cluster, serviceName: APP_ONLY.service, containerName: APP_ONLY.container, newTaskDefinitionArn: live.taskDefinitionArn, observedTaskDefinitionArn: live.taskDefinitionArn, expectedImageDigest: live.backendDigest, observedImageDigest: live.backendDigest, desiredCount: live.desiredCount, runningCount: live.desiredCount, pendingCount: 0, serviceStable: true }))
    assert.equal(metadata?.[key], expected, `Rotation deployment metadata ${key} mismatch`);
  const imageSource = readers.readBackendImageSource(live.backendDigest);
  assert.equal(isProtectedMainAncestor(imageSource), true, "Rotated backend source is not protected-main history.");
  const backend = { sourceSha: imageSource, establishedThroughSha: sourceSha, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: live.desiredCount };
  const releaseIdentity = hash({ mode, sourceSha, rotationId, rotationStateSha256, readinessSha256, readiness: readiness.evidence });
  return advanceProductionComponentDeploymentStateWithRetry({ client, current, lane: "SECURITY_INFRASTRUCTURE", changes: { security: { sourceSha, releaseIdentity }, backend }, emergencyCompletion: { mode, sourceSha, evidenceSha256: releaseIdentity }, ...writerContext });
}

function main() {
  const values = Object.fromEntries(process.argv.slice(2).map((value) => value.split("=", 2)).filter(([key, value]) => key && value).map(([key, value]) => [key.replace(/^--/, ""), value]));
  assert.deepEqual(Object.keys(values).sort(), ["deployment", "deployment-sha256", "mode", "readiness", "readiness-sha256", "rotation-id", "rotation-state-sha256", "source-sha"]);
  assert.ok(path.isAbsolute(values.readiness)); assertGithubOidcReleaseDeployerEnvironment();
  assert.match(process.env.GITHUB_WORKFLOW_REF || "", /^T-ej2003\/genuine-scan-main\/.github\/workflows\/release-gate\.yml@refs\/heads\/main$/); assert.match(process.env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: PRODUCTION_COMPONENT_STATE.region });
  const caller = JSON.parse(run(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"])); assert.equal(String(caller.Account), PRODUCTION_COMPONENT_STATE.account); assert.match(caller.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const deployment = readBoundStageBPrivateJson({ filePath: values.deployment, expectedSha256: values["deployment-sha256"], label: "Rotation deployment result" });
  const result = commitRotationComponentState({ mode: values.mode, sourceSha: values["source-sha"], rotationId: values["rotation-id"], rotationStateSha256: values["rotation-state-sha256"], readinessFile: values.readiness, readinessSha256: values["readiness-sha256"], deployment, readers: createAppOnlyEcsReaders(run), client: createProductionComponentDeploymentStateClient({ run }), writerContext: { updatedByWorkflow: process.env.GITHUB_WORKFLOW_REF, githubRunId: process.env.GITHUB_RUN_ID, githubRunAttempt: process.env.GITHUB_RUN_ATTEMPT }, isProtectedMainAncestor: (source) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", source, "refs/remotes/origin/main"], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  } });
  process.stdout.write(`${JSON.stringify({ generation: result.state.generation, component: "security", sourceSha: result.state.components.security.sourceSha })}\n`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) main();
