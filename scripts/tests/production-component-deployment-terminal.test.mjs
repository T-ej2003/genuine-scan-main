import assert from "node:assert/strict";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { authenticatedBackendRecoveryComponent, commitBackendRecoveryComponentState, assertCompletedBackendRecoveryEvidence } from "../aws/commit-production-component-recovery-state.mjs";
import { completedBackendRecoveryEvidence } from "./fixtures/completed-backend-recovery-evidence.mjs";
import { taskDefinitionFingerprint } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { createAppOnlyEcsReaders } from "../aws/production-app-only-adapters.mjs";
import { assertBackendHealthRecoveryTaskArn } from "../aws/production-backend-health-recovery-contract.mjs";
import { commitRotationComponentState } from "../aws/commit-production-component-rotation-state.mjs";
import { commitSecurityComponentState } from "../aws/commit-production-component-security-state.mjs";
import { READY_FOR_OVERLAP_DEPLOYMENT_STAGES } from "../aws/production-overlap-readiness-contract.mjs";
import { writeOverlapReadinessEvidence } from "../aws/produce-production-overlap-readiness-evidence.mjs";
import { classifyNormalLiveComponentState } from "../aws/production-normal-release.mjs";

const source = "b".repeat(40), recoverySource = "c".repeat(40);
const state = () => createProductionComponentDeploymentState({ components: {
  backend: { sourceSha: "a".repeat(40), establishedThroughSha: "a".repeat(40), imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend:1", desiredCount: 2 },
  frontend: { sourceSha: "a".repeat(40), establishedThroughSha: "a".repeat(40), imageDigest: `sha256:${"2".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:1", desiredCount: 2 }, database: null, security: null,
} });

test("security terminal advances only the authenticated security component", () => {
  const body = { sourceSha: source, valid: true }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const initial = state(); let request;
  const result = commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: (_current, next) => { request = next; } }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.security.sourceSha, source); assert.equal(result.state.components.backend.sourceSha, initial.components.backend.sourceSha); assert.equal(request.components.frontend.sourceSha, initial.components.frontend.sourceSha);
});

test("security terminal rejects forged authorization and non-main source", () => {
  const initial = state();
  assert.throws(() => commitSecurityComponentState({ sourceSha: source, authorization: { sourceSha: source, authorizationSha256: "0".repeat(64) }, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true }), /integrity/);
  const body = { sourceSha: source, valid: true }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  assert.throws(() => commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => false }), /protected-main/);
});

test("normal security completion records only live-authenticated backend, database, and security identities", () => {
  const workflow = readFileSync(".github/workflows/release-gate.yml", "utf8");
  const writer = readFileSync("scripts/aws/commit-production-component-security-state.mjs", "utf8");
  const activation = workflow.indexOf("Activate exact Stage-B backend candidate");
  const commit = workflow.indexOf("Commit authenticated security component state");
  assert(activation >= 0 && commit > activation, "state must commit only after the authenticated security terminal");
  assert.match(workflow.slice(commit), /--release-receipt="\$RLS_RECEIPT"[\s\S]*--backend-metadata="\$BACKEND_METADATA"/);
  assert.match(workflow.slice(activation, commit), /frontend-activation\.json[\s\S]*evidence_sha256/);
  assert.match(workflow.slice(commit), /--frontend-activation="\$FRONTEND_ACTIVATION"[\s\S]*--frontend-activation-sha256="\$FRONTEND_ACTIVATION_SHA256"/);
  assert.match(writer, /assertProductionRlsReleaseReceipt\(releaseReceipt, \{ sourceSha, imageDigest: authorizedBackendDigest\(authorization\) \}\)/);
  assert.match(writer, /assertNormalBackendActivationEvidence\(backendActivation, \{ sourceSha, stageBAuthorization: authorization \}\)/);
  assert.match(writer, /changes\.database = \{ sourceSha, releaseIdentity: releaseReceipt\.receiptBundleSha256 \}/);
  assert.match(writer, /changes\.backend = \{ sourceSha: backendImageSource, establishedThroughSha: sourceSha, imageDigest: backendLive\.backendDigest, taskDefinitionArn: backendLive\.taskDefinitionArn, desiredCount: backendLive\.desiredCount \}/);
});

test("web-required security completion records the exact activated frontend only", () => {
  const initial = state(); const body = { sourceSha: source, valid: true, imageReuseEvidence: { webPublicationRequired: true } }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const frontend = { sourceSha: source, imageDigest: `sha256:${"4".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:8", desiredCount: 2 };
  const activation = { sourceSha: source, candidateTaskDefinitionArn: frontend.taskDefinitionArn, imageRef: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-web@${frontend.imageDigest}`, health: { ready: true, loginStatus: 200 } };
  const result = commitSecurityComponentState({ sourceSha: source, authorization, frontendActivation: activation, frontendLive: frontend, frontendImageSource: source, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.deepEqual(result.state.components.frontend, { ...frontend, establishedThroughSha: source });
  assert.throws(() => commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true }), /Web-required/);
});

test("a verified security rotation may refresh only its release identity at the same source", () => {
  const initial = createProductionComponentDeploymentState({ components: { ...state().components, security: { sourceSha: source, releaseIdentity: "a".repeat(64) } } });
  const body = { sourceSha: source, valid: true, rotation: "overlap" }; const authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const result = commitSecurityComponentState({ sourceSha: source, authorization, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.security.sourceSha, source); assert.equal(result.state.components.security.releaseIdentity, authorization.authorizationSha256);
  assert.equal(result.state.components.backend.sourceSha, initial.components.backend.sourceSha);
});

test("backend recovery writes only the authenticated restored backend identity", () => {
  const live = { backendDigest: `sha256:${"3".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:7", desiredCount: 2 };
  const evidence = completedBackendRecoveryEvidence({ sourceSha: recoverySource, imageReleaseSha: source, recoveryImageDigest: live.backendDigest, targetArn: live.taskDefinitionArn, candidateFingerprint: "a".repeat(64) });
  assert.deepEqual(authenticatedBackendRecoveryComponent(live, evidence), { sourceSha: source, establishedThroughSha: recoverySource, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: 2 });
  assert.throws(() => authenticatedBackendRecoveryComponent(live, { ...evidence, recoveryImageDigest: `sha256:${"4".repeat(64)}` }), /tampered/);
  assert.throws(() => authenticatedBackendRecoveryComponent(live, completedBackendRecoveryEvidence({ ...evidence, recoveryImageDigest: `sha256:${"4".repeat(64)}` })), /Expected values/);
  assert.throws(() => assertCompletedBackendRecoveryEvidence(completedBackendRecoveryEvidence({ ...evidence, status: "HEALTH_VERIFICATION_FAILED" })), /RECOVERY_COMPLETE/);
});

test("backend recovery forwards its explicit regression authority through the CAS transition", () => {
  const initial = state(); const live = { backendDigest: `sha256:${"3".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:7", desiredCount: 2 };
  const readers = { readLive: () => ({ service: { taskDefinition: live.taskDefinitionArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service, clusterArn: APP_ONLY.clusterArn, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ status: "PRIMARY", taskDefinition: live.taskDefinitionArn, rolloutState: "COMPLETED", id: "ecs-svc/1" }] }, definition: { taskDefinitionArn: live.taskDefinitionArn, family: APP_ONLY.family, taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${live.backendDigest}` }], status: "ACTIVE" }, tasks: ["a", "b"].map((taskArn) => ({ taskArn, clusterArn: APP_ONLY.clusterArn, group: `service:${APP_ONLY.service}`, taskDefinitionArn: live.taskDefinitionArn, lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: "ecs-svc/1", containers: [{ name: "backend", imageDigest: live.backendDigest }] })) }), readBackendImageSource: () => source };
  const snapshot = readers.readLive(); snapshot.definition.family = "mscqr-backend"; snapshot.definition.tags = [];
  readers.readLive = () => snapshot;
  const evidence = completedBackendRecoveryEvidence({ sourceSha: recoverySource, imageReleaseSha: source, recoveryImageDigest: live.backendDigest, targetArn: live.taskDefinitionArn, candidateFingerprint: taskDefinitionFingerprint(snapshot.definition) });
  const result = commitBackendRecoveryComponentState({ evidence, readers, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.backend.sourceSha, source); assert.equal(result.state.components.backend.establishedThroughSha, recoverySource);
  let writes = 0;
  assert.throws(() => commitBackendRecoveryComponentState({ evidence, readers, client: { read: () => initial, advance: () => { writes += 1; } }, isProtectedMainAncestor: (value) => value !== recoverySource }), /completion source/);
  assert.equal(writes, 0); assert.equal(initial.components.backend.establishedThroughSha, "a".repeat(40));
  assert.deepEqual(result.state.components.frontend, initial.components.frontend);
  const identity = { sourceSha: source, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: 2 };
  const candidate = { sourceSha: "d".repeat(40), imageDigest: `sha256:${"4".repeat(64)}` };
  assert.equal(classifyNormalLiveComponentState({ live: identity, predecessor: result.state.components.backend, candidate }), "LIVE_IS_PREDECESSOR");
  assert.equal(classifyNormalLiveComponentState({ live: { ...identity, taskDefinitionArn: identity.taskDefinitionArn.replace(":7", ":8") }, predecessor: result.state.components.backend, candidate }), "LIVE_IS_UNKNOWN");
  for (const targetArn of [live.taskDefinitionArn.replace("mscqr-backend", APP_ONLY.family), live.taskDefinitionArn.replace("368992683803", "111111111111"), live.taskDefinitionArn.replace("eu-west-2", "eu-west-1"), live.taskDefinitionArn.replace(":7", ":0")]) {
    assert.throws(() => assertCompletedBackendRecoveryEvidence(completedBackendRecoveryEvidence({ ...evidence, targetArn, evidenceSha256: undefined })), /tampered|target revision|canonical/);
  }
  for (const key of ["sourceSha", "imageReleaseSha", "recoveryImageDigest", "authorizationSha256", "status"])
    assert.throws(() => assertCompletedBackendRecoveryEvidence({ ...evidence, [key]: "invalid" }));
  assert.throws(() => commitBackendRecoveryComponentState({ evidence, readers: { ...readers, readBackendImageSource: () => "d".repeat(40) }, client: { read: () => initial, advance: () => assert.fail("write") }, isProtectedMainAncestor: () => true }));
  // The actual reader uses the canonical legacy ARN only for this terminal;
  // app-only readers retain their existing green-family boundary.
  const run = () => JSON.stringify({ taskDefinition: snapshot.definition });
  assert.equal(createAppOnlyEcsReaders(run, { assertDefinitionArn: assertBackendHealthRecoveryTaskArn }).readDefinition(live.taskDefinitionArn).family, "mscqr-backend");
  assert.throws(() => createAppOnlyEcsReaders(run).readDefinition(live.taskDefinitionArn));
  snapshot.tasks.forEach((task, i) => { task.taskArn = `arn:aws:ecs:eu-west-2:368992683803:task/${APP_ONLY.cluster}/${String(i + 1).padStart(32, "0")}`; });
  const aws = (args) => {
    const responses = {
      "describe-services": { services: [snapshot.service] },
      "describe-task-definition": { taskDefinition: snapshot.definition, tags: [] },
      "list-tasks": { taskArns: snapshot.tasks.map(({ taskArn }) => taskArn) },
      "describe-tasks": { tasks: snapshot.tasks },
      "describe-images": { imageDetails: [{ repositoryName: "mscqr-backend", registryId: APP_ONLY.account, imageDigest: live.backendDigest, imageTags: [source] }] },
    };
    assert.ok(responses[args[1]], "Unexpected AWS command"); return JSON.stringify(responses[args[1]]);
  };
  assert.equal(commitBackendRecoveryComponentState({ evidence, run: aws, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true }).state.components.backend.taskDefinitionArn, live.taskDefinitionArn);
});

test("overlap and cleanup atomically record the live backend for the next normal release", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "component-rotation-")); const rotationId = "rotation-test-1234"; const rotationStateSha256 = "c".repeat(64);
  const taskDefinitionArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:7`, imageDigest = `sha256:${"3".repeat(64)}`, imageSource = "a".repeat(40);
  const readiness = writeOverlapReadinessEvidence({ outputPath: path.join(dir, "readiness.json"), sourceSha: source, rotationId, rotationStateSha256, stages: Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((name) => [name, { valid: true, evidenceRef: `test://${name}`, evidenceSha256: crypto.createHash("sha256").update(name).digest("hex"), identityBindings: { sourceSha: source, rotationId, ...(name === "overlapTaskDefinition" ? { taskDefinitionArn } : {}) } }])) });
  const live = { sourceSha: imageSource, imageDigest, taskDefinitionArn, desiredCount: 2 };
  const readers = { readBackendImageSource: () => imageSource, readLive: () => ({
    service: { clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service, status: "ACTIVE", taskDefinition: taskDefinitionArn, desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ id: "ecs-svc/1", status: "PRIMARY", rolloutState: "COMPLETED", taskDefinition: taskDefinitionArn }] },
    definition: { taskDefinitionArn, family: APP_ONLY.family, status: "ACTIVE", taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${imageDigest}` }] },
    tasks: ["a", "b"].map((taskArn) => ({ taskArn, clusterArn: APP_ONLY.clusterArn, group: `service:${APP_ONLY.service}`, taskDefinitionArn, lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: "ecs-svc/1", containers: [{ name: "backend", imageDigest }] })),
  }) };
  for (const mode of ["rotation-overlap", "rotation-cleanup"]) {
    const initial = state(); let writes = 0;
    const deployment = { sourceSha: source, transitionMode: mode, rotationId, rotationStateSha256, readinessSha256: readiness.evidenceSha256, workflowRunId: "123", workflowRunAttempt: "1", terminalState: mode === "rotation-overlap" ? "DEPLOYED_PENDING_VERIFICATION" : "DEPLOYED", updateServiceCount: 1, taskDefinitionArn,
      metadata: { mode: "existing-task-definition", clusterName: APP_ONLY.cluster, serviceName: APP_ONLY.service, containerName: APP_ONLY.container, newTaskDefinitionArn: taskDefinitionArn, observedTaskDefinitionArn: taskDefinitionArn, expectedImageDigest: imageDigest, observedImageDigest: imageDigest, desiredCount: 2, runningCount: 2, pendingCount: 0, serviceStable: true } };
    const options = { mode, sourceSha: source, rotationId, rotationStateSha256, readinessFile: readiness.outputPath, readinessSha256: readiness.evidenceSha256, deployment, readers, client: { read: () => initial, advance: (_, next) => { writes++; assert.equal(next.components.backend.taskDefinitionArn, taskDefinitionArn); assert.equal(next.components.security.sourceSha, source); } }, isProtectedMainAncestor: () => true, writerContext: { githubRunId: "123", githubRunAttempt: "1" } };
    assert.equal(classifyNormalLiveComponentState({ live, predecessor: initial.components.backend, candidate: { sourceSha: recoverySource, imageDigest: `sha256:${"4".repeat(64)}` } }), "LIVE_IS_UNKNOWN");
    const result = commitRotationComponentState(options);
    assert.equal(writes, 1); assert.deepEqual(result.state.components.backend, { ...live, establishedThroughSha: source });
    assert.deepEqual(result.state.components.frontend, initial.components.frontend);
    const candidate = { sourceSha: recoverySource, imageDigest: `sha256:${"4".repeat(64)}` };
    assert.equal(classifyNormalLiveComponentState({ live, predecessor: result.state.components.backend, candidate }), "LIVE_IS_PREDECESSOR");
    assert.equal(classifyNormalLiveComponentState({ live: { ...live, taskDefinitionArn: taskDefinitionArn.replace(":7", ":8") }, predecessor: result.state.components.backend, candidate }), "LIVE_IS_UNKNOWN");
    for (const [key, value] of Object.entries({ newTaskDefinitionArn: taskDefinitionArn.replace(":7", ":8"), observedImageDigest: candidate.imageDigest, desiredCount: 3 }))
      assert.throws(() => commitRotationComponentState({ ...options, deployment: { ...deployment, metadata: { ...deployment.metadata, [key]: value } } }), /mismatch/);
    assert.throws(() => commitRotationComponentState({ ...options, deployment: { ...deployment, workflowRunAttempt: "2" } }), /mismatch/);
    assert.throws(() => commitRotationComponentState({ ...options, readinessSha256: "d".repeat(64) }), /does not match/);
    assert.equal(writes, 1);
  }
});
