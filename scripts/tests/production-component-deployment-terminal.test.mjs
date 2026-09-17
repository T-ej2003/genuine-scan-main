import assert from "node:assert/strict";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { authenticatedBackendRecoveryComponent, commitBackendRecoveryComponentState } from "../aws/commit-production-component-recovery-state.mjs";
import { commitRotationComponentState } from "../aws/commit-production-component-rotation-state.mjs";
import { commitSecurityComponentState } from "../aws/commit-production-component-security-state.mjs";
import { READY_FOR_OVERLAP_DEPLOYMENT_STAGES } from "../aws/production-overlap-readiness-contract.mjs";
import { writeOverlapReadinessEvidence } from "../aws/produce-production-overlap-readiness-evidence.mjs";

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
  const live = { backendDigest: `sha256:${"3".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend:7", desiredCount: 2 };
  const evidence = { sourceSha: recoverySource, imageReleaseSha: source, recoveryImageDigest: live.backendDigest, targetArn: live.taskDefinitionArn };
  assert.deepEqual(authenticatedBackendRecoveryComponent(live, evidence), { sourceSha: source, establishedThroughSha: recoverySource, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: 2 });
  assert.throws(() => authenticatedBackendRecoveryComponent(live, { ...evidence, recoveryImageDigest: `sha256:${"4".repeat(64)}` }), /Expected values to be strictly equal/);
});

test("backend recovery forwards its explicit regression authority through the CAS transition", () => {
  const initial = state(); const live = { backendDigest: `sha256:${"3".repeat(64)}`, taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${APP_ONLY.family}:7`, desiredCount: 2 };
  const evidence = { sourceSha: recoverySource, imageReleaseSha: source, recoveryImageDigest: live.backendDigest, targetArn: live.taskDefinitionArn };
  const readers = { readLive: () => ({ service: { taskDefinition: live.taskDefinitionArn, serviceArn: APP_ONLY.serviceArn, serviceName: APP_ONLY.service, clusterArn: APP_ONLY.clusterArn, status: "ACTIVE", desiredCount: 2, runningCount: 2, pendingCount: 0, deployments: [{ status: "PRIMARY", taskDefinition: live.taskDefinitionArn, rolloutState: "COMPLETED", id: "ecs-svc/1" }] }, definition: { taskDefinitionArn: live.taskDefinitionArn, family: APP_ONLY.family, taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc", runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${live.backendDigest}` }], status: "ACTIVE" }, tasks: ["a", "b"].map((taskArn) => ({ taskArn, clusterArn: APP_ONLY.clusterArn, group: `service:${APP_ONLY.service}`, taskDefinitionArn: live.taskDefinitionArn, lastStatus: "RUNNING", healthStatus: "HEALTHY", startedBy: "ecs-svc/1", containers: [{ name: "backend", imageDigest: live.backendDigest }] })) }), readBackendImageSource: () => source };
  const result = commitBackendRecoveryComponentState({ evidence, readers, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.backend.sourceSha, source); assert.equal(result.state.components.backend.establishedThroughSha, recoverySource);
  let writes = 0;
  assert.throws(() => commitBackendRecoveryComponentState({ evidence: { ...evidence, sourceSha: "d".repeat(40) }, readers, client: { read: () => initial, advance: () => { writes += 1; } }, isProtectedMainAncestor: (value) => value !== "d".repeat(40) }), /completion source/);
  assert.equal(writes, 0); assert.equal(initial.components.backend.establishedThroughSha, "a".repeat(40));
});

test("rotation terminal accepts only hash-bound readiness and changes security alone", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "component-rotation-")); const rotationId = "rotation-test-1234"; const rotationStateSha256 = "c".repeat(64);
  const readiness = writeOverlapReadinessEvidence({ outputPath: path.join(dir, "readiness.json"), sourceSha: source, rotationId, rotationStateSha256, stages: Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((name) => [name, { valid: true, evidenceRef: `test://${name}`, evidenceSha256: crypto.createHash("sha256").update(name).digest("hex"), identityBindings: { sourceSha: source, rotationId } }])) });
  const initial = state(); const result = commitRotationComponentState({ mode: "rotation-overlap", sourceSha: source, rotationId, rotationStateSha256, readinessFile: readiness.outputPath, readinessSha256: readiness.evidenceSha256, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.security.sourceSha, source); assert.equal(result.state.components.backend.sourceSha, initial.components.backend.sourceSha);
  assert.throws(() => commitRotationComponentState({ mode: "rotation-overlap", sourceSha: source, rotationId, rotationStateSha256, readinessFile: readiness.outputPath, readinessSha256: "d".repeat(64), client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true }), /does not match/);
});
