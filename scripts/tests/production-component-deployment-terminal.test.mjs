import assert from "node:assert/strict";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, readFileSync } from "node:fs";
import test from "node:test";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";
import { authenticatedBackendRecoveryComponent } from "../aws/commit-production-component-recovery-state.mjs";
import { commitRotationComponentState } from "../aws/commit-production-component-rotation-state.mjs";
import { commitSecurityComponentState } from "../aws/commit-production-component-security-state.mjs";
import { READY_FOR_OVERLAP_DEPLOYMENT_STAGES } from "../aws/production-overlap-readiness-contract.mjs";
import { writeOverlapReadinessEvidence } from "../aws/produce-production-overlap-readiness-evidence.mjs";

const source = "b".repeat(40);
const state = () => createProductionComponentDeploymentState({ components: {
  backend: { sourceSha: "a".repeat(40), imageDigest: `sha256:${"1".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend:1", desiredCount: 2 },
  frontend: { sourceSha: "a".repeat(40), imageDigest: `sha256:${"2".repeat(64)}`, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:1", desiredCount: 2 }, database: null, security: null,
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
  assert.match(writer, /assertProductionRlsReleaseReceipt\(releaseReceipt, \{ sourceSha, imageDigest: authorizedBackendDigest\(authorization\) \}\)/);
  assert.match(writer, /assertNormalBackendActivationEvidence\(backendActivation, \{ sourceSha, stageBAuthorization: authorization \}\)/);
  assert.match(writer, /changes\.database = \{ sourceSha, releaseIdentity: releaseReceipt\.receiptBundleSha256 \}/);
  assert.match(writer, /changes\.backend = \{ sourceSha: backendImageSource, imageDigest: backendLive\.backendDigest, taskDefinitionArn: backendLive\.taskDefinitionArn, desiredCount: backendLive\.desiredCount \}/);
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
  const evidence = { imageReleaseSha: source, recoveryImageDigest: live.backendDigest, targetArn: live.taskDefinitionArn };
  assert.deepEqual(authenticatedBackendRecoveryComponent(live, evidence), { sourceSha: source, imageDigest: live.backendDigest, taskDefinitionArn: live.taskDefinitionArn, desiredCount: 2 });
  assert.throws(() => authenticatedBackendRecoveryComponent(live, { ...evidence, recoveryImageDigest: `sha256:${"4".repeat(64)}` }), /Expected values to be strictly equal/);
});

test("rotation terminal accepts only hash-bound readiness and changes security alone", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "component-rotation-")); const rotationId = "rotation-test-1234"; const rotationStateSha256 = "c".repeat(64);
  const readiness = writeOverlapReadinessEvidence({ outputPath: path.join(dir, "readiness.json"), sourceSha: source, rotationId, rotationStateSha256, stages: Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((name) => [name, { valid: true, evidenceRef: `test://${name}`, evidenceSha256: crypto.createHash("sha256").update(name).digest("hex"), identityBindings: { sourceSha: source, rotationId } }])) });
  const initial = state(); const result = commitRotationComponentState({ mode: "rotation-overlap", sourceSha: source, rotationId, rotationStateSha256, readinessFile: readiness.outputPath, readinessSha256: readiness.evidenceSha256, client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true });
  assert.equal(result.state.components.security.sourceSha, source); assert.equal(result.state.components.backend.sourceSha, initial.components.backend.sourceSha);
  assert.throws(() => commitRotationComponentState({ mode: "rotation-overlap", sourceSha: source, rotationId, rotationStateSha256, readinessFile: readiness.outputPath, readinessSha256: "d".repeat(64), client: { read: () => initial, advance: () => {} }, isProtectedMainAncestor: () => true }), /does not match/);
});
