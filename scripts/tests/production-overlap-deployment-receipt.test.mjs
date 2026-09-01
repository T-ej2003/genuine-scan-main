import assert from "node:assert/strict";
import { writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { buildProductionOverlapDeploymentReceipt, assertProductionOverlapDeploymentReceipt, resolveProductionOverlapDeploymentReceipt } from "../aws/production-overlap-deployment-receipt.mjs";
import { runPostOverlapVerification, runProductionCutoverOverlapControlPlane } from "../aws/production-cutover-control-plane.mjs";
import { buildOverlapReadinessEvidence } from "../aws/produce-production-overlap-readiness-evidence.mjs";
import { READY_FOR_OVERLAP_DEPLOYMENT_STAGES } from "../aws/production-overlap-readiness-contract.mjs";

const sourceSha = "a".repeat(40);
const rotationId = "rotation-20260829015311-765c8a16";
const sha = (value) => value.repeat(64);
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1";
const previousTaskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend:9";
const imageDigest = `sha256:${"b".repeat(64)}`;
const approval = createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "10", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-09-01T10:00:00.000Z" });
const readiness = buildOverlapReadinessEvidence({ sourceSha, rotationId, rotationStateSha256: sha("c"), generatedAt: "2026-09-01T10:00:00.000Z", stages: Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((name) => [name, { valid: true, evidenceRef: name, evidenceSha256: sha("1"), identityBindings: { sourceSha, rotationId } }])) });

const receipt = () => buildProductionOverlapDeploymentReceipt({ sourceSha, rotationId, rotationStateSha256: sha("c"), readinessSha256: sha("d"), rotationFixtureSha256: sha("e"), environmentApproval: approval, deployedAt: "2026-09-01T10:01:00.000Z", expectedCurrentTaskDefinitionArn: previousTaskDefinitionArn, taskDefinitionArn, imageDigest, deploymentSha: sourceSha, deployment: { updateServiceCount: 1, metadata: { clusterName: "mscqr-prod-euw2-main", serviceName: "mscqr-backend-servi-euw2", observedTaskDefinitionArn: taskDefinitionArn, observedImageDigest: imageDigest, serviceStable: true } } });

test("deployment receipt binds the exact authorized stable overlap deployment", () => {
  const value = receipt();
  assert.equal(value.terminalState, "DEPLOYED_PENDING_VERIFICATION");
  for (const field of ["sourceSha", "rotationId", "rotationStateSha256", "readinessSha256", "rotationFixtureSha256", "taskDefinitionArn", "imageDigest", "deploymentSha", "workflowRunId", "workflowRunAttempt"]) {
    const changed = { ...value, [field]: field.includes("Sha256") ? sha("f") : field === "workflowRunId" ? "11" : field === "workflowRunAttempt" ? "2" : `${value[field]}-tampered` };
    assert.throws(() => assertProductionOverlapDeploymentReceipt(changed), /receipt|binding|identity|deployment/i);
  }
});

test("receipt resolver authenticates the exact independently approved workflow deployment", () => {
  const value = receipt();
  const job = { id: 20, run_id: 10, run_attempt: 1, name: "Deploy production ECS", head_sha: sourceSha, status: "completed", conclusion: "success", steps: [
    { name: "Authenticate production environment approval boundary", status: "completed", conclusion: "success" },
    { name: "Deploy rotation transition backend ECS service", status: "completed", conclusion: "success" },
    { name: "Upload overlap deployment receipt", status: "completed", conclusion: "success", started_at: "2026-09-01T10:01:00.000Z", completed_at: "2026-09-01T10:01:10.000Z" },
  ] };
  const logUrl = "https://github.com/T-ej2003/genuine-scan-main/actions/runs/10/job/20";
  const workflow = { id: 10, run_attempt: 1, repository: { id: 30, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 30, full_name: "T-ej2003/genuine-scan-main" }, head_sha: sourceSha, head_branch: "main", path: ".github/workflows/release-gate.yml", event: "workflow_dispatch", status: "completed", conclusion: "success", actor: { login: "operator" } };
  const run = (_command, args) => {
    if (args[0] === "run") { writeFileSync(path.join(args[args.indexOf("--dir") + 1], "production-overlap-deployment-receipt.json"), JSON.stringify(value)); return ""; }
    const endpoint = args[1];
    if (endpoint.endsWith("/actions/runs/10")) return JSON.stringify(workflow);
    if (endpoint.endsWith("/attempts/1/jobs")) return JSON.stringify([{ jobs: [job] }]);
    if (endpoint.includes("/deployments?")) return JSON.stringify([[{ id: 40, sha: sourceSha, ref: "main", task: "deploy", environment: "production", performed_via_github_app: { slug: "github-actions" } }]]);
    if (endpoint.endsWith("/deployments/40/statuses")) return JSON.stringify([["waiting", "in_progress", "success"].map((state) => ({ state, environment: "production", log_url: logUrl }))]);
    if (endpoint.endsWith("/approvals")) return JSON.stringify([[{ state: "approved", user: { login: "reviewer", type: "User", site_admin: false }, environments: [{ name: "production", can_admins_bypass: false }] }]]);
    if (endpoint.endsWith("/artifacts")) return JSON.stringify([{ artifacts: [{ id: 50, name: "production-overlap-deployment-receipt", expired: false, digest: `sha256:${sha("9")}`, created_at: "2026-09-01T10:01:05.000Z", workflow_run: { id: 10, head_sha: sourceSha, head_branch: "main", repository_id: 30, head_repository_id: 30 } }] }]);
    throw new Error(`unexpected mock call: ${args.join(" ")}`);
  };
  const resolved = resolveProductionOverlapDeploymentReceipt({ workflowRunId: "10", workflowRunAttempt: "1", sourceSha, run });
  assert.equal(resolved.receipt.receiptSha256, value.receiptSha256);
  assert.equal(resolved.reviewer, "reviewer");
});

test("authorized deployment stops pending independent verification", async () => {
  let updates = 0;
  const value = receipt();
  const result = await runProductionCutoverOverlapControlPlane({ transitionMode: "rotation-overlap", readiness, sourceSha, rotationId, rotationStateSha256: sha("c"), taskDefinitionArn, readinessSha256: sha("d"), deployOverlap: { run: async () => ({ updateServiceCount: ++updates, propagateTags: "TASK_DEFINITION", taskDefinitionArn }) }, deploymentReceipt: { persist: async () => ({ receiptSha256: value.receiptSha256 }), authenticate: async () => value } });
  assert.equal(result.terminalState, "DEPLOYED_PENDING_VERIFICATION");
  assert.equal(updates, 1);
  assert.equal(result.readyForOnboarding, undefined);
});

test("overlap cannot silently omit receipt authentication", async () => {
  await assert.rejects(() => runProductionCutoverOverlapControlPlane({ transitionMode: "rotation-overlap", readiness, sourceSha, rotationId, rotationStateSha256: sha("c"), taskDefinitionArn, readinessSha256: sha("d"), deployOverlap: { run: async () => ({ updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn }) } }), /receipt persistence/);
});

test("independent continuation shares runtime proof and coordinator verification without deployment", async () => {
  let runtimeProofs = 0;
  let coordinatorVerifies = 0;
  const result = await runPostOverlapVerification({ deployment: {}, sourceSha, rotationId, rotationStateSha256: sha("c"), rotationFixtureSha256: sha("e"), taskDefinitionArn, expectedImageDigest: imageDigest, verifierSession: {}, postDeploy: { run: async () => ({ valid: true, taskArn: "task", taskDefinitionArn, imageDigest, taskTag: "MSCQRExecTarget=production-backend" }) }, ecsExec: { run: async () => ({ valid: ++runtimeProofs === 1, proof: {} }) }, rotationVerify: { run: async () => ({ terminalState: ++coordinatorVerifies === 1 ? "VERIFIED_OVERLAP" : "INVALID", rotationId, rotationStateSha256: sha("f"), overlapReadyAt: "2026-09-01T10:02:00.000Z", cleanupEligibleAt: "2026-09-02T10:02:00.000Z" }) } });
  assert.equal(result.terminalState, "VERIFIED_OVERLAP");
  assert.equal(runtimeProofs, 1);
  assert.equal(coordinatorVerifies, 1);
  assert.equal(result.readyForOnboarding, undefined);
});

test("verified continuation reuses persisted runtime proof without post-deploy or ECS Exec replay", async () => {
  let postDeployCalls = 0;
  let ecsExecCalls = 0;
  let coordinatorCalls = 0;
  const persistedDeployed = { valid: true, taskArn: "task", taskDefinitionArn, imageDigest, taskTag: "MSCQRExecTarget=production-backend" };
  const persistedExecProof = { valid: true, rotationId, phase: "overlap", deploymentSha: sourceSha, runtimeInvocationRef: "persisted-proof" };
  const result = await runPostOverlapVerification({
    deployment: { resumeVerified: true, persistedDeployed, persistedExecProof }, sourceSha, rotationId, rotationStateSha256: sha("c"), rotationFixtureSha256: sha("e"), taskDefinitionArn, expectedImageDigest: imageDigest, verifierSession: {},
    postDeploy: { run: async () => { postDeployCalls += 1; throw new Error("must not read deployment again"); } },
    ecsExec: { run: async () => { ecsExecCalls += 1; throw new Error("must not replay ECS Exec"); } },
    rotationVerify: { run: async () => { coordinatorCalls += 1; return { terminalState: "VERIFIED_OVERLAP", rotationId, rotationStateSha256: sha("f"), overlapReadyAt: "2026-09-01T10:02:00.000Z", cleanupEligibleAt: "2026-09-02T10:02:00.000Z" }; } },
  });
  assert.equal(result.terminalState, "VERIFIED_OVERLAP");
  assert.equal(postDeployCalls, 0);
  assert.equal(ecsExecCalls, 0);
  assert.equal(coordinatorCalls, 1);
});

test("verification failure cannot produce VERIFIED_OVERLAP or redeploy", async () => {
  await assert.rejects(() => runPostOverlapVerification({ deployment: {}, sourceSha, rotationId, rotationStateSha256: sha("c"), rotationFixtureSha256: sha("e"), taskDefinitionArn, expectedImageDigest: imageDigest, verifierSession: {}, postDeploy: { run: async () => ({ valid: true, taskArn: "task", taskDefinitionArn, imageDigest, taskTag: "MSCQRExecTarget=production-backend" }) }, ecsExec: { run: async () => ({ valid: false }) }, rotationVerify: { run: async () => assert.fail("coordinator must not run") } }), /runtime proof/);
  await assert.rejects(() => runPostOverlapVerification({ deployment: {}, sourceSha, rotationId, rotationStateSha256: sha("c"), rotationFixtureSha256: sha("e"), taskDefinitionArn, expectedImageDigest: imageDigest, verifierSession: {}, postDeploy: { run: async () => ({ valid: true, taskArn: "task", taskDefinitionArn, imageDigest, taskTag: "MSCQRExecTarget=production-backend" }) }, ecsExec: { run: async () => ({ valid: true, proof: {} }) }, rotationVerify: { run: async () => ({ terminalState: "DEPLOYED_PENDING_VERIFICATION" }) } }), /VERIFIED_OVERLAP/);
  await assert.rejects(() => runPostOverlapVerification({ deployment: {}, sourceSha, rotationId, rotationStateSha256: sha("c"), rotationFixtureSha256: sha("e"), taskDefinitionArn, expectedImageDigest: imageDigest, verifierSession: {}, postDeploy: { run: async () => ({ valid: true }) } }), /adapters are incomplete/);
});
