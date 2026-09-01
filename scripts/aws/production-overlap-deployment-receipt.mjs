#!/usr/bin/env node
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { readBoundStageBPrivateJson, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";

export const OVERLAP_DEPLOYMENT_RECEIPT = Object.freeze({ schemaVersion: 1, kind: "PRODUCTION_OVERLAP_DEPLOYMENT_RECEIPT", operation: "rotation-overlap", terminalState: "DEPLOYED_PENDING_VERIFICATION", artifactName: "production-overlap-deployment-receipt", repository: "T-ej2003/genuine-scan-main", environment: "production" });
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const RUN = /^[1-9][0-9]*$/;
const ARN = /^arn:aws:ecs:eu-west-2:368992683803:/;
const FIELDS = Object.freeze(["schemaVersion", "kind", "operation", "terminalState", "repository", "environment", "sourceSha", "rotationId", "rotationStateSha256", "readinessSha256", "rotationFixtureSha256", "workflowRef", "workflowRunId", "workflowRunAttempt", "executionActor", "environmentApprovalSha256", "deployedAt", "expectedCurrentTaskDefinitionArn", "taskDefinitionArn", "imageDigest", "deploymentSha", "cluster", "service", "observedTaskDefinitionArn", "observedImageDigest", "serviceStable", "updateServiceCount", "deploymentResultSha256", "receiptSha256"]);

export function buildProductionOverlapDeploymentReceipt(input = {}) {
  const approval = input.environmentApproval;
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: input.sourceSha, repository: OVERLAP_DEPLOYMENT_RECEIPT.repository });
  const metadata = input.deployment?.metadata || {};
  const body = {
    ...Object.fromEntries(Object.entries(OVERLAP_DEPLOYMENT_RECEIPT).filter(([key]) => key !== "artifactName")),
    sourceSha: input.sourceSha, rotationId: input.rotationId, rotationStateSha256: input.rotationStateSha256, readinessSha256: input.readinessSha256, rotationFixtureSha256: input.rotationFixtureSha256,
    workflowRef: approval.workflowRef, workflowRunId: approval.workflowRunId, workflowRunAttempt: approval.workflowRunAttempt, executionActor: approval.executionActor, environmentApprovalSha256: approval.evidenceSha256,
    deployedAt: input.deployedAt, expectedCurrentTaskDefinitionArn: input.expectedCurrentTaskDefinitionArn, taskDefinitionArn: input.taskDefinitionArn, imageDigest: input.imageDigest, deploymentSha: input.deploymentSha,
    cluster: metadata.clusterName, service: metadata.serviceName, observedTaskDefinitionArn: metadata.observedTaskDefinitionArn, observedImageDigest: metadata.observedImageDigest, serviceStable: metadata.serviceStable, updateServiceCount: input.deployment?.updateServiceCount, deploymentResultSha256: canonicalSha256(metadata),
  };
  return assertProductionOverlapDeploymentReceipt({ ...body, receiptSha256: canonicalSha256(body) }, input);
}

export function assertProductionOverlapDeploymentReceipt(value, expected = {}) {
  if (!value || Object.keys(value).sort().join(",") !== [...FIELDS].sort().join(",") || value.schemaVersion !== 1 || value.kind !== OVERLAP_DEPLOYMENT_RECEIPT.kind || value.operation !== OVERLAP_DEPLOYMENT_RECEIPT.operation || value.terminalState !== OVERLAP_DEPLOYMENT_RECEIPT.terminalState || value.repository !== OVERLAP_DEPLOYMENT_RECEIPT.repository || value.environment !== "production") throw new Error("Overlap deployment receipt schema is invalid.");
  if (!SHA40.test(value.sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(value.rotationId || "") || ![value.rotationStateSha256, value.readinessSha256, value.rotationFixtureSha256, value.environmentApprovalSha256, value.deploymentResultSha256, value.receiptSha256].every((item) => SHA256.test(item || "")) || !RUN.test(value.workflowRunId || "") || !RUN.test(value.workflowRunAttempt || "") || value.workflowRef !== "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main" || !/^[A-Za-z0-9-]+$/.test(value.executionActor || "")) throw new Error("Overlap deployment receipt identities are invalid.");
  if (![value.expectedCurrentTaskDefinitionArn, value.taskDefinitionArn, value.observedTaskDefinitionArn].every((item) => ARN.test(item || "")) || value.observedTaskDefinitionArn !== value.taskDefinitionArn || value.cluster !== "mscqr-prod-euw2-main" || value.service !== "mscqr-backend-servi-euw2" || !/^sha256:[a-f0-9]{64}$/.test(value.imageDigest || "") || value.observedImageDigest !== value.imageDigest || !SHA40.test(value.deploymentSha || "") || value.serviceStable !== true || value.updateServiceCount !== 1 || Number.isNaN(Date.parse(value.deployedAt)) || new Date(value.deployedAt).toISOString() !== value.deployedAt) throw new Error("Overlap deployment receipt did not prove one stable exact deployment.");
  for (const field of ["sourceSha", "rotationId", "rotationStateSha256", "readinessSha256", "rotationFixtureSha256", "expectedCurrentTaskDefinitionArn", "taskDefinitionArn", "imageDigest", "deploymentSha", "workflowRunId", "workflowRunAttempt"]) if (expected[field] !== undefined && value[field] !== String(expected[field])) throw new Error(`Overlap deployment receipt ${field} binding is wrong.`);
  const { receiptSha256, ...body } = value;
  if (canonicalSha256(body) !== receiptSha256) throw new Error("Overlap deployment receipt hash is invalid.");
  return value;
}

export function persistProductionOverlapDeploymentReceipt({ outputPath, receipt, repositoryRoot = process.cwd() } = {}) {
  const checked = assertProductionOverlapDeploymentReceipt(receipt);
  writeStageBPrivateFileAtomic({ filePath: path.resolve(outputPath), bytes: Buffer.from(`${JSON.stringify(checked, null, 2)}\n`), repositoryRoot, label: "Overlap deployment receipt" });
  return { terminalState: checked.terminalState, receiptSha256: checked.receiptSha256, outputPath: path.resolve(outputPath) };
}

export function readProductionOverlapDeploymentReceipt({ filePath, receiptSha256, repositoryRoot = process.cwd(), ...expected } = {}) {
  return assertProductionOverlapDeploymentReceipt(readBoundStageBPrivateJson({ filePath: path.resolve(filePath), expectedSha256: receiptSha256, repositoryRoot, label: "Overlap deployment receipt" }), expected);
}

export function resolveProductionOverlapDeploymentReceipt({ workflowRunId, workflowRunAttempt, sourceSha, run } = {}) {
  if (!RUN.test(String(workflowRunId || "")) || !RUN.test(String(workflowRunAttempt || "")) || typeof run !== "function") throw new Error("Overlap deployment workflow identity is invalid.");
  const json = (args) => JSON.parse(run("gh", args));
  const pages = (endpoint, field) => {
    const value = json(["api", endpoint, "--paginate", "--slurp"]);
    if (!Array.isArray(value)) throw new Error(`Overlap deployment ${field} response is malformed.`);
    return field ? value.flatMap((page) => page?.[field] || []) : value.flat();
  };
  const workflow = json(["api", `repos/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/actions/runs/${workflowRunId}`]);
  if (String(workflow.id) !== String(workflowRunId) || String(workflow.run_attempt) !== String(workflowRunAttempt) || workflow.repository?.full_name !== OVERLAP_DEPLOYMENT_RECEIPT.repository || workflow.head_repository?.full_name !== OVERLAP_DEPLOYMENT_RECEIPT.repository || workflow.head_sha !== sourceSha || workflow.head_branch !== "main" || workflow.path !== ".github/workflows/release-gate.yml" || workflow.event !== "workflow_dispatch" || workflow.status !== "completed" || !["success", "failure"].includes(workflow.conclusion)) throw new Error("Overlap deployment workflow is not the exact completed protected-main run.");
  const jobs = pages(`repos/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/actions/runs/${workflowRunId}/attempts/${workflowRunAttempt}/jobs`, "jobs");
  const job = jobs.filter((item) => item.name === "Deploy production ECS" && String(item.run_id) === String(workflowRunId) && String(item.run_attempt) === String(workflowRunAttempt) && item.head_sha === sourceSha && item.status === "completed" && ["success", "failure"].includes(item.conclusion));
  const expectedSteps = ["Authenticate production environment approval boundary", "Deploy rotation transition backend ECS service", "Upload overlap deployment receipt"];
  const boundarySteps = expectedSteps.map((name) => job.length === 1 ? job[0].steps?.find((step) => step.name === name) : undefined);
  if (job.length !== 1 || boundarySteps.some((step) => step?.status !== "completed" || step.conclusion !== "success") || boundarySteps.some((step, index) => job[0].steps.indexOf(step) !== job[0].steps.indexOf(boundarySteps[0]) + index)) throw new Error("Overlap deployment job did not complete every authenticated receipt boundary in order.");
  const deploymentLogUrl = `https://github.com/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/actions/runs/${workflowRunId}/job/${job[0].id}`;
  const deployments = pages(`repos/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/deployments?sha=${sourceSha}&environment=production&per_page=100`);
  const correlated = deployments.filter((item) => item.sha === sourceSha && item.ref === "main" && item.task === "deploy" && item.environment === "production" && item.performed_via_github_app?.slug === "github-actions").filter((item) => {
    const statuses = pages(`repos/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/deployments/${item.id}/statuses`);
    return ["waiting", "in_progress", "success"].every((state) => statuses.some((status) => status.state === state && status.environment === "production" && status.log_url === deploymentLogUrl));
  });
  if (correlated.length !== 1) throw new Error("Overlap deployment is not correlated to one protected-production deployment.");
  const approvals = pages(`repos/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/actions/runs/${workflowRunId}/approvals`);
  const approved = approvals.filter((item) => item.state === "approved" && item.user?.type === "User" && item.user?.site_admin === false && item.environments?.length === 1 && item.environments[0]?.name === "production" && item.environments[0]?.can_admins_bypass === false);
  if (approved.length !== 1 || approved[0].user.login.toLowerCase() === workflow.actor?.login?.toLowerCase()) throw new Error("Overlap deployment lacks one independent protected-production approval.");
  const artifacts = pages(`repos/${OVERLAP_DEPLOYMENT_RECEIPT.repository}/actions/runs/${workflowRunId}/artifacts`, "artifacts");
  const uploadStep = boundarySteps[2];
  const matches = artifacts.filter((item) => item.name === OVERLAP_DEPLOYMENT_RECEIPT.artifactName && item.expired === false && String(item.workflow_run?.id) === String(workflowRunId) && item.workflow_run?.head_sha === sourceSha && item.workflow_run?.head_branch === "main" && item.workflow_run?.repository_id === workflow.repository.id && item.workflow_run?.head_repository_id === workflow.head_repository.id && Date.parse(item.created_at) >= Date.parse(uploadStep.started_at) && Date.parse(item.created_at) <= Date.parse(uploadStep.completed_at) && /^sha256:[a-f0-9]{64}$/.test(item.digest || ""));
  if (matches?.length !== 1) throw new Error("Overlap deployment run does not expose one immutable receipt artifact.");
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-overlap-receipt-"));
  try {
    run("gh", ["run", "download", String(workflowRunId), "--repo", OVERLAP_DEPLOYMENT_RECEIPT.repository, "--name", OVERLAP_DEPLOYMENT_RECEIPT.artifactName, "--dir", directory]);
    const receipt = assertProductionOverlapDeploymentReceipt(JSON.parse(readFileSync(path.join(directory, "production-overlap-deployment-receipt.json"), "utf8")), { sourceSha, workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt) });
    if (receipt.executionActor.toLowerCase() !== workflow.actor?.login?.toLowerCase()) throw new Error("Overlap deployment receipt execution actor is wrong.");
    const tailFailures = job[0].steps.slice(job[0].steps.indexOf(uploadStep) + 1).filter((step) => step.status === "completed" && step.conclusion !== "success");
    return { receipt, artifact: matches[0], reviewer: approved[0].user.login, job: job[0], workflow, tailFailures };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const arg = (name) => { const i = process.argv.indexOf(name); if (i < 0 || !process.argv[i + 1]) throw new Error(`${name} is required.`); return process.argv[i + 1]; };
  const approval = JSON.parse(readFileSync(arg("--environment-approval"), "utf8"));
  const deployment = JSON.parse(readFileSync(arg("--deployment"), "utf8"));
  const receipt = buildProductionOverlapDeploymentReceipt({ environmentApproval: approval, deployment: { ...deployment, updateServiceCount: 1, metadata: deployment }, sourceSha: arg("--source-sha"), rotationId: arg("--rotation-id"), rotationStateSha256: arg("--rotation-state-sha256"), readinessSha256: arg("--readiness-sha256"), rotationFixtureSha256: arg("--rotation-fixture-sha256"), expectedCurrentTaskDefinitionArn: arg("--expected-current-task-definition"), taskDefinitionArn: arg("--task-definition"), imageDigest: arg("--image-digest"), deploymentSha: arg("--deployment-sha"), deployedAt: new Date().toISOString() });
  persistProductionOverlapDeploymentReceipt({ outputPath: arg("--output"), receipt, repositoryRoot: root });
  process.stdout.write(`${JSON.stringify({ terminalState: receipt.terminalState, receiptSha256: receipt.receiptSha256 })}\n`);
}
