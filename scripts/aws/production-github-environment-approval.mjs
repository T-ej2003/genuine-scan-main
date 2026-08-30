#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

export const PRODUCTION_ENVIRONMENT_APPROVAL = Object.freeze({
  kind: "GITHUB_PROTECTED_ENVIRONMENT_APPROVAL",
  schemaVersion: 2,
  repository: "T-ej2003/genuine-scan-main",
  environment: "production",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main",
  stageAReconciliationWorkflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-stage-a-reconciliation.yml@refs/heads/main",
  dualSlotRebaselineWorkflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-dual-slot-rebaseline.yml@refs/heads/main",
  dualSlotRebaselineRecoveryWorkflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-dual-slot-rebaseline-recovery.yml@refs/heads/main",
  stageBApplyAttemptReconciliationWorkflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-green-stage-b-apply-attempt-reconciliation.yml@refs/heads/main",
  eventName: "workflow_dispatch",
  maxAgeMs: 30 * 60 * 1000,
});

const approvedWorkflowRefs = new Set([
  PRODUCTION_ENVIRONMENT_APPROVAL.workflowRef,
  PRODUCTION_ENVIRONMENT_APPROVAL.stageAReconciliationWorkflowRef,
  PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineWorkflowRef,
  PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineRecoveryWorkflowRef,
  PRODUCTION_ENVIRONMENT_APPROVAL.stageBApplyAttemptReconciliationWorkflowRef,
]);

const SHA = /^[a-f0-9]{40}$/;
const RUN_ID = /^[1-9][0-9]*$/;
const FIELDS = new Set(["schemaVersion", "kind", "repository", "environment", "environmentId", "sourceSha", "workflowRef", "eventName", "workflowRunId", "workflowRunAttempt", "executionActor", "configuredReviewers", "requiredReviewerCount", "preventSelfReview", "canAdminsBypass", "observedAt", "actualApproval", "evidenceSha256"]);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

const requiredText = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};

const normalizeReviewers = (reviewers) => {
  if (!Array.isArray(reviewers) || reviewers.length < 1) throw new Error("Production environment must require at least one reviewer.");
  const normalized = reviewers.map(({ type, reviewer } = {}) => {
    const name = type === "User" ? reviewer?.login : type === "Team" ? reviewer?.slug : undefined;
    if (!Number.isSafeInteger(reviewer?.id) || reviewer.id < 1 || !name || !/^[A-Za-z0-9-]+$/.test(name)) throw new Error("Production environment contains an invalid required reviewer.");
    return { type, id: reviewer.id, name };
  }).sort((left, right) => `${left.type}:${left.id}`.localeCompare(`${right.type}:${right.id}`));
  if (new Set(normalized.map(({ type, id }) => `${type}:${id}`)).size !== normalized.length) throw new Error("Production environment contains duplicate required reviewers.");
  return normalized;
};

const assertEvidenceReviewers = (reviewers) => {
  if (!Array.isArray(reviewers) || reviewers.length < 1 || reviewers.some((reviewer) =>
    !reviewer || Object.keys(reviewer).length !== 3 || !["User", "Team"].includes(reviewer.type)
    || !Number.isSafeInteger(reviewer.id) || reviewer.id < 1 || typeof reviewer.name !== "string" || !/^[A-Za-z0-9-]+$/.test(reviewer.name))) {
    throw new Error("GitHub environment approval reviewer evidence is invalid.");
  }
  const keys = reviewers.map(({ type, id }) => `${type}:${id}`);
  if (new Set(keys).size !== keys.length || keys.some((key, index) => index > 0 && keys[index - 1].localeCompare(key) > 0)) throw new Error("GitHub environment approval reviewer evidence is invalid.");
  return reviewers;
};

function assertActualApproval(value, environmentId, environment) {
  if (!value || Object.keys(value).length !== 5 || value.state !== "approved" || value.environmentId !== environmentId || value.environmentName !== environment || !Number.isSafeInteger(value.userId) || value.userId < 1 || typeof value.userLogin !== "string" || !/^[A-Za-z0-9-]+$/.test(value.userLogin)) throw new Error("GitHub environment actual approval evidence is invalid.");
  return Object.freeze({ ...value });
}

export function createProductionEnvironmentApprovalEvidence({ environmentConfig, repository, environment, sourceSha, workflowRef, eventName, workflowRunId, workflowRunAttempt, executionActor, observedAt = new Date().toISOString(), actualApproval } = {}) {
  if (repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || environment !== PRODUCTION_ENVIRONMENT_APPROVAL.environment || environmentConfig?.name !== environment) throw new Error("GitHub production environment identity is invalid.");
  if (!SHA.test(sourceSha || "") || !approvedWorkflowRefs.has(workflowRef) || eventName !== PRODUCTION_ENVIRONMENT_APPROVAL.eventName
    || !RUN_ID.test(String(workflowRunId || "")) || !RUN_ID.test(String(workflowRunAttempt || ""))) throw new Error("GitHub environment approval source or workflow identity is invalid.");
  const rules = (environmentConfig.protection_rules || []).filter((rule) => rule?.type === "required_reviewers");
  if (rules.length !== 1 || typeof rules[0].prevent_self_review !== "boolean") throw new Error("Production environment required-reviewer policy is invalid.");
  const configuredReviewers = normalizeReviewers(rules[0].reviewers);
  if (environmentConfig.can_admins_bypass !== false) throw new Error("Production environment must disable administrator bypass.");
  const body = {
    schemaVersion: actualApproval ? 3 : PRODUCTION_ENVIRONMENT_APPROVAL.schemaVersion,
    kind: PRODUCTION_ENVIRONMENT_APPROVAL.kind,
    repository,
    environment,
    environmentId: environmentConfig.id,
    sourceSha,
    workflowRef,
    eventName,
    workflowRunId: String(workflowRunId),
    workflowRunAttempt: String(workflowRunAttempt),
    executionActor: requiredText(executionActor, "executionActor"),
    configuredReviewers,
    requiredReviewerCount: configuredReviewers.length,
    preventSelfReview: rules[0].prevent_self_review,
    canAdminsBypass: false,
    observedAt,
    ...(actualApproval ? { actualApproval: assertActualApproval(actualApproval, environmentConfig.id, environment) } : {}),
  };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertProductionEnvironmentApprovalEvidence(evidence, { sourceSha, repository, environment, workflowRef, eventName, workflowRunId, workflowRunAttempt, executionActor, githubActions, now = new Date() } = {}) {
  assertProductionEnvironmentApprovalIdentity(evidence, { sourceSha, repository });
  const actor = requiredText(evidence.executionActor, "evidence.executionActor");
  const reviewers = assertEvidenceReviewers(evidence.configuredReviewers);
  if (environment !== PRODUCTION_ENVIRONMENT_APPROVAL.environment || evidence.environment !== environment
    || githubActions !== "true" || !approvedWorkflowRefs.has(workflowRef) || evidence.workflowRef !== workflowRef
    || eventName !== PRODUCTION_ENVIRONMENT_APPROVAL.eventName || evidence.eventName !== eventName
    || evidence.workflowRunId !== String(workflowRunId || "") || !RUN_ID.test(evidence.workflowRunId)
    || evidence.workflowRunAttempt !== String(workflowRunAttempt || "") || !RUN_ID.test(evidence.workflowRunAttempt)
    || actor.toLowerCase() !== requiredText(executionActor, "executionActor").toLowerCase()
    || !Number.isSafeInteger(evidence.requiredReviewerCount) || evidence.requiredReviewerCount !== reviewers.length) throw new Error("GitHub environment approval evidence is not bound to this protected recovery run.");
  const observed = new Date(evidence.observedAt);
  const age = now.getTime() - observed.getTime();
  if (!Number.isFinite(observed.getTime()) || observed.toISOString() !== evidence.observedAt || age < 0 || age > PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs) throw new Error("GitHub environment approval evidence is stale or malformed.");
  return evidence;
}

export function assertProductionEnvironmentApprovalIdentity(evidence, { sourceSha, repository } = {}) {
  if (!evidence || ![2, 3].includes(evidence.schemaVersion) || Object.keys(evidence).some((field) => !FIELDS.has(field)) || (evidence.schemaVersion === 2 && Object.keys(evidence).length !== FIELDS.size - 1) || (evidence.schemaVersion === 3 && Object.keys(evidence).length !== FIELDS.size)) throw new Error("GitHub environment approval evidence schema is invalid.");
  requiredText(evidence.executionActor, "evidence.executionActor");
  const reviewers = assertEvidenceReviewers(evidence.configuredReviewers);
  if (![PRODUCTION_ENVIRONMENT_APPROVAL.schemaVersion, 3].includes(evidence.schemaVersion) || evidence.kind !== PRODUCTION_ENVIRONMENT_APPROVAL.kind
    || repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || evidence.repository !== repository
    || evidence.environment !== PRODUCTION_ENVIRONMENT_APPROVAL.environment
    || evidence.sourceSha !== sourceSha || !SHA.test(sourceSha || "")
    || !approvedWorkflowRefs.has(evidence.workflowRef) || evidence.eventName !== PRODUCTION_ENVIRONMENT_APPROVAL.eventName
    || !RUN_ID.test(evidence.workflowRunId) || !RUN_ID.test(evidence.workflowRunAttempt)
    || !Number.isSafeInteger(evidence.environmentId) || evidence.environmentId < 1
    || !Number.isSafeInteger(evidence.requiredReviewerCount) || evidence.requiredReviewerCount !== reviewers.length
    || typeof evidence.preventSelfReview !== "boolean" || evidence.canAdminsBypass !== false) throw new Error("GitHub environment approval evidence is not bound to this protected recovery run.");
  const observed = new Date(evidence.observedAt);
  if (!Number.isFinite(observed.getTime()) || observed.toISOString() !== evidence.observedAt) throw new Error("GitHub environment approval evidence is stale or malformed.");
  if (evidence.schemaVersion === 3) assertActualApproval(evidence.actualApproval, evidence.environmentId, evidence.environment);
  const { evidenceSha256, ...body } = evidence;
  if (!/^[a-f0-9]{64}$/.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) throw new Error("GitHub environment approval evidence hash is invalid.");
  return evidence;
}

export function assertProductionEnvironmentReviewer(evidence, { approvedBy, executionActor } = {}) {
  const reviewer = requiredText(approvedBy, "approval.approvedBy");
  const actor = requiredText(executionActor, "executionActor");
  if (!assertEvidenceReviewers(evidence?.configuredReviewers).some(({ name }) => name.toLowerCase() === reviewer.toLowerCase())) throw new Error("Backend health recovery approvedBy is not a configured production environment reviewer.");
  if (evidence.preventSelfReview === true && reviewer.toLowerCase() === actor.toLowerCase()) throw new Error("Backend health recovery cannot be self-approved while GitHub prevents self-review.");
  return reviewer;
}

export function assertProductionEnvironmentActualReviewer(evidence, { sourceSha, repository, executionActor } = {}) {
  assertProductionEnvironmentApprovalIdentity(evidence, { sourceSha, repository });
  if (evidence.schemaVersion !== 3) throw new Error("Actual approval evidence from GitHub is required.");
  const actor = requiredText(executionActor, "executionActor");
  if (evidence.actualApproval.userLogin.toLowerCase() === actor.toLowerCase() && evidence.preventSelfReview === true) throw new Error("GitHub environment approval cannot be self-approved while GitHub prevents self-review.");
  return evidence.actualApproval.userLogin;
}

export async function fetchProductionEnvironmentApprovalEvidence(input, { fetchImpl = fetch } = {}) {
  const { token, repository, environment } = input;
  requiredText(token, "GitHub token");
  const response = await fetchImpl(`https://api.github.com/repos/${repository}/environments/${environment}`, { headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" } });
  if (!response.ok) throw new Error(`Unable to authenticate production environment protection rules (${response.status}).`);
  const environmentConfig = await response.json();
  let actualApproval;
  if (input.requireActualApproval) {
    const approvalsResponse = await fetchImpl(`https://api.github.com/repos/${repository}/actions/runs/${input.workflowRunId}/approvals`, { headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" } });
    if (!approvalsResponse.ok) throw new Error(`Unable to authenticate GitHub environment approval event (${approvalsResponse.status}).`);
    const approvals = await approvalsResponse.json();
    const matches = (Array.isArray(approvals) ? approvals : []).flatMap((approval) => (approval?.state === "approved" ? (approval.environments || []).filter((item) => item?.id === environmentConfig.id && item?.name === environment).map(() => ({ state: "approved", environmentId: environmentConfig.id, environmentName: environment, userId: approval.user?.id, userLogin: approval.user?.login })) : []));
    if (matches.length !== 1) throw new Error("Exactly one authenticated GitHub environment approval event is required.");
    actualApproval = matches[0];
  }
  return createProductionEnvironmentApprovalEvidence({ ...input, environmentConfig, actualApproval, token: undefined });
}

export async function runProductionEnvironmentApprovalCli(argv = process.argv.slice(2), deps = {}) {
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "GitHub environment approval evidence", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "GitHub environment approval directory" });
  const evidence = await fetchProductionEnvironmentApprovalEvidence({
    token: (deps.env || process.env).GITHUB_TOKEN,
    repository: required(argv, "--repository"),
    environment: required(argv, "--environment"),
    sourceSha: required(argv, "--source-sha"),
    workflowRef: required(argv, "--workflow-ref"),
    eventName: required(argv, "--event-name"),
    workflowRunId: required(argv, "--workflow-run-id"),
    workflowRunAttempt: required(argv, "--workflow-run-attempt"),
    executionActor: required(argv, "--execution-actor"),
    requireActualApproval: argv.includes("--require-actual-approval"),
  }, deps);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), label: "GitHub environment approval evidence" }] });
  return evidence;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runProductionEnvironmentApprovalCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`));
