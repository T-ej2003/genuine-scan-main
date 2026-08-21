#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

export const PRODUCTION_ENVIRONMENT_APPROVAL = Object.freeze({
  kind: "GITHUB_PROTECTED_ENVIRONMENT_APPROVAL",
  schemaVersion: 1,
  repository: "T-ej2003/genuine-scan-main",
  environment: "production",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main",
  eventName: "workflow_dispatch",
  maxAgeMs: 30 * 60 * 1000,
});

const SHA = /^[a-f0-9]{40}$/;
const RUN_ID = /^[1-9][0-9]*$/;
const FIELDS = new Set(["schemaVersion", "kind", "repository", "environment", "environmentId", "sourceSha", "workflowRef", "eventName", "workflowRunId", "workflowRunAttempt", "executionActor", "requiredReviewerCount", "preventSelfReview", "canAdminsBypass", "observedAt", "evidenceSha256"]);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

const requiredText = (value, label) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`);
  return value.trim();
};

export function createProductionEnvironmentApprovalEvidence({ environmentConfig, repository, environment, sourceSha, workflowRef, eventName, workflowRunId, workflowRunAttempt, executionActor, observedAt = new Date().toISOString() } = {}) {
  if (repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || environment !== PRODUCTION_ENVIRONMENT_APPROVAL.environment || environmentConfig?.name !== environment) throw new Error("GitHub production environment identity is invalid.");
  if (!SHA.test(sourceSha || "") || workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.workflowRef || eventName !== PRODUCTION_ENVIRONMENT_APPROVAL.eventName
    || !RUN_ID.test(String(workflowRunId || "")) || !RUN_ID.test(String(workflowRunAttempt || ""))) throw new Error("GitHub environment approval source or workflow identity is invalid.");
  const rules = (environmentConfig.protection_rules || []).filter((rule) => rule?.type === "required_reviewers");
  if (rules.length !== 1 || !Array.isArray(rules[0].reviewers) || rules[0].reviewers.length < 1) throw new Error("Production environment must require at least one reviewer.");
  if (rules[0].prevent_self_review !== true) throw new Error("Production environment must prevent self-review.");
  if (environmentConfig.can_admins_bypass !== false) throw new Error("Production environment must disable administrator bypass.");
  const body = {
    schemaVersion: PRODUCTION_ENVIRONMENT_APPROVAL.schemaVersion,
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
    requiredReviewerCount: rules[0].reviewers.length,
    preventSelfReview: true,
    canAdminsBypass: false,
    observedAt,
  };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertProductionEnvironmentApprovalEvidence(evidence, { sourceSha, repository, environment, workflowRef, eventName, workflowRunId, workflowRunAttempt, executionActor, githubActions, now = new Date() } = {}) {
  if (!evidence || Object.keys(evidence).length !== FIELDS.size || Object.keys(evidence).some((field) => !FIELDS.has(field))) throw new Error("GitHub environment approval evidence schema is invalid.");
  const actor = requiredText(evidence.executionActor, "evidence.executionActor");
  if (evidence.schemaVersion !== PRODUCTION_ENVIRONMENT_APPROVAL.schemaVersion || evidence.kind !== PRODUCTION_ENVIRONMENT_APPROVAL.kind
    || repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || evidence.repository !== repository
    || environment !== PRODUCTION_ENVIRONMENT_APPROVAL.environment || evidence.environment !== environment
    || evidence.sourceSha !== sourceSha || !SHA.test(sourceSha || "")
    || githubActions !== "true" || workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.workflowRef || evidence.workflowRef !== workflowRef
    || eventName !== PRODUCTION_ENVIRONMENT_APPROVAL.eventName || evidence.eventName !== eventName
    || evidence.workflowRunId !== String(workflowRunId || "") || !RUN_ID.test(evidence.workflowRunId)
    || evidence.workflowRunAttempt !== String(workflowRunAttempt || "") || !RUN_ID.test(evidence.workflowRunAttempt)
    || actor.toLowerCase() !== requiredText(executionActor, "executionActor").toLowerCase()
    || !Number.isSafeInteger(evidence.environmentId) || evidence.environmentId < 1
    || !Number.isSafeInteger(evidence.requiredReviewerCount) || evidence.requiredReviewerCount < 1
    || evidence.preventSelfReview !== true || evidence.canAdminsBypass !== false) throw new Error("GitHub environment approval evidence is not bound to this protected recovery run.");
  const observed = new Date(evidence.observedAt);
  const age = now.getTime() - observed.getTime();
  if (!Number.isFinite(observed.getTime()) || observed.toISOString() !== evidence.observedAt || age < 0 || age > PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs) throw new Error("GitHub environment approval evidence is stale or malformed.");
  const { evidenceSha256, ...body } = evidence;
  if (!/^[a-f0-9]{64}$/.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) throw new Error("GitHub environment approval evidence hash is invalid.");
  return evidence;
}

export async function fetchProductionEnvironmentApprovalEvidence(input, { fetchImpl = fetch } = {}) {
  const { token, repository, environment } = input;
  requiredText(token, "GitHub token");
  const response = await fetchImpl(`https://api.github.com/repos/${repository}/environments/${environment}`, { headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "X-GitHub-Api-Version": "2022-11-28" } });
  if (!response.ok) throw new Error(`Unable to authenticate production environment protection rules (${response.status}).`);
  return createProductionEnvironmentApprovalEvidence({ ...input, environmentConfig: await response.json(), token: undefined });
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
  }, deps);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), label: "GitHub environment approval evidence" }] });
  return evidence;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runProductionEnvironmentApprovalCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`));
