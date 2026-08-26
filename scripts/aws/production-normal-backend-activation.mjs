#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { iamSimulationContextArgs } from "./iam-simulation-context.mjs";
import { NORMAL_ACTIVATION, NORMAL_CANDIDATE_ARN, NORMAL_LEGACY_SOURCE_ARN, assertNormalActivationPolicy, assertNormalActivationPolicyTransitionOnly, assertNormalActivationTransactionPolicy, buildNormalActivationPolicy, buildNormalActivationTransactionPolicy, canonicalNormalActivationValue } from "./production-normal-backend-activation-policy.mjs";
import { stageBApprovalIdForReleaseSha } from "./production-green-stage-b-contract.mjs";
import { readBoundStageBPrivateJson } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

export { NORMAL_ACTIVATION, assertNormalActivationPolicy, assertNormalActivationTransactionPolicy, buildNormalActivationPolicy, buildNormalActivationTransactionPolicy } from "./production-normal-backend-activation-policy.mjs";

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonical = canonicalNormalActivationValue;
const POLICY_VERSION = /^v[1-9][0-9]*$/;
const WORKFLOW_RUN_ID = /^[1-9][0-9]*$/;
const BACKEND_IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@(sha256:[a-f0-9]{64})$/;

export class NormalActivationPolicyConvergenceError extends Error {
  constructor(report, cause) {
    super(`${report.status}: ${cause instanceof Error ? cause.message : String(cause)} EXACT_NEXT_ACTION=${report.exactNextAction}`, { cause });
    this.name = "NormalActivationPolicyConvergenceError";
    this.report = Object.freeze(report);
  }
}

export class NormalActivationExecutionError extends Error {
  constructor(report, cause) {
    super(`${report.status}: ${cause instanceof Error ? cause.message : String(cause)} EXACT_NEXT_ACTION=${report.exactNextAction}`, { cause });
    this.name = "NormalActivationExecutionError";
    this.report = Object.freeze(report);
  }
}

function backendResource(state) {
  const candidates = (state?.resources || []).filter(({ mode, type, name }) => mode === "managed" && type === "aws_ecs_task_definition" && name === "candidate")
    .flatMap(({ instances = [] }) => instances)
    .filter(({ index_key: key }) => key === "backend");
  if (candidates.length !== 1) throw new Error("Stage-B state must contain exactly one managed backend candidate instance.");
  return candidates[0].attributes;
}

export function deriveNormalBackendCandidate({ state, stateBytes = Buffer.from(JSON.stringify(state)), sourceSha, imageAuthorization, validateImageAuthorization = assertImageAuthorization } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Normal activation requires the exact protected source SHA.");
  validateImageAuthorization(imageAuthorization, sourceSha);
  if (state?.version !== 4 || state.lineage !== NORMAL_ACTIVATION.lineage || !Number.isInteger(state.serial) || state.serial < NORMAL_ACTIVATION.minimumSerial) throw new Error("Stage-B state identity is outside the production activation contract.");
  const attributes = backendResource(state);
  const targetArn = attributes?.arn;
  if (!NORMAL_CANDIDATE_ARN.test(targetArn || "") || attributes.family !== NORMAL_ACTIVATION.family) throw new Error("Stage-B backend candidate ARN/family is invalid.");
  if (state.outputs?.task_definition_arns?.value?.backend !== targetArn) throw new Error("Stage-B backend candidate output does not match the managed state resource.");
  const containers = JSON.parse(attributes.container_definitions || "null");
  const selected = Array.isArray(containers) ? containers.filter(({ name }) => name === NORMAL_ACTIVATION.container) : [];
  if (selected.length !== 1) throw new Error("Stage-B backend candidate must contain exactly one backend container.");
  const image = selected[0].image;
  const digest = /@(sha256:[a-f0-9]{64})$/.exec(image || "")?.[1];
  if (!digest || digest !== authorizedBackendDigest(imageAuthorization) || state.outputs?.bound_images?.value?.backend !== image) throw new Error("Stage-B backend candidate image is not bound to the current image authorization and state output.");
  const environment = new Map((selected[0].environment || []).map(({ name, value }) => [name, value]));
  if (environment.get("RELEASE_GIT_SHA") !== sourceSha || (environment.has("GIT_SHA") && environment.get("GIT_SHA") !== sourceSha)) throw new Error("Stage-B backend candidate source metadata is stale or mismatched.");
  const tags = attributes.tags_all || attributes.tags || {};
  if (tags.Environment !== "production" || tags.ManagedBy !== "Terraform" || tags.Component !== "full-rls-green-stage-b" || tags.MSCQRExecTarget !== "production-backend") throw new Error("Stage-B backend candidate tags are outside the reviewed contract.");
  return Object.freeze({ sourceSha, stateLineage: state.lineage, stateSerial: state.serial, stateSha256: sha256(stateBytes), targetArn, family: NORMAL_ACTIVATION.family, image, digest });
}

const parseJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
function readLivePolicy(run) {
  const metadata = parseJson(run, ["iam", "get-policy", "--policy-arn", NORMAL_ACTIVATION.policyArn]).Policy;
  if (!/^v[1-9][0-9]*$/.test(metadata?.DefaultVersionId || "")) throw new Error("FinalApplyWrite live policy has no valid default version.");
  const version = parseJson(run, ["iam", "get-policy-version", "--policy-arn", NORMAL_ACTIVATION.policyArn, "--version-id", metadata.DefaultVersionId]).PolicyVersion;
  return { document: normalizeIamPolicyDocument(version?.Document, "live FinalApplyWrite policy"), defaultVersionId: metadata.DefaultVersionId };
}

function readLiveState(run) {
  const bytes = Buffer.from(run(["s3", "cp", NORMAL_ACTIVATION.stateUrl, "-"]));
  return { bytes, state: JSON.parse(bytes) };
}

function oldestDeletablePolicyVersion(versions, defaultVersionId) {
  if (!Array.isArray(versions) || versions.length < 1 || versions.length > 5 || !POLICY_VERSION.test(defaultVersionId || "") || versions.some(({ VersionId, IsDefaultVersion, CreateDate }) => !POLICY_VERSION.test(VersionId || "") || typeof IsDefaultVersion !== "boolean" || Number.isNaN(Date.parse(CreateDate))) || new Set(versions.map(({ VersionId }) => VersionId)).size !== versions.length) throw new Error("FinalApplyWrite policy version topology is malformed.");
  const defaults = versions.filter(({ IsDefaultVersion }) => IsDefaultVersion);
  if (defaults.length !== 1 || defaults[0].VersionId !== defaultVersionId) throw new Error("FinalApplyWrite policy default-version topology is inconsistent.");
  if (versions.length < 5) return null;
  const oldest = versions.filter(({ IsDefaultVersion }) => !IsDefaultVersion).sort((left, right) => Date.parse(left.CreateDate) - Date.parse(right.CreateDate) || left.VersionId.localeCompare(right.VersionId))[0];
  if (!oldest?.VersionId) throw new Error("FinalApplyWrite policy version retention cannot be reconciled safely.");
  return oldest.VersionId;
}

export function assertProductionRlsReleaseReceipt(receipt, { sourceSha, imageDigest }) {
  const copy = structuredClone(receipt);
  const claimed = copy?.receiptBundleSha256;
  delete copy.receiptBundleSha256;
  if (receipt?.schemaVersion !== 2 || receipt.environment !== "production" || receipt.releaseSha !== sourceSha || receipt.images?.backend !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imageDigest}` || receipt.approvalId !== stageBApprovalIdForReleaseSha(sourceSha) || !SHA256.test(claimed || "") || claimed !== sha256(`${JSON.stringify(copy)}\n`)) throw new Error("Production RLS release receipt is not bound to the normal backend activation.");
  return receipt.approvalId;
}

function assertReleaseReceipt(receipt, { sourceSha, imageAuthorization }) {
  return assertProductionRlsReleaseReceipt(receipt, { sourceSha, imageDigest: authorizedBackendDigest(imageAuthorization) });
}

function assertService(service, expectedCurrentArn, expectedCurrentDeploymentId) {
  if (service?.serviceArn !== NORMAL_ACTIVATION.serviceArn || service.clusterArn !== NORMAL_ACTIVATION.clusterArn || service.status !== "ACTIVE" || service.taskDefinition !== expectedCurrentArn || !Number.isInteger(service.desiredCount) || service.desiredCount < 1) throw new Error("Production backend service identity/current revision is invalid.");
  const deployments = service.deployments || [];
  if (deployments.length !== 1 || !/^ecs-svc\/[1-9][0-9]*$/.test(deployments[0]?.id || "") || deployments[0]?.status !== "PRIMARY" || deployments[0]?.taskDefinition !== expectedCurrentArn || deployments[0]?.pendingCount !== 0 || deployments[0]?.runningCount !== service.desiredCount || (deployments[0]?.rolloutState && deployments[0].rolloutState !== "COMPLETED")) throw new Error("Production backend service changed or is not stable before activation.");
  if (expectedCurrentDeploymentId !== undefined && deployments[0].id !== expectedCurrentDeploymentId) throw new Error("Production backend deployment identity changed after overlap verification.");
  return deployments[0].id;
}

function assertTaskDefinition(response, candidate) {
  const task = response?.taskDefinition;
  if (task?.taskDefinitionArn !== candidate.targetArn || task.family !== candidate.family || task.status !== "ACTIVE") throw new Error("Live backend candidate does not match authenticated Stage-B state.");
  const selected = (task.containerDefinitions || []).filter(({ name }) => name === NORMAL_ACTIVATION.container);
  if (selected.length !== 1 || selected[0].image !== candidate.image) throw new Error("Live backend candidate image differs from authenticated Stage-B state.");
  return true;
}

export function classifyNormalActivationSource(taskDefinitionArn) {
  if (NORMAL_CANDIDATE_ARN.test(taskDefinitionArn || "")) return "STAGE_B_CANDIDATE";
  if (NORMAL_LEGACY_SOURCE_ARN.test(taskDefinitionArn || "")) return "LEGACY_BACKEND";
  throw new Error("Normal activation SOURCE task definition is outside the permitted rollback families.");
}

function sourceTaskDefinitionIdentity(response, sourceArn) {
  const task = response?.taskDefinition;
  const sourceClass = classifyNormalActivationSource(sourceArn);
  if (task?.taskDefinitionArn !== sourceArn || task.status !== "ACTIVE") throw new Error("Normal activation SOURCE task definition is not the exact active revision.");
  const family = sourceClass === "STAGE_B_CANDIDATE" ? NORMAL_ACTIVATION.family : "mscqr-backend";
  if (task.family !== family) throw new Error("Normal activation SOURCE task-definition family is inconsistent.");
  const selected = (task.containerDefinitions || []).filter(({ name }) => name === NORMAL_ACTIVATION.container);
  const match = selected.length === 1 ? BACKEND_IMAGE.exec(selected[0].image || "") : null;
  if (!match) throw new Error("Normal activation SOURCE backend image is not an exact immutable production digest.");
  return Object.freeze({ sourceArn, sourceClass, sourceImage: selected[0].image, sourceDigest: match[1] });
}

function assertRollbackImageAvailable(run, digest) {
  let response;
  try { response = parseJson(run, ["ecr", "describe-images", "--repository-name", "mscqr-backend", "--image-ids", `imageDigest=${digest}`]); }
  catch (error) { throw new Error(`Normal activation rollback image viability is unproven: ${/ImageNotFoundException/.test(`${error?.stderr || error?.message || ""}`) ? "exact source digest is absent" : "ECR lookup failed"}.`); }
  if (response?.imageDetails?.length !== 1 || response.imageDetails[0]?.imageDigest !== digest) throw new Error("Normal activation rollback image viability response does not match the exact source digest.");
  return true;
}

function assertRunningServiceTarget(run, { taskDefinitionArn, digest, desiredCount }) {
  const listed = parseJson(run, ["ecs", "list-tasks", "--cluster", NORMAL_ACTIVATION.cluster, "--service-name", NORMAL_ACTIVATION.service, "--desired-status", "RUNNING"]);
  if (!Array.isArray(listed?.taskArns) || listed.nextToken || listed.taskArns.length !== desiredCount) throw new Error("Normal activation running task list is incomplete.");
  const tasks = parseJson(run, ["ecs", "describe-tasks", "--cluster", NORMAL_ACTIVATION.cluster, "--tasks", ...listed.taskArns]);
  if (!Array.isArray(tasks?.failures) || tasks.failures.length !== 0 || !Array.isArray(tasks.tasks) || tasks.tasks.length !== desiredCount) throw new Error("Normal activation running task readback is incomplete.");
  for (const task of tasks.tasks) {
    const containers = (task.containers || []).filter(({ name }) => name === NORMAL_ACTIVATION.container);
    if (task.lastStatus !== "RUNNING" || task.taskDefinitionArn !== taskDefinitionArn || containers.length !== 1 || containers[0].imageDigest !== digest) throw new Error("Normal activation running task does not match the authenticated task definition and digest.");
  }
  return true;
}

function assertRunIdentity(runIdentity) {
  if (!WORKFLOW_RUN_ID.test(String(runIdentity?.workflowRunId || "")) || !WORKFLOW_RUN_ID.test(String(runIdentity?.releaseTrainRunId || ""))) throw new Error("Normal activation requires exact Release Gate and Release Train run identities.");
  return Object.freeze({ workflowRunId: String(runIdentity.workflowRunId), releaseTrainRunId: String(runIdentity.releaseTrainRunId) });
}

export function collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn, expectedCurrentDeploymentId, validateImageAuthorization, runIdentity } = {}) {
  if (typeof run !== "function") throw new Error("Authenticated AWS command runner is required.");
  const caller = parseJson(run, ["sts", "get-caller-identity"]);
  if (caller.Account !== NORMAL_ACTIVATION.account || !new RegExp(`^arn:aws:sts::${NORMAL_ACTIVATION.account}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(caller.Arn || "")) throw new Error("Normal activation requires the canonical release-deployer session.");
  const liveState = readLiveState(run);
  const candidate = deriveNormalBackendCandidate({ state: liveState.state, stateBytes: liveState.bytes, sourceSha, imageAuthorization, ...(validateImageAuthorization ? { validateImageAuthorization } : {}) });
  assertTaskDefinition(parseJson(run, ["ecs", "describe-task-definition", "--task-definition", candidate.targetArn, "--include", "TAGS"]), candidate);
  const service = parseJson(run, ["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.cluster, "--services", NORMAL_ACTIVATION.service]).services?.[0];
  const current = expectedCurrentTaskDefinitionArn || service?.taskDefinition;
  const currentDeploymentId = assertService(service, current, expectedCurrentDeploymentId);
  const source = sourceTaskDefinitionIdentity(parseJson(run, ["ecs", "describe-task-definition", "--task-definition", current, "--include", "TAGS"]), current);
  assertRollbackImageAvailable(run, source.sourceDigest);
  assertRunningServiceTarget(run, { taskDefinitionArn: current, digest: source.sourceDigest, desiredCount: service.desiredCount });
  const policy = readLivePolicy(run);
  assertNormalActivationTransactionPolicy(policy.document, { sourceArn: current, targetArn: candidate.targetArn });
  return Object.freeze({ schemaVersion: 2, releaseMode: "normal", ...candidate, ...source, rollbackImageVerified: true, desiredCount: service.desiredCount, clusterArn: NORMAL_ACTIVATION.clusterArn, serviceArn: NORMAL_ACTIVATION.serviceArn, expectedCurrentTaskDefinitionArn: current, expectedCurrentDeploymentId: currentDeploymentId, policyArn: NORMAL_ACTIVATION.policyArn, policyVersionId: policy.defaultVersionId, livePolicySha256: sha256(canonical(policy.document)), ...(runIdentity ? assertRunIdentity(runIdentity) : {}) });
}

export function assertNormalActivationBinding(binding, expected) {
  if (canonical(binding) !== canonical(expected)) throw new Error("Normal activation binding is stale, modified, or replayed across live state.");
  return true;
}

export function normalActivationSimulationContext(taskDefinitionArn) {
  classifyNormalActivationSource(taskDefinitionArn);
  return Object.freeze([
    Object.freeze({ key: "aws:RequestedRegion", type: "string", values: Object.freeze([NORMAL_ACTIVATION.region]) }),
    Object.freeze({ key: "ecs:cluster", type: "string", values: Object.freeze([NORMAL_ACTIVATION.clusterArn]) }),
    Object.freeze({ key: "ecs:task-definition", type: "string", values: Object.freeze([taskDefinitionArn]) }),
  ]);
}

function simulateNormalActivationTarget(run, taskDefinitionArn) {
  const response = parseJson(run, ["iam", "simulate-principal-policy", "--policy-source-arn", NORMAL_ACTIVATION.roleArn, "--action-names", "ecs:UpdateService", "--resource-arns", NORMAL_ACTIVATION.serviceArn, "--context-entries", ...iamSimulationContextArgs(normalActivationSimulationContext(taskDefinitionArn))]);
  if (!Array.isArray(response?.EvaluationResults) || response.EvaluationResults.length !== 1) throw new Error("Normal activation IAM simulation returned malformed results.");
  const result = response.EvaluationResults[0];
  if (result?.EvalActionName !== "ecs:UpdateService" || result.EvalResourceName !== NORMAL_ACTIVATION.serviceArn || !["allowed", "explicitDeny", "implicitDeny"].includes(result.EvalDecision)) throw new Error("Normal activation IAM simulation did not bind the exact action and service.");
  return result.EvalDecision;
}

function convergenceFailure({ mutationAttempted, readbackVerified, confirmedIamWrites }, error) {
  const status = !mutationAttempted
    ? "NO_MUTATION_CONVERGENCE_FAILED"
    : readbackVerified
      ? "CONVERGENCE_MUTATION_READBACK_VERIFIED_VALIDATION_FAILED"
      : "PARTIAL_CONVERGENCE_LIVE_STATE_UNAUTHENTICATED";
  const exactNextAction = !mutationAttempted
    ? "CORRECT_REPORTED_PRECONDITION_AND_RERUN_GOVERNED_CONVERGENCE"
    : readbackVerified
      ? "RERUN_GOVERNED_CONVERGENCE_TO_COMPLETE_SIMULATION_VALIDATION"
      : "RERUN_SAME_GOVERNED_CONVERGENCE_WITH_ADMIN_PROFILE_TO_AUTHENTICATE_AND_RECONCILE_LIVE_POLICY";
  return new NormalActivationPolicyConvergenceError({ status, mutationAttempted, readbackVerified, confirmedIamWrites, unknownMutations: mutationAttempted && !readbackVerified ? 1 : 0, rollbackAttempted: false, retrySafe: true, exactNextAction }, error);
}

function publishNormalActivationPolicy({ run, before, expected, assertAfter, progress }) {
  let ambiguousMutationError = null;
  let policyVersionCreateAttempted = false;
  if (canonical(before.document) !== canonical(expected)) {
    try {
      const versions = parseJson(run, ["iam", "list-policy-versions", "--policy-arn", NORMAL_ACTIVATION.policyArn]).Versions;
      const versionToDelete = oldestDeletablePolicyVersion(versions, before.defaultVersionId);
      if (versionToDelete) {
        progress.mutationAttempted = true;
        run(["iam", "delete-policy-version", "--policy-arn", NORMAL_ACTIVATION.policyArn, "--version-id", versionToDelete, "--no-cli-pager"]); progress.confirmedIamWrites += 1;
      }
      progress.mutationAttempted = true;
      policyVersionCreateAttempted = true;
      run(["iam", "create-policy-version", "--policy-arn", NORMAL_ACTIVATION.policyArn, "--policy-document", JSON.stringify(expected), "--set-as-default", "--no-cli-pager"]); progress.confirmedIamWrites += 1;
    } catch (error) { ambiguousMutationError = error; }
  }
  const after = readLivePolicy(run);
  assertAfter(after.document);
  progress.readbackVerified = true;
  if (ambiguousMutationError && policyVersionCreateAttempted) progress.confirmedIamWrites += 1;
  return { after, ambiguousMutationError };
}

function readNormalActivationStateTarget(run, sourceSha) {
  const liveState = readLiveState(run);
  const state = liveState.state;
  const attributes = backendResource(state);
  const targetArn = attributes?.arn;
  const containers = JSON.parse(attributes?.container_definitions || "null");
  const backend = containers?.filter(({ name }) => name === NORMAL_ACTIVATION.container) || [];
  const releaseSha = new Map((backend[0]?.environment || []).map(({ name, value }) => [name, value])).get("RELEASE_GIT_SHA");
  const imageMatch = backend.length === 1 ? BACKEND_IMAGE.exec(backend[0].image || "") : null;
  if (state.lineage !== NORMAL_ACTIVATION.lineage || !Number.isInteger(state.serial) || state.serial < NORMAL_ACTIVATION.minimumSerial || state.outputs?.task_definition_arns?.value?.backend !== targetArn || state.outputs?.bound_images?.value?.backend !== backend[0]?.image || releaseSha !== sourceSha || !NORMAL_CANDIDATE_ARN.test(targetArn || "") || !imageMatch) throw new Error("Normal activation IAM convergence requires the current-source authenticated Stage-B candidate state.");
  return { liveState, state, targetArn, targetDigest: imageMatch[1] };
}

function readNormalActivationServiceSource(run, targetArn) {
  const service = parseJson(run, ["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.cluster, "--services", NORMAL_ACTIVATION.service]).services?.[0];
  const sourceArn = service?.taskDefinition;
  assertService(service, sourceArn);
  const source = sourceTaskDefinitionIdentity(parseJson(run, ["ecs", "describe-task-definition", "--task-definition", sourceArn, "--include", "TAGS"]), sourceArn);
  assertRunningServiceTarget(run, { taskDefinitionArn: sourceArn, digest: source.sourceDigest, desiredCount: service.desiredCount });
  return { service, sourceArn, source, alreadyAtTarget: sourceArn === targetArn };
}

function normalActivationDeniedTargets(sourceArn, targetArn) {
  const revision = Number(NORMAL_CANDIDATE_ARN.exec(targetArn)[1]);
  const candidates = [revision - 2, revision - 1, revision + 1, revision + 2].filter((value) => value > 0).map((value) => targetArn.replace(/:[1-9][0-9]*$/, `:${value}`));
  const legacy = [1, 2].map((revisionValue) => `arn:aws:ecs:${NORMAL_ACTIVATION.region}:${NORMAL_ACTIVATION.account}:task-definition/mscqr-backend:${revisionValue}`);
  return [...new Set([...candidates, ...legacy])].filter((arn) => arn !== sourceArn && arn !== targetArn);
}

export function convergeNormalActivationPolicy({ run, sourceSha } = {}) {
  const progress = { mutationAttempted: false, readbackVerified: false, confirmedIamWrites: 0 };
  try {
    if (typeof run !== "function" || !SHA.test(sourceSha || "")) throw new Error("Governed normal activation convergence inputs are invalid.");
    const caller = parseJson(run, ["sts", "get-caller-identity"]);
    if (caller.Account !== NORMAL_ACTIVATION.account || caller.Arn !== NORMAL_ACTIVATION.administratorArn) throw new Error("Normal activation IAM convergence requires the governed root administrator identity.");
    const { liveState, state, targetArn } = readNormalActivationStateTarget(run, sourceSha);
    const { service, sourceArn, source, alreadyAtTarget } = readNormalActivationServiceSource(run, targetArn);
    const expected = buildNormalActivationTransactionPolicy({ sourceArn, targetArn });
    const before = readLivePolicy(run);
    assertNormalActivationPolicyTransitionOnly(before.document, { sourceArn, targetArn });
    const publication = publishNormalActivationPolicy({ run, before, expected, assertAfter: (document) => assertNormalActivationTransactionPolicy(document, { sourceArn, targetArn }), progress });
    const { after, ambiguousMutationError } = publication;
    for (const allowedTargetArn of new Set([sourceArn, targetArn])) if (simulateNormalActivationTarget(run, allowedTargetArn) !== "allowed") throw new Error("Exact normal activation SOURCE or TARGET revision is not authorized after IAM convergence.");
    for (const deniedTargetArn of normalActivationDeniedTargets(sourceArn, targetArn)) if (simulateNormalActivationTarget(run, deniedTargetArn) !== "implicitDeny") throw new Error("Unrelated normal or recovery task-definition revision is unexpectedly authorized during normal activation.");
    return Object.freeze({ status: progress.mutationAttempted ? ambiguousMutationError ? "RECONCILED_AFTER_AMBIGUOUS_WRITE" : "CONVERGED" : "ALREADY_CONVERGED", sourceSha, sourceArn, sourceClass: source.sourceClass, sourceDigest: source.sourceDigest, targetArn, desiredCount: service.desiredCount, alreadyAtTarget, stateLineage: state.lineage, stateSerial: state.serial, stateSha256: sha256(liveState.bytes), policyVersionId: after.defaultVersionId, iamWrites: progress.confirmedIamWrites, mutationAttempted: progress.mutationAttempted, mutationOutcome: ambiguousMutationError ? "CONFIRMED_SUCCESS_READBACK" : progress.mutationAttempted ? "CONFIRMED_SUCCESS" : "NO_MUTATION", readbackVerified: progress.readbackVerified, validationComplete: true, unknownMutations: 0 });
  } catch (error) {
    if (error instanceof NormalActivationPolicyConvergenceError) throw error;
    throw convergenceFailure(progress, error);
  }
}

export function contractNormalActivationPolicy({ run, sourceSha, sourceArn } = {}) {
  const progress = { mutationAttempted: false, readbackVerified: false, confirmedIamWrites: 0 };
  try {
    if (typeof run !== "function" || !SHA.test(sourceSha || "") || !sourceArn) throw new Error("Governed normal activation contraction inputs are invalid.");
    const caller = parseJson(run, ["sts", "get-caller-identity"]);
    if (caller.Account !== NORMAL_ACTIVATION.account || caller.Arn !== NORMAL_ACTIVATION.administratorArn) throw new Error("Normal activation IAM contraction requires the governed root administrator identity.");
    const { state, targetArn, targetDigest } = readNormalActivationStateTarget(run, sourceSha);
    classifyNormalActivationSource(sourceArn);
    const service = parseJson(run, ["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.cluster, "--services", NORMAL_ACTIVATION.service]).services?.[0];
    assertService(service, targetArn);
    assertRunningServiceTarget(run, { taskDefinitionArn: targetArn, digest: targetDigest, desiredCount: service.desiredCount });
    const before = readLivePolicy(run);
    let initialState;
    try { assertNormalActivationPolicy(before.document, targetArn); initialState = "STEADY_TARGET"; }
    catch { assertNormalActivationTransactionPolicy(before.document, { sourceArn, targetArn }); initialState = "TRANSACTION"; }
    const expected = buildNormalActivationPolicy(targetArn);
    const publication = publishNormalActivationPolicy({ run, before, expected, assertAfter: (document) => assertNormalActivationPolicy(document, targetArn), progress });
    const { after, ambiguousMutationError } = publication;
    if (simulateNormalActivationTarget(run, targetArn) !== "allowed") throw new Error("Exact steady-state TARGET is not authorized after contraction.");
    return Object.freeze({ status: progress.mutationAttempted ? ambiguousMutationError ? "CONTRACTION_RECONCILED_AFTER_AMBIGUOUS_WRITE" : "CONTRACTED" : "ALREADY_CONTRACTED", sourceSha, sourceArn, targetArn, initialState, stateLineage: state.lineage, stateSerial: state.serial, policyVersionId: after.defaultVersionId, iamWrites: progress.confirmedIamWrites, readbackVerified: progress.readbackVerified, unknownMutations: 0 });
  } catch (error) {
    if (error instanceof NormalActivationPolicyConvergenceError) throw error;
    throw convergenceFailure(progress, error);
  }
}

function writePrivateJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
}

export function classifyNormalActivationLiveOutcome({ run, binding }) {
  try {
    const service = parseJson(run, ["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.cluster, "--services", NORMAL_ACTIVATION.service]).services?.[0];
    const currentArn = service?.taskDefinition;
    const expectedDigest = currentArn === binding.targetArn ? binding.digest : currentArn === binding.sourceArn ? binding.sourceDigest : null;
    if (!expectedDigest) return Object.freeze({ status: "UNEXPECTED_SERVICE_TARGET", currentArn });
    assertService(service, currentArn);
    assertRunningServiceTarget(run, { taskDefinitionArn: currentArn, digest: expectedDigest, desiredCount: binding.desiredCount });
    return Object.freeze({ status: currentArn === binding.sourceArn ? "SOURCE_STABLE" : "TARGET_STABLE", currentArn, runningDigest: expectedDigest });
  } catch (error) { return Object.freeze({ status: "LIVE_STATE_UNAUTHENTICATED", error: error.message }); }
}

export function executeNormalBackendActivation({ run, runScript = execFileSync, sourceSha, imageAuthorization, releaseReceipt, binding, metadataFile, deployScript = path.resolve("scripts/aws/deploy-ecs-service.sh"), runIdentity } = {}) {
  assertReleaseReceipt(releaseReceipt, { sourceSha, imageAuthorization });
  const fresh = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: binding?.expectedCurrentTaskDefinitionArn, expectedCurrentDeploymentId: binding?.expectedCurrentDeploymentId, runIdentity });
  assertNormalActivationBinding(binding, fresh);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-activation-"));
  const bindingFile = path.join(directory, "binding.json");
  const outcomeFile = path.join(directory, "outcome.json");
  try {
    writePrivateJson(bindingFile, binding);
    runScript(deployScript, [], { cwd: process.cwd(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: {
      ...process.env,
      AWS_REGION: NORMAL_ACTIVATION.region,
      CLUSTER_NAME: NORMAL_ACTIVATION.cluster,
      SERVICE_NAME: NORMAL_ACTIVATION.service,
      CONTAINER_NAME: NORMAL_ACTIVATION.container,
      EXISTING_TASK_DEFINITION_ARN: binding.targetArn,
      EXPECTED_CURRENT_TASK_DEFINITION_ARN: binding.expectedCurrentTaskDefinitionArn,
      EXPECTED_FAMILY: NORMAL_ACTIVATION.family,
      EXPECTED_IMAGE_DIGEST: binding.digest,
      EXPECTED_GIT_SHA: sourceSha,
      VERSION_URL: "https://www.mscqr.com/api/health",
      WAIT_FOR_STABLE: "true",
      ENABLE_EXECUTE_COMMAND: "true",
      PROPAGATE_TAGS: "TASK_DEFINITION",
      METADATA_FILE: metadataFile,
      MSCQR_GOVERNED_ORCHESTRATOR: "1",
      MSCQR_EXISTING_TASK_DEPLOYMENT_MODE: "normal-stage-b",
      NORMAL_ACTIVATION_BINDING_FILE: bindingFile,
      NORMAL_ACTIVATION_BINDING_SHA256: sha256(fs.readFileSync(bindingFile)),
      NORMAL_ACTIVATION_OUTCOME_FILE: outcomeFile,
    } });
    const metadata = JSON.parse(fs.readFileSync(metadataFile, "utf8"));
    fs.writeFileSync(metadataFile, `${JSON.stringify({ ...metadata, normalActivationSourceArn: binding.sourceArn, normalActivationTargetArn: binding.targetArn, authorityContractionRequired: true, contractionCommand: `npm run production:normal-backend-activation -- --mode contract-policy --source-sha ${sourceSha} --source-task-definition ${binding.sourceArn} --admin-profile <governed-admin-profile>` }, null, 2)}\n`, { mode: 0o600 });
    return Object.freeze({ status: binding.sourceArn === binding.targetArn ? "ALREADY_APPLIED_EXACT_TARGET" : "APPLIED_EXACT_TARGET", sourceArn: binding.sourceArn, targetArn: binding.targetArn, postSuccessAuthorityContractionRequired: true, exactNextAction: `RUN_GOVERNED_ADMIN_CONTRACTION_FOR_${binding.targetArn}` });
  } catch (error) {
    const outcome = classifyNormalActivationLiveOutcome({ run, binding });
    let scriptOutcome;
    try { scriptOutcome = JSON.parse(fs.readFileSync(outcomeFile, "utf8")); } catch { scriptOutcome = null; }
    const noMutation = scriptOutcome?.updateState === "NOT_ATTEMPTED" && outcome.status === "SOURCE_STABLE";
    const rollbackVerified = new Set(["VERIFIED_SOURCE", "SOURCE_ALREADY_RESTORED"]).has(scriptOutcome?.rollbackResult) && outcome.status === "SOURCE_STABLE";
    const status = noMutation ? "NO_ECS_MUTATION_FAILED" : rollbackVerified ? "TARGET_FAILED_ROLLBACK_VERIFIED" : outcome.status === "TARGET_STABLE" ? "TARGET_REMAINS_RECONCILIATION_REQUIRED" : "ACTIVATION_STATE_UNAUTHENTICATED";
    const report = { status, sourceArn: binding.sourceArn, targetArn: binding.targetArn, scriptOutcome, liveOutcome: outcome, rollbackVerified, retrySafe: noMutation || rollbackVerified, authorityContractionRequired: false, exactNextAction: noMutation || rollbackVerified ? "RETRY_SAME_AUTHENTICATED_NORMAL_ACTIVATION_TRANSACTION" : "READ_LIVE_SERVICE_WITH_GOVERNED_RELEASE_IDENTITY_AND_RECONCILE_BEFORE_RETRY" };
    fs.writeFileSync(metadataFile, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    throw new NormalActivationExecutionError(report, error);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    values.set(key, value);
  }
  return values;
}
const required = (values, name) => { const value = values.get(name); if (!value) throw new Error(`${name} is required.`); return value; };

export function runCli(argv = process.argv.slice(2)) {
  const values = parseArgs(argv);
  const mode = required(values, "--mode");
  const sourceSha = required(values, "--source-sha");
  if (mode === "converge-policy") {
    const checkout = readStageBProtectedMainCheckout({ cwd: process.cwd() });
    if (checkout.currentHead !== sourceSha) throw new Error("Normal activation convergence must run from exact protected main.");
    const result = convergeNormalActivationPolicy({ run: createProductionCommandRunner({ profile: required(values, "--admin-profile") }), sourceSha });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result;
  }
  if (mode === "contract-policy") {
    const checkout = readStageBProtectedMainCheckout({ cwd: process.cwd() });
    if (checkout.currentHead !== sourceSha) throw new Error("Normal activation contraction must run from exact protected main.");
    const result = contractNormalActivationPolicy({ run: createProductionCommandRunner({ profile: required(values, "--admin-profile") }), sourceSha, sourceArn: required(values, "--source-task-definition") });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result;
  }
  const imageAuthorization = readBoundStageBPrivateJson({ filePath: required(values, "--image-authorization"), expectedSha256: required(values, "--image-authorization-sha256"), label: "Normal release image authorization" });
  const run = createProductionCommandRunner();
  const runIdentity = { workflowRunId: required(values, "--workflow-run-id"), releaseTrainRunId: required(values, "--release-train-run-id") };
  if (mode === "prepare") {
    const binding = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: values.get("--expected-current-task-definition"), expectedCurrentDeploymentId: values.get("--expected-current-deployment-id"), runIdentity });
    writePrivateJson(required(values, "--binding-out"), binding);
    process.stdout.write(`${JSON.stringify({ status: "AUTHORIZED", targetArn: binding.targetArn, stateSerial: binding.stateSerial })}\n`);
    return binding;
  }
  if (mode === "verify") {
    const binding = readBoundStageBPrivateJson({ filePath: required(values, "--binding"), expectedSha256: required(values, "--binding-sha256"), label: "Normal backend activation binding" });
    const fresh = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: binding.expectedCurrentTaskDefinitionArn, expectedCurrentDeploymentId: binding.expectedCurrentDeploymentId, runIdentity });
    assertNormalActivationBinding(binding, fresh);
    process.stdout.write(`${JSON.stringify({ status: "VERIFIED", sourceArn: binding.sourceArn, targetArn: binding.targetArn, expectedCurrentDeploymentId: binding.expectedCurrentDeploymentId })}\n`);
    return binding;
  }
  if (mode === "execute") {
    const binding = readBoundStageBPrivateJson({ filePath: required(values, "--binding"), expectedSha256: required(values, "--binding-sha256"), label: "Normal backend activation binding" });
    const receipt = readBoundStageBPrivateJson({ filePath: required(values, "--release-receipt"), expectedSha256: required(values, "--release-receipt-sha256"), label: "Production RLS release receipt" });
    const result = executeNormalBackendActivation({ run, sourceSha, imageAuthorization, releaseReceipt: receipt, binding, metadataFile: required(values, "--metadata-out"), runIdentity });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result;
  }
  throw new Error("--mode must be converge-policy, contract-policy, prepare, verify, or execute.");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { runCli(); }
  catch (error) {
    if (!(error instanceof NormalActivationPolicyConvergenceError) && !(error instanceof NormalActivationExecutionError)) throw error;
    process.stderr.write(`${JSON.stringify(error.report)}\n`);
    process.exitCode = 1;
  }
}
