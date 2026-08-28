#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { assertManagedPolicyDocumentSize } from "./production-stage-a-temporary-kms-capability.mjs";
import { AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES } from "./reconcile-production-stage-a-temporary-kms-capability.mjs";
import { assertStageAApprovalKeyReconciliationAuthorization, assertStageAApprovalKeyReconciliationPlan, executeStageAApprovalKeyReconciliation, materializeStageAReconciliationPlan, resolveStageAReconciliationAuthorizationArtifact, STAGE_A_RECONCILIATION_AUTHORIZATION } from "./production-stage-a-approval-key-reconciliation-authorization.mjs";
import { buildStageAStateIdentity, parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { ensureStageBPrivateDirectory, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sourcePolicyPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const policyHash = (value) => canonicalSha256(value);
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const same = (left, right) => canonical(left) === canonical(right);
const actions = (statement) => Array.isArray(statement?.Action) ? statement.Action : [statement?.Action];
const historicalSteadyPolicyHashes = new Set(AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES.map(({ policySha256 }) => policySha256));

export const STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY = Object.freeze({
  schemaVersion: 1,
  kind: "STAGE_A_APPROVAL_KEY_RECONCILIATION_TEMPORARY_CAPABILITY",
  operation: "STAGE_A_APPROVAL_KEY_POLICY_RECONCILIATION",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageARelease",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  releaseRoleName: "mscqr-production-release-deployer",
  action: "kms:PutKeyPolicy",
  approvalKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478",
  region: "eu-west-2",
  maxTerraformApplies: 1,
});

export function assertApprovalKeyReconciliationSteadyPolicy(policy) {
  if (!policy || policy.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) throw new Error("Stage-A approval-key capability steady policy is malformed.");
  if (policy.Statement.some((statement) => actions(statement).some((action) => action === STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.action || action === "kms:*"))) throw new Error("Stage-A release-deployer steady policy must not grant temporary approval-key capability.");
  return true;
}

export function temporaryApprovalKeyCapabilityStatement(authorization) {
  assertStageAApprovalKeyReconciliationAuthorization(authorization, { sourceSha: authorization?.sourceSha });
  if (authorization.approvalKeyArn !== STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.approvalKeyArn) throw new Error("Stage-A approval-key capability is outside the exact approval key boundary.");
  return Object.freeze({
    Sid: `TemporaryStageAApprovalKeyPutKeyPolicy${authorization.authorizationSha256}`,
    Effect: "Allow",
    Action: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.action,
    Resource: authorization.approvalKeyArn,
  });
}

export function buildTemporaryApprovalKeyCapabilityPolicy(steadyPolicy, authorization) {
  assertApprovalKeyReconciliationSteadyPolicy(steadyPolicy);
  const statement = temporaryApprovalKeyCapabilityStatement(authorization);
  const policy = { ...structuredClone(steadyPolicy), Statement: [...steadyPolicy.Statement, statement] };
  assertTemporaryApprovalKeyCapabilityPolicy(policy, { steadyPolicy, authorization });
  assertManagedPolicyDocumentSize(policy, { label: "Temporary Stage-A approval-key capability policy" });
  return policy;
}

export function assertTemporaryApprovalKeyCapabilityPolicy(policy, { steadyPolicy, authorization } = {}) {
  assertApprovalKeyReconciliationSteadyPolicy(steadyPolicy);
  const expected = temporaryApprovalKeyCapabilityStatement(authorization);
  if (!policy || policy.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) throw new Error("Temporary Stage-A approval-key capability policy is malformed.");
  const temporary = policy.Statement.filter((statement) => statement?.Sid === expected.Sid);
  if (temporary.length !== 1 || !same(temporary[0], expected)) throw new Error("Temporary Stage-A approval-key capability is not exact.");
  const remaining = policy.Statement.filter((statement) => statement?.Sid !== expected.Sid);
  if (!same({ ...policy, Statement: remaining }, steadyPolicy)) throw new Error("Temporary Stage-A approval-key capability changes more than the exact permission.");
  if (policy.Statement.filter((statement) => actions(statement).includes(STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.action)).length !== 1) throw new Error("Temporary Stage-A approval-key capability grants an additional KMS policy action.");
  return true;
}

export function buildApprovalKeyReconciliationCapabilityEvidence({ authorization, workflow, artifact, previousDefaultVersionId, temporaryVersionId } = {}) {
  assertStageAApprovalKeyReconciliationAuthorization(authorization, { sourceSha: authorization?.sourceSha });
  if (!workflow || String(workflow.id) !== authorization.protectedEnvironmentApprovalEvidence.workflowRunId || String(workflow.run_attempt) !== authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt || workflow.path !== ".github/workflows/authorize-production-stage-a-reconciliation.yml") throw new Error("Stage-A approval-key capability workflow binding is invalid.");
  if (!artifact || !Number.isSafeInteger(artifact.id) || artifact.id < 1 || artifact.name !== "stage-a-approval-key-reconciliation-authorization" || artifact.expired !== false || !/^sha256:[a-f0-9]{64}$/.test(artifact.digest || "") || String(artifact.workflow_run?.id) !== String(workflow.id) || artifact.workflow_run?.head_sha !== authorization.sourceSha) throw new Error("Stage-A approval-key capability artifact binding is invalid.");
  if (!VERSION.test(previousDefaultVersionId || "") || !VERSION.test(temporaryVersionId || "")) throw new Error("Stage-A approval-key capability policy-version binding is invalid.");
  const body = {
    schemaVersion: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.schemaVersion,
    kind: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.kind,
    operation: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.operation,
    sourceSha: authorization.sourceSha,
    repository: authorization.protectedEnvironmentApprovalEvidence.repository,
    authorizationSha256: authorization.authorizationSha256,
    workflowRunId: String(workflow.id),
    workflowRunAttempt: String(workflow.run_attempt),
    workflowRef: authorization.protectedEnvironmentApprovalEvidence.workflowRef,
    authorizationArtifactId: artifact.id,
    authorizationArtifactName: artifact.name,
    authorizationArtifactDigest: artifact.digest,
    savedPlanSha256: authorization.savedPlanSha256,
    renderedPlanSha256: authorization.renderedPlanSha256,
    stageAStateLineage: authorization.stageAStateLineage,
    stageAStateSerial: authorization.stageAStateSerial,
    stageAStateSha256: authorization.stageAStateSha256,
    approvalKeyArn: authorization.approvalKeyArn,
    beforePolicySha256: authorization.beforePolicySha256,
    afterPolicySha256: authorization.afterPolicySha256,
    action: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.action,
    resource: authorization.approvalKeyArn,
    previousDefaultVersionId,
    temporaryVersionId,
    maxTerraformApplies: STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.maxTerraformApplies,
  };
  return Object.freeze({ ...body, capabilitySha256: policyHash(body) });
}

export function assertApprovalKeyReconciliationCapabilityEvidence(evidence, { authorization, workflow, artifact } = {}) {
  const { capabilitySha256, ...body } = evidence || {};
  if (!SHA256.test(capabilitySha256 || "") || policyHash(body) !== capabilitySha256) throw new Error("Stage-A approval-key capability evidence hash is invalid.");
  const expected = buildApprovalKeyReconciliationCapabilityEvidence({ authorization, workflow, artifact, previousDefaultVersionId: body.previousDefaultVersionId, temporaryVersionId: body.temporaryVersionId });
  if (!same(evidence, expected)) throw new Error("Stage-A approval-key capability evidence is not bound to the authorized reconciliation.");
  return evidence;
}

function assertTopology(topology, steadyPolicy) {
  assertPolicyVersionTopology(topology);
  const active = topology.versions.find(({ VersionId }) => VersionId === topology.defaultVersionId);
  if (!active || !same(active.document, steadyPolicy)) throw new Error("Stage-A approval-key managed-policy steady state differs from protected source.");
  assertApprovalKeyReconciliationSteadyPolicy(active.document);
  return active;
}

function assertPolicyVersionTopology(topology) {
  if (!topology || !Array.isArray(topology.versions) || topology.versions.length < 1 || topology.versions.length > 5 || !VERSION.test(topology.defaultVersionId || "")) throw new Error("Stage-A approval-key managed-policy topology is invalid.");
  if (topology.versions.some((version) => !VERSION.test(version?.VersionId || "") || !version.document) || new Set(topology.versions.map(({ VersionId }) => VersionId)).size !== topology.versions.length) throw new Error("Stage-A approval-key managed-policy versions are invalid.");
  if (!topology.versions.some(({ VersionId }) => VersionId === topology.defaultVersionId)) throw new Error("Stage-A approval-key managed-policy default version is missing.");
  return topology;
}

const criticalCapabilityCleanupFailure = (message, cause) => {
  const error = new Error(`CRITICAL_TEMPORARY_CAPABILITY_CLEANUP_FAILURE: ${message}`);
  error.code = "CRITICAL_TEMPORARY_CAPABILITY_CLEANUP_FAILURE";
  error.capabilityState = "UNKNOWN";
  error.capabilityMutationAttempted = true;
  if (cause) error.cause = cause;
  return error;
};

function readTopologyWithRecovery(readTopology) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try { return assertPolicyVersionTopology(readTopology()); } catch (error) { lastError = error; }
  }
  throw criticalCapabilityCleanupFailure("authoritative managed-policy topology could not be recovered after a mutation attempt", lastError);
}

function exactTemporaryVersions(topology, temporaryPolicy) {
  return topology.versions.filter(({ document }) => same(document, temporaryPolicy));
}

function restoreDefaultAndAuthenticate({ readTopology, setDefaultVersion, originalDefaultVersionId, temporaryPolicy, steadyPolicy } = {}) {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try { setDefaultVersion(originalDefaultVersionId); } catch (error) { lastError = error; }
    const topology = readTopologyWithRecovery(readTopology);
    if (topology.defaultVersionId === originalDefaultVersionId) {
      try { assertTopology(topology, steadyPolicy); return topology; } catch (error) { throw criticalCapabilityCleanupFailure("previous managed-policy default was not restored to the authenticated steady policy", error); }
    }
    const active = topology.versions.find(({ VersionId }) => VersionId === topology.defaultVersionId);
    if (!active || !exactTemporaryVersions(topology, temporaryPolicy).some(({ VersionId }) => VersionId === topology.defaultVersionId)) throw criticalCapabilityCleanupFailure("managed-policy default changed to an unexpected policy while restoring the original version", lastError);
  }
  throw criticalCapabilityCleanupFailure("previous managed-policy default could not be restored", lastError);
}

function deleteVersionAndAuthenticate({ readTopology, deletePolicyVersion, versionId } = {}) {
  let lastError;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try { deletePolicyVersion(versionId); } catch (error) { lastError = error; }
    const topology = readTopologyWithRecovery(readTopology);
    if (!topology.versions.some(({ VersionId }) => VersionId === versionId)) return topology;
    if (topology.defaultVersionId === versionId) throw criticalCapabilityCleanupFailure(`temporary policy version ${versionId} became default during cleanup`, lastError);
  }
  throw criticalCapabilityCleanupFailure(`temporary policy version ${versionId} could not be deleted`, lastError);
}

function cleanupTemporaryCapability({ readTopology, setDefaultVersion, deletePolicyVersion, verifyCapabilityAbsent, originalDefaultVersionId, temporaryPolicy, steadyPolicy } = {}) {
  let topology = readTopologyWithRecovery(readTopology);
  let temporaryVersions = exactTemporaryVersions(topology, temporaryPolicy);
  if (temporaryVersions.some(({ VersionId }) => VersionId === topology.defaultVersionId)) topology = restoreDefaultAndAuthenticate({ readTopology, setDefaultVersion, originalDefaultVersionId, temporaryPolicy, steadyPolicy });
  else if (topology.defaultVersionId !== originalDefaultVersionId) throw criticalCapabilityCleanupFailure("managed-policy default is neither the original nor the exact temporary capability");
  assertTopology(topology, steadyPolicy);
  temporaryVersions = exactTemporaryVersions(topology, temporaryPolicy);
  for (const { VersionId } of temporaryVersions) topology = deleteVersionAndAuthenticate({ readTopology, deletePolicyVersion, versionId: VersionId });
  if (exactTemporaryVersions(topology, temporaryPolicy).length !== 0) throw criticalCapabilityCleanupFailure("temporary capability policy versions remain after cleanup");
  try { assertTopology(topology, steadyPolicy); } catch (error) { throw criticalCapabilityCleanupFailure("steady managed-policy topology was not authenticated after cleanup", error); }
  try {
    if (verifyCapabilityAbsent() !== true) throw new Error("temporary approval-key capability remains effective after cleanup");
  } catch (error) { throw criticalCapabilityCleanupFailure("temporary approval-key capability absence was not authenticated", error); }
  return topology;
}

function selectSafeCapacityVersion(topology, steadyPolicy) {
  const currentHash = policyHash(steadyPolicy);
  const candidates = topology.versions.filter(({ VersionId, document, CreateDate }) => VersionId !== topology.defaultVersionId && (policyHash(document) === currentHash || historicalSteadyPolicyHashes.has(policyHash(document))) && Number.isFinite(Date.parse(CreateDate)));
  if (!candidates.length) throw new Error("Stage-A approval-key managed-policy version capacity cannot be safely reconciled.");
  return candidates.sort((left, right) => String(left.CreateDate).localeCompare(String(right.CreateDate)) || left.VersionId.localeCompare(right.VersionId))[0];
}

export function createApprovalKeyReconciliationCapabilityRunner({ authorization, sourceSha, workflow, artifact, steadyPolicy, readTopology, createTemporaryVersion, setDefaultVersion, deletePolicyVersion, verifyEffectiveCapability, verifyCapabilityAbsent, executeAuthorization } = {}) {
  assertStageAApprovalKeyReconciliationAuthorization(authorization, { sourceSha });
  if (typeof readTopology !== "function" || typeof createTemporaryVersion !== "function" || typeof setDefaultVersion !== "function" || typeof deletePolicyVersion !== "function" || typeof verifyEffectiveCapability !== "function" || typeof verifyCapabilityAbsent !== "function" || typeof executeAuthorization !== "function") throw new Error("Stage-A approval-key capability runner dependencies are incomplete.");
  assertApprovalKeyReconciliationSteadyPolicy(steadyPolicy);
  let executed = false;
  return {
    execute() {
      if (executed) throw new Error("Stage-A approval-key capability authorization has already been attempted.");
      executed = true;
      const before = readTopology();
      assertTopology(before, steadyPolicy);
      const previousDefaultVersionId = before.defaultVersionId;
      const temporaryPolicy = buildTemporaryApprovalKeyCapabilityPolicy(steadyPolicy, authorization);
      let temporaryCapabilityMutationAttempted = false;
      let capabilityState = "ABSENT";
      let temporaryVersionId;
      let capacityDeletedVersionId;
      let operationError;
      let result;
      try {
        if (before.versions.length === 5) {
          capacityDeletedVersionId = selectSafeCapacityVersion(before, steadyPolicy).VersionId;
          deletePolicyVersion(capacityDeletedVersionId);
          const reduced = readTopology();
          if (reduced.defaultVersionId !== previousDefaultVersionId || reduced.versions.length !== 4 || reduced.versions.some(({ VersionId }) => VersionId === capacityDeletedVersionId)) throw new Error("Stage-A approval-key managed-policy capacity cleanup is not exact.");
          assertTopology(reduced, steadyPolicy);
        }
        temporaryCapabilityMutationAttempted = true;
        capabilityState = "UNKNOWN";
        try {
          createTemporaryVersion(temporaryPolicy);
        } catch (error) {
          const recovered = readTopologyWithRecovery(readTopology);
          const recoveredTemporaryVersions = exactTemporaryVersions(recovered, temporaryPolicy);
          if (recoveredTemporaryVersions.length === 0) capabilityState = "ABSENT";
          operationError = error;
        }
        if (!operationError) {
          const activeTopology = readTopologyWithRecovery(readTopology);
          const temporaryVersions = exactTemporaryVersions(activeTopology, temporaryPolicy);
          if (temporaryVersions.length !== 1) throw new Error("Temporary Stage-A approval-key policy version identity is not unique.");
          temporaryVersionId = temporaryVersions[0].VersionId;
          if (activeTopology.defaultVersionId !== temporaryVersionId) throw new Error("Temporary Stage-A approval-key capability did not become the default policy version.");
          assertTemporaryApprovalKeyCapabilityPolicy(temporaryVersions[0].document, { steadyPolicy, authorization });
          capabilityState = "EFFECTIVE";
          const evidence = buildApprovalKeyReconciliationCapabilityEvidence({ authorization, workflow, artifact, previousDefaultVersionId, temporaryVersionId });
          assertApprovalKeyReconciliationCapabilityEvidence(evidence, { authorization, workflow, artifact });
          if (verifyEffectiveCapability(evidence) !== true) throw new Error("Temporary Stage-A approval-key capability is not effective for release-deployer.");
          if (capabilityState !== "EFFECTIVE") throw new Error(`Stage-A approval-key capability state is ${capabilityState}.`);
          result = executeAuthorization(evidence);
        }
      } catch (error) {
        operationError ||= error;
      } finally {
        if (temporaryCapabilityMutationAttempted) {
          capabilityState = "UNKNOWN";
          cleanupTemporaryCapability({ readTopology, setDefaultVersion, deletePolicyVersion, verifyCapabilityAbsent, originalDefaultVersionId: previousDefaultVersionId, temporaryPolicy, steadyPolicy });
          capabilityState = "ABSENT";
        }
      }
      if (operationError) throw operationError;
      return Object.freeze({ ...result, temporaryCapabilityRemoved: true, temporaryVersionId, previousDefaultVersionId, capacityDeletedVersionId });
    },
  };
}

function runJson(run, args) { return JSON.parse(run(args)); }
function parsePolicy(value) { return normalizeIamPolicyDocument(value, "Live Stage-A approval-key policy"); }
function decodePolicy(value) { return parsePolicy(typeof value === "string" ? decodeURIComponent(value) : value); }

function managedPolicyTopology(run) {
  const policy = runJson(run, ["iam", "get-policy", "--policy-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn]).Policy;
  const versions = runJson(run, ["iam", "list-policy-versions", "--policy-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn]).Versions;
  if (!policy || !Array.isArray(versions)) throw new Error("Stage-A approval-key managed-policy topology response is malformed.");
  return {
    defaultVersionId: policy.DefaultVersionId,
    versions: versions.map((version) => ({ ...version, document: normalizeIamPolicyDocument(runJson(run, ["iam", "get-policy-version", "--policy-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn, "--version-id", version.VersionId]).PolicyVersion?.Document, "Stage-A release policy version") })),
  };
}

function writeTemporaryPolicyVersion(run, policy) {
  const directory = fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "mscqr-stage-a-approval-capability-"));
  const file = path.join(directory, "policy.json");
  try {
    fs.writeFileSync(file, JSON.stringify(policy), { mode: 0o600, flag: "wx" });
    return runJson(run, ["iam", "create-policy-version", "--policy-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn, "--policy-document", `file://${file}`, "--set-as-default"]).PolicyVersion;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function assertSimulation(run, authorization, expected) {
  const result = runJson(run, ["iam", "simulate-principal-policy", "--policy-source-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.releaseRoleArn, "--action-names", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.action, "--resource-arns", authorization.approvalKeyArn, "--context-entries", "ContextKeyName=aws:RequestedRegion,ContextKeyType=string,ContextKeyValues=eu-west-2"]);
  if (result.EvaluationResults?.length !== 1 || result.EvaluationResults[0]?.EvalDecision !== expected) throw new Error(`Stage-A approval-key release-deployer simulation is not ${expected}.`);
  return true;
}

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--execute")) throw new Error("Stage-A approval-key reconciliation is mutation-capable and requires --execute.");
  const sourceSha = required(argv, "--source-sha");
  if (!SHA40.test(sourceSha)) throw new Error("--source-sha must be an exact protected-main SHA.");
  const adminProfile = required(argv, "--admin-profile");
  const releaseProfile = required(argv, "--release-profile");
  if (adminProfile === releaseProfile) throw new Error("Stage-A approval-key administrator and release profiles must be distinct.");
  const execute = deps.execFileSync || execFileSync;
  const textRun = deps.run || ((command, args, options = {}) => execute(command, args, { cwd: root, encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }));
  const resolved = (deps.resolveAuthorizationArtifact || resolveStageAReconciliationAuthorizationArtifact)({ workflowRunId: required(argv, "--workflow-run-id"), workflowRunAttempt: required(argv, "--workflow-run-attempt"), sourceSha, run: textRun });
  const authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(resolved.authorizationBytes));
  if (authorization?.protectedEnvironmentApprovalEvidence?.workflowRunId !== String(resolved.workflow.id) || authorization?.protectedEnvironmentApprovalEvidence?.workflowRunAttempt !== String(resolved.workflow.run_attempt) || authorization?.protectedEnvironmentApprovalEvidence?.executionActor?.toLowerCase() !== String(resolved.workflow.actor?.login || "").toLowerCase()) throw new Error("Stage-A approval-key authorization is not bound to the resolved protected-environment run.");
  assertStageAApprovalKeyReconciliationAuthorization(authorization, { sourceSha });
  const checkout = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root });
  if (checkout.toolingSha !== sourceSha) throw new Error("Stage-A approval-key executor is not at the authorized protected source.");
  const adminRun = deps.adminRun || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: adminProfile, exec: execute });
  const releaseEnvironment = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: releaseProfile });
  const releaseRun = deps.releaseRun || ((command, args) => execute(command, args, { cwd: root, env: releaseEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const releaseAws = deps.releaseAws || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: releaseProfile, exec: execute });
  const administratorIdentity = runJson(adminRun, ["sts", "get-caller-identity"]);
  const releaseIdentity = runJson(releaseAws, ["sts", "get-caller-identity"]);
  if (administratorIdentity.Arn !== "arn:aws:iam::368992683803:root" || !String(releaseIdentity.Arn || "").startsWith(`arn:aws:sts::368992683803:assumed-role/${STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.releaseRoleName}/`)) throw new Error("Stage-A approval-key credential identities are not the governed root and release-deployer boundaries.");
  const role = runJson(adminRun, ["iam", "get-role", "--role-name", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.releaseRoleName]).Role;
  const attached = runJson(adminRun, ["iam", "list-attached-role-policies", "--role-name", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.releaseRoleName]).AttachedPolicies;
  if (role?.Arn !== STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.releaseRoleArn || role.PermissionsBoundary || !Array.isArray(attached) || !attached.some(({ PolicyArn }) => PolicyArn === STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn)) throw new Error("Stage-A approval-key release-deployer attachment boundary is invalid.");
  assertSimulation(adminRun, authorization, "implicitDeny");
  const savedPlanBytes = fs.readFileSync(path.resolve(required(argv, "--saved-plan")));
  const privateDirectory = path.join(process.env.HOME || "", ".mscqr", "production-stage-a", "approval-key-reconciliation");
  ensureStageBPrivateDirectory({ directory: privateDirectory, repositoryRoot: root, create: true, label: "Stage-A approval-key reconciliation directory" });
  const executorSavedPlanPath = path.join(privateDirectory, `${authorization.authorizationSha256}.tfplan`);
  const executorPlan = materializeStageAReconciliationPlan({ savedPlanBytes, expectedSha256: authorization.savedPlanSha256, applyPlanPath: executorSavedPlanPath, repositoryRoot: root });
  const renderedPlanBytes = Buffer.from(releaseRun("terraform", [`-chdir=${STAGE_A_RECONCILIATION_AUTHORIZATION.terraformRoot}`, "show", "-json", executorPlan.path]));
  if (crypto.createHash("sha256").update(renderedPlanBytes).digest("hex") !== authorization.renderedPlanSha256) throw new Error("Stage-A approval-key rendered plan changed after authorization.");
  assertStageAApprovalKeyReconciliationPlan(JSON.parse(renderedPlanBytes), authorization);
  const readState = () => releaseRun("terraform", [`-chdir=${STAGE_A_RECONCILIATION_AUTHORIZATION.terraformRoot}`, "state", "pull"]);
  const readPolicy = () => decodePolicy(runJson(releaseAws, ["kms", "get-key-policy", "--key-id", authorization.approvalKeyArn, "--policy-name", "default", "--output", "json", "--no-cli-pager"]).Policy);
  const stateBytes = Buffer.from(readState()); const state = buildStageAStateIdentity(parseAuthenticatedStateBytes(stateBytes), { stateBytes });
  if (state.lineage !== authorization.stageAStateLineage || state.serial !== authorization.stageAStateSerial || state.stateSha256 !== authorization.stageAStateSha256 || policyHash(readPolicy()) !== authorization.beforePolicySha256) throw new Error("Stage-A approval-key pre-capability CAS changed.");
  const steadyPolicy = JSON.parse(fs.readFileSync(sourcePolicyPath, "utf8"));
  const runner = createApprovalKeyReconciliationCapabilityRunner({ authorization, sourceSha, workflow: resolved.workflow, artifact: resolved.artifact, steadyPolicy,
    readTopology: () => managedPolicyTopology(adminRun),
    createTemporaryVersion: (policy) => writeTemporaryPolicyVersion(adminRun, policy),
    setDefaultVersion: (versionId) => adminRun(["iam", "set-default-policy-version", "--policy-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn, "--version-id", versionId]),
    deletePolicyVersion: (versionId) => adminRun(["iam", "delete-policy-version", "--policy-arn", STAGE_A_APPROVAL_KEY_RECONCILIATION_CAPABILITY.policyArn, "--version-id", versionId]),
    verifyEffectiveCapability: () => assertSimulation(adminRun, authorization, "allowed"),
    verifyCapabilityAbsent: () => assertSimulation(adminRun, authorization, "implicitDeny"),
    executeAuthorization: () => {
      const postCapabilityCheckout = (deps.readProtectedCheckout || readStageBProtectedMainCheckout)({ cwd: root });
      if (postCapabilityCheckout.toolingSha !== sourceSha) throw new Error("Stage-A approval-key protected source changed after temporary capability creation.");
      return executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath, repositoryRoot: root, readState, readPolicy,
      recordConsumption: () => writeStageBPrivateFileExclusive({ filePath: path.join(privateDirectory, `${authorization.authorizationSha256}.json`), bytes: Buffer.from(`${JSON.stringify({ authorizationSha256: authorization.authorizationSha256, attemptedAt: new Date().toISOString() })}\n`), repositoryRoot: root, label: "Stage-A approval-key reconciliation consumption record" }),
      applySavedPlan: ({ path: applyPath, sha256 }) => { if (applyPath !== executorSavedPlanPath || sha256 !== authorization.savedPlanSha256) throw new Error("Stage-A approval-key apply artifact binding is invalid."); return releaseRun("terraform", [`-chdir=${STAGE_A_RECONCILIATION_AUTHORIZATION.terraformRoot}`, "apply", "-input=false", applyPath]); },
      });
    },
  });
  return runner.execute();
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`));
