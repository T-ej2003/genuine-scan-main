#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { sourcePolicyEvidence } from "./validate-production-green-stage-b-permissions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;

export const INITIAL_ACTIVATION_POLICY_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION",
  policyName: "MSCQRProductionInitialActivationLifecycle",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  sourcePath: "documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json",
  predecessorVersionId: "v1",
  predecessorPolicySha256: "2a90146c8fc8f6062198650134c0e92724cc4dd69720bde629fd0752e4432c71",
  desiredPolicySha256: "7e9eef0b5dd5c089f4734a43cbc40ed963078dc500828c2e592cc07f04c6d564",
  maxCreatePolicyVersionCount: 1,
  maxPolicyVersionsBeforeCreate: 4,
  workflowPath: ".github/workflows/authorize-production-initial-activation-lifecycle-policy-reconciliation.yml",
});

const exact = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const sha = (value) => canonicalSha256(value);
const requireSha40 = (value, label) => { if (!SHA40.test(value || "")) throw new Error(`${label} is invalid.`); return value; };
export function readInitialActivationLifecycleDesiredPolicy({ repositoryRoot = root } = {}) {
  const source = path.resolve(repositoryRoot, INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath);
  const document = normalizeIamPolicyDocument(fs.readFileSync(source, "utf8"), "Initial activation lifecycle source policy");
  const policySha256 = sha(document);
  if (policySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256) throw new Error("Initial activation lifecycle source policy is not the reviewed desired document.");
  return Object.freeze({ sourcePath: INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath, document, policySha256 });
}

const expectedReleaseRolePolicyArns = () => sourcePolicyEvidence().map(({ arn }) => arn).sort();
const stateFields = ["policyArn", "defaultVersionId", "document", "policyVersionCount", "releaseRolePolicyArns", "targetPolicyRoles", "targetPolicyUsers", "targetPolicyGroups", "permissionsBoundaryUsageCount"];
export function assertInitialActivationLifecyclePolicyState(value, { desired = readInitialActivationLifecycleDesiredPolicy() } = {}) {
  exact(value, stateFields, "Initial activation lifecycle live policy state");
  if (value.policyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !VERSION.test(value.defaultVersionId || "") || !Number.isSafeInteger(value.policyVersionCount) || value.policyVersionCount < 1 || value.policyVersionCount > 5 || !Number.isSafeInteger(value.permissionsBoundaryUsageCount) || value.permissionsBoundaryUsageCount !== 0 || ![value.releaseRolePolicyArns, value.targetPolicyRoles, value.targetPolicyUsers, value.targetPolicyGroups].every(Array.isArray)) throw new Error("Initial activation lifecycle live policy identity is invalid.");
  const releaseRolePolicyArns = [...value.releaseRolePolicyArns].sort();
  const targetPolicyRoles = [...value.targetPolicyRoles].sort();
  const targetPolicyUsers = [...value.targetPolicyUsers].sort();
  const targetPolicyGroups = [...value.targetPolicyGroups].sort();
  if (JSON.stringify(releaseRolePolicyArns) !== JSON.stringify(expectedReleaseRolePolicyArns())) throw new Error("Initial activation lifecycle release-role policy attachment set changed.");
  if (JSON.stringify(targetPolicyRoles) !== JSON.stringify(["mscqr-production-release-deployer"]) || targetPolicyUsers.length !== 0 || targetPolicyGroups.length !== 0) throw new Error("Initial activation lifecycle target-policy entity boundary changed.");
  const document = normalizeIamPolicyDocument(value.document, "Initial activation lifecycle live policy");
  const policySha256 = sha(document);
  const releaseRolePolicySetSha256 = sha({ releaseRolePolicyArns });
  const targetPolicyEntityBoundarySha256 = sha({ targetPolicyRoles, targetPolicyUsers, targetPolicyGroups, permissionsBoundaryUsageCount: 0 });
  const predecessor = value.defaultVersionId === INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId && policySha256 === INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256;
  const alreadyDesired = policySha256 === desired.policySha256 && value.defaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId;
  if (!predecessor && !alreadyDesired) throw new Error("Initial activation lifecycle live policy is neither the authenticated predecessor nor the exact desired policy.");
  return Object.freeze({ ...value, document, releaseRolePolicyArns, targetPolicyRoles, targetPolicyUsers, targetPolicyGroups, policySha256, releaseRolePolicySetSha256, targetPolicyEntityBoundarySha256, status: alreadyDesired ? "ALREADY_RECONCILED" : "AUTHENTICATED_PREDECESSOR" });
}

const authorizationFields = ["schemaVersion", "kind", "environment", "operation", "sourceSha", "targetPolicyArn", "predecessorDefaultVersionId", "predecessorPolicySha256", "desiredPolicySha256", "desiredPolicySourcePath", "policyVersionCount", "releaseRolePolicySetSha256", "targetPolicyEntityBoundarySha256", "expectedAction", "setAsDefault", "maxCreatePolicyVersionCount", "maxSetDefaultPolicyVersionCount", "maxDeletePolicyVersionCount", "maxPolicyAttachmentMutations", "executionPrincipal", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
export function createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState, protectedEnvironmentApprovalEvidence, desired = readInitialActivationLifecycleDesiredPolicy(), now = new Date() } = {}) {
  requireSha40(sourceSha, "sourceSha");
  if (desired?.sourcePath !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath || desired?.policySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || sha(desired?.document) !== desired.policySha256) throw new Error("Initial activation lifecycle desired policy must be the exact tracked protected-source document.");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository });
  if (protectedEnvironmentApprovalEvidence.schemaVersion !== 3) throw new Error("Initial activation lifecycle policy authorization requires authenticated GitHub approval evidence.");
  assertProductionEnvironmentApprovalFreshness(protectedEnvironmentApprovalEvidence, { now });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== `${repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main`) throw new Error("Initial activation lifecycle policy authorization requires its exact protected workflow.");
  const state = assertInitialActivationLifecyclePolicyState(liveState, { desired });
  if (state.status !== "AUTHENTICATED_PREDECESSOR") throw new Error("Initial activation lifecycle policy authorization requires the exact authenticated predecessor.");
  if (state.policyVersionCount > INITIAL_ACTIVATION_POLICY_RECONCILIATION.maxPolicyVersionsBeforeCreate) throw new Error("Initial activation lifecycle policy version capacity requires pruning and is not authorized.");
  const body = {
    schemaVersion: INITIAL_ACTIVATION_POLICY_RECONCILIATION.schemaVersion, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_AUTHORIZATION", environment: "production", operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, sourceSha,
    targetPolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, predecessorDefaultVersionId: state.defaultVersionId, predecessorPolicySha256: state.policySha256, desiredPolicySha256: desired.policySha256, desiredPolicySourcePath: desired.sourcePath, policyVersionCount: state.policyVersionCount, releaseRolePolicySetSha256: state.releaseRolePolicySetSha256, targetPolicyEntityBoundarySha256: state.targetPolicyEntityBoundarySha256,
    expectedAction: "iam:CreatePolicyVersion", setAsDefault: true, maxCreatePolicyVersionCount: 1, maxSetDefaultPolicyVersionCount: 0, maxDeletePolicyVersionCount: 0, maxPolicyAttachmentMutations: 0, executionPrincipal: "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler",
    protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256,
  };
  return Object.freeze({ ...body, authorizationSha256: sha(body) });
}

export function assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now = new Date() } = {}) {
  exact(value, authorizationFields, "Initial activation lifecycle policy authorization");
  const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_AUTHORIZATION" || value.environment !== "production" || value.operation !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA256.test(authorizationSha256 || "") || sha(body) !== authorizationSha256) throw new Error("Initial activation lifecycle policy authorization identity is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository });
  if (value.protectedEnvironmentApprovalEvidence.schemaVersion !== 3) throw new Error("Initial activation lifecycle policy authorization requires authenticated GitHub approval evidence.");
  assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== `${repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main` || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || value.predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || value.predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || value.desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || value.desiredPolicySourcePath !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath || !Number.isSafeInteger(value.policyVersionCount) || value.policyVersionCount < 1 || value.policyVersionCount > 4 || !SHA256.test(value.releaseRolePolicySetSha256 || "") || !SHA256.test(value.targetPolicyEntityBoundarySha256 || "") || value.expectedAction !== "iam:CreatePolicyVersion" || value.setAsDefault !== true || value.maxCreatePolicyVersionCount !== 1 || value.maxSetDefaultPolicyVersionCount !== 0 || value.maxDeletePolicyVersionCount !== 0 || value.maxPolicyAttachmentMutations !== 0 || value.executionPrincipal !== "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler") throw new Error("Initial activation lifecycle policy authorization bindings are invalid.");
  return value;
}

const CONVERGENCE_ATTEMPTS = 6;
const CONVERGENCE_DELAYS = Object.freeze([100, 200, 400, 800, 1000]);
export const INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ = "INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ";
const defaultSleep = (milliseconds) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds); };

const isTransientPolicyVersionRead = (error) => error?.code === INITIAL_ACTIVATION_TRANSIENT_POLICY_VERSION_READ;

const isTransientConvergenceRead = (error) => {
  if (isTransientPolicyVersionRead(error)) return true;
  const retryable = /^(Throttling|ThrottlingException|TooManyRequestsException|RequestLimitExceeded|ServiceUnavailable|ServiceUnavailableException|InternalFailure|InternalError)$/;
  // AWS CLI wraps the service code in a diagnostic; never match arbitrary message substrings.
  const diagnostic = String(error?.stderr || error?.message || "").match(/(?:^|\n)An error occurred \((\w+)\) when calling the (GetPolicy|GetPolicyVersion|ListPolicyVersions|GetRole|ListAttachedRolePolicies|ListEntitiesForPolicy) operation(?: \(reached max retries: \d+\))?:/);
  return retryable.test(error?.code || error?.name || "") || Boolean(diagnostic && retryable.test(diagnostic[1]));
};

const hasExpectedConvergenceTopology = (value, authorization) => {
  if (!value || typeof value !== "object" || value.policyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !Array.isArray(value.releaseRolePolicyArns) || !Array.isArray(value.targetPolicyRoles) || !Array.isArray(value.targetPolicyUsers) || !Array.isArray(value.targetPolicyGroups) || value.permissionsBoundaryUsageCount !== 0) return false;
  const releaseRolePolicyArns = [...value.releaseRolePolicyArns].sort();
  const targetPolicyRoles = [...value.targetPolicyRoles].sort();
  const targetPolicyUsers = [...value.targetPolicyUsers].sort();
  const targetPolicyGroups = [...value.targetPolicyGroups].sort();
  return sha({ releaseRolePolicyArns }) === authorization.releaseRolePolicySetSha256 && sha({ targetPolicyRoles, targetPolicyUsers, targetPolicyGroups, permissionsBoundaryUsageCount: 0 }) === authorization.targetPolicyEntityBoundarySha256;
};

const isTransientConvergenceSnapshot = (value, before, authorization, desired, expectedVersionId) => {
  if (!hasExpectedConvergenceTopology(value, authorization) || !VERSION.test(value.defaultVersionId || "") || !Number.isSafeInteger(value.policyVersionCount)) return false;
  let policySha256;
  try { policySha256 = sha(normalizeIamPolicyDocument(value.document, "Initial activation lifecycle convergence snapshot")); } catch { return false; }
  const predecessorDocument = policySha256 === before.policySha256;
  const desiredDocument = policySha256 === desired.policySha256;
  const predecessorDefault = value.defaultVersionId === before.defaultVersionId;
  const desiredDefault = value.defaultVersionId !== before.defaultVersionId && (!expectedVersionId || value.defaultVersionId === expectedVersionId);
  const plausibleNewDefault = desiredDefault || (!expectedVersionId && value.defaultVersionId !== before.defaultVersionId);
  const oldCount = value.policyVersionCount === before.policyVersionCount;
  const newCount = value.policyVersionCount === before.policyVersionCount + 1;
  return (predecessorDefault && desiredDocument && (oldCount || newCount)) || (plausibleNewDefault && predecessorDocument && (oldCount || newCount)) || (desiredDocument && desiredDefault && oldCount) || (predecessorDocument && predecessorDefault && newCount);
};

export function waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before, authorization, desired, expectedVersionId, sleep = defaultSleep } = {}) {
  if (typeof readLiveState !== "function" || !before || !authorization || !desired) throw new Error("Initial activation lifecycle convergence inputs are required.");
  for (let attempt = 0; attempt < CONVERGENCE_ATTEMPTS; attempt += 1) {
    let raw; let candidate;
    try {
      raw = readLiveState();
      candidate = assertInitialActivationLifecyclePolicyState(raw, { desired });
    } catch (error) {
      if (!(raw === undefined && isTransientConvergenceRead(error)) && !isTransientConvergenceSnapshot(raw, before, authorization, desired, expectedVersionId)) throw error;
      if (attempt < CONVERGENCE_ATTEMPTS - 1) sleep(CONVERGENCE_DELAYS[attempt]);
      continue;
    }
    if (candidate.releaseRolePolicySetSha256 !== authorization.releaseRolePolicySetSha256 || candidate.targetPolicyEntityBoundarySha256 !== authorization.targetPolicyEntityBoundarySha256) throw new Error("Initial activation lifecycle policy topology changed during convergence.");
    if (isTransientConvergenceSnapshot(candidate, before, authorization, desired, expectedVersionId)) {
      if (attempt < CONVERGENCE_ATTEMPTS - 1) sleep(CONVERGENCE_DELAYS[attempt]);
      continue;
    }
    if (candidate.status === "AUTHENTICATED_PREDECESSOR") {
      if (candidate.defaultVersionId !== before.defaultVersionId || candidate.policySha256 !== before.policySha256 || candidate.policyVersionCount !== before.policyVersionCount) throw new Error("Initial activation lifecycle policy entered an unexpected predecessor state during convergence.");
    } else {
      if (candidate.defaultVersionId === before.defaultVersionId || candidate.policyVersionCount !== before.policyVersionCount + 1 || (expectedVersionId && candidate.defaultVersionId !== expectedVersionId)) throw new Error("Initial activation lifecycle policy converged to an unexpected default version.");
      return candidate;
    }
    if (attempt < CONVERGENCE_ATTEMPTS - 1) sleep(CONVERGENCE_DELAYS[attempt]);
  }
  throw new Error(`Initial activation lifecycle policy did not converge within ${CONVERGENCE_ATTEMPTS} observations.`);
}

export function executeInitialActivationLifecyclePolicyReconciliation({ authorization, sourceSha, readLiveState, createPolicyVersion, desired = readInitialActivationLifecycleDesiredPolicy(), now = () => new Date(), sleep = defaultSleep } = {}) {
  const readClock = typeof now === "function" ? now : () => now;
  assertInitialActivationLifecyclePolicyReconciliationAuthorization(authorization, { sourceSha, now: readClock() });
  if (typeof readLiveState !== "function" || typeof createPolicyVersion !== "function") throw new Error("Initial activation lifecycle policy reconciliation requires authenticated readers and writer.");
  const before = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
  if (before.releaseRolePolicySetSha256 !== authorization.releaseRolePolicySetSha256 || before.targetPolicyEntityBoundarySha256 !== authorization.targetPolicyEntityBoundarySha256) throw new Error("Initial activation lifecycle policy attachment state changed since authorization.");
  if (before.status === "ALREADY_RECONCILED") return Object.freeze({ status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: before });
  if (before.defaultVersionId !== authorization.predecessorDefaultVersionId || before.policySha256 !== authorization.predecessorPolicySha256 || before.policyVersionCount !== authorization.policyVersionCount || before.policyVersionCount > 4) throw new Error("Initial activation lifecycle policy predecessor CAS changed since authorization.");
  const latest = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
  if (latest.releaseRolePolicySetSha256 !== authorization.releaseRolePolicySetSha256 || latest.targetPolicyEntityBoundarySha256 !== authorization.targetPolicyEntityBoundarySha256) throw new Error("Initial activation lifecycle policy topology changed before mutation.");
  if (latest.status === "ALREADY_RECONCILED") return Object.freeze({ status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: latest });
  if (latest.defaultVersionId !== authorization.predecessorDefaultVersionId || latest.policySha256 !== authorization.predecessorPolicySha256 || latest.policyVersionCount !== authorization.policyVersionCount) throw new Error("Initial activation lifecycle policy predecessor CAS changed before mutation.");
  assertProductionEnvironmentApprovalFreshness(authorization.protectedEnvironmentApprovalEvidence, { now: readClock() });
  let response;
  try { response = createPolicyVersion({ PolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, PolicyDocument: desired.document, SetAsDefault: true }); }
  catch (error) { const recovered = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before: latest, authorization, desired, sleep }); return Object.freeze({ status: "COMPLETED_BY_READBACK", createPolicyVersionCount: 1, postState: recovered, cause: error }); }
  if (!VERSION.test(response?.PolicyVersion?.VersionId || "") || response.PolicyVersion.VersionId === before.defaultVersionId) {
    const recovered = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before: latest, authorization, desired, sleep });
    return Object.freeze({ status: "COMPLETED_BY_READBACK", createPolicyVersionCount: 1, postState: recovered });
  }
  const after = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before: latest, authorization, desired, expectedVersionId: response.PolicyVersion.VersionId, sleep });
  return Object.freeze({ status: "RECONCILED", createPolicyVersionCount: 1, postState: after });
}

export function buildInitialActivationLifecyclePolicyReconciliationResult({ authorization, outcome } = {}) {
  if (!outcome || !["RECONCILED", "COMPLETED_BY_READBACK", "ALREADY_RECONCILED"].includes(outcome.status)) throw new Error("Initial activation lifecycle policy result outcome is invalid.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_RESULT", operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, sourceSha: authorization?.sourceSha, targetPolicyArn: authorization?.targetPolicyArn, authorizationSha256: authorization?.authorizationSha256, predecessorDefaultVersionId: authorization?.predecessorDefaultVersionId, predecessorPolicySha256: authorization?.predecessorPolicySha256, desiredPolicySha256: authorization?.desiredPolicySha256, status: outcome.status, createPolicyVersionCount: outcome.createPolicyVersionCount, postDefaultVersionId: outcome.postState?.defaultVersionId, postPolicySha256: outcome.postState?.policySha256, postReleaseRolePolicySetSha256: outcome.postState?.releaseRolePolicySetSha256, postTargetPolicyEntityBoundarySha256: outcome.postState?.targetPolicyEntityBoundarySha256 };
  if (!SHA40.test(body.sourceSha || "") || body.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !SHA256.test(body.authorizationSha256 || "") || body.predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || body.predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || body.desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || !VERSION.test(body.postDefaultVersionId || "") || body.postPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || !SHA256.test(body.postReleaseRolePolicySetSha256 || "") || !SHA256.test(body.postTargetPolicyEntityBoundarySha256 || "") || ![0, 1].includes(body.createPolicyVersionCount)) throw new Error("Initial activation lifecycle policy result bindings are invalid.");
  return Object.freeze({ ...body, resultSha256: sha(body) });
}
