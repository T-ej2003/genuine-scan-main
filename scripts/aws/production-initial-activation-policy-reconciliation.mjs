#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;
const artifactName = "production-initial-activation-lifecycle-policy-reconciliation-authorization";

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
const requireSha = (value, label) => { if (!SHA256.test(value || "")) throw new Error(`${label} is invalid.`); return value; };

export function readInitialActivationLifecycleDesiredPolicy({ repositoryRoot = root } = {}) {
  const source = path.resolve(repositoryRoot, INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath);
  const document = normalizeIamPolicyDocument(fs.readFileSync(source, "utf8"), "Initial activation lifecycle source policy");
  const policySha256 = sha(document);
  if (policySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256) throw new Error("Initial activation lifecycle source policy is not the reviewed desired document.");
  return Object.freeze({ sourcePath: INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath, document, policySha256 });
}

const stateFields = ["policyArn", "defaultVersionId", "document", "policyVersionCount", "attachedPolicyArns", "permissionsBoundaryArn"];
export function assertInitialActivationLifecyclePolicyState(value, { desired = readInitialActivationLifecycleDesiredPolicy() } = {}) {
  exact(value, stateFields, "Initial activation lifecycle live policy state");
  if (value.policyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !VERSION.test(value.defaultVersionId || "") || !Number.isSafeInteger(value.policyVersionCount) || value.policyVersionCount < 1 || value.policyVersionCount > 5 || !Array.isArray(value.attachedPolicyArns) || value.permissionsBoundaryArn !== null) throw new Error("Initial activation lifecycle live policy identity is invalid.");
  const attached = [...value.attachedPolicyArns].sort();
  if (JSON.stringify(attached) !== JSON.stringify([INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn])) throw new Error("Initial activation lifecycle policy attachment boundary changed.");
  const document = normalizeIamPolicyDocument(value.document, "Initial activation lifecycle live policy");
  const policySha256 = sha(document);
  const attachmentSha256 = sha({ attachedPolicyArns: attached, permissionsBoundaryArn: null });
  const predecessor = value.defaultVersionId === INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId && policySha256 === INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256;
  const alreadyDesired = policySha256 === desired.policySha256;
  if (!predecessor && !alreadyDesired) throw new Error("Initial activation lifecycle live policy is neither the authenticated predecessor nor the exact desired policy.");
  return Object.freeze({ ...value, document, attachedPolicyArns: attached, policySha256, attachmentSha256, status: alreadyDesired ? "ALREADY_RECONCILED" : "AUTHENTICATED_PREDECESSOR" });
}

const authorizationFields = ["schemaVersion", "kind", "environment", "operation", "sourceSha", "targetPolicyArn", "predecessorDefaultVersionId", "predecessorPolicySha256", "desiredPolicySha256", "desiredPolicySourcePath", "policyVersionCount", "attachmentSha256", "expectedAction", "setAsDefault", "maxCreatePolicyVersionCount", "maxSetDefaultPolicyVersionCount", "maxDeletePolicyVersionCount", "maxPolicyAttachmentMutations", "executionPrincipal", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
export function createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState, protectedEnvironmentApprovalEvidence, desired = readInitialActivationLifecycleDesiredPolicy() } = {}) {
  requireSha40(sourceSha, "sourceSha");
  if (desired?.sourcePath !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath || desired?.policySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || sha(desired?.document) !== desired.policySha256) throw new Error("Initial activation lifecycle desired policy must be the exact tracked protected-source document.");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== `${repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main`) throw new Error("Initial activation lifecycle policy authorization requires its exact protected workflow.");
  const state = assertInitialActivationLifecyclePolicyState(liveState, { desired });
  if (state.status !== "AUTHENTICATED_PREDECESSOR") throw new Error("Initial activation lifecycle policy authorization requires the exact authenticated predecessor.");
  if (state.policyVersionCount > INITIAL_ACTIVATION_POLICY_RECONCILIATION.maxPolicyVersionsBeforeCreate) throw new Error("Initial activation lifecycle policy version capacity requires pruning and is not authorized.");
  const body = {
    schemaVersion: INITIAL_ACTIVATION_POLICY_RECONCILIATION.schemaVersion, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_AUTHORIZATION", environment: "production", operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, sourceSha,
    targetPolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, predecessorDefaultVersionId: state.defaultVersionId, predecessorPolicySha256: state.policySha256, desiredPolicySha256: desired.policySha256, desiredPolicySourcePath: desired.sourcePath, policyVersionCount: state.policyVersionCount, attachmentSha256: state.attachmentSha256,
    expectedAction: "iam:CreatePolicyVersion", setAsDefault: true, maxCreatePolicyVersionCount: 1, maxSetDefaultPolicyVersionCount: 0, maxDeletePolicyVersionCount: 0, maxPolicyAttachmentMutations: 0, executionPrincipal: "ROOT_OPERATOR",
    protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256,
  };
  return Object.freeze({ ...body, authorizationSha256: sha(body) });
}

export function assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha } = {}) {
  exact(value, authorizationFields, "Initial activation lifecycle policy authorization");
  const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_AUTHORIZATION" || value.environment !== "production" || value.operation !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA256.test(authorizationSha256 || "") || sha(body) !== authorizationSha256) throw new Error("Initial activation lifecycle policy authorization identity is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== `${repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main` || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || value.predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || value.predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || value.desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || value.desiredPolicySourcePath !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath || !Number.isSafeInteger(value.policyVersionCount) || value.policyVersionCount < 1 || value.policyVersionCount > 4 || !SHA256.test(value.attachmentSha256 || "") || value.expectedAction !== "iam:CreatePolicyVersion" || value.setAsDefault !== true || value.maxCreatePolicyVersionCount !== 1 || value.maxSetDefaultPolicyVersionCount !== 0 || value.maxDeletePolicyVersionCount !== 0 || value.maxPolicyAttachmentMutations !== 0 || value.executionPrincipal !== "ROOT_OPERATOR") throw new Error("Initial activation lifecycle policy authorization bindings are invalid.");
  return value;
}

export function executeInitialActivationLifecyclePolicyReconciliation({ authorization, sourceSha, readLiveState, createPolicyVersion, desired = readInitialActivationLifecycleDesiredPolicy() } = {}) {
  assertInitialActivationLifecyclePolicyReconciliationAuthorization(authorization, { sourceSha });
  if (typeof readLiveState !== "function" || typeof createPolicyVersion !== "function") throw new Error("Initial activation lifecycle policy reconciliation requires authenticated AWS readers and writer.");
  const before = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
  if (before.attachmentSha256 !== authorization.attachmentSha256) throw new Error("Initial activation lifecycle policy attachment state changed since authorization.");
  if (before.status === "ALREADY_RECONCILED") return Object.freeze({ status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: before });
  if (before.defaultVersionId !== authorization.predecessorDefaultVersionId || before.policySha256 !== authorization.predecessorPolicySha256 || before.policyVersionCount !== authorization.policyVersionCount || before.policyVersionCount > 4) throw new Error("Initial activation lifecycle policy predecessor CAS changed since authorization.");
  let response;
  try { response = createPolicyVersion({ PolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, PolicyDocument: desired.document, SetAsDefault: true }); }
  catch (error) {
    const recovered = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
    if (recovered.status === "ALREADY_RECONCILED" && recovered.attachmentSha256 === authorization.attachmentSha256 && recovered.defaultVersionId !== before.defaultVersionId) return Object.freeze({ status: "COMPLETED_BY_READBACK", createPolicyVersionCount: 1, postState: recovered });
    throw error;
  }
  if (!VERSION.test(response?.PolicyVersion?.VersionId || "") || response.PolicyVersion.VersionId === before.defaultVersionId) throw new Error("CreatePolicyVersion did not return a new default-version identity.");
  const after = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
  if (after.status !== "ALREADY_RECONCILED" || after.defaultVersionId !== response.PolicyVersion.VersionId || after.defaultVersionId === before.defaultVersionId || after.attachmentSha256 !== authorization.attachmentSha256) throw new Error("Initial activation lifecycle policy post-write readback is invalid.");
  return Object.freeze({ status: "RECONCILED", createPolicyVersionCount: 1, postState: after });
}

export function buildInitialActivationLifecyclePolicyReconciliationResult({ authorization, outcome } = {}) {
  if (!outcome || !["RECONCILED", "COMPLETED_BY_READBACK", "ALREADY_RECONCILED"].includes(outcome.status)) throw new Error("Initial activation lifecycle policy result outcome is invalid.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_RESULT", operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, sourceSha: authorization?.sourceSha, targetPolicyArn: authorization?.targetPolicyArn, authorizationSha256: authorization?.authorizationSha256, predecessorDefaultVersionId: authorization?.predecessorDefaultVersionId, predecessorPolicySha256: authorization?.predecessorPolicySha256, desiredPolicySha256: authorization?.desiredPolicySha256, status: outcome.status, createPolicyVersionCount: outcome.createPolicyVersionCount, postDefaultVersionId: outcome.postState?.defaultVersionId, postPolicySha256: outcome.postState?.policySha256, postAttachmentSha256: outcome.postState?.attachmentSha256 };
  if (!SHA40.test(body.sourceSha || "") || body.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !SHA256.test(body.authorizationSha256 || "") || body.predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || body.predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || body.desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || !VERSION.test(body.postDefaultVersionId || "") || body.postPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || !SHA256.test(body.postAttachmentSha256 || "") || ![0, 1].includes(body.createPolicyVersionCount)) throw new Error("Initial activation lifecycle policy result bindings are invalid.");
  return Object.freeze({ ...body, resultSha256: sha(body) });
}

export function resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }) } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "")) throw new Error("Initial activation lifecycle policy authorization coordinates are invalid.");
  const workflow = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== repository || workflow.path !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Initial activation lifecycle policy authorization workflow provenance is invalid.");
  const artifacts = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}/artifacts`]));
  const matches = artifacts?.artifacts?.filter((artifact) => artifact.name === artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (!Array.isArray(matches) || matches.length !== 1) throw new Error("Initial activation lifecycle policy authorization artifact is not exact.");
  const artifact = matches[0]; const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-initial-activation-policy-authorization-")); const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = run("gh", ["api", `repos/${repository}/actions/artifacts/${artifact.id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 });
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}` !== artifact.digest) throw new Error("Initial activation lifecycle policy authorization archive digest is invalid.");
    fs.writeFileSync(archive, bytes, { mode: 0o600, flag: "wx" });
    const names = String(run("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean);
    if (JSON.stringify(names) !== JSON.stringify(["authorization.json"])) throw new Error("Initial activation lifecycle policy authorization archive contents are invalid.");
    const authorizationBytes = run("unzip", ["-p", archive, "authorization.json"], { encoding: null });
    let authorization; try { authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(authorizationBytes)); } catch { throw new Error("Initial activation lifecycle policy authorization artifact is malformed."); }
    assertInitialActivationLifecyclePolicyReconciliationAuthorization(authorization, { sourceSha });
    return Object.freeze({ workflow, artifact, authorization, authorizationBytes });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
