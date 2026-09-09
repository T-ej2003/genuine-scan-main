import crypto from "node:crypto";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { INSTALLATION, assertInstallationPlan, assertInstallationStateResources, stateIdentity } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const exact = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...fields].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const iso = (value, label) => {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) throw new Error(`${label} is invalid.`);
  return date;
};

export const RECONCILER_STATE_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION",
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  account: "368992683803",
  region: "eu-west-2",
  terraformRoot: INSTALLATION.terraformRoot,
  backend: INSTALLATION.backend,
  policyArn: INSTALLATION.policyArn,
  roleName: "mscqr-production-initial-activation-policy-reconciler",
  bootstrapRoleArn: INSTALLATION.executionRoleArn,
  environment: PRODUCTION_ENVIRONMENT_APPROVAL.installationBootstrapEnvironment,
  authorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-reconciler-state-reconciliation.yml",
  executionWorkflowPath: ".github/workflows/execute-production-initial-activation-reconciler-state-reconciliation.yml",
  authorizationArtifactName: "production-initial-activation-reconciler-state-reconciliation-authorization",
  authorizationFilename: "authorization.json",
  maxAgeMs: 30 * 60 * 1000,
  drift: Object.freeze([
    Object.freeze({ address: "aws_iam_policy.reconciler", field: "attachment_count", before: 0, after: 1 }),
    Object.freeze({ address: "aws_iam_role.reconciler", field: "managed_policy_arns", before: Object.freeze([]), after: Object.freeze([INSTALLATION.policyArn]) }),
  ]),
});

const workflowRef = (path) => `${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/${path}@refs/heads/main`;
const stateResource = (state, address) => {
  const [type, name] = address.split(".");
  const found = state?.resources?.filter((resource) => resource?.mode === "managed" && !resource.module && resource.type === type && resource.name === name);
  if (!Array.isArray(found) || found.length !== 1 || !Array.isArray(found[0].instances) || found[0].instances.length !== 1 || !found[0].instances[0]?.attributes) throw new Error(`Terraform state ${address} is not exact.`);
  return found[0];
};
const normalizedState = (bytes) => {
  const identity = stateIdentity(bytes);
  if (!identity.stateExists) throw new Error("Reconciler state reconciliation requires an existing Terraform state.");
  const state = JSON.parse(Buffer.from(bytes).toString("utf8"));
  stateResource(state, "aws_iam_policy.reconciler");
  stateResource(state, "aws_iam_role.reconciler");
  stateResource(state, "aws_iam_role_policy_attachment.reconciler");
  return { identity, state };
};
const exactDrift = (entry, expected) => {
  if (entry?.address !== expected.address || canonicalJson(entry?.change?.actions) !== canonicalJson(["update"])) throw new Error("Refresh-only plan contains an unreviewed resource drift address or action.");
  const before = entry.change.before; const after = entry.change.after;
  if (!before || !after || before[expected.field] === undefined || after[expected.field] === undefined || canonicalJson(before[expected.field]) !== canonicalJson(expected.before) || canonicalJson(after[expected.field]) !== canonicalJson(expected.after)) throw new Error("Refresh-only plan drift value is not exact.");
  const restBefore = { ...before }; const restAfter = { ...after }; delete restBefore[expected.field]; delete restAfter[expected.field];
  if (canonicalJson(restBefore) !== canonicalJson(restAfter) || Object.keys(entry.change.before_unknown || {}).length || Object.keys(entry.change.after_unknown || {}).length || Object.keys(entry.change.before_sensitive || {}).length || Object.keys(entry.change.after_sensitive || {}).length || entry.change.replace_paths?.length) throw new Error("Refresh-only plan drift changes fields outside the exact allowance.");
};

export function assertExactReconcilerRefreshOnlyPlan(plan) {
  if (!plan || plan.format_version !== "1.2" || plan.terraform_version !== INSTALLATION.terraformVersion || plan.errored !== false || plan.complete !== true || plan.applyable !== true || !Array.isArray(plan.resource_drift)) throw new Error("Refresh-only plan envelope is invalid.");
  if (plan.resource_changes !== undefined && (!Array.isArray(plan.resource_changes) || plan.resource_changes.some(({ change }) => ![["no-op"], ["read"]].some((actions) => canonicalJson(change?.actions) === canonicalJson(actions))))) throw new Error("Refresh-only plan contains an actionable resource operation.");
  if (plan.output_changes && Object.values(plan.output_changes).some(({ actions }) => actions && canonicalJson(actions) !== canonicalJson(["no-op"]))) throw new Error("Refresh-only plan changes an output.");
  if (plan.resource_drift.length !== RECONCILER_STATE_RECONCILIATION.drift.length) throw new Error("Refresh-only plan drift count is not exact.");
  const byAddress = new Map(plan.resource_drift.map((entry) => [entry?.address, entry]));
  if (byAddress.size !== RECONCILER_STATE_RECONCILIATION.drift.length) throw new Error("Refresh-only plan drift addresses are duplicated.");
  for (const expected of RECONCILER_STATE_RECONCILIATION.drift) exactDrift(byAddress.get(expected.address), expected);
  return Object.freeze({ resourceDrift: RECONCILER_STATE_RECONCILIATION.drift, refreshOnly: true, terraformResourceAddCount: 0, terraformResourceChangeCount: 0, terraformResourceDestroyCount: 0 });
}

export function assertCanonicalAttachmentTopology(value) {
  exact(value, ["roles", "users", "groups"], "Reconciler attachment topology");
  if (canonicalJson([...value.roles].sort()) !== canonicalJson([RECONCILER_STATE_RECONCILIATION.roleName]) || !Array.isArray(value.users) || value.users.length || !Array.isArray(value.groups) || value.groups.length) throw new Error("Reconciler attachment topology is not canonical.");
  return Object.freeze({ roles: [RECONCILER_STATE_RECONCILIATION.roleName], users: [], groups: [] });
}

export function assertStateObject(value, state) {
  exact(value, ["versionId", "etag"], "Terraform backend object identity");
  if (typeof value.versionId !== "string" || !value.versionId || typeof value.etag !== "string" || !value.etag) throw new Error("Terraform backend VersionId or ETag is missing.");
  const checked = normalizedState(state);
  return Object.freeze({ ...checked.identity, versionId: value.versionId, etag: value.etag });
}

const preparationFields = ["schemaVersion", "kind", "operation", "sourceSha", "account", "terraformRoot", "backend", "policyArn", "bootstrapRoleArn", "predecessorState", "attachmentTopology", "attachmentTopologySha256", "drift", "driftSha256", "savedPlanSha256", "savedPlanByteLength", "planSemantics", "createdAt", "expiresAt", "preparationSha256"];
export function createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes, stateObject, attachmentTopology, planBytes, planJson, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "")) throw new Error("State reconciliation source SHA is invalid.");
  const predecessorState = assertStateObject(stateObject, stateBytes);
  const topology = assertCanonicalAttachmentTopology(attachmentTopology);
  const semantics = assertExactReconcilerRefreshOnlyPlan(planJson);
  if (!Buffer.isBuffer(planBytes) || !planBytes.length) throw new Error("Refresh-only saved plan is required.");
  const created = iso(preparedAt, "State reconciliation preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_PREPARATION", operation: RECONCILER_STATE_RECONCILIATION.operation, sourceSha, account: RECONCILER_STATE_RECONCILIATION.account, terraformRoot: RECONCILER_STATE_RECONCILIATION.terraformRoot, backend: RECONCILER_STATE_RECONCILIATION.backend, policyArn: RECONCILER_STATE_RECONCILIATION.policyArn, bootstrapRoleArn: RECONCILER_STATE_RECONCILIATION.bootstrapRoleArn, predecessorState, attachmentTopology: topology, attachmentTopologySha256: sha256(topology), drift: RECONCILER_STATE_RECONCILIATION.drift, driftSha256: sha256(RECONCILER_STATE_RECONCILIATION.drift), savedPlanSha256: sha256(planBytes), savedPlanByteLength: planBytes.length, planSemantics: semantics, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + RECONCILER_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}
export function assertReconcilerStateReconciliationPreparation(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, preparationFields, "State reconciliation preparation");
  const { preparationSha256, ...body } = value;
  const expectedSemantics = { resourceDrift: RECONCILER_STATE_RECONCILIATION.drift, refreshOnly: true, terraformResourceAddCount: 0, terraformResourceChangeCount: 0, terraformResourceDestroyCount: 0 };
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_PREPARATION" || value.operation !== RECONCILER_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || value.account !== RECONCILER_STATE_RECONCILIATION.account || value.terraformRoot !== RECONCILER_STATE_RECONCILIATION.terraformRoot || canonicalJson(value.backend) !== canonicalJson(RECONCILER_STATE_RECONCILIATION.backend) || value.policyArn !== RECONCILER_STATE_RECONCILIATION.policyArn || value.bootstrapRoleArn !== RECONCILER_STATE_RECONCILIATION.bootstrapRoleArn || !value.predecessorState?.stateExists || !SHA256.test(value.predecessorState.stateSha256 || "") || !Number.isSafeInteger(value.predecessorState.serial) || typeof value.predecessorState.lineage !== "string" || !value.predecessorState.versionId || !value.predecessorState.etag || canonicalJson(value.drift) !== canonicalJson(RECONCILER_STATE_RECONCILIATION.drift) || value.driftSha256 !== sha256(value.drift) || value.attachmentTopologySha256 !== sha256(assertCanonicalAttachmentTopology(value.attachmentTopology)) || !SHA256.test(value.savedPlanSha256 || "") || !Number.isSafeInteger(value.savedPlanByteLength) || value.savedPlanByteLength < 1 || canonicalJson(value.planSemantics) !== canonicalJson(expectedSemantics) || value.preparationSha256 !== sha256(body)) throw new Error("State reconciliation preparation binding is invalid.");
  const created = iso(value.createdAt, "State reconciliation preparation creation timestamp"); const expires = iso(value.expiresAt, "State reconciliation preparation expiry timestamp");
  if (expires.getTime() - created.getTime() !== RECONCILER_STATE_RECONCILIATION.maxAgeMs || (!allowExpired && (now < created || now > expires))) throw new Error("State reconciliation preparation is stale.");
  return value;
}

const authorizationFields = ["schemaVersion", "kind", "operation", "sourceSha", "preparationSha256", "savedPlanSha256", "predecessorState", "driftSha256", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
export function createReconcilerStateReconciliationAuthorization({ preparation, approval, now = new Date() } = {}) {
  const checked = assertReconcilerStateReconciliationPreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: checked.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(RECONCILER_STATE_RECONCILIATION.authorizationWorkflowPath)) throw new Error("State reconciliation authorization requires its dedicated workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: checked.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_AUTHORIZATION", operation: checked.operation, sourceSha: checked.sourceSha, preparationSha256: checked.preparationSha256, savedPlanSha256: checked.savedPlanSha256, predecessorState: checked.predecessorState, driftSha256: checked.driftSha256, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}
export function assertReconcilerStateReconciliationAuthorization(value, preparation, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, authorizationFields, "State reconciliation authorization");
  const checked = assertReconcilerStateReconciliationPreparation(preparation, { sourceSha, now, allowExpired }); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_AUTHORIZATION" || value.operation !== checked.operation || value.sourceSha !== checked.sourceSha || value.preparationSha256 !== checked.preparationSha256 || value.savedPlanSha256 !== checked.savedPlanSha256 || canonicalJson(value.predecessorState) !== canonicalJson(checked.predecessorState) || value.driftSha256 !== checked.driftSha256 || !SHA256.test(authorizationSha256 || "") || authorizationSha256 !== sha256(body)) throw new Error("State reconciliation authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (!allowExpired) assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(RECONCILER_STATE_RECONCILIATION.authorizationWorkflowPath) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("State reconciliation approval provenance is invalid.");
  return value;
}

export function assertExactStateSuccessor({ beforeBytes, afterBytes }) {
  const before = normalizedState(beforeBytes); const after = normalizedState(afterBytes);
  if (after.identity.lineage !== before.identity.lineage || after.identity.serial !== before.identity.serial + 1 || after.identity.stateSha256 === before.identity.stateSha256) throw new Error("State reconciliation successor identity is invalid.");
  const projected = structuredClone(after.state); projected.serial = before.state.serial;
  stateResource(projected, "aws_iam_policy.reconciler").instances[0].attributes.attachment_count = 0;
  stateResource(projected, "aws_iam_role.reconciler").instances[0].attributes.managed_policy_arns = [];
  if (canonicalJson(projected) !== canonicalJson(before.state)) throw new Error("State reconciliation successor changes fields outside the exact allowance.");
  const policy = stateResource(after.state, "aws_iam_policy.reconciler").instances[0].attributes;
  const role = stateResource(after.state, "aws_iam_role.reconciler").instances[0].attributes;
  if (policy.attachment_count !== 1 || canonicalJson(role.managed_policy_arns) !== canonicalJson([RECONCILER_STATE_RECONCILIATION.policyArn])) throw new Error("State reconciliation successor fields are not exact.");
  return after.identity;
}

const assertReplaySuccessor = ({ stateBytes, stateObject, preparation }) => {
  const { identity, state } = normalizedState(stateBytes);
  if (identity.lineage !== preparation.predecessorState.lineage || identity.serial <= preparation.predecessorState.serial || identity.stateSha256 === preparation.predecessorState.stateSha256 || stateObject?.versionId === preparation.predecessorState.versionId || stateObject?.etag === preparation.predecessorState.etag) throw new Error("State reconciliation state is neither the exact predecessor nor a valid successor.");
  const policy = stateResource(state, "aws_iam_policy.reconciler").instances[0].attributes;
  const role = stateResource(state, "aws_iam_role.reconciler").instances[0].attributes;
  if (policy.attachment_count !== 1 || canonicalJson(role.managed_policy_arns) !== canonicalJson([RECONCILER_STATE_RECONCILIATION.policyArn])) throw new Error("State reconciliation successor fields are not exact.");
  assertInstallationStateResources(stateBytes);
  return identity;
};
const assertExactPostRefreshNormalPlan = (plan) => {
  const normal = assertInstallationPlan(plan);
  if (normal.updateCount !== 1 || normal.changedAddresses[0] !== "aws_iam_policy.reconciler" || normal.createCount || normal.deleteCount || normal.replaceCount) throw new Error("Post-refresh normal installation plan is not the exact policy update.");
  return normal;
};
const assertPostStateObject = (value, predecessor) => {
  if (!value?.versionId || !value?.etag || value.versionId === predecessor.versionId) throw new Error("State reconciliation post-state object identity is invalid.");
  return value;
};

export function executeReconcilerStateReconciliation({ sourceSha, preparation, authorization, planBytes, planJson, beforeStateBytes, beforeObject, beforeTopology, applySavedPlan, readPostSnapshot, readPostTopology, renderNormalPlan, reauthenticateSource, verifyPostconditions, now = new Date() } = {}) {
  if (![applySavedPlan, readPostSnapshot, readPostTopology, renderNormalPlan, reauthenticateSource, verifyPostconditions].every((value) => typeof value === "function")) throw new Error("State reconciliation execution adapters are required.");
  assertReconcilerStateReconciliationAuthorization(authorization, preparation, { sourceSha, now });
  if (sha256(planBytes) !== preparation.savedPlanSha256 || !Number.isSafeInteger(planBytes?.length) || planBytes.length !== preparation.savedPlanByteLength) throw new Error("State reconciliation saved plan changed after authorization.");
  assertExactReconcilerRefreshOnlyPlan(planJson);
  const currentObject = assertStateObject(beforeObject, beforeStateBytes);
  if (canonicalJson(assertCanonicalAttachmentTopology(beforeTopology)) !== canonicalJson(preparation.attachmentTopology)) throw new Error("State reconciliation live IAM changed before apply.");
  if (canonicalJson(currentObject) !== canonicalJson(preparation.predecessorState)) {
    const replay = assertReplaySuccessor({ stateBytes: beforeStateBytes, stateObject: beforeObject, preparation });
    verifyPostconditions();
    const normal = assertExactPostRefreshNormalPlan(renderNormalPlan());
    return Object.freeze({ status: "ALREADY_COMPLETE", refreshOnlyApplyCount: 0, terraformStateMutationCount: 0, remoteIamMutationCount: 0, postState: { ...replay, versionId: beforeObject.versionId, etag: beforeObject.etag }, normalPlan: normal });
  }
  reauthenticateSource();
  try { applySavedPlan(planBytes); }
  catch (error) {
    const { bytes: after, object } = readPostSnapshot(); const topology = readPostTopology();
    try {
      const successor = assertExactStateSuccessor({ beforeBytes: beforeStateBytes, afterBytes: after });
      assertCanonicalAttachmentTopology(topology);
      assertPostStateObject(object, currentObject);
      verifyPostconditions();
      assertExactPostRefreshNormalPlan(renderNormalPlan());
      return Object.freeze({ status: "COMPLETED_BY_READBACK", refreshOnlyApplyCount: 1, terraformStateMutationCount: 1, remoteIamMutationCount: 0, postState: { ...successor, versionId: object.versionId, etag: object.etag } });
    } catch { error.mutationOutcome = "AMBIGUOUS"; throw error; }
  }
  const { bytes: after, object } = readPostSnapshot(); const topology = readPostTopology();
  const successor = assertExactStateSuccessor({ beforeBytes: beforeStateBytes, afterBytes: after });
  assertCanonicalAttachmentTopology(topology);
  assertPostStateObject(object, currentObject);
  verifyPostconditions();
  const normal = assertExactPostRefreshNormalPlan(renderNormalPlan());
  return Object.freeze({ status: "COMPLETE", refreshOnlyApplyCount: 1, terraformStateMutationCount: 1, remoteIamMutationCount: 0, postState: { ...successor, versionId: object.versionId, etag: object.etag }, normalPlan: normal });
}
