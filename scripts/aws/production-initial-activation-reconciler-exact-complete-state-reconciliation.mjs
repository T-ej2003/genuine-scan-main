import crypto from "node:crypto";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { INSTALLATION, assertInstallationPlan, assertInstallationPlanConfiguration, assertInstallationStateResources, stateIdentity } from "./production-initial-activation-reconciler-installation-contract.mjs";
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

export const EXACT_COMPLETE_STATE_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION",
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  account: "368992683803",
  terraformRoot: INSTALLATION.terraformRoot,
  backend: INSTALLATION.backend,
  roleName: "mscqr-production-mixed-dual-slot-recovery-executor",
  roleArn: INSTALLATION.mixedRecoveryRoleArn,
  policyArn: INSTALLATION.mixedRecoveryPolicyArn,
  bootstrapRoleArn: INSTALLATION.executionRoleArn,
  environment: PRODUCTION_ENVIRONMENT_APPROVAL.installationBootstrapEnvironment,
  authorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-exact-complete-state-reconciliation.yml",
  executionWorkflowPath: ".github/workflows/execute-production-initial-activation-exact-complete-state-reconciliation.yml",
  authorizationArtifactName: "production-initial-activation-exact-complete-state-reconciliation-authorization",
  authorizationFilename: "authorization.json",
  recoveryAuthorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-exact-complete-state-reconciliation-recovery.yml",
  recoveryExecutionWorkflowPath: ".github/workflows/execute-production-initial-activation-exact-complete-state-reconciliation-recovery.yml",
  recoveryAuthorizationArtifactName: "production-initial-activation-exact-complete-state-reconciliation-recovery-authorization",
  recoveryAuthorizationFilename: "recovery-authorization.json",
  maxAgeMs: 30 * 60 * 1000,
  drift: Object.freeze([
    Object.freeze({ address: "aws_iam_policy.mixed_recovery", field: "attachment_count", before: 0, after: 1 }),
    Object.freeze({ address: "aws_iam_role.mixed_recovery", field: "managed_policy_arns", before: Object.freeze([]), after: Object.freeze([INSTALLATION.mixedRecoveryPolicyArn]) }),
  ]),
});

const workflowRef = (path) => `${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/${path}@refs/heads/main`;
const stateResource = (state, address) => {
  const [type, name] = address.split(".");
  const resources = state?.resources?.filter((resource) => resource?.mode === "managed" && !resource.module && resource.type === type && resource.name === name);
  if (!Array.isArray(resources) || resources.length !== 1 || !Array.isArray(resources[0].instances) || resources[0].instances.length !== 1 || !resources[0].instances[0]?.attributes) throw new Error(`Terraform state ${address} is not exact.`);
  return resources[0];
};
const normalizedState = (bytes) => {
  const identity = assertInstallationStateResources(bytes);
  if (!identity.stateExists) throw new Error("Exact-complete state reconciliation requires an existing Terraform state.");
  const state = JSON.parse(Buffer.from(bytes).toString("utf8"));
  for (const address of INSTALLATION.expectedAddresses) stateResource(state, address);
  return { identity, state };
};
const assertFalseOnly = (value) => {
  if (value === false) return;
  if (Array.isArray(value)) return value.forEach(assertFalseOnly);
  if (value && typeof value === "object") return Object.values(value).forEach(assertFalseOnly);
  throw new Error("Exact-complete refresh-only plan has sensitive or malformed metadata.");
};
const assertExactDrift = (entry, expected) => {
  if (entry?.address !== expected.address || canonicalJson(entry?.change?.actions) !== canonicalJson(["update"])) throw new Error("Exact-complete refresh-only plan contains an unreviewed drift address or action.");
  const { before, after } = entry.change;
  if (!before || !after || canonicalJson(before[expected.field]) !== canonicalJson(expected.before) || canonicalJson(after[expected.field]) !== canonicalJson(expected.after)) throw new Error("Exact-complete refresh-only plan drift value is not exact.");
  const beforeRest = { ...before }; const afterRest = { ...after }; delete beforeRest[expected.field]; delete afterRest[expected.field];
  if (canonicalJson(beforeRest) !== canonicalJson(afterRest) || Object.keys(entry.change.before_unknown || {}).length || Object.keys(entry.change.after_unknown || {}).length || entry.change.replace_paths?.length) throw new Error("Exact-complete refresh-only plan changes fields outside the exact allowance.");
  const beforeSensitive = entry.change.before_sensitive === undefined ? {} : entry.change.before_sensitive;
  const afterSensitive = entry.change.after_sensitive === undefined ? {} : entry.change.after_sensitive;
  if (expected.field === "managed_policy_arns") {
    const split = (mask, value) => {
      if (!mask || typeof mask !== "object" || Array.isArray(mask) || !Object.hasOwn(mask, expected.field)) throw new Error("Exact-complete refresh-only plan managed-policy sensitivity metadata is malformed.");
      const rest = { ...mask }; const fieldMask = rest[expected.field]; delete rest[expected.field]; assertFalseOnly(fieldMask); return rest;
    };
    if (canonicalJson(split(beforeSensitive, before[expected.field])) !== canonicalJson(split(afterSensitive, after[expected.field]))) throw new Error("Exact-complete refresh-only plan sensitivity metadata changed.");
  } else {
    if (canonicalJson(beforeSensitive) !== canonicalJson(afterSensitive)) throw new Error("Exact-complete refresh-only plan sensitivity metadata changed.");
    assertFalseOnly(beforeSensitive);
  }
};

export function assertExactCompleteRefreshOnlyPlan(plan) {
  if (!plan || plan.format_version !== "1.2" || plan.terraform_version !== INSTALLATION.terraformVersion || plan.errored !== false || plan.complete !== true || plan.applyable !== true || !Array.isArray(plan.resource_drift)) throw new Error("Exact-complete refresh-only plan envelope is invalid.");
  assertInstallationPlanConfiguration(plan);
  if (plan.resource_changes !== undefined) {
    if (!Array.isArray(plan.resource_changes)) throw new Error("Exact-complete refresh-only plan resource_changes is malformed.");
    if (plan.resource_changes.length) {
      const clean = structuredClone(plan); clean.resource_drift = [];
      const normal = assertInstallationPlan(clean);
      if (normal.resourceChangeCount !== 0 || normal.createCount || normal.updateCount || normal.deleteCount || normal.replaceCount || normal.noOpCount !== INSTALLATION.expectedAddresses.length) throw new Error("Exact-complete refresh-only plan contains an actionable Terraform resource operation.");
    }
  }
  if (Object.values(plan.output_changes || {}).some((change) => canonicalJson(change?.actions) !== canonicalJson(["no-op"]))) throw new Error("Exact-complete refresh-only plan contains an output mutation.");
  if (plan.resource_drift.length !== EXACT_COMPLETE_STATE_RECONCILIATION.drift.length) throw new Error("Exact-complete refresh-only plan drift count is not exact.");
  const drift = new Map(plan.resource_drift.map((entry) => [entry?.address, entry]));
  if (drift.size !== EXACT_COMPLETE_STATE_RECONCILIATION.drift.length) throw new Error("Exact-complete refresh-only plan drift addresses are duplicated.");
  for (const expected of EXACT_COMPLETE_STATE_RECONCILIATION.drift) assertExactDrift(drift.get(expected.address), expected);
  return Object.freeze({ resourceDrift: EXACT_COMPLETE_STATE_RECONCILIATION.drift, refreshOnly: true, terraformResourceAddCount: 0, terraformResourceChangeCount: 0, terraformResourceDestroyCount: 0 });
}

export function assertExactCompleteCleanNormalPlan(plan) {
  const noDrift = plan?.resource_drift === undefined || plan?.resource_drift === null || Array.isArray(plan?.resource_drift) && plan.resource_drift.length === 0;
  if (plan?.applyable !== false || !noDrift) throw new Error("Exact-complete post-reconciliation normal plan must be the canonical non-applyable no-op.");
  const semantics = assertInstallationPlan({ ...plan, applyable: true });
  if (semantics.resourceChangeCount !== 0 || semantics.createCount || semantics.updateCount || semantics.deleteCount || semantics.replaceCount || semantics.noOpCount !== INSTALLATION.expectedAddresses.length || Object.values(plan.output_changes || {}).some((change) => canonicalJson(change?.actions) !== canonicalJson(["no-op"]))) throw new Error("Exact-complete post-reconciliation normal plan is not clean.");
  return semantics;
}

export function assertExactMixedRecoveryAttachmentTopology(value) {
  exact(value, ["roles", "users", "groups"], "Exact-complete mixed recovery attachment topology");
  if (canonicalJson(value.roles) !== canonicalJson([EXACT_COMPLETE_STATE_RECONCILIATION.roleName]) || !Array.isArray(value.users) || value.users.length || !Array.isArray(value.groups) || value.groups.length) throw new Error("Exact-complete mixed recovery attachment topology is not exact.");
  return Object.freeze({ roles: [EXACT_COMPLETE_STATE_RECONCILIATION.roleName], users: [], groups: [] });
}
const assertStateObject = (value, bytes) => {
  exact(value, ["versionId", "etag"], "Exact-complete Terraform backend object identity");
  if (typeof value.versionId !== "string" || !value.versionId || typeof value.etag !== "string" || !value.etag) throw new Error("Exact-complete Terraform backend object identity is invalid.");
  const { identity } = normalizedState(bytes);
  return Object.freeze({ ...identity, versionId: value.versionId, etag: value.etag });
};
const exactSuccessor = (beforeBytes) => {
  const { state } = normalizedState(beforeBytes); const successor = structuredClone(state);
  successor.serial += 1;
  stateResource(successor, "aws_iam_policy.mixed_recovery").instances[0].attributes.attachment_count = 1;
  stateResource(successor, "aws_iam_role.mixed_recovery").instances[0].attributes.managed_policy_arns = [EXACT_COMPLETE_STATE_RECONCILIATION.policyArn];
  return successor;
};
export function assertExactCompleteStateSuccessor({ beforeBytes, afterBytes } = {}) {
  const before = normalizedState(beforeBytes); const after = normalizedState(afterBytes);
  if (after.identity.lineage !== before.identity.lineage || after.identity.serial !== before.identity.serial + 1 || after.identity.stateSha256 === before.identity.stateSha256 || canonicalJson(after.state) !== canonicalJson(exactSuccessor(beforeBytes))) throw new Error("Exact-complete state reconciliation successor is not exact.");
  return Object.freeze({ ...after.identity, successorStateSha256: sha256(after.state) });
}

const preparationFields = ["schemaVersion", "kind", "operation", "sourceSha", "account", "terraformRoot", "backend", "roleArn", "policyArn", "bootstrapRoleArn", "predecessorState", "successorStateSha256", "attachmentTopology", "attachmentTopologySha256", "drift", "driftSha256", "savedPlanSha256", "savedPlanByteLength", "planSemantics", "createdAt", "expiresAt", "preparationSha256"];
export function createExactCompleteStateReconciliationPreparation({ sourceSha, stateBytes, stateObject, attachmentTopology, planBytes, planJson, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "") || !Buffer.isBuffer(planBytes) || !planBytes.length) throw new Error("Exact-complete state reconciliation preparation input is invalid.");
  const predecessorState = assertStateObject(stateObject, stateBytes); const topology = assertExactMixedRecoveryAttachmentTopology(attachmentTopology); const planSemantics = assertExactCompleteRefreshOnlyPlan(planJson); const created = iso(preparedAt, "Exact-complete state reconciliation preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_PREPARATION", operation: EXACT_COMPLETE_STATE_RECONCILIATION.operation, sourceSha, account: EXACT_COMPLETE_STATE_RECONCILIATION.account, terraformRoot: EXACT_COMPLETE_STATE_RECONCILIATION.terraformRoot, backend: EXACT_COMPLETE_STATE_RECONCILIATION.backend, roleArn: EXACT_COMPLETE_STATE_RECONCILIATION.roleArn, policyArn: EXACT_COMPLETE_STATE_RECONCILIATION.policyArn, bootstrapRoleArn: EXACT_COMPLETE_STATE_RECONCILIATION.bootstrapRoleArn, predecessorState, successorStateSha256: sha256(exactSuccessor(stateBytes)), attachmentTopology: topology, attachmentTopologySha256: sha256(topology), drift: EXACT_COMPLETE_STATE_RECONCILIATION.drift, driftSha256: sha256(EXACT_COMPLETE_STATE_RECONCILIATION.drift), savedPlanSha256: sha256(planBytes), savedPlanByteLength: planBytes.length, planSemantics, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + EXACT_COMPLETE_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}
export function assertExactCompleteStateReconciliationPreparation(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, preparationFields, "Exact-complete state reconciliation preparation"); const { preparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_PREPARATION" || value.operation !== EXACT_COMPLETE_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || value.account !== EXACT_COMPLETE_STATE_RECONCILIATION.account || value.terraformRoot !== EXACT_COMPLETE_STATE_RECONCILIATION.terraformRoot || canonicalJson(value.backend) !== canonicalJson(EXACT_COMPLETE_STATE_RECONCILIATION.backend) || value.roleArn !== EXACT_COMPLETE_STATE_RECONCILIATION.roleArn || value.policyArn !== EXACT_COMPLETE_STATE_RECONCILIATION.policyArn || value.bootstrapRoleArn !== EXACT_COMPLETE_STATE_RECONCILIATION.bootstrapRoleArn || !value.predecessorState?.stateExists || !SHA256.test(value.predecessorState.stateSha256 || "") || !Number.isSafeInteger(value.predecessorState.serial) || value.predecessorState.serial < 0 || typeof value.predecessorState.lineage !== "string" || !value.predecessorState.lineage || !SHA256.test(value.successorStateSha256 || "") || typeof value.predecessorState.versionId !== "string" || !value.predecessorState.versionId || typeof value.predecessorState.etag !== "string" || !value.predecessorState.etag || canonicalJson(value.drift) !== canonicalJson(EXACT_COMPLETE_STATE_RECONCILIATION.drift) || value.driftSha256 !== sha256(value.drift) || value.attachmentTopologySha256 !== sha256(assertExactMixedRecoveryAttachmentTopology(value.attachmentTopology)) || !SHA256.test(value.savedPlanSha256 || "") || !Number.isSafeInteger(value.savedPlanByteLength) || value.savedPlanByteLength < 1 || value.preparationSha256 !== sha256(body)) throw new Error("Exact-complete state reconciliation preparation binding is invalid.");
  exact(value.predecessorState, ["stateExists", "lineage", "serial", "stateSha256", "versionId", "etag"], "Exact-complete state reconciliation predecessor state");
  if (canonicalJson(value.planSemantics) !== canonicalJson({ resourceDrift: EXACT_COMPLETE_STATE_RECONCILIATION.drift, refreshOnly: true, terraformResourceAddCount: 0, terraformResourceChangeCount: 0, terraformResourceDestroyCount: 0 })) throw new Error("Exact-complete state reconciliation plan semantics are invalid.");
  const created = iso(value.createdAt, "Exact-complete state reconciliation preparation creation timestamp"); const expires = iso(value.expiresAt, "Exact-complete state reconciliation preparation expiry timestamp");
  if (expires.getTime() - created.getTime() !== EXACT_COMPLETE_STATE_RECONCILIATION.maxAgeMs || (!allowExpired && (now < created || now > expires))) throw new Error("Exact-complete state reconciliation preparation is stale.");
  return value;
}

const authorizationFields = ["schemaVersion", "kind", "operation", "sourceSha", "preparationSha256", "savedPlanSha256", "predecessorState", "driftSha256", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
export function createExactCompleteStateReconciliationAuthorization({ preparation, approval, now = new Date() } = {}) {
  const checked = assertExactCompleteStateReconciliationPreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: checked.sourceSha, repository: EXACT_COMPLETE_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(EXACT_COMPLETE_STATE_RECONCILIATION.authorizationWorkflowPath)) throw new Error("Exact-complete state reconciliation requires its dedicated workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: checked.sourceSha, repository: EXACT_COMPLETE_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_AUTHORIZATION", operation: checked.operation, sourceSha: checked.sourceSha, preparationSha256: checked.preparationSha256, savedPlanSha256: checked.savedPlanSha256, predecessorState: checked.predecessorState, driftSha256: checked.driftSha256, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}
export function assertExactCompleteStateReconciliationAuthorization(value, preparation, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, authorizationFields, "Exact-complete state reconciliation authorization"); const prepared = assertExactCompleteStateReconciliationPreparation(preparation, { sourceSha, now, allowExpired }); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== prepared.sourceSha || value.preparationSha256 !== prepared.preparationSha256 || value.savedPlanSha256 !== prepared.savedPlanSha256 || canonicalJson(value.predecessorState) !== canonicalJson(prepared.predecessorState) || value.driftSha256 !== prepared.driftSha256 || !SHA256.test(authorizationSha256 || "") || authorizationSha256 !== sha256(body)) throw new Error("Exact-complete state reconciliation authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: EXACT_COMPLETE_STATE_RECONCILIATION.repository }); if (!allowExpired) assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(EXACT_COMPLETE_STATE_RECONCILIATION.authorizationWorkflowPath) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("Exact-complete state reconciliation approval provenance is invalid.");
  return value;
}

const recoveryPreparationFields = ["schemaVersion", "kind", "operation", "sourceSha", "originalSourceSha", "originalPreparationSha256", "originalAuthorizationSha256", "originalAuthorizationWorkflowRunId", "originalAuthorizationWorkflowRunAttempt", "predecessorState", "successorStateSha256", "successorStateObject", "attachmentTopology", "attachmentTopologySha256", "createdAt", "expiresAt", "recoveryPreparationSha256"];
const recoveryAuthorizationFields = ["schemaVersion", "kind", "operation", "sourceSha", "recoveryPreparationSha256", "originalPreparationSha256", "originalAuthorizationSha256", "successorStateSha256", "successorStateObject", "maxAwsMutations", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "recoveryAuthorizationSha256"];
const assertBoundState = (value, label) => {
  exact(value, ["stateExists", "lineage", "serial", "stateSha256", "versionId", "etag"], label);
  if (value.stateExists !== true || typeof value.lineage !== "string" || !value.lineage || !Number.isSafeInteger(value.serial) || value.serial < 0 || !SHA256.test(value.stateSha256 || "") || typeof value.versionId !== "string" || !value.versionId || typeof value.etag !== "string" || !value.etag) throw new Error(`${label} is invalid.`);
  return value;
};
const assertExactAuthorizedSuccessor = ({ stateBytes, stateObject, preparation }) => {
  const successor = assertStateObject(stateObject, stateBytes);
  if (sha256(JSON.parse(Buffer.from(stateBytes).toString("utf8"))) !== preparation.successorStateSha256 || successor.lineage !== preparation.predecessorState.lineage || successor.serial !== preparation.predecessorState.serial + 1 || successor.versionId === preparation.predecessorState.versionId || successor.etag === preparation.predecessorState.etag) throw new Error("Exact-complete state reconciliation successor is not the authorized state.");
  return successor;
};

export function createExactCompleteStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation, originalAuthorization, originalAuthorizationWorkflowRunId, originalAuthorizationWorkflowRunAttempt, stateBytes, stateObject, attachmentTopology, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[1-9][0-9]*$/.test(String(originalAuthorizationWorkflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(originalAuthorizationWorkflowRunAttempt || ""))) throw new Error("Exact-complete state reconciliation recovery coordinates are invalid.");
  const original = assertExactCompleteStateReconciliationPreparation(originalPreparation, { sourceSha: originalPreparation?.sourceSha, allowExpired: true });
  const authorization = assertExactCompleteStateReconciliationAuthorization(originalAuthorization, original, { sourceSha: original.sourceSha, allowExpired: true });
  if (authorization.protectedEnvironmentApprovalEvidence.workflowRunId !== String(originalAuthorizationWorkflowRunId) || authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt !== String(originalAuthorizationWorkflowRunAttempt)) throw new Error("Exact-complete state reconciliation original authorization is invalid.");
  const successor = assertExactAuthorizedSuccessor({ stateBytes, stateObject, preparation: original }); const topology = assertExactMixedRecoveryAttachmentTopology(attachmentTopology); const created = iso(preparedAt, "Exact-complete state reconciliation recovery preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_RECOVERY_PREPARATION", operation: EXACT_COMPLETE_STATE_RECONCILIATION.operation, sourceSha, originalSourceSha: original.sourceSha, originalPreparationSha256: original.preparationSha256, originalAuthorizationSha256: authorization.authorizationSha256, originalAuthorizationWorkflowRunId: String(originalAuthorizationWorkflowRunId), originalAuthorizationWorkflowRunAttempt: String(originalAuthorizationWorkflowRunAttempt), predecessorState: original.predecessorState, successorStateSha256: original.successorStateSha256, successorStateObject: successor, attachmentTopology: topology, attachmentTopologySha256: sha256(topology), createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + EXACT_COMPLETE_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, recoveryPreparationSha256: sha256(body) });
}

export function assertExactCompleteStateReconciliationRecoveryPreparation(value, { sourceSha, now = new Date() } = {}) {
  exact(value, recoveryPreparationFields, "Exact-complete state reconciliation recovery preparation"); const { recoveryPreparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_RECOVERY_PREPARATION" || value.operation !== EXACT_COMPLETE_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(value.sourceSha || "") || !SHA40.test(value.originalSourceSha || "") || !SHA256.test(value.originalPreparationSha256 || "") || !SHA256.test(value.originalAuthorizationSha256 || "") || !/^[1-9][0-9]*$/.test(value.originalAuthorizationWorkflowRunId || "") || !/^[1-9][0-9]*$/.test(value.originalAuthorizationWorkflowRunAttempt || "") || !SHA256.test(value.successorStateSha256 || "") || value.attachmentTopologySha256 !== sha256(assertExactMixedRecoveryAttachmentTopology(value.attachmentTopology)) || value.recoveryPreparationSha256 !== sha256(body)) throw new Error("Exact-complete state reconciliation recovery preparation binding is invalid.");
  assertBoundState(value.predecessorState, "Exact-complete state reconciliation recovery predecessor state"); const successor = assertBoundState(value.successorStateObject, "Exact-complete state reconciliation recovery successor state");
  if (successor.lineage !== value.predecessorState.lineage || successor.serial !== value.predecessorState.serial + 1 || successor.versionId === value.predecessorState.versionId || successor.etag === value.predecessorState.etag) throw new Error("Exact-complete state reconciliation recovery successor is invalid.");
  const created = iso(value.createdAt, "Exact-complete state reconciliation recovery preparation creation timestamp"); const expires = iso(value.expiresAt, "Exact-complete state reconciliation recovery preparation expiry timestamp");
  if (expires.getTime() - created.getTime() !== EXACT_COMPLETE_STATE_RECONCILIATION.maxAgeMs || now < created || now > expires) throw new Error("Exact-complete state reconciliation recovery preparation is stale.");
  return value;
}

export function createExactCompleteStateReconciliationRecoveryAuthorization({ recoveryPreparation, approval, now = new Date() } = {}) {
  const prepared = assertExactCompleteStateReconciliationRecoveryPreparation(recoveryPreparation, { sourceSha: recoveryPreparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: prepared.sourceSha, repository: EXACT_COMPLETE_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(EXACT_COMPLETE_STATE_RECONCILIATION.recoveryAuthorizationWorkflowPath)) throw new Error("Exact-complete state reconciliation recovery requires its dedicated workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: prepared.sourceSha, repository: EXACT_COMPLETE_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_RECOVERY_AUTHORIZATION", operation: prepared.operation, sourceSha: prepared.sourceSha, recoveryPreparationSha256: prepared.recoveryPreparationSha256, originalPreparationSha256: prepared.originalPreparationSha256, originalAuthorizationSha256: prepared.originalAuthorizationSha256, successorStateSha256: prepared.successorStateSha256, successorStateObject: prepared.successorStateObject, maxAwsMutations: {}, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, recoveryAuthorizationSha256: sha256(body) });
}

export function assertExactCompleteStateReconciliationRecoveryAuthorization(value, recoveryPreparation, { sourceSha, now = new Date() } = {}) {
  exact(value, recoveryAuthorizationFields, "Exact-complete state reconciliation recovery authorization"); const prepared = assertExactCompleteStateReconciliationRecoveryPreparation(recoveryPreparation, { sourceSha, now }); const { recoveryAuthorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_EXACT_COMPLETE_STATE_RECONCILIATION_RECOVERY_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== prepared.sourceSha || value.recoveryPreparationSha256 !== prepared.recoveryPreparationSha256 || value.originalPreparationSha256 !== prepared.originalPreparationSha256 || value.originalAuthorizationSha256 !== prepared.originalAuthorizationSha256 || value.successorStateSha256 !== prepared.successorStateSha256 || canonicalJson(value.successorStateObject) !== canonicalJson(prepared.successorStateObject) || canonicalJson(value.maxAwsMutations) !== canonicalJson({}) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256 || value.recoveryAuthorizationSha256 !== sha256(body)) throw new Error("Exact-complete state reconciliation recovery authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: EXACT_COMPLETE_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(EXACT_COMPLETE_STATE_RECONCILIATION.recoveryAuthorizationWorkflowPath) || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("Exact-complete state reconciliation recovery approval provenance is invalid.");
  return value;
}

export function executeExactCompleteStateReconciliation({ sourceSha, preparation, authorization, planBytes, planJson, beforeStateBytes, beforeObject, beforeTopology, applyRefreshOnlyPlan, readPostSnapshot, readPostTopology, renderNormalPlan, reauthenticateSource, verifyLive, now = new Date() } = {}) {
  if (![applyRefreshOnlyPlan, readPostSnapshot, readPostTopology, renderNormalPlan, reauthenticateSource, verifyLive].every((value) => typeof value === "function")) throw new Error("Exact-complete state reconciliation execution adapters are required.");
  const prepared = assertExactCompleteStateReconciliationPreparation(preparation, { sourceSha, now }); assertExactCompleteStateReconciliationAuthorization(authorization, prepared, { sourceSha, now });
  if (!Buffer.isBuffer(planBytes) || sha256(planBytes) !== prepared.savedPlanSha256 || planBytes.length !== prepared.savedPlanByteLength || canonicalJson(assertExactCompleteRefreshOnlyPlan(planJson)) !== canonicalJson(prepared.planSemantics)) throw new Error("Exact-complete state reconciliation saved plan changed after authorization.");
  const before = assertStateObject(beforeObject, beforeStateBytes);
  if (canonicalJson(assertExactMixedRecoveryAttachmentTopology(beforeTopology)) !== canonicalJson(prepared.attachmentTopology)) throw new Error("Exact-complete state reconciliation attachment topology changed before refresh-only apply.");
  reauthenticateSource(); verifyLive();
  const complete = (status, snapshot, applyCount) => {
    const successor = assertExactCompleteStateSuccessor({ beforeBytes: beforeStateBytes, afterBytes: snapshot.bytes });
    if (successor.successorStateSha256 !== prepared.successorStateSha256 || snapshot.object?.versionId === before.versionId || snapshot.object?.etag === before.etag || canonicalJson(assertExactMixedRecoveryAttachmentTopology(readPostTopology())) !== canonicalJson(prepared.attachmentTopology)) throw new Error("Exact-complete state reconciliation post-state is not exact.");
    verifyLive(); const normalPlan = assertExactCompleteCleanNormalPlan(renderNormalPlan());
    return Object.freeze({ status, refreshOnlyApplyCount: applyCount, terraformStateMutationCount: applyCount, remoteIamMutationCount: 0, planSemantics: prepared.planSemantics, postState: { ...successor, versionId: snapshot.object.versionId, etag: snapshot.object.etag }, normalPlan });
  };
  const successorReplay = sha256(JSON.parse(beforeStateBytes.toString("utf8"))) === prepared.successorStateSha256 && before.lineage === prepared.predecessorState.lineage && before.serial === prepared.predecessorState.serial + 1 && before.versionId !== prepared.predecessorState.versionId && before.etag !== prepared.predecessorState.etag;
  if (successorReplay) {
    if (canonicalJson(assertExactMixedRecoveryAttachmentTopology(readPostTopology())) !== canonicalJson(prepared.attachmentTopology)) throw new Error("Exact-complete state reconciliation successor attachment topology changed.");
    verifyLive(); const normalPlan = assertExactCompleteCleanNormalPlan(renderNormalPlan());
    return Object.freeze({ status: "ALREADY_COMPLETE", refreshOnlyApplyCount: 0, terraformStateMutationCount: 0, remoteIamMutationCount: 0, planSemantics: prepared.planSemantics, postState: { ...before, successorStateSha256: prepared.successorStateSha256 }, normalPlan });
  }
  if (canonicalJson(before) !== canonicalJson(prepared.predecessorState)) throw new Error("Exact-complete state reconciliation live state changed before refresh-only apply.");
  try { applyRefreshOnlyPlan(planBytes); }
  catch (error) { try { return complete("COMPLETED_BY_READBACK", readPostSnapshot(), 1); } catch { error.mutationOutcome = "AMBIGUOUS"; throw error; } }
  return complete("COMPLETE", readPostSnapshot(), 1);
}

export function executeExactCompleteStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes, stateObject, attachmentTopology, renderNormalPlan, reauthenticateSource, verifyLive, now = new Date() } = {}) {
  if (![renderNormalPlan, reauthenticateSource, verifyLive].every((value) => typeof value === "function")) throw new Error("Exact-complete state reconciliation recovery adapters are required.");
  const prepared = assertExactCompleteStateReconciliationRecoveryPreparation(recoveryPreparation, { sourceSha, now }); assertExactCompleteStateReconciliationRecoveryAuthorization(recoveryAuthorization, prepared, { sourceSha, now });
  const successor = assertExactAuthorizedSuccessor({ stateBytes, stateObject, preparation: prepared });
  if (canonicalJson(successor) !== canonicalJson(prepared.successorStateObject) || canonicalJson(assertExactMixedRecoveryAttachmentTopology(attachmentTopology)) !== canonicalJson(prepared.attachmentTopology)) throw new Error("Exact-complete state reconciliation recovery live state changed.");
  reauthenticateSource(); verifyLive(); const normalPlan = assertExactCompleteCleanNormalPlan(renderNormalPlan());
  return Object.freeze({ status: "RECOVERED_COMPLETE", refreshOnlyApplyCount: 0, terraformStateMutationCount: 0, remoteIamMutationCount: 0, planSemantics: { resourceDrift: [], refreshOnly: false, terraformResourceAddCount: 0, terraformResourceChangeCount: 0, terraformResourceDestroyCount: 0 }, postState: { ...successor, successorStateSha256: prepared.successorStateSha256 }, normalPlan });
}
