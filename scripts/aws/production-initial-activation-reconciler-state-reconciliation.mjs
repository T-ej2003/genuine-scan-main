import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { INSTALLATION, assertInstallationPlan, assertInstallationStateResources, stateIdentity } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const sourceRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const permissionsPolicyOutput = Object.freeze({ name: "permissions_policy_sha256", after: crypto.createHash("sha256").update(fs.readFileSync(path.join(sourceRoot, `${INSTALLATION.terraformRoot}/permissions-policy.json`))).digest("hex") });
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
  recoveryAuthorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-reconciler-state-reconciliation-recovery.yml",
  recoveryExecutionWorkflowPath: ".github/workflows/execute-production-initial-activation-reconciler-state-reconciliation-recovery.yml",
  recoveryAuthorizationArtifactName: "production-initial-activation-reconciler-state-reconciliation-recovery-authorization",
  recoveryAuthorizationFilename: "recovery-authorization.json",
  maxAgeMs: 30 * 60 * 1000,
  drift: Object.freeze([
    Object.freeze({ address: "aws_iam_policy.reconciler", field: "attachment_count", before: 0, after: 1 }),
    Object.freeze({ address: "aws_iam_role.reconciler", field: "managed_policy_arns", before: Object.freeze([]), after: Object.freeze([INSTALLATION.policyArn]) }),
  ]),
  outputReconciliation: permissionsPolicyOutput,
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
const exactSuccessorState = (beforeBytes, semantics) => {
  const before = normalizedState(beforeBytes); const expected = structuredClone(before.state);
  expected.serial += 1;
  stateResource(expected, "aws_iam_policy.reconciler").instances[0].attributes.attachment_count = 1;
  stateResource(expected, "aws_iam_role.reconciler").instances[0].attributes.managed_policy_arns = [RECONCILER_STATE_RECONCILIATION.policyArn];
  expected.outputs[semantics.outputReconciliation.name].value = semantics.outputReconciliation.after;
  return expected;
};
const exactDrift = (entry, expected) => {
  if (entry?.address !== expected.address || canonicalJson(entry?.change?.actions) !== canonicalJson(["update"])) throw new Error("Refresh-only plan contains an unreviewed resource drift address or action.");
  const before = entry.change.before; const after = entry.change.after;
  if (!before || !after || before[expected.field] === undefined || after[expected.field] === undefined || canonicalJson(before[expected.field]) !== canonicalJson(expected.before) || canonicalJson(after[expected.field]) !== canonicalJson(expected.after)) throw new Error("Refresh-only plan drift value is not exact.");
  const restBefore = { ...before }; const restAfter = { ...after }; delete restBefore[expected.field]; delete restAfter[expected.field];
  if (canonicalJson(restBefore) !== canonicalJson(restAfter) || Object.keys(entry.change.before_unknown || {}).length || Object.keys(entry.change.after_unknown || {}).length || entry.change.replace_paths?.length) throw new Error("Refresh-only plan drift changes fields outside the exact allowance.");
  const beforeSensitivity = entry.change.before_sensitive === undefined ? {} : entry.change.before_sensitive;
  const afterSensitivity = entry.change.after_sensitive === undefined ? {} : entry.change.after_sensitive;
  if (expected.address === "aws_iam_role.reconciler" && expected.field === "managed_policy_arns") {
    const split = (mask, value) => {
      if (!mask || typeof mask !== "object" || Array.isArray(mask) || !Object.hasOwn(mask, expected.field)) throw new Error("Refresh-only plan managed-policy sensitivity metadata is malformed.");
      const rest = { ...mask }; const fieldMask = rest[expected.field]; delete rest[expected.field]; assertFalseOnlySensitivityMask(value, fieldMask); return rest;
    };
    assertExactSensitivityStructure(split(beforeSensitivity, before[expected.field]), split(afterSensitivity, after[expected.field]));
  } else assertExactSensitivityStructure(beforeSensitivity, afterSensitivity);
};

const assertFalseOnlySensitivityMask = (value, mask) => {
  if (Array.isArray(value)) {
    if (!Array.isArray(mask) || mask.length !== value.length) throw new Error("Refresh-only plan sensitivity metadata is structurally incompatible.");
    return value.forEach((item, index) => assertFalseOnlySensitivityMask(item, mask[index]));
  }
  if (value && typeof value === "object") {
    if (!mask || typeof mask !== "object" || Array.isArray(mask) || Object.keys(mask).some((key) => !Object.hasOwn(value, key))) throw new Error("Refresh-only plan sensitivity metadata is structurally incompatible.");
    return Object.entries(mask).forEach(([key, child]) => assertFalseOnlySensitivityMask(value[key], child));
  }
  if (mask !== false) throw new Error("Refresh-only plan contains a sensitive or malformed value.");
};
const assertSensitivityTree = (value) => {
  if (value === false) return;
  if (value === true) throw new Error("Refresh-only plan contains a sensitive value.");
  if (Array.isArray(value)) return value.forEach(assertSensitivityTree);
  if (value && typeof value === "object") return Object.values(value).forEach(assertSensitivityTree);
  throw new Error("Refresh-only plan sensitivity metadata is malformed.");
};

export function assertExactSensitivityStructure(before, after) {
  if (canonicalJson(before) !== canonicalJson(after)) throw new Error("Refresh-only plan sensitivity metadata changed.");
  assertSensitivityTree(before);
  return before;
}

const outputTransitionFields = ["name", "actions", "before", "after", "sensitive", "unknown"];
const assertExactOutputReconciliation = (plan, stateBytes, expectedBefore) => {
  const changes = Object.entries(plan.output_changes || {});
  const nonNoop = changes.filter(([, change]) => canonicalJson(change?.actions) !== canonicalJson(["no-op"]));
  if (nonNoop.length !== 1) throw new Error("Refresh-only plan output reconciliation is not exact.");
  const [name, change] = nonNoop[0]; const beforeOutput = normalizedState(stateBytes).state.outputs?.[name]?.value;
  if (name !== RECONCILER_STATE_RECONCILIATION.outputReconciliation.name || canonicalJson(change?.actions) !== canonicalJson(["update"]) || typeof change?.before !== "string" || change.before !== (expectedBefore ?? beforeOutput) || change.after !== RECONCILER_STATE_RECONCILIATION.outputReconciliation.after || change.before_sensitive !== false || change.after_sensitive !== false || (Object.hasOwn(change, "before_unknown") && change.before_unknown !== false) || change.after_unknown !== false) throw new Error("Refresh-only plan output reconciliation is not exact.");
  return Object.freeze({ name, actions: ["update"], before: change.before, after: change.after, sensitive: false, unknown: false });
};
const assertPlanSemantics = (value) => {
  exact(value, ["resourceDrift", "refreshOnly", "terraformResourceAddCount", "terraformResourceChangeCount", "terraformResourceDestroyCount", "exactTwoFieldDrift", "outputDrift", "outputReconciliation"], "State reconciliation plan semantics");
  exact(value.outputReconciliation, outputTransitionFields, "State reconciliation output reconciliation");
  if (canonicalJson(value.resourceDrift) !== canonicalJson(RECONCILER_STATE_RECONCILIATION.drift) || value.refreshOnly !== true || value.terraformResourceAddCount !== 0 || value.terraformResourceChangeCount !== 0 || value.terraformResourceDestroyCount !== 0 || value.exactTwoFieldDrift !== true || value.outputDrift !== true || value.outputReconciliation.name !== RECONCILER_STATE_RECONCILIATION.outputReconciliation.name || canonicalJson(value.outputReconciliation.actions) !== canonicalJson(["update"]) || !SHA256.test(value.outputReconciliation.before || "") || value.outputReconciliation.after !== RECONCILER_STATE_RECONCILIATION.outputReconciliation.after || value.outputReconciliation.sensitive !== false || value.outputReconciliation.unknown !== false) throw new Error("State reconciliation plan semantics are invalid.");
  return value;
};

export function assertExactReconcilerRefreshOnlyPlan(plan, { stateBytes, expectedOutputBefore } = {}) {
  if (!plan || plan.format_version !== "1.2" || plan.terraform_version !== INSTALLATION.terraformVersion || plan.errored !== false || plan.complete !== true || plan.applyable !== true || !Array.isArray(plan.resource_drift)) throw new Error("Refresh-only plan envelope is invalid.");
  if (plan.resource_changes !== undefined && (!Array.isArray(plan.resource_changes) || plan.resource_changes.some(({ change }) => ![["no-op"], ["read"]].some((actions) => canonicalJson(change?.actions) === canonicalJson(actions))))) throw new Error("Refresh-only plan contains an actionable resource operation.");
  if (!Buffer.isBuffer(stateBytes)) throw new Error("Refresh-only plan requires the authenticated predecessor state.");
  if (plan.resource_drift.length !== RECONCILER_STATE_RECONCILIATION.drift.length) throw new Error("Refresh-only plan drift count is not exact.");
  const byAddress = new Map(plan.resource_drift.map((entry) => [entry?.address, entry]));
  if (byAddress.size !== RECONCILER_STATE_RECONCILIATION.drift.length) throw new Error("Refresh-only plan drift addresses are duplicated.");
  for (const expected of RECONCILER_STATE_RECONCILIATION.drift) exactDrift(byAddress.get(expected.address), expected);
  return Object.freeze(assertPlanSemantics({ resourceDrift: RECONCILER_STATE_RECONCILIATION.drift, refreshOnly: true, terraformResourceAddCount: 0, terraformResourceChangeCount: 0, terraformResourceDestroyCount: 0, exactTwoFieldDrift: true, outputDrift: true, outputReconciliation: assertExactOutputReconciliation(plan, stateBytes, expectedOutputBefore) }));
}

export function assertCanonicalAttachmentTopology(value) {
  exact(value, ["roles", "users", "groups"], "Reconciler attachment topology");
  if (canonicalJson([...value.roles].sort()) !== canonicalJson([RECONCILER_STATE_RECONCILIATION.roleName]) || !Array.isArray(value.users) || value.users.length || !Array.isArray(value.groups) || value.groups.length) throw new Error("Reconciler attachment topology is not canonical.");
  return Object.freeze({ roles: [RECONCILER_STATE_RECONCILIATION.roleName], users: [], groups: [] });
}

export function assertStateObject(value, state) {
  assertStateObjectIdentity(value);
  const checked = normalizedState(state);
  return Object.freeze({ ...checked.identity, versionId: value.versionId, etag: value.etag });
}

const assertStateObjectIdentity = (value) => {
  exact(value, ["versionId", "etag"], "Terraform backend object identity");
  if (typeof value.versionId !== "string" || !value.versionId || typeof value.etag !== "string" || !value.etag) throw new Error("Terraform backend VersionId or ETag is missing.");
  return value;
};
const assertBoundStateIdentity = (value, label) => {
  exact(value, ["stateExists", "lineage", "serial", "stateSha256", "versionId", "etag"], label);
  if (value.stateExists !== true || typeof value.lineage !== "string" || !value.lineage || !Number.isSafeInteger(value.serial) || value.serial < 0 || !SHA256.test(value.stateSha256 || "")) throw new Error(`${label} is invalid.`);
  if (typeof value.versionId !== "string" || !value.versionId || typeof value.etag !== "string" || !value.etag) throw new Error(`${label} object identity is invalid.`);
  return value;
};

const preparationFields = ["schemaVersion", "kind", "operation", "sourceSha", "account", "terraformRoot", "backend", "policyArn", "bootstrapRoleArn", "predecessorState", "successorStateSha256", "attachmentTopology", "attachmentTopologySha256", "drift", "driftSha256", "savedPlanSha256", "savedPlanByteLength", "planSemantics", "createdAt", "expiresAt", "preparationSha256"];
export function createReconcilerStateReconciliationPreparation({ sourceSha, stateBytes, stateObject, attachmentTopology, planBytes, planJson, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "")) throw new Error("State reconciliation source SHA is invalid.");
  const predecessorState = assertStateObject(stateObject, stateBytes);
  const topology = assertCanonicalAttachmentTopology(attachmentTopology);
  const semantics = assertExactReconcilerRefreshOnlyPlan(planJson, { stateBytes });
  if (!Buffer.isBuffer(planBytes) || !planBytes.length) throw new Error("Refresh-only saved plan is required.");
  const created = iso(preparedAt, "State reconciliation preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_PREPARATION", operation: RECONCILER_STATE_RECONCILIATION.operation, sourceSha, account: RECONCILER_STATE_RECONCILIATION.account, terraformRoot: RECONCILER_STATE_RECONCILIATION.terraformRoot, backend: RECONCILER_STATE_RECONCILIATION.backend, policyArn: RECONCILER_STATE_RECONCILIATION.policyArn, bootstrapRoleArn: RECONCILER_STATE_RECONCILIATION.bootstrapRoleArn, predecessorState, successorStateSha256: sha256(exactSuccessorState(stateBytes, semantics)), attachmentTopology: topology, attachmentTopologySha256: sha256(topology), drift: RECONCILER_STATE_RECONCILIATION.drift, driftSha256: sha256(RECONCILER_STATE_RECONCILIATION.drift), savedPlanSha256: sha256(planBytes), savedPlanByteLength: planBytes.length, planSemantics: semantics, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + RECONCILER_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}
export function assertReconcilerStateReconciliationPreparation(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, preparationFields, "State reconciliation preparation");
  const { preparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_PREPARATION" || value.operation !== RECONCILER_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || value.account !== RECONCILER_STATE_RECONCILIATION.account || value.terraformRoot !== RECONCILER_STATE_RECONCILIATION.terraformRoot || canonicalJson(value.backend) !== canonicalJson(RECONCILER_STATE_RECONCILIATION.backend) || value.policyArn !== RECONCILER_STATE_RECONCILIATION.policyArn || value.bootstrapRoleArn !== RECONCILER_STATE_RECONCILIATION.bootstrapRoleArn || !value.predecessorState?.stateExists || !SHA256.test(value.predecessorState.stateSha256 || "") || !SHA256.test(value.successorStateSha256 || "") || !Number.isSafeInteger(value.predecessorState.serial) || typeof value.predecessorState.lineage !== "string" || !value.predecessorState.versionId || !value.predecessorState.etag || canonicalJson(value.drift) !== canonicalJson(RECONCILER_STATE_RECONCILIATION.drift) || value.driftSha256 !== sha256(value.drift) || value.attachmentTopologySha256 !== sha256(assertCanonicalAttachmentTopology(value.attachmentTopology)) || !SHA256.test(value.savedPlanSha256 || "") || !Number.isSafeInteger(value.savedPlanByteLength) || value.savedPlanByteLength < 1 || value.preparationSha256 !== sha256(body)) throw new Error("State reconciliation preparation binding is invalid.");
  assertPlanSemantics(value.planSemantics);
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

const recoveryPreparationFields = ["schemaVersion", "kind", "operation", "sourceSha", "originalSourceSha", "originalPreparationSha256", "originalAuthorizationSha256", "originalAuthorizationWorkflowRunId", "originalAuthorizationWorkflowRunAttempt", "predecessorState", "successorStateSha256", "successorStateObject", "savedPlanSha256", "planSemantics", "driftSha256", "attachmentTopology", "createdAt", "expiresAt", "recoveryPreparationSha256"];
const recoveryAuthorizationFields = ["schemaVersion", "kind", "operation", "sourceSha", "recoveryPreparationSha256", "originalPreparationSha256", "originalAuthorizationSha256", "successorStateSha256", "successorStateObject", "maxAwsMutations", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "recoveryAuthorizationSha256"];
const recoveryCompatibility = (preparation) => preparation?.operation === RECONCILER_STATE_RECONCILIATION.operation && preparation?.account === RECONCILER_STATE_RECONCILIATION.account && preparation?.terraformRoot === RECONCILER_STATE_RECONCILIATION.terraformRoot && canonicalJson(preparation?.backend) === canonicalJson(RECONCILER_STATE_RECONCILIATION.backend) && preparation?.policyArn === RECONCILER_STATE_RECONCILIATION.policyArn && preparation?.bootstrapRoleArn === RECONCILER_STATE_RECONCILIATION.bootstrapRoleArn && canonicalJson(preparation?.drift) === canonicalJson(RECONCILER_STATE_RECONCILIATION.drift);

export function createReconcilerStateReconciliationRecoveryPreparation({ sourceSha, originalPreparation, originalAuthorization, originalAuthorizationWorkflowRunId, originalAuthorizationWorkflowRunAttempt, stateBytes, stateObject, attachmentTopology, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "") || !/^[1-9][0-9]*$/.test(String(originalAuthorizationWorkflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(originalAuthorizationWorkflowRunAttempt || ""))) throw new Error("State reconciliation recovery coordinates are invalid.");
  const original = assertReconcilerStateReconciliationPreparation(originalPreparation, { sourceSha: originalPreparation?.sourceSha, allowExpired: true });
  if (!recoveryCompatibility(original)) throw new Error("State reconciliation recovery source contract is incompatible.");
  const authorization = assertReconcilerStateReconciliationAuthorization(originalAuthorization, original, { sourceSha: original.sourceSha, allowExpired: true });
  if (authorization.authorizationSha256 !== originalAuthorization.authorizationSha256 || authorization.preparationSha256 !== original.preparationSha256 || authorization.savedPlanSha256 !== original.savedPlanSha256 || authorization.protectedEnvironmentApprovalEvidence.workflowRunId !== String(originalAuthorizationWorkflowRunId) || authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt !== String(originalAuthorizationWorkflowRunAttempt)) throw new Error("State reconciliation original authorization is invalid.");
  const successor = assertAuthorizedExactStateSuccessor({ stateBytes, stateObject, preparation: original });
  const topology = assertCanonicalAttachmentTopology(attachmentTopology);
  const created = iso(preparedAt, "State reconciliation recovery preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_RECOVERY_PREPARATION", operation: RECONCILER_STATE_RECONCILIATION.operation, sourceSha, originalSourceSha: original.sourceSha, originalPreparationSha256: original.preparationSha256, originalAuthorizationSha256: authorization.authorizationSha256, originalAuthorizationWorkflowRunId: String(originalAuthorizationWorkflowRunId), originalAuthorizationWorkflowRunAttempt: String(originalAuthorizationWorkflowRunAttempt), predecessorState: original.predecessorState, successorStateSha256: successor.successorStateSha256, successorStateObject: assertStateObject(stateObject, stateBytes), savedPlanSha256: original.savedPlanSha256, planSemantics: original.planSemantics, driftSha256: original.driftSha256, attachmentTopology: topology, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + RECONCILER_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, recoveryPreparationSha256: sha256(body) });
}

export function assertReconcilerStateReconciliationRecoveryPreparation(value, { sourceSha, now = new Date() } = {}) {
  exact(value, recoveryPreparationFields, "State reconciliation recovery preparation"); const { recoveryPreparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_RECOVERY_PREPARATION" || value.operation !== RECONCILER_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(value.sourceSha || "") || !SHA40.test(value.originalSourceSha || "") || !SHA256.test(value.originalPreparationSha256 || "") || !SHA256.test(value.originalAuthorizationSha256 || "") || !/^[1-9][0-9]*$/.test(value.originalAuthorizationWorkflowRunId || "") || !/^[1-9][0-9]*$/.test(value.originalAuthorizationWorkflowRunAttempt || "") || !SHA256.test(value.successorStateSha256 || "") || !SHA256.test(value.savedPlanSha256 || "") || !SHA256.test(value.driftSha256 || "") || canonicalJson(assertCanonicalAttachmentTopology(value.attachmentTopology)) !== canonicalJson(value.attachmentTopology) || value.recoveryPreparationSha256 !== sha256(body)) throw new Error("State reconciliation recovery preparation binding is invalid.");
  assertPlanSemantics(value.planSemantics);
  assertBoundStateIdentity(value.predecessorState, "State reconciliation recovery predecessor state");
  assertBoundStateIdentity(value.successorStateObject, "State reconciliation recovery successor state");
  if (value.successorStateObject.lineage !== value.predecessorState.lineage || value.successorStateObject.serial !== value.predecessorState.serial + 1 || value.successorStateObject.versionId === value.predecessorState.versionId || value.successorStateObject.etag === value.predecessorState.etag) throw new Error("State reconciliation recovery successor identity is invalid.");
  const created = iso(value.createdAt, "State reconciliation recovery preparation creation timestamp"); const expires = iso(value.expiresAt, "State reconciliation recovery preparation expiry timestamp");
  if (expires.getTime() - created.getTime() !== RECONCILER_STATE_RECONCILIATION.maxAgeMs || now < created || now > expires) throw new Error("State reconciliation recovery preparation is stale.");
  return value;
}

export function createReconcilerStateReconciliationRecoveryAuthorization({ recoveryPreparation, approval, now = new Date() } = {}) {
  const prepared = assertReconcilerStateReconciliationRecoveryPreparation(recoveryPreparation, { sourceSha: recoveryPreparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: prepared.sourceSha, repository: RECONCILER_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(RECONCILER_STATE_RECONCILIATION.recoveryAuthorizationWorkflowPath)) throw new Error("State reconciliation recovery requires its dedicated workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: prepared.sourceSha, repository: RECONCILER_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_RECOVERY_AUTHORIZATION", operation: prepared.operation, sourceSha: prepared.sourceSha, recoveryPreparationSha256: prepared.recoveryPreparationSha256, originalPreparationSha256: prepared.originalPreparationSha256, originalAuthorizationSha256: prepared.originalAuthorizationSha256, successorStateSha256: prepared.successorStateSha256, successorStateObject: prepared.successorStateObject, maxAwsMutations: {}, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, recoveryAuthorizationSha256: sha256(body) });
}

export function assertReconcilerStateReconciliationRecoveryAuthorization(value, recoveryPreparation, { sourceSha, now = new Date() } = {}) {
  exact(value, recoveryAuthorizationFields, "State reconciliation recovery authorization"); const prepared = assertReconcilerStateReconciliationRecoveryPreparation(recoveryPreparation, { sourceSha, now }); const { recoveryAuthorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_RECONCILER_STATE_RECONCILIATION_RECOVERY_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== prepared.sourceSha || value.recoveryPreparationSha256 !== prepared.recoveryPreparationSha256 || value.originalPreparationSha256 !== prepared.originalPreparationSha256 || value.originalAuthorizationSha256 !== prepared.originalAuthorizationSha256 || value.successorStateSha256 !== prepared.successorStateSha256 || canonicalJson(value.successorStateObject) !== canonicalJson(prepared.successorStateObject) || canonicalJson(value.maxAwsMutations) !== canonicalJson({}) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256 || value.recoveryAuthorizationSha256 !== sha256(body)) throw new Error("State reconciliation recovery authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: RECONCILER_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(RECONCILER_STATE_RECONCILIATION.recoveryAuthorizationWorkflowPath) || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("State reconciliation recovery approval provenance is invalid.");
  return value;
}

export function assertExactStateSuccessor({ beforeBytes, afterBytes, planSemantics }) {
  const before = normalizedState(beforeBytes); const after = normalizedState(afterBytes);
  if (after.identity.lineage !== before.identity.lineage || after.identity.serial !== before.identity.serial + 1 || after.identity.stateSha256 === before.identity.stateSha256) throw new Error("State reconciliation successor identity is invalid.");
  if (canonicalJson(after.state) !== canonicalJson(exactSuccessorState(beforeBytes, assertPlanSemantics(planSemantics)))) throw new Error("State reconciliation successor changes fields outside the exact allowance.");
  const policy = stateResource(after.state, "aws_iam_policy.reconciler").instances[0].attributes;
  const role = stateResource(after.state, "aws_iam_role.reconciler").instances[0].attributes;
  if (policy.attachment_count !== 1 || canonicalJson(role.managed_policy_arns) !== canonicalJson([RECONCILER_STATE_RECONCILIATION.policyArn])) throw new Error("State reconciliation successor fields are not exact.");
  return { ...after.identity, successorStateSha256: sha256(after.state) };
}

const assertReplaySuccessor = ({ stateBytes, stateObject, preparation }) => {
  const { identity, state } = normalizedState(stateBytes);
  if (identity.lineage !== preparation.predecessorState.lineage || identity.serial !== preparation.predecessorState.serial + 1 || sha256(state) !== preparation.successorStateSha256 || stateObject?.versionId === preparation.predecessorState.versionId || stateObject?.etag === preparation.predecessorState.etag) throw new Error("State reconciliation state is not the exact authorized successor.");
  assertInstallationStateResources(stateBytes); return { ...identity, successorStateSha256: sha256(state) };
};
const assertAuthorizedExactStateSuccessor = ({ beforeBytes, stateBytes, stateObject, preparation }) => {
  const successor = beforeBytes ? assertExactStateSuccessor({ beforeBytes, afterBytes: stateBytes, planSemantics: preparation.planSemantics }) : assertReplaySuccessor({ stateBytes, stateObject, preparation });
  if (successor.successorStateSha256 !== preparation.successorStateSha256) throw new Error("State reconciliation state is not the exact authorized successor.");
  return successor;
};
const assertExactPostRefreshNormalPlan = (plan) => {
  const normal = assertInstallationPlan(plan);
  if (normal.updateCount !== 1 || normal.changedAddresses[0] !== "aws_iam_policy.reconciler" || normal.createCount || normal.deleteCount || normal.replaceCount) throw new Error("Post-refresh normal installation plan is not the exact policy update.");
  return normal;
};
const resultFields = ["status", "refreshOnlyApplyCount", "terraformStateMutationCount", "remoteIamMutationCount", "planSemantics", "postState", "normalPlan"];
const normalPlanFields = ["plannedResourceCount", "resourceChangeCount", "actionableResourceChangeCount", "createCount", "noOpCount", "updateCount", "deleteCount", "replaceCount", "changedAddresses", "noOpAddresses", "resourceChanges"];
const assertResultNormalPlan = (value) => {
  exact(value, normalPlanFields, "State reconciliation normal plan");
  const resourceAddresses = Array.isArray(value.resourceChanges) ? value.resourceChanges.map((change) => change?.address) : [];
  if (value.plannedResourceCount !== INSTALLATION.expectedAddresses.length || value.resourceChangeCount !== 1 || value.actionableResourceChangeCount !== 1 || value.createCount !== 0 || value.noOpCount !== INSTALLATION.expectedAddresses.length - 1 || value.updateCount !== 1 || value.deleteCount !== 0 || value.replaceCount !== 0 || canonicalJson(value.changedAddresses) !== canonicalJson(["aws_iam_policy.reconciler"]) || canonicalJson(value.noOpAddresses) !== canonicalJson(INSTALLATION.expectedAddresses.filter((address) => address !== "aws_iam_policy.reconciler").sort()) || resourceAddresses.length !== INSTALLATION.expectedAddresses.length || new Set(resourceAddresses).size !== resourceAddresses.length || canonicalJson([...resourceAddresses].sort()) !== canonicalJson([...INSTALLATION.expectedAddresses].sort()) || value.resourceChanges.some((change) => canonicalJson(change.actions) !== canonicalJson(change.address === "aws_iam_policy.reconciler" ? ["update"] : ["no-op"]))) throw new Error("State reconciliation normal plan semantics are not exact.");
  return value;
};
const resultPostStateFields = ["stateExists", "lineage", "serial", "stateSha256", "successorStateSha256", "versionId", "etag"];
const assertResultPostState = (value) => {
  exact(value, resultPostStateFields, "State reconciliation post-state");
  if (value.stateExists !== true || typeof value.lineage !== "string" || !value.lineage || !Number.isSafeInteger(value.serial) || value.serial < 0 || !SHA256.test(value.stateSha256 || "") || !SHA256.test(value.successorStateSha256 || "") || typeof value.versionId !== "string" || !value.versionId || typeof value.etag !== "string" || !value.etag) throw new Error("State reconciliation post-state is invalid.");
  return value;
};
export function assertReconcilerStateReconciliationResult(value, { preparation } = {}) {
  exact(value, resultFields, "State reconciliation result");
  if (!preparation?.predecessorState || !SHA256.test(preparation.successorStateSha256 || "")) throw new Error("State reconciliation result requires its authenticated preparation.");
  if (!["COMPLETE", "ALREADY_COMPLETE", "COMPLETED_BY_READBACK", "RECOVERED_COMPLETE"].includes(value.status) || !Number.isSafeInteger(value.refreshOnlyApplyCount) || value.refreshOnlyApplyCount < 0 || !Number.isSafeInteger(value.terraformStateMutationCount) || value.terraformStateMutationCount < 0 || value.remoteIamMutationCount !== 0 || canonicalJson(value.planSemantics) !== canonicalJson(preparation.planSemantics) || canonicalJson(assertResultPostState(value.postState)) !== canonicalJson(value.postState) || value.postState.lineage !== preparation.predecessorState.lineage || value.postState.serial !== preparation.predecessorState.serial + 1 || value.postState.successorStateSha256 !== preparation.successorStateSha256 || canonicalJson(assertResultNormalPlan(value.normalPlan)) !== canonicalJson(value.normalPlan)) throw new Error("State reconciliation successful result is not exact.");
  const applied = value.status === "COMPLETE" || value.status === "COMPLETED_BY_READBACK";
  if (value.refreshOnlyApplyCount !== (applied ? 1 : 0) || value.terraformStateMutationCount !== (applied ? 1 : 0)) throw new Error("State reconciliation result mutation counts are inconsistent.");
  return value;
}
const assertPostStateObject = (value, predecessor) => {
  if (!value?.versionId || !value?.etag || value.versionId === predecessor.versionId) throw new Error("State reconciliation post-state object identity is invalid.");
  return value;
};

export function executeReconcilerStateReconciliation({ sourceSha, preparation, authorization, planBytes, planJson, beforeStateBytes, beforeObject, beforeTopology, applySavedPlan, readPostSnapshot, readPostTopology, renderNormalPlan, reauthenticateSource, verifyPostconditions, now = new Date() } = {}) {
  if (![applySavedPlan, readPostSnapshot, readPostTopology, renderNormalPlan, reauthenticateSource, verifyPostconditions].every((value) => typeof value === "function")) throw new Error("State reconciliation execution adapters are required.");
  assertReconcilerStateReconciliationAuthorization(authorization, preparation, { sourceSha, now });
  if (sha256(planBytes) !== preparation.savedPlanSha256 || !Number.isSafeInteger(planBytes?.length) || planBytes.length !== preparation.savedPlanByteLength) throw new Error("State reconciliation saved plan changed after authorization.");
  const planSemantics = assertExactReconcilerRefreshOnlyPlan(planJson, { stateBytes: beforeStateBytes, expectedOutputBefore: preparation.planSemantics.outputReconciliation.before });
  if (canonicalJson(planSemantics) !== canonicalJson(preparation.planSemantics)) throw new Error("State reconciliation plan semantics changed after authorization.");
  const complete = (result) => Object.freeze(assertReconcilerStateReconciliationResult({ ...result, planSemantics }, { preparation }));
  const currentObject = assertStateObject(beforeObject, beforeStateBytes);
  if (canonicalJson(assertCanonicalAttachmentTopology(beforeTopology)) !== canonicalJson(preparation.attachmentTopology)) throw new Error("State reconciliation live IAM changed before apply.");
  if (canonicalJson(currentObject) !== canonicalJson(preparation.predecessorState)) {
    const replay = assertAuthorizedExactStateSuccessor({ stateBytes: beforeStateBytes, stateObject: beforeObject, preparation });
    verifyPostconditions();
    const normal = assertExactPostRefreshNormalPlan(renderNormalPlan());
    return complete({ status: "ALREADY_COMPLETE", refreshOnlyApplyCount: 0, terraformStateMutationCount: 0, remoteIamMutationCount: 0, postState: { ...replay, versionId: beforeObject.versionId, etag: beforeObject.etag }, normalPlan: normal });
  }
  reauthenticateSource();
  try { applySavedPlan(planBytes); }
  catch (error) {
    const { bytes: after, object } = readPostSnapshot(); const topology = readPostTopology();
    try {
      const successor = assertAuthorizedExactStateSuccessor({ beforeBytes: beforeStateBytes, stateBytes: after, object, stateObject: object, preparation });
      assertCanonicalAttachmentTopology(topology);
      assertPostStateObject(object, currentObject);
      verifyPostconditions();
      const normalPlan = assertExactPostRefreshNormalPlan(renderNormalPlan());
      return complete({ status: "COMPLETED_BY_READBACK", refreshOnlyApplyCount: 1, terraformStateMutationCount: 1, remoteIamMutationCount: 0, postState: { ...successor, versionId: object.versionId, etag: object.etag }, normalPlan });
    } catch { error.mutationOutcome = "AMBIGUOUS"; throw error; }
  }
  const { bytes: after, object } = readPostSnapshot(); const topology = readPostTopology();
  const successor = assertAuthorizedExactStateSuccessor({ beforeBytes: beforeStateBytes, stateBytes: after, stateObject: object, preparation });
  assertCanonicalAttachmentTopology(topology);
  assertPostStateObject(object, currentObject);
  verifyPostconditions();
  const normal = assertExactPostRefreshNormalPlan(renderNormalPlan());
  return complete({ status: "COMPLETE", refreshOnlyApplyCount: 1, terraformStateMutationCount: 1, remoteIamMutationCount: 0, postState: { ...successor, versionId: object.versionId, etag: object.etag }, normalPlan: normal });
}

export function executeReconcilerStateReconciliationRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes, stateObject, attachmentTopology, renderNormalPlan, reauthenticateSource, verifyPostconditions, now = new Date() } = {}) {
  if (![renderNormalPlan, reauthenticateSource, verifyPostconditions].every((value) => typeof value === "function")) throw new Error("State reconciliation recovery adapters are required.");
  const prepared = assertReconcilerStateReconciliationRecoveryPreparation(recoveryPreparation, { sourceSha, now }); assertReconcilerStateReconciliationRecoveryAuthorization(recoveryAuthorization, prepared, { sourceSha, now });
  const complete = (result) => Object.freeze(assertReconcilerStateReconciliationResult({ ...result, planSemantics: prepared.planSemantics }, { preparation: prepared }));
  if (canonicalJson(assertStateObject(stateObject, stateBytes)) !== canonicalJson(prepared.successorStateObject) || canonicalJson(assertCanonicalAttachmentTopology(attachmentTopology)) !== canonicalJson(prepared.attachmentTopology)) throw new Error("State reconciliation recovery live state changed.");
  const successor = assertReplaySuccessor({ stateBytes, stateObject, preparation: { predecessorState: prepared.predecessorState, successorStateSha256: prepared.successorStateSha256 } });
  reauthenticateSource(); verifyPostconditions(); const normal = assertExactPostRefreshNormalPlan(renderNormalPlan());
  return complete({ status: "RECOVERED_COMPLETE", refreshOnlyApplyCount: 0, terraformStateMutationCount: 0, remoteIamMutationCount: 0, postState: { ...successor, versionId: stateObject.versionId, etag: stateObject.etag }, normalPlan: normal });
}
