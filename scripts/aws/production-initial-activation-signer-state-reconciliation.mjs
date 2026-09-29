import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { INSTALLATION, assertInstallationPlan, assertInstallationPlanConfiguration, assertInstallationStateResources } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { assertRefreshOnlyResourceChangeActions, assertStateObject } from "./production-initial-activation-reconciler-state-reconciliation.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const sourceRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const policy = JSON.parse(fs.readFileSync(path.join(sourceRoot, INSTALLATION.terraformRoot, "signer-policy-installer-permissions-policy.json"), "utf8"));
const address = "aws_iam_role.signer_policy_installer";
const name = "ProductionSignerPolicyInstaller";
const roleName = "mscqr-production-signer-policy-installer";
const roleArn = `arn:aws:iam::368992683803:role/${roleName}`;
const exact = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...fields].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const iso = (value) => { const date = new Date(value); if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) throw new Error("Signer state reconciliation timestamp is invalid."); return date; };
const sha40 = (value) => /^[a-f0-9]{40}$/.test(value || "");
const sha64 = (value) => /^[a-f0-9]{64}$/.test(value || "");
const workflowRef = (file) => `${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/${file}@refs/heads/main`;
const noOutputChange = (change) => canonicalJson(change?.actions) === canonicalJson(["no-op"]) && canonicalJson(change.before) === canonicalJson(change.after) && change.after_unknown === false && change.before_sensitive === false && change.after_sensitive === false;

export const SIGNER_STATE_RECONCILIATION = Object.freeze({
  operation: "PRODUCTION_INITIAL_ACTIVATION_SIGNER_STATE_RECONCILIATION",
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  account: "368992683803",
  region: "eu-west-2",
  terraformRoot: INSTALLATION.terraformRoot,
  backend: INSTALLATION.backend,
  bootstrapRoleArn: INSTALLATION.executionRoleArn,
  environment: PRODUCTION_ENVIRONMENT_APPROVAL.installationBootstrapEnvironment,
  authorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-signer-state-reconciliation.yml",
  executionWorkflowPath: ".github/workflows/execute-production-initial-activation-signer-state-reconciliation.yml",
  recoveryAuthorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-signer-state-reconciliation-recovery.yml",
  recoveryExecutionWorkflowPath: ".github/workflows/execute-production-initial-activation-signer-state-reconciliation-recovery.yml",
  authorizationArtifactName: "production-initial-activation-signer-state-reconciliation-authorization",
  recoveryAuthorizationArtifactName: "production-initial-activation-signer-state-reconciliation-recovery-authorization",
  authorizationFilename: "authorization.json",
  recoveryAuthorizationFilename: "recovery-authorization.json",
  roleName, roleArn, address, policyName: name,
  maxAgeMs: 30 * 60 * 1000,
});

const stateResource = (state) => {
  const resources = state?.resources?.filter((resource) => resource?.mode === "managed" && !resource.module && resource.type === "aws_iam_role" && resource.name === "signer_policy_installer");
  if (resources?.length !== 1 || resources[0].instances?.length !== 1 || !resources[0].instances[0]?.attributes) throw new Error("Signer installer state address is not exact.");
  return resources[0].instances[0].attributes;
};
const state = (bytes) => {
  assertInstallationStateResources(bytes);
  const value = JSON.parse(bytes.toString("utf8"));
  const addresses = value.resources.map((resource) => `${resource.module ? `${resource.module}.` : ""}${resource.type}.${resource.name}`);
  if (addresses.length !== INSTALLATION.expectedAddresses.length || canonicalJson([...addresses].sort()) !== canonicalJson([...INSTALLATION.expectedAddresses].sort())) throw new Error("Signer state contains an unrelated Terraform resource.");
  return value;
};
const canonicalInline = (value) => {
  if (!Array.isArray(value) || value.length !== 1 || value[0]?.name !== name || canonicalJson(Object.keys(value[0]).sort()) !== canonicalJson(["name", "policy"]) || typeof value[0].policy !== "string") throw new Error("Signer installer inline policy is not exact.");
  let document; try { document = JSON.parse(value[0].policy); } catch { throw new Error("Signer installer inline policy is malformed."); }
  if (canonicalJson(document) !== canonicalJson(policy)) throw new Error("Signer installer inline policy differs from protected source.");
  return value;
};
const statePreimage = (bytes, object) => assertStateObject(object, bytes);
const successor = (bytes, inline) => {
  const result = structuredClone(state(bytes)); result.serial += 1;
  const role = stateResource(result);
  if (role.name !== roleName || role.arn !== roleArn || canonicalJson(role.inline_policy) !== canonicalJson([]) || role.tags !== null) throw new Error("Signer installer saved-state preimage is not exact.");
  role.inline_policy = canonicalInline(inline); role.tags = {};
  return result;
};

export function assertSignerRefreshOnlyPlan(plan, stateBytes) {
  if (!plan || plan.format_version !== "1.2" || plan.terraform_version !== INSTALLATION.terraformVersion || plan.errored !== false || plan.complete !== true || plan.applyable !== true) throw new Error("Signer refresh-only plan envelope is invalid.");
  assertInstallationPlanConfiguration(plan);
  if (!Buffer.isBuffer(stateBytes) || !Array.isArray(plan.resource_drift) || plan.resource_drift.length !== 1 || Object.values(plan.output_changes || {}).some((change) => !noOutputChange(change))) throw new Error("Signer refresh-only plan contains additional state or remote changes.");
  assertRefreshOnlyResourceChangeActions(plan, { allowRead: false });
  const seen = new Set();
  for (const entry of plan.resource_changes || []) {
    const change = entry?.change;
    if (entry?.address !== `${entry?.type}.${entry?.name}` || entry?.mode !== "managed" || entry?.provider_name !== "registry.terraform.io/hashicorp/aws" || !INSTALLATION.expectedAddresses.includes(entry.address) || seen.has(entry.address) || canonicalJson(change.before) !== canonicalJson(change.after) || canonicalJson(change.after_unknown) !== canonicalJson({}) || canonicalJson(change.before_sensitive) !== canonicalJson(change.after_sensitive)) throw new Error("Signer refresh-only no-op resource is not exact.");
    seen.add(entry.address);
  }
  const entry = plan.resource_drift[0];
  exact(entry, ["address", "change", "mode", "name", "provider_name", "type"], "Signer refresh-only drift");
  exact(entry.change, ["actions", "before", "after", "before_sensitive", "after_sensitive", "after_unknown"], "Signer refresh-only drift change");
  const { before, after } = entry.change;
  if (entry.address !== address || entry.mode !== "managed" || entry.type !== "aws_iam_role" || entry.name !== "signer_policy_installer" || entry.provider_name !== "registry.terraform.io/hashicorp/aws" || canonicalJson(entry.change.actions) !== canonicalJson(["update"]) || canonicalJson(entry.change.after_unknown) !== canonicalJson({}) || !before || !after || before.name !== roleName || before.arn !== roleArn || canonicalJson(before.inline_policy) !== canonicalJson([]) || before.tags !== null || canonicalJson(after.tags) !== canonicalJson({}) || canonicalJson({ ...before, inline_policy: after.inline_policy, tags: {} }) !== canonicalJson(after)) throw new Error("Signer refresh-only drift is not the exact captured reflection.");
  canonicalInline(after.inline_policy);
  const prior = stateResource(state(stateBytes));
  if (canonicalJson(prior) !== canonicalJson(before)) throw new Error("Signer refresh-only plan does not match the saved-state preimage.");
  if (canonicalJson(entry.change.before_sensitive) !== canonicalJson({ inline_policy: [], managed_policy_arns: [], tags_all: {} }) || canonicalJson(entry.change.after_sensitive) !== canonicalJson({ inline_policy: [{}], managed_policy_arns: [], tags: {}, tags_all: {} })) throw new Error("Signer refresh-only sensitivity metadata is not exact.");
  return Object.freeze({ address, beforeInlinePolicy: [], afterInlinePolicy: after.inline_policy, beforeTags: null, afterTags: {}, remoteMutationCount: 0 });
}

export function assertSignerPostRefreshNormalPlan(plan) {
  if (Object.values(plan?.output_changes || {}).some((change) => !noOutputChange(change))) throw new Error("Post-refresh normal plan contains an output change.");
  const value = assertInstallationPlan(plan, { livePredecessor: "EXACT_AUTHORIZER_POLICY_UPDATE" });
  if (value.resourceDriftCount !== 0 || value.createCount || value.updateCount !== 1 || value.deleteCount || value.replaceCount || canonicalJson(value.changedAddresses) !== canonicalJson(["aws_iam_policy.bootstrap_operator_policy_authorizer"])) throw new Error("Post-refresh normal plan is not the exact authorizer policy update.");
  return value;
}

const preparationFields = ["schemaVersion", "kind", "operation", "sourceSha", "account", "region", "terraformRoot", "backend", "bootstrapRoleArn", "roleArn", "predecessorState", "successorStateSha256", "savedPlanSha256", "savedPlanByteLength", "planSemantics", "createdAt", "expiresAt", "preparationSha256"];
export function createSignerStatePreparation({ sourceSha, stateBytes, stateObject, planBytes, planJson, preparedAt = new Date().toISOString() }) {
  if (!sha40(sourceSha) || !Buffer.isBuffer(planBytes) || !planBytes.length) throw new Error("Signer state preparation input is invalid.");
  const predecessorState = statePreimage(stateBytes, stateObject);
  const planSemantics = assertSignerRefreshOnlyPlan(planJson, stateBytes);
  const created = iso(preparedAt);
  const body = { schemaVersion: 1, kind: "SIGNER_INSTALLER_STATE_RECONCILIATION_PREPARATION", operation: SIGNER_STATE_RECONCILIATION.operation, sourceSha, account: SIGNER_STATE_RECONCILIATION.account, region: SIGNER_STATE_RECONCILIATION.region, terraformRoot: INSTALLATION.terraformRoot, backend: INSTALLATION.backend, bootstrapRoleArn: INSTALLATION.executionRoleArn, roleArn, predecessorState, successorStateSha256: sha256(successor(stateBytes, planSemantics.afterInlinePolicy)), savedPlanSha256: sha256(planBytes), savedPlanByteLength: planBytes.length, planSemantics, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + SIGNER_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}
export function assertSignerStatePreparation(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, preparationFields, "Signer state preparation"); const { preparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "SIGNER_INSTALLER_STATE_RECONCILIATION_PREPARATION" || value.operation !== SIGNER_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !sha40(sourceSha) || value.account !== SIGNER_STATE_RECONCILIATION.account || value.region !== SIGNER_STATE_RECONCILIATION.region || value.terraformRoot !== INSTALLATION.terraformRoot || canonicalJson(value.backend) !== canonicalJson(INSTALLATION.backend) || value.bootstrapRoleArn !== INSTALLATION.executionRoleArn || value.roleArn !== roleArn || !sha64(value.savedPlanSha256) || value.savedPlanByteLength < 1 || !sha64(value.successorStateSha256) || value.preparationSha256 !== sha256(body)) throw new Error("Signer state preparation binding is invalid.");
  exact(value.predecessorState, ["stateExists", "lineage", "serial", "stateSha256", "versionId", "etag"], "Signer state preimage");
  if (!value.predecessorState.stateExists || !value.predecessorState.lineage || !Number.isSafeInteger(value.predecessorState.serial) || !sha64(value.predecessorState.stateSha256) || !value.predecessorState.versionId || !value.predecessorState.etag) throw new Error("Signer state preimage binding is invalid.");
  exact(value.planSemantics, ["address", "beforeInlinePolicy", "afterInlinePolicy", "beforeTags", "afterTags", "remoteMutationCount"], "Signer state plan semantics");
  if (value.planSemantics.address !== address || canonicalJson(value.planSemantics.beforeInlinePolicy) !== canonicalJson([]) || value.planSemantics.beforeTags !== null || canonicalJson(value.planSemantics.afterTags) !== canonicalJson({}) || value.planSemantics.remoteMutationCount !== 0) throw new Error("Signer state plan semantics are invalid.");
  canonicalInline(value.planSemantics.afterInlinePolicy);
  const created = iso(value.createdAt); const expires = iso(value.expiresAt);
  if (expires.getTime() - created.getTime() !== SIGNER_STATE_RECONCILIATION.maxAgeMs || !allowExpired && (now < created || now > expires)) throw new Error("Signer state preparation is stale.");
  return value;
}

const authorizationFields = ["schemaVersion", "kind", "operation", "sourceSha", "preparationSha256", "savedPlanSha256", "predecessorState", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
export function createSignerStateAuthorization({ preparation, approval, now = new Date() }) {
  const prepared = assertSignerStatePreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: prepared.sourceSha, repository: SIGNER_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(SIGNER_STATE_RECONCILIATION.authorizationWorkflowPath)) throw new Error("Signer state reconciliation requires its dedicated workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: prepared.sourceSha, repository: SIGNER_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "SIGNER_INSTALLER_STATE_RECONCILIATION_AUTHORIZATION", operation: prepared.operation, sourceSha: prepared.sourceSha, preparationSha256: prepared.preparationSha256, savedPlanSha256: prepared.savedPlanSha256, predecessorState: prepared.predecessorState, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}
export function assertSignerStateAuthorization(value, preparation, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exact(value, authorizationFields, "Signer state authorization"); const prepared = assertSignerStatePreparation(preparation, { sourceSha, now, allowExpired }); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "SIGNER_INSTALLER_STATE_RECONCILIATION_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== prepared.sourceSha || value.preparationSha256 !== prepared.preparationSha256 || value.savedPlanSha256 !== prepared.savedPlanSha256 || canonicalJson(value.predecessorState) !== canonicalJson(prepared.predecessorState) || authorizationSha256 !== sha256(body) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256) throw new Error("Signer state authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: SIGNER_STATE_RECONCILIATION.repository }); if (!allowExpired) assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(SIGNER_STATE_RECONCILIATION.authorizationWorkflowPath) || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("Signer state approval provenance is invalid.");
  return value;
}

const exactSuccessor = (bytes, object, preparation) => {
  const actual = statePreimage(bytes, object);
  if (actual.lineage !== preparation.predecessorState.lineage || actual.serial !== preparation.predecessorState.serial + 1 || sha256(state(bytes)) !== preparation.successorStateSha256 || actual.versionId === preparation.predecessorState.versionId || actual.etag === preparation.predecessorState.etag) throw new Error("Signer state is not the exact authorized successor.");
  return actual;
};
export function executeSignerStateReconciliation({ sourceSha, preparation, authorization, planBytes, planJson, beforeStateBytes, beforeObject, applySavedPlan, readPostSnapshot, renderNormalPlan, reauthenticateSource, verifyLive, now = new Date() }) {
  if (![applySavedPlan, readPostSnapshot, renderNormalPlan, reauthenticateSource, verifyLive].every((fn) => typeof fn === "function")) throw new Error("Signer state execution adapters are missing.");
  assertSignerStateAuthorization(authorization, preparation, { sourceSha, now });
  if (!Buffer.isBuffer(planBytes) || sha256(planBytes) !== preparation.savedPlanSha256 || planBytes.length !== preparation.savedPlanByteLength) throw new Error("Signer refresh-only saved plan changed after authorization.");
  const current = statePreimage(beforeStateBytes, beforeObject);
  const replay = canonicalJson(current) !== canonicalJson(preparation.predecessorState);
  if (replay) {
    const post = exactSuccessor(beforeStateBytes, beforeObject, preparation);
    reauthenticateSource(); verifyLive(); const normalPlan = assertSignerPostRefreshNormalPlan(renderNormalPlan());
    return Object.freeze({ status: "ALREADY_COMPLETE", stateWriteCount: 0, remoteMutationCount: 0, postState: post, normalPlan });
  }
  const semantics = assertSignerRefreshOnlyPlan(planJson, beforeStateBytes);
  if (canonicalJson(semantics) !== canonicalJson(preparation.planSemantics)) throw new Error("Signer refresh-only plan changed after authorization.");
  reauthenticateSource(); verifyLive();
  let error;
  try { applySavedPlan(planBytes); } catch (caught) { error = caught; }
  try {
    const snapshot = readPostSnapshot(); const post = exactSuccessor(snapshot.bytes, snapshot.object, preparation);
    verifyLive(); const normalPlan = assertSignerPostRefreshNormalPlan(renderNormalPlan());
    return Object.freeze({ status: error ? "COMPLETED_BY_READBACK" : "COMPLETE", stateWriteCount: 1, remoteMutationCount: 0, postState: post, normalPlan });
  } catch (verificationError) {
    if (!error) { verificationError.mutationOutcome = "AMBIGUOUS"; throw verificationError; }
    error.mutationOutcome = "AMBIGUOUS"; throw error;
  }
}

export function createSignerStateRecoveryPreparation({ sourceSha, originalPreparation, originalAuthorization, originalRunId, originalRunAttempt, stateBytes, stateObject, preparedAt = new Date().toISOString() }) {
  const original = assertSignerStatePreparation(originalPreparation, { sourceSha: originalPreparation?.sourceSha, allowExpired: true });
  const authorization = assertSignerStateAuthorization(originalAuthorization, original, { sourceSha: original.sourceSha, allowExpired: true });
  if (!sha40(sourceSha) || authorization.protectedEnvironmentApprovalEvidence.workflowRunId !== String(originalRunId) || authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt !== String(originalRunAttempt)) throw new Error("Signer state recovery original authorization is invalid.");
  const successorState = exactSuccessor(stateBytes, stateObject, original); const created = iso(preparedAt);
  const body = { schemaVersion: 1, kind: "SIGNER_INSTALLER_STATE_RECONCILIATION_RECOVERY_PREPARATION", operation: SIGNER_STATE_RECONCILIATION.operation, sourceSha, originalSourceSha: original.sourceSha, originalPreparationSha256: original.preparationSha256, originalAuthorizationSha256: authorization.authorizationSha256, originalRunId: String(originalRunId), originalRunAttempt: String(originalRunAttempt), predecessorState: original.predecessorState, successorStateSha256: original.successorStateSha256, successorState, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + SIGNER_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, recoveryPreparationSha256: sha256(body) });
}
export function assertSignerStateRecoveryPreparation(value, { sourceSha, now = new Date() } = {}) {
  exact(value, ["schemaVersion", "kind", "operation", "sourceSha", "originalSourceSha", "originalPreparationSha256", "originalAuthorizationSha256", "originalRunId", "originalRunAttempt", "predecessorState", "successorStateSha256", "successorState", "createdAt", "expiresAt", "recoveryPreparationSha256"], "Signer state recovery preparation");
  const { recoveryPreparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "SIGNER_INSTALLER_STATE_RECONCILIATION_RECOVERY_PREPARATION" || value.operation !== SIGNER_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !sha40(sourceSha) || !sha40(value.originalSourceSha) || !sha64(value.originalPreparationSha256) || !sha64(value.originalAuthorizationSha256) || !/^[1-9][0-9]*$/.test(value.originalRunId) || !/^[1-9][0-9]*$/.test(value.originalRunAttempt) || !sha64(value.successorStateSha256) || value.recoveryPreparationSha256 !== sha256(body) || value.successorState?.lineage !== value.predecessorState?.lineage || value.successorState?.serial !== value.predecessorState?.serial + 1 || value.successorState?.versionId === value.predecessorState?.versionId || value.successorState?.etag === value.predecessorState?.etag || value.successorState?.stateSha256 !== value.successorStateSha256) throw new Error("Signer state recovery binding is invalid.");
  const created = iso(value.createdAt); const expires = iso(value.expiresAt);
  if (expires.getTime() - created.getTime() !== SIGNER_STATE_RECONCILIATION.maxAgeMs || now < created || now > expires) throw new Error("Signer state recovery preparation is stale.");
  return value;
}
export function createSignerStateRecoveryAuthorization({ recoveryPreparation, approval, now = new Date() }) {
  const prepared = assertSignerStateRecoveryPreparation(recoveryPreparation, { sourceSha: recoveryPreparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: prepared.sourceSha, repository: SIGNER_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(SIGNER_STATE_RECONCILIATION.recoveryAuthorizationWorkflowPath)) throw new Error("Signer state recovery requires its dedicated workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: prepared.sourceSha, repository: SIGNER_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "SIGNER_INSTALLER_STATE_RECONCILIATION_RECOVERY_AUTHORIZATION", operation: prepared.operation, sourceSha: prepared.sourceSha, recoveryPreparationSha256: prepared.recoveryPreparationSha256, originalAuthorizationSha256: prepared.originalAuthorizationSha256, successorStateSha256: prepared.successorStateSha256, maxAwsMutations: {}, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, recoveryAuthorizationSha256: sha256(body) });
}
export function assertSignerStateRecoveryAuthorization(value, preparation, { sourceSha, now = new Date() } = {}) {
  exact(value, ["schemaVersion", "kind", "operation", "sourceSha", "recoveryPreparationSha256", "originalAuthorizationSha256", "successorStateSha256", "maxAwsMutations", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "recoveryAuthorizationSha256"], "Signer state recovery authorization");
  const prepared = assertSignerStateRecoveryPreparation(preparation, { sourceSha, now }); const { recoveryAuthorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "SIGNER_INSTALLER_STATE_RECONCILIATION_RECOVERY_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== prepared.sourceSha || value.recoveryPreparationSha256 !== prepared.recoveryPreparationSha256 || value.originalAuthorizationSha256 !== prepared.originalAuthorizationSha256 || value.successorStateSha256 !== prepared.successorStateSha256 || canonicalJson(value.maxAwsMutations) !== canonicalJson({}) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence?.evidenceSha256 || value.recoveryAuthorizationSha256 !== sha256(body)) throw new Error("Signer state recovery authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: SIGNER_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(SIGNER_STATE_RECONCILIATION.recoveryAuthorizationWorkflowPath) || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("Signer state recovery approval provenance is invalid.");
  return value;
}
export function executeSignerStateRecovery({ sourceSha, recoveryPreparation, recoveryAuthorization, stateBytes, stateObject, renderNormalPlan, reauthenticateSource, verifyLive, now = new Date() }) {
  assertSignerStateRecoveryAuthorization(recoveryAuthorization, recoveryPreparation, { sourceSha, now });
  const current = statePreimage(stateBytes, stateObject);
  if (canonicalJson(current) !== canonicalJson(recoveryPreparation.successorState) || current.stateSha256 !== recoveryPreparation.successorState.stateSha256 || sha256(state(stateBytes)) !== recoveryPreparation.successorStateSha256) throw new Error("Signer state recovery successor changed.");
  reauthenticateSource(); verifyLive(); const normalPlan = assertSignerPostRefreshNormalPlan(renderNormalPlan());
  return Object.freeze({ status: "RECOVERED_COMPLETE", stateWriteCount: 0, remoteMutationCount: 0, postState: current, normalPlan });
}
