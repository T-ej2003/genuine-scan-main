import crypto from "node:crypto";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import {
  PRODUCTION_ENVIRONMENT_APPROVAL,
  assertProductionEnvironmentActualReviewer,
  assertProductionEnvironmentApprovalFreshness,
  assertProductionEnvironmentApprovalIdentity,
} from "./production-github-environment-approval.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const TICKET = /^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/;
const iso = (value, label) => { const date = new Date(value); if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) throw new Error(`${label} is invalid.`); return date; };
const exactKeys = (value, fields, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...fields].sort())) throw new Error(`${label} schema is invalid.`); return value; };

export const STAGE_B_STATE_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_GREEN_STAGE_B_TEN_ADDRESS_REFRESH_ONLY_STATE_RECONCILIATION",
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  environment: "production",
  account: "368992683803",
  region: "eu-west-2",
  terraformRoot: "infra/aws/terraform/production-green-stage-b",
  expectedLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a",
  expectedSerial: 104,
  authorizationWorkflowPath: ".github/workflows/authorize-production-green-stage-b-state-reconciliation.yml",
  executionWorkflowPath: ".github/workflows/execute-production-green-stage-b-state-reconciliation.yml",
  authorizationArtifactName: "production-green-stage-b-state-reconciliation-authorization",
  authorizationFilename: "authorization.json",
  maxAgeMs: 30 * 60 * 1000,
  addresses: Object.freeze([
    'aws_iam_role.execution["backend"]',
    'aws_iam_role.execution["canary"]',
    'aws_iam_role.execution["executor"]',
    'aws_iam_role.task["backend"]',
    'aws_iam_role.task["canary"]',
    'aws_iam_role_policy.candidate_object_storage["backend"]',
    'aws_iam_role_policy.candidate_object_storage["canary"]',
    'aws_iam_role_policy.execution["backend"]',
    'aws_iam_role_policy.execution["canary"]',
    'aws_iam_role_policy.execution["executor"]',
  ]),
});

const addressSet = new Set(STAGE_B_STATE_RECONCILIATION.addresses);
const workflowRef = (path) => `${STAGE_B_STATE_RECONCILIATION.repository}/${path}@refs/heads/main`;
const equal = (left, right) => canonicalJson(left) === canonicalJson(right);

function assertStateIdentity(value) {
  exactKeys(value, ["lineage", "serial", "stateSha256"], "Stage B state identity");
  if (value.lineage !== STAGE_B_STATE_RECONCILIATION.expectedLineage || value.serial !== STAGE_B_STATE_RECONCILIATION.expectedSerial || !SHA256.test(value.stateSha256 || "")) throw new Error("Stage B state identity is outside the exact reviewed predecessor.");
  return value;
}

function changedTopLevelFields(change) {
  if (!change?.before || !change?.after || typeof change.before !== "object" || typeof change.after !== "object") throw new Error("Stage B refresh-only drift has malformed before/after state.");
  const keys = new Set([...Object.keys(change.before), ...Object.keys(change.after)]);
  return [...keys].filter((key) => !equal(change.before[key], change.after[key])).sort();
}

function assertNoSensitive(value) {
  if (value === undefined || value === false) return;
  if (value === true || value === null || typeof value !== "object") throw new Error("Refresh-only plan contains sensitive or malformed metadata.");
  if (Array.isArray(value)) return value.forEach(assertNoSensitive);
  Object.values(value).forEach(assertNoSensitive);
}

function assertExactDrift(entry) {
  const address = entry?.address;
  if (!addressSet.has(address) || entry?.mode !== "managed" || !["aws_iam_role", "aws_iam_role_policy"].includes(entry?.type) || !equal(entry?.change?.actions, ["update"]) || (entry?.change?.replace_paths || []).length) throw new Error("Refresh-only plan contains an unreviewed Stage B state observation.");
  const expectedField = entry.type === "aws_iam_role" ? "inline_policy" : "policy";
  if (!equal(changedTopLevelFields(entry.change), [expectedField])) throw new Error("Refresh-only plan changes an unreviewed state field.");
  if (Object.keys(entry.change.before_unknown || {}).length || Object.keys(entry.change.after_unknown || {}).length) throw new Error("Refresh-only plan contains unknown state metadata.");
  if (!equal(entry.change.before_sensitive || {}, entry.change.after_sensitive || {})) throw new Error("Refresh-only plan changes sensitive metadata.");
  assertNoSensitive(entry.change.before_sensitive); assertNoSensitive(entry.change.after_sensitive);
  const identity = entry.type === "aws_iam_role" ? ["arn", "name", "path", "permissions_boundary", "assume_role_policy"] : ["id", "name", "role"];
  for (const field of identity) if (!equal(entry.change.before[field], entry.change.after[field])) throw new Error("Refresh-only plan changes a managed resource identity.");
}

export function assertExactStageBRefreshOnlyPlan(plan, { sourceSha, stateIdentity, tfvarsSha256, bindingSha256 } = {}) {
  if (!SHA40.test(sourceSha || "") || !SHA256.test(tfvarsSha256 || "") || !SHA256.test(bindingSha256 || "")) throw new Error("Stage B state reconciliation plan bindings are malformed.");
  assertStateIdentity(stateIdentity);
  if (!plan || plan.format_version !== "1.2" || plan.terraform_version !== "1.15.8" || plan.errored !== false || plan.complete !== true || plan.applyable !== true || plan.variables?.tooling_sha?.value !== sourceSha) throw new Error("Stage B refresh-only plan envelope is invalid.");
  const normal = plan.resource_changes || [];
  if (!Array.isArray(normal) || normal.some((entry) => !equal(entry?.change?.actions, ["no-op"]) && !equal(entry?.change?.actions, ["read"]))) throw new Error("Stage B reconciliation rejects normal Terraform resource operations.");
  const drift = plan.resource_drift;
  if (!Array.isArray(drift) || drift.length !== STAGE_B_STATE_RECONCILIATION.addresses.length || new Set(drift.map((entry) => entry?.address)).size !== drift.length) throw new Error("Stage B refresh-only plan does not contain the exact ten-address drift envelope.");
  for (const entry of drift) assertExactDrift(entry);
  if (!equal([...new Set(drift.map((entry) => entry.address))].sort(), [...addressSet].sort())) throw new Error("Stage B refresh-only plan address set is not exact.");
  if (Object.values(plan.output_changes || {}).some((entry) => !equal(entry?.actions, ["no-op"]))) throw new Error("Stage B refresh-only plan changes an unreviewed output.");
  return Object.freeze({ refreshOnly: true, remoteResourceMutationCount: 0, stateRecordChangeCount: drift.length, addresses: [...STAGE_B_STATE_RECONCILIATION.addresses] });
}

export function assertCleanStageBNormalPlan(plan, { sourceSha } = {}) {
  if (!SHA40.test(sourceSha || "") || !plan || plan.errored !== false || plan.complete !== true || plan.applyable !== true || plan.variables?.tooling_sha?.value !== sourceSha || (plan.resource_drift || []).length !== 0 || Object.values(plan.output_changes || {}).some((entry) => !equal(entry?.actions, ["no-op"])) || (plan.resource_changes || []).some((entry) => !equal(entry?.change?.actions, ["no-op"]) && !equal(entry?.change?.actions, ["read"]))) throw new Error("Stage B state reconciliation normal closure is not clean.");
  return true;
}

export function createStageBStateReconciliationPreparation({ sourceSha, ticketId, stateIdentity, tfvarsSha256, bindingSha256, preflightSha256, planBytes, planJson, createdAt = new Date().toISOString() } = {}) {
  if (!TICKET.test(ticketId || "") || !SHA256.test(preflightSha256 || "") || !Buffer.isBuffer(planBytes) || !planBytes.length) throw new Error("Stage B state reconciliation preparation inputs are invalid.");
  const semantics = assertExactStageBRefreshOnlyPlan(planJson, { sourceSha, stateIdentity, tfvarsSha256, bindingSha256 });
  const created = iso(createdAt, "Stage B state reconciliation preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_PREPARATION", operation: STAGE_B_STATE_RECONCILIATION.operation, sourceSha, ticketId, terraformRoot: STAGE_B_STATE_RECONCILIATION.terraformRoot, predecessorState: stateIdentity, tfvarsSha256, bindingSha256, preflightSha256, addresses: semantics.addresses, refreshOnlyPlanSha256: sha256(planBytes), refreshOnlyPlanJsonSha256: sha256(planJson), planSemantics: semantics, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + STAGE_B_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}

export function assertStageBStateReconciliationPreparation(value, { sourceSha, now = new Date() } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "sourceSha", "ticketId", "terraformRoot", "predecessorState", "tfvarsSha256", "bindingSha256", "preflightSha256", "addresses", "refreshOnlyPlanSha256", "refreshOnlyPlanJsonSha256", "planSemantics", "createdAt", "expiresAt", "preparationSha256"];
  exactKeys(value, fields, "Stage B state reconciliation preparation");
  const { preparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_PREPARATION" || value.operation !== STAGE_B_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || !TICKET.test(value.ticketId || "") || value.terraformRoot !== STAGE_B_STATE_RECONCILIATION.terraformRoot || !SHA256.test(value.tfvarsSha256 || "") || !SHA256.test(value.bindingSha256 || "") || !SHA256.test(value.preflightSha256 || "") || !SHA256.test(value.refreshOnlyPlanSha256 || "") || !SHA256.test(value.refreshOnlyPlanJsonSha256 || "") || !equal(value.addresses, STAGE_B_STATE_RECONCILIATION.addresses) || !equal(value.planSemantics, { refreshOnly: true, remoteResourceMutationCount: 0, stateRecordChangeCount: 10, addresses: STAGE_B_STATE_RECONCILIATION.addresses }) || value.preparationSha256 !== sha256(body)) throw new Error("Stage B state reconciliation preparation binding is invalid.");
  assertStateIdentity(value.predecessorState); const created = iso(value.createdAt, "Stage B state reconciliation preparation creation"); const expires = iso(value.expiresAt, "Stage B state reconciliation preparation expiry"); if (expires.getTime() - created.getTime() !== STAGE_B_STATE_RECONCILIATION.maxAgeMs || now < created || now > expires) throw new Error("Stage B state reconciliation preparation is stale.");
  return value;
}

export function createStageBStateReconciliationAuthorization({ preparation, approval, now = new Date() } = {}) {
  const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: prepared.sourceSha, repository: STAGE_B_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(STAGE_B_STATE_RECONCILIATION.authorizationWorkflowPath)) throw new Error("Stage B state reconciliation requires its dedicated protected-environment workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: prepared.sourceSha, repository: STAGE_B_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_AUTHORIZATION", operation: prepared.operation, sourceSha: prepared.sourceSha, ticketId: prepared.ticketId, preparationSha256: prepared.preparationSha256, stateLineage: prepared.predecessorState.lineage, preOperationStateSerial: prepared.predecessorState.serial, addresses: prepared.addresses, refreshOnlyPlanSha256: prepared.refreshOnlyPlanSha256, tfvarsSha256: prepared.tfvarsSha256, bindingSha256: prepared.bindingSha256, preflightSha256: prepared.preflightSha256, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}

export function assertStageBStateReconciliationAuthorization(value, { preparation, sourceSha, now = new Date() } = {}) {
  const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha, now });
  const fields = ["schemaVersion", "kind", "operation", "sourceSha", "ticketId", "preparationSha256", "stateLineage", "preOperationStateSerial", "addresses", "refreshOnlyPlanSha256", "tfvarsSha256", "bindingSha256", "preflightSha256", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
  exactKeys(value, fields, "Stage B state reconciliation authorization"); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== sourceSha || value.ticketId !== prepared.ticketId || value.preparationSha256 !== prepared.preparationSha256 || value.stateLineage !== prepared.predecessorState.lineage || value.preOperationStateSerial !== prepared.predecessorState.serial || !equal(value.addresses, prepared.addresses) || value.refreshOnlyPlanSha256 !== prepared.refreshOnlyPlanSha256 || value.tfvarsSha256 !== prepared.tfvarsSha256 || value.bindingSha256 !== prepared.bindingSha256 || value.preflightSha256 !== prepared.preflightSha256 || value.authorizationSha256 !== sha256(body)) throw new Error("Stage B state reconciliation authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: STAGE_B_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(STAGE_B_STATE_RECONCILIATION.authorizationWorkflowPath) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("Stage B state reconciliation authorization approval provenance is invalid.");
  return value;
}

export function executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings, planBytes, planJson, readState, applyRefreshOnlyPlan, renderRefreshClosurePlan, renderNormalClosurePlan, now = new Date() } = {}) {
  if (![readState, applyRefreshOnlyPlan, renderRefreshClosurePlan, renderNormalClosurePlan].every((value) => typeof value === "function")) throw new Error("Stage B state reconciliation execution adapters are required.");
  const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha, now });
  assertStageBStateReconciliationAuthorization(authorization, { preparation: prepared, sourceSha, now });
  if (!bindings || bindings.tfvarsSha256 !== prepared.tfvarsSha256 || bindings.bindingSha256 !== prepared.bindingSha256 || bindings.preflightSha256 !== prepared.preflightSha256) throw new Error("Stage B state reconciliation execution inputs differ from the approved preparation.");
  if (!Buffer.isBuffer(planBytes) || sha256(planBytes) !== prepared.refreshOnlyPlanSha256 || sha256(planJson) !== prepared.refreshOnlyPlanJsonSha256 || !equal(assertExactStageBRefreshOnlyPlan(planJson, { sourceSha, stateIdentity: prepared.predecessorState, tfvarsSha256: bindings.tfvarsSha256, bindingSha256: bindings.bindingSha256 }), prepared.planSemantics)) throw new Error("Stage B state reconciliation saved plan changed after authorization.");
  const before = readState();
  if (!equal(before, prepared.predecessorState)) throw new Error("Stage B state reconciliation CAS failed.");
  applyRefreshOnlyPlan(planBytes);
  const after = readState();
  if (after.lineage !== before.lineage || after.serial !== before.serial + 1 || after.stateSha256 === before.stateSha256) throw new Error("Stage B state reconciliation successor is not exact.");
  assertCleanStageBNormalPlan(renderRefreshClosurePlan(), { sourceSha });
  assertCleanStageBNormalPlan(renderNormalClosurePlan(), { sourceSha });
  return Object.freeze({ schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_RESULT", status: "complete", sourceSha, authorizationSha256: authorization.authorizationSha256, predecessorState: before, successorState: after, remainingExpectedStateObservations: 0, sourceToLiveIamSemanticDifferences: 0, newUnexpectedDriftCount: 0, remoteResourceMutationCount: 0, terraformStateMutationCount: 1 });
}

export const stageBStateReconciliationSha256 = (value) => sha256(value);
