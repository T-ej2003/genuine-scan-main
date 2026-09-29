import crypto from "node:crypto";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { classifyStageBPlan } from "./stage-b-deployment-contract.mjs";
import { stageBBoundImagesFromBindingReport } from "./generate-production-green-stage-b-tfvars.mjs";
import { assertStageBPlanSemanticCompleteness } from "./stage-b-plan-semantic-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "./stage-b-reference-audit-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import {
  PRODUCTION_ENVIRONMENT_APPROVAL,
  assertProductionEnvironmentActualReviewer,
  assertProductionEnvironmentApprovalFreshness,
  assertProductionEnvironmentApprovalIdentity,
} from "./production-github-environment-approval.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-(backend|worker)@sha256:[a-f0-9]{64}$/;
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
  prerequisiteBundleWorkflowPath: ".github/workflows/produce-production-green-stage-b-prerequisite-bundle.yml",
  prerequisiteBundleArtifactName: "production-green-stage-b-state-reconciliation-prerequisites",
  maxAgeMs: 30 * 60 * 1000,
  predecessorBoundImages: Object.freeze({
    backend: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:4613df0a5e1d61e63914a7f1bfd612abfa1a92b5bea9ebf1a1e66ebcef4e2409",
    canary: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:8b160f065747bed4b547fda7b140e06a249f74686cc5350988b87469ad62bea6",
    executor: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:2e5dee8dafc8746acdc8e1942fca334f909a037bf9a209d44453144e3df96fa2",
    read_only_canary: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:8b160f065747bed4b547fda7b140e06a249f74686cc5350988b87469ad62bea6",
    worker: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:44d6913a1aadc38a5ba4e41094ec3ae4a95397dc3ab40ab083b77360e1df3ffe",
  }),
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
const reflectionActionAddresses = new Set(STAGE_B_STATE_RECONCILIATION.addresses.filter((address) => address.startsWith("aws_iam_role_policy.")));
const pendingConvergenceAddresses = Object.freeze([...Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES), "aws_iam_policy.broker", "aws_lambda_alias.reviewed", "aws_lambda_function.broker"].sort());
const pendingConvergenceAddressSet = new Set(pendingConvergenceAddresses);
const workflowRef = (path) => `${STAGE_B_STATE_RECONCILIATION.repository}/${path}@refs/heads/main`;
const equal = (left, right) => canonicalJson(left) === canonicalJson(right);
const canonicalPolicy = (value, label) => {
  const document = structuredClone(normalizeIamPolicyDocument(value, label));
  if (!Array.isArray(document.Statement)) throw new Error(`${label} has no statement array.`);
  document.Statement = document.Statement.map((statement) => {
    const normalized = { ...statement };
    for (const field of ["Action", "NotAction", "Resource", "NotResource"]) if (field in normalized) normalized[field] = (Array.isArray(normalized[field]) ? normalized[field] : [normalized[field]]).sort();
    return normalized;
  }).sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return document;
};

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
  const expectedType = address?.startsWith("aws_iam_role_policy") ? "aws_iam_role_policy" : "aws_iam_role";
  if (!addressSet.has(address) || entry?.mode !== "managed" || entry?.type !== expectedType || !equal(entry?.change?.actions, ["update"]) || (entry?.change?.replace_paths || []).length) throw new Error("Refresh-only plan contains an unreviewed Stage B state observation.");
  const expectedField = entry.type === "aws_iam_role" ? "inline_policy" : "policy";
  if (!equal(changedTopLevelFields(entry.change), [expectedField])) throw new Error("Refresh-only plan changes an unreviewed state field.");
  if (Object.keys(entry.change.before_unknown || {}).length || Object.keys(entry.change.after_unknown || {}).length) throw new Error("Refresh-only plan contains unknown state metadata.");
  if (!equal(entry.change.before_sensitive || {}, entry.change.after_sensitive || {})) throw new Error("Refresh-only plan changes sensitive metadata.");
  assertNoSensitive(entry.change.before_sensitive); assertNoSensitive(entry.change.after_sensitive);
  const identity = entry.type === "aws_iam_role" ? ["arn", "name", "path", "permissions_boundary", "assume_role_policy"] : ["id", "name", "role"];
  for (const field of identity) if (!equal(entry.change.before[field], entry.change.after[field])) throw new Error("Refresh-only plan changes a managed resource identity.");
}

const policyValueHashes = (plan) => Object.fromEntries((plan.resource_drift || []).map((entry) => {
  const field = entry.type === "aws_iam_role" ? "inline_policy" : "policy";
  return [entry.address, { field, beforeSha256: sha256(entry.change.before[field]), afterSha256: sha256(entry.change.after[field]) }];
}));

function assertPolicyValueHashes(plan, expected) {
  if (!expected || !equal(policyValueHashes(plan), expected)) throw new Error("Stage B refresh-only plan policy values differ from the reviewed source alignment.");
}

function assertBoundImagesTransition(plan, bindingReport) {
  const actionable = Object.entries(plan?.output_changes || {}).filter(([, entry]) => !equal(entry?.actions, ["no-op"]));
  if (actionable.length !== 1 || actionable[0][0] !== "bound_images") throw new Error("Stage B refresh-only plan output transition is not the exact bound_images reconciliation.");
  const change = actionable[0][1];
  const after = stageBBoundImagesFromBindingReport(bindingReport);
  if (Object.values(after).some((value) => !IMAGE.test(value || ""))) throw new Error("Stage B bound_images successor contains a mutable or unreviewed image reference.");
  if (!equal(change?.actions, ["update"]) || !equal(change?.before, STAGE_B_STATE_RECONCILIATION.predecessorBoundImages) || !equal(change?.after, after)
    || !equal(change?.after_unknown, false) || ![undefined, false].includes(change?.before_unknown) || !equal(change?.before_sensitive, false) || !equal(change?.after_sensitive, false)) throw new Error("Stage B bound_images transition differs from the authenticated serial-104 state and tfvars binding.");
  return Object.freeze({ name: "bound_images", actions: ["update"], before: change.before, after: change.after, beforeUnknown: false, afterUnknown: false, beforeSensitive: false, afterSensitive: false, transitionSha256: sha256(change) });
}

function assertReviewedReflectionChanges(normalPlan, refreshPlan, postWrite) {
  const byAddress = new Map((normalPlan.resource_changes || []).map((entry) => [entry.address, entry]));
  if (byAddress.size !== (normalPlan.resource_changes || []).length) throw new Error("Stage B normal plan contains duplicate resource addresses.");
  const driftByAddress = new Map(refreshPlan.resource_drift.map((entry) => [entry.address, entry]));
  for (const address of STAGE_B_STATE_RECONCILIATION.addresses) {
    const normal = byAddress.get(address); const drift = driftByAddress.get(address);
    if (!normal || normal.type !== drift.type || normal.mode !== drift.mode) throw new Error("Stage B normal plan omits a reviewed state-reflection address.");
    if (postWrite) {
      if (!equal(normal.change?.actions, ["no-op"])) throw new Error("Stage B post-reconciliation normal plan retains a reviewed state-reflection action.");
      continue;
    }
    const expectedActions = reflectionActionAddresses.has(address) ? ["update"] : ["no-op"];
    if (!equal(normal.change?.actions, expectedActions)) throw new Error("Stage B normal plan state-reflection action is outside the serial-104 topology.");
    if (reflectionActionAddresses.has(address)) {
      const field = drift.type === "aws_iam_role_policy" ? "policy" : "inline_policy";
      if (!equal(canonicalPolicy(normal.change?.before?.[field], `${address} normal predecessor`), canonicalPolicy(drift.change.before[field], `${address} refresh predecessor`)) || !equal(canonicalPolicy(normal.change?.after?.[field], `${address} normal successor`), canonicalPolicy(drift.change.after[field], `${address} refresh successor`))) throw new Error("Stage B normal plan state-reflection values differ from the refresh-only plan.");
    }
  }
}

function actionableEntries(entries = []) { return entries.filter((entry) => !equal(entry?.change?.actions, ["no-op"]) && !equal(entry?.change?.actions, ["read"])); }

function assertPendingOutputTopology(normalPlan, refreshPlan, postWrite) {
  const actionable = Object.entries(normalPlan.output_changes || {}).filter(([, entry]) => !equal(entry?.actions, ["no-op"]));
  const allowed = postWrite ? ["task_definition_arns"] : ["bound_images", "task_definition_arns"];
  if (!equal(actionable.map(([name]) => name).sort(), allowed)) throw new Error("Stage B pending convergence output topology is not exact.");
  if (!postWrite && !equal(normalPlan.output_changes.bound_images, refreshPlan.output_changes.bound_images)) throw new Error("Stage B normal plan bound_images transition differs from the refresh-only plan.");
  const taskDefinitions = normalPlan.output_changes.task_definition_arns;
  if (!equal(taskDefinitions?.actions, ["update"]) || taskDefinitions?.after !== undefined || taskDefinitions?.after_unknown !== true || ![undefined, false].includes(taskDefinitions?.before_unknown) || taskDefinitions?.before_sensitive !== false || taskDefinitions?.after_sensitive !== false || !taskDefinitions?.before || typeof taskDefinitions.before !== "object" || Array.isArray(taskDefinitions.before)) throw new Error("Stage B task_definition_arns output is outside the exact replacement-derived topology.");
  return Object.freeze({ name: "task_definition_arns", changeSha256: sha256(taskDefinitions) });
}

function assertPendingStageBConvergence(normalPlan, refreshPlan, { sourceSha, terraformConfiguration, postWrite = false, expectedSemantics } = {}) {
  if (typeof terraformConfiguration !== "string" || !normalPlan || normalPlan.format_version !== "1.2" || normalPlan.terraform_version !== "1.15.8" || normalPlan.errored !== false || normalPlan.complete !== true || normalPlan.applyable !== true || normalPlan.variables?.tooling_sha?.value !== sourceSha) throw new Error("Stage B pending ordinary-plan source alignment envelope is invalid.");
  if ((normalPlan.resource_drift || []).length !== 0) throw new Error("Stage B pending ordinary plan has unexpected resource drift.");
  assertReviewedReflectionChanges(normalPlan, refreshPlan, postWrite);
  const output = assertPendingOutputTopology(normalPlan, refreshPlan, postWrite);
  const filtered = { ...normalPlan, resource_changes: (normalPlan.resource_changes || []).filter((entry) => !addressSet.has(entry.address)) };
  const classification = classifyStageBPlan(filtered, { strict: true, terraformConfiguration });
  assertStageBPlanSemanticCompleteness(filtered, { terraformConfiguration });
  const changes = actionableEntries(filtered.resource_changes);
  if (classification.planProfile !== "ECS_TASK_DEFINITION_ROTATION" || !equal(changes.map(({ address }) => address).sort(), pendingConvergenceAddresses)
    || classification.taskDefinitionRotations.length !== Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).length
    || classification.actionCounts.replacement !== Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).length || classification.actionCounts.update !== 3 || classification.unclassifiedResources.length) throw new Error("Stage B pending ordinary convergence topology is not exact.");
  for (const entry of changes) if (!pendingConvergenceAddressSet.has(entry.address)) throw new Error("Stage B pending ordinary convergence contains an unrelated mutation.");
  const body = { planProfile: classification.planProfile, addresses: pendingConvergenceAddresses, actionCounts: { replacement: classification.actionCounts.replacement, update: classification.actionCounts.update }, resourceChanges: changes.map((entry) => ({ address: entry.address, type: entry.type, actions: entry.change.actions, changeSha256: sha256(entry.change) })).sort((left, right) => left.address.localeCompare(right.address)), output };
  const semantics = Object.freeze({ ...body, semanticsSha256: sha256(body) });
  if (expectedSemantics && !equal(semantics, expectedSemantics)) throw new Error("Stage B pending ordinary convergence changed after preparation.");
  return semantics;
}

export function assertExactStageBRefreshOnlyPlan(plan, { sourceSha, stateIdentity, tfvarsSha256, bindingSha256, bindingReport, expectedPolicyValueHashes } = {}) {
  if (!SHA40.test(sourceSha || "") || !SHA256.test(tfvarsSha256 || "") || !SHA256.test(bindingSha256 || "")) throw new Error("Stage B state reconciliation plan bindings are malformed.");
  assertStateIdentity(stateIdentity);
  if (!plan || plan.format_version !== "1.2" || plan.terraform_version !== "1.15.8" || plan.errored !== false || plan.complete !== true || plan.applyable !== true || plan.variables?.tooling_sha?.value !== sourceSha) throw new Error("Stage B refresh-only plan envelope is invalid.");
  const normal = plan.resource_changes || [];
  if (!Array.isArray(normal) || normal.length) throw new Error("Stage B reconciliation rejects every Terraform resource_changes entry.");
  const drift = plan.resource_drift;
  if (!Array.isArray(drift) || drift.length !== STAGE_B_STATE_RECONCILIATION.addresses.length || new Set(drift.map((entry) => entry?.address)).size !== drift.length) throw new Error("Stage B refresh-only plan does not contain the exact ten-address drift envelope.");
  for (const entry of drift) assertExactDrift(entry);
  if (!equal([...new Set(drift.map((entry) => entry.address))].sort(), [...addressSet].sort())) throw new Error("Stage B refresh-only plan address set is not exact.");
  const boundImagesTransition = assertBoundImagesTransition(plan, bindingReport);
  if (expectedPolicyValueHashes) assertPolicyValueHashes(plan, expectedPolicyValueHashes);
  return Object.freeze({ refreshOnly: true, remoteResourceMutationCount: 0, stateRecordChangeCount: drift.length + 1, resourceStateChangeCount: drift.length, outputStateChangeCount: 1, addresses: [...STAGE_B_STATE_RECONCILIATION.addresses], boundImagesTransitionSha256: boundImagesTransition.transitionSha256 });
}

export function assertStageBStateReconciliationSourceAlignment(refreshPlan, normalPlan, options = {}) {
  assertExactStageBRefreshOnlyPlan(refreshPlan, options);
  return Object.freeze({ reviewedPolicyValueHashes: policyValueHashes(refreshPlan), pendingConvergenceSemantics: assertPendingStageBConvergence(normalPlan, refreshPlan, options) });
}

export function assertCleanStageBRefreshClosurePlan(plan, { sourceSha } = {}) {
  if (!SHA40.test(sourceSha || "") || !plan || plan.format_version !== "1.2" || plan.terraform_version !== "1.15.8" || plan.errored !== false || plan.complete !== true || plan.applyable !== false || plan.variables?.tooling_sha?.value !== sourceSha || (plan.resource_drift || []).length !== 0 || Object.values(plan.output_changes || {}).some((entry) => !equal(entry?.actions, ["no-op"])) || actionableEntries(plan.resource_changes).length) throw new Error("Stage B refresh-only closure is not clean.");
  return true;
}

export function createStageBStateReconciliationPreparation({ sourceSha, ticketId, stateIdentity, tfvarsSha256, bindingSha256, bindingReport, terraformConfiguration, preflightSha256, runtimeTfvarsSha256, runtimeBindingSha256, runtimeMaterializationSha256, relocationContractSha256, prerequisiteManifestSha256, brokerPackageSha256, brokerManifestSha256, stageAInputSha256, stageAStateBackupSha256, prerequisiteProducerWorkflowRunId, prerequisiteProducerWorkflowRunAttempt, prerequisiteBundleArtifactId, prerequisiteBundleArtifactDigest, planBytes, planJson, normalPlan, createdAt = new Date().toISOString() } = {}) {
  if (!TICKET.test(ticketId || "") || ![preflightSha256, runtimeTfvarsSha256, runtimeBindingSha256, runtimeMaterializationSha256, relocationContractSha256, prerequisiteManifestSha256, brokerPackageSha256, brokerManifestSha256, stageAInputSha256, stageAStateBackupSha256].every((value) => SHA256.test(value || "")) || !/^\d+$/.test(String(prerequisiteProducerWorkflowRunId)) || String(prerequisiteProducerWorkflowRunAttempt) !== "1" || !/^\d+$/.test(String(prerequisiteBundleArtifactId)) || !/^sha256:[a-f0-9]{64}$/.test(prerequisiteBundleArtifactDigest || "") || !Buffer.isBuffer(planBytes) || !planBytes.length) throw new Error("Stage B state reconciliation preparation inputs are invalid.");
  const options = { sourceSha, stateIdentity, tfvarsSha256: runtimeTfvarsSha256, bindingSha256: runtimeBindingSha256, bindingReport, terraformConfiguration };
  const semantics = assertExactStageBRefreshOnlyPlan(planJson, options);
  const { reviewedPolicyValueHashes, pendingConvergenceSemantics } = assertStageBStateReconciliationSourceAlignment(planJson, normalPlan, options);
  const boundImagesTransition = assertBoundImagesTransition(planJson, bindingReport);
  const created = iso(createdAt, "Stage B state reconciliation preparation timestamp");
  const body = { schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_PREPARATION", operation: STAGE_B_STATE_RECONCILIATION.operation, sourceSha, ticketId, terraformRoot: STAGE_B_STATE_RECONCILIATION.terraformRoot, predecessorState: stateIdentity, tfvarsSha256, bindingSha256, preflightSha256, runtimeTfvarsSha256, runtimeBindingSha256, runtimeMaterializationSha256, relocationContractSha256, prerequisiteManifestSha256, brokerPackageSha256, brokerManifestSha256, stageAInputSha256, stageAStateBackupSha256, prerequisiteProducerWorkflowRunId: String(prerequisiteProducerWorkflowRunId), prerequisiteProducerWorkflowRunAttempt: String(prerequisiteProducerWorkflowRunAttempt), prerequisiteBundleArtifactId: String(prerequisiteBundleArtifactId), prerequisiteBundleArtifactDigest, addresses: semantics.addresses, refreshOnlyPlanSha256: sha256(planBytes), refreshOnlyPlanJsonSha256: sha256(planJson), boundImagesTransition, reviewedPolicyValueHashes, pendingConvergenceSemantics, planSemantics: semantics, createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + STAGE_B_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}

export function assertStageBStateReconciliationPreparation(value, { sourceSha, now = new Date() } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "sourceSha", "ticketId", "terraformRoot", "predecessorState", "tfvarsSha256", "bindingSha256", "preflightSha256", "runtimeTfvarsSha256", "runtimeBindingSha256", "runtimeMaterializationSha256", "relocationContractSha256", "prerequisiteManifestSha256", "brokerPackageSha256", "brokerManifestSha256", "stageAInputSha256", "stageAStateBackupSha256", "prerequisiteProducerWorkflowRunId", "prerequisiteProducerWorkflowRunAttempt", "prerequisiteBundleArtifactId", "prerequisiteBundleArtifactDigest", "addresses", "refreshOnlyPlanSha256", "refreshOnlyPlanJsonSha256", "boundImagesTransition", "reviewedPolicyValueHashes", "pendingConvergenceSemantics", "planSemantics", "createdAt", "expiresAt", "preparationSha256"];
  exactKeys(value, fields, "Stage B state reconciliation preparation");
  const { preparationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_PREPARATION" || value.operation !== STAGE_B_STATE_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || !TICKET.test(value.ticketId || "") || value.terraformRoot !== STAGE_B_STATE_RECONCILIATION.terraformRoot || ![value.tfvarsSha256, value.bindingSha256, value.preflightSha256, value.runtimeTfvarsSha256, value.runtimeBindingSha256, value.runtimeMaterializationSha256, value.relocationContractSha256, value.prerequisiteManifestSha256, value.brokerPackageSha256, value.brokerManifestSha256, value.stageAInputSha256, value.stageAStateBackupSha256, value.refreshOnlyPlanSha256, value.refreshOnlyPlanJsonSha256, value.boundImagesTransition?.transitionSha256, value.pendingConvergenceSemantics?.semanticsSha256].every((candidate) => SHA256.test(candidate || "")) || !/^\d+$/.test(value.prerequisiteProducerWorkflowRunId || "") || value.prerequisiteProducerWorkflowRunAttempt !== "1" || !/^\d+$/.test(value.prerequisiteBundleArtifactId || "") || !/^sha256:[a-f0-9]{64}$/.test(value.prerequisiteBundleArtifactDigest || "") || !equal(Object.keys(value.reviewedPolicyValueHashes || {}).sort(), STAGE_B_STATE_RECONCILIATION.addresses.slice().sort()) || !STAGE_B_STATE_RECONCILIATION.addresses.every((address) => { const entry = value.reviewedPolicyValueHashes?.[address]; return entry?.field === (address.startsWith("aws_iam_role_policy") ? "policy" : "inline_policy") && SHA256.test(entry?.beforeSha256 || "") && SHA256.test(entry?.afterSha256 || ""); }) || !equal(value.addresses, STAGE_B_STATE_RECONCILIATION.addresses) || value.boundImagesTransition?.name !== "bound_images" || !equal(value.boundImagesTransition?.actions, ["update"]) || !equal(value.boundImagesTransition?.before, STAGE_B_STATE_RECONCILIATION.predecessorBoundImages) || value.boundImagesTransition.transitionSha256 !== sha256({ actions: value.boundImagesTransition.actions, before: value.boundImagesTransition.before, after: value.boundImagesTransition.after, after_unknown: false, before_sensitive: false, after_sensitive: false }) || value.pendingConvergenceSemantics.semanticsSha256 !== sha256(Object.fromEntries(Object.entries(value.pendingConvergenceSemantics).filter(([key]) => key !== "semanticsSha256"))) || !equal(value.planSemantics, { refreshOnly: true, remoteResourceMutationCount: 0, stateRecordChangeCount: 11, resourceStateChangeCount: 10, outputStateChangeCount: 1, addresses: STAGE_B_STATE_RECONCILIATION.addresses, boundImagesTransitionSha256: value.boundImagesTransition.transitionSha256 }) || value.preparationSha256 !== sha256(body)) throw new Error("Stage B state reconciliation preparation binding is invalid.");
  assertStateIdentity(value.predecessorState); const created = iso(value.createdAt, "Stage B state reconciliation preparation creation"); const expires = iso(value.expiresAt, "Stage B state reconciliation preparation expiry"); if (expires.getTime() - created.getTime() !== STAGE_B_STATE_RECONCILIATION.maxAgeMs || now < created || now > expires) throw new Error("Stage B state reconciliation preparation is stale.");
  return value;
}

export function createStageBStateReconciliationAuthorization({ preparation, approval, now = new Date() } = {}) {
  const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(approval, { sourceSha: prepared.sourceSha, repository: STAGE_B_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(approval, { now });
  if (approval.workflowRef !== workflowRef(STAGE_B_STATE_RECONCILIATION.authorizationWorkflowPath)) throw new Error("Stage B state reconciliation requires its dedicated protected-environment workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(approval, { sourceSha: prepared.sourceSha, repository: STAGE_B_STATE_RECONCILIATION.repository, executionActor: approval.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_AUTHORIZATION", operation: prepared.operation, sourceSha: prepared.sourceSha, ticketId: prepared.ticketId, preparationSha256: prepared.preparationSha256, stateLineage: prepared.predecessorState.lineage, preOperationStateSerial: prepared.predecessorState.serial, addresses: prepared.addresses, refreshOnlyPlanSha256: prepared.refreshOnlyPlanSha256, boundImagesTransitionSha256: prepared.boundImagesTransition.transitionSha256, pendingConvergenceSemanticsSha256: prepared.pendingConvergenceSemantics.semanticsSha256, tfvarsSha256: prepared.tfvarsSha256, bindingSha256: prepared.bindingSha256, preflightSha256: prepared.preflightSha256, runtimeTfvarsSha256: prepared.runtimeTfvarsSha256, runtimeBindingSha256: prepared.runtimeBindingSha256, runtimeMaterializationSha256: prepared.runtimeMaterializationSha256, relocationContractSha256: prepared.relocationContractSha256, prerequisiteManifestSha256: prepared.prerequisiteManifestSha256, brokerPackageSha256: prepared.brokerPackageSha256, brokerManifestSha256: prepared.brokerManifestSha256, stageAInputSha256: prepared.stageAInputSha256, stageAStateBackupSha256: prepared.stageAStateBackupSha256, prerequisiteProducerWorkflowRunId: prepared.prerequisiteProducerWorkflowRunId, prerequisiteProducerWorkflowRunAttempt: prepared.prerequisiteProducerWorkflowRunAttempt, prerequisiteBundleArtifactId: prepared.prerequisiteBundleArtifactId, prerequisiteBundleArtifactDigest: prepared.prerequisiteBundleArtifactDigest, approvedBy, protectedEnvironmentApprovalEvidence: approval, protectedEnvironmentApprovalEvidenceSha256: approval.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}

export function assertStageBStateReconciliationAuthorization(value, { preparation, sourceSha, now = new Date() } = {}) {
  const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha, now });
  const fields = ["schemaVersion", "kind", "operation", "sourceSha", "ticketId", "preparationSha256", "stateLineage", "preOperationStateSerial", "addresses", "refreshOnlyPlanSha256", "boundImagesTransitionSha256", "pendingConvergenceSemanticsSha256", "tfvarsSha256", "bindingSha256", "preflightSha256", "runtimeTfvarsSha256", "runtimeBindingSha256", "runtimeMaterializationSha256", "relocationContractSha256", "prerequisiteManifestSha256", "brokerPackageSha256", "brokerManifestSha256", "stageAInputSha256", "stageAStateBackupSha256", "prerequisiteProducerWorkflowRunId", "prerequisiteProducerWorkflowRunAttempt", "prerequisiteBundleArtifactId", "prerequisiteBundleArtifactDigest", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
  exactKeys(value, fields, "Stage B state reconciliation authorization"); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_AUTHORIZATION" || value.operation !== prepared.operation || value.sourceSha !== sourceSha || value.ticketId !== prepared.ticketId || value.preparationSha256 !== prepared.preparationSha256 || value.stateLineage !== prepared.predecessorState.lineage || value.preOperationStateSerial !== prepared.predecessorState.serial || !equal(value.addresses, prepared.addresses) || value.refreshOnlyPlanSha256 !== prepared.refreshOnlyPlanSha256 || value.boundImagesTransitionSha256 !== prepared.boundImagesTransition.transitionSha256 || value.pendingConvergenceSemanticsSha256 !== prepared.pendingConvergenceSemantics.semanticsSha256 || value.tfvarsSha256 !== prepared.tfvarsSha256 || value.bindingSha256 !== prepared.bindingSha256 || value.preflightSha256 !== prepared.preflightSha256 || value.runtimeTfvarsSha256 !== prepared.runtimeTfvarsSha256 || value.runtimeBindingSha256 !== prepared.runtimeBindingSha256 || value.runtimeMaterializationSha256 !== prepared.runtimeMaterializationSha256 || value.relocationContractSha256 !== prepared.relocationContractSha256 || value.prerequisiteManifestSha256 !== prepared.prerequisiteManifestSha256 || value.brokerPackageSha256 !== prepared.brokerPackageSha256 || value.brokerManifestSha256 !== prepared.brokerManifestSha256 || value.stageAInputSha256 !== prepared.stageAInputSha256 || value.stageAStateBackupSha256 !== prepared.stageAStateBackupSha256 || value.prerequisiteProducerWorkflowRunId !== prepared.prerequisiteProducerWorkflowRunId || value.prerequisiteProducerWorkflowRunAttempt !== prepared.prerequisiteProducerWorkflowRunAttempt || value.prerequisiteBundleArtifactId !== prepared.prerequisiteBundleArtifactId || value.prerequisiteBundleArtifactDigest !== prepared.prerequisiteBundleArtifactDigest || value.authorizationSha256 !== sha256(body)) throw new Error("Stage B state reconciliation authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: STAGE_B_STATE_RECONCILIATION.repository }); assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== workflowRef(STAGE_B_STATE_RECONCILIATION.authorizationWorkflowPath) || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("Stage B state reconciliation authorization approval provenance is invalid.");
  return value;
}

export function executeStageBStateReconciliation({ sourceSha, preparation, authorization, bindings, terraformConfiguration, planBytes, planJson, readState, applyRefreshOnlyPlan, renderPreApplyNormalPlan, renderRefreshClosurePlan, renderNormalClosurePlan, reauthenticateSource, now = new Date() } = {}) {
  if (![readState, applyRefreshOnlyPlan, renderPreApplyNormalPlan, renderRefreshClosurePlan, renderNormalClosurePlan, reauthenticateSource].every((value) => typeof value === "function")) throw new Error("Stage B state reconciliation execution adapters are required.");
  const prepared = assertStageBStateReconciliationPreparation(preparation, { sourceSha, now });
  assertStageBStateReconciliationAuthorization(authorization, { preparation: prepared, sourceSha, now });
  if (!bindings || !SHA256.test(bindings.tfvarsSha256 || "") || !SHA256.test(bindings.bindingSha256 || "") || !bindings.bindingReport || !SHA256.test(bindings.runtimeMaterializationSha256 || "") || bindings.preflightSha256 !== prepared.preflightSha256 || bindings.relocationContractSha256 !== prepared.relocationContractSha256 || bindings.prerequisiteManifestSha256 !== prepared.prerequisiteManifestSha256 || bindings.brokerPackageSha256 !== prepared.brokerPackageSha256 || bindings.brokerManifestSha256 !== prepared.brokerManifestSha256 || bindings.stageAInputSha256 !== prepared.stageAInputSha256 || bindings.stageAStateBackupSha256 !== prepared.stageAStateBackupSha256) throw new Error("Stage B state reconciliation execution inputs differ from the approved preparation.");
  const planOptions = { sourceSha, stateIdentity: prepared.predecessorState, tfvarsSha256: bindings.tfvarsSha256, bindingSha256: bindings.bindingSha256, bindingReport: bindings.bindingReport, expectedPolicyValueHashes: prepared.reviewedPolicyValueHashes };
  if (!Buffer.isBuffer(planBytes) || sha256(planBytes) !== prepared.refreshOnlyPlanSha256 || sha256(planJson) !== prepared.refreshOnlyPlanJsonSha256 || !equal(assertExactStageBRefreshOnlyPlan(planJson, planOptions), prepared.planSemantics) || !equal(assertBoundImagesTransition(planJson, bindings.bindingReport), prepared.boundImagesTransition)) throw new Error("Stage B state reconciliation saved plan changed after authorization.");
  const before = readState();
  const exactSuccessor = before?.lineage === prepared.predecessorState.lineage && before?.serial === prepared.predecessorState.serial + 1 && before?.stateSha256 !== prepared.predecessorState.stateSha256;
  if (!equal(before, prepared.predecessorState) && !exactSuccessor) throw new Error("Stage B state reconciliation CAS failed.");
  const result = (status, successorState, terraformStateMutationCount = 1) => { const closureProven = status === "complete" || status === "recovered-complete"; return Object.freeze({ schemaVersion: 1, kind: "PRODUCTION_GREEN_STAGE_B_STATE_RECONCILIATION_RESULT", status, sourceSha, authorizationSha256: authorization.authorizationSha256, predecessorState: prepared.predecessorState, successorState, remainingExpectedStateObservations: closureProven ? 0 : null, pendingOrdinaryConvergenceSemanticsSha256: closureProven ? prepared.pendingConvergenceSemantics.semanticsSha256 : null, pendingOrdinaryResourceMutationCount: closureProven ? prepared.pendingConvergenceSemantics.resourceChanges.length : null, newUnexpectedDriftCount: closureProven ? 0 : null, remoteResourceMutationCount: 0, terraformStateMutationCount }); };
  const successor = () => {
    const after = readState();
    if (after.lineage !== prepared.predecessorState.lineage || after.serial !== prepared.predecessorState.serial + 1 || after.stateSha256 === prepared.predecessorState.stateSha256) throw Object.assign(new Error("Stage B state reconciliation successor is not exact."), { observedState: after });
    return after;
  };
  const complete = (status, terraformStateMutationCount = 1) => {
    let after;
    try { after = successor(); } catch (error) { error.reconciliationResult = result("state-write-completed-postverify-failed", error.observedState || null); throw error; }
    try {
      assertCleanStageBRefreshClosurePlan(renderRefreshClosurePlan(), { sourceSha });
      assertPendingStageBConvergence(renderNormalClosurePlan(), planJson, { sourceSha, terraformConfiguration, postWrite: true, expectedSemantics: prepared.pendingConvergenceSemantics });
    } catch (error) {
      error.reconciliationResult = result("state-write-completed-postverify-failed", after);
      throw error;
    }
    return result(status, after, terraformStateMutationCount);
  };
  reauthenticateSource();
  if (exactSuccessor) return complete("recovered-complete", 0);
  assertPendingStageBConvergence(renderPreApplyNormalPlan(), planJson, { sourceSha, terraformConfiguration, expectedSemantics: prepared.pendingConvergenceSemantics });
  try { applyRefreshOnlyPlan(planBytes); } catch (error) {
    try {
      const after = readState();
      if (equal(after, before)) {
        error.reconciliationResult = result("state-write-not-committed", after, 0);
      } else {
        error.reconciliationResult = result("state-write-outcome-ambiguous", after, null);
        error.mutationOutcome = "AMBIGUOUS";
      }
    } catch (verificationError) {
      if (verificationError.reconciliationResult) throw verificationError;
      error.reconciliationResult = result("state-write-outcome-ambiguous", null, null);
      error.mutationOutcome = "AMBIGUOUS";
    }
    throw error;
  }
  return complete("complete");
}

export const stageBStateReconciliationSha256 = (value) => sha256(value);
