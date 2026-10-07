import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity, createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const RUN_ID = /^[1-9][0-9]*$/;
const sha256 = value => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : canonicalJson(value)).digest("hex");
const canonicalBytes = value => Buffer.from(`${canonicalJson(value)}\n`);
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const iso = (value, label) => { const parsed = new Date(value); if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) throw new Error(`${label} is invalid.`); return parsed; };

export class WorkspaceStateRetryableObservationError extends Error {
  constructor(message, options) { super(message, options); this.name = "WorkspaceStateRetryableObservationError"; }
}

export const WORKSPACE_STATE_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION",
  account: "368992683803",
  region: "eu-west-2",
  policyName: "MSCQRProductionGreenStageBWorkspaceState",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBWorkspaceState",
  sourcePath: "documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json",
  releaseRoleName: "mscqr-production-release-deployer",
  workflowPath: ".github/workflows/authorize-production-workspace-state-policy-reconciliation.yml",
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.workspaceStatePolicyReconciliationWorkflowRef,
  artifactName: "production-workspace-state-policy-reconciliation-authorization",
  authorizationFilename: "authorization.json",
  journalBucket: STAGE_B_TERRAFORM_BACKEND.bucketName,
  journalPrefix: `${STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefix}/workspace-state-policy-reconciliation/`,
  maxAgeMs: 30 * 60 * 1000,
  rollbackRetention: "PRESERVE_THREE_NEWEST_NON_DEFAULT_VERSIONS",
  readDelaysMs: Object.freeze([100, 300, 700]),
});

export const workspaceStateProductionSleep = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));

export function readWorkspaceStateDesiredPolicy({ repositoryRoot = root } = {}) {
  const document = normalizeIamPolicyDocument(fs.readFileSync(path.resolve(repositoryRoot, WORKSPACE_STATE_RECONCILIATION.sourcePath), "utf8"), "WorkspaceState source policy");
  const grants = document.Statement.filter(statement => statement.Sid === "ReadStageBApplyAttemptVersions");
  if (grants.length !== 1 || canonicalJson(grants[0]) !== canonicalJson({ Sid: "ReadStageBApplyAttemptVersions", Effect: "Allow", Action: "s3:GetObjectVersion", Resource: STAGE_B_TERRAFORM_BACKEND.applyAttemptPrefixArn })) throw new Error("WorkspaceState desired policy lacks the exact version-read grant.");
  const predecessor = structuredClone(document);
  predecessor.Statement = predecessor.Statement.filter(statement => statement.Sid !== "ReadStageBApplyAttemptVersions");
  return Object.freeze({ sourcePath: WORKSPACE_STATE_RECONCILIATION.sourcePath, document, desiredDocumentSha256: sha256(document), predecessor, predecessorDocumentSha256: sha256(predecessor), delta: Object.freeze({ add: Object.freeze([grants[0]]), remove: Object.freeze([]), change: Object.freeze([]) }) });
}

const normalizeVersions = versions => {
  if (!Array.isArray(versions) || versions.length < 1 || versions.length > 5) throw new Error("WorkspaceState version inventory is invalid.");
  const normalized = versions.map(({ versionId, isDefault, createDate, document }) => {
    if (!VERSION.test(versionId || "") || typeof isDefault !== "boolean") throw new Error("WorkspaceState version identity is invalid.");
    const created = iso(createDate, "WorkspaceState version createDate");
    const normalizedDocument = normalizeIamPolicyDocument(document, "WorkspaceState version document");
    return { versionId, isDefault, createDate: created.toISOString(), document: normalizedDocument, documentSha256: sha256(normalizedDocument) };
  }).sort((a, b) => Number(a.versionId.slice(1)) - Number(b.versionId.slice(1)));
  if (new Set(normalized.map(({ versionId }) => versionId)).size !== normalized.length || normalized.filter(({ isDefault }) => isDefault).length !== 1) throw new Error("WorkspaceState version topology is ambiguous.");
  return normalized;
};

export function authenticateWorkspaceStateLiveState(value, { desired = readWorkspaceStateDesiredPolicy(), allowPre = true, allowAfterDeletion = true, allowPost = true } = {}) {
  exactKeys(value, ["policyArn", "defaultVersionId", "versions", "attachedRoles", "attachedUsers", "attachedGroups", "permissionsBoundaryUsageCount"], "WorkspaceState live state");
  const versions = normalizeVersions(value.versions);
  const current = versions.find(version => version.versionId === value.defaultVersionId);
  const attachedRoles = [...value.attachedRoles].sort(); const attachedUsers = [...value.attachedUsers].sort(); const attachedGroups = [...value.attachedGroups].sort();
  if (value.policyArn !== WORKSPACE_STATE_RECONCILIATION.policyArn || !current?.isDefault || canonicalJson(attachedRoles) !== canonicalJson([WORKSPACE_STATE_RECONCILIATION.releaseRoleName]) || attachedUsers.length || attachedGroups.length || value.permissionsBoundaryUsageCount !== 0) throw new Error("WorkspaceState target or attachment topology is invalid.");
  const pre = allowPre && versions.length === 5 && current.documentSha256 === desired.predecessorDocumentSha256;
  const afterDeletion = allowAfterDeletion && versions.length === 4 && current.documentSha256 === desired.predecessorDocumentSha256;
  const post = allowPost && versions.length === 5 && current.documentSha256 === desired.desiredDocumentSha256;
  if (!pre && !afterDeletion && !post) throw new Error("WorkspaceState live policy contains unexpected drift.");
  return Object.freeze({ ...value, versions, attachedRoles, attachedUsers, attachedGroups, defaultDocumentSha256: current.documentSha256, inventorySha256: sha256(versions), attachmentTopologySha256: sha256({ roles: attachedRoles, users: attachedUsers, groups: attachedGroups, permissionsBoundaryUsageCount: 0 }), status: pre ? "AUTHENTICATED_PRE_STATE" : afterDeletion ? "AUTHENTICATED_CAPACITY_STATE" : "EXPECTED_POST_STATE" });
}

const chooseDeletionCandidate = versions => {
  const candidates = versions.filter(version => !version.isDefault);
  if (candidates.length !== 4) throw new Error("WorkspaceState has no uniquely oldest safe non-default version.");
  const oldestDate = Math.min(...candidates.map(version => Date.parse(version.createDate)));
  const oldest = candidates.filter(version => Date.parse(version.createDate) === oldestDate);
  if (oldest.length !== 1) throw new Error("WorkspaceState has no uniquely oldest safe non-default version.");
  return oldest[0];
};

const operationId = body => sha256({ schemaVersion: 1, operation: WORKSPACE_STATE_RECONCILIATION.operation, account: WORKSPACE_STATE_RECONCILIATION.account, targetPolicyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, ...body });
const PREPARATION_FIELDS = ["schemaVersion", "kind", "operation", "operationId", "sourceSha", "account", "targetPolicyArn", "sourcePolicyPath", "currentDefaultVersionId", "currentDefaultDocumentSha256", "desiredDocumentSha256", "permissionDelta", "permissionDeltaSha256", "versionInventory", "versionInventorySha256", "deletionCandidate", "rollbackRetention", "attachmentTopology", "attachmentTopologySha256", "expectedWritePlan", "expectedWritePlanSha256", "createdAt", "expiresAt", "preparationSha256"];

export function createWorkspaceStatePreparation({ sourceSha, liveState, desired = readWorkspaceStateDesiredPolicy(), preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "")) throw new Error("WorkspaceState preparation source SHA is invalid.");
  const state = authenticateWorkspaceStateLiveState(liveState, { desired, allowAfterDeletion: false, allowPost: false });
  const candidate = chooseDeletionCandidate(state.versions);
  const deletionCandidate = { versionId: candidate.versionId, createDate: candidate.createDate, documentSha256: candidate.documentSha256 };
  const identity = { sourceSha, currentDefaultVersionId: state.defaultVersionId, currentDefaultDocumentSha256: state.defaultDocumentSha256, desiredDocumentSha256: desired.desiredDocumentSha256, versionInventorySha256: state.inventorySha256, deletionCandidate, attachmentTopologySha256: state.attachmentTopologySha256 };
  const created = iso(preparedAt, "WorkspaceState preparation createdAt");
  const expectedWritePlan = [
    { action: "iam:DeletePolicyVersion", policyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, versionId: candidate.versionId },
    { action: "iam:CreatePolicyVersion", policyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, policyDocumentSha256: desired.desiredDocumentSha256, setAsDefault: true },
  ];
  const body = { schemaVersion: 1, kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_PREPARATION", operation: WORKSPACE_STATE_RECONCILIATION.operation, operationId: operationId(identity), sourceSha, account: WORKSPACE_STATE_RECONCILIATION.account, targetPolicyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, sourcePolicyPath: desired.sourcePath, currentDefaultVersionId: state.defaultVersionId, currentDefaultDocumentSha256: state.defaultDocumentSha256, desiredDocumentSha256: desired.desiredDocumentSha256, permissionDelta: desired.delta, permissionDeltaSha256: sha256(desired.delta), versionInventory: state.versions, versionInventorySha256: state.inventorySha256, deletionCandidate, rollbackRetention: WORKSPACE_STATE_RECONCILIATION.rollbackRetention, attachmentTopology: { roles: state.attachedRoles, users: state.attachedUsers, groups: state.attachedGroups, permissionsBoundaryUsageCount: 0 }, attachmentTopologySha256: state.attachmentTopologySha256, expectedWritePlan, expectedWritePlanSha256: sha256(expectedWritePlan), createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + WORKSPACE_STATE_RECONCILIATION.maxAgeMs).toISOString() };
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}

export function assertWorkspaceStatePreparation(value, { sourceSha, desired = readWorkspaceStateDesiredPolicy(), now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, PREPARATION_FIELDS, "WorkspaceState preparation");
  const body = { ...value }; delete body.preparationSha256;
  const versions = normalizeVersions(value.versionInventory); const candidate = chooseDeletionCandidate(versions);
  const deletionCandidate = { versionId: candidate.versionId, createDate: candidate.createDate, documentSha256: candidate.documentSha256 };
  const identity = { sourceSha, currentDefaultVersionId: value.currentDefaultVersionId, currentDefaultDocumentSha256: value.currentDefaultDocumentSha256, desiredDocumentSha256: value.desiredDocumentSha256, versionInventorySha256: value.versionInventorySha256, deletionCandidate, attachmentTopologySha256: value.attachmentTopologySha256 };
  const expectedWritePlan = [{ action: "iam:DeletePolicyVersion", policyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, versionId: candidate.versionId }, { action: "iam:CreatePolicyVersion", policyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, policyDocumentSha256: desired.desiredDocumentSha256, setAsDefault: true }];
  const current = versions.find(version => version.versionId === value.currentDefaultVersionId);
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_PREPARATION" || value.operation !== WORKSPACE_STATE_RECONCILIATION.operation || value.operationId !== operationId(identity) || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || value.account !== WORKSPACE_STATE_RECONCILIATION.account || value.targetPolicyArn !== WORKSPACE_STATE_RECONCILIATION.policyArn || value.sourcePolicyPath !== desired.sourcePath || versions.length !== 5 || !current?.isDefault || current.documentSha256 !== desired.predecessorDocumentSha256 || value.currentDefaultDocumentSha256 !== desired.predecessorDocumentSha256 || value.desiredDocumentSha256 !== desired.desiredDocumentSha256 || canonicalJson(value.permissionDelta) !== canonicalJson(desired.delta) || value.permissionDeltaSha256 !== sha256(desired.delta) || value.versionInventorySha256 !== sha256(versions) || canonicalJson(value.deletionCandidate) !== canonicalJson(deletionCandidate) || value.rollbackRetention !== WORKSPACE_STATE_RECONCILIATION.rollbackRetention || value.attachmentTopologySha256 !== sha256(value.attachmentTopology) || canonicalJson(value.attachmentTopology) !== canonicalJson({ roles: [WORKSPACE_STATE_RECONCILIATION.releaseRoleName], users: [], groups: [], permissionsBoundaryUsageCount: 0 }) || canonicalJson(value.expectedWritePlan) !== canonicalJson(expectedWritePlan) || value.expectedWritePlanSha256 !== sha256(expectedWritePlan) || value.preparationSha256 !== sha256(body)) throw new Error("WorkspaceState preparation binding is invalid.");
  const created = iso(value.createdAt, "WorkspaceState preparation createdAt"); const expires = iso(value.expiresAt, "WorkspaceState preparation expiresAt"); const clock = now instanceof Date ? now : new Date(now);
  if (!Number.isFinite(clock.getTime()) || expires.getTime() - created.getTime() !== WORKSPACE_STATE_RECONCILIATION.maxAgeMs || clock < created || (!allowExpired && clock > expires)) throw new Error("WorkspaceState preparation is stale.");
  return value;
}

const AUTHORIZATION_FIELDS = ["schemaVersion", "kind", "operation", "operationId", "sourceSha", "targetPolicyArn", "currentDefaultVersionId", "currentDefaultDocumentSha256", "desiredDocumentSha256", "permissionDeltaSha256", "versionInventorySha256", "deletionCandidate", "attachmentTopologySha256", "expectedWritePlanSha256", "preparationSha256", "expiresAt", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationConsumed", "authorizationSha256"];
export function createWorkspaceStateAuthorization({ preparation, protectedEnvironmentApprovalEvidence, now = new Date() } = {}) {
  const checked = assertWorkspaceStatePreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha: checked.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  assertProductionEnvironmentApprovalFreshness(protectedEnvironmentApprovalEvidence, { now });
  if (protectedEnvironmentApprovalEvidence.schemaVersion !== 3 || protectedEnvironmentApprovalEvidence.workflowRef !== WORKSPACE_STATE_RECONCILIATION.workflowRef) throw new Error("WorkspaceState authorization requires its dedicated protected workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha: checked.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_AUTHORIZATION", operation: checked.operation, operationId: checked.operationId, sourceSha: checked.sourceSha, targetPolicyArn: checked.targetPolicyArn, currentDefaultVersionId: checked.currentDefaultVersionId, currentDefaultDocumentSha256: checked.currentDefaultDocumentSha256, desiredDocumentSha256: checked.desiredDocumentSha256, permissionDeltaSha256: checked.permissionDeltaSha256, versionInventorySha256: checked.versionInventorySha256, deletionCandidate: checked.deletionCandidate, attachmentTopologySha256: checked.attachmentTopologySha256, expectedWritePlanSha256: checked.expectedWritePlanSha256, preparationSha256: checked.preparationSha256, expiresAt: checked.expiresAt, approvedBy, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, authorizationConsumed: false };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}

export function assertWorkspaceStateAuthorization(value, preparation, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, AUTHORIZATION_FIELDS, "WorkspaceState authorization");
  const checked = assertWorkspaceStatePreparation(preparation, { sourceSha, now, allowExpired }); const body = { ...value }; delete body.authorizationSha256;
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (!allowExpired) assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  const approvedBy = assertProductionEnvironmentActualReviewer(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: value.protectedEnvironmentApprovalEvidence.executionActor });
  const bindings = ["operation", "operationId", "sourceSha", "targetPolicyArn", "currentDefaultVersionId", "currentDefaultDocumentSha256", "desiredDocumentSha256", "permissionDeltaSha256", "versionInventorySha256", "deletionCandidate", "attachmentTopologySha256", "expectedWritePlanSha256", "preparationSha256", "expiresAt"];
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_AUTHORIZATION" || bindings.some(field => canonicalJson(value[field]) !== canonicalJson(checked[field])) || value.protectedEnvironmentApprovalEvidence.workflowRef !== WORKSPACE_STATE_RECONCILIATION.workflowRef || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== approvedBy || value.authorizationConsumed !== false || value.authorizationSha256 !== sha256(body)) throw new Error("WorkspaceState authorization binding is invalid.");
  return value;
}

export async function resolveWorkspaceStateAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, preparation, run, now = new Date(), allowExpired = true } = {}) {
  if (!RUN_ID.test(String(workflowRunId || "")) || String(workflowRunAttempt) !== "1" || typeof run !== "function") throw new Error("WorkspaceState authorization workflow identity is invalid.");
  const parse = (args, label) => { let value; try { value = JSON.parse(run("gh", args, { encoding: "utf8", maxBuffer: 8 * 1024 * 1024 })); } catch { throw new Error(`${label} is unavailable.`); } return value; };
  const workflow = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}`], "WorkspaceState authorization workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.head_repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.path !== WORKSPACE_STATE_RECONCILIATION.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== "1") throw new Error("WorkspaceState authorization workflow provenance is invalid.");
  const pages = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"], "WorkspaceState authorization artifacts");
  const matches = pages.flatMap(page => page?.artifacts || []).filter(artifact => artifact?.name === WORKSPACE_STATE_RECONCILIATION.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository?.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1) throw new Error("WorkspaceState authorization artifact identity is not exact.");
  const archive = Buffer.from(run("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
  if (`sha256:${sha256(archive)}` !== matches[0].digest) throw new Error("WorkspaceState authorization archive digest is invalid.");
  const zip = await JSZip.loadAsync(archive); const entries = Object.values(zip.files).filter(entry => !entry.dir);
  if (entries.length !== 1 || entries[0].name !== WORKSPACE_STATE_RECONCILIATION.authorizationFilename || (Number(entries[0].unixPermissions || 0) & 0o170000) === 0o120000) throw new Error("WorkspaceState authorization archive contents are not exact.");
  const bytes = Buffer.from(await entries[0].async("uint8array")); let authorization;
  try { authorization = JSON.parse(new TextDecoder("utf8", { fatal: true }).decode(bytes)); } catch { throw new Error("WorkspaceState authorization artifact payload is malformed."); }
  assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now, allowExpired });
  const environment = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/environments/production`], "WorkspaceState environment");
  const approvals = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}/approvals`], "WorkspaceState approvals");
  const actual = approvals.flatMap(approval => approval?.state === "approved" ? (approval.environments || []).filter(item => item?.id === environment.id && item?.name === "production").map(() => ({ state: "approved", environmentId: environment.id, environmentName: "production", userId: approval.user?.id, userLogin: approval.user?.login })) : []);
  if (actual.length !== 1) throw new Error("Exactly one authenticated WorkspaceState production approval is required.");
  const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef: WORKSPACE_STATE_RECONCILIATION.workflowRef, eventName: "workflow_dispatch", workflowRunId: String(workflow.id), workflowRunAttempt: "1", executionActor: workflow.actor?.login, observedAt: authorization.protectedEnvironmentApprovalEvidence.observedAt, actualApproval: actual[0] });
  if (canonicalJson(observed) !== canonicalJson(authorization.protectedEnvironmentApprovalEvidence)) throw new Error("WorkspaceState approval differs from authenticated GitHub provenance.");
  const provenanceBody = { schemaVersion: 1, kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE", repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, workflowPath: workflow.path, workflowRunId: String(workflow.id), workflowRunAttempt: "1", event: workflow.event, status: workflow.status, conclusion: workflow.conclusion, headSha: workflow.head_sha, artifactId: matches[0].id, artifactName: matches[0].name, artifactDigest: matches[0].digest, authorizationFileSha256: sha256(bytes), authorizationSha256: authorization.authorizationSha256, approvedBy: authorization.approvedBy };
  return Object.freeze({ authorization, provenance: Object.freeze({ ...provenanceBody, provenanceSha256: sha256(provenanceBody) }) });
}

export function assertWorkspaceStateAuthorizationProvenance(value, { authorization, sourceSha } = {}) {
  const fields = ["schemaVersion", "kind", "repository", "workflowPath", "workflowRunId", "workflowRunAttempt", "event", "status", "conclusion", "headSha", "artifactId", "artifactName", "artifactDigest", "authorizationFileSha256", "authorizationSha256", "approvedBy", "provenanceSha256"];
  exactKeys(value, fields, "WorkspaceState authorization provenance"); const { provenanceSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE" || value.repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || value.workflowPath !== WORKSPACE_STATE_RECONCILIATION.workflowPath || !RUN_ID.test(value.workflowRunId || "") || value.workflowRunAttempt !== "1" || value.workflowRunId !== authorization?.protectedEnvironmentApprovalEvidence?.workflowRunId || value.event !== "workflow_dispatch" || value.status !== "completed" || value.conclusion !== "success" || value.headSha !== sourceSha || !Number.isSafeInteger(value.artifactId) || value.artifactId < 1 || value.artifactName !== WORKSPACE_STATE_RECONCILIATION.artifactName || !/^sha256:[a-f0-9]{64}$/.test(value.artifactDigest || "") || !SHA256.test(value.authorizationFileSha256 || "") || value.authorizationSha256 !== authorization?.authorizationSha256 || value.approvedBy !== authorization?.approvedBy || provenanceSha256 !== sha256(body)) throw new Error("WorkspaceState authorization provenance is invalid.");
  return value;
}

const RECORDS = Object.freeze(["reservation.json", "deletion-attempt.json", "deletion-prewrite-failed.json", "deletion-retry-attempt.json", "deletion-complete.json", "creation-attempt.json", "terminal.json"]);
export const workspaceStateJournalKey = (operationIdValue, record) => {
  if (!SHA256.test(operationIdValue || "") || !RECORDS.includes(record)) throw new Error("WorkspaceState journal key is invalid.");
  return `${WORKSPACE_STATE_RECONCILIATION.journalPrefix}${operationIdValue}/${record}`;
};
export function createWorkspaceStateJournal({ read, create } = {}) {
  if (typeof read !== "function" || typeof create !== "function") throw new Error("WorkspaceState journal adapters are required.");
  const get = async (authorization, record) => { const bytes = await read(workspaceStateJournalKey(authorization.operationId, record)); if (!bytes) return null; const value = JSON.parse(new TextDecoder("utf8", { fatal: true }).decode(bytes)); if (!Buffer.from(bytes).equals(canonicalBytes(value))) throw new Error("WorkspaceState journal record is not canonical."); return value; };
  const put = async (authorization, record, body) => { const value = Object.freeze({ ...body, recordSha256: sha256(body) }); const bytes = canonicalBytes(value); if (!await create(workspaceStateJournalKey(authorization.operationId, record), bytes)) return false; const captured = await read(workspaceStateJournalKey(authorization.operationId, record)); if (!captured || !Buffer.from(captured).equals(bytes)) throw new Error("WorkspaceState journal write readback failed."); return value; };
  return Object.freeze({ read: get, create: put });
}

const recordBody = ({ kind, preparation, authorization, provenance, createdAt, postState }) => ({ schemaVersion: 1, kind, operationId: preparation.operationId, sourceSha: preparation.sourceSha, targetPolicyArn: preparation.targetPolicyArn, preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256, authorizationProvenanceSha256: provenance.provenanceSha256, currentDefaultVersionId: preparation.currentDefaultVersionId, currentDefaultDocumentSha256: preparation.currentDefaultDocumentSha256, desiredDocumentSha256: preparation.desiredDocumentSha256, permissionDeltaSha256: preparation.permissionDeltaSha256, versionInventorySha256: preparation.versionInventorySha256, deletionCandidate: preparation.deletionCandidate, expectedWritePlanSha256: preparation.expectedWritePlanSha256, ...(postState ? { createdPolicyVersionId: postState.defaultVersionId, postVersionInventorySha256: postState.inventorySha256, status: "COMPLETED", authorizationConsumed: true } : {}), createdAt });
const assertRecord = (value, expected) => { const { recordSha256, ...body } = value || {}; exactKeys(value, [...Object.keys(expected), "recordSha256"], "WorkspaceState journal record"); if (canonicalJson(body) !== canonicalJson(expected) || recordSha256 !== sha256(body)) throw new Error("WorkspaceState journal record differs from the authorized transaction."); return value; };
const assertZeroWriteReservation = (value, preparation, authorization, provenance) => {
  const { recordSha256, ...body } = value || {};
  exactKeys(value, [...Object.keys(recordBody({ kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION", preparation, authorization, provenance, createdAt: value?.createdAt })), "recordSha256"], "WorkspaceState reservation");
  const expected = recordBody({ kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION", preparation, authorization, provenance, createdAt: value.createdAt });
  const historicalHashes = ["preparationSha256", "authorizationSha256", "authorizationProvenanceSha256"];
  if (value.recordSha256 !== sha256(body) || iso(value.createdAt, "WorkspaceState reservation createdAt").toISOString() !== value.createdAt || historicalHashes.some(field => !SHA256.test(value[field] || "")) || Object.keys(expected).some(field => !historicalHashes.includes(field) && canonicalJson(value[field]) !== canonicalJson(expected[field]))) throw new Error("WorkspaceState reservation is not an adoptable zero-write record.");
  return value;
};

const stateMatchesPreparation = (state, preparation) => state.status === "AUTHENTICATED_PRE_STATE" && state.defaultVersionId === preparation.currentDefaultVersionId && state.defaultDocumentSha256 === preparation.currentDefaultDocumentSha256 && state.inventorySha256 === preparation.versionInventorySha256 && state.attachmentTopologySha256 === preparation.attachmentTopologySha256;
const stateMatchesAfterDeletion = (state, preparation) => state.status === "AUTHENTICATED_CAPACITY_STATE" && state.defaultVersionId === preparation.currentDefaultVersionId && state.defaultDocumentSha256 === preparation.currentDefaultDocumentSha256 && state.attachmentTopologySha256 === preparation.attachmentTopologySha256 && state.versions.length === 4 && preparation.versionInventory.filter(version => version.versionId !== preparation.deletionCandidate.versionId).every(version => state.versions.some(current => canonicalJson(current) === canonicalJson(version)));
const stateMatchesPost = (state, preparation) => {
  if (state.status !== "EXPECTED_POST_STATE" || state.defaultDocumentSha256 !== preparation.desiredDocumentSha256 || state.defaultVersionId === preparation.currentDefaultVersionId || state.attachmentTopologySha256 !== preparation.attachmentTopologySha256 || state.versions.some(version => version.versionId === preparation.deletionCandidate.versionId)) return false;
  const retained = preparation.versionInventory.filter(version => version.versionId !== preparation.deletionCandidate.versionId);
  return retained.every(version => state.versions.some(current => current.versionId === version.versionId && current.documentSha256 === version.documentSha256 && current.isDefault === false)) && state.versions.filter(version => !retained.some(old => old.versionId === version.versionId)).length === 1;
};

async function observe(readLiveState, desired) { return authenticateWorkspaceStateLiveState(await readLiveState(), { desired }); }
async function bounded(readLiveState, desired, predicate, sleep, { intermediate = () => false } = {}) {
  let lastTransient;
  for (let index = 0; index <= WORKSPACE_STATE_RECONCILIATION.readDelaysMs.length; index += 1) {
    let state;
    try { state = await observe(readLiveState, desired); lastTransient = undefined; }
    catch (error) {
      if (!(error instanceof WorkspaceStateRetryableObservationError)) throw error;
      lastTransient = error;
    }
    if (state && predicate(state)) return state;
    if (state && !intermediate(state)) throw new Error("WorkspaceState observation is authenticated but contradicts the authorized transition.");
    if (index < WORKSPACE_STATE_RECONCILIATION.readDelaysMs.length) await sleep(WORKSPACE_STATE_RECONCILIATION.readDelaysMs[index]);
  }
  if (lastTransient) throw new Error("WorkspaceState IAM observation remained transient after the bounded retry budget.", { cause: lastTransient });
  return null;
}
async function boundedOutcome(readLiveState, desired, predicate, sleep, options, mutationOutcome) {
  try { return await bounded(readLiveState, desired, predicate, sleep, options); }
  catch (error) { error.mutationOutcome = mutationOutcome; throw error; }
}

export async function executeWorkspaceStateReconciliation({ sourceSha, preparation, authorization, provenance, readLiveState, deletePolicyVersion, createPolicyVersion, journal, reauthenticateSource, now = () => new Date(), sleep = workspaceStateProductionSleep } = {}) {
  if (![readLiveState, deletePolicyVersion, createPolicyVersion, reauthenticateSource, sleep].every(value => typeof value === "function") || !journal) throw new Error("WorkspaceState executor adapters are required.");
  const clock = typeof now === "function" ? now : () => now; const desired = readWorkspaceStateDesiredPolicy(); let iamDeleteCount = 0; let iamCreateCount = 0;
  assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock(), allowExpired: true }); assertWorkspaceStateAuthorizationProvenance(provenance, { authorization, sourceSha });
  const expected = (kind, createdAt, postState) => recordBody({ kind, preparation, authorization, provenance, createdAt, postState });
  const terminal = await journal.read(authorization, "terminal.json");
  if (terminal) { reauthenticateSource(); const current = await observe(readLiveState, desired); if (!stateMatchesPost(current, preparation)) throw new Error("Consumed WorkspaceState transaction no longer matches live IAM."); assertRecord(terminal, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_TERMINAL", terminal.createdAt, current)); return Object.freeze({ status: "CONSUMED", iamDeleteCount: 0, iamCreateCount: 0, postState: current }); }
  let reservation = await journal.read(authorization, "reservation.json");
  if (reservation) {
    try { assertRecord(reservation, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION", reservation.createdAt)); }
    catch (error) {
      assertZeroWriteReservation(reservation, preparation, authorization, provenance);
      assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() });
      const laterNames = ["deletion-attempt.json", "deletion-prewrite-failed.json", "deletion-retry-attempt.json", "deletion-complete.json", "creation-attempt.json"];
      const laterRecords = await Promise.all(laterNames.map(record => journal.read(authorization, record)));
      if (laterRecords.some(Boolean)) {
        const kinds = ["DELETION_ATTEMPT", "DELETION_PREWRITE_FAILED", "DELETION_RETRY_ATTEMPT", "DELETION_COMPLETE", "CREATION_ATTEMPT"];
        laterRecords.forEach((record, index) => { if (record) assertRecord(record, expected(`PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_${kinds[index]}`, record.createdAt)); });
        if ((laterRecords[3] || laterRecords[4]) && !laterRecords[0] || laterRecords[4] && !laterRecords[3]) throw new Error("WorkspaceState adopted reservation continuation has an invalid mutation order.");
      } else {
        assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() });
        const current = await observe(readLiveState, desired);
        if (!stateMatchesPreparation(current, preparation)) throw new Error("WorkspaceState zero-write reservation cannot be adopted after live pre-state changed.");
      }
    }
  }
  else { assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() }); reservation = await journal.create(authorization, "reservation.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION", preparation.createdAt)); if (!reservation) throw new Error("WorkspaceState reservation raced another executor."); }
  const deletionAttempt = await journal.read(authorization, "deletion-attempt.json");
  const deletionPrewriteFailed = await journal.read(authorization, "deletion-prewrite-failed.json");
  const deletionRetryAttempt = await journal.read(authorization, "deletion-retry-attempt.json");
  let deletionComplete = await journal.read(authorization, "deletion-complete.json");
  if (deletionAttempt) assertRecord(deletionAttempt, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_ATTEMPT", deletionAttempt.createdAt));
  if (deletionPrewriteFailed) assertRecord(deletionPrewriteFailed, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_PREWRITE_FAILED", deletionPrewriteFailed.createdAt));
  if (deletionRetryAttempt) assertRecord(deletionRetryAttempt, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_RETRY_ATTEMPT", deletionRetryAttempt.createdAt));
  if (deletionComplete) assertRecord(deletionComplete, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_COMPLETE", deletionComplete.createdAt));
  if ((deletionPrewriteFailed && !deletionAttempt) || (deletionRetryAttempt && !deletionPrewriteFailed) || (deletionRetryAttempt && !deletionAttempt)) throw new Error("WorkspaceState deletion retry journal is inconsistent.");
  const deleteOnce = async () => {
    try { iamDeleteCount += 1; await deletePolicyVersion({ PolicyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, VersionId: preparation.deletionCandidate.versionId }); }
    catch (error) { let recovered; try { recovered = await bounded(readLiveState, desired, state => stateMatchesAfterDeletion(state, preparation), sleep, { intermediate: state => stateMatchesPreparation(state, preparation) }); } catch (observationError) { error.cause = observationError; } if (!recovered) { error.mutationOutcome = "DELETE_OUTCOME_AMBIGUOUS"; throw error; } }
  };
  if (!deletionAttempt) {
    assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() }); reauthenticateSource();
    const before = await observe(readLiveState, desired); if (!stateMatchesPreparation(before, preparation)) throw new Error("WorkspaceState final pre-deletion CAS changed after authorization.");
    const attempt = await journal.create(authorization, "deletion-attempt.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_ATTEMPT", new Date(clock()).toISOString())); if (!attempt) throw new Error("WorkspaceState deletion-attempt raced another executor.");
    reauthenticateSource();
    try {
      const latest = await bounded(readLiveState, desired, state => stateMatchesPreparation(state, preparation), sleep);
      if (!latest) throw new Error("WorkspaceState final pre-deletion CAS changed at the mutation boundary.");
    } catch (error) {
      if (error.cause instanceof WorkspaceStateRetryableObservationError) {
        const recorded = await journal.create(authorization, "deletion-prewrite-failed.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_PREWRITE_FAILED", new Date(clock()).toISOString()));
        if (!recorded) throw new Error("WorkspaceState pre-delete failure record raced another executor.", { cause: error });
        throw Object.assign(new Error("WorkspaceState pre-delete observation exhausted its retry budget; DeletePolicyVersion was not called.", { cause: error }), { mutationOutcome: "DELETE_NOT_ISSUED" });
      }
      throw error;
    }
    assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() });
    await deleteOnce();
  } else if (deletionPrewriteFailed && !deletionRetryAttempt && !deletionComplete) {
    assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() }); reauthenticateSource();
    const latest = await bounded(readLiveState, desired, state => stateMatchesPreparation(state, preparation), sleep);
    if (!latest) throw new Error("WorkspaceState final pre-deletion CAS changed during recovery.");
    assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() });
    const retryAttempt = await journal.create(authorization, "deletion-retry-attempt.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_RETRY_ATTEMPT", new Date(clock()).toISOString()));
    if (!retryAttempt) throw new Error("WorkspaceState deletion retry-attempt raced another executor.");
    await deleteOnce();
  }
  if (!deletionComplete) {
    reauthenticateSource(); const capacity = await boundedOutcome(readLiveState, desired, state => stateMatchesAfterDeletion(state, preparation), sleep, { intermediate: state => stateMatchesPreparation(state, preparation) }, "DELETE_OUTCOME_AMBIGUOUS");
    if (!capacity) throw Object.assign(new Error("WorkspaceState deletion did not converge to the exact authorized capacity state."), { mutationOutcome: "DELETE_OUTCOME_AMBIGUOUS" });
    deletionComplete = await journal.create(authorization, "deletion-complete.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_COMPLETE", new Date(clock()).toISOString())); if (!deletionComplete) throw new Error("WorkspaceState deletion completion raced another executor.");
  }
  const creationAttempt = await journal.read(authorization, "creation-attempt.json");
  if (creationAttempt) {
    assertRecord(creationAttempt, expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_CREATION_ATTEMPT", creationAttempt.createdAt)); reauthenticateSource();
    const recovered = await boundedOutcome(readLiveState, desired, state => stateMatchesPost(state, preparation), sleep, { intermediate: state => stateMatchesAfterDeletion(state, preparation) }, "CREATE_OUTCOME_AMBIGUOUS");
    if (!recovered) throw Object.assign(new Error("WorkspaceState CreatePolicyVersion outcome remains ambiguous; no retry is permitted."), { mutationOutcome: "CREATE_OUTCOME_AMBIGUOUS" });
    const completed = await journal.create(authorization, "terminal.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_TERMINAL", new Date(clock()).toISOString(), recovered)); if (!completed) throw new Error("WorkspaceState terminal consumption raced another executor.");
    return Object.freeze({ status: "EXPECTED_POST_STATE_RECOVERED", iamDeleteCount: 0, iamCreateCount: 0, postState: recovered });
  }
  reauthenticateSource(); const capacity = await observe(readLiveState, desired); if (!stateMatchesAfterDeletion(capacity, preparation)) throw new Error("WorkspaceState capacity state changed before successor publication.");
  assertWorkspaceStateAuthorization(authorization, preparation, { sourceSha, now: clock() });
  const createAttempt = await journal.create(authorization, "creation-attempt.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_CREATION_ATTEMPT", new Date(clock()).toISOString())); if (!createAttempt) throw new Error("WorkspaceState creation-attempt raced another executor.");
  let response;
  try { iamCreateCount += 1; response = await createPolicyVersion({ PolicyArn: WORKSPACE_STATE_RECONCILIATION.policyArn, PolicyDocument: desired.document, SetAsDefault: true }); }
  catch (error) { let recovered; try { recovered = await bounded(readLiveState, desired, state => stateMatchesPost(state, preparation), sleep, { intermediate: state => stateMatchesAfterDeletion(state, preparation) }); } catch (observationError) { error.cause = observationError; } if (!recovered) { error.mutationOutcome = "CREATE_OUTCOME_AMBIGUOUS"; throw error; } response = { PolicyVersion: { VersionId: recovered.defaultVersionId } }; }
  if (!VERSION.test(response?.PolicyVersion?.VersionId || "")) throw Object.assign(new Error("WorkspaceState CreatePolicyVersion response is ambiguous."), { mutationOutcome: "CREATE_OUTCOME_AMBIGUOUS" });
  const post = await boundedOutcome(readLiveState, desired, state => stateMatchesPost(state, preparation) && state.defaultVersionId === response.PolicyVersion.VersionId, sleep, { intermediate: state => stateMatchesAfterDeletion(state, preparation) }, "CREATE_OUTCOME_AMBIGUOUS");
  if (!post) throw Object.assign(new Error("WorkspaceState successor did not converge to the exact declared contract."), { mutationOutcome: "CREATE_OUTCOME_AMBIGUOUS" });
  const completed = await journal.create(authorization, "terminal.json", expected("PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_TERMINAL", new Date(clock()).toISOString(), post)); if (!completed) throw new Error("WorkspaceState terminal consumption raced another executor.");
  return Object.freeze({ status: "COMPLETED", iamDeleteCount, iamCreateCount, postState: post, terminal: completed });
}
