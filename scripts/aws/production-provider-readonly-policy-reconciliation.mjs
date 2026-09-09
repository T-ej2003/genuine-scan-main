import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import JSZip from "jszip";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity, createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { canonicalJson, PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const RUN_ID = /^[1-9][0-9]*$/;
const WORKER_SID = "ReadExactStageBWorkerPublicationImage";
const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : canonicalJson(value)).digest("hex");
const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`);
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const iso = (value, label) => { const parsed = new Date(value); if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) throw new Error(`${label} is invalid.`); return parsed; };

export const PROVIDER_READONLY_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION",
  account: "368992683803",
  region: "eu-west-2",
  policyName: "MSCQRProductionGreenStageBProviderReadOnly",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBProviderReadOnly",
  sourcePath: "documents/ops/iam/MSCQRProductionGreenStageBProviderReadOnly-v1.json",
  releaseRoleName: "mscqr-production-release-deployer",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  executorRoleName: "mscqr-production-initial-activation-policy-reconciler",
  executorRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler",
  workflowPath: ".github/workflows/authorize-production-provider-readonly-policy-reconciliation.yml",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-provider-readonly-policy-reconciliation.yml@refs/heads/main",
  executionWorkflowRef: "T-ej2003/genuine-scan-main/.github/workflows/execute-production-provider-readonly-policy-reconciliation.yml@refs/heads/main",
  artifactName: "production-provider-readonly-policy-reconciliation-authorization",
  authorizationFilename: "authorization.json",
  journalBucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
  journalPrefix: "production-provider-readonly-policy-reconciliation/",
  maxAgeMs: 30 * 60 * 1000,
  maxPolicyVersionsBeforeCreate: 4,
  retentionRule: "NONE_FAIL_CLOSED",
  ambiguousWriteReadDelaysMs: Object.freeze([100, 300]),
  postWriteReadDelaysMs: Object.freeze([100, 200, 400, 800, 1000]),
});

export const providerReadonlyProductionSleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export function readProviderReadonlyDesiredPolicy({ repositoryRoot = root } = {}) {
  const document = normalizeIamPolicyDocument(fs.readFileSync(path.resolve(repositoryRoot, PROVIDER_READONLY_RECONCILIATION.sourcePath), "utf8"), "ProviderReadOnly source policy");
  const worker = document.Statement?.filter(({ Sid }) => Sid === WORKER_SID) || [];
  if (worker.length !== 1 || canonicalJson(worker[0]) !== canonicalJson({ Sid: WORKER_SID, Effect: "Allow", Action: "ecr:DescribeImages", Resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker", Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } })) throw new Error("ProviderReadOnly source policy does not contain the exact reviewed worker statement.");
  const predecessorDocument = { ...document, Statement: document.Statement.filter(({ Sid }) => Sid !== WORKER_SID) };
  return Object.freeze({ sourcePath: PROVIDER_READONLY_RECONCILIATION.sourcePath, document, sourcePolicySha256: sha256(document), predecessorDocument, predecessorPolicySha256: sha256(predecessorDocument) });
}

const normalizeVersions = (versions) => {
  if (!Array.isArray(versions) || versions.length < 1 || versions.length > 5) throw new Error("ProviderReadOnly policy version inventory is invalid.");
  const normalized = versions.map(({ versionId, isDefault }) => {
    if (!VERSION.test(versionId || "") || typeof isDefault !== "boolean") throw new Error("ProviderReadOnly policy version identity is invalid.");
    return { versionId, isDefault };
  }).sort((a, b) => Number(a.versionId.slice(1)) - Number(b.versionId.slice(1)));
  if (new Set(normalized.map(({ versionId }) => versionId)).size !== normalized.length || normalized.filter(({ isDefault }) => isDefault).length !== 1) throw new Error("ProviderReadOnly policy version topology is ambiguous.");
  return normalized;
};

export function authenticateProviderReadonlyLiveState(value, { desired = readProviderReadonlyDesiredPolicy(), allowPostState = true } = {}) {
  exactKeys(value, ["policyArn", "defaultVersionId", "document", "versions", "attachedRoles", "attachedUsers", "attachedGroups", "permissionsBoundaryUsageCount"], "ProviderReadOnly live state");
  const versions = normalizeVersions(value.versions);
  const document = normalizeIamPolicyDocument(value.document, "ProviderReadOnly live policy");
  const documentSha256 = sha256(document);
  const attachedRoles = [...value.attachedRoles].sort(); const attachedUsers = [...value.attachedUsers].sort(); const attachedGroups = [...value.attachedGroups].sort();
  if (value.policyArn !== PROVIDER_READONLY_RECONCILIATION.policyArn || !VERSION.test(value.defaultVersionId || "") || versions.find(({ isDefault }) => isDefault)?.versionId !== value.defaultVersionId || canonicalJson(attachedRoles) !== canonicalJson([PROVIDER_READONLY_RECONCILIATION.releaseRoleName]) || attachedUsers.length || attachedGroups.length || value.permissionsBoundaryUsageCount !== 0) throw new Error("ProviderReadOnly target or attachment topology is invalid.");
  const pre = documentSha256 === desired.predecessorPolicySha256;
  const post = allowPostState && documentSha256 === desired.sourcePolicySha256;
  if (!pre && !post) throw new Error("ProviderReadOnly live policy contains unexpected drift.");
  return Object.freeze({ ...value, document, versions, attachedRoles, attachedUsers, attachedGroups, documentSha256, versionInventorySha256: sha256(versions), attachmentTopologySha256: sha256({ roles: attachedRoles, users: attachedUsers, groups: attachedGroups, permissionsBoundaryUsageCount: 0 }), status: post ? "EXPECTED_POST_STATE" : "AUTHENTICATED_PRE_STATE" });
}

const delta = Object.freeze({ add: Object.freeze([{ effect: "Allow", action: "ecr:DescribeImages", resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker", condition: Object.freeze({ StringEquals: Object.freeze({ "aws:RequestedRegion": "eu-west-2" }) }) }]), remove: Object.freeze([]), change: Object.freeze([]) });
export const providerReadonlyOperationId = ({ sourceSha, currentDefaultVersionId, currentDefaultDocumentSha256, desiredDocumentSha256, versionInventorySha256, attachmentTopologySha256 } = {}) => sha256({
  schemaVersion: PROVIDER_READONLY_RECONCILIATION.schemaVersion,
  operation: PROVIDER_READONLY_RECONCILIATION.operation,
  account: PROVIDER_READONLY_RECONCILIATION.account,
  targetPolicyArn: PROVIDER_READONLY_RECONCILIATION.policyArn,
  sourceSha,
  currentDefaultVersionId,
  currentDefaultDocumentSha256,
  desiredDocumentSha256,
  versionInventorySha256,
  attachmentTopologySha256,
});
const preparationBody = ({ sourceSha, state, desired, preparedAt }) => {
  const created = iso(preparedAt, "ProviderReadOnly preparation createdAt");
  const operationId = providerReadonlyOperationId({ sourceSha, currentDefaultVersionId: state.defaultVersionId, currentDefaultDocumentSha256: state.documentSha256, desiredDocumentSha256: desired.sourcePolicySha256, versionInventorySha256: state.versionInventorySha256, attachmentTopologySha256: state.attachmentTopologySha256 });
  return {
    schemaVersion: 1, kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_PREPARATION", operation: PROVIDER_READONLY_RECONCILIATION.operation, operationId,
    sourceSha, account: PROVIDER_READONLY_RECONCILIATION.account, targetPolicyArn: PROVIDER_READONLY_RECONCILIATION.policyArn, sourcePolicyPath: desired.sourcePath, sourcePolicySha256: desired.sourcePolicySha256,
    currentDefaultVersionId: state.defaultVersionId, currentDefaultDocumentSha256: state.documentSha256, desiredDocumentSha256: desired.sourcePolicySha256, semanticDelta: delta, semanticDeltaSha256: sha256(delta),
    versionInventory: state.versions, versionInventorySha256: state.versionInventorySha256, policyVersionCount: state.versions.length, versionLimitReached: state.versions.length === 5, deletionRequired: false, deletionCandidate: null, deletionPolicySource: PROVIDER_READONLY_RECONCILIATION.retentionRule,
    attachmentTopology: { roles: state.attachedRoles, users: state.attachedUsers, groups: state.attachedGroups, permissionsBoundaryUsageCount: 0 }, attachmentTopologySha256: state.attachmentTopologySha256,
    expectedWritePlan: [{ action: "iam:CreatePolicyVersion", policyArn: PROVIDER_READONLY_RECONCILIATION.policyArn, policyDocumentSha256: desired.sourcePolicySha256, setAsDefault: true }], expectedWritePlanSha256: sha256([{ action: "iam:CreatePolicyVersion", policyArn: PROVIDER_READONLY_RECONCILIATION.policyArn, policyDocumentSha256: desired.sourcePolicySha256, setAsDefault: true }]),
    createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + PROVIDER_READONLY_RECONCILIATION.maxAgeMs).toISOString(), preparationEligible: true,
  };
};
const PREPARATION_FIELDS = ["schemaVersion", "kind", "operation", "operationId", "sourceSha", "account", "targetPolicyArn", "sourcePolicyPath", "sourcePolicySha256", "currentDefaultVersionId", "currentDefaultDocumentSha256", "desiredDocumentSha256", "semanticDelta", "semanticDeltaSha256", "versionInventory", "versionInventorySha256", "policyVersionCount", "versionLimitReached", "deletionRequired", "deletionCandidate", "deletionPolicySource", "attachmentTopology", "attachmentTopologySha256", "expectedWritePlan", "expectedWritePlanSha256", "createdAt", "expiresAt", "preparationEligible", "preparationSha256"];

export function createProviderReadonlyPreparation({ sourceSha, liveState, desired = readProviderReadonlyDesiredPolicy(), preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "")) throw new Error("ProviderReadOnly preparation source SHA is invalid.");
  const state = authenticateProviderReadonlyLiveState(liveState, { desired, allowPostState: false });
  if (state.status !== "AUTHENTICATED_PRE_STATE") throw new Error("ProviderReadOnly preparation requires the exact predecessor policy.");
  if (state.versions.length > PROVIDER_READONLY_RECONCILIATION.maxPolicyVersionsBeforeCreate) throw new Error("ProviderReadOnly policy has five versions and no reviewed retention rule; preparation is ineligible.");
  const body = preparationBody({ sourceSha, state, desired, preparedAt });
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}

export function assertProviderReadonlyPreparation(value, { sourceSha, desired = readProviderReadonlyDesiredPolicy(), now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, PREPARATION_FIELDS, "ProviderReadOnly preparation");
  const body = { ...value }; delete body.preparationSha256;
  const versions = normalizeVersions(value.versionInventory);
  const expectedOperationId = providerReadonlyOperationId({ sourceSha, currentDefaultVersionId: value.currentDefaultVersionId, currentDefaultDocumentSha256: value.currentDefaultDocumentSha256, desiredDocumentSha256: value.desiredDocumentSha256, versionInventorySha256: value.versionInventorySha256, attachmentTopologySha256: value.attachmentTopologySha256 });
  if (!value || value.schemaVersion !== 1 || value.kind !== "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_PREPARATION" || value.operation !== PROVIDER_READONLY_RECONCILIATION.operation || value.operationId !== expectedOperationId || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "") || value.account !== PROVIDER_READONLY_RECONCILIATION.account || value.targetPolicyArn !== PROVIDER_READONLY_RECONCILIATION.policyArn || value.sourcePolicyPath !== desired.sourcePath || value.sourcePolicySha256 !== desired.sourcePolicySha256 || value.currentDefaultDocumentSha256 !== desired.predecessorPolicySha256 || value.desiredDocumentSha256 !== desired.sourcePolicySha256 || versions.find(({ isDefault }) => isDefault)?.versionId !== value.currentDefaultVersionId || value.semanticDeltaSha256 !== sha256(delta) || canonicalJson(value.semanticDelta) !== canonicalJson(delta) || value.versionLimitReached !== false || value.deletionRequired !== false || value.deletionCandidate !== null || value.deletionPolicySource !== "NONE_FAIL_CLOSED" || value.policyVersionCount !== versions.length || value.policyVersionCount < 1 || value.policyVersionCount > 4 || value.versionInventorySha256 !== sha256(versions) || value.attachmentTopologySha256 !== sha256(value.attachmentTopology) || canonicalJson(value.attachmentTopology) !== canonicalJson({ roles: [PROVIDER_READONLY_RECONCILIATION.releaseRoleName], users: [], groups: [], permissionsBoundaryUsageCount: 0 }) || canonicalJson(value.expectedWritePlan) !== canonicalJson([{ action: "iam:CreatePolicyVersion", policyArn: PROVIDER_READONLY_RECONCILIATION.policyArn, policyDocumentSha256: desired.sourcePolicySha256, setAsDefault: true }]) || value.expectedWritePlanSha256 !== sha256(value.expectedWritePlan) || value.preparationEligible !== true || !SHA256.test(value.preparationSha256 || "") || value.preparationSha256 !== sha256(body)) throw new Error("ProviderReadOnly preparation binding is invalid.");
  const created = iso(value.createdAt, "ProviderReadOnly preparation createdAt"); const expires = iso(value.expiresAt, "ProviderReadOnly preparation expiresAt"); const current = now instanceof Date ? now : new Date(now);
  if (!Number.isFinite(current.getTime()) || expires.getTime() - created.getTime() !== PROVIDER_READONLY_RECONCILIATION.maxAgeMs || current < created || (!allowExpired && current > expires)) throw new Error("ProviderReadOnly preparation is stale.");
  return value;
}

const AUTHORIZATION_FIELDS = ["schemaVersion", "kind", "operation", "operationId", "sourceSha", "account", "targetPolicyArn", "sourcePolicySha256", "currentDefaultVersionId", "currentDefaultDocumentSha256", "desiredDocumentSha256", "semanticDeltaSha256", "versionInventorySha256", "deletionRequired", "deletionCandidate", "attachmentTopologySha256", "expectedWritePlanSha256", "preparationSha256", "expiresAt", "approvedBy", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationConsumed", "authorizationSha256"];

export function createProviderReadonlyAuthorization({ preparation, protectedEnvironmentApprovalEvidence, now = new Date() } = {}) {
  const checked = assertProviderReadonlyPreparation(preparation, { sourceSha: preparation?.sourceSha, now });
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha: checked.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  assertProductionEnvironmentApprovalFreshness(protectedEnvironmentApprovalEvidence, { now });
  if (protectedEnvironmentApprovalEvidence.schemaVersion !== 3 || protectedEnvironmentApprovalEvidence.workflowRef !== PROVIDER_READONLY_RECONCILIATION.workflowRef) throw new Error("ProviderReadOnly authorization requires its dedicated protected workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha: checked.sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  const body = { schemaVersion: 1, kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_AUTHORIZATION", operation: checked.operation, operationId: checked.operationId, sourceSha: checked.sourceSha, account: checked.account, targetPolicyArn: checked.targetPolicyArn, sourcePolicySha256: checked.sourcePolicySha256, currentDefaultVersionId: checked.currentDefaultVersionId, currentDefaultDocumentSha256: checked.currentDefaultDocumentSha256, desiredDocumentSha256: checked.desiredDocumentSha256, semanticDeltaSha256: checked.semanticDeltaSha256, versionInventorySha256: checked.versionInventorySha256, deletionRequired: false, deletionCandidate: null, attachmentTopologySha256: checked.attachmentTopologySha256, expectedWritePlanSha256: checked.expectedWritePlanSha256, preparationSha256: checked.preparationSha256, expiresAt: checked.expiresAt, approvedBy, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, authorizationConsumed: false };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}

export function assertProviderReadonlyAuthorization(value, preparation, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, AUTHORIZATION_FIELDS, "ProviderReadOnly authorization");
  const checked = assertProviderReadonlyPreparation(preparation, { sourceSha, now, allowExpired });
  const body = { ...value }; delete body.authorizationSha256;
  if (!value || value.schemaVersion !== 1 || value.kind !== "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_AUTHORIZATION" || value.operation !== checked.operation || value.operationId !== checked.operationId || value.sourceSha !== checked.sourceSha || value.account !== checked.account || value.targetPolicyArn !== checked.targetPolicyArn || value.sourcePolicySha256 !== checked.sourcePolicySha256 || value.currentDefaultVersionId !== checked.currentDefaultVersionId || value.currentDefaultDocumentSha256 !== checked.currentDefaultDocumentSha256 || value.desiredDocumentSha256 !== checked.desiredDocumentSha256 || value.semanticDeltaSha256 !== checked.semanticDeltaSha256 || value.versionInventorySha256 !== checked.versionInventorySha256 || value.deletionRequired !== false || value.deletionCandidate !== null || value.attachmentTopologySha256 !== checked.attachmentTopologySha256 || value.expectedWritePlanSha256 !== checked.expectedWritePlanSha256 || value.preparationSha256 !== checked.preparationSha256 || value.expiresAt !== checked.expiresAt || value.authorizationConsumed !== false || !SHA256.test(value.authorizationSha256 || "") || value.authorizationSha256 !== sha256(body)) throw new Error("ProviderReadOnly authorization binding is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository });
  if (!allowExpired) assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PROVIDER_READONLY_RECONCILIATION.workflowRef || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin) throw new Error("ProviderReadOnly approval provenance binding is invalid.");
  return value;
}

export async function resolveProviderReadonlyAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, preparation, run = createProductionGithubCommandRunner(), now = new Date(), allowExpired = false } = {}) {
  if (!RUN_ID.test(String(workflowRunId || "")) || String(workflowRunAttempt) !== "1") throw new Error("ProviderReadOnly authorization workflow coordinates are invalid.");
  const parse = (args, label, options) => { try { return JSON.parse(run("gh", args, options)); } catch { throw new Error(`${label} is unavailable or malformed.`); } };
  const workflow = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}`], "ProviderReadOnly authorization workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.head_repository?.full_name !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || workflow.path !== PROVIDER_READONLY_RECONCILIATION.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== "1") throw new Error("ProviderReadOnly authorization workflow provenance is invalid.");
  const pages = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"], "ProviderReadOnly authorization artifacts");
  const matches = pages.flatMap((page) => page?.artifacts || []).filter((artifact) => artifact?.name === PROVIDER_READONLY_RECONCILIATION.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository?.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1) throw new Error("ProviderReadOnly authorization artifact identity is not exact.");
  const archive = Buffer.from(run("gh", ["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
  if (`sha256:${sha256(archive)}` !== matches[0].digest) throw new Error("ProviderReadOnly authorization archive digest is invalid.");
  const zip = await JSZip.loadAsync(archive); const entries = Object.values(zip.files).filter((entry) => !entry.dir);
  if (entries.length !== 1 || entries[0].name !== PROVIDER_READONLY_RECONCILIATION.authorizationFilename || (Number(entries[0].unixPermissions || 0) & 0o170000) === 0o120000) throw new Error("ProviderReadOnly authorization archive contents are not exact.");
  const bytes = Buffer.from(await entries[0].async("uint8array"));
  if (!bytes.length || bytes.length > 1024 * 1024) throw new Error("ProviderReadOnly authorization artifact payload size is invalid.");
  let authorization; try { authorization = JSON.parse(new TextDecoder("utf8", { fatal: true }).decode(bytes)); } catch { throw new Error("ProviderReadOnly authorization artifact payload is malformed."); }
  assertProviderReadonlyAuthorization(authorization, preparation, { sourceSha, now, allowExpired });
  const environment = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/environments/production`], "ProviderReadOnly environment");
  const approvals = parse(["api", `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}/approvals`], "ProviderReadOnly approvals");
  const actual = approvals.flatMap((approval) => approval?.state === "approved" ? (approval.environments || []).filter((item) => item?.id === environment.id && item?.name === "production").map(() => ({ state: "approved", environmentId: environment.id, environmentName: "production", userId: approval.user?.id, userLogin: approval.user?.login })) : []);
  if (actual.length !== 1) throw new Error("Exactly one authenticated ProviderReadOnly production approval is required.");
  const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha, workflowRef: PROVIDER_READONLY_RECONCILIATION.workflowRef, eventName: "workflow_dispatch", workflowRunId: String(workflow.id), workflowRunAttempt: "1", executionActor: workflow.actor?.login, observedAt: authorization.protectedEnvironmentApprovalEvidence.observedAt, actualApproval: actual[0] });
  if (canonicalJson(observed) !== canonicalJson(authorization.protectedEnvironmentApprovalEvidence)) throw new Error("ProviderReadOnly approval differs from authenticated GitHub provenance.");
  const provenanceBody = { schemaVersion: 1, kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE", repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, workflowPath: workflow.path, workflowRunId: String(workflow.id), workflowRunAttempt: "1", event: workflow.event, status: workflow.status, conclusion: workflow.conclusion, headSha: workflow.head_sha, artifactId: matches[0].id, artifactName: matches[0].name, artifactDigest: matches[0].digest, authorizationFileSha256: sha256(bytes), authorizationSha256: authorization.authorizationSha256, approvedBy: authorization.approvedBy };
  return Object.freeze({ authorization, provenance: Object.freeze({ ...provenanceBody, provenanceSha256: sha256(provenanceBody) }) });
}

export function assertProviderReadonlyAuthorizationProvenance(value, { authorization, sourceSha } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "repository", "workflowPath", "workflowRunId", "workflowRunAttempt", "event", "status", "conclusion", "headSha", "artifactId", "artifactName", "artifactDigest", "authorizationFileSha256", "authorizationSha256", "approvedBy", "provenanceSha256"], "ProviderReadOnly authorization provenance");
  const { provenanceSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE" || value.repository !== PRODUCTION_ENVIRONMENT_APPROVAL.repository || value.workflowPath !== PROVIDER_READONLY_RECONCILIATION.workflowPath || !RUN_ID.test(value.workflowRunId || "") || value.workflowRunAttempt !== "1" || value.workflowRunId !== authorization?.protectedEnvironmentApprovalEvidence?.workflowRunId || value.event !== "workflow_dispatch" || value.status !== "completed" || value.conclusion !== "success" || value.headSha !== sourceSha || !Number.isSafeInteger(value.artifactId) || value.artifactId < 1 || value.artifactName !== PROVIDER_READONLY_RECONCILIATION.artifactName || !/^sha256:[a-f0-9]{64}$/.test(value.artifactDigest || "") || !SHA256.test(value.authorizationFileSha256 || "") || value.authorizationSha256 !== authorization?.authorizationSha256 || value.approvedBy !== authorization?.approvedBy || provenanceSha256 !== sha256(body)) throw new Error("ProviderReadOnly authorization provenance is invalid.");
  return value;
}

export const providerReadonlyJournalKey = (operationId, record) => {
  if (!SHA256.test(operationId || "") || !["reservation.json", "write-attempt.json", "terminal.json"].includes(record)) throw new Error("ProviderReadOnly journal key is invalid.");
  return `${PROVIDER_READONLY_RECONCILIATION.journalPrefix}${operationId}/${record}`;
};

export function createProviderReadonlyJournal({ read, create } = {}) {
  if (typeof read !== "function" || typeof create !== "function") throw new Error("ProviderReadOnly journal adapters are required.");
  const get = async (authorization, record) => { const bytes = await read(providerReadonlyJournalKey(authorization.operationId, record)); if (!bytes) return null; const value = JSON.parse(new TextDecoder("utf8", { fatal: true }).decode(bytes)); if (!Buffer.from(bytes).equals(canonicalBytes(value))) throw new Error("ProviderReadOnly journal record is not canonical."); return value; };
  const put = async (authorization, record, body) => { const value = Object.freeze({ ...body, recordSha256: sha256(body) }); const bytes = canonicalBytes(value); if (!await create(providerReadonlyJournalKey(authorization.operationId, record), bytes)) return false; const captured = await read(providerReadonlyJournalKey(authorization.operationId, record)); if (!captured || !Buffer.from(captured).equals(bytes)) throw new Error("ProviderReadOnly journal write readback failed."); return value; };
  return Object.freeze({ read: get, create: put });
}

const JOURNAL_STABLE_FIELDS = ["schemaVersion", "operationId", "sourceSha", "account", "targetPolicyArn", "sourcePolicySha256", "currentDefaultVersionId", "currentDefaultDocumentSha256", "desiredDocumentSha256", "semanticDeltaSha256", "versionInventorySha256", "attachmentTopologySha256", "expectedWritePlanSha256"];
const JOURNAL_EVIDENCE_FIELDS = ["preparationSha256", "authorizationSha256", "authorizationProvenanceSha256", "createdAt"];
const JOURNAL_POST_FIELDS = ["createdPolicyVersionId", "postDefaultDocumentSha256", "postVersionInventorySha256", "status", "authorizationConsumed"];
const journalIdentity = ({ kind, authorization, provenance, preparation, createdAt, postState }) => ({ schemaVersion: 1, kind, operationId: preparation.operationId, sourceSha: preparation.sourceSha, account: preparation.account, targetPolicyArn: preparation.targetPolicyArn, sourcePolicySha256: preparation.sourcePolicySha256, preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256, authorizationProvenanceSha256: provenance.provenanceSha256, currentDefaultVersionId: preparation.currentDefaultVersionId, currentDefaultDocumentSha256: preparation.currentDefaultDocumentSha256, desiredDocumentSha256: preparation.desiredDocumentSha256, semanticDeltaSha256: preparation.semanticDeltaSha256, versionInventorySha256: preparation.versionInventorySha256, attachmentTopologySha256: preparation.attachmentTopologySha256, expectedWritePlanSha256: preparation.expectedWritePlanSha256, ...(postState ? { createdPolicyVersionId: postState.defaultVersionId, postDefaultDocumentSha256: postState.documentSha256, postVersionInventorySha256: postState.versionInventorySha256, status: "COMPLETED", authorizationConsumed: true } : {}), createdAt });
const assertJournalRecord = (value, expected, kind, { allowRefreshedEvidence = false } = {}) => {
  const { recordSha256, ...body } = value || {};
  exactKeys(value, ["kind", ...JOURNAL_STABLE_FIELDS, ...JOURNAL_EVIDENCE_FIELDS, ...(expected.status ? JOURNAL_POST_FIELDS : []), "recordSha256"], "ProviderReadOnly journal record");
  if (body.kind !== kind || recordSha256 !== sha256(body)) throw new Error("ProviderReadOnly journal record does not match the authorized transaction.");
  if (canonicalJson(body) === canonicalJson(expected)) return "EXACT_AUTHORIZATION";
  const stable = (record) => Object.fromEntries([...JOURNAL_STABLE_FIELDS, ...(expected.status ? JOURNAL_POST_FIELDS : [])].map((field) => [field, record[field]]));
  if (!allowRefreshedEvidence || canonicalJson(stable(body)) !== canonicalJson(stable(expected)) || !SHA256.test(body.preparationSha256 || "") || !SHA256.test(body.authorizationSha256 || "") || !SHA256.test(body.authorizationProvenanceSha256 || "")) throw new Error("ProviderReadOnly journal record does not match the authorized transaction.");
  iso(body.createdAt, "ProviderReadOnly journal createdAt");
  return "REFRESHED_AUTHORIZATION";
};

const waitForConvergence = async (sleep, milliseconds) => {
  if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0 || milliseconds > 1000) throw new Error("ProviderReadOnly convergence delay is invalid.");
  try { await sleep(milliseconds); }
  catch (cause) { const error = cause instanceof Error ? cause : new Error("ProviderReadOnly convergence timer failed.", { cause }); error.mutationOutcome = "WRITE_OUTCOME_AMBIGUOUS"; throw error; }
};

const stateMatchesPreparation = (state, preparation) => state.status === "AUTHENTICATED_PRE_STATE" && state.defaultVersionId === preparation.currentDefaultVersionId && state.documentSha256 === preparation.currentDefaultDocumentSha256 && state.versionInventorySha256 === preparation.versionInventorySha256 && state.attachmentTopologySha256 === preparation.attachmentTopologySha256;
const stateMatchesPost = (state, preparation) => {
  if (state.status !== "EXPECTED_POST_STATE" || state.documentSha256 !== preparation.desiredDocumentSha256 || state.defaultVersionId === preparation.currentDefaultVersionId || state.versions.length !== preparation.policyVersionCount + 1 || state.attachmentTopologySha256 !== preparation.attachmentTopologySha256) return false;
  const prepared = new Map(preparation.versionInventory.map(({ versionId }) => [versionId, false]));
  const added = state.versions.filter(({ versionId }) => !prepared.has(versionId));
  return added.length === 1 && added[0].versionId === state.defaultVersionId && added[0].isDefault === true && preparation.versionInventory.every(({ versionId }) => state.versions.some((version) => version.versionId === versionId && version.isDefault === false));
};

export async function executeProviderReadonlyReconciliation({ sourceSha, preparation, authorization, provenance, readLiveState, createPolicyVersion, journal, reauthenticateSource, now = () => new Date(), sleep = providerReadonlyProductionSleep } = {}) {
  if (![readLiveState, createPolicyVersion, reauthenticateSource, sleep].every((value) => typeof value === "function") || !journal) throw new Error("ProviderReadOnly executor adapters are required.");
  const clock = typeof now === "function" ? now : () => now;
  assertProviderReadonlyAuthorization(authorization, preparation, { sourceSha, now: clock(), allowExpired: true });
  assertProviderReadonlyAuthorizationProvenance(provenance, { authorization, sourceSha });
  const desired = readProviderReadonlyDesiredPolicy();
  const reservationExpected = journalIdentity({ kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_RESERVATION", authorization, provenance, preparation, createdAt: preparation.createdAt });
  const terminal = await journal.read(authorization, "terminal.json");
  if (terminal) {
    reauthenticateSource();
    const current = authenticateProviderReadonlyLiveState(await readLiveState(), { desired });
    if (!stateMatchesPost(current, preparation)) throw new Error("Consumed ProviderReadOnly authorization no longer matches live IAM.");
    const expected = journalIdentity({ kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_TERMINAL", authorization, provenance, preparation, createdAt: terminal.createdAt, postState: current });
    assertJournalRecord(terminal, expected, expected.kind, { allowRefreshedEvidence: true });
    return Object.freeze({ status: "CONSUMED", transactionState: "CONSUMED", iamWriteCount: 0, postState: current });
  }
  let reservation = await journal.read(authorization, "reservation.json");
  let reservationMatch = "EXACT_AUTHORIZATION";
  if (reservation) reservationMatch = assertJournalRecord(reservation, reservationExpected, reservationExpected.kind, { allowRefreshedEvidence: true });
  else {
    assertProviderReadonlyAuthorization(authorization, preparation, { sourceSha, now: clock() });
    reservation = await journal.create(authorization, "reservation.json", reservationExpected);
    if (!reservation) throw new Error("ProviderReadOnly authorization reservation raced another executor.");
  }
  const attemptExpected = journalIdentity({ kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_WRITE_ATTEMPT", authorization, provenance, preparation, createdAt: reservation.createdAt });
  const attempt = await journal.read(authorization, "write-attempt.json");
  if (attempt) {
    assertJournalRecord(attempt, attemptExpected, attemptExpected.kind);
    reauthenticateSource(); const current = authenticateProviderReadonlyLiveState(await readLiveState(), { desired });
    if (!stateMatchesPost(current, preparation)) throw Object.assign(new Error(stateMatchesPreparation(current, preparation) ? "ProviderReadOnly CreatePolicyVersion outcome remains ambiguous; no retry is permitted." : "ProviderReadOnly live IAM drifted after the write attempt."), { mutationOutcome: stateMatchesPreparation(current, preparation) ? "WRITE_OUTCOME_AMBIGUOUS" : "UNEXPECTED_IAM_DRIFT" });
    const terminalBody = journalIdentity({ kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_TERMINAL", authorization, provenance, preparation, createdAt: new Date(clock()).toISOString(), postState: current });
    const completed = await journal.create(authorization, "terminal.json", terminalBody);
    if (!completed) throw new Error("ProviderReadOnly terminal consumption raced another executor.");
    return Object.freeze({ status: "EXPECTED_POST_STATE_RECOVERED", transactionState: "COMPLETED", iamWriteCount: 0, postState: current });
  }
  // A different fresh authorization may adopt only this immutable zero-write
  // reservation. Any write-attempt remains bound to its original authorization.
  assertProviderReadonlyAuthorization(authorization, preparation, { sourceSha, now: clock() });
  reauthenticateSource();
  const before = authenticateProviderReadonlyLiveState(await readLiveState(), { desired, allowPostState: false });
  if (!stateMatchesPreparation(before, preparation)) throw new Error("ProviderReadOnly final live CAS changed after authorization.");
  reauthenticateSource();
  const latest = authenticateProviderReadonlyLiveState(await readLiveState(), { desired, allowPostState: false });
  if (!stateMatchesPreparation(latest, preparation)) throw new Error("ProviderReadOnly final live CAS changed at the write boundary.");
  reauthenticateSource();
  assertProviderReadonlyAuthorization(authorization, preparation, { sourceSha, now: clock() });
  if (!await journal.create(authorization, "write-attempt.json", attemptExpected)) throw new Error("ProviderReadOnly write-attempt reservation raced another executor.");
  let response;
  try { response = await createPolicyVersion({ PolicyArn: PROVIDER_READONLY_RECONCILIATION.policyArn, PolicyDocument: desired.document, SetAsDefault: true }); }
  catch (error) {
    for (let index = 0; index < 3; index += 1) {
      try { const observed = authenticateProviderReadonlyLiveState(await readLiveState(), { desired }); if (stateMatchesPost(observed, preparation)) { response = { PolicyVersion: { VersionId: observed.defaultVersionId } }; break; } } catch {}
      if (index < PROVIDER_READONLY_RECONCILIATION.ambiguousWriteReadDelaysMs.length) await waitForConvergence(sleep, PROVIDER_READONLY_RECONCILIATION.ambiguousWriteReadDelaysMs[index]);
    }
    if (!response) { error.mutationOutcome = "WRITE_OUTCOME_AMBIGUOUS"; throw error; }
  }
  if (!VERSION.test(response?.PolicyVersion?.VersionId || "")) throw Object.assign(new Error("ProviderReadOnly CreatePolicyVersion response is ambiguous."), { mutationOutcome: "WRITE_OUTCOME_AMBIGUOUS" });
  let post;
  for (let index = 0; index < 6; index += 1) {
    const candidate = authenticateProviderReadonlyLiveState(await readLiveState(), { desired });
    if (stateMatchesPost(candidate, preparation) && candidate.defaultVersionId === response.PolicyVersion.VersionId) { post = candidate; break; }
    if (!stateMatchesPreparation(candidate, preparation)) throw new Error("ProviderReadOnly policy entered an unexpected post-write state.");
    if (index < PROVIDER_READONLY_RECONCILIATION.postWriteReadDelaysMs.length) await waitForConvergence(sleep, PROVIDER_READONLY_RECONCILIATION.postWriteReadDelaysMs[index]);
  }
  if (!post) throw Object.assign(new Error("ProviderReadOnly policy mutation did not converge to the exact authorized post-state."), { mutationOutcome: "WRITE_OUTCOME_AMBIGUOUS" });
  const terminalBody = journalIdentity({ kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_TERMINAL", authorization, provenance, preparation, createdAt: new Date(clock()).toISOString(), postState: post });
  const completed = await journal.create(authorization, "terminal.json", terminalBody);
  if (!completed) throw new Error("ProviderReadOnly terminal consumption raced another executor.");
  return Object.freeze({ status: "COMPLETED", transactionState: "COMPLETED", reservationMatch, iamWriteCount: 1, postState: post, terminal: completed });
}
