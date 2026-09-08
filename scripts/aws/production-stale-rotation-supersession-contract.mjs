import crypto from "node:crypto";
import JSZip from "jszip";
import {
  assertProductionEnvironmentActualReviewer,
  assertProductionEnvironmentApprovalFreshness,
  assertProductionEnvironmentApprovalIdentity,
  assertProductionEnvironmentReviewer,
  PRODUCTION_ENVIRONMENT_APPROVAL,
  createProductionEnvironmentApprovalEvidence,
} from "./production-github-environment-approval.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { STALE_ROTATION_SUPERSESSION_WRITE_ORDER } from "./production-initial-dual-slot-bootstrap.mjs";

export const STALE_ROTATION_SUPERSESSION_PREPARATION_KIND = "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION_PREPARATION";
export const STALE_ROTATION_SUPERSESSION_AUTHORIZATION_KIND = "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION";
export const STALE_ROTATION_SUPERSESSION_OPERATION = "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION";
export const STALE_ROTATION_SUPERSESSION_CONSUMPTION_KIND = "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION_CONSUMPTION";
export const STALE_ROTATION_SUPERSESSION_WORKFLOW_REF = "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-stale-rotation-supersession.yml@refs/heads/main";
export const STALE_ROTATION_SUPERSESSION_WORKFLOW_PATH = ".github/workflows/authorize-production-stale-rotation-supersession.yml";
export const STALE_ROTATION_SUPERSESSION_ARTIFACT_NAME = "production-stale-rotation-supersession-authorization";
export const STALE_ROTATION_SUPERSESSION_REPOSITORY = "T-ej2003/genuine-scan-main";
export const STALE_ROTATION_SUPERSESSION_MAX_AGE_MS = 30 * 60 * 1000;

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ROTATION = /^[A-Za-z0-9._-]{8,128}$/;
const ARN = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+$/;
const TASK = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-backend:[1-9][0-9]*$/;
const IMAGE_NAMES = Object.freeze(["backend", "worker", "rlsExecutor", "rlsCanary"]);
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
export const staleRotationSupersessionSha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : canonical(value)).digest("hex");
const fail = (message) => { throw new Error(message); };
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) fail(`${label} schema is invalid.`);
  return value;
};
const date = (value, label) => {
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) fail(`${label} is invalid.`);
  return parsed;
};
const parseGithubJson = (run, args, label) => { try { return JSON.parse(run("gh", args)); } catch { fail(`${label} is malformed or unavailable.`); } };

function assertWritePlan(writePlan, resources) {
  if (!Array.isArray(writePlan) || writePlan.length !== 7) fail("Supersession write plan must contain exactly seven writes.");
  const seen = new Set();
  for (let index = 0; index < writePlan.length; index += 1) {
    const entry = exactKeys(writePlan[index], ["slot", "secretArn", "clientRequestToken", "payloadSha256"], `writePlan[${index}]`);
    const slot = STALE_ROTATION_SUPERSESSION_WRITE_ORDER[index];
    if (entry.slot !== slot || entry.secretArn !== resources[slot] || !ARN.test(entry.secretArn) || !SHA256.test(entry.clientRequestToken) || !SHA256.test(entry.payloadSha256) || seen.has(entry.secretArn)) fail("Supersession write plan is not the exact canonical seven-target plan.");
    seen.add(entry.secretArn);
  }
  return Object.freeze(writePlan.map((entry) => Object.freeze({ ...entry })));
}

export function deriveStaleRotationReplacementId({ sourceSha, staleRotationId, publicationIdentitySha256, now = new Date() } = {}) {
  if (!SHA40.test(sourceSha || "") || !ROTATION.test(staleRotationId || "") || !SHA256.test(publicationIdentitySha256 || "")) fail("Supersession replacement identity inputs are invalid.");
  const instant = date(now instanceof Date ? now.toISOString() : now, "Supersession preparation time");
  const stamp = instant.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  return `rotation-${stamp}-${staleRotationSupersessionSha256({ sourceSha, staleRotationId, publicationIdentitySha256, stamp }).slice(0, 8)}`;
}

export function createStaleRotationSupersessionPreparation({ discovery, publication, liveBackend, stageBState, preparedAt = new Date().toISOString() } = {}) {
  exactKeys(discovery, ["sourceSha", "staleSourceSha", "rotationId", "staleRotationId", "resources", "predecessorSlotIdentities", "currentPredecessor", "materialJournalFile", "materialJournalFileSha256", "writePlan"], "Supersession discovery");
  if (!SHA40.test(discovery.sourceSha || "") || !SHA40.test(discovery.staleSourceSha || "") || !ROTATION.test(discovery.rotationId || "") || !ROTATION.test(discovery.staleRotationId || "") || discovery.rotationId === discovery.staleRotationId || !SHA256.test(discovery.materialJournalFileSha256 || "")) fail("Supersession discovery identity is invalid.");
  const resources = exactKeys(discovery.resources, STALE_ROTATION_SUPERSESSION_WRITE_ORDER, "Supersession resources");
  for (const arn of Object.values(resources)) if (!ARN.test(arn)) fail("Supersession resource is outside the production namespace.");
  const writePlan = assertWritePlan(discovery.writePlan, resources);
  const checkedPublication = exactKeys(publication, ["runId", "artifactSha256", "identitySha256", "imageDigests"], "Supersession publication");
  if (!/^[1-9][0-9]*$/.test(String(checkedPublication.runId || "")) || !SHA256.test(checkedPublication.artifactSha256 || "") || !SHA256.test(checkedPublication.identitySha256 || "")) fail("Supersession publication identity is invalid.");
  exactKeys(checkedPublication.imageDigests, IMAGE_NAMES, "Supersession image digests");
  for (const digest of Object.values(checkedPublication.imageDigests)) if (!DIGEST.test(digest)) fail("Supersession image digest is invalid.");
  const checkedBackend = exactKeys(liveBackend, ["taskDefinitionArn", "imageDigest", "identitySha256"], "Supersession live backend");
  if (!TASK.test(checkedBackend.taskDefinitionArn || "") || !DIGEST.test(checkedBackend.imageDigest || "") || !SHA256.test(checkedBackend.identitySha256 || "")) fail("Supersession live backend identity is invalid.");
  const checkedState = exactKeys(stageBState, ["lineage", "serial", "stateSha256"], "Supersession Stage-B state");
  if (!/^[0-9a-f-]{36}$/.test(checkedState.lineage || "") || !Number.isSafeInteger(checkedState.serial) || checkedState.serial < 0 || !SHA256.test(checkedState.stateSha256 || "")) fail("Supersession Stage-B state identity is invalid.");
  const prepared = date(preparedAt, "Supersession preparedAt");
  const body = {
    schemaVersion: 1,
    kind: STALE_ROTATION_SUPERSESSION_PREPARATION_KIND,
    operation: STALE_ROTATION_SUPERSESSION_OPERATION,
    environment: "production",
    accountId: "368992683803",
    region: "eu-west-2",
    sourceSha: discovery.sourceSha,
    staleSourceSha: discovery.staleSourceSha,
    staleRotationId: discovery.staleRotationId,
    replacementRotationId: discovery.rotationId,
    publication: structuredClone(checkedPublication),
    liveBackend: structuredClone(checkedBackend),
    stageBState: structuredClone(checkedState),
    resources: structuredClone(resources),
    predecessorSlotIdentities: structuredClone(discovery.predecessorSlotIdentities),
    currentPredecessorIdentitySha256: discovery.currentPredecessor.predecessorIdentitySha256,
    selectorIdentitiesSha256: staleRotationSupersessionSha256({ slot: discovery.predecessorSlotIdentities, current: discovery.currentPredecessor.current }),
    materialJournalIdentity: staleRotationSupersessionSha256({ sourceSha: discovery.sourceSha, rotationId: discovery.rotationId, fileSha256: discovery.materialJournalFileSha256 }),
    materialJournalFileSha256: discovery.materialJournalFileSha256,
    writePlan,
    writePlanSha256: staleRotationSupersessionSha256(writePlan),
    preparedAt: prepared.toISOString(),
    expiresAt: new Date(prepared.getTime() + STALE_ROTATION_SUPERSESSION_MAX_AGE_MS).toISOString(),
  };
  return Object.freeze({ ...body, preparationSha256: staleRotationSupersessionSha256(body) });
}

export function assertStaleRotationSupersessionPreparation(value, { sourceSha, now = new Date() } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "environment", "accountId", "region", "sourceSha", "staleSourceSha", "staleRotationId", "replacementRotationId", "publication", "liveBackend", "stageBState", "resources", "predecessorSlotIdentities", "currentPredecessorIdentitySha256", "selectorIdentitiesSha256", "materialJournalIdentity", "materialJournalFileSha256", "writePlan", "writePlanSha256", "preparedAt", "expiresAt", "preparationSha256"];
  exactKeys(value, fields, "Supersession preparation");
  if (value.schemaVersion !== 1 || value.kind !== STALE_ROTATION_SUPERSESSION_PREPARATION_KIND || value.operation !== STALE_ROTATION_SUPERSESSION_OPERATION || value.environment !== "production" || value.accountId !== "368992683803" || value.region !== "eu-west-2" || value.sourceSha !== sourceSha || !SHA40.test(sourceSha || "")) fail("Supersession preparation identity is invalid.");
  exactKeys(value.resources, STALE_ROTATION_SUPERSESSION_WRITE_ORDER, "Supersession resources");
  for (const arn of Object.values(value.resources)) if (!ARN.test(arn)) fail("Supersession resource is outside the production namespace.");
  exactKeys(value.publication, ["runId", "artifactSha256", "identitySha256", "imageDigests"], "Supersession publication");
  exactKeys(value.publication.imageDigests, IMAGE_NAMES, "Supersession image digests");
  if (!/^[1-9][0-9]*$/.test(String(value.publication.runId || "")) || !SHA256.test(value.publication.artifactSha256 || "") || !SHA256.test(value.publication.identitySha256 || "") || Object.values(value.publication.imageDigests).some((digest) => !DIGEST.test(digest))) fail("Supersession publication identity is invalid.");
  exactKeys(value.liveBackend, ["taskDefinitionArn", "imageDigest", "identitySha256"], "Supersession live backend");
  if (!TASK.test(value.liveBackend.taskDefinitionArn || "") || !DIGEST.test(value.liveBackend.imageDigest || "") || !SHA256.test(value.liveBackend.identitySha256 || "")) fail("Supersession live backend identity is invalid.");
  exactKeys(value.stageBState, ["lineage", "serial", "stateSha256"], "Supersession Stage-B state");
  if (!/^[0-9a-f-]{36}$/.test(value.stageBState.lineage || "") || !Number.isSafeInteger(value.stageBState.serial) || value.stageBState.serial < 0 || !SHA256.test(value.stageBState.stateSha256 || "")) fail("Supersession Stage-B state identity is invalid.");
  const { preparationSha256, ...body } = value;
  if (!SHA256.test(preparationSha256 || "") || staleRotationSupersessionSha256(body) !== preparationSha256 || value.writePlanSha256 !== staleRotationSupersessionSha256(assertWritePlan(value.writePlan, value.resources))) fail("Supersession preparation hash or write plan is invalid.");
  for (const field of ["currentPredecessorIdentitySha256", "selectorIdentitiesSha256", "materialJournalIdentity", "materialJournalFileSha256"]) if (!SHA256.test(value[field] || "")) fail(`Supersession preparation ${field} is invalid.`);
  const prepared = date(value.preparedAt, "Supersession preparedAt"); const expires = date(value.expiresAt, "Supersession expiresAt"); const current = now instanceof Date ? now : new Date(now);
  if (expires.getTime() - prepared.getTime() !== STALE_ROTATION_SUPERSESSION_MAX_AGE_MS || current < prepared || current > expires) fail("Supersession preparation is expired or not yet valid.");
  return value;
}

export function createPendingStaleRotationSupersessionAuthorization(preparation) {
  const checked = assertStaleRotationSupersessionPreparation(preparation, { sourceSha: preparation?.sourceSha, now: preparation?.preparedAt });
  const body = { schemaVersion: 1, kind: STALE_ROTATION_SUPERSESSION_AUTHORIZATION_KIND, operation: STALE_ROTATION_SUPERSESSION_OPERATION, sourceSha: checked.sourceSha, preparationSha256: checked.preparationSha256, staleRotationId: checked.staleRotationId, staleSourceSha: checked.staleSourceSha, replacementRotationId: checked.replacementRotationId, materialJournalIdentity: checked.materialJournalIdentity, writePlanSha256: checked.writePlanSha256, publicationIdentitySha256: checked.publication.identitySha256, imageDigests: checked.publication.imageDigests, liveBackendIdentitySha256: checked.liveBackend.identitySha256, stageBState: checked.stageBState, requiredReviewer: "T-ej2003", authorizationStatus: "PENDING", approvalStatus: "PENDING", approvedBy: "UNSET", approvedAt: null, authorizationConsumed: false };
  return Object.freeze({ ...body, authorizationSha256: staleRotationSupersessionSha256(body) });
}

export function createApprovedStaleRotationSupersessionAuthorization({ pendingAuthorization, preparation, protectedEnvironmentApprovalEvidence } = {}) {
  const pending = assertPendingStaleRotationSupersessionAuthorization(pendingAuthorization, preparation);
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha: pending.sourceSha, repository: STALE_ROTATION_SUPERSESSION_REPOSITORY });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== STALE_ROTATION_SUPERSESSION_WORKFLOW_REF) fail("Supersession approval requires the dedicated protected-environment workflow.");
  const approvedBy = assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha: pending.sourceSha, repository: STALE_ROTATION_SUPERSESSION_REPOSITORY, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  assertProductionEnvironmentReviewer(protectedEnvironmentApprovalEvidence, { approvedBy, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  if (approvedBy.toLowerCase() !== pending.requiredReviewer.toLowerCase()) fail("Supersession authorization reviewer is not the exact required production operator.");
  const { authorizationSha256: _pendingSha, authorizationStatus: _as, approvalStatus: _ps, approvedBy: _by, approvedAt: _at, ...bound } = pending;
  const body = { ...bound, authorizationStatus: "APPROVED", approvalStatus: "APPROVED", approvedBy, approvedAt: protectedEnvironmentApprovalEvidence.observedAt, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: staleRotationSupersessionSha256(body) });
}

export function assertPendingStaleRotationSupersessionAuthorization(value, preparation) {
  const checked = assertStaleRotationSupersessionPreparation(preparation, { sourceSha: preparation?.sourceSha, now: preparation?.preparedAt });
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "preparationSha256", "staleRotationId", "staleSourceSha", "replacementRotationId", "materialJournalIdentity", "writePlanSha256", "publicationIdentitySha256", "imageDigests", "liveBackendIdentitySha256", "stageBState", "requiredReviewer", "authorizationStatus", "approvalStatus", "approvedBy", "approvedAt", "authorizationConsumed", "authorizationSha256"], "Pending supersession authorization");
  if (!value || value.kind !== STALE_ROTATION_SUPERSESSION_AUTHORIZATION_KIND || value.authorizationStatus !== "PENDING" || value.approvalStatus !== "PENDING" || value.approvedBy !== "UNSET" || value.approvedAt !== null || value.authorizationConsumed !== false) fail("Supersession authorization is not pending and unconsumed.");
  const { authorizationSha256, ...body } = value;
  if (!SHA256.test(authorizationSha256 || "") || staleRotationSupersessionSha256(body) !== authorizationSha256) fail("Supersession authorization hash is invalid.");
  assertAuthorizationBindings(value, checked);
  return value;
}

function assertAuthorizationBindings(value, preparation) {
  if (value.sourceSha !== preparation.sourceSha || value.preparationSha256 !== preparation.preparationSha256 || value.staleRotationId !== preparation.staleRotationId || value.staleSourceSha !== preparation.staleSourceSha || value.replacementRotationId !== preparation.replacementRotationId || value.materialJournalIdentity !== preparation.materialJournalIdentity || value.writePlanSha256 !== preparation.writePlanSha256 || value.publicationIdentitySha256 !== preparation.publication.identitySha256 || canonical(value.imageDigests) !== canonical(preparation.publication.imageDigests) || value.liveBackendIdentitySha256 !== preparation.liveBackend.identitySha256 || canonical(value.stageBState) !== canonical(preparation.stageBState) || value.requiredReviewer !== "T-ej2003" || value.authorizationConsumed !== false) fail("Supersession authorization is bound to a different prepared transaction.");
}

export function assertApprovedStaleRotationSupersessionAuthorization(value, preparation, { sourceSha, materialJournalFileSha256, now = new Date() } = {}) {
  const checked = assertStaleRotationSupersessionPreparation(preparation, { sourceSha, now });
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "preparationSha256", "staleRotationId", "staleSourceSha", "replacementRotationId", "materialJournalIdentity", "writePlanSha256", "publicationIdentitySha256", "imageDigests", "liveBackendIdentitySha256", "stageBState", "requiredReviewer", "authorizationConsumed", "authorizationStatus", "approvalStatus", "approvedBy", "approvedAt", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"], "Approved supersession authorization");
  if (!value || value.authorizationStatus !== "APPROVED" || value.approvalStatus !== "APPROVED" || value.approvedBy !== "T-ej2003" || !value.approvedAt || value.authorizationConsumed !== false) fail("Supersession authorization is not exactly approved and unconsumed.");
  const { authorizationSha256, ...body } = value;
  if (!SHA256.test(authorizationSha256 || "") || staleRotationSupersessionSha256(body) !== authorizationSha256) fail("Supersession authorization hash is invalid.");
  assertAuthorizationBindings(value, checked);
  if (materialJournalFileSha256 !== checked.materialJournalFileSha256) fail("Supersession material journal differs from the approved preparation.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: STALE_ROTATION_SUPERSESSION_REPOSITORY });
  assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== STALE_ROTATION_SUPERSESSION_WORKFLOW_REF || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin !== value.approvedBy) fail("Supersession protected-environment approval binding is invalid.");
  return value;
}

export function assertStaleRotationSupersessionAuthorizationProvenance(value, { authorization, sourceSha } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "repository", "workflowPath", "workflowRunId", "workflowRunAttempt", "event", "headSha", "status", "conclusion", "artifactId", "artifactName", "artifactDigest", "authorizationFileSha256", "authorizationSha256", "approvedBy", "provenanceSha256"], "Supersession authorization provenance");
  const { provenanceSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION_AUTHORIZATION_PROVENANCE" || value.repository !== STALE_ROTATION_SUPERSESSION_REPOSITORY || value.workflowPath !== STALE_ROTATION_SUPERSESSION_WORKFLOW_PATH || !/^[1-9][0-9]*$/.test(value.workflowRunId || "") || !/^[1-9][0-9]*$/.test(value.workflowRunAttempt || "") || value.workflowRunId !== authorization?.protectedEnvironmentApprovalEvidence?.workflowRunId || value.workflowRunAttempt !== authorization?.protectedEnvironmentApprovalEvidence?.workflowRunAttempt || value.event !== "workflow_dispatch" || value.headSha !== sourceSha || value.status !== "completed" || value.conclusion !== "success" || !Number.isSafeInteger(value.artifactId) || value.artifactId < 1 || value.artifactName !== STALE_ROTATION_SUPERSESSION_ARTIFACT_NAME || !/^sha256:[a-f0-9]{64}$/.test(value.artifactDigest || "") || !SHA256.test(value.authorizationFileSha256 || "") || value.authorizationSha256 !== authorization?.authorizationSha256 || value.approvedBy !== authorization?.approvedBy || !SHA256.test(provenanceSha256 || "") || staleRotationSupersessionSha256(body) !== provenanceSha256) fail("Supersession authorization provenance is invalid.");
  return value;
}

export async function resolveStaleRotationSupersessionAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, preparation, run = createProductionGithubCommandRunner(), now = new Date() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "")) fail("Supersession authorization workflow coordinates are invalid.");
  const workflow = parseGithubJson(run, ["api", `repos/${STALE_ROTATION_SUPERSESSION_REPOSITORY}/actions/runs/${workflowRunId}`], "Supersession authorization workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== STALE_ROTATION_SUPERSESSION_REPOSITORY || workflow.head_repository?.full_name !== STALE_ROTATION_SUPERSESSION_REPOSITORY || workflow.path !== STALE_ROTATION_SUPERSESSION_WORKFLOW_PATH || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) fail("Supersession authorization workflow provenance is not authentic.");
  const pages = parseGithubJson(run, ["api", `repos/${STALE_ROTATION_SUPERSESSION_REPOSITORY}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"], "Supersession authorization artifacts");
  const matches = (Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : []).filter((artifact) => artifact?.name === STALE_ROTATION_SUPERSESSION_ARTIFACT_NAME && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository?.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id) || matches[0].id < 1) fail("Supersession authorization artifact identity is not exact.");
  const archiveBytes = Buffer.from(run("gh", ["api", `repos/${STALE_ROTATION_SUPERSESSION_REPOSITORY}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 }));
  if (archiveBytes.length === 0 || archiveBytes.length > 64 * 1024 * 1024 || `sha256:${staleRotationSupersessionSha256(archiveBytes)}` !== matches[0].digest) fail("Supersession authorization archive digest is invalid.");
  const zip = await JSZip.loadAsync(archiveBytes);
  const entries = Object.values(zip.files).filter((entry) => !entry.dir);
  if (entries.length !== 1 || entries[0].name !== "authorization.json" || (Number(entries[0].unixPermissions || 0) & 0o170000) === 0o120000) fail("Supersession authorization archive contents are not exact.");
  const authorizationBytes = Buffer.from(await entries[0].async("uint8array"));
  if (authorizationBytes.length === 0 || authorizationBytes.length > 1024 * 1024) fail("Supersession authorization artifact payload size is invalid.");
  let authorization;
  try { authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(authorizationBytes)); } catch { fail("Supersession authorization artifact payload is malformed."); }
  assertApprovedStaleRotationSupersessionAuthorization(authorization, preparation, { sourceSha, materialJournalFileSha256: preparation?.materialJournalFileSha256, now });
  const environment = parseGithubJson(run, ["api", `repos/${STALE_ROTATION_SUPERSESSION_REPOSITORY}/environments/production`], "Supersession authorization environment");
  const approvals = parseGithubJson(run, ["api", `repos/${STALE_ROTATION_SUPERSESSION_REPOSITORY}/actions/runs/${workflowRunId}/approvals`], "Supersession authorization approvals");
  const actual = (Array.isArray(approvals) ? approvals : []).flatMap((approval) => approval?.state === "approved" ? (approval.environments || []).filter((item) => item?.id === environment.id && item?.name === "production").map(() => ({ state: "approved", environmentId: environment.id, environmentName: "production", userId: approval.user?.id, userLogin: approval.user?.login })) : []);
  if (actual.length !== 1) fail("Exactly one authenticated supersession production approval is required.");
  const observedApproval = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: STALE_ROTATION_SUPERSESSION_REPOSITORY, environment: "production", sourceSha, workflowRef: STALE_ROTATION_SUPERSESSION_WORKFLOW_REF, eventName: "workflow_dispatch", workflowRunId: String(workflow.id), workflowRunAttempt: String(workflow.run_attempt), executionActor: workflow.actor?.login, observedAt: authorization.protectedEnvironmentApprovalEvidence.observedAt, actualApproval: actual[0] });
  if (canonical(observedApproval) !== canonical(authorization.protectedEnvironmentApprovalEvidence)) fail("Supersession approval differs from authenticated GitHub provenance.");
  const provenanceBody = { schemaVersion: 1, kind: "PRODUCTION_STALE_PENDING_ROTATION_SUPERSESSION_AUTHORIZATION_PROVENANCE", repository: STALE_ROTATION_SUPERSESSION_REPOSITORY, workflowPath: STALE_ROTATION_SUPERSESSION_WORKFLOW_PATH, workflowRunId: String(workflow.id), workflowRunAttempt: String(workflow.run_attempt), event: workflow.event, headSha: workflow.head_sha, status: workflow.status, conclusion: workflow.conclusion, artifactId: matches[0].id, artifactName: matches[0].name, artifactDigest: matches[0].digest, authorizationFileSha256: staleRotationSupersessionSha256(authorizationBytes), authorizationSha256: authorization.authorizationSha256, approvedBy: authorization.approvedBy };
  const provenance = Object.freeze({ ...provenanceBody, provenanceSha256: staleRotationSupersessionSha256(provenanceBody) });
  assertStaleRotationSupersessionAuthorizationProvenance(provenance, { authorization, sourceSha });
  return Object.freeze({ workflow, artifact: matches[0], authorization, provenance });
}

export function createStaleRotationSupersessionConsumption({ authorization, authorizationProvenance, preparation, supersessionEvidenceSha256, rotationBindingSha256, consumedAt = new Date().toISOString() } = {}) {
  assertStaleRotationSupersessionAuthorizationProvenance(authorizationProvenance, { authorization, sourceSha: preparation?.sourceSha });
  if (!SHA256.test(authorization?.authorizationSha256 || "") || !SHA256.test(preparation?.preparationSha256 || "") || !SHA256.test(supersessionEvidenceSha256 || "") || !SHA256.test(rotationBindingSha256 || "")) fail("Supersession consumption inputs are invalid.");
  const terminalExecutionIdentitySha256 = staleRotationSupersessionSha256({ authorizationProvenanceSha256: authorizationProvenance.provenanceSha256, preparationSha256: preparation.preparationSha256, materialJournalIdentity: preparation.materialJournalIdentity, materialJournalFileSha256: preparation.materialJournalFileSha256, writePlanSha256: preparation.writePlanSha256, supersessionEvidenceSha256, rotationBindingSha256 });
  const body = { schemaVersion: 2, kind: STALE_ROTATION_SUPERSESSION_CONSUMPTION_KIND, sourceSha: preparation.sourceSha, staleRotationId: preparation.staleRotationId, replacementRotationId: preparation.replacementRotationId, preparationSha256: preparation.preparationSha256, authorizationSha256: authorization.authorizationSha256, authorizationProvenanceSha256: authorizationProvenance.provenanceSha256, materialJournalIdentity: preparation.materialJournalIdentity, materialJournalFileSha256: preparation.materialJournalFileSha256, writePlanSha256: preparation.writePlanSha256, supersessionEvidenceSha256, rotationBindingSha256, terminalState: "COMPLETE", terminalExecutionIdentitySha256, authorizationConsumed: true, consumedAt: date(consumedAt, "Supersession consumedAt").toISOString() };
  return Object.freeze({ ...body, consumptionSha256: staleRotationSupersessionSha256(body) });
}

export function assertStaleRotationSupersessionConsumption(value, { authorization, authorizationProvenance, preparation } = {}) {
  assertStaleRotationSupersessionAuthorizationProvenance(authorizationProvenance, { authorization, sourceSha: preparation?.sourceSha });
  exactKeys(value, ["schemaVersion", "kind", "sourceSha", "staleRotationId", "replacementRotationId", "preparationSha256", "authorizationSha256", "authorizationProvenanceSha256", "materialJournalIdentity", "materialJournalFileSha256", "writePlanSha256", "supersessionEvidenceSha256", "rotationBindingSha256", "terminalState", "terminalExecutionIdentitySha256", "authorizationConsumed", "consumedAt", "consumptionSha256"], "Supersession consumption");
  const { consumptionSha256, ...body } = value;
  const terminalExecutionIdentitySha256 = staleRotationSupersessionSha256({ authorizationProvenanceSha256: authorizationProvenance?.provenanceSha256, preparationSha256: preparation?.preparationSha256, materialJournalIdentity: preparation?.materialJournalIdentity, materialJournalFileSha256: preparation?.materialJournalFileSha256, writePlanSha256: preparation?.writePlanSha256, supersessionEvidenceSha256: value.supersessionEvidenceSha256, rotationBindingSha256: value.rotationBindingSha256 });
  if (value.schemaVersion !== 2 || value.kind !== STALE_ROTATION_SUPERSESSION_CONSUMPTION_KIND || value.authorizationConsumed !== true || value.terminalState !== "COMPLETE" || value.sourceSha !== preparation?.sourceSha || value.staleRotationId !== preparation?.staleRotationId || value.replacementRotationId !== preparation?.replacementRotationId || value.preparationSha256 !== preparation?.preparationSha256 || value.authorizationSha256 !== authorization?.authorizationSha256 || value.authorizationProvenanceSha256 !== authorizationProvenance?.provenanceSha256 || value.materialJournalIdentity !== preparation?.materialJournalIdentity || value.materialJournalFileSha256 !== preparation?.materialJournalFileSha256 || value.writePlanSha256 !== preparation?.writePlanSha256 || !SHA256.test(value.supersessionEvidenceSha256 || "") || !SHA256.test(value.rotationBindingSha256 || "") || value.terminalExecutionIdentitySha256 !== terminalExecutionIdentitySha256 || !SHA256.test(consumptionSha256 || "") || staleRotationSupersessionSha256(body) !== consumptionSha256) fail("Supersession consumption binding is invalid.");
  date(value.consumedAt, "Supersession consumedAt");
  return value;
}
