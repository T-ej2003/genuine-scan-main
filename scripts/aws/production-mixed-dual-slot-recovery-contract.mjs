import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalIdentity, PRODUCTION_ENVIRONMENT_APPROVAL } from "./production-github-environment-approval.mjs";

export const MIXED_DUAL_SLOT_RECOVERY_OPERATION = "PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY";
export const MIXED_DUAL_SLOT_RECOVERY_PREPARATION_KIND = "PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY_PREPARATION";
export const MIXED_DUAL_SLOT_RECOVERY_AUTHORIZATION_KIND = "PRODUCTION_MIXED_DUAL_SLOT_TOPOLOGY_RECOVERY_AUTHORIZATION";
export const MIXED_DUAL_SLOT_RECOVERY_SOURCE = "4e64a3bf8a62c1b1071b7c98fa42015fdd039f95";
export const MIXED_DUAL_SLOT_RECOVERY_ROTATION = "rotation-20260907175920-efd1f0f7";
export const MIXED_DUAL_SLOT_RECOVERY_REPOSITORY = "T-ej2003/genuine-scan-main";
export const MIXED_DUAL_SLOT_RECOVERY_ARTIFACT = "production-mixed-dual-slot-topology-recovery-authorization";
export const MIXED_DUAL_SLOT_RECOVERY_POST_STATE = "SEVEN_EXISTING_RESOURCES_WITHOUT_AWSCURRENT";
export const MIXED_DUAL_SLOT_RECOVERY_MAX_AGE_MS = PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs;
export const MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR = Object.freeze({
  cluster: "mscqr-prod-euw2-main", service: "mscqr-backend-servi-euw2",
  taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:52",
  backendImage: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:b55ffef21cd794a1fefb0f0da3b56e70a727d44818a9d0a5f1c26d3e1d2e1b3e",
  legacySecretArns: Object.freeze([
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex",
  ]),
});
export const MIXED_DUAL_SLOT_RECOVERY_ORDER = Object.freeze(["jwtPending", "qrPrivatePending", "qrPublicPending", "jwtPrevious", "qrPublicPrevious", "qrCurrentVersion", "qrPreviousVersion"]);

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ARN = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+$/;
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
export const mixedDualSlotRecoverySha256 = (value) => crypto.createHash("sha256").update(canonical(value)).digest("hex");
const fail = (message) => { throw new Error(message); };
const exactKeys = (value, keys, label) => { if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...keys].sort())) fail(`${label} schema is invalid.`); return value; };

// This is deliberately an immutable admission allowlist, not a historical-source exception.
// Values are safe resource/version/payload identities; no secret material is represented.
const predecessor = {
  jwtPending: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/jwt-pending-1CnWMp", versionId: "13bcedde2e46717f6eb89dd689b88c0695ae07efb64b4945a6c8131223464766", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "38fdc4269d2923267f8118eed17747ca91aaa824ade3ae210830618bebcfd8b0", schemaKeys: Object.freeze(["family", "materialFingerprint", "rotationId", "slot", "sourceSha", "supersessionPredecessorIdentitySha256", "value"]), sourceSha: MIXED_DUAL_SLOT_RECOVERY_SOURCE, slot: "pending", materialFingerprint: "c2d884385ef04265", keyVersion: null }),
  qrPrivatePending: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/qr-private-pending-LZhc54", versionId: "1d572ba23ffa93b9673d397538f50619d407bab14abf5b253c2822d86fb6f839", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "13875bcd713dc7043ec3e971409ca8049cc1b524e4214cc6baa242ad96b1271e", schemaKeys: Object.freeze(["family", "keyVersion", "materialFingerprint", "rotationId", "slot", "sourceSha", "supersessionPredecessorIdentitySha256", "value"]), sourceSha: MIXED_DUAL_SLOT_RECOVERY_SOURCE, slot: "pending-private", materialFingerprint: "7cb14d015815ebc0", keyVersion: "3cad751d823933d4" }),
  qrPublicPending: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/qr-public-pending-uB3P1Q", versionId: "3892eb7772eb595b012352bd5112c4b71f19f531302b7eb91e37c1d6791011ee", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "3e06f104229d3a6a7b53d8a3dc5758d34cec46f9f807baee9ff5bf49a1e52739", schemaKeys: Object.freeze(["family", "keyVersion", "materialFingerprint", "rotationId", "slot", "sourceSha", "supersessionPredecessorIdentitySha256", "value"]), sourceSha: MIXED_DUAL_SLOT_RECOVERY_SOURCE, slot: "pending-public", materialFingerprint: "3cad751d823933d4", keyVersion: "3cad751d823933d4" }),
  jwtPrevious: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/jwt-previous-6rQrqj", versionId: "26b8afb90b8dcf883ceb7bf71da0f6d4d4ff11b38ed48800a75eccdd6c7d71f3", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "0271db917d5cf70a6fa5eb3cf2df7cc7e10e5dfa2e04a2ef86a4b44484624e75", schemaKeys: Object.freeze(["family", "materialFingerprint", "rotationId", "slot", "value"]), sourceSha: null, slot: "previous", materialFingerprint: "465ccccb1c54732a", keyVersion: null }),
  qrPublicPrevious: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/qr-public-previous-rLZwcX", versionId: "dfd2e77d176c23138d2971fbfb9ca996572e0814b53275304c66d46ba60886dd", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "9106d5ec6a6b9c7950cb9a30ea36ac678243cffed302f2fa5f19e803dcd1ffc4", schemaKeys: Object.freeze(["family", "keyVersion", "materialFingerprint", "rotationId", "slot", "value"]), sourceSha: null, slot: "previous", materialFingerprint: "c41ca96ab047dd25", keyVersion: "2026-04-20" }),
  qrCurrentVersion: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/qr-current-version-8fNOVE", versionId: "eb119cc3d24ba5e77c373ca199ed014e92d41f04619f61f05ea3e242d39a8af6", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "3fd7a95e43f1d3e25c48c4f03211a5e60793b3d54b3682a963f86fffdd034827", schemaKeys: Object.freeze(["family", "keyVersion", "rotationId", "slot", "sourceSha", "value"]), sourceSha: MIXED_DUAL_SLOT_RECOVERY_SOURCE, slot: "current", materialFingerprint: null, keyVersion: "3cad751d823933d4" }),
  qrPreviousVersion: Object.freeze({ arn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/qr-previous-version-PDFul2", versionId: "0758354d42296a51adb317c3a306338b4cf6e3c171cfb3eb05caf0ae49029052", stagingLabels: Object.freeze(["AWSCURRENT"]), payloadSha256: "11b405bf0be2e5d71f22014f3331a2ec1563871455bb9b4cdcc521ea4f27056c", schemaKeys: Object.freeze(["family", "keyVersion", "rotationId", "slot", "sourceSha", "value"]), sourceSha: MIXED_DUAL_SLOT_RECOVERY_SOURCE, slot: "previous", materialFingerprint: null, keyVersion: "2026-04-20" }),
};
export const MIXED_DUAL_SLOT_PREDECESSOR = Object.freeze(Object.fromEntries(Object.entries(predecessor).map(([slot, value]) => [slot, Object.freeze({ ...value, rotationId: MIXED_DUAL_SLOT_RECOVERY_ROTATION })])));
export const MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID = mixedDualSlotRecoverySha256(MIXED_DUAL_SLOT_PREDECESSOR);
export const MIXED_DUAL_SLOT_RECOVERY_POST_STATE_CANONICAL_ID = mixedDualSlotRecoverySha256(Object.fromEntries(MIXED_DUAL_SLOT_RECOVERY_ORDER.map((slot) => [slot, { ...MIXED_DUAL_SLOT_PREDECESSOR[slot], stagingLabels: [] }])));

export function assertMixedDualSlotPredecessor(observed) {
  exactKeys(observed, MIXED_DUAL_SLOT_RECOVERY_ORDER, "Mixed dual-slot predecessor");
  for (const slot of MIXED_DUAL_SLOT_RECOVERY_ORDER) {
    const expected = MIXED_DUAL_SLOT_PREDECESSOR[slot]; const actual = exactKeys(observed[slot], ["arn", "versionId", "stagingLabels", "payloadSha256", "schemaKeys", "sourceSha", "rotationId", "slot", "materialFingerprint", "keyVersion"], `Mixed predecessor ${slot}`);
    if (!ARN.test(actual.arn || "") || canonical(actual) !== canonical(expected)) fail(`Mixed dual-slot predecessor ${slot} is not the exact admitted live identity.`);
  }
  return Object.freeze(structuredClone(observed));
}

export function buildMixedDualSlotRecoveryPreparation({ sourceSha, predecessor, initialCompletedStageLabelMutations = 0, livePredecessor = MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR, preparedAt } = {}) {
  if (!SHA40.test(sourceSha || "")) fail("Recovery protected source is invalid.");
  const checked = assertMixedDualSlotPredecessor(predecessor);
  if (!Number.isInteger(initialCompletedStageLabelMutations) || initialCompletedStageLabelMutations < 0 || initialCompletedStageLabelMutations > 7) fail("Recovery prepared prefix is invalid.");
  if (typeof preparedAt !== "string" || new Date(preparedAt).toISOString() !== preparedAt) fail("Recovery preparation time is invalid.");
  const mutationPlan = MIXED_DUAL_SLOT_RECOVERY_ORDER.map((slot) => ({ slot, secretArn: checked[slot].arn, versionId: checked[slot].versionId, removeStage: "AWSCURRENT" }));
  if (canonical(livePredecessor) !== canonical(MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR) || livePredecessor.legacySecretArns.some((arn) => mutationPlan.some((entry) => entry.secretArn === arn))) fail("Mixed recovery live predecessor is not the exact non-intersecting deployment.");
  const body = { schemaVersion: 1, kind: MIXED_DUAL_SLOT_RECOVERY_PREPARATION_KIND, operation: MIXED_DUAL_SLOT_RECOVERY_OPERATION, sourceSha, historicalSourceSha: MIXED_DUAL_SLOT_RECOVERY_SOURCE, historicalRotationId: MIXED_DUAL_SLOT_RECOVERY_ROTATION, predecessor: checked, predecessorCanonicalId: MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID, initialCompletedStageLabelMutations, maximumRemainingStageLabelMutations: 7 - initialCompletedStageLabelMutations, livePredecessor, livePredecessorCanonicalId: mixedDualSlotRecoverySha256(livePredecessor), postState: MIXED_DUAL_SLOT_RECOVERY_POST_STATE, postStateCanonicalId: MIXED_DUAL_SLOT_RECOVERY_POST_STATE_CANONICAL_ID, mutationPlan, mutationPlanSha256: mixedDualSlotRecoverySha256(mutationPlan), expectedStageLabelMutations: 7, expectedSecretValueWrites: 0, expectedSecretCreates: 0, expectedSecretDeletes: 0, preparedAt };
  return Object.freeze({ ...body, preparationSha256: mixedDualSlotRecoverySha256(body) });
}

export function assertMixedDualSlotRecoveryPreparation(value, { sourceSha } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "historicalSourceSha", "historicalRotationId", "predecessor", "predecessorCanonicalId", "initialCompletedStageLabelMutations", "maximumRemainingStageLabelMutations", "livePredecessor", "livePredecessorCanonicalId", "postState", "postStateCanonicalId", "mutationPlan", "mutationPlanSha256", "expectedStageLabelMutations", "expectedSecretValueWrites", "expectedSecretCreates", "expectedSecretDeletes", "preparedAt", "preparationSha256"], "Mixed recovery preparation");
  if (value.schemaVersion !== 1 || value.kind !== MIXED_DUAL_SLOT_RECOVERY_PREPARATION_KIND || value.operation !== MIXED_DUAL_SLOT_RECOVERY_OPERATION || value.sourceSha !== sourceSha || value.historicalSourceSha !== MIXED_DUAL_SLOT_RECOVERY_SOURCE || value.historicalRotationId !== MIXED_DUAL_SLOT_RECOVERY_ROTATION || value.predecessorCanonicalId !== MIXED_DUAL_SLOT_PREDECESSOR_CANONICAL_ID || !Number.isInteger(value.initialCompletedStageLabelMutations) || value.initialCompletedStageLabelMutations < 0 || value.initialCompletedStageLabelMutations > 7 || value.maximumRemainingStageLabelMutations !== 7 - value.initialCompletedStageLabelMutations || canonical(value.livePredecessor) !== canonical(MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR) || value.livePredecessorCanonicalId !== mixedDualSlotRecoverySha256(MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR) || value.postState !== MIXED_DUAL_SLOT_RECOVERY_POST_STATE || value.postStateCanonicalId !== MIXED_DUAL_SLOT_RECOVERY_POST_STATE_CANONICAL_ID || value.expectedStageLabelMutations !== 7 || value.expectedSecretValueWrites !== 0 || value.expectedSecretCreates !== 0 || value.expectedSecretDeletes !== 0) fail("Mixed recovery preparation identity is invalid.");
  assertMixedDualSlotPredecessor(value.predecessor);
  if (!Array.isArray(value.mutationPlan) || value.mutationPlan.length !== 7 || value.mutationPlan.some((entry, index) => canonical(entry) !== canonical({ slot: MIXED_DUAL_SLOT_RECOVERY_ORDER[index], secretArn: MIXED_DUAL_SLOT_PREDECESSOR[MIXED_DUAL_SLOT_RECOVERY_ORDER[index]].arn, versionId: MIXED_DUAL_SLOT_PREDECESSOR[MIXED_DUAL_SLOT_RECOVERY_ORDER[index]].versionId, removeStage: "AWSCURRENT" }))) fail("Mixed recovery mutation plan is not exact.");
  if (value.mutationPlanSha256 !== mixedDualSlotRecoverySha256(value.mutationPlan)) fail("Mixed recovery mutation plan hash is invalid.");
  const { preparationSha256, ...body } = value; if (!SHA256.test(preparationSha256 || "") || mixedDualSlotRecoverySha256(body) !== preparationSha256) fail("Mixed recovery preparation hash is invalid."); return value;
}

export function createMixedDualSlotRecoveryAuthorization({ preparation, preparationFileSha256, protectedEnvironmentApprovalEvidence, reason, approverRole, verificationRef, now = new Date() } = {}) {
  const checked = assertMixedDualSlotRecoveryPreparation(preparation, { sourceSha: preparation?.sourceSha });
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha: checked.sourceSha, repository: MIXED_DUAL_SLOT_RECOVERY_REPOSITORY, now });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.mixedDualSlotRecoveryAuthorizationWorkflowRef) fail("Mixed recovery authorization requires its dedicated protected workflow identity.");
  const approvedBy = assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha: checked.sourceSha, repository: MIXED_DUAL_SLOT_RECOVERY_REPOSITORY, executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  for (const [name, value] of Object.entries({ reason, approverRole, verificationRef })) if (typeof value !== "string" || !value.trim()) fail(`${name} is required.`);
  if (!SHA256.test(preparationFileSha256 || "")) fail("Mixed recovery preparation file hash is invalid.");
  const body = { schemaVersion: 1, kind: MIXED_DUAL_SLOT_RECOVERY_AUTHORIZATION_KIND, operation: MIXED_DUAL_SLOT_RECOVERY_OPERATION, sourceSha: checked.sourceSha, predecessorCanonicalId: checked.predecessorCanonicalId, preparationSha256: checked.preparationSha256, preparationFileSha256, initialCompletedStageLabelMutations: checked.initialCompletedStageLabelMutations, maximumRemainingStageLabelMutations: checked.maximumRemainingStageLabelMutations, postStateCanonicalId: checked.postStateCanonicalId, mutationPlanSha256: checked.mutationPlanSha256, historicalRotationId: checked.historicalRotationId, historicalSourceSha: checked.historicalSourceSha, expectedStageLabelMutations: 7, expectedSecretValueWrites: 0, expectedSecretCreates: 0, expectedSecretDeletes: 0, approvedBy, reason: reason.trim(), approverRole: approverRole.trim(), verificationRef: verificationRef.trim(), protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: mixedDualSlotRecoverySha256(body) });
}

export function assertMixedDualSlotRecoveryAuthorization(value, { preparation, preparationFileSha256, sourceSha, now = new Date(), allowExpiredResume = false } = {}) {
  const checked = assertMixedDualSlotRecoveryPreparation(preparation, { sourceSha });
  exactKeys(value, ["schemaVersion", "kind", "operation", "sourceSha", "predecessorCanonicalId", "preparationSha256", "preparationFileSha256", "initialCompletedStageLabelMutations", "maximumRemainingStageLabelMutations", "postStateCanonicalId", "mutationPlanSha256", "historicalRotationId", "historicalSourceSha", "expectedStageLabelMutations", "expectedSecretValueWrites", "expectedSecretCreates", "expectedSecretDeletes", "approvedBy", "reason", "approverRole", "verificationRef", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"], "Mixed recovery authorization");
  if (value.schemaVersion !== 1 || value.kind !== MIXED_DUAL_SLOT_RECOVERY_AUTHORIZATION_KIND || value.operation !== MIXED_DUAL_SLOT_RECOVERY_OPERATION || value.sourceSha !== sourceSha || value.predecessorCanonicalId !== checked.predecessorCanonicalId || value.preparationSha256 !== checked.preparationSha256 || !SHA256.test(value.preparationFileSha256 || "") || preparationFileSha256 && value.preparationFileSha256 !== preparationFileSha256 || value.initialCompletedStageLabelMutations !== checked.initialCompletedStageLabelMutations || value.maximumRemainingStageLabelMutations !== checked.maximumRemainingStageLabelMutations || value.postStateCanonicalId !== checked.postStateCanonicalId || value.mutationPlanSha256 !== checked.mutationPlanSha256 || value.historicalRotationId !== checked.historicalRotationId || value.historicalSourceSha !== checked.historicalSourceSha || value.expectedStageLabelMutations !== 7 || value.expectedSecretValueWrites !== 0 || value.expectedSecretCreates !== 0 || value.expectedSecretDeletes !== 0) fail("Mixed recovery authorization identity is invalid.");
  const evidenceNow = allowExpiredResume ? new Date(value.protectedEnvironmentApprovalEvidence?.observedAt) : now;
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: MIXED_DUAL_SLOT_RECOVERY_REPOSITORY, now: evidenceNow });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.mixedDualSlotRecoveryAuthorizationWorkflowRef || value.protectedEnvironmentApprovalEvidence.schemaVersion !== 3 || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.approvedBy !== value.protectedEnvironmentApprovalEvidence.actualApproval.userLogin) fail("Mixed recovery protected approval identity is invalid.");
  const age = now.getTime() - Date.parse(value.protectedEnvironmentApprovalEvidence.observedAt); if (!allowExpiredResume && (age < 0 || age > MIXED_DUAL_SLOT_RECOVERY_MAX_AGE_MS)) fail("Mixed recovery authorization is stale.");
  const { authorizationSha256, ...body } = value; if (!SHA256.test(authorizationSha256 || "") || mixedDualSlotRecoverySha256(body) !== authorizationSha256) fail("Mixed recovery authorization hash is invalid."); return value;
}

export function resolveMixedDualSlotRecoveryAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, preparation, preparationFileSha256, now = new Date(), run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }) } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || ""))) fail("Mixed recovery authorization coordinates are invalid.");
  const workflow = JSON.parse(run("gh", ["api", `repos/${MIXED_DUAL_SLOT_RECOVERY_REPOSITORY}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== MIXED_DUAL_SLOT_RECOVERY_REPOSITORY || workflow.head_repository?.full_name !== MIXED_DUAL_SLOT_RECOVERY_REPOSITORY || workflow.path !== ".github/workflows/authorize-production-mixed-dual-slot-topology-recovery.yml" || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) fail("Mixed recovery authorization workflow provenance is not authentic.");
  const pages = JSON.parse(run("gh", ["api", `repos/${MIXED_DUAL_SLOT_RECOVERY_REPOSITORY}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"]));
  const artifacts = (Array.isArray(pages) ? pages : []).flatMap((page) => page?.artifacts || []);
  const matches = artifacts.filter((artifact) => artifact.name === MIXED_DUAL_SLOT_RECOVERY_ARTIFACT && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id) || matches[0].id < 1) fail("Mixed recovery authorization artifact identity is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-mixed-recovery-auth-")); const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = run("gh", ["api", `repos/${MIXED_DUAL_SLOT_RECOVERY_REPOSITORY}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 });
    if (!Buffer.isBuffer(bytes) || `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}` !== matches[0].digest) fail("Mixed recovery authorization archive bytes are not authentic.");
    fs.writeFileSync(archive, bytes, { mode: 0o600, flag: "wx" });
    const entries = String(run("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean); if (canonical(entries) !== canonical(["authorization.json"])) fail("Mixed recovery authorization archive contents are not exact.");
    const listing = String(run("unzip", ["-Z", "-l", archive])).split("\n").filter((line) => line.trim().endsWith(" authorization.json")); if (listing.length !== 1 || !listing[0].trim().startsWith("-")) fail("Mixed recovery authorization archive payload is not a regular file.");
    const authorization = JSON.parse(Buffer.from(run("unzip", ["-p", archive, "authorization.json"])).toString("utf8"));
    assertMixedDualSlotRecoveryAuthorization(authorization, { preparation, preparationFileSha256, sourceSha, now, allowExpiredResume: true });
    if (authorization.protectedEnvironmentApprovalEvidence.workflowRunId !== String(workflow.id) || authorization.protectedEnvironmentApprovalEvidence.workflowRunAttempt !== String(workflow.run_attempt) || authorization.protectedEnvironmentApprovalEvidence.executionActor?.toLowerCase() !== String(workflow.actor?.login || "").toLowerCase()) fail("Mixed recovery authorization is not bound to the workflow run.");
    return Object.freeze({ workflow, artifact: matches[0], authorization });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
