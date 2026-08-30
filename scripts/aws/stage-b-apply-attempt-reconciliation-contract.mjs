import crypto from "node:crypto";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./stage-b-evidence-freshness.mjs";

export const STAGE_B_APPLY_ATTEMPT_SCHEMA_VERSION = 3;
export const STAGE_B_APPLY_ATTEMPT_KIND = "MSCQRProductionGreenStageBApplyAttempt";
export const STAGE_B_APPLY_ATTEMPT_RECONCILIATION_SCHEMA_VERSION = 3;
export const STAGE_B_APPLY_ATTEMPT_RECONCILIATION_KIND = "MSCQRProductionGreenStageBApplyAttemptReconciliation";
export const STAGE_B_APPLY_ATTEMPT_RECONCILIATION_AUTHORIZATION_KIND = "MSCQRProductionGreenStageBApplyAttemptReconciliationAuthorization";
export const STAGE_B_APPLY_ATTEMPT_RECONCILIATION_OPERATION = "STAGE_B_APPLY_ATTEMPT_RECONCILIATION";
export const STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF = "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-green-stage-b-apply-attempt-reconciliation.yml@refs/heads/main";
export const STAGE_B_APPLY_ATTEMPT_RECONCILIATION_REASON = "RESERVATION_COMMITTED_BEFORE_TERRAFORM_REACHABILITY_CONFIRMATION";

export const HISTORICAL_STAGE_B_V2_INCIDENT = Object.freeze({
  reservationIdentity: "1aefb5f358412d102e68be79c324e221c6a7af4114f12ce18a9ddbd465d85021",
  sourceSha: "2798e4109b6ecacf1fe2ddb76ef913f62c1d57f9",
  planSha256: "48d340168a7a19211f1b1968856cac01b3511ed2e85ef43fc7a102ff75ae8c13",
  savedPlanSha256: "65c598d5300c4b4eb1528ff6a1b94610d511e10566b5b74fe095aadac1def430",
  stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a",
  stateSerial: 102,
  stateSha256: "1a458c55cce4a2a8c85b0e24c1b10bca5ae5f76ed18057f97c1561e54f500a36",
  workspace: "default",
  backendIdentitySha256: "7c8cedda5fe692272bbe281294d664024b9ec29f00c516b683402b89b6996128",
  createdAt: "2026-08-30T03:38:40.212Z",
});

export const STAGE_B_APPLY_ATTEMPT_STATES = Object.freeze(["RESERVED", "APPLY_INTENT_RECORDED", "APPLIED", "FAILED", "UNKNOWN", "ABORTED_BEFORE_APPLY"]);
export const STAGE_B_APPLY_ATTEMPT_RESULT_CLASSES = Object.freeze(["CONDITIONAL_CREATE_COMMITTED", "APPLY_INTENT_RECORDED", "APPLY_RESULT_COMMITTED", "APPLY_RESULT_FAILED", "OCCUPIED", "CONCURRENT_CONFLICT", "AUTHORIZATION_FAILURE", "TRANSPORT_FAILURE", "SERVICE_FAILURE", "READBACK_MISMATCH", "UNKNOWN_RESULT"]);

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const fail = (message) => { throw new Error(message); };
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonicalSha256 = (value) => sha256(Buffer.from(canonicalJson(value)));
const text = (value, label) => { if (typeof value !== "string" || !value.trim() || value.length > 512) fail(`${label} is required.`); return value; };
const digest = (value, label) => { if (!SHA256.test(value || "")) fail(`${label} must be a SHA256.`); return value; };
const source = (value, label) => { if (!SHA40.test(value || "")) fail(`${label} must be a full source SHA.`); return value; };
const serial = (value, label) => { if (!Number.isSafeInteger(value) || value < 0) fail(`${label} must be a safe non-negative integer.`); return value; };
const exactKeys = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...fields].sort())) fail(`${label} schema is invalid.`);
};
const RECONCILIATION_BINDING_FIELDS = ["artifactSha256", "authorizationSha256", "successorAttemptId"];
const assertReconciliationBinding = (value) => {
  exactKeys(value, RECONCILIATION_BINDING_FIELDS, "Stage B reconciliation binding");
  digest(value.artifactSha256, "reconciliation binding artifactSha256"); digest(value.authorizationSha256, "reconciliation binding authorizationSha256"); digest(value.successorAttemptId, "reconciliation binding successorAttemptId");
  return value;
};

export function stageBApplyAttemptIdentity(bindings = {}) {
  return canonicalSha256({ sourceSha: source(bindings.sourceSha, "sourceSha"), planSha256: digest(bindings.planSha256, "planSha256"), savedPlanSha256: digest(bindings.savedPlanSha256, "savedPlanSha256"), stateLineage: text(bindings.stateLineage, "stateLineage"), stateSerial: serial(bindings.stateSerial, "stateSerial"), stateSha256: digest(bindings.stateSha256, "stateSha256"), workspace: text(bindings.workspace, "workspace"), backendIdentitySha256: digest(bindings.backendIdentitySha256, "backendIdentitySha256") });
}

export function stageBApplyAttemptSuccessorIdentity({ predecessorAttemptId, reconciliationArtifactSha256, sourceSha, planSha256, savedPlanSha256, stateLineage, stateSerial, stateSha256, workspace, backendIdentitySha256 } = {}) {
  if (!SHA256.test(predecessorAttemptId || "")) fail("Predecessor attempt identity must be a SHA256.");
  digest(reconciliationArtifactSha256, "reconciliationArtifactSha256");
  return canonicalSha256({ predecessorAttemptId, reconciliationArtifactSha256, sourceSha: source(sourceSha, "sourceSha"), planSha256: digest(planSha256, "planSha256"), savedPlanSha256: digest(savedPlanSha256, "savedPlanSha256"), stateLineage: text(stateLineage, "stateLineage"), stateSerial: serial(stateSerial, "stateSerial"), stateSha256: digest(stateSha256, "stateSha256"), workspace: text(workspace, "workspace"), backendIdentitySha256: digest(backendIdentitySha256, "backendIdentitySha256") });
}

export function classifyStageBReservationAwsResult(result, { operation = "conditional-create" } = {}) {
  const output = `${result?.stdout || ""}\n${result?.stderr || ""}`;
  if (result?.status === 0) return { operation, classification: "CONDITIONAL_CREATE_COMMITTED", exitCode: 0, stdoutSha256: sha256(Buffer.from(result.stdout || "")), stderrSha256: sha256(Buffer.from(result.stderr || "")) };
  if (/(?:412|PreconditionFailed)/i.test(output)) return { operation, classification: "OCCUPIED", exitCode: result?.status ?? null };
  if (/(?:409|ConditionalRequestConflict)/i.test(output)) return { operation, classification: "CONCURRENT_CONFLICT", exitCode: result?.status ?? null };
  if (/(?:AccessDenied|Unauthorized|Forbidden|ExpiredToken|InvalidClientToken)/i.test(output)) return { operation, classification: "AUTHORIZATION_FAILURE", exitCode: result?.status ?? null };
  if (/(?:timed out|timeout|connection|network|socket|TLS|EOF)/i.test(output)) return { operation, classification: "TRANSPORT_FAILURE", exitCode: result?.status ?? null };
  if (/(?:ServiceUnavailable|InternalError|503|500|SlowDown)/i.test(output)) return { operation, classification: "SERVICE_FAILURE", exitCode: result?.status ?? null };
  return { operation, classification: "UNKNOWN_RESULT", exitCode: result?.status ?? null };
}

export function classifyStageBReservationReadback({ status, exists, bytesMatch } = {}) {
  if (status === 0 && exists === true && bytesMatch === true) return { classification: "CONDITIONAL_CREATE_COMMITTED", readback: "EXACT" };
  if (status === 0 && exists === true && bytesMatch === false) return { classification: "READBACK_MISMATCH", readback: "MISMATCH" };
  return { classification: "UNKNOWN_RESULT", readback: "UNKNOWN" };
}

export function createStageBApplyAttemptReservation({ attemptId, sourceSha, planSha256, savedPlanSha256, stateLineage, stateSerial, stateSha256, workspace, backendIdentitySha256, executionPrincipal, createdAt = new Date().toISOString(), predecessorAttemptId = null } = {}) {
  const identity = digest(attemptId || stageBApplyAttemptIdentity({ sourceSha, planSha256, savedPlanSha256, stateLineage, stateSerial, stateSha256, workspace, backendIdentitySha256 }), "attemptId");
  if (predecessorAttemptId !== null && !SHA256.test(predecessorAttemptId || "")) fail("predecessorAttemptId must be null or a SHA256.");
  return Object.freeze({ schemaVersion: STAGE_B_APPLY_ATTEMPT_SCHEMA_VERSION, kind: STAGE_B_APPLY_ATTEMPT_KIND, attemptId: identity, predecessorAttemptId, sequence: 0, phase: "RESERVED", status: "RESERVED", sourceSha: source(sourceSha, "sourceSha"), planSha256: digest(planSha256, "planSha256"), savedPlanSha256: digest(savedPlanSha256, "savedPlanSha256"), stateLineage: text(stateLineage, "stateLineage"), stateSerial: serial(stateSerial, "stateSerial"), stateSha256: digest(stateSha256, "stateSha256"), workspace: text(workspace, "workspace"), backendIdentitySha256: digest(backendIdentitySha256, "backendIdentitySha256"), executionPrincipal: text(executionPrincipal, "executionPrincipal"), createdAt: text(createdAt, "createdAt"), operationResult: { classification: "CONDITIONAL_CREATE_COMMITTED", readback: "EXACT" }, applyMayHaveOccurred: false, applyStarted: { status: "NOT_STARTED", evidenceSha256: null }, applyResult: { status: "PENDING", evidenceSha256: null }, reconciliationBinding: null });
}

const V3_FIELDS = ["schemaVersion", "kind", "attemptId", "predecessorAttemptId", "sequence", "phase", "status", "sourceSha", "planSha256", "savedPlanSha256", "stateLineage", "stateSerial", "stateSha256", "workspace", "backendIdentitySha256", "executionPrincipal", "createdAt", "operationResult", "applyMayHaveOccurred", "applyStarted", "applyResult", "reconciliationBinding"];

export function assertStageBApplyAttemptReservation(value, { expected = {}, allowHistoricalV2 = false } = {}) {
  if (value?.schemaVersion === 2) {
    if (!allowHistoricalV2) fail("Historical schema-v2 apply reservation requires the explicit incident bridge.");
    return assertHistoricalStageBV2Incident(value, expected);
  }
  exactKeys(value, V3_FIELDS, "Stage B apply reservation");
  if (value.schemaVersion !== 3 || value.kind !== STAGE_B_APPLY_ATTEMPT_KIND || !SHA256.test(value.attemptId || "") || (value.predecessorAttemptId !== null && !SHA256.test(value.predecessorAttemptId || "")) || !Number.isSafeInteger(value.sequence) || value.sequence < 0 || value.phase !== value.status || !STAGE_B_APPLY_ATTEMPT_STATES.includes(value.status)) fail("Stage B apply reservation identity or state is invalid.");
  source(value.sourceSha, "sourceSha"); digest(value.planSha256, "planSha256"); digest(value.savedPlanSha256, "savedPlanSha256"); text(value.stateLineage, "stateLineage"); serial(value.stateSerial, "stateSerial"); digest(value.stateSha256, "stateSha256"); text(value.workspace, "workspace"); digest(value.backendIdentitySha256, "backendIdentitySha256"); text(value.executionPrincipal, "executionPrincipal"); text(value.createdAt, "createdAt");
  if (!STAGE_B_APPLY_ATTEMPT_RESULT_CLASSES.includes(value.operationResult?.classification) || !["EXACT", "MISMATCH", "UNKNOWN"].includes(value.operationResult?.readback) || typeof value.applyMayHaveOccurred !== "boolean" || !["NOT_STARTED", "INTENT_RECORDED", "REACHABLE", "UNKNOWN"].includes(value.applyStarted?.status) || (value.applyStarted?.evidenceSha256 !== null && !SHA256.test(value.applyStarted?.evidenceSha256 || "")) || !["PENDING", "SUCCEEDED", "FAILED", "UNKNOWN"].includes(value.applyResult?.status) || (value.applyResult?.evidenceSha256 !== null && !SHA256.test(value.applyResult?.evidenceSha256 || ""))) fail("Stage B apply reservation operation evidence is invalid.");
  if (value.reconciliationBinding !== null) assertReconciliationBinding(value.reconciliationBinding);
  if (value.status === "RESERVED" && (value.sequence !== 0 || value.applyMayHaveOccurred !== false || value.applyStarted.status !== "NOT_STARTED" || value.applyResult.status !== "PENDING")) fail("RESERVED apply reservation cannot contain apply-start evidence.");
  if (["APPLY_INTENT_RECORDED", "APPLIED", "FAILED", "UNKNOWN"].includes(value.status) && value.applyMayHaveOccurred !== true) fail("Started or uncertain apply reservation must conservatively set applyMayHaveOccurred.");
  if (value.status === "APPLY_INTENT_RECORDED" && (value.operationResult.classification !== "APPLY_INTENT_RECORDED" || value.applyStarted.status !== "INTENT_RECORDED" || value.applyResult.status !== "PENDING")) fail("Apply-intent reservation must preserve the pre-spawn uncertainty boundary.");
  if (value.status === "APPLIED" && (!["INTENT_RECORDED", "REACHABLE"].includes(value.applyStarted.status) || value.applyResult.status !== "SUCCEEDED")) fail("APPLIED reservation must contain successful apply evidence.");
  if (value.status === "FAILED" && (!["INTENT_RECORDED", "REACHABLE"].includes(value.applyStarted.status) || value.applyResult.status !== "FAILED")) fail("FAILED reservation must contain failed apply evidence.");
  if (value.status === "UNKNOWN" && (value.applyStarted.status !== "UNKNOWN" || value.applyResult.status !== "UNKNOWN")) fail("UNKNOWN reservation must preserve uncertain apply evidence.");
  if (value.status === "ABORTED_BEFORE_APPLY" && (value.applyStarted.status !== "NOT_STARTED" || value.applyResult.status !== "PENDING" || value.applyMayHaveOccurred !== false || value.reconciliationBinding === null)) fail("ABORTED_BEFORE_APPLY reservation must prove no apply was reachable and bind reconciliation evidence.");
  for (const [field, expectedValue] of Object.entries(expected)) if (expectedValue !== undefined && value[field] !== expectedValue) fail(`Stage B apply reservation ${field} binding mismatch.`);
  return value;
}

export function assertHistoricalStageBV2Incident(value, expected = {}) {
  const incident = HISTORICAL_STAGE_B_V2_INCIDENT;
  const fields = ["schemaVersion", "kind", "phase", "applyCalls", "applyMayHaveOccurred", "artifactSetIdentity", "executableAuditSha256", "createdAt", "planSha256", "savedPlanSha256", "protectedMainSha", "workspace", "backendIdentitySha256"];
  exactKeys(value, fields, "Historical Stage B schema-v2 reservation");
  if (value.schemaVersion !== 2 || value.kind !== STAGE_B_APPLY_ATTEMPT_KIND || value.phase !== "APPLYING" || value.applyCalls !== 1 || value.applyMayHaveOccurred !== true || value.artifactSetIdentity !== incident.reservationIdentity || value.executableAuditSha256 !== incident.reservationIdentity || value.createdAt !== incident.createdAt || value.planSha256 !== incident.planSha256 || value.savedPlanSha256 !== incident.savedPlanSha256 || value.protectedMainSha !== incident.sourceSha || value.workspace !== incident.workspace || value.backendIdentitySha256 !== incident.backendIdentitySha256) fail("Historical Stage B schema-v2 reservation is not the exact reviewed incident.");
  for (const [field, expectedValue] of Object.entries(expected)) if (expectedValue !== undefined && value[field] !== expectedValue) fail(`Historical Stage B reservation ${field} binding mismatch.`);
  return value;
}

export function assertStageBApplyAttemptTransition(previous, next) {
  assertStageBApplyAttemptReservation(previous); assertStageBApplyAttemptReservation(next);
  const immutableFields = ["attemptId", "predecessorAttemptId", "sourceSha", "planSha256", "savedPlanSha256", "stateLineage", "stateSerial", "stateSha256", "workspace", "backendIdentitySha256", "executionPrincipal", "createdAt"];
  if (immutableFields.some((field) => next[field] !== previous[field]) || next.sequence !== previous.sequence + 1 || previous.status === "APPLIED" || previous.status === "FAILED" || previous.status === "ABORTED_BEFORE_APPLY" || previous.status === "UNKNOWN") fail("Stage B apply reservation transition is not monotonic.");
  const allowed = { RESERVED: ["APPLY_INTENT_RECORDED", "ABORTED_BEFORE_APPLY"], APPLY_INTENT_RECORDED: ["APPLIED", "FAILED", "UNKNOWN"] };
  if (!allowed[previous.status]?.includes(next.status)) fail("Stage B apply reservation transition is not authorized.");
  return true;
}

export function createStageBApplyAttemptTransition(previous, { status, operationResult, applyStarted, applyResult, applyMayHaveOccurred = true, reconciliationBinding = previous.reconciliationBinding } = {}) {
  assertStageBApplyAttemptReservation(previous);
  const next = { ...previous, sequence: previous.sequence + 1, phase: status, status, operationResult, applyMayHaveOccurred, applyStarted, applyResult, reconciliationBinding };
  assertStageBApplyAttemptTransition(previous, next);
  return Object.freeze(next);
}

export function assertStageBApplyAttemptTuple(value, expected = {}) {
  assertStageBApplyAttemptReservation(value, { expected });
  return true;
}

const RECONCILIATION_EVIDENCE_DOMAINS = Object.freeze(["LOCAL_EXECUTION", "REMOTE_STATE_AND_INFRASTRUCTURE"]);
const predecessorTuple = (reservation, bridgeType) => bridgeType === "HISTORICAL_V2_INCIDENT"
  ? { reservationIdentity: HISTORICAL_STAGE_B_V2_INCIDENT.reservationIdentity, sourceSha: HISTORICAL_STAGE_B_V2_INCIDENT.sourceSha, planSha256: HISTORICAL_STAGE_B_V2_INCIDENT.planSha256, savedPlanSha256: HISTORICAL_STAGE_B_V2_INCIDENT.savedPlanSha256, stateLineage: HISTORICAL_STAGE_B_V2_INCIDENT.stateLineage, stateSerial: HISTORICAL_STAGE_B_V2_INCIDENT.stateSerial, stateSha256: HISTORICAL_STAGE_B_V2_INCIDENT.stateSha256, workspace: HISTORICAL_STAGE_B_V2_INCIDENT.workspace, backendIdentitySha256: HISTORICAL_STAGE_B_V2_INCIDENT.backendIdentitySha256 }
  : { reservationIdentity: reservation.attemptId, sourceSha: reservation.sourceSha, planSha256: reservation.planSha256, savedPlanSha256: reservation.savedPlanSha256, stateLineage: reservation.stateLineage, stateSerial: reservation.stateSerial, stateSha256: reservation.stateSha256, workspace: reservation.workspace, backendIdentitySha256: reservation.backendIdentitySha256 };

export function classifyStageBApplyAttemptReconciliationState(reservation) {
  if (reservation?.schemaVersion === 2) {
    assertHistoricalStageBV2Incident(reservation);
    return Object.freeze({ status: "HISTORICAL_V2_EXACT_INCIDENT_CANDIDATE", automaticSuccessorAllowed: false });
  }
  assertStageBApplyAttemptReservation(reservation);
  if (reservation.status === "RESERVED" && reservation.sequence === 0 && reservation.applyMayHaveOccurred === false && reservation.applyStarted.status === "NOT_STARTED" && reservation.applyResult.status === "PENDING") return Object.freeze({ status: "V3_RESERVED_BEFORE_APPLY_CANDIDATE", automaticSuccessorAllowed: false });
  return Object.freeze({ status: "INDETERMINATE_NO_AUTOMATIC_SUCCESSOR", automaticSuccessorAllowed: false });
}

function assertReconciliationPredecessor(reservation, transitions = []) {
  if (!Array.isArray(transitions)) fail("Stage B reconciliation predecessor transitions are invalid.");
  if (reservation?.schemaVersion === 2) {
    if (transitions.length !== 0) fail("Historical schema-v2 reconciliation cannot contain transitions.");
    assertHistoricalStageBV2Incident(reservation);
    return { bridgeType: "HISTORICAL_V2_INCIDENT", tuple: predecessorTuple(reservation, "HISTORICAL_V2_INCIDENT") };
  }
  assertStageBApplyAttemptReservation(reservation);
  let current = reservation;
  for (const transition of transitions) { assertStageBApplyAttemptTransition(current, transition); current = transition; }
  if (transitions.length === 0 && classifyStageBApplyAttemptReconciliationState(reservation).status === "V3_RESERVED_BEFORE_APPLY_CANDIDATE") return { bridgeType: "V3_RESERVED_BEFORE_APPLY", tuple: predecessorTuple(reservation, "V3_RESERVED_BEFORE_APPLY") };
  if (transitions.length === 1 && current.status === "APPLY_INTENT_RECORDED") return { bridgeType: "V3_APPLY_INTENT_PRE_TERRAFORM", tuple: predecessorTuple(reservation, "V3_APPLY_INTENT_PRE_TERRAFORM") };
  fail("Only an authenticated v3 pre-spawn reservation or apply intent can enter governed reconciliation.");
}

function assertFreshObservation(observation, incident, { now = new Date(), requireMissingLocalReservationMarker = false } = {}) {
  const fields = ["reservationIdentity", "sourceSha", "planSha256", "savedPlanSha256", "stateLineage", "stateSerial", "stateSha256", "workspace", "backendIdentitySha256", "applyEntrypointReached", "terraformProcessStarted", "providerSideMutationEvidence", "infrastructureMutationDetected", "localReservationMarkerCreated", "observedAt", "evidenceSource"];
  exactKeys(observation, fields, "Stage B reconciliation observation");
  if (observation.reservationIdentity !== incident.reservationIdentity || observation.sourceSha !== incident.sourceSha || observation.planSha256 !== incident.planSha256 || observation.savedPlanSha256 !== incident.savedPlanSha256 || observation.stateLineage !== incident.stateLineage || observation.stateSerial !== incident.stateSerial || observation.stateSha256 !== incident.stateSha256 || observation.workspace !== incident.workspace || observation.backendIdentitySha256 !== incident.backendIdentitySha256 || observation.applyEntrypointReached !== false || observation.terraformProcessStarted !== false || observation.providerSideMutationEvidence !== "NONE" || observation.infrastructureMutationDetected !== false || typeof observation.localReservationMarkerCreated !== "boolean" || (requireMissingLocalReservationMarker && observation.localReservationMarkerCreated !== false) || !Array.isArray(observation.evidenceSource) || observation.evidenceSource.length !== RECONCILIATION_EVIDENCE_DOMAINS.length) fail("Stage B reconciliation observation does not independently prove a pre-Terraform failure.");
  assertStageBDeploymentEvidenceFreshness(observation.observedAt, { now, evidenceType: "Stage B reconciliation observation" });
  const domains = new Set(); const kinds = new Set(); const digests = new Set(); const authenticators = new Set();
  for (const item of observation.evidenceSource) {
    exactKeys(item, ["domain", "kind", "sha256", "authenticatedBy"], "Stage B reconciliation evidence source");
    if (!RECONCILIATION_EVIDENCE_DOMAINS.includes(item.domain) || !text(item.kind, "reconciliation evidence kind") || !SHA256.test(item.sha256 || "") || !text(item.authenticatedBy, "reconciliation evidence authenticator")) fail("Stage B reconciliation evidence source is invalid.");
    domains.add(item.domain); kinds.add(item.kind); digests.add(item.sha256); authenticators.add(item.authenticatedBy);
  }
  if (domains.size !== RECONCILIATION_EVIDENCE_DOMAINS.length || !RECONCILIATION_EVIDENCE_DOMAINS.every((domain) => domains.has(domain)) || kinds.size !== RECONCILIATION_EVIDENCE_DOMAINS.length || digests.size !== RECONCILIATION_EVIDENCE_DOMAINS.length || authenticators.size !== RECONCILIATION_EVIDENCE_DOMAINS.length) fail("Stage B reconciliation evidence domains are not independent.");
  return observation;
}

export function createStageBApplyAttemptReconciliationArtifact({ historicalReservation, historicalTransitions = [], observation, successorSourceSha, generatedAt = new Date().toISOString(), reason = STAGE_B_APPLY_ATTEMPT_RECONCILIATION_REASON, now = new Date() } = {}) {
  const predecessor = assertReconciliationPredecessor(historicalReservation, historicalTransitions); source(successorSourceSha, "successorSourceSha"); if (successorSourceSha === predecessor.tuple.sourceSha) fail("A reconciliation successor must be a distinct protected source."); const checkedObservation = assertFreshObservation(observation, predecessor.tuple, { now, requireMissingLocalReservationMarker: predecessor.bridgeType === "HISTORICAL_V2_INCIDENT" }); text(reason, "reason"); assertStageBDeploymentEvidenceFreshness(generatedAt, { now, evidenceType: "Stage B reconciliation artifact" });
  return Object.freeze({ schemaVersion: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_SCHEMA_VERSION, kind: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_KIND, bridgeType: predecessor.bridgeType, generatedAt, reason, predecessor: predecessor.tuple, predecessorReservation: historicalReservation, predecessorTransitions: historicalTransitions, successorSourceSha, observation: checkedObservation });
}

export function assertStageBApplyAttemptReconciliationArtifact(value, { successorSourceSha, now = new Date() } = {}) {
  exactKeys(value, ["schemaVersion", "kind", "bridgeType", "generatedAt", "reason", "predecessor", "predecessorReservation", "predecessorTransitions", "successorSourceSha", "observation"], "Stage B reconciliation artifact");
  if (value.schemaVersion !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_SCHEMA_VERSION || value.kind !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_KIND || value.reason !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_REASON || value.successorSourceSha !== successorSourceSha) fail("Stage B reconciliation artifact identity is invalid.");
  const predecessor = assertReconciliationPredecessor(value.predecessorReservation, value.predecessorTransitions);
  if (value.bridgeType !== predecessor.bridgeType || canonicalJson(value.predecessor) !== canonicalJson(predecessor.tuple)) fail("Stage B reconciliation predecessor is not authentically bound.");
  source(value.successorSourceSha, "successorSourceSha"); if (value.successorSourceSha === predecessor.tuple.sourceSha) fail("Stage B reconciliation successor source must be distinct from the predecessor source.");
  assertStageBDeploymentEvidenceFreshness(value.generatedAt, { now, evidenceType: "Stage B reconciliation artifact" });
  assertFreshObservation(value.observation, predecessor.tuple, { now, requireMissingLocalReservationMarker: predecessor.bridgeType === "HISTORICAL_V2_INCIDENT" }); return value;
}

export function stageBApplyAttemptReconciliationSha256(value, { now = new Date() } = {}) { assertStageBApplyAttemptReconciliationArtifact(value, { successorSourceSha: value?.successorSourceSha, now }); return canonicalSha256(value); }

export function createStageBApplyAttemptReconciliationAuthorization({ protectedEnvironmentApprovalEvidence, reconciliationArtifact, reconciliationArtifactSha256, successorSourceSha, approvedBy, approverRole, verificationRef, now = new Date() } = {}) {
  assertStageBApplyAttemptReconciliationArtifact(reconciliationArtifact, { successorSourceSha, now }); digest(reconciliationArtifactSha256, "reconciliationArtifactSha256"); source(successorSourceSha, "successorSourceSha");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha: successorSourceSha, repository: "T-ej2003/genuine-scan-main" }); assertProductionEnvironmentApprovalFreshness(protectedEnvironmentApprovalEvidence, { now });
  assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha: successorSourceSha, repository: "T-ej2003/genuine-scan-main", executionActor: protectedEnvironmentApprovalEvidence.executionActor });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF || protectedEnvironmentApprovalEvidence.schemaVersion !== 3 || protectedEnvironmentApprovalEvidence.actualApproval?.userLogin !== approvedBy) fail("Stage B reconciliation authorization requires actual independent approval from the dedicated workflow.");
  const body = { schemaVersion: 1, kind: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_AUTHORIZATION_KIND, operation: STAGE_B_APPLY_ATTEMPT_RECONCILIATION_OPERATION, environment: "production", accountId: "368992683803", region: "eu-west-2", successorSourceSha, predecessor: reconciliationArtifact.predecessor, reconciliationArtifactSha256, successorAttemptId: stageBApplyAttemptSuccessorIdentity({ predecessorAttemptId: reconciliationArtifact.predecessor.reservationIdentity, reconciliationArtifactSha256, sourceSha: successorSourceSha, planSha256: reconciliationArtifact.predecessor.planSha256, savedPlanSha256: reconciliationArtifact.predecessor.savedPlanSha256, stateLineage: reconciliationArtifact.predecessor.stateLineage, stateSerial: reconciliationArtifact.predecessor.stateSerial, stateSha256: reconciliationArtifact.predecessor.stateSha256, workspace: reconciliationArtifact.predecessor.workspace, backendIdentitySha256: reconciliationArtifact.predecessor.backendIdentitySha256 }), maximumTerraformApplies: 1, expectedTerraformApplies: 1, expectedSecretDeletes: 0, approvedBy, approverRole: text(approverRole, "approverRole"), verificationRef: text(verificationRef, "verificationRef"), protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256 };
  return Object.freeze({ ...body, authorizationSha256: canonicalSha256(body) });
}

export function createStageBApplyAttemptSuccessorReservation({ reconciliationArtifact, reconciliationArtifactSha256, authorization, authorizationSha256, currentReservation, currentTransitions, executionPrincipal, createdAt = new Date().toISOString(), now = new Date() } = {}) {
  const sourceSha = reconciliationArtifact?.successorSourceSha;
  assertStageBApplyAttemptReconciliationEligibility({ reservation: currentReservation, transitions: currentTransitions, reconciliationArtifact, reconciliationArtifactSha256, authorization, authorizationSha256, successorSourceSha: sourceSha, now });
  const predecessor = reconciliationArtifact.predecessor;
  return createStageBApplyAttemptReservation({ attemptId: authorization.successorAttemptId, predecessorAttemptId: predecessor.reservationIdentity, sourceSha, planSha256: predecessor.planSha256, savedPlanSha256: predecessor.savedPlanSha256, stateLineage: predecessor.stateLineage, stateSerial: predecessor.stateSerial, stateSha256: predecessor.stateSha256, workspace: predecessor.workspace, backendIdentitySha256: predecessor.backendIdentitySha256, executionPrincipal, createdAt });
}

export function assertStageBApplyAttemptReconciliationAuthorization(value, { successorSourceSha, reconciliationArtifact, reconciliationArtifactSha256, now = new Date() } = {}) {
  const fields = ["schemaVersion", "kind", "operation", "environment", "accountId", "region", "successorSourceSha", "predecessor", "reconciliationArtifactSha256", "successorAttemptId", "maximumTerraformApplies", "expectedTerraformApplies", "expectedSecretDeletes", "approvedBy", "approverRole", "verificationRef", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
  exactKeys(value, fields, "Stage B reconciliation authorization");
  if (value.schemaVersion !== 1 || value.kind !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_AUTHORIZATION_KIND || value.operation !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_OPERATION || value.environment !== "production" || value.accountId !== "368992683803" || value.region !== "eu-west-2" || value.successorSourceSha !== successorSourceSha || value.reconciliationArtifactSha256 !== reconciliationArtifactSha256 || value.maximumTerraformApplies !== 1 || value.expectedTerraformApplies !== 1 || value.expectedSecretDeletes !== 0 || !SHA256.test(value.successorAttemptId || "")) fail("Stage B reconciliation authorization identity is invalid.");
  assertStageBApplyAttemptReconciliationArtifact(reconciliationArtifact, { successorSourceSha, now });
  if (canonicalJson(value.predecessor) !== canonicalJson(reconciliationArtifact.predecessor)) fail("Stage B reconciliation authorization predecessor binding is invalid.");
  text(value.approvedBy, "approvedBy"); text(value.approverRole, "approverRole"); text(value.verificationRef, "verificationRef");
  if (canonicalSha256(reconciliationArtifact) !== reconciliationArtifactSha256 || value.successorAttemptId !== stageBApplyAttemptSuccessorIdentity({ predecessorAttemptId: value.predecessor.reservationIdentity, reconciliationArtifactSha256, sourceSha: successorSourceSha, planSha256: value.predecessor.planSha256, savedPlanSha256: value.predecessor.savedPlanSha256, stateLineage: value.predecessor.stateLineage, stateSerial: value.predecessor.stateSerial, stateSha256: value.predecessor.stateSha256, workspace: value.predecessor.workspace, backendIdentitySha256: value.predecessor.backendIdentitySha256 })) fail("Stage B reconciliation authorization is not bound to the exact successor attempt.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha: successorSourceSha, repository: "T-ej2003/genuine-scan-main" }); assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== STAGE_B_APPLY_ATTEMPT_RECONCILIATION_WORKFLOW_REF || value.protectedEnvironmentApprovalEvidence.schemaVersion !== 3 || value.protectedEnvironmentApprovalEvidence.actualApproval?.userLogin !== value.approvedBy || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256) fail("Stage B reconciliation approval evidence is not independently bound.");
  const { authorizationSha256, ...body } = value; if (canonicalSha256(body) !== authorizationSha256) fail("Stage B reconciliation authorization hash is invalid."); return value;
}

export function assertStageBApplyAttemptReconciliationEligibility({ reservation, transitions = [], reconciliationArtifact, reconciliationArtifactSha256, authorization, authorizationSha256, successorSourceSha, expectedState = {}, now = new Date() } = {}) {
  const predecessor = assertReconciliationPredecessor(reservation, transitions); for (const [field, expectedValue] of Object.entries(expectedState)) if (expectedValue !== undefined && reservation[field] !== expectedValue) fail(`Stage B reconciliation reservation ${field} binding mismatch.`); assertStageBApplyAttemptReconciliationArtifact(reconciliationArtifact, { successorSourceSha, now }); if (canonicalJson(reservation) !== canonicalJson(reconciliationArtifact.predecessorReservation) || canonicalJson(transitions) !== canonicalJson(reconciliationArtifact.predecessorTransitions) || canonicalJson(predecessor.tuple) !== canonicalJson(reconciliationArtifact.predecessor)) fail("Stage B reconciliation predecessor changed after observation."); digest(reconciliationArtifactSha256, "reconciliationArtifactSha256"); if (canonicalSha256(reconciliationArtifact) !== reconciliationArtifactSha256) fail("Stage B reconciliation artifact hash is invalid.");
  if (!authorization || authorization.authorizationSha256 !== authorizationSha256) fail("Stage B reconciliation authorization is not byte-bound.");
  assertStageBApplyAttemptReconciliationAuthorization(authorization, { successorSourceSha, reconciliationArtifact, reconciliationArtifactSha256, now }); return Object.freeze({ status: "RECOVERABLE", successorAttemptId: authorization.successorAttemptId, maximumTerraformApplies: authorization.maximumTerraformApplies });
}
