import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { canonicalJson, PRODUCTION_ACTIVATION_LIFECYCLE, STAGE_B } from "./production-green-stage-b-contract.mjs";

export const STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION = "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION";
export const STAGE_A_PRODUCTION_ARTIFACTS_JOURNAL_PREFIX = PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationPrefix;
const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;
const LINEAGE = /^[0-9a-f-]{36}$/;
const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`);
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const exactKeys = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) throw new Error(`${label} schema is invalid.`);
};
const text = (value, label) => { if (typeof value !== "string" || !value) throw new Error(`${label} is invalid.`); return value; };
const identity = (value) => ({ operation: value.operation, sourceSha: value.sourceSha, account: value.account, region: value.region, executionPrincipal: value.executionPrincipal, authorizationSha256: value.authorizationSha256, recoveryCompletionSha256: value.recoveryCompletionSha256, savedPlanSha256: value.savedPlanSha256, preStateLineage: value.preStateLineage, preStateSerial: value.preStateSerial, preStateSha256: value.preStateSha256, desiredPolicySha256: value.desiredPolicySha256 });
const reservationFields = Object.freeze(["schemaVersion", "kind", "operation", "sourceSha", "account", "region", "executionPrincipal", "authorizationSha256", "recoveryCompletionSha256", "savedPlanSha256", "preStateLineage", "preStateSerial", "preStateSha256", "desiredPolicySha256", "reservationSha256"]);
const resultFields = Object.freeze(["schemaVersion", "kind", "operation", "sourceSha", "account", "region", "executionPrincipal", "authorizationSha256", "recoveryCompletionSha256", "savedPlanSha256", "preStateLineage", "preStateSerial", "preStateSha256", "desiredPolicySha256", "reservationSha256", "status", "postStateLineage", "postStateSerial", "postStateSha256", "postLivePolicySha256", "refreshOnlyApplyCount", "awsInfrastructureMutationCount", "resultSha256"]);

export function stageAProductionArtifactsJournalKey({ authorizationSha256, record } = {}) {
  if (!SHA256.test(authorizationSha256 || "") || !["reservation.json", "result.json"].includes(record)) throw new Error("Stage A reconciliation journal key is invalid.");
  return `${STAGE_A_PRODUCTION_ARTIFACTS_JOURNAL_PREFIX}${authorizationSha256}/${record}`;
}

export function stageAProductionArtifactsRecoveryCompletionKey({ recoveryAuthorizationSha256 } = {}) {
  if (!SHA256.test(recoveryAuthorizationSha256 || "")) throw new Error("Stage A recovery completion key is invalid.");
  return `${STAGE_A_PRODUCTION_ARTIFACTS_JOURNAL_PREFIX}recovery/${recoveryAuthorizationSha256}/completion.json`;
}

function assertIdentity(value, label) {
  if (value.operation !== STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION || !SHA40.test(value.sourceSha || "") || value.account !== STAGE_B.account || value.region !== STAGE_B.region || value.executionPrincipal !== PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn || ![value.authorizationSha256, value.recoveryCompletionSha256, value.savedPlanSha256, value.preStateSha256, value.desiredPolicySha256].every((field) => SHA256.test(field || "")) || !LINEAGE.test(value.preStateLineage || "") || !Number.isSafeInteger(value.preStateSerial) || value.preStateSerial < 1) throw new Error(`${label} identity is invalid.`);
}

export function createStageAProductionArtifactsReservation(input = {}) {
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_RESERVATION", ...identity(input) };
  assertIdentity(body, "Stage A reconciliation reservation");
  return Object.freeze({ ...body, reservationSha256: sha256(canonicalBytes(body)) });
}

export function assertStageAProductionArtifactsReservation(value, expected = {}) {
  exactKeys(value, reservationFields, "Stage A reconciliation reservation");
  assertIdentity(value, "Stage A reconciliation reservation");
  const { reservationSha256, ...body } = value;
  if (!SHA256.test(reservationSha256 || "") || reservationSha256 !== sha256(canonicalBytes(body))) throw new Error("Stage A reconciliation reservation hash is invalid.");
  for (const [key, expectedValue] of Object.entries(expected)) if (expectedValue !== undefined && value[key] !== expectedValue) throw new Error("Stage A reconciliation reservation does not match the authorized operation.");
  return Object.freeze(value);
}

export function createStageAProductionArtifactsJournalResult({ reservation, status, postState, postLivePolicySha256 = null } = {}) {
  assertStageAProductionArtifactsReservation(reservation);
  const completed = status === "COMPLETED";
  if (!completed && !["ABORTED_BEFORE_APPLY", "FAILED_OR_INDETERMINATE"].includes(status)) throw new Error("Stage A reconciliation journal result status is invalid.");
  if (completed && (!postState || postState.lineage !== reservation.preStateLineage || !Number.isSafeInteger(postState.serial) || postState.serial !== reservation.preStateSerial + 1 || !SHA256.test(postState.stateSha256 || "") || !SHA256.test(postLivePolicySha256 || ""))) throw new Error("Stage A reconciliation completed result is invalid.");
  const body = { schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_RESULT", ...identity(reservation), reservationSha256: reservation.reservationSha256, status, postStateLineage: completed ? postState.lineage : null, postStateSerial: completed ? postState.serial : null, postStateSha256: completed ? postState.stateSha256 : null, postLivePolicySha256: completed ? postLivePolicySha256 : null, refreshOnlyApplyCount: completed ? 1 : 0, awsInfrastructureMutationCount: 0 };
  return Object.freeze({ ...body, resultSha256: sha256(canonicalBytes(body)) });
}

export function assertStageAProductionArtifactsJournalResult(value, { reservation } = {}) {
  exactKeys(value, resultFields, "Stage A reconciliation journal result");
  assertIdentity(value, "Stage A reconciliation journal result");
  if (!SHA256.test(value.reservationSha256 || "") || !SHA256.test(value.resultSha256 || "") || !["COMPLETED", "ABORTED_BEFORE_APPLY", "FAILED_OR_INDETERMINATE"].includes(value.status) || value.awsInfrastructureMutationCount !== 0) throw new Error("Stage A reconciliation journal result binding is invalid.");
  if (reservation) {
    assertStageAProductionArtifactsReservation(reservation);
    if (value.reservationSha256 !== reservation.reservationSha256 || canonicalJson(identity(value)) !== canonicalJson(identity(reservation))) throw new Error("Stage A reconciliation journal result does not belong to its reservation.");
  }
  const completed = value.status === "COMPLETED";
  if (completed ? !(value.postStateLineage === value.preStateLineage && value.postStateSerial === value.preStateSerial + 1 && SHA256.test(value.postStateSha256 || "") && SHA256.test(value.postLivePolicySha256 || "") && value.refreshOnlyApplyCount === 1) : !(value.postStateLineage === null && value.postStateSerial === null && value.postStateSha256 === null && value.postLivePolicySha256 === null && value.refreshOnlyApplyCount === 0)) throw new Error("Stage A reconciliation journal result state is invalid.");
  const { resultSha256, ...body } = value;
  if (resultSha256 !== sha256(canonicalBytes(body))) throw new Error("Stage A reconciliation journal result hash is invalid.");
  return Object.freeze(value);
}

function readObject({ run, key }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-journal-")); const output = path.join(directory, "record.json");
  try {
    try { run(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--output", "json", "--no-cli-pager", output]); }
    catch (error) { if (/NoSuchKey|NotFound|404/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return null; throw error; }
    return fs.readFileSync(output);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function conditionalCreate({ run, key, bytes }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-journal-")); const body = path.join(directory, "record.json");
  try {
    fs.writeFileSync(body, bytes, { mode: 0o600, flag: "wx" });
    try { run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--output", "json", "--no-cli-pager"]); }
    catch (error) { if (/PreconditionFailed|ConditionalRequestConflict|412|409/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return false; throw error; }
    const readback = readObject({ run, key });
    if (!readback || !readback.equals(bytes)) throw new Error("Stage A reconciliation journal conditional create did not persist exact bytes.");
    return true;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function createStageAProductionArtifactsJournal({ run } = {}) {
  if (typeof run !== "function") throw new Error("Stage A reconciliation journal requires an explicit release-deployer AWS runner.");
  const load = (authorizationSha256, record) => {
    const bytes = readObject({ run, key: stageAProductionArtifactsJournalKey({ authorizationSha256, record }) });
    if (!bytes) return null;
    let value; try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new Error("Stage A reconciliation journal record is not canonical UTF-8 JSON."); }
    if (!bytes.equals(canonicalBytes(value))) throw new Error("Stage A reconciliation journal record is not canonical.");
    return { value, bytes, sha256: sha256(bytes) };
  };
  return Object.freeze({
    reserve(input) {
      const reservation = createStageAProductionArtifactsReservation(input); const key = stageAProductionArtifactsJournalKey({ authorizationSha256: reservation.authorizationSha256, record: "reservation.json" }); const bytes = canonicalBytes(reservation);
      if (!conditionalCreate({ run, key, bytes })) throw new Error("Stage A reconciliation authorization is already reserved; no replay is permitted.");
      return Object.freeze({ reservation, key, sha256: sha256(bytes) });
    },
    finalize({ reservation, status, postState, postLivePolicySha256 } = {}) {
      assertStageAProductionArtifactsReservation(reservation); const result = createStageAProductionArtifactsJournalResult({ reservation, status, postState, postLivePolicySha256 }); const key = stageAProductionArtifactsJournalKey({ authorizationSha256: reservation.authorizationSha256, record: "result.json" }); const bytes = canonicalBytes(result);
      if (!conditionalCreate({ run, key, bytes })) throw new Error("Stage A reconciliation already has a terminal journal result; no replay is permitted.");
      return Object.freeze({ result, key, sha256: sha256(bytes) });
    },
    readReservation(authorizationSha256) { const record = load(authorizationSha256, "reservation.json"); return record && { ...record, reservation: assertStageAProductionArtifactsReservation(record.value) }; },
    readResult(authorizationSha256) { const record = load(authorizationSha256, "result.json"); if (!record) return null; const reservation = load(authorizationSha256, "reservation.json"); if (!reservation) throw new Error("Stage A reconciliation journal result is missing its reservation."); return { ...record, result: assertStageAProductionArtifactsJournalResult(record.value, { reservation: reservation.value }) }; },
    writeRecoveryCompletion({ recoveryAuthorizationSha256, bytes } = {}) {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error("Stage A recovery completion bytes are invalid.");
      const key = stageAProductionArtifactsRecoveryCompletionKey({ recoveryAuthorizationSha256 });
      if (!conditionalCreate({ run, key, bytes })) throw new Error("Stage A recovery completion already exists; no overwrite is permitted.");
      return Object.freeze({ key, sha256: sha256(bytes) });
    },
    readRecoveryCompletion(recoveryAuthorizationSha256) {
      const key = stageAProductionArtifactsRecoveryCompletionKey({ recoveryAuthorizationSha256 }); const bytes = readObject({ run, key });
      return bytes && Object.freeze({ key, bytes, sha256: sha256(bytes) });
    },
  });
}
