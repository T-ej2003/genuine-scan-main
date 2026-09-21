import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));
const backend = JSON.parse(fs.readFileSync(path.join(directory, "../../infra/aws/terraform/production-component-deployment-state/state-backend-contract.json")));
const sha = /^[a-f0-9]{64}$/;
const artifactSha = /^sha256:[a-f0-9]{64}$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const checkpointStates = new Set(["RECOVERY_EXECUTING", "IMPORT_LOCK_CAPTURED", "PLAN_LOCK_CAPTURED", "RESOURCE_ADOPTED", "STATE_VERIFIED", "RECOVERY_CLOSED"]);

export const partialActivationRecovery = Object.freeze({
  transitionType: "COMPONENT_INFRASTRUCTURE_PARTIAL_ACTIVATION_RECOVERY",
  environment: "production-component-infrastructure-activation-recovery",
  workflow: ".github/workflows/authorize-component-infrastructure-partial-activation-recovery.yml",
  artifact: "component-infrastructure-partial-activation-recovery-authorization",
  file: "component-infrastructure-partial-activation-recovery-authorization.json",
  maxAgeMs: 30 * 60 * 1000,
});

export const partialActivationRecoveryTarget = Object.freeze({
  address: "aws_dynamodb_table.component_deployment_state",
  id: "mscqr-production-component-deployment-state",
  stateKey: backend.key,
  lockKey: `${backend.key}.tflock`,
  attemptKey: `${backend.key}.initial-activation-attempt`,
});

export function assertPartialActivationHistoricalActivation(value) {
  assert.deepEqual(Object.keys(value || {}).sort(), ["activationAuthorizationSourceSha", "authorizationArtifactSha256", "authorizationRunId", "installationReservationSourceSha", "planSha256", "preparationSha256", "transitionId"]);
  for (const field of ["activationAuthorizationSourceSha", "installationReservationSourceSha"]) assert.match(value[field] || "", /^[a-f0-9]{40}$/);
  assert.match(value.authorizationRunId || "", /^[1-9][0-9]*$/);
  assert.match(value.authorizationArtifactSha256 || "", artifactSha);
  for (const field of ["planSha256", "preparationSha256"]) assert.match(value[field] || "", sha);
  assert.match(value.transitionId || "", uuid);
  return Object.freeze(structuredClone(value));
}

export function assertPartialActivationRecoveryPreparation(value) {
  assert.deepEqual(Object.keys(value || {}).sort(), ["attempt", "backend", "historicalActivation", "iamInstallation", "liveTable", "lock", "recoveryTransitionId", "schemaVersion", "sourceSha", "stateIdentity"].sort());
  assert.equal(value.schemaVersion, 1);
  assert.match(value.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(value.recoveryTransitionId || "", uuid);
  assert.equal(value.stateIdentity, "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE");
  assert.deepEqual(value.backend, backend);
  assert.deepEqual(value.liveTable, partialActivationRecoveryTarget);
  assert.deepEqual(Object.keys(value.attempt || {}).sort(), ["authorizationRunId", "etag", "sha256", "versionId"]);
  assert.match(value.attempt.authorizationRunId || "", /^[1-9][0-9]*$/); assert.equal(value.attempt.versionId?.length > 0, true); assert.equal(value.attempt.etag?.length > 0, true); assert.match(value.attempt.sha256 || "", sha);
  assert.deepEqual(Object.keys(value.lock || {}).sort(), ["etag", "key", "sha256", "versionId"]);
  assert.equal(value.lock.key, partialActivationRecoveryTarget.lockKey);
  assert.match(value.lock.sha256 || "", sha); assert(typeof value.lock.etag === "string" && value.lock.etag); assert(typeof value.lock.versionId === "string" && value.lock.versionId);
  assertPartialActivationHistoricalActivation(value.historicalActivation);
  assert.deepEqual(Object.keys(value.iamInstallation || {}).sort(), ["authorizationSha256", "documentBindingsSha256", "receiptSha256", "sourceSha", "transitionId"]);
  assert.match(value.iamInstallation.sourceSha || "", /^[a-f0-9]{40}$/); assert.match(value.iamInstallation.transitionId || "", uuid);
  for (const field of ["authorizationSha256", "documentBindingsSha256", "receiptSha256"]) assert.match(value.iamInstallation[field] || "", sha);
  return Object.freeze(structuredClone(value));
}

export function partialActivationRecoveryBindings(preparation) {
  const value = assertPartialActivationRecoveryPreparation(preparation);
  return Object.freeze({
    recoverySourceSha: value.sourceSha,
    recoveryTransitionId: value.recoveryTransitionId,
    historicalActivationAuthorizationSourceSha: value.historicalActivation.activationAuthorizationSourceSha,
    historicalInstallationReservationSourceSha: value.historicalActivation.installationReservationSourceSha,
    historicalAuthorizationRunId: value.historicalActivation.authorizationRunId,
    historicalAuthorizationArtifactSha256: value.historicalActivation.authorizationArtifactSha256,
    historicalPlanSha256: value.historicalActivation.planSha256,
    historicalPreparationSha256: value.historicalActivation.preparationSha256,
    historicalTransitionId: value.historicalActivation.transitionId,
    iamInstallation: value.iamInstallation,
    expectedResource: { address: partialActivationRecoveryTarget.address, id: partialActivationRecoveryTarget.id },
    attempt: value.attempt,
    lock: value.lock,
    stateIdentity: value.stateIdentity,
  });
}

// Lock versions are the only already-authorized durable journal surface for
// this incident.  Keep every checkpoint bound to one preparation and target.
export function assertPartialActivationRecoveryCheckpoint(value, preparation, preparationSha256) {
  const expected = assertPartialActivationRecoveryPreparation(preparation);
  assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationSha256", "expiresAt", "historical", "lock", "owner", "preparationSha256", "recoveryTransitionId", "schemaVersion", "sourceSha", "state"]);
  assert.equal(value.schemaVersion, 1); assert(checkpointStates.has(value.state));
  assert.equal(value.sourceSha, expected.sourceSha); assert.equal(value.recoveryTransitionId, expected.recoveryTransitionId);
  assert.match(preparationSha256 || "", sha); assert.equal(value.preparationSha256, preparationSha256);
  assert.match(value.authorizationSha256 || "", sha); assert.deepEqual(value.historical, expected.historicalActivation); assert.deepEqual(value.lock, expected.lock);
  assert.equal(value.owner?.expiresAt, value.expiresAt); assert(typeof value.owner?.principal === "string" && value.owner.principal);
  const expires = Date.parse(value.expiresAt); assert.equal(new Date(expires).toISOString(), value.expiresAt); assert(Number.isFinite(expires));
  return Object.freeze(structuredClone(value));
}
