#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";
import { canonicalJson, canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { sourcePolicyEvidence } from "./validate-production-green-stage-b-permissions.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const repository = PRODUCTION_ENVIRONMENT_APPROVAL.repository;
const artifactName = "production-initial-activation-lifecycle-policy-reconciliation-authorization";

export const INITIAL_ACTIVATION_POLICY_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION",
  policyName: "MSCQRProductionInitialActivationLifecycle",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  sourcePath: "documents/ops/iam/MSCQRProductionInitialActivationLifecycle-v1.json",
  predecessorVersionId: "v1",
  predecessorPolicySha256: "2a90146c8fc8f6062198650134c0e92724cc4dd69720bde629fd0752e4432c71",
  desiredPolicySha256: "7e9eef0b5dd5c089f4734a43cbc40ed963078dc500828c2e592cc07f04c6d564",
  maxCreatePolicyVersionCount: 1,
  maxPolicyVersionsBeforeCreate: 4,
  workflowPath: ".github/workflows/authorize-production-initial-activation-lifecycle-policy-reconciliation.yml",
});

const exact = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const sha = (value) => canonicalSha256(value);
const requireSha40 = (value, label) => { if (!SHA40.test(value || "")) throw new Error(`${label} is invalid.`); return value; };
const requireSha = (value, label) => { if (!SHA256.test(value || "")) throw new Error(`${label} is invalid.`); return value; };
const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`);
const INITIAL_ACTIVATION_RESERVATION_PREFIX = PRODUCTION_ACTIVATION_LIFECYCLE.initialActivationPolicyReconciliationReservationPrefix;
const OWNER_NONCE = /^[a-f0-9]{32}$/;
const createReservationOwnerNonce = () => crypto.randomBytes(16).toString("hex");

export function initialActivationLifecyclePolicyReservationIdentity({ sourceSha, authorizationSha256, predecessorDefaultVersionId, predecessorPolicySha256, desiredPolicySha256 } = {}) {
  requireSha40(sourceSha, "sourceSha"); requireSha(authorizationSha256, "authorizationSha256");
  if (!VERSION.test(predecessorDefaultVersionId || "")) throw new Error("predecessorDefaultVersionId is invalid.");
  requireSha(predecessorPolicySha256, "predecessorPolicySha256"); requireSha(desiredPolicySha256, "desiredPolicySha256");
  if (predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256) throw new Error("Initial activation lifecycle policy reservation transition is not the reviewed predecessor-to-desired transition.");
  return Object.freeze({ operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, environment: "production", repository, sourceSha, targetPolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, authorizationSha256, predecessorDefaultVersionId, predecessorPolicySha256, desiredPolicySha256 });
}

export function createInitialActivationLifecyclePolicyReservation(input = {}) {
  const identity = initialActivationLifecyclePolicyReservationIdentity(input);
  if (!OWNER_NONCE.test(input.ownerNonce || "")) throw new Error("ownerNonce is invalid.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_RESERVATION", ...identity, ownerNonce: input.ownerNonce };
  return Object.freeze({ ...body, reservationSha256: canonicalSha256(body) });
}

export function initialActivationLifecyclePolicyReservationKey(reservation) {
  const identity = initialActivationLifecyclePolicyReservationIdentity(reservation);
  return `${INITIAL_ACTIVATION_RESERVATION_PREFIX}${canonicalSha256(identity)}.json`;
}

export function assertInitialActivationLifecyclePolicyReservation(value, expected = {}) {
  const fields = ["schemaVersion", "kind", "operation", "environment", "repository", "sourceSha", "targetPolicyArn", "authorizationSha256", "predecessorDefaultVersionId", "predecessorPolicySha256", "desiredPolicySha256", "ownerNonce", "reservationSha256"];
  exact(value, fields, "Initial activation lifecycle policy reservation");
  const { reservationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_RESERVATION" || value.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !OWNER_NONCE.test(value.ownerNonce || "") || reservationSha256 !== canonicalSha256(body)) throw new Error("Initial activation lifecycle policy reservation identity is invalid.");
  initialActivationLifecyclePolicyReservationIdentity(value);
  for (const [key, expectedValue] of Object.entries(expected)) if (expectedValue !== undefined && value[key] !== expectedValue) throw new Error("Initial activation lifecycle policy reservation does not match the authorized transition.");
  return Object.freeze(value);
}

export function createInitialActivationLifecyclePolicyReservationStore({ run } = {}) {
  if (typeof run !== "function") throw new Error("Initial activation lifecycle policy reservation requires an explicit AWS runner.");
  const read = (reservation) => {
      const key = initialActivationLifecyclePolicyReservationKey(reservation);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-initial-activation-reservation-")); const output = path.join(directory, "reservation.json");
    try {
      try { run(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--expected-bucket-owner", "368992683803", "--output", "json", "--no-cli-pager", output]); }
      catch (error) { if (/NoSuchKey|NotFound|404/i.test(`${error.message || ""}\n${error.stderr || ""}`)) return null; throw error; }
      const bytes = fs.readFileSync(output); let value;
      try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new Error("Initial activation lifecycle policy reservation is not canonical UTF-8 JSON."); }
      if (!bytes.equals(canonicalBytes(value))) throw new Error("Initial activation lifecycle policy reservation bytes are not canonical.");
      return Object.freeze({ key, bytes, reservation: assertInitialActivationLifecyclePolicyReservation(value, initialActivationLifecyclePolicyReservationIdentity(reservation)) });
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  return Object.freeze({
    read,
    reserve(input) {
      const reservation = createInitialActivationLifecyclePolicyReservation(input); const key = initialActivationLifecyclePolicyReservationKey(reservation); const bytes = canonicalBytes(reservation);
      const existing = read(reservation);
      if (existing) return Object.freeze({ owned: existing.reservation.ownerNonce === reservation.ownerNonce, created: false, ...existing });
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-initial-activation-reservation-")); const body = path.join(directory, "reservation.json");
      try {
        fs.writeFileSync(body, bytes, { mode: 0o600, flag: "wx" });
        try { run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--expected-bucket-owner", "368992683803", "--output", "json", "--no-cli-pager"]); }
        catch (error) {
          const errorText = `${error.message || ""}\n${error.stderr || ""}`;
          if (!/PreconditionFailed|ConditionalRequestConflict|412|409/i.test(errorText)) {
            if (!/ambiguous|response lost|timed? ?out|network|socket|ECONNRESET/i.test(errorText)) throw error;
            const recovered = read(reservation);
            if (!recovered) throw error;
            return Object.freeze({ owned: recovered.reservation.ownerNonce === reservation.ownerNonce, created: false, ...recovered });
          }
          const raced = read(reservation); if (!raced) throw new Error("Initial activation lifecycle policy reservation conflict could not be authenticated.");
          return Object.freeze({ owned: raced.reservation.ownerNonce === reservation.ownerNonce, created: false, ...raced });
        }
        const persisted = read(reservation); if (!persisted || !persisted.bytes.equals(bytes)) throw new Error("Initial activation lifecycle policy reservation create did not persist exact bytes.");
        return Object.freeze({ owned: true, created: true, ...persisted });
      } finally { fs.rmSync(directory, { recursive: true, force: true }); }
    },
  });
}

export function readInitialActivationLifecycleDesiredPolicy({ repositoryRoot = root } = {}) {
  const source = path.resolve(repositoryRoot, INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath);
  const document = normalizeIamPolicyDocument(fs.readFileSync(source, "utf8"), "Initial activation lifecycle source policy");
  const policySha256 = sha(document);
  if (policySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256) throw new Error("Initial activation lifecycle source policy is not the reviewed desired document.");
  return Object.freeze({ sourcePath: INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath, document, policySha256 });
}

const expectedReleaseRolePolicyArns = () => sourcePolicyEvidence().map(({ arn }) => arn).sort();
const stateFields = ["policyArn", "defaultVersionId", "document", "policyVersionCount", "releaseRolePolicyArns", "targetPolicyRoles", "targetPolicyUsers", "targetPolicyGroups", "permissionsBoundaryUsageCount"];
export function assertInitialActivationLifecyclePolicyState(value, { desired = readInitialActivationLifecycleDesiredPolicy() } = {}) {
  exact(value, stateFields, "Initial activation lifecycle live policy state");
  if (value.policyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !VERSION.test(value.defaultVersionId || "") || !Number.isSafeInteger(value.policyVersionCount) || value.policyVersionCount < 1 || value.policyVersionCount > 5 || !Number.isSafeInteger(value.permissionsBoundaryUsageCount) || value.permissionsBoundaryUsageCount !== 0 || ![value.releaseRolePolicyArns, value.targetPolicyRoles, value.targetPolicyUsers, value.targetPolicyGroups].every(Array.isArray)) throw new Error("Initial activation lifecycle live policy identity is invalid.");
  const releaseRolePolicyArns = [...value.releaseRolePolicyArns].sort();
  const targetPolicyRoles = [...value.targetPolicyRoles].sort();
  const targetPolicyUsers = [...value.targetPolicyUsers].sort();
  const targetPolicyGroups = [...value.targetPolicyGroups].sort();
  if (JSON.stringify(releaseRolePolicyArns) !== JSON.stringify(expectedReleaseRolePolicyArns())) throw new Error("Initial activation lifecycle release-role policy attachment set changed.");
  if (JSON.stringify(targetPolicyRoles) !== JSON.stringify(["mscqr-production-release-deployer"]) || targetPolicyUsers.length !== 0 || targetPolicyGroups.length !== 0) throw new Error("Initial activation lifecycle target-policy entity boundary changed.");
  const document = normalizeIamPolicyDocument(value.document, "Initial activation lifecycle live policy");
  const policySha256 = sha(document);
  const releaseRolePolicySetSha256 = sha({ releaseRolePolicyArns });
  const targetPolicyEntityBoundarySha256 = sha({ targetPolicyRoles, targetPolicyUsers, targetPolicyGroups, permissionsBoundaryUsageCount: 0 });
  const predecessor = value.defaultVersionId === INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId && policySha256 === INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256;
  const alreadyDesired = policySha256 === desired.policySha256 && value.defaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId;
  if (!predecessor && !alreadyDesired) throw new Error("Initial activation lifecycle live policy is neither the authenticated predecessor nor the exact desired policy.");
  return Object.freeze({ ...value, document, releaseRolePolicyArns, targetPolicyRoles, targetPolicyUsers, targetPolicyGroups, policySha256, releaseRolePolicySetSha256, targetPolicyEntityBoundarySha256, status: alreadyDesired ? "ALREADY_RECONCILED" : "AUTHENTICATED_PREDECESSOR" });
}

const authorizationFields = ["schemaVersion", "kind", "environment", "operation", "sourceSha", "targetPolicyArn", "predecessorDefaultVersionId", "predecessorPolicySha256", "desiredPolicySha256", "desiredPolicySourcePath", "policyVersionCount", "releaseRolePolicySetSha256", "targetPolicyEntityBoundarySha256", "expectedAction", "setAsDefault", "maxCreatePolicyVersionCount", "maxSetDefaultPolicyVersionCount", "maxDeletePolicyVersionCount", "maxPolicyAttachmentMutations", "executionPrincipal", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizationSha256"];
export function createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState, protectedEnvironmentApprovalEvidence, desired = readInitialActivationLifecycleDesiredPolicy(), now = new Date() } = {}) {
  requireSha40(sourceSha, "sourceSha");
  if (desired?.sourcePath !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath || desired?.policySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || sha(desired?.document) !== desired.policySha256) throw new Error("Initial activation lifecycle desired policy must be the exact tracked protected-source document.");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository });
  assertProductionEnvironmentApprovalFreshness(protectedEnvironmentApprovalEvidence, { now });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== `${repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main`) throw new Error("Initial activation lifecycle policy authorization requires its exact protected workflow.");
  const state = assertInitialActivationLifecyclePolicyState(liveState, { desired });
  if (state.status !== "AUTHENTICATED_PREDECESSOR") throw new Error("Initial activation lifecycle policy authorization requires the exact authenticated predecessor.");
  if (state.policyVersionCount > INITIAL_ACTIVATION_POLICY_RECONCILIATION.maxPolicyVersionsBeforeCreate) throw new Error("Initial activation lifecycle policy version capacity requires pruning and is not authorized.");
  const body = {
    schemaVersion: INITIAL_ACTIVATION_POLICY_RECONCILIATION.schemaVersion, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_AUTHORIZATION", environment: "production", operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, sourceSha,
    targetPolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, predecessorDefaultVersionId: state.defaultVersionId, predecessorPolicySha256: state.policySha256, desiredPolicySha256: desired.policySha256, desiredPolicySourcePath: desired.sourcePath, policyVersionCount: state.policyVersionCount, releaseRolePolicySetSha256: state.releaseRolePolicySetSha256, targetPolicyEntityBoundarySha256: state.targetPolicyEntityBoundarySha256,
    expectedAction: "iam:CreatePolicyVersion", setAsDefault: true, maxCreatePolicyVersionCount: 1, maxSetDefaultPolicyVersionCount: 0, maxDeletePolicyVersionCount: 0, maxPolicyAttachmentMutations: 0, executionPrincipal: "ROOT_OPERATOR",
    protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256,
  };
  return Object.freeze({ ...body, authorizationSha256: sha(body) });
}

export function assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now = new Date() } = {}) {
  exact(value, authorizationFields, "Initial activation lifecycle policy authorization");
  const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_AUTHORIZATION" || value.environment !== "production" || value.operation !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation || value.sourceSha !== sourceSha || !SHA256.test(authorizationSha256 || "") || sha(body) !== authorizationSha256) throw new Error("Initial activation lifecycle policy authorization identity is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository });
  assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== `${repository}/${INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath}@refs/heads/main` || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || value.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || value.predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || value.predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || value.desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || value.desiredPolicySourcePath !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.sourcePath || !Number.isSafeInteger(value.policyVersionCount) || value.policyVersionCount < 1 || value.policyVersionCount > 4 || !SHA256.test(value.releaseRolePolicySetSha256 || "") || !SHA256.test(value.targetPolicyEntityBoundarySha256 || "") || value.expectedAction !== "iam:CreatePolicyVersion" || value.setAsDefault !== true || value.maxCreatePolicyVersionCount !== 1 || value.maxSetDefaultPolicyVersionCount !== 0 || value.maxDeletePolicyVersionCount !== 0 || value.maxPolicyAttachmentMutations !== 0 || value.executionPrincipal !== "ROOT_OPERATOR") throw new Error("Initial activation lifecycle policy authorization bindings are invalid.");
  return value;
}

const CONVERGENCE_ATTEMPTS = 6;
const CONVERGENCE_DELAYS = Object.freeze([100, 200, 400, 800, 1000]);
const defaultSleep = (milliseconds) => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds); };

export function waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before, authorization, desired, expectedVersionId, sleep = defaultSleep } = {}) {
  if (typeof readLiveState !== "function" || !before || !authorization || !desired) throw new Error("Initial activation lifecycle convergence inputs are required.");
  for (let attempt = 0; attempt < CONVERGENCE_ATTEMPTS; attempt += 1) {
    const candidate = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
    if (candidate.releaseRolePolicySetSha256 !== authorization.releaseRolePolicySetSha256 || candidate.targetPolicyEntityBoundarySha256 !== authorization.targetPolicyEntityBoundarySha256) throw new Error("Initial activation lifecycle policy topology changed during convergence.");
    if (candidate.status === "AUTHENTICATED_PREDECESSOR") {
      if (candidate.defaultVersionId !== before.defaultVersionId || candidate.policySha256 !== before.policySha256 || candidate.policyVersionCount !== before.policyVersionCount) throw new Error("Initial activation lifecycle policy entered an unexpected predecessor state during convergence.");
    } else {
      if (candidate.defaultVersionId === before.defaultVersionId || candidate.policyVersionCount !== before.policyVersionCount + 1 || (expectedVersionId && candidate.defaultVersionId !== expectedVersionId)) throw new Error("Initial activation lifecycle policy converged to an unexpected default version.");
      return candidate;
    }
    if (attempt < CONVERGENCE_ATTEMPTS - 1) sleep(CONVERGENCE_DELAYS[attempt]);
  }
  throw new Error(`Initial activation lifecycle policy did not converge within ${CONVERGENCE_ATTEMPTS} observations.`);
}

export function executeInitialActivationLifecyclePolicyReconciliation({ authorization, sourceSha, readLiveState, createPolicyVersion, reserve, desired = readInitialActivationLifecycleDesiredPolicy(), now = () => new Date(), sleep = defaultSleep, createReservationOwnerNonce: ownerNonceFactory = createReservationOwnerNonce } = {}) {
  const readClock = typeof now === "function" ? now : () => now;
  assertInitialActivationLifecyclePolicyReconciliationAuthorization(authorization, { sourceSha, now: readClock() });
  if (typeof readLiveState !== "function" || typeof createPolicyVersion !== "function" || typeof reserve !== "function") throw new Error("Initial activation lifecycle policy reconciliation requires authenticated readers, writer, and reservation.");
  const before = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
  if (before.releaseRolePolicySetSha256 !== authorization.releaseRolePolicySetSha256 || before.targetPolicyEntityBoundarySha256 !== authorization.targetPolicyEntityBoundarySha256) throw new Error("Initial activation lifecycle policy attachment state changed since authorization.");
  if (before.status === "ALREADY_RECONCILED") return Object.freeze({ status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: before });
  if (before.defaultVersionId !== authorization.predecessorDefaultVersionId || before.policySha256 !== authorization.predecessorPolicySha256 || before.policyVersionCount !== authorization.policyVersionCount || before.policyVersionCount > 4) throw new Error("Initial activation lifecycle policy predecessor CAS changed since authorization.");
  const ownerNonce = ownerNonceFactory();
  if (!OWNER_NONCE.test(ownerNonce || "")) throw new Error("Initial activation lifecycle policy reservation owner nonce is invalid.");
  const reservation = reserve({ ...initialActivationLifecyclePolicyReservationIdentity({ sourceSha, authorizationSha256: authorization.authorizationSha256, predecessorDefaultVersionId: before.defaultVersionId, predecessorPolicySha256: before.policySha256, desiredPolicySha256: desired.policySha256 }), ownerNonce });
  if (!reservation || reservation.owned !== true) throw new Error("Initial activation lifecycle policy reservation ownership was not authenticated.");
  const latest = assertInitialActivationLifecyclePolicyState(readLiveState(), { desired });
  if (latest.releaseRolePolicySetSha256 !== authorization.releaseRolePolicySetSha256 || latest.targetPolicyEntityBoundarySha256 !== authorization.targetPolicyEntityBoundarySha256) throw new Error("Initial activation lifecycle policy topology changed after reservation.");
  if (latest.status === "ALREADY_RECONCILED") return Object.freeze({ status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: latest });
  if (latest.defaultVersionId !== authorization.predecessorDefaultVersionId || latest.policySha256 !== authorization.predecessorPolicySha256 || latest.policyVersionCount !== authorization.policyVersionCount) throw new Error("Initial activation lifecycle policy predecessor CAS changed after reservation.");
  assertProductionEnvironmentApprovalFreshness(authorization.protectedEnvironmentApprovalEvidence, { now: readClock() });
  let response;
  try { response = createPolicyVersion({ PolicyArn: INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn, PolicyDocument: desired.document, SetAsDefault: true }); }
  catch (error) { const recovered = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before: latest, authorization, desired, sleep }); return Object.freeze({ status: "COMPLETED_BY_READBACK", createPolicyVersionCount: 1, postState: recovered, cause: error }); }
  if (!VERSION.test(response?.PolicyVersion?.VersionId || "") || response.PolicyVersion.VersionId === before.defaultVersionId) {
    const recovered = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before: latest, authorization, desired, sleep });
    return Object.freeze({ status: "COMPLETED_BY_READBACK", createPolicyVersionCount: 1, postState: recovered });
  }
  const after = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState, before: latest, authorization, desired, expectedVersionId: response.PolicyVersion.VersionId, sleep });
  return Object.freeze({ status: "RECONCILED", createPolicyVersionCount: 1, postState: after });
}

export function buildInitialActivationLifecyclePolicyReconciliationResult({ authorization, outcome } = {}) {
  if (!outcome || !["RECONCILED", "COMPLETED_BY_READBACK", "ALREADY_RECONCILED"].includes(outcome.status)) throw new Error("Initial activation lifecycle policy result outcome is invalid.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_LIFECYCLE_POLICY_RECONCILIATION_RESULT", operation: INITIAL_ACTIVATION_POLICY_RECONCILIATION.operation, sourceSha: authorization?.sourceSha, targetPolicyArn: authorization?.targetPolicyArn, authorizationSha256: authorization?.authorizationSha256, predecessorDefaultVersionId: authorization?.predecessorDefaultVersionId, predecessorPolicySha256: authorization?.predecessorPolicySha256, desiredPolicySha256: authorization?.desiredPolicySha256, status: outcome.status, createPolicyVersionCount: outcome.createPolicyVersionCount, postDefaultVersionId: outcome.postState?.defaultVersionId, postPolicySha256: outcome.postState?.policySha256, postReleaseRolePolicySetSha256: outcome.postState?.releaseRolePolicySetSha256, postTargetPolicyEntityBoundarySha256: outcome.postState?.targetPolicyEntityBoundarySha256 };
  if (!SHA40.test(body.sourceSha || "") || body.targetPolicyArn !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.policyArn || !SHA256.test(body.authorizationSha256 || "") || body.predecessorDefaultVersionId !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorVersionId || body.predecessorPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.predecessorPolicySha256 || body.desiredPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || !VERSION.test(body.postDefaultVersionId || "") || body.postPolicySha256 !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.desiredPolicySha256 || !SHA256.test(body.postReleaseRolePolicySetSha256 || "") || !SHA256.test(body.postTargetPolicyEntityBoundarySha256 || "") || ![0, 1].includes(body.createPolicyVersionCount)) throw new Error("Initial activation lifecycle policy result bindings are invalid.");
  return Object.freeze({ ...body, resultSha256: sha(body) });
}

export function resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact({ workflowRunId, workflowRunAttempt, sourceSha, now = new Date(), run = (command, args, options = {}) => execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer }) } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(workflowRunAttempt || "")) || !SHA40.test(sourceSha || "")) throw new Error("Initial activation lifecycle policy authorization coordinates are invalid.");
  const workflow = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== repository || workflow.path !== INITIAL_ACTIVATION_POLICY_RECONCILIATION.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== String(workflowRunAttempt)) throw new Error("Initial activation lifecycle policy authorization workflow provenance is invalid.");
  const artifacts = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}/artifacts`]));
  const matches = artifacts?.artifacts?.filter((artifact) => artifact.name === artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (!Array.isArray(matches) || matches.length !== 1) throw new Error("Initial activation lifecycle policy authorization artifact is not exact.");
  const artifact = matches[0]; const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-initial-activation-policy-authorization-")); const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = run("gh", ["api", `repos/${repository}/actions/artifacts/${artifact.id}/zip`], { encoding: null, maxBuffer: 64 * 1024 * 1024 });
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}` !== artifact.digest) throw new Error("Initial activation lifecycle policy authorization archive digest is invalid.");
    fs.writeFileSync(archive, bytes, { mode: 0o600, flag: "wx" });
    const names = String(run("unzip", ["-Z1", archive])).trim().split("\n").filter(Boolean);
    if (JSON.stringify(names) !== JSON.stringify(["authorization.json"])) throw new Error("Initial activation lifecycle policy authorization archive contents are invalid.");
    const authorizationBytes = run("unzip", ["-p", archive, "authorization.json"], { encoding: null });
    let authorization; try { authorization = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(authorizationBytes)); } catch { throw new Error("Initial activation lifecycle policy authorization artifact is malformed."); }
    assertInitialActivationLifecyclePolicyReconciliationAuthorization(authorization, { sourceSha, now });
    return Object.freeze({ workflow, artifact, authorization, authorizationBytes });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
