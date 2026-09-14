#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalJson, PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentApprovalFreshness, assertProductionEnvironmentApprovalIdentity, createProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN } from "./production-ecs-exec-operator-contract.mjs";
import { assertInitialBindingSchemaClosed, assertInitialDualSlotBindings, verifyLiveInitialDualSlotBindingWithRunner } from "./production-initial-dual-slot-bootstrap.mjs";
import { MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR } from "./production-mixed-dual-slot-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : Buffer.from(canonicalJson(value))).digest("hex");
const runJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactKeys = (value, keys, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) throw new Error(`${label} schema is invalid.`);
  return value;
};
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const requiredSha = (value, label) => { if (!/^[a-f0-9]{40}$/.test(value || "")) throw new Error(`${label} must be an exact source SHA.`); return value; };
const parseGithubJson = (run, args, label) => { try { return JSON.parse(run("gh", args)); } catch { throw new Error(`${label} is malformed or unavailable.`); } };
const noSuchEntity = (error) => /\bNoSuchEntity(?:Exception)?\b/.test(`${error?.stderr || ""} ${error?.message || ""}`);
const bootstrapOperatorPolicyReconciliationSleep = (milliseconds) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
const isTransientBootstrapOperatorRead = (error) => /\b(?:Throttling|ThrottlingException|TooManyRequestsException|RequestLimitExceeded|ServiceUnavailable|ServiceUnavailableException|ServiceFailure|InternalFailure|InternalError)\b/.test(`${error?.code || ""} ${error?.name || ""} ${error?.stderr || ""} ${error?.message || ""}`);

export const BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION = Object.freeze({
  schemaVersion: 1,
  operation: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION",
  repository: "T-ej2003/genuine-scan-main",
  environment: PRODUCTION_ENVIRONMENT_APPROVAL.bootstrapOperatorPolicyAuthorizationEnvironment,
  account: "368992683803",
  administratorArn: "arn:aws:iam::368992683803:root",
  userName: "mscqr-production-bootstrap-operator",
  userArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator",
  inlinePolicyName: "MSCQRProductionBootstrapOperator",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  verifierRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier",
  publisherBootstrapRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-stage-b-publisher-bootstrap",
  sourcePath: "documents/ops/iam/MSCQRProductionBootstrapOperator-v1.json",
  workflowPath: ".github/workflows/authorize-production-bootstrap-operator-policy-reconciliation.yml",
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.bootstrapOperatorPolicyReconciliationWorkflowRef,
  artifactName: "production-bootstrap-operator-policy-reconciliation-authorization",
  authorizationRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-bootstrap-operator-policy-authorizer",
  authorizationPolicyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionBootstrapOperatorPolicyAuthorizer",
  authorizationPolicyPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/bootstrap-operator-policy-authorizer-permissions-policy.json",
  legacyTransitionConsumptionTagKey: "mscqr:LegacyBootstrapTransitionAuthorization",
  legacyTransitionReservationKey: `${PRODUCTION_ACTIVATION_LIFECYCLE.initialActivationPolicyReconciliationReservationPrefix}bootstrap-operator-legacy-mfa-transition.json`,
  authorizationFilename: "authorization.json",
  maxAgeMs: 30 * 60 * 1000,
  maxAwsMutations: Object.freeze({ "iam:PutUserPolicy": 1, "iam:TagUser": 2, "s3:PutObject": 1 }),
  postWriteReadDelaysMs: Object.freeze([250, 500, 1000, 2000, 4000]),
});

// This is deliberately a one-transaction compatibility state, not an alternate
// credential model. The regular reconciler continues to require zero keys.
export const LEGACY_BOOTSTRAP_TRANSITION_KIND = "LEGACY_BOOTSTRAP_MFA_TRANSITION";
export const LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID = "rotation-20260913011819-98b062c4";
export const LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA = "054d1adce8a477df362719f5b7b70c98483cedc7";
export const LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 = "49013c088ca4e9b9093e566f88d90589acff6e085823f39d45977d0342e88bc7";
export const LEGACY_BOOTSTRAP_TRANSITION_SUPERSESSION_GENERATED_AT = "2026-09-13T01:38:21.459Z";
export const LEGACY_BOOTSTRAP_TRANSITION_LIVE_PREDECESSOR_POLICY_SHA256 = "bd4764ea853548d4cff8814113fb846ac203dfdeb1c6de5e6825e02e9f4c4f00";
export const LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES = Object.freeze([
  ...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES,
  ...MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.legacySecretArns,
]);
export const LEGACY_BOOTSTRAP_MFA_TRANSITION = Object.freeze({
  kind: LEGACY_BOOTSTRAP_TRANSITION_KIND,
  releaseLifecycle: "authenticated-initial-overlap",
  rotationId: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID,
  historicalTransactionSourceSha: LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA,
  rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256,
  supersessionGeneratedAt: LEGACY_BOOTSTRAP_TRANSITION_SUPERSESSION_GENERATED_AT,
  livePredecessorPolicySha256: LEGACY_BOOTSTRAP_TRANSITION_LIVE_PREDECESSOR_POLICY_SHA256,
  accessKeyCount: 2,
  accessKeyStatus: "Active",
  accessKeyCreatedAt: Object.freeze(["2026-07-29T19:28:57.000Z", "2026-07-29T19:31:58.000Z"]),
  bootstrapProfile: "mscqr-production-bootstrap-operator",
});

const legacyTransition = (value) => {
  try { exactKeys(value, ["kind", "rotationBindingsFileSha256"], "Legacy bootstrap MFA transition"); } catch { return false; }
  return value.kind === LEGACY_BOOTSTRAP_TRANSITION_KIND && value.rotationBindingsFileSha256 === LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256;
};
const legacyAccessKeyCreatedAt = (accessKeys) => accessKeys.map(({ CreateDate }) => new Date(CreateDate).toISOString()).sort();
const readLegacyTransitionConsumption = (run) => {
  const tags = runJson(run, ["iam", "list-user-tags", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).Tags;
  if (!Array.isArray(tags) || tags.some((tag) => !tag || typeof tag.Key !== "string" || typeof tag.Value !== "string")) throw new Error("Bootstrap operator transition consumption tags are malformed.");
  const markers = tags.filter(({ Key }) => Key === BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey);
  if (markers.length > 1) throw new Error("Bootstrap operator transition consumption marker is invalid.");
  if (!markers.length) return null;
  const completed = /^completed:([a-f0-9]{64})$/.exec(markers[0].Value);
  if (completed) return Object.freeze({ state: "COMPLETED", authorizationSha256: completed[1] });
  const reserved = /^reserved:([a-f0-9]{64}):(.+)$/.exec(markers[0].Value);
  const expiresAt = new Date(reserved?.[2]);
  if (!reserved || !Number.isFinite(expiresAt.getTime()) || expiresAt.toISOString() !== reserved[2]) throw new Error("Bootstrap operator transition consumption marker is invalid.");
  return Object.freeze({ state: "RESERVED", authorizationSha256: reserved[1], expiresAt: reserved[2] });
};
const assertLegacyTransitionAvailable = (run, now) => {
  const marker = readLegacyTransitionConsumption(run);
  if (marker?.state === "COMPLETED") throw new Error("Legacy bootstrap MFA transition has already been consumed.");
  if (marker?.state === "RESERVED" && new Date(marker.expiresAt).getTime() >= now.getTime()) throw new Error("Legacy bootstrap MFA transition has an active reservation.");
  return marker;
};
const legacyTransitionMarker = (state, authorization) => state === "RESERVED" ? `reserved:${authorization.authorizationSha256}:${authorization.preparation.expiresAt}` : `completed:${authorization.authorizationSha256}`;
const writeLegacyTransitionMarker = (run, value) => run(["iam", "tag-user", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, "--tags", `Key=${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey},Value=${value}`, "--no-cli-pager"]);
const LEGACY_RESERVATION_LEASE_MS = 2 * 60 * 1000;
const legacyReservationBody = (authorization, { executionId = crypto.randomUUID(), now = new Date() } = {}) => {
  const leaseExpiresAt = new Date(Math.min(new Date(authorization.preparation.expiresAt).getTime(), now.getTime() + LEGACY_RESERVATION_LEASE_MS)).toISOString();
  return Object.freeze({ schemaVersion: 2, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION", authorizationSha256: authorization.authorizationSha256, expiresAt: authorization.preparation.expiresAt, executionId, leaseExpiresAt });
};
const assertLegacyReservation = (value) => {
  const keys = value?.schemaVersion === 1 ? ["schemaVersion", "kind", "authorizationSha256", "expiresAt"] : ["schemaVersion", "kind", "authorizationSha256", "expiresAt", "executionId", "leaseExpiresAt"];
  exactKeys(value, keys, "Legacy bootstrap MFA transition reservation");
  const expiresAt = new Date(value.expiresAt);
  const leaseExpiresAt = value.schemaVersion === 2 ? new Date(value.leaseExpiresAt) : null;
  if (![1, 2].includes(value.schemaVersion) || value.kind !== "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION" || !/^[a-f0-9]{64}$/.test(value.authorizationSha256 || "") || !Number.isFinite(expiresAt.getTime()) || expiresAt.toISOString() !== value.expiresAt || value.schemaVersion === 2 && (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.executionId || "") || !Number.isFinite(leaseExpiresAt.getTime()) || leaseExpiresAt.toISOString() !== value.leaseExpiresAt || leaseExpiresAt > expiresAt)) throw new Error("Legacy bootstrap MFA transition reservation is invalid.");
  return value;
};
const noSuchKey = (error) => /\bNoSuchKey\b/.test(`${error?.stderr || ""} ${error?.message || ""}`);
const conditionalConflict = (error) => /\b(?:PreconditionFailed|ConditionalRequestConflict)\b/.test(`${error?.stderr || ""} ${error?.message || ""}`);
const readLegacyTransitionReservation = (run) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-operator-reservation-"));
  const output = path.join(directory, "reservation.json");
  try {
    let response;
    try { response = runJson(run, ["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionReservationKey, output]); }
    catch (error) { if (noSuchKey(error)) return null; throw error; }
    if (typeof response?.ETag !== "string" || !/^"[0-9a-f]{32}"$/.test(response.ETag)) throw new Error("Legacy bootstrap MFA transition reservation ETag is invalid.");
    return Object.freeze({ value: assertLegacyReservation(JSON.parse(fs.readFileSync(output, "utf8"))), etag: response.ETag });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
const putLegacyTransitionReservation = (run, authorization, condition, reservation = legacyReservationBody(authorization)) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-operator-reservation-"));
  const body = path.join(directory, "reservation.json");
  try {
    fs.writeFileSync(body, `${canonicalJson(reservation)}\n`, { flag: "wx", mode: 0o600 });
    try {
      if (condition === "CREATE") run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionReservationKey, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*", "--no-cli-pager"]);
      else run(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionReservationKey, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-match", condition, "--no-cli-pager"]);
      return true;
    } catch (error) { if (conditionalConflict(error)) return false; throw error; }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
const acquireLegacyTransitionReservation = (run, authorization, now) => {
  let current = readLegacyTransitionReservation(run);
  const leaseActive = (reservation) => reservation && (reservation.schemaVersion === 1 ? new Date(reservation.expiresAt).getTime() >= now.getTime() : new Date(reservation.leaseExpiresAt).getTime() >= now.getTime());
  if (leaseActive(current?.value)) throw new Error("Legacy bootstrap MFA transition reservation is held by another active executor/authorization.");
  const expected = legacyReservationBody(authorization, { now });
  if (!putLegacyTransitionReservation(run, authorization, current ? current.etag : "CREATE", expected)) {
    current = readLegacyTransitionReservation(run);
    if (leaseActive(current?.value)) throw new Error("Legacy bootstrap MFA transition reservation is held by another active executor/authorization.");
    throw new Error("Legacy bootstrap MFA transition reservation acquisition conflicted.");
  }
  const verified = readLegacyTransitionReservation(run);
  if (!verified || canonicalJson(verified.value) !== canonicalJson(expected)) throw new Error("Legacy bootstrap MFA transition reservation did not converge.");
  return Object.freeze({ acquired: true, resumed: false, reservation: verified });
};
const assertOwnedUnexpiredLegacyTransitionReservation = (run, authorization, now, owned) => {
  const reservation = readLegacyTransitionReservation(run);
  if (!owned?.reservation || !reservation || canonicalJson(reservation.value) !== canonicalJson(owned.reservation.value) || reservation.value.authorizationSha256 !== authorization.authorizationSha256 || (reservation.value.schemaVersion === 2 ? new Date(reservation.value.leaseExpiresAt).getTime() : new Date(reservation.value.expiresAt).getTime()) <= now.getTime() || new Date(reservation.value.expiresAt).getTime() <= now.getTime()) throw new Error("Legacy bootstrap MFA transition reservation is no longer owned and fresh.");
  return reservation;
};
const initialOverlapResources = (bindings) => ({ jwtPrevious: bindings.jwt.previousSecretId, jwtPending: bindings.jwt.pendingSecretId, qrPrivatePending: bindings.qr.privatePendingSecretId, qrPublicPrevious: bindings.qr.publicPreviousSecretId, qrPublicPending: bindings.qr.publicPendingSecretId, qrCurrentVersion: bindings.qr.currentKeyVersionSecretId, qrPreviousVersion: bindings.qr.previousKeyVersionSecretId });
const assertLegacyBootstrapMfaTransitionStaticBinding = (bindings, transition) => {
  if (!legacyTransition(transition) || bindings?.schemaVersion !== 3) throw new Error("Legacy bootstrap MFA transition is not bound to the reviewed finalized supersession.");
  assertInitialBindingSchemaClosed(bindings);
  const current = bindings.supersessionPredecessor?.current;
  const legacy = { jwtCurrent: bindings.jwt.currentSecretId, qrPrivateCurrent: bindings.qr.privateCurrentSecretId, qrPublicCurrent: bindings.qr.publicCurrentSecretId, qrCurrentVersion: bindings.qr.previousKeyVersion };
  if (assertInitialDualSlotBindings(bindings) !== true || canonicalJson(Object.values(initialOverlapResources(bindings)).sort()) !== canonicalJson([...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES].sort()) || bindings.sourceSha !== LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA || bindings.rotationId !== LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID || bindings.supersessionEvidence.generatedAt !== LEGACY_BOOTSTRAP_TRANSITION_SUPERSESSION_GENERATED_AT || canonicalJson(bindings.legacy) !== canonicalJson(legacy) || current?.jwt?.secretArn !== bindings.jwt.currentSecretId || current?.qrPrivate?.secretArn !== bindings.qr.privateCurrentSecretId || current?.qrPublic?.secretArn !== bindings.qr.publicCurrentSecretId || bindings.supersessionPredecessor.runtimeQrVersionLabel !== bindings.qr.previousKeyVersion) throw new Error("Legacy bootstrap MFA transition is not bound to the reviewed initial-overlap resources.");
  return bindings;
};
const legacyBindingOrigin = (origin, bindings, transition) => {
  const { bindingSha256, originSha256, ...body } = origin || {};
  const resources = initialOverlapResources(bindings);
  const optional = [bindings.supersessionPredecessor ? "supersessionPredecessorIdentitySha256" : null, bindings.retainedHistory ? "retainedHistoryCanonicalId" : null, bindings.recoveryHandoff ? "recoveryHandoffCanonicalId" : null].filter(Boolean);
  try { exactKeys(body, ["schemaVersion", "kind", "producer", "sourceSha", "rotationId", "resources", "observedSlots", ...optional], "Legacy bootstrap MFA transition origin"); } catch { return false; }
  return body.schemaVersion === 1 && body.kind === "PRODUCTION_INITIAL_DUAL_SLOT_BINDING_ORIGIN" && body.producer === bindings.producer && body.sourceSha === LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA && body.rotationId === LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID
    && canonicalJson(body.resources) === canonicalJson(resources) && body.observedSlots && typeof body.observedSlots === "object" && !Array.isArray(body.observedSlots) && canonicalJson(Object.keys(body.observedSlots).sort()) === canonicalJson(Object.keys(resources).sort())
    && Object.entries(resources).every(([slot, arn]) => body.observedSlots[slot]?.arn === arn && typeof body.observedSlots[slot]?.versionId === "string" && body.observedSlots[slot].versionId.length > 0 && canonicalJson(body.observedSlots[slot].stages) === canonicalJson(["AWSCURRENT"]))
    && (!bindings.supersessionPredecessor || body.supersessionPredecessorIdentitySha256 === bindings.supersessionPredecessor.predecessorIdentitySha256)
    && (!bindings.retainedHistory || body.retainedHistoryCanonicalId === bindings.retainedHistoryCanonicalId)
    && (!bindings.recoveryHandoff || body.recoveryHandoffCanonicalId === bindings.recoveryHandoffCanonicalId)
    && bindingSha256 === sha256(bindings) && originSha256 === sha256(body);
};
export function assertLegacyBootstrapMfaTransitionBinding(bindings, transition, origin) {
  assertLegacyBootstrapMfaTransitionStaticBinding(bindings, transition);
  if (!legacyBindingOrigin(origin, bindings, transition)) throw new Error("Legacy bootstrap MFA transition is not bound to the authenticated initial-overlap rotation.");
  return bindings;
}
export function verifyLegacyBootstrapMfaTransitionBinding({ run, bindings, transition, currentSourceSha, proveDescendant, verifyLiveBinding = verifyLiveInitialDualSlotBindingWithRunner } = {}) {
  assertLegacyBootstrapMfaTransitionStaticBinding(bindings, transition);
  if (typeof proveDescendant !== "function" || proveDescendant({ ancestorSha: bindings.sourceSha, descendantSha: requiredSha(currentSourceSha, "Legacy bootstrap MFA transition current source SHA") }) !== true) throw new Error("Legacy bootstrap MFA transition current source is not descended from the authenticated historical transaction.");
  const origin = verifyLiveBinding({ run, bindings, proveDescendant });
  assertLegacyBootstrapMfaTransitionBinding(bindings, transition, origin);
  return origin;
}
const credentialTopology = ({ accessKeys, consoleLoginPresent, mfaDevices, transition }) => {
  const mfaExact = canonicalJson(mfaDevices) === canonicalJson([{ UserName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, SerialNumber: ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN }]);
  if (consoleLoginPresent !== false || !Array.isArray(accessKeys) || !mfaExact) throw new Error("Bootstrap operator credential topology is unexpected.");
  if (accessKeys.length === 0) return "ZERO_PERMANENT_ACCESS_KEYS";
  if (legacyTransition(transition) && accessKeys.length === LEGACY_BOOTSTRAP_MFA_TRANSITION.accessKeyCount && accessKeys.every((key) => typeof key?.AccessKeyId === "string" && key.Status === LEGACY_BOOTSTRAP_MFA_TRANSITION.accessKeyStatus && !Number.isNaN(new Date(key.CreateDate).getTime())) && canonicalJson(legacyAccessKeyCreatedAt(accessKeys)) === canonicalJson(LEGACY_BOOTSTRAP_MFA_TRANSITION.accessKeyCreatedAt)) return LEGACY_BOOTSTRAP_TRANSITION_KIND;
  throw new Error("Bootstrap operator credential topology is unexpected.");
};

export function readBootstrapOperatorDesiredPolicy({ repositoryRoot = root } = {}) {
  const document = normalizeIamPolicyDocument(fs.readFileSync(path.resolve(repositoryRoot, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.sourcePath), "utf8"), "bootstrap operator source policy");
  const expected = [
    { Sid: "AssumeReleaseRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    { Sid: "AssumeEcsExecVerifierRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    { Sid: "AssumeStageBPublisherBootstrapRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    { Sid: "ReadOwnMfaState", Effect: "Allow", Action: ["iam:GetUser", "iam:ListMFADevices"], Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn },
  ];
  if (document.Version !== "2012-10-17" || !Array.isArray(document.Statement) || document.Statement.length !== expected.length || expected.some((statement) => canonicalJson(document.Statement.find(({ Sid }) => Sid === statement.Sid)) !== canonicalJson(statement))) throw new Error("Bootstrap operator source policy is not the reviewed exact document.");
  const predecessorDocument = { Version: "2012-10-17", Statement: document.Statement.filter(({ Sid }) => Sid !== "AssumeEcsExecVerifierRoleOnlyWithMfa") };
  const legacyLivePredecessorDocument = { Version: "2012-10-17", Statement: document.Statement.filter(({ Sid }) => !["AssumeEcsExecVerifierRoleOnlyWithMfa", "AssumeStageBPublisherBootstrapRoleOnlyWithMfa"].includes(Sid)) };
  const legacyLivePredecessorPolicySha256 = sha256(legacyLivePredecessorDocument);
  if (legacyLivePredecessorPolicySha256 !== LEGACY_BOOTSTRAP_TRANSITION_LIVE_PREDECESSOR_POLICY_SHA256) throw new Error("Bootstrap operator legacy live predecessor is not the authenticated production policy.");
  return Object.freeze({ document, predecessorDocument, legacyLivePredecessorDocument, sourcePolicySha256: sha256(document), predecessorPolicySha256: sha256(predecessorDocument), legacyLivePredecessorPolicySha256 });
}

export function authenticateBootstrapOperatorLiveState(value, { desired = readBootstrapOperatorDesiredPolicy(), allowPostState = true, transition } = {}) {
  exactKeys(value, ["user", "attachedPolicies", "inlinePolicyNames", "groups", "consoleLoginPresent", "accessKeys", "mfaDevices", "document"], "Bootstrap operator live state");
  if (value.user?.Arn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn || value.user?.UserName !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName || value.user?.Path !== "/" || Object.hasOwn(value.user, "PermissionsBoundary")) throw new Error("Bootstrap operator user identity is unexpected.");
  if (!Array.isArray(value.attachedPolicies) || value.attachedPolicies.length || !Array.isArray(value.groups) || value.groups.length || canonicalJson(value.inlinePolicyNames) !== canonicalJson([BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName])) throw new Error("Bootstrap operator policy topology is unexpected.");
  const credentialState = credentialTopology({ accessKeys: value.accessKeys, consoleLoginPresent: value.consoleLoginPresent, mfaDevices: value.mfaDevices, transition });
  const document = normalizeIamPolicyDocument(value.document, "bootstrap operator live policy");
  const documentSha256 = sha256(document);
  const pre = documentSha256 === desired.predecessorPolicySha256;
  const legacyPre = legacyTransition(transition) && documentSha256 === desired.legacyLivePredecessorPolicySha256;
  const post = allowPostState && documentSha256 === desired.sourcePolicySha256;
  if (!pre && !legacyPre && !post) throw new Error("Bootstrap operator policy contains unexpected drift.");
  return Object.freeze({ ...value, document, documentSha256, credentialState, status: post ? "EXACT_COMPLETE" : legacyPre ? "EXACT_LEGACY_LIVE_PREDECESSOR" : "EXACT_PREDECESSOR" });
}

const authenticatePreparationLiveState = (value, transition) => {
  const { documentSha256, credentialState, status, ...raw } = value || {};
  const state = authenticateBootstrapOperatorLiveState(raw, { transition });
  if (documentSha256 === undefined && credentialState === undefined && status === undefined) return state;
  if (documentSha256 !== state.documentSha256 || credentialState !== state.credentialState || status !== state.status) throw new Error("Bootstrap operator authenticated live state changed before preparation.");
  return state;
};

export function readBootstrapOperatorLiveState({ run, transition } = {}) {
  if (typeof run !== "function") throw new Error("Bootstrap operator IAM runner is required.");
  const user = runJson(run, ["iam", "get-user", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).User;
  const attachedPolicies = runJson(run, ["iam", "list-attached-user-policies", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).AttachedPolicies;
  const inlinePolicyNames = runJson(run, ["iam", "list-user-policies", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).PolicyNames;
  const groups = runJson(run, ["iam", "list-groups-for-user", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).Groups;
  const accessKeys = runJson(run, ["iam", "list-access-keys", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).AccessKeyMetadata;
  const mfaDevices = runJson(run, ["iam", "list-mfa-devices", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]).MFADevices?.map(({ UserName, SerialNumber }) => ({ UserName, SerialNumber }));
  let consoleLoginPresent;
  try { runJson(run, ["iam", "get-login-profile", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName]); consoleLoginPresent = true; }
  catch (error) { if (!noSuchEntity(error)) throw error; consoleLoginPresent = false; }
  const document = runJson(run, ["iam", "get-user-policy", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, "--policy-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName]).PolicyDocument;
  return authenticateBootstrapOperatorLiveState({ user, attachedPolicies, inlinePolicyNames, groups, consoleLoginPresent, accessKeys, mfaDevices, document }, { transition });
}

const readBootstrapOperatorPostWriteState = ({ run, transition, sleep = bootstrapOperatorPolicyReconciliationSleep } = {}) => {
  let transient;
  for (let attempt = 0; attempt <= BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.postWriteReadDelaysMs.length; attempt += 1) {
    try {
      const state = readBootstrapOperatorLiveState({ run, transition });
      if (state.status === "EXACT_COMPLETE") return state;
    } catch (error) {
      if (!isTransientBootstrapOperatorRead(error)) throw error;
      transient = error;
    }
    if (attempt < BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.postWriteReadDelaysMs.length) {
      const milliseconds = BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.postWriteReadDelaysMs[attempt];
      if (!Number.isSafeInteger(milliseconds) || milliseconds <= 0 || milliseconds > 5000) throw new Error("Bootstrap operator policy convergence delay is invalid.");
      sleep(milliseconds);
    }
  }
  throw new Error("Bootstrap operator policy readback did not converge to the exact authorized post-state.", { cause: transient });
};

const predecessorStatus = (status) => ["EXACT_PREDECESSOR", "EXACT_LEGACY_LIVE_PREDECESSOR"].includes(status);
const writePlan = (state, transition) => {
  const desired = readBootstrapOperatorDesiredPolicy();
  const addedStatements = predecessorStatus(state.status) ? desired.document.Statement.filter(({ Sid }) => !state.document.Statement.some((statement) => statement.Sid === Sid)) : [];
  return [
    ...(legacyTransition(transition) && (predecessorStatus(state.status) || state.status === "EXACT_COMPLETE") ? [{ action: "s3:PutObject", resource: `${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionReservationKey}`, condition: "IF_NONE_MATCH_OR_EXACT_ETAG" }] : []),
    ...(legacyTransition(transition) && predecessorStatus(state.status) ? [{ action: "iam:TagUser", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, tagKey: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, valueBinding: "RESERVED_AUTHORIZATION_SHA256_AND_EXPIRY" }] : []),
    ...(predecessorStatus(state.status) ? [{ action: "iam:PutUserPolicy", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, policySha256: desired.sourcePolicySha256, addedStatements }] : []),
    ...(legacyTransition(transition) ? [{ action: "iam:TagUser", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, tagKey: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, valueBinding: "COMPLETED_AUTHORIZATION_SHA256" }] : []),
  ];
};
const preparationBody = ({ sourceSha, state, preparedAt, transition, legacyRotationBindings, legacyRotationBindingOrigin }) => ({
  schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_PREPARATION", operation: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation,
  sourceSha, userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName,
  predecessorClassification: state.status, predecessorPolicySha256: state.documentSha256, successorPolicySha256: readBootstrapOperatorDesiredPolicy().sourcePolicySha256,
  credentialState: state.credentialState,
  transition: state.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND ? transition : null,
  legacyRotationBindings: state.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND ? legacyRotationBindings : null,
  legacyRotationBindingOrigin: state.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND ? legacyRotationBindingOrigin : null,
  expectedWritePlan: writePlan(state, transition), expectedWritePlanSha256: sha256(writePlan(state, transition)),
  createdAt: new Date(preparedAt).toISOString(), expiresAt: new Date(new Date(preparedAt).getTime() + BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAgeMs).toISOString(),
});
const PREPARATION_KEYS = ["schemaVersion", "kind", "operation", "sourceSha", "userArn", "inlinePolicyName", "predecessorClassification", "predecessorPolicySha256", "successorPolicySha256", "credentialState", "transition", "legacyRotationBindings", "legacyRotationBindingOrigin", "expectedWritePlan", "expectedWritePlanSha256", "createdAt", "expiresAt", "preparationSha256"];
export function createBootstrapOperatorPolicyPreparation({ sourceSha, liveState, transition, legacyRotationBindings, legacyRotationBindingOrigin, preparedAt = new Date().toISOString() } = {}) {
  requiredSha(sourceSha, "Bootstrap operator preparation source SHA");
  if (transition !== undefined) assertLegacyBootstrapMfaTransitionBinding(legacyRotationBindings, transition, legacyRotationBindingOrigin);
  const state = authenticatePreparationLiveState(liveState, transition);
  if (!predecessorStatus(state.status) && state.status !== "EXACT_COMPLETE") throw new Error("Bootstrap operator preparation requires an exact governed policy state.");
  const body = preparationBody({ sourceSha, state, preparedAt, transition, legacyRotationBindings, legacyRotationBindingOrigin });
  return Object.freeze({ ...body, preparationSha256: sha256(body) });
}
export function assertBootstrapOperatorPolicyPreparation(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, PREPARATION_KEYS, "Bootstrap operator preparation");
  const desired = readBootstrapOperatorDesiredPolicy(); const { preparationSha256, ...body } = value;
  const created = new Date(value.createdAt); const expires = new Date(value.expiresAt);
  const state = value.predecessorClassification === "EXACT_PREDECESSOR" ? { status: "EXACT_PREDECESSOR", document: desired.predecessorDocument, documentSha256: desired.predecessorPolicySha256 } : value.predecessorClassification === "EXACT_LEGACY_LIVE_PREDECESSOR" ? { status: "EXACT_LEGACY_LIVE_PREDECESSOR", document: desired.legacyLivePredecessorDocument, documentSha256: desired.legacyLivePredecessorPolicySha256 } : value.predecessorClassification === "EXACT_COMPLETE" ? { status: "EXACT_COMPLETE", document: desired.document, documentSha256: desired.sourcePolicySha256 } : null;
  const transitionValid = value.credentialState === "ZERO_PERMANENT_ACCESS_KEYS" ? value.transition === null && value.legacyRotationBindings === null && value.legacyRotationBindingOrigin === null : value.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND && (() => { try { assertLegacyBootstrapMfaTransitionBinding(value.legacyRotationBindings, value.transition, value.legacyRotationBindingOrigin); return true; } catch { return false; } })();
  const expectedState = state && { ...state, credentialState: value.credentialState };
  if (!state || !transitionValid || value.schemaVersion !== 1 || value.kind !== "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_PREPARATION" || value.operation !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation || value.sourceSha !== sourceSha || value.userArn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn || value.inlinePolicyName !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName || value.predecessorPolicySha256 !== state.documentSha256 || value.successorPolicySha256 !== desired.sourcePolicySha256 || value.expectedWritePlanSha256 !== sha256(value.expectedWritePlan) || canonicalJson(value.expectedWritePlan) !== canonicalJson(preparationBody({ sourceSha, state: expectedState, preparedAt: value.createdAt, transition: value.transition, legacyRotationBindings: value.legacyRotationBindings, legacyRotationBindingOrigin: value.legacyRotationBindingOrigin }).expectedWritePlan) || preparationSha256 !== sha256(body) || !Number.isFinite(created.getTime()) || created.toISOString() !== value.createdAt || !Number.isFinite(expires.getTime()) || expires.toISOString() !== value.expiresAt || expires.getTime() - created.getTime() !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAgeMs || (!allowExpired && now.getTime() > expires.getTime())) throw new Error("Bootstrap operator preparation is not exact or fresh.");
  return value;
}

export function authenticateBootstrapOperatorAuthorizationLiveState({ run, preparation, sourceSha, proveDescendant, verifyLiveBinding = verifyLiveInitialDualSlotBindingWithRunner, now = new Date() } = {}) {
  if (typeof run !== "function") throw new Error("Bootstrap operator authorization AWS runner is required.");
  const prepared = assertBootstrapOperatorPolicyPreparation(preparation, { sourceSha, now });
  const principalArn = runJson(run, ["sts", "get-caller-identity"]).Arn;
  const expectedPrefix = `arn:aws:sts::${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.account}:assumed-role/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationRoleArn.split("/").at(-1)}/`;
  if (typeof principalArn !== "string" || !principalArn.startsWith(expectedPrefix) || principalArn.length === expectedPrefix.length) throw new Error("Bootstrap operator authorization requires the exact protected OIDC reconciler role.");
  if (prepared.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND) {
    assertLegacyTransitionAvailable(run, now);
    const liveOrigin = verifyLegacyBootstrapMfaTransitionBinding({ run: (args) => run(args.slice(1)), bindings: prepared.legacyRotationBindings, transition: prepared.transition, currentSourceSha: sourceSha, proveDescendant, verifyLiveBinding });
    if (canonicalJson(liveOrigin) !== canonicalJson(prepared.legacyRotationBindingOrigin)) throw new Error("Bootstrap operator authorization live initial-overlap binding changed after preparation.");
  }
  return Object.freeze({ principalArn, liveInitialOverlapBindingReverified: prepared.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND });
}

const AUTHORIZATION_KEYS = ["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "administratorArn", "userArn", "inlinePolicyName", "maxAwsMutations", "preparation", "preparationSha256", "protectedEnvironmentApprovalEvidence", "approvedBy", "authorizedAt", "authorizationSha256"];
export function createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence, authorizedAt = new Date().toISOString() } = {}) {
  const prepared = assertBootstrapOperatorPolicyPreparation(preparation, { sourceSha, now: new Date(authorizedAt) });
  assertProductionEnvironmentApprovalEvidence(protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, workflowRef: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowRef, eventName: "workflow_dispatch", workflowRunId: protectedEnvironmentApprovalEvidence?.workflowRunId, workflowRunAttempt: protectedEnvironmentApprovalEvidence?.workflowRunAttempt, executionActor: protectedEnvironmentApprovalEvidence?.executionActor, githubActions: "true", now: new Date(authorizedAt) });
  const maxAwsMutations = Object.freeze(Object.fromEntries(Object.entries(Object.groupBy(prepared.expectedWritePlan, ({ action }) => action)).map(([action, entries]) => [action, entries.length])));
  const body = { schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_AUTHORIZATION", operation: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, sourceSha, administratorArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn, userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, maxAwsMutations, preparation: prepared, preparationSha256: prepared.preparationSha256, protectedEnvironmentApprovalEvidence, approvedBy: assertProductionEnvironmentActualReviewer(protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, executionActor: protectedEnvironmentApprovalEvidence.executionActor }), authorizedAt };
  return Object.freeze({ ...body, authorizationSha256: sha256(body) });
}
export function assertBootstrapOperatorPolicyAuthorization(value, { sourceSha, now = new Date(), allowExpired = false } = {}) {
  exactKeys(value, AUTHORIZATION_KEYS, "Bootstrap operator authorization"); const { authorizationSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_AUTHORIZATION" || value.operation !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation || value.repository !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository || value.environment !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment || value.sourceSha !== sourceSha || value.administratorArn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn || value.userArn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn || value.inlinePolicyName !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName || value.preparationSha256 !== value.preparation?.preparationSha256 || value.authorizationSha256 !== sha256(body)) throw new Error("Bootstrap operator authorization binding is invalid.");
  const prepared = assertBootstrapOperatorPolicyPreparation(value.preparation, { sourceSha, now, allowExpired });
  const expectedMutations = Object.fromEntries(Object.entries(Object.groupBy(prepared.expectedWritePlan, ({ action }) => action)).map(([action, entries]) => [action, entries.length]));
  if (canonicalJson(value.maxAwsMutations) !== canonicalJson(expectedMutations)) throw new Error("Bootstrap operator authorization mutation envelope is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository });
  assertProductionEnvironmentApprovalFreshness(value.protectedEnvironmentApprovalEvidence, { now });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowRef || value.approvedBy !== assertProductionEnvironmentActualReviewer(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, executionActor: value.protectedEnvironmentApprovalEvidence.executionActor })) throw new Error("Bootstrap operator authorization approval is invalid.");
  return value;
}

export function reconcileBootstrapOperatorPolicy({ run, authorization, sourceSha, proveDescendant, verifyLiveBinding = verifyLiveInitialDualSlotBindingWithRunner, now = new Date(), clock = () => new Date(), sleep } = {}) {
  assertBootstrapOperatorPolicyAuthorization(authorization, { sourceSha, now });
  const transition = authorization.preparation.credentialState === LEGACY_BOOTSTRAP_TRANSITION_KIND ? authorization.preparation.transition : undefined;
  let iamTagUserCount = 0;
  let s3PutObjectCount = 0;
  let marker = null;
  let ownedReservation;
  const before = readBootstrapOperatorLiveState({ run, transition });
  if (transition) {
    const liveOrigin = verifyLegacyBootstrapMfaTransitionBinding({ run: (args) => run(args.slice(1)), bindings: authorization.preparation.legacyRotationBindings, transition, currentSourceSha: sourceSha, proveDescendant, verifyLiveBinding });
    if (canonicalJson(liveOrigin) !== canonicalJson(authorization.preparation.legacyRotationBindingOrigin)) throw new Error("Bootstrap operator execution live initial-overlap binding changed after authorization.");
    marker = readLegacyTransitionConsumption(run);
    if (marker?.state === "COMPLETED" && marker.authorizationSha256 !== authorization.authorizationSha256) throw new Error("Legacy bootstrap MFA transition was consumed by a different authorization.");
    if (marker?.state === "RESERVED" && marker.authorizationSha256 !== authorization.authorizationSha256 && new Date(marker.expiresAt).getTime() >= now.getTime()) throw new Error("Legacy bootstrap MFA transition is reserved by another active authorization.");
  }
  if (before.status === "EXACT_COMPLETE") {
    const sameTransitionResume = transition && marker?.state === "RESERVED" && marker.authorizationSha256 === authorization.authorizationSha256 && predecessorStatus(authorization.preparation.predecessorClassification) && before.documentSha256 === authorization.preparation.successorPolicySha256;
    const freshComplete = authorization.preparation.predecessorClassification === "EXACT_COMPLETE" && before.documentSha256 === authorization.preparation.predecessorPolicySha256;
    const completedReplay = transition && marker?.state === "COMPLETED" && marker.authorizationSha256 === authorization.authorizationSha256 && before.documentSha256 === authorization.preparation.successorPolicySha256;
    if (!sameTransitionResume && !freshComplete && !completedReplay) throw new Error("Bootstrap operator completed state differs from the authorized transaction.");
    if (transition && marker?.state !== "COMPLETED") {
      ownedReservation = acquireLegacyTransitionReservation(run, authorization, now);
      if (ownedReservation.acquired) s3PutObjectCount += 1;
      writeLegacyTransitionMarker(run, legacyTransitionMarker("COMPLETED", authorization));
      iamTagUserCount += 1;
      const completed = readLegacyTransitionConsumption(run);
      if (completed?.state !== "COMPLETED" || completed.authorizationSha256 !== authorization.authorizationSha256) throw new Error("Legacy bootstrap MFA transition completion marker did not converge.");
    }
    return Object.freeze({ status: "COMPLETE", iamPutUserPolicyCount: 0, ...(transition ? { iamTagUserCount, s3PutObjectCount } : {}), recovered: true });
  }
  if (!predecessorStatus(authorization.preparation.predecessorClassification) || before.status !== authorization.preparation.predecessorClassification || before.documentSha256 !== authorization.preparation.predecessorPolicySha256) throw new Error("Bootstrap operator predecessor changed after authorization.");
  if (transition) {
    if (marker?.state === "COMPLETED") throw new Error("Legacy bootstrap MFA transition has already been consumed.");
    ownedReservation = acquireLegacyTransitionReservation(run, authorization, now);
    if (ownedReservation.acquired) s3PutObjectCount += 1;
    if (marker?.state !== "RESERVED" || marker.authorizationSha256 !== authorization.authorizationSha256) {
      writeLegacyTransitionMarker(run, legacyTransitionMarker("RESERVED", authorization));
      iamTagUserCount += 1;
      marker = readLegacyTransitionConsumption(run);
      if (marker?.state !== "RESERVED" || marker.authorizationSha256 !== authorization.authorizationSha256 || marker.expiresAt !== authorization.preparation.expiresAt) throw new Error("Legacy bootstrap MFA transition reservation marker did not converge.");
    }
  }
  let recovered = false;
  if (transition) assertOwnedUnexpiredLegacyTransitionReservation(run, authorization, clock(), ownedReservation);
  try {
    run(["iam", "put-user-policy", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, "--policy-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, "--policy-document", `file://${path.join(root, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.sourcePath)}`, "--no-cli-pager"]);
  } catch (error) {
    try { readBootstrapOperatorPostWriteState({ run, transition, sleep }); }
    catch { throw error; }
    recovered = true;
  }
  if (!recovered) readBootstrapOperatorPostWriteState({ run, transition, sleep });
  if (transition) {
    writeLegacyTransitionMarker(run, legacyTransitionMarker("COMPLETED", authorization));
    iamTagUserCount += 1;
    const completed = readLegacyTransitionConsumption(run);
    if (completed?.state !== "COMPLETED" || completed.authorizationSha256 !== authorization.authorizationSha256) throw new Error("Legacy bootstrap MFA transition completion marker did not converge.");
  }
  return Object.freeze({ status: "COMPLETE", iamPutUserPolicyCount: 1, ...(transition ? { iamTagUserCount, s3PutObjectCount } : {}), recovered });
}

export function resolveBootstrapOperatorPolicyAuthorization({ workflowRunId, workflowRunAttempt, sourceSha, githubRun = createProductionGithubCommandRunner(), now = new Date() } = {}) {
  if (!/^[1-9][0-9]*$/.test(String(workflowRunId || "")) || String(workflowRunAttempt) !== "1") throw new Error("Bootstrap operator authorization workflow coordinates are invalid.");
  const workflow = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/runs/${workflowRunId}`], "Bootstrap operator workflow");
  if (String(workflow.id) !== String(workflowRunId) || workflow.repository?.full_name !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository || workflow.head_repository?.full_name !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository || workflow.path !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowPath || workflow.event !== "workflow_dispatch" || workflow.head_sha !== sourceSha || workflow.status !== "completed" || workflow.conclusion !== "success" || String(workflow.run_attempt) !== "1") throw new Error("Bootstrap operator authorization workflow provenance is not authentic.");
  const pages = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"], "Bootstrap operator authorization artifacts");
  const matches = (Array.isArray(pages) ? pages.flatMap((page) => page?.artifacts || []) : []).filter((artifact) => artifact?.name === BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.artifactName && artifact.expired === false && String(artifact.workflow_run?.id) === String(workflowRunId) && artifact.workflow_run?.head_sha === sourceSha && artifact.workflow_run?.repository_id === workflow.repository.id && /^sha256:[a-f0-9]{64}$/.test(artifact.digest || ""));
  if (matches.length !== 1 || !Number.isSafeInteger(matches[0]?.id)) throw new Error("Bootstrap operator authorization artifact identity is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-bootstrap-operator-auth-")); const archive = path.join(directory, "authorization.zip");
  try {
    const bytes = Buffer.from(githubRun("gh", ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/artifacts/${matches[0].id}/zip`], { encoding: null, maxBuffer: 8 * 1024 * 1024 }));
    if (`sha256:${sha256(bytes)}` !== matches[0].digest) throw new Error("Bootstrap operator authorization artifact digest is invalid.");
    fs.writeFileSync(archive, bytes, { flag: "wx", mode: 0o600 });
    if (String(githubRun("unzip", ["-Z1", archive])).trim() !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationFilename) throw new Error("Bootstrap operator authorization artifact contents are not exact.");
    const authorization = JSON.parse(Buffer.from(githubRun("unzip", ["-p", archive, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationFilename])).toString("utf8"));
    assertBootstrapOperatorPolicyAuthorization(authorization, { sourceSha, now });
    const environment = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/environments/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment}`], "Bootstrap operator environment");
    const approvals = parseGithubJson(githubRun, ["api", `repos/${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository}/actions/runs/${workflowRunId}/approvals`], "Bootstrap operator approvals");
    const actual = (Array.isArray(approvals) ? approvals : []).flatMap((approval) => approval?.state === "approved" ? (approval.environments || []).filter((item) => item?.id === environment.id && item?.name === BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment).map(() => ({ state: "approved", environmentId: environment.id, environmentName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, userId: approval.user?.id, userLogin: approval.user?.login })) : []);
    if (actual.length !== 1) throw new Error("Exactly one authenticated bootstrap operator production approval is required.");
    const observed = createProductionEnvironmentApprovalEvidence({ environmentConfig: environment, repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, sourceSha, workflowRef: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.workflowRef, eventName: "workflow_dispatch", workflowRunId: String(workflow.id), workflowRunAttempt: "1", executionActor: workflow.actor?.login, observedAt: authorization.protectedEnvironmentApprovalEvidence.observedAt, actualApproval: actual[0] });
    if (canonicalJson(observed) !== canonicalJson(authorization.protectedEnvironmentApprovalEvidence)) throw new Error("Bootstrap operator authorization approval differs from GitHub provenance.");
    return authorization;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function runBootstrapOperatorPolicyReconciliationCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = requiredSha(required(argv, "--source-sha"), "Bootstrap operator policy source SHA");
  if (argv.includes("--prepare")) {
    let transition;
    let legacyRotationBindings;
    let legacyRotationBindingOrigin;
    if (argv.includes("--legacy-bootstrap-mfa-transition")) {
      if (required(argv, "--rotation-id") !== LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID) throw new Error("Legacy bootstrap MFA transition rotation ID is not the reviewed initial-overlap rotation.");
      transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: required(argv, "--rotation-bindings-file-sha256") };
      legacyRotationBindings = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--rotation-bindings")), expectedSha256: transition.rotationBindingsFileSha256, repositoryRoot: root, label: "Legacy bootstrap MFA transition bindings" });
    }
    assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec: deps.exec || execFileSync });
    const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(argv, "--admin-profile") });
    if (runJson(run, ["sts", "get-caller-identity"]).Arn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn) throw new Error("Bootstrap operator preparation requires the exact root administrator.");
    if (transition) {
      assertLegacyTransitionAvailable(run, deps.now || new Date());
      const proveDescendant = ({ ancestorSha, descendantSha }) => { try { (deps.exec || execFileSync)("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; } };
      legacyRotationBindingOrigin = verifyLegacyBootstrapMfaTransitionBinding({ run: (args) => run(args.slice(1)), bindings: legacyRotationBindings, transition, currentSourceSha: sourceSha, proveDescendant });
    }
    const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: readBootstrapOperatorLiveState({ run, transition }), transition, legacyRotationBindings, legacyRotationBindingOrigin, preparedAt: (deps.now || new Date()).toISOString() });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Bootstrap operator preparation", allowExisting: false });
    ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap operator preparation directory" });
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(preparation, null, 2)}\n`), label: "Bootstrap operator preparation" }] }); return preparation;
  }
  if (argv.includes("--legacy-bootstrap-mfa-transition") || argv.includes("--rotation-id")) throw new Error("Legacy bootstrap MFA transition is valid only during preparation.");
  if (argv.includes("--authorize")) {
    const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--preparation")), expectedSha256: required(argv, "--preparation-file-sha256"), repositoryRoot: root, label: "Bootstrap operator preparation" });
    const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-file-sha256"), repositoryRoot: root, label: "Bootstrap operator environment approval" });
    assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec: deps.exec || execFileSync });
    const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER });
    const proveDescendant = ({ ancestorSha, descendantSha }) => { try { (deps.exec || execFileSync)("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; } };
    authenticateBootstrapOperatorAuthorizationLiveState({ run, preparation, sourceSha, proveDescendant, verifyLiveBinding: deps.verifyLiveBinding, now: deps.now || new Date() });
    const authorization = createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: (deps.now || new Date()).toISOString() });
    const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Bootstrap operator authorization", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap operator authorization directory" }); writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Bootstrap operator authorization" }] }); return authorization;
  }
  if (!argv.includes("--execute")) throw new Error("Bootstrap operator reconciliation requires --prepare, --authorize, or --execute.");
  assertProtectedCheckout({ sourceSha, repositoryRoot: root, exec: deps.exec || execFileSync });
  const authorization = (deps.resolveAuthorization || resolveBootstrapOperatorPolicyAuthorization)({ workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), sourceSha, githubRun: deps.githubRun || createProductionGithubCommandRunner(), now: deps.now || new Date() });
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: required(argv, "--admin-profile") });
  if (runJson(run, ["sts", "get-caller-identity"]).Arn !== BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn) throw new Error("Bootstrap operator execution requires the exact root administrator.");
  const proveDescendant = ({ ancestorSha, descendantSha }) => { try { (deps.exec || execFileSync)("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; } };
  const reconciliation = reconcileBootstrapOperatorPolicy({ run, authorization, sourceSha, proveDescendant, verifyLiveBinding: deps.verifyLiveBinding, now: deps.now || new Date() });
  const result = Object.freeze({ schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION_RESULT", operation: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.operation, sourceSha, userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, authorizationSha256: authorization.authorizationSha256, ...reconciliation, completedAt: (deps.now || new Date()).toISOString() });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--result")), repositoryRoot: root, label: "Bootstrap operator reconciliation result", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Bootstrap operator reconciliation result directory" }); writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(result, null, 2)}\n`), label: "Bootstrap operator reconciliation result" }] }); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runBootstrapOperatorPolicyReconciliationCli(), null, 2)}\n`);
