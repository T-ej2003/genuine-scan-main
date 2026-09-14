import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR } from "../aws/production-mixed-dual-slot-recovery-contract.mjs";
import {
  BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION,
  LEGACY_BOOTSTRAP_MFA_TRANSITION,
  LEGACY_BOOTSTRAP_TRANSITION_KIND,
  LEGACY_BOOTSTRAP_TRANSITION_LIVE_PREDECESSOR_POLICY_SHA256,
  LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256,
  LEGACY_BOOTSTRAP_TRANSITION_SUPERSESSION_GENERATED_AT,
  LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID,
  LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES,
  LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA,
  assertLegacyBootstrapMfaTransitionBinding,
  authenticateBootstrapOperatorAuthorizationLiveState,
  authenticateBootstrapOperatorLiveState,
  createBootstrapOperatorPolicyAuthorization,
  createBootstrapOperatorPolicyPreparation,
  readBootstrapOperatorDesiredPolicy,
  reconcileBootstrapOperatorPolicy,
  verifyLegacyBootstrapMfaTransitionBinding,
} from "../aws/production-bootstrap-operator-policy-reconciliation.mjs";
import { assertEcsExecOperatorTrustDocument, ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN } from "../aws/production-ecs-exec-operator-contract.mjs";
import { rotationBindingsToTaskBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { productionStaleSupersessionPredecessorIdentity, productionSupersessionEvidenceIdentity, productionSupersessionVersionId } from "../security/production-initial-migration-source-advance.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-09-14T12:00:00.000Z");
const desired = readBootstrapOperatorDesiredPolicy();
const approval = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 7, name: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 3, login: "reviewer" } }] }] },
  repository: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.repository, environment: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.bootstrapOperatorPolicyReconciliationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "100", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 7, environmentName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.environment, userId: 3, userLogin: "reviewer" },
});
const live = (document, credentialTopology = {}) => ({ user: { Arn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, UserName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, Path: "/" }, attachedPolicies: [], inlinePolicyNames: [BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName], groups: [], consoleLoginPresent: false, accessKeys: [], mfaDevices: [{ UserName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, SerialNumber: ECS_EXEC_OPERATOR_BOOTSTRAP_MFA_SERIAL_ARN }], ...credentialTopology, document });
const authorized = () => {
  const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.predecessorDocument), preparedAt: now.toISOString() });
  return createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() });
};
const recoveredAuthorization = () => {
  const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.document), preparedAt: now.toISOString() });
  return createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() });
};
const legacyAccessKeys = Object.freeze([
  { AccessKeyId: "key-a", Status: "Active", CreateDate: "2026-07-29T19:28:57Z" },
  { AccessKeyId: "key-b", Status: "Active", CreateDate: "2026-07-29T19:31:58Z" },
]);
const legacyAuthorized = () => {
  const transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 };
  const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.predecessorDocument, { accessKeys: legacyAccessKeys }), transition, legacyRotationBindings: legacyBindings(), legacyRotationBindingOrigin: legacyBindingOrigin(), preparedAt: now.toISOString() });
  return createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() });
};
const legacyLivePredecessorAuthorized = () => {
  const transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 };
  const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.legacyLivePredecessorDocument, { accessKeys: legacyAccessKeys }), transition, legacyRotationBindings: legacyBindings(), legacyRotationBindingOrigin: legacyBindingOrigin(), preparedAt: now.toISOString() });
  return createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() });
};
const legacyRecoveredAuthorization = (credentialTopology = {}) => {
  const transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 };
  const preparation = createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.document, { accessKeys: legacyAccessKeys }), transition, legacyRotationBindings: legacyBindings(), legacyRotationBindingOrigin: legacyBindingOrigin(), preparedAt: now.toISOString() });
  return createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() });
};
const legacyBindings = () => {
  const [jwtPending, qrPrivatePending, qrPublicPending, jwtPrevious, qrPublicPrevious, qrCurrentVersion, qrPreviousVersion] = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES;
  const resources = { jwtPending, qrPrivatePending, qrPublicPending, jwtPrevious, qrPublicPrevious, qrCurrentVersion, qrPreviousVersion };
  const predecessorSlotIdentities = Object.fromEntries(Object.entries(resources).map(([slot, secretArn]) => [slot, { secretArn, versionId: `previous-${slot}`, payloadSha256: createHash("sha256").update(`previous-${slot}`).digest("hex"), materialFingerprint: null, keyVersion: null }]));
  const supersessionEvidence = {
    schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha: LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA, staleSourceSha: "1".repeat(40), rotationId: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID, staleRotationId: "rotation-stale-predecessor", generatedAt: LEGACY_BOOTSTRAP_TRANSITION_SUPERSESSION_GENERATED_AT,
    resources: Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: productionSupersessionVersionId(LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA, LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID, slot), stages: ["AWSCURRENT"] }])),
    predecessorSlotIdentities,
  };
  supersessionEvidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(supersessionEvidence);
  const supersessionPredecessor = {
    schemaVersion: 1, kind: "PRODUCTION_STALE_SUPERSESSION_PREDECESSOR", sourceSha: LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA, rotationId: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID, staleSourceSha: supersessionEvidence.staleSourceSha, staleRotationId: supersessionEvidence.staleRotationId, supersessionEvidenceIdentitySha256: supersessionEvidence.evidenceIdentitySha256, runtimeQrVersionLabel: "legacy-current", currentRotationId: "rotation-current-predecessor",
    current: {
      jwt: { secretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk", versionId: "current-jwt-version", rotationId: "rotation-current-predecessor", family: "jwt_secrets", slot: "current", materialFingerprint: "1".repeat(16) },
      qrPrivate: { secretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO", versionId: "current-private-version", rotationId: "rotation-current-predecessor", family: "qr_signing_keys", slot: "current-private", keyVersion: "current-key", materialFingerprint: "2".repeat(16) },
      qrPublic: { secretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex", versionId: "current-public-version", rotationId: "rotation-current-predecessor", family: "qr_signing_keys", slot: "current-public", keyVersion: "current-key", materialFingerprint: "3".repeat(16) },
    },
    slotIdentities: predecessorSlotIdentities,
  };
  supersessionPredecessor.predecessorIdentitySha256 = productionStaleSupersessionPredecessorIdentity(supersessionPredecessor);
  const bindings = {
    schemaVersion: 3, kind: "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS", producer: "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation",
    sourceSha: LEGACY_BOOTSTRAP_TRANSITION_SOURCE_SHA, rotationId: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_ID,
    legacy: { jwtCurrent: supersessionPredecessor.current.jwt.secretArn, qrPrivateCurrent: supersessionPredecessor.current.qrPrivate.secretArn, qrPublicCurrent: supersessionPredecessor.current.qrPublic.secretArn, qrCurrentVersion: supersessionPredecessor.runtimeQrVersionLabel },
    jwt: { currentSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-wBQNqk", previousSecretId: jwtPrevious, pendingSecretId: jwtPending },
    qr: { privateCurrentSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_private_key-BcQFPO", privatePendingSecretId: qrPrivatePending, publicCurrentSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr_sign_public_key-v7Xeex", publicPreviousSecretId: qrPublicPrevious, publicPendingSecretId: qrPublicPending, currentKeyVersionSecretId: qrCurrentVersion, previousKeyVersionSecretId: qrPreviousVersion, previousKeyVersion: "legacy-current", pendingKeyVersion: "pending-key" },
    supersessionEvidence,
    supersessionPredecessor,
  };
  bindings.ecs = rotationBindingsToTaskBindings(bindings);
  return bindings;
};
const legacyBindingOrigin = (bindings = legacyBindings()) => {
  const resources = { jwtPrevious: bindings.jwt.previousSecretId, jwtPending: bindings.jwt.pendingSecretId, qrPrivatePending: bindings.qr.privatePendingSecretId, qrPublicPrevious: bindings.qr.publicPreviousSecretId, qrPublicPending: bindings.qr.publicPendingSecretId, qrCurrentVersion: bindings.qr.currentKeyVersionSecretId, qrPreviousVersion: bindings.qr.previousKeyVersionSecretId };
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_DUAL_SLOT_BINDING_ORIGIN", producer: bindings.producer, sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, resources, observedSlots: Object.fromEntries(Object.entries(resources).map(([slot, arn]) => [slot, { arn, versionId: `version-${slot}`, stages: ["AWSCURRENT"] }])), supersessionPredecessorIdentitySha256: bindings.supersessionPredecessor.predecessorIdentitySha256 };
  const hash = (value) => createHash("sha256").update(Buffer.from(canonicalJson(value))).digest("hex");
  return { ...body, bindingSha256: hash(bindings), originSha256: hash(body) };
};
const runner = (initial, credentialTopology = {}, { stalePostWriteReads = 0, transientPostWriteReads = 0 } = {}) => {
  let document = structuredClone(initial); let writes = 0; let tagWrites = 0; let reservationWrites = 0; const commands = []; let tags = structuredClone(credentialTopology.tags || []); let reservation = credentialTopology.reservation ? structuredClone(credentialTopology.reservation) : null; let reservationVersion = 0; let staleReads = 0; let transientReads = 0;
  const run = (args) => {
    commands.push([...args]);
    if (args[0] === "sts") return JSON.stringify({ Arn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.administratorArn });
    if (args[1] === "get-user") return JSON.stringify({ User: live(document).user });
    if (args[1] === "list-attached-user-policies") return JSON.stringify({ AttachedPolicies: [] });
    if (args[1] === "list-user-policies") return JSON.stringify({ PolicyNames: [BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName] });
    if (args[1] === "list-groups-for-user") return JSON.stringify({ Groups: [] });
    if (args[1] === "list-access-keys") return JSON.stringify({ AccessKeyMetadata: credentialTopology.accessKeys || [] });
    if (args[1] === "list-mfa-devices") return JSON.stringify({ MFADevices: credentialTopology.mfaDevices || live(document).mfaDevices });
    if (args[1] === "list-user-tags") return JSON.stringify({ Tags: tags });
    if (args[1] === "get-login-profile") {
      if (credentialTopology.consoleLoginPresent) return JSON.stringify({ LoginProfile: { UserName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName } });
      throw Object.assign(new Error("NoSuchEntity"), { stderr: "NoSuchEntity" });
    }
    if (args[1] === "get-user-policy") {
      if (writes && transientReads++ < transientPostWriteReads) throw Object.assign(new Error("ThrottlingException"), { stderr: "ThrottlingException" });
      return JSON.stringify({ PolicyDocument: writes && staleReads++ < stalePostWriteReads ? initial : document });
    }
    if (args[1] === "put-user-policy") { writes += 1; document = structuredClone(desired.document); return ""; }
    if (args[1] === "tag-user") {
      tagWrites += 1;
      const [Key, Value] = args[args.indexOf("--tags") + 1].split(",").map((part) => part.split("=")[1]);
      tags = [...tags.filter((tag) => tag.Key !== Key), { Key, Value }];
      return "";
    }
    if (args[0] === "s3api" && args[1] === "get-object") {
      if (!reservation) throw Object.assign(new Error("NoSuchKey"), { stderr: "NoSuchKey" });
      fs.writeFileSync(args[args.indexOf("--key") + 2], `${JSON.stringify(reservation)}\n`);
      return JSON.stringify({ ETag: `\"${String(reservationVersion).padStart(32, "0")}\"` });
    }
    if (args[0] === "s3api" && args[1] === "put-object") {
      const create = args.includes("--if-none-match"); const match = args.includes("--if-match") ? args[args.indexOf("--if-match") + 1] : null;
      if ((create && reservation) || (match && match !== `\"${String(reservationVersion).padStart(32, "0")}\"`)) throw Object.assign(new Error("PreconditionFailed"), { stderr: "PreconditionFailed" });
      reservation = JSON.parse(fs.readFileSync(args[args.indexOf("--body") + 1], "utf8")); reservationVersion += 1; reservationWrites += 1;
      return JSON.stringify({ ETag: `\"${String(reservationVersion).padStart(32, "0")}\"` });
    }
    throw new Error(`unexpected command: ${args.join(" ")}`);
  };
  return { run, writes: () => writes, tagWrites: () => tagWrites, reservationWrites: () => reservationWrites, document: () => document, tags: () => tags, reservation: () => reservation, commands: () => commands };
};
const permitsAssumeRole = ({ roleArn, mfa }) => desired.document.Statement.some((statement) => statement.Effect === "Allow" && statement.Action === "sts:AssumeRole" && statement.Resource === roleArn && statement.Condition?.Bool?.["aws:MultiFactorAuthPresent"] === "true" && mfa === true);

test("bootstrap policy contains only the three exact MFA-gated assumption targets", () => {
  const statements = new Map(desired.document.Statement.map((statement) => [statement.Sid, statement]));
  assert.deepEqual(statements.get("AssumeReleaseRoleOnlyWithMfa"), { Sid: "AssumeReleaseRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } });
  assert.deepEqual(statements.get("AssumeEcsExecVerifierRoleOnlyWithMfa"), { Sid: "AssumeEcsExecVerifierRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } });
  assert.deepEqual(statements.get("AssumeStageBPublisherBootstrapRoleOnlyWithMfa"), { Sid: "AssumeStageBPublisherBootstrapRoleOnlyWithMfa", Effect: "Allow", Action: "sts:AssumeRole", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } });
  assert.equal(desired.document.Statement.some(({ Resource }) => Resource === "*" || (Array.isArray(Resource) && Resource.includes("*"))), false);
  assert.equal(desired.document.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]).every((action) => ["sts:AssumeRole", "iam:GetUser", "iam:ListMFADevices"].includes(action)), true);
  assert.equal(desired.document.Statement.some(({ Action }) => JSON.stringify(Action).includes("ecs:") || JSON.stringify(Action).includes("secretsmanager:")), false);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, mfa: true }), true);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, mfa: true }), true);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, mfa: true }), true);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, mfa: false }), false);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, mfa: false }), false);
  assert.equal(permitsAssumeRole({ roleArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn, mfa: false }), false);
  assert.equal(permitsAssumeRole({ roleArn: "arn:aws:iam::368992683803:role/unrelated", mfa: true }), false);
  const trust = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_TRUST_POLICY.json", "utf8"));
  assert.doesNotThrow(() => assertEcsExecOperatorTrustDocument(trust));
});

test("RLS operator contract and canonical policy enumerate the same three MFA-gated targets", () => {
  const contract = JSON.parse(fs.readFileSync("documents/security/rls-program/production-full-rls-executor-contract.json", "utf8"));
  const requirement = contract.stageAOperatorPath.bootstrapOperatorRequirements.find((value) => value.startsWith("only sts:AssumeRole"));
  const targets = desired.document.Statement.filter(({ Action }) => Action === "sts:AssumeRole").map(({ Resource }) => Resource).sort();
  assert.deepEqual(targets, [BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.releaseRoleArn, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.verifierRoleArn, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.publisherBootstrapRoleArn].sort());
  assert.equal(targets.every((target) => requirement.includes(target)), true);
  assert.equal(requirement.includes("*"), false);
  assert.equal(desired.document.Statement.filter(({ Action }) => Action === "sts:AssumeRole").every((statement) => statement.Condition?.Bool?.["aws:MultiFactorAuthPresent"] === "true"), true);
});

test("governed reconciliation accepts only the exact predecessor and converges with one PutUserPolicy", () => {
  const authorization = authorized(); const fixture = runner(desired.predecessorDocument);
  assert.equal(authenticateBootstrapOperatorLiveState(live(desired.predecessorDocument)).status, "EXACT_PREDECESSOR");
  const result = reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, now });
  assert.deepEqual(result, { status: "COMPLETE", iamPutUserPolicyCount: 1, recovered: false });
  assert.equal(fixture.writes(), 1);
  assert.equal(authenticateBootstrapOperatorLiveState(live(fixture.document())).status, "EXACT_COMPLETE");
});

test("legacy transition authenticates the real live predecessor and binds its exact two-statement delta", () => {
  const authorization = legacyLivePredecessorAuthorized();
  const policyWrite = authorization.preparation.expectedWritePlan.find(({ action }) => action === "iam:PutUserPolicy");
  assert.equal(desired.legacyLivePredecessorPolicySha256, LEGACY_BOOTSTRAP_TRANSITION_LIVE_PREDECESSOR_POLICY_SHA256);
  assert.equal(authorization.preparation.predecessorClassification, "EXACT_LEGACY_LIVE_PREDECESSOR");
  assert.equal(authorization.preparation.predecessorPolicySha256, LEGACY_BOOTSTRAP_TRANSITION_LIVE_PREDECESSOR_POLICY_SHA256);
  assert.deepEqual(policyWrite.addedStatements, desired.document.Statement.filter(({ Sid }) => ["AssumeEcsExecVerifierRoleOnlyWithMfa", "AssumeStageBPublisherBootstrapRoleOnlyWithMfa"].includes(Sid)));
  assert.equal(authorization.preparation.expectedWritePlan.filter(({ action }) => action === "iam:PutUserPolicy").length, 1);
  assert.deepEqual(authorization.maxAwsMutations, { "iam:PutUserPolicy": 1, "iam:TagUser": 2, "s3:PutObject": 1 });

  const fixture = runner(desired.legacyLivePredecessorDocument, { accessKeys: legacyAccessKeys });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 1, iamTagUserCount: 2, s3PutObjectCount: 1, recovered: false });
  assert.deepEqual(fixture.document(), desired.document);
  const replay = runner(desired.document, { accessKeys: legacyAccessKeys, tags: fixture.tags() });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: replay.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 0, iamTagUserCount: 0, s3PutObjectCount: 0, recovered: true });
  assert.equal(replay.writes(), 0);
});

test("legacy live predecessor classification is exact and transition-only", () => {
  const transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 };
  const prepare = (document) => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(document, { accessKeys: legacyAccessKeys }), transition, legacyRotationBindings: legacyBindings(), legacyRotationBindingOrigin: legacyBindingOrigin(), preparedAt: now.toISOString() });
  assert.throws(() => authenticateBootstrapOperatorLiveState(live(desired.legacyLivePredecessorDocument)), /unexpected drift/);
  const transitionState = authenticateBootstrapOperatorLiveState(live(desired.legacyLivePredecessorDocument, { accessKeys: legacyAccessKeys }), { transition });
  assert.equal(transitionState.status, "EXACT_LEGACY_LIVE_PREDECESSOR");
  assert.equal(authenticateBootstrapOperatorLiveState(live(desired.predecessorDocument, { accessKeys: legacyAccessKeys }), { transition }).status, "EXACT_PREDECESSOR");
  assert.equal(authenticateBootstrapOperatorLiveState(live(desired.document, { accessKeys: legacyAccessKeys }), { transition }).status, "EXACT_COMPLETE");
  for (const mutate of [
    (document) => { document.Statement = document.Statement.filter(({ Sid }) => Sid !== "AssumeReleaseRoleOnlyWithMfa"); },
    (document) => { document.Statement = document.Statement.filter(({ Sid }) => Sid !== "ReadOwnMfaState"); },
    (document) => { document.Statement.find(({ Sid }) => Sid === "AssumeReleaseRoleOnlyWithMfa").Resource = "arn:aws:iam::368992683803:role/substituted"; },
    (document) => { delete document.Statement.find(({ Sid }) => Sid === "AssumeReleaseRoleOnlyWithMfa").Condition; },
    (document) => { document.Statement.push({ Sid: "ArbitraryThirdRole", Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::368992683803:role/unrelated", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }); },
    (document) => { document.Statement[0].Resource = "*"; },
    (document) => { document.Statement[0].Action = "sts:*"; },
    (document) => { document.Statement.push({ ...desired.document.Statement.find(({ Sid }) => Sid === "AssumeStageBPublisherBootstrapRoleOnlyWithMfa"), Condition: undefined }); },
    (document) => { document.Statement.push({ ...desired.document.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa"), Condition: undefined }); },
    (document) => { document.Statement.push({ ...desired.document.Statement.find(({ Sid }) => Sid === "AssumeStageBPublisherBootstrapRoleOnlyWithMfa"), Resource: "arn:aws:iam::368992683803:role/substituted-publisher" }); },
    (document) => { document.Statement.push({ ...desired.document.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa"), Resource: "arn:aws:iam::368992683803:role/substituted-verifier" }); },
    (document) => { document.Statement.push(desired.document.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa")); },
    (document) => { document.Statement.push({ Sid: "Extra", Effect: "Allow", Action: "iam:GetUser", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn }); },
  ]) {
    const altered = structuredClone(desired.legacyLivePredecessorDocument); mutate(altered);
    assert.throws(() => prepare(altered), /unexpected drift/);
  }
});

test("governed reconciliation retries only stale or transient IAM post-write readback", () => {
  for (const options of [{ stalePostWriteReads: 2 }, { transientPostWriteReads: 2 }]) {
    const fixture = runner(desired.predecessorDocument, {}, options); const waits = [];
    const result = reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization: authorized(), sourceSha, now, sleep: (milliseconds) => waits.push(milliseconds) });
    assert.deepEqual(result, { status: "COMPLETE", iamPutUserPolicyCount: 1, recovered: false });
    assert.equal(fixture.writes(), 1);
    assert.deepEqual(waits, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.postWriteReadDelaysMs.slice(0, 2));
  }
});

test("post-write convergence exhaustion never repeats the authorized IAM mutation", () => {
  const fixture = runner(desired.predecessorDocument, {}, { stalePostWriteReads: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.postWriteReadDelaysMs.length + 1 }); const waits = [];
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization: authorized(), sourceSha, now, sleep: (milliseconds) => waits.push(milliseconds) }), /did not converge/);
  assert.equal(fixture.writes(), 1);
  assert.deepEqual(waits, BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.postWriteReadDelaysMs);
});

test("fresh exact-complete recovery authorization finalizes without another IAM mutation", () => {
  const authorization = recoveredAuthorization(); const fixture = runner(desired.document);
  assert.equal(authorization.preparation.predecessorClassification, "EXACT_COMPLETE");
  assert.deepEqual(authorization.preparation.expectedWritePlan, []);
  assert.deepEqual(authorization.maxAwsMutations, {});
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, now }), { status: "COMPLETE", iamPutUserPolicyCount: 0, recovered: true });
  assert.equal(fixture.writes(), 0);
  const predecessor = runner(desired.predecessorDocument);
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: predecessor.run, authorization, sourceSha, now }), /predecessor changed/);
  assert.equal(predecessor.writes(), 0);
  const expired = runner(desired.predecessorDocument);
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: expired.run, authorization: authorized(), sourceSha, now: new Date(now.getTime() + BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAgeMs + 1) }), /not exact or fresh/);
  assert.equal(expired.writes(), 0);
});

test("legacy exact-complete authorization includes every reachable reservation and completion write", () => {
  const authorization = legacyRecoveredAuthorization();
  assert.deepEqual(authorization.preparation.expectedWritePlan.map(({ action }) => action), ["s3:PutObject", "iam:TagUser"]);
  assert.deepEqual(authorization.maxAwsMutations, { "s3:PutObject": 1, "iam:TagUser": 1 });
  const fixture = runner(desired.document, { accessKeys: legacyAccessKeys });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, now, proveDescendant: () => true, verifyLiveBinding: () => authorization.preparation.legacyRotationBindingOrigin }), { status: "COMPLETE", iamPutUserPolicyCount: 0, iamTagUserCount: 1, s3PutObjectCount: 1, recovered: true });
  assert.equal(fixture.reservationWrites(), 1);
  assert.equal(fixture.tagWrites(), 1);
  const owned = runner(desired.document, { accessKeys: legacyAccessKeys, reservation: { schemaVersion: 2, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION", authorizationSha256: authorization.authorizationSha256, expiresAt: authorization.preparation.expiresAt, executionId: "11111111-1111-4111-8111-111111111111", leaseExpiresAt: new Date(now.getTime() + 60_000).toISOString() } });
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: owned.run, authorization, sourceSha, now, proveDescendant: () => true, verifyLiveBinding: () => authorization.preparation.legacyRotationBindingOrigin }), /active executor/);
  assert.equal(owned.reservationWrites(), 0);
  assert.equal(owned.tagWrites(), 0);
  const expiredOwned = runner(desired.document, { accessKeys: legacyAccessKeys, reservation: { schemaVersion: 2, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION", authorizationSha256: authorization.authorizationSha256, expiresAt: authorization.preparation.expiresAt, executionId: "11111111-1111-4111-8111-111111111111", leaseExpiresAt: new Date(now.getTime() - 1).toISOString() } });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: expiredOwned.run, authorization, sourceSha, now, proveDescendant: () => true, verifyLiveBinding: () => authorization.preparation.legacyRotationBindingOrigin }), { status: "COMPLETE", iamPutUserPolicyCount: 0, iamTagUserCount: 1, s3PutObjectCount: 1, recovered: true });
  assert.equal(expiredOwned.reservationWrites(), 1);
  assert.equal(expiredOwned.tagWrites(), 1);
  const concurrent = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys, reservation: { schemaVersion: 2, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION", authorizationSha256: authorization.authorizationSha256, expiresAt: authorization.preparation.expiresAt, executionId: "11111111-1111-4111-8111-111111111111", leaseExpiresAt: new Date(now.getTime() + 60_000).toISOString() } });
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: concurrent.run, authorization, sourceSha, now, proveDescendant: () => true, verifyLiveBinding: () => authorization.preparation.legacyRotationBindingOrigin }), /active executor|predecessor changed/);
  assert.equal(concurrent.writes(), 0);
  assert.equal(concurrent.tagWrites(), 0);
  const completed = runner(desired.document, { accessKeys: legacyAccessKeys, tags: [{ Key: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, Value: `completed:${authorization.authorizationSha256}` }] });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: completed.run, authorization, sourceSha, now, proveDescendant: () => true, verifyLiveBinding: () => authorization.preparation.legacyRotationBindingOrigin }), { status: "COMPLETE", iamPutUserPolicyCount: 0, iamTagUserCount: 0, s3PutObjectCount: 0, recovered: true });
  assert.equal(completed.reservationWrites(), 0);
  assert.equal(completed.tagWrites(), 0);
});

test("missing verifier capability, malformed policy topology, and unrelated roles fail closed", () => {
  const extraRole = structuredClone(desired.document);
  extraRole.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa").Resource = "arn:aws:iam::368992683803:role/unrelated";
  assert.throws(() => authenticateBootstrapOperatorLiveState(live(extraRole)), /unexpected drift/);
  assert.throws(() => authenticateBootstrapOperatorLiveState({ ...live(desired.predecessorDocument), attachedPolicies: [{ PolicyArn: "arn:aws:iam::368992683803:policy/unexpected" }] }), /topology/);
  assert.doesNotThrow(() => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.document), preparedAt: now.toISOString() }));
});

test("governed reconciliation fails closed on a console password, access key, or incorrect MFA topology", () => {
  for (const credentialTopology of [
    { consoleLoginPresent: true },
    { accessKeys: [{ AccessKeyId: "AKIAEXAMPLE", Status: "Active" }] },
    { mfaDevices: [] },
    { mfaDevices: [{ UserName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, SerialNumber: "arn:aws:iam::368992683803:mfa/unreviewed" }] },
  ]) {
    assert.throws(() => authenticateBootstrapOperatorLiveState(live(desired.predecessorDocument, credentialTopology)), /credential topology/);
    const fixture = runner(desired.predecessorDocument, credentialTopology);
    assert.throws(() => reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization: authorized(), sourceSha, now }), /credential topology/);
    assert.equal(fixture.writes(), 0);
  }
});

test("the source-bound legacy MFA transition requires the exact historical binding and does not serialize raw key identifiers", () => {
  assert.deepEqual(BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.maxAwsMutations, { "iam:PutUserPolicy": 1, "iam:TagUser": 2, "s3:PutObject": 1 });
  const transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 };
  assert.doesNotThrow(() => assertLegacyBootstrapMfaTransitionBinding(legacyBindings(), transition, legacyBindingOrigin()));
  assert.throws(() => assertLegacyBootstrapMfaTransitionBinding(legacyBindings(), transition), /not bound/);
  assert.throws(() => assertLegacyBootstrapMfaTransitionBinding({ ...legacyBindings(), rotationId: "rotation-wrong" }, transition, legacyBindingOrigin()), /authenticated transition|not bound/);
  const schema2 = structuredClone(legacyBindings()); schema2.schemaVersion = 2; delete schema2.supersessionEvidence; delete schema2.supersessionPredecessor;
  assert.throws(() => assertLegacyBootstrapMfaTransitionBinding(schema2, transition, legacyBindingOrigin()), /finalized supersession/);
  assert.throws(() => assertLegacyBootstrapMfaTransitionBinding(legacyBindings(), { ...transition, rotationBindingsFileSha256: "b".repeat(64) }, legacyBindingOrigin()), /not bound/);
  for (const mutate of [
    (bindings) => { bindings.supersessionEvidence.evidenceIdentitySha256 = "0".repeat(64); },
    (bindings) => { delete bindings.supersessionEvidence; },
    (bindings) => { bindings.supersessionPredecessor.predecessorIdentitySha256 = "0".repeat(64); },
    (bindings) => { bindings.supersessionEvidence.resources.jwtPending.versionId = "substituted-version"; },
    (bindings) => { bindings.supersessionEvidence.generatedAt = "2026-09-13T01:38:21.460Z"; },
    (bindings) => { bindings.jwt.currentSecretId = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-substitute"; },
    (bindings) => { bindings.qr.privateCurrentSecretId = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-substitute"; },
    (bindings) => { bindings.qr.publicCurrentSecretId = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-substitute"; },
    (bindings) => { bindings.qr.previousKeyVersion = "substituted-version"; },
    (bindings) => { bindings.jwt.pendingSecretId = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-substitute"; },
    (bindings) => { delete bindings.jwt.pendingSecretId; },
    (bindings) => { bindings.jwt.extraSecretId = MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES[0]; },
  ]) {
    const altered = structuredClone(legacyBindings()); mutate(altered);
    assert.throws(() => assertLegacyBootstrapMfaTransitionBinding(altered, transition, legacyBindingOrigin(altered)));
  }
  assert.throws(() => assertLegacyBootstrapMfaTransitionBinding(legacyBindings(), transition, { ...legacyBindingOrigin(), originSha256: "0".repeat(64) }), /not bound/);
  assert.throws(() => assertLegacyBootstrapMfaTransitionBinding(legacyBindings(), transition, { ...legacyBindingOrigin(), unexpected: true }), /not bound/);
  const authorization = legacyAuthorized();
  assert.equal(authorization.preparation.credentialState, LEGACY_BOOTSTRAP_TRANSITION_KIND);
  assert.deepEqual(authorization.preparation.transition, transition);
  assert.deepEqual(authorization.preparation.legacyRotationBindings, legacyBindings());
  assert.deepEqual(authorization.preparation.legacyRotationBindingOrigin, legacyBindingOrigin());
  assert.deepEqual(authorization.maxAwsMutations, { "iam:PutUserPolicy": 1, "iam:TagUser": 2, "s3:PutObject": 1 });
  assert.deepEqual(authorization.preparation.expectedWritePlan.map(({ action }) => action), ["s3:PutObject", "iam:TagUser", "iam:PutUserPolicy", "iam:TagUser"]);
  assert.deepEqual(authorization.preparation.expectedWritePlan.find(({ action }) => action === "iam:PutUserPolicy").addedStatements, [desired.document.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa")]);
  assert.doesNotMatch(JSON.stringify(authorization), /key-a|key-b/);
  const fixture = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 1, iamTagUserCount: 2, s3PutObjectCount: 1, recovered: false });
  assert.equal(fixture.writes(), 1);
  assert.equal(fixture.tagWrites(), 2);
  assert.equal(fixture.reservationWrites(), 1);

  const reservation = [{ Key: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, Value: `reserved:${authorization.authorizationSha256}:${authorization.preparation.expiresAt}` }];
  const interrupted = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys, tags: reservation });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: interrupted.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 1, iamTagUserCount: 1, s3PutObjectCount: 1, recovered: false });
  assert.equal(interrupted.writes(), 1);
  assert.equal(interrupted.tagWrites(), 1);

  const postWriteInterruption = runner(desired.document, { accessKeys: legacyAccessKeys, tags: reservation });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: postWriteInterruption.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 0, iamTagUserCount: 1, s3PutObjectCount: 1, recovered: true });
  assert.equal(postWriteInterruption.writes(), 0);
  assert.equal(postWriteInterruption.tagWrites(), 1);

  const completedReplay = runner(desired.document, { accessKeys: legacyAccessKeys, tags: fixture.tags() });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: completedReplay.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 0, iamTagUserCount: 0, s3PutObjectCount: 0, recovered: true });
  assert.equal(completedReplay.writes(), 0);
  assert.equal(completedReplay.tagWrites(), 0);

  const expiredReservation = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys, tags: [{ Key: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, Value: `reserved:${"e".repeat(64)}:${new Date(now.getTime() - 1).toISOString()}` }] });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: expiredReservation.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 1, iamTagUserCount: 2, s3PutObjectCount: 1, recovered: false });
  assert.equal(expiredReservation.writes(), 1);
  assert.equal(expiredReservation.tagWrites(), 2);

  const laterAuthorization = createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation: authorization.preparation, protectedEnvironmentApprovalEvidence: approval, authorizedAt: new Date(now.getTime() + 1000).toISOString() });
  const restored = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys, tags: fixture.tags() });
  assert.notEqual(laterAuthorization.authorizationSha256, authorization.authorizationSha256);
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: restored.run, authorization: laterAuthorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now: new Date(now.getTime() + 1000) }), /consumed by a different authorization/);
  assert.equal(restored.writes(), 0);
  assert.equal(restored.tagWrites(), 0);
  for (const topology of [
    { accessKeys: legacyAccessKeys.slice(0, 1) },
    { accessKeys: [...legacyAccessKeys.slice(0, 1), { ...legacyAccessKeys[1], Status: "Inactive" }] },
    { accessKeys: [...legacyAccessKeys, { AccessKeyId: "key-c", Status: "Active", CreateDate: "2026-07-29T19:32:00Z" }] },
    { accessKeys: [{ ...legacyAccessKeys[0], CreateDate: "2026-07-29T19:28:58Z" }, legacyAccessKeys[1]] },
  ]) assert.throws(() => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.predecessorDocument, topology), transition, legacyRotationBindings: legacyBindings(), legacyRotationBindingOrigin: legacyBindingOrigin(), preparedAt: now.toISOString() }), /credential topology/);
  assert.throws(() => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: live(desired.predecessorDocument, { accessKeys: legacyAccessKeys }), transition: { ...transition, rotationId: "wrong" }, legacyRotationBindings: legacyBindings(), legacyRotationBindingOrigin: legacyBindingOrigin(), preparedAt: now.toISOString() }), /not bound|credential topology/);
  const forged = structuredClone(authorization.preparation); forged.legacyRotationBindings.jwt.pendingSecretId = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:forged";
  assert.throws(() => createBootstrapOperatorPolicyAuthorization({ sourceSha, preparation: forged, protectedEnvironmentApprovalEvidence: approval, authorizedAt: now.toISOString() }), /not exact or fresh/);
});

test("legacy binding resources are rejected before any AWS read and are reverified before IAM mutation", () => {
  const transition = { kind: LEGACY_BOOTSTRAP_TRANSITION_KIND, rotationBindingsFileSha256: LEGACY_BOOTSTRAP_TRANSITION_ROTATION_BINDINGS_FILE_SHA256 };
  const substituted = legacyBindings();
  substituted.jwt.pendingSecretId = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:legacy-substitute";
  let reads = 0;
  assert.throws(() => verifyLegacyBootstrapMfaTransitionBinding({ bindings: substituted, transition, currentSourceSha: sourceSha, proveDescendant: () => true, verifyLiveBinding: () => { reads += 1; } }), /reviewed initial-overlap resources|authenticated transition/);
  assert.equal(reads, 0);
  assert.throws(() => verifyLegacyBootstrapMfaTransitionBinding({ bindings: legacyBindings(), transition, currentSourceSha: sourceSha, proveDescendant: () => false, verifyLiveBinding: () => legacyBindingOrigin() }), /not descended/);
  assert.throws(() => verifyLegacyBootstrapMfaTransitionBinding({ bindings: legacyBindings(), transition, currentSourceSha: sourceSha, proveDescendant: () => true, run: () => { throw new Error("AccessDenied"); } }), /AWS read failed/);
  assert.throws(() => verifyLegacyBootstrapMfaTransitionBinding({ bindings: legacyBindings(), transition, currentSourceSha: sourceSha, proveDescendant: () => true, run: () => "not-json" }), /not valid JSON/);

  const authorization = legacyAuthorized();
  const fixture = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys });
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: fixture.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => ({ ...legacyBindingOrigin(), originSha256: "0".repeat(64) }), now }), /not bound|changed after authorization/);
  assert.equal(fixture.writes(), 0);
});

test("legacy transition reserves atomically before IAM mutation and only replaces an expired reservation by ETag", () => {
  const authorization = legacyAuthorized();
  const active = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys, reservation: { schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION", authorizationSha256: "e".repeat(64), expiresAt: authorization.preparation.expiresAt } });
  assert.throws(() => reconcileBootstrapOperatorPolicy({ run: active.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now }), /active executor\/authorization/);
  assert.equal(active.writes(), 0);
  assert.equal(active.tagWrites(), 0);
  assert.equal(active.reservationWrites(), 0);

  const expired = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys, reservation: { schemaVersion: 1, kind: "PRODUCTION_BOOTSTRAP_OPERATOR_LEGACY_MFA_TRANSITION_RESERVATION", authorizationSha256: "e".repeat(64), expiresAt: new Date(now.getTime() - 1).toISOString() } });
  assert.deepEqual(reconcileBootstrapOperatorPolicy({ run: expired.run, authorization, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => legacyBindingOrigin(), now, clock: () => now }), { status: "COMPLETE", iamPutUserPolicyCount: 1, iamTagUserCount: 2, s3PutObjectCount: 1, recovered: false });
  const replacement = expired.commands().find((args) => args[0] === "s3api" && args[1] === "put-object");
  assert.equal(replacement.includes("--if-match"), true);
  assert.equal(replacement.includes("--if-none-match"), false);
});

test("legacy transition rechecks its owned reservation immediately before the policy write", () => {
  const authorization = legacyAuthorized();
  const fixture = runner(desired.predecessorDocument, { accessKeys: legacyAccessKeys });
  assert.throws(() => reconcileBootstrapOperatorPolicy({
    run: fixture.run, authorization, sourceSha, proveDescendant: () => true,
    verifyLiveBinding: () => legacyBindingOrigin(), now,
    clock: () => new Date(new Date(authorization.preparation.expiresAt).getTime() + 1),
  }), /no longer owned and fresh/);
  assert.equal(fixture.writes(), 0);
  assert.equal(fixture.tagWrites(), 1);
  assert.equal(fixture.reservationWrites(), 1);
});

test("protected authorization independently authenticates OIDC identity and the live legacy binding", () => {
  const preparation = legacyAuthorized().preparation;
  const exactPrincipal = `${BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationRoleArn.replace(":iam::", ":sts::").replace(":role/", ":assumed-role/")}/authorization-test`;
  const calls = [];
  const run = (args) => { calls.push(args); return JSON.stringify(args[0] === "sts" ? { Arn: exactPrincipal } : { Tags: [] }); };
  const verified = authenticateBootstrapOperatorAuthorizationLiveState({ run, preparation, sourceSha, proveDescendant: () => true, verifyLiveBinding: ({ bindings }) => {
    assert.deepEqual(bindings, preparation.legacyRotationBindings);
    return preparation.legacyRotationBindingOrigin;
  }, now });
  assert.deepEqual(verified, { principalArn: exactPrincipal, liveInitialOverlapBindingReverified: true });
  assert.deepEqual(calls, [["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], ["iam", "list-user-tags", "--user-name", BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userName, "--output", "json", "--no-cli-pager"]]);
  assert.throws(() => authenticateBootstrapOperatorAuthorizationLiveState({ run: (args) => JSON.stringify(args[0] === "sts" ? { Arn: exactPrincipal } : { Tags: [{ Key: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, Value: `completed:${"f".repeat(64)}` }] }), preparation, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => preparation.legacyRotationBindingOrigin, now }), /already been consumed/);
  assert.throws(() => authenticateBootstrapOperatorAuthorizationLiveState({ run: (args) => JSON.stringify(args[0] === "sts" ? { Arn: exactPrincipal } : { Tags: [{ Key: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, Value: `reserved:${"f".repeat(64)}:${preparation.expiresAt}` }] }), preparation, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => preparation.legacyRotationBindingOrigin, now }), /active reservation/);
  assert.doesNotThrow(() => authenticateBootstrapOperatorAuthorizationLiveState({ run: (args) => JSON.stringify(args[0] === "sts" ? { Arn: exactPrincipal } : { Tags: [{ Key: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.legacyTransitionConsumptionTagKey, Value: `reserved:${"f".repeat(64)}:${new Date(now.getTime() - 1).toISOString()}` }] }), preparation, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => preparation.legacyRotationBindingOrigin, now }));
  assert.throws(() => authenticateBootstrapOperatorAuthorizationLiveState({ run: () => JSON.stringify({ Arn: "arn:aws:sts::368992683803:assumed-role/unrelated/session" }), preparation, sourceSha, proveDescendant: () => true, now }), /exact protected OIDC reconciler role/);
  assert.throws(() => authenticateBootstrapOperatorAuthorizationLiveState({ run, preparation, sourceSha, proveDescendant: () => true, verifyLiveBinding: () => ({ ...preparation.legacyRotationBindingOrigin, originSha256: "0".repeat(64) }), now }), /not bound|changed after preparation/);
});

test("preparation accepts a readback already authenticated by the production reader and rejects altered enrichment", () => {
  const authenticated = authenticateBootstrapOperatorLiveState(live(desired.predecessorDocument));
  assert.doesNotThrow(() => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: authenticated, preparedAt: now.toISOString() }));
  assert.throws(() => createBootstrapOperatorPolicyPreparation({ sourceSha, liveState: { ...authenticated, credentialState: "forged" }, preparedAt: now.toISOString() }), /changed before preparation/);
});

test("the RLS contract makes the legacy transition explicit without weakening the zero-key default", () => {
  const contract = JSON.parse(fs.readFileSync("documents/security/rls-program/production-full-rls-executor-contract.json", "utf8"));
  assert.match(contract.stageAOperatorPath.bootstrapOperatorRequirements.join("\n"), /no permanent access keys/);
  assert.deepEqual(Object.fromEntries(Object.entries(contract.stageAOperatorPath.legacyBootstrapMfaTransition).filter(([key]) => key !== "scope")), LEGACY_BOOTSTRAP_MFA_TRANSITION);
  assert.match(contract.stageAOperatorPath.legacyBootstrapMfaTransition.scope, /exact governed addition of MFA-gated publisher-bootstrap and verifier AssumeRole statements/);
});

test("authorization workflow uses exact read-only OIDC authority and produces a source-bound authorization", () => {
  const workflow = fs.readFileSync(".github/workflows/authorize-production-bootstrap-operator-policy-reconciliation.yml", "utf8");
  assert.match(workflow, /environment: production-bootstrap-operator-policy-authorization/);
  assert.doesNotMatch(workflow, /environment: production\s*$/m);
  assert.match(workflow, /^permissions:\n  actions: read\n  contents: read\n  id-token: write/m);
  assert.match(workflow, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-bootstrap-operator-policy-authorizer/);
  assert.match(workflow, /npm --prefix backend ci --ignore-scripts --no-audit --no-fund/);
  assert.match(workflow, /inline-session-policy:[\s\S]*secretsmanager:DescribeSecret[\s\S]*secretsmanager:GetSecretValue/);
  assert.match(workflow, /iam:ListUserTags[\s\S]*arn:aws:iam::368992683803:user\/mscqr-production-bootstrap-operator/);
  assert.doesNotMatch(workflow, /secretsmanager:(?:Put|Create|Delete|Update)|iam:(?:Put|Tag|Untag|Create|Update|Delete)|ecs:(?:Update|Register|Deregister)|pull-requests: write|packages: write/);
  const inlinePolicy = JSON.parse(workflow.match(/inline-session-policy: >-\n\s+(\{.*\})/)?.[1] || "null");
  const inlineRead = inlinePolicy.Statement.find(({ Action }) => Array.isArray(Action) && Action.includes("secretsmanager:DescribeSecret"));
  assert.deepEqual(LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES, [...MIXED_DUAL_SLOT_RECOVERY_IAM_RESOURCES, ...MIXED_DUAL_SLOT_RECOVERY_LIVE_PREDECESSOR.legacySecretArns]);
  assert.equal(new Set(LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES).size, 10);
  const bindings = legacyBindings();
  const verifierResources = [...Object.values(legacyBindingOrigin(bindings).resources), ...Object.values(bindings.supersessionPredecessor.current).map(({ secretArn }) => secretArn)];
  assert.deepEqual(new Set(verifierResources), new Set(LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES));
  assert.deepEqual(inlineRead, { Effect: "Allow", Action: ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource: [...LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES] });
  const reconcilerPolicy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json", "utf8"));
  assert.equal(reconcilerPolicy.Statement.some(({ Action }) => JSON.stringify(Action).includes("secretsmanager:") || JSON.stringify(Action).includes("iam:ListUserTags")), false);
  const authorizerPolicy = JSON.parse(fs.readFileSync(BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.authorizationPolicyPath, "utf8"));
  const read = authorizerPolicy.Statement.find(({ Sid }) => Sid === "ReadExactInitialDualSlotBindingForBootstrapOperatorAuthorization");
  assert.deepEqual(read, { Sid: "ReadExactInitialDualSlotBindingForBootstrapOperatorAuthorization", Effect: "Allow", Action: ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource: [...LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES] });
  for (const policy of [inlinePolicy, authorizerPolicy]) {
    const statements = policy.Statement.filter(({ Action }) => JSON.stringify(Action).includes("secretsmanager:"));
    assert.equal(statements.length, 1);
    assert.deepEqual(statements[0].Action, ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]);
    assert.deepEqual(statements[0].Resource, [...LEGACY_BOOTSTRAP_TRANSITION_SECRET_READ_RESOURCES]);
    assert.equal(statements[0].Resource.some((resource) => resource.includes("*")), false);
  }
  assert.deepEqual(authorizerPolicy.Statement.find(({ Sid }) => Sid === "ReadBootstrapOperatorTransitionConsumption"), { Sid: "ReadBootstrapOperatorTransitionConsumption", Effect: "Allow", Action: "iam:ListUserTags", Resource: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn });
  const authorization = authorized();
  assert.equal(authorization.sourceSha, sourceSha);
  assert.equal(authorization.preparation.predecessorPolicySha256, desired.predecessorPolicySha256);
  assert.equal(authorization.preparation.successorPolicySha256, desired.sourcePolicySha256);
  assert.deepEqual(authorization.maxAwsMutations, { "iam:PutUserPolicy": 1 });
  assert.deepEqual(authorization.preparation.expectedWritePlan, [{ action: "iam:PutUserPolicy", userArn: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.userArn, inlinePolicyName: BOOTSTRAP_OPERATOR_POLICY_RECONCILIATION.inlinePolicyName, policySha256: desired.sourcePolicySha256, addedStatements: [desired.document.Statement.find(({ Sid }) => Sid === "AssumeEcsExecVerifierRoleOnlyWithMfa")] }]);
});
