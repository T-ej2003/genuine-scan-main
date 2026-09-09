import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import {
  buildStageAProductionArtifactsBucketPolicy,
  buildStageAProductionArtifactsBucketPolicyPredecessor,
  buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation,
  buildStageAProductionArtifactsBucketPolicyWithRecoveryListBucketBootstrap,
  buildStageAProductionArtifactsBucketPolicyWithProviderReadonlyJournalProtection,
  buildStageAProductionArtifactsBucketPolicyWithoutInitialActivationReservation,
  assertStageAProductionArtifactsExecutableTransition,
  canonicalizeStageAProductionArtifactsPolicy,
  resolveStageAProductionArtifactsBucketPolicyTransition,
  stageAProductionArtifactsPolicySemanticallyEqual,
  stageAProductionArtifactsPolicySha256,
} from "../aws/production-stage-a-control-plane.mjs";
import { classifyStageAProductionArtifactsRecovery, readRawTerraformStateIdentity, STAGE_A_RECOVERY_CLASSIFICATION } from "../aws/run-production-stage-a-production-artifacts-recovery.mjs";
import { assertStageAProductionArtifactsRecoverySourceCompatibility, stageAProductionArtifactsGovernedExecutableManifest, stageAProductionArtifactsGovernedExecutableManifestSha256, STAGE_A_RECOVERY_CONTINUATION_SAFE_FILES } from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";

const desired = buildStageAProductionArtifactsBucketPolicy();
const clone = () => structuredClone(desired);
const statement = (value, sid) => value.Statement.find((entry) => entry.Sid === sid);
const allowsExactList = ({ policy, principal, bucket, prefix }) => policy.Statement.some((entry) => entry.Effect === "Allow" && entry.Action === "s3:ListBucket" && entry.Resource === bucket && entry.Principal?.AWS === principal && (entry.Condition?.StringLike?.["s3:prefix"] || []).some((pattern) => pattern.endsWith("*") ? prefix.startsWith(pattern.slice(0, -1)) : prefix === pattern));
const values = (value) => Array.isArray(value) ? value : [value];
const matches = (value, actual) => values(value).includes(actual);
const resourceMatches = (value, actual) => values(value).some((pattern) => pattern.endsWith("*") ? actual.startsWith(pattern.slice(0, -1)) : pattern === actual);
const conditionMatches = (condition, context) => Object.entries(condition || {}).every(([operator, entries]) => Object.entries(entries).every(([key, value]) => operator === "StringEquals" ? matches(value, context[key]) : operator === "StringNotEquals" ? !matches(value, context[key]) : false));
const policyMatches = (entry, { principal, action, resource, context }) => matches(entry.Action, action) && resourceMatches(entry.Resource, resource) && (entry.Principal === "*" || entry.Principal?.AWS === "*" || matches(entry.Principal?.AWS, principal)) && conditionMatches(entry.Condition, { ...context, "aws:PrincipalArn": principal });
const explicitlyDenied = (policy, request) => policy.Statement.some((entry) => entry.Effect === "Deny" && policyMatches(entry, request));
const explicitlyAllowed = (policy, request) => policy.Statement.some((entry) => entry.Effect === "Allow" && policyMatches(entry, request));

test("Stage-A policy canonicalization preserves the historical desired hash and accepts AWS singleton readback", () => {
  const live = clone();
  for (const entry of live.Statement) if (Array.isArray(entry.Resource) && entry.Resource.length === 1) entry.Resource = entry.Resource[0];
  assert.equal(stageAProductionArtifactsPolicySha256(desired), "765e091f99ee56e186741aa2fd849d755dc19f0b668779801855105350db8ff3");
  assert.equal(stageAProductionArtifactsPolicySha256(live), stageAProductionArtifactsPolicySha256(desired));
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(live, desired), true);
  assert.equal(canonicalizeStageAProductionArtifactsPolicy(live).Statement.length, desired.Statement.length);
});

test("ProviderReadOnly-protected retirement removes exactly the six obsolete reservation statements", () => {
  const predecessor = buildStageAProductionArtifactsBucketPolicyWithProviderReadonlyJournalProtection();
  const target = buildStageAProductionArtifactsBucketPolicyWithoutInitialActivationReservation();
  const transition = resolveStageAProductionArtifactsBucketPolicyTransition({
    predecessorPolicySha256: stageAProductionArtifactsPolicySha256(predecessor),
    desiredPolicySha256: stageAProductionArtifactsPolicySha256(target),
  });
  const targetSids = new Set(target.Statement.map(({ Sid }) => Sid));
  const removed = predecessor.Statement.filter(({ Sid }) => !targetSids.has(Sid)).map(({ Sid }) => Sid);
  assert.deepEqual(removed, [
    "AllowRootOperatorReadInitialActivationPolicyReconciliationReservations",
    "DenyOtherPrincipalsInitialActivationPolicyReconciliationReservationReads",
    "AllowRootOperatorConditionalInitialActivationPolicyReconciliationReservationCreate",
    "DenyNonConditionalInitialActivationPolicyReconciliationReservationWrites",
    "DenyOtherPrincipalsInitialActivationPolicyReconciliationReservationWrites",
    "DenyInitialActivationPolicyReconciliationReservationDeletion",
  ]);
  assert.equal(removed.length, 6);
  assert.deepEqual(transition.predecessor, predecessor);
  assert.deepEqual(transition.desired, target);
  for (const statement of target.Statement) assert.deepEqual(statement, predecessor.Statement.find(({ Sid }) => Sid === statement.Sid));
  for (const sid of ["AllowReleaseDeployerListStageAProductionArtifactsRecovery", "AllowInitialActivationReconcilerListProviderReadonlyReconciliation", "AllowInitialActivationReconcilerReadProviderReadonlyReconciliation", "DenyOtherPrincipalsProviderReadonlyReconciliationReads", "AllowInitialActivationReconcilerConditionalProviderReadonlyReconciliationCreate", "DenyNonConditionalProviderReadonlyReconciliationWrites", "DenyOtherPrincipalsProviderReadonlyReconciliationWrites", "DenyProviderReadonlyReconciliationDeletion"]) assert.ok(targetSids.has(sid));
  assert.notEqual(stageAProductionArtifactsPolicySha256(target), stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicy()));
  assert.throws(() => resolveStageAProductionArtifactsBucketPolicyTransition({
    predecessorPolicySha256: stageAProductionArtifactsPolicySha256(predecessor),
    desiredPolicySha256: stageAProductionArtifactsPolicySha256({ ...target, Statement: target.Statement.slice(1) }),
  }), /not exact or reviewed/);
});

test("Stage-A reservation and ProviderReadOnly transitions compose only as A to A-prime to B to C", () => {
  const A = buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation();
  const APrime = buildStageAProductionArtifactsBucketPolicyWithRecoveryListBucketBootstrap();
  const B = buildStageAProductionArtifactsBucketPolicyWithProviderReadonlyJournalProtection();
  const C = buildStageAProductionArtifactsBucketPolicyWithoutInitialActivationReservation();
  const transition = (predecessor, desired) => resolveStageAProductionArtifactsBucketPolicyTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(predecessor), desiredPolicySha256: stageAProductionArtifactsPolicySha256(desired) });
  assert.deepEqual(transition(A, APrime), { predecessor: A, desired: APrime });
  assert.deepEqual(transition(APrime, B), { predecessor: APrime, desired: B });
  assert.deepEqual(transition(B, C), { predecessor: B, desired: C });
  assert.deepEqual(transition(C, C), { predecessor: C, desired: C });
  assert.throws(() => transition(A, B), /not exact or reviewed/);
  assert.throws(() => transition(A, C), /not exact or reviewed/);
  assert.throws(() => transition(B, buildStageAProductionArtifactsBucketPolicy()), /not exact or reviewed/);
  assert.throws(() => transition({ ...B, Statement: B.Statement.slice(1) }, C), /not exact or reviewed/);
  assert.deepEqual(assertStageAProductionArtifactsExecutableTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(A), desiredPolicySha256: stageAProductionArtifactsPolicySha256(APrime) }), { predecessor: A, desired: APrime });
  assert.deepEqual(assertStageAProductionArtifactsExecutableTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(APrime), desiredPolicySha256: stageAProductionArtifactsPolicySha256(B) }), { predecessor: APrime, desired: B });
  assert.throws(() => assertStageAProductionArtifactsExecutableTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(B), desiredPolicySha256: stageAProductionArtifactsPolicySha256(C) }), /non-executable/);
});

test("Terraform's current Stage-A desired policy retains reservations, so State C stays classification-only", () => {
  const terraform = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  for (const sid of [
    "AllowRootOperatorReadInitialActivationPolicyReconciliationReservations",
    "DenyOtherPrincipalsInitialActivationPolicyReconciliationReservationReads",
    "AllowRootOperatorConditionalInitialActivationPolicyReconciliationReservationCreate",
    "DenyNonConditionalInitialActivationPolicyReconciliationReservationWrites",
    "DenyOtherPrincipalsInitialActivationPolicyReconciliationReservationWrites",
    "DenyInitialActivationPolicyReconciliationReservationDeletion",
  ]) assert.match(terraform, new RegExp(`Sid = \"${sid}\"`));
  const B = buildStageAProductionArtifactsBucketPolicyWithProviderReadonlyJournalProtection();
  const C = buildStageAProductionArtifactsBucketPolicyWithoutInitialActivationReservation();
  assert.notEqual(stageAProductionArtifactsPolicySha256(B), stageAProductionArtifactsPolicySha256(C));
  assert.throws(() => assertStageAProductionArtifactsExecutableTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(B), desiredPolicySha256: stageAProductionArtifactsPolicySha256(C) }), /non-executable/);
  assert.throws(() => assertStageAProductionArtifactsExecutableTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(C), desiredPolicySha256: stageAProductionArtifactsPolicySha256(C) }), /non-executable/);
});

test("bootstrap adds only exact Stage-A recovery absence detection and B adds ProviderReadOnly protection", () => {
  const predecessor = buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation();
  const bootstrap = buildStageAProductionArtifactsBucketPolicyWithRecoveryListBucketBootstrap();
  const desired = buildStageAProductionArtifactsBucketPolicyWithProviderReadonlyJournalProtection();
  const bootstrapTransition = resolveStageAProductionArtifactsBucketPolicyTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(predecessor), desiredPolicySha256: stageAProductionArtifactsPolicySha256(bootstrap) });
  assert.deepEqual(bootstrap.Statement.filter(({ Sid }) => !new Set(predecessor.Statement.map(({ Sid }) => Sid)).has(Sid)), [{ Sid: "AllowReleaseDeployerListStageAProductionArtifactsRecovery", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer" }, Action: "s3:ListBucket", Resource: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an", Condition: { StringLike: { "s3:prefix": ["production-stage-a-production-artifacts-reconciliation/recovery/*"] } } }]);
  assert.deepEqual(bootstrapTransition, { predecessor, desired: bootstrap });
  const transition = resolveStageAProductionArtifactsBucketPolicyTransition({ predecessorPolicySha256: stageAProductionArtifactsPolicySha256(bootstrap), desiredPolicySha256: stageAProductionArtifactsPolicySha256(desired) });
  const predecessorSids = new Set(bootstrap.Statement.map(({ Sid }) => Sid));
  assert.deepEqual(desired.Statement.filter(({ Sid }) => !predecessorSids.has(Sid)).map(({ Sid }) => Sid), [
    "AllowInitialActivationReconcilerListProviderReadonlyReconciliation",
    "AllowInitialActivationReconcilerReadProviderReadonlyReconciliation",
    "DenyOtherPrincipalsProviderReadonlyReconciliationReads",
    "AllowInitialActivationReconcilerConditionalProviderReadonlyReconciliationCreate",
    "DenyNonConditionalProviderReadonlyReconciliationWrites",
    "DenyOtherPrincipalsProviderReadonlyReconciliationWrites",
    "DenyProviderReadonlyReconciliationDeletion",
  ]);
  assert.deepEqual(transition, { predecessor: bootstrap, desired });
});

test("A-prime ListBucket allows only the canonical recovery namespace", () => {
  const policy = buildStageAProductionArtifactsBucketPolicyWithRecoveryListBucketBootstrap();
  const request = { policy, principal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", bucket: "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an" };
  assert.equal(allowsExactList({ ...request, prefix: "production-stage-a-production-artifacts-reconciliation/recovery/a/attempt.json" }), true);
  for (const prefix of ["production-stage-a-production-artifacts-reconciliation/other/attempt.json", "production-provider-readonly-policy-reconciliation/a/reservation.json", ""]) assert.equal(allowsExactList({ ...request, prefix }), false);
  assert.equal(allowsExactList({ ...request, bucket: "arn:aws:s3:::other", prefix: "production-stage-a-production-artifacts-reconciliation/recovery/a/attempt.json" }), false);
});

test("State A requires the root-read and release-write bootstrap split without weakening its explicit deny", () => {
  const A = buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation();
  const APrime = buildStageAProductionArtifactsBucketPolicyWithRecoveryListBucketBootstrap();
  const bucket = "arn:aws:s3:::mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an";
  const prefix = "production-stage-a-production-artifacts-reconciliation/recovery/";
  const attempt = `${bucket}/${prefix}${"a".repeat(64)}/attempt.json`;
  const root = "arn:aws:iam::368992683803:root";
  const release = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
  const conditionalWrite = { action: "s3:PutObject", resource: attempt, context: { "s3:if-none-match": "*" } };
  assert.equal(explicitlyDenied(A, { ...conditionalWrite, principal: root }), true);
  assert.equal(explicitlyAllowed(A, { ...conditionalWrite, principal: release }), true);
  assert.equal(explicitlyDenied(A, { ...conditionalWrite, principal: release }), false);
  assert.equal(explicitlyDenied(A, { principal: root, action: "s3:GetObject", resource: attempt, context: {} }), false);
  assert.equal(allowsExactList({ policy: A, principal: release, bucket, prefix: `${prefix}${"a".repeat(64)}/attempt.json` }), false);
  assert.equal(explicitlyAllowed(APrime, { ...conditionalWrite, principal: release }), true);
  assert.equal(explicitlyDenied(APrime, { ...conditionalWrite, principal: release }), false);
  assert.ok(statement(A, "DenyOtherPrincipalsStageAProductionArtifactsReconciliationWrites"));
});

test("IAM grammar singleton forms are normalized only at their grammar positions", () => {
  const action = clone(); const actionEntry = statement(action, "AllowReleaseDeployerReadActivationLifecycle"); actionEntry.Action = [actionEntry.Action];
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(action, desired), true);
  const principal = clone(); const principalEntry = statement(principal, "AllowReleaseDeployerReadActivationLifecycle"); principalEntry.Principal.AWS = [principalEntry.Principal.AWS];
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(principal, desired), true);
  const condition = clone(); const conditionEntry = statement(condition, "DenyNonConditionalActivationLifecycleWrites"); conditionEntry.Condition.StringNotEquals["s3:if-none-match"] = ["*"];
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(condition, desired), true);
  const multiAction = clone(); statement(multiAction, "AllowReleaseDeployerReadActivationLifecycle").Action = ["s3:GetObject", "s3:PutObject"];
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(multiAction, desired), false);
  const multiResource = clone(); statement(multiResource, "AllowReleaseDeployerReadRebaselineEvidence").Resource = ["a", "b"];
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(multiResource, desired), false);
});

test("policy semantic comparison rejects authorization broadening and malformed grammar", () => {
  for (const mutate of [
    (policy) => (statement(policy, "AllowReleaseDeployerReadActivationLifecycle").Principal.AWS = "arn:aws:iam::368992683803:role/other", policy),
    (policy) => (statement(policy, "AllowReleaseDeployerReadActivationLifecycle").Action = "s3:PutObject", policy),
    (policy) => (statement(policy, "AllowReleaseDeployerReadActivationLifecycle").Resource = ["arn:aws:s3:::other/*", "arn:aws:s3:::other2/*"], policy),
    (policy) => (statement(policy, "DenyNonConditionalActivationLifecycleWrites").Condition.StringNotEquals["s3:if-none-match"] = "other", policy),
    (policy) => (statement(policy, "DenyNonConditionalActivationLifecycleWrites").Effect = "Allow", policy),
    (policy) => (policy.Statement = policy.Statement.slice(1), policy),
    (policy) => (policy.Statement.push(structuredClone(policy.Statement[0])), policy),
  ]) assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(mutate(clone()), desired), false);
  for (const malformed of [
    { Version: "2012-10-17", Statement: [] },
    { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: [], Resource: "x" }] },
    { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "x", Resource: "x", Condition: { StringEquals: [] } }] },
  ]) assert.throws(() => canonicalizeStageAProductionArtifactsPolicy(malformed), /malformed|non-empty/);
});

test("recovery classifier distinguishes write-free completion from writable P0", () => {
  const predecessor = buildStageAProductionArtifactsBucketPolicyPredecessor();
  assert.equal(classifyStageAProductionArtifactsRecovery({ livePolicy: predecessor }), STAGE_A_RECOVERY_CLASSIFICATION.READY_FOR_WRITE);
  assert.equal(classifyStageAProductionArtifactsRecovery({ livePolicy: predecessor, attempt: {} }), STAGE_A_RECOVERY_CLASSIFICATION.MUTATION_ATTEMPT_STARTED);
  const normalizedP2 = clone(); for (const entry of normalizedP2.Statement) if (Array.isArray(entry.Resource) && entry.Resource.length === 1) entry.Resource = entry.Resource[0];
  assert.equal(classifyStageAProductionArtifactsRecovery({ livePolicy: normalizedP2, attempt: {} }), STAGE_A_RECOVERY_CLASSIFICATION.POST_WRITE_COMPLETION_PENDING);
  assert.equal(classifyStageAProductionArtifactsRecovery({ livePolicy: normalizedP2 }), STAGE_A_RECOVERY_CLASSIFICATION.P2_WITHOUT_ATTEMPT);
  assert.equal(classifyStageAProductionArtifactsRecovery({ livePolicy: { Version: "2012-10-17", Statement: [] }, attempt: {} }), STAGE_A_RECOVERY_CLASSIFICATION.LIVE_POLICY_CONFLICT);
});

test("historical recovery continuation accepts only the bounded canonicalization source delta", () => {
  const args = { sourceSha: "b".repeat(40), recoverySourceSha: "a".repeat(40), proveDescendant: () => true, historicalGovernedExecutableManifestSha256: "1".repeat(64), readGovernedExecutableManifestSha256: (sha) => sha === "a".repeat(40) ? "1".repeat(64) : "2".repeat(64) };
  const exactRepairDelta = [
    "scripts/aws/production-stage-a-control-plane.mjs",
    "scripts/aws/production-stage-a-production-artifacts-recovery-governance.mjs",
    "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs",
  ];
  assert.deepEqual(STAGE_A_RECOVERY_CONTINUATION_SAFE_FILES, exactRepairDelta);
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ ...args, readContinuationChangedFiles: () => exactRepairDelta }));
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ ...args, readContinuationChangedFiles: () => exactRepairDelta.filter((file) => !file.endsWith("recovery-governance.mjs")) }), /unsafe governed/);
  for (const file of [
    "scripts/aws/run-production-green-stage-b-preflight.mjs",
    "scripts/aws/production-dual-slot-rebaseline-contract.mjs",
    "infra/aws/terraform/production-green-stage-a/main.tf",
    "scripts/aws/dispatch-production-green-stage-b-images.mjs",
    "scripts/aws/production-github-environment-approval.mjs",
  ]) assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ ...args, readContinuationChangedFiles: () => [...exactRepairDelta, file] }), /unsafe governed/);
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility(args), /changed the governed/);
});

test("the reviewed reservation descendant does not advertise historical A-to-B continuation", () => {
  const recoverySourceSha = "5ae231bee520442dc6c66365b74c7b0b1b61ec3a";
  const sourceSha = "9d271df29fb4ec01763d6987e8d2d6a2ea1b4a5b";
  const manifest = (sha) => stageAProductionArtifactsGovernedExecutableManifest(sha);
  const ancestor = new Map(manifest(recoverySourceSha).files.map(({ path, sha256 }) => [path, sha256]));
  const descendant = new Map(manifest(sourceSha).files.map(({ path, sha256 }) => [path, sha256]));
  const changed = [...new Set([...ancestor.keys(), ...descendant.keys()])].filter((file) => ancestor.get(file) !== descendant.get(file)).sort();
  assert.deepEqual(changed, [
    "infra/aws/terraform/production-green-stage-a/main.tf",
    "scripts/aws/production-green-stage-b-contract.mjs",
    "scripts/aws/production-stage-a-control-plane.mjs",
    "scripts/aws/production-stage-a-production-artifacts-recovery-governance.mjs",
    "scripts/aws/run-production-stage-a-production-artifacts-reconciliation.mjs",
    "scripts/aws/run-production-stage-a-production-artifacts-recovery.mjs",
  ]);
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha, recoverySourceSha, proveDescendant: () => true, historicalGovernedExecutableManifestSha256: stageAProductionArtifactsGovernedExecutableManifestSha256(recoverySourceSha), readGovernedExecutableManifestSha256: stageAProductionArtifactsGovernedExecutableManifestSha256, readContinuationChangedFiles: () => changed }), /unsafe governed/);
});

test("recovery CAS reads the exact raw Terraform backend bytes", () => {
  const raw = Buffer.from('{"serial":54,"lineage":"02afb75a-f902-ab8a-f4c1-751d4aef7837"}\n');
  const identity = readRawTerraformStateIdentity((args) => fs.writeFileSync(args.at(-1), raw, { mode: 0o600, flag: "wx" }));
  assert.deepEqual(identity, { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 54, stateSha256: createHash("sha256").update(raw).digest("hex") });
});
