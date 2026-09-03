import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import {
  buildStageAProductionArtifactsBucketPolicy,
  buildStageAProductionArtifactsBucketPolicyPredecessor,
  canonicalizeStageAProductionArtifactsPolicy,
  stageAProductionArtifactsPolicySemanticallyEqual,
  stageAProductionArtifactsPolicySha256,
} from "../aws/production-stage-a-control-plane.mjs";
import { classifyStageAProductionArtifactsRecovery, readRawTerraformStateIdentity, STAGE_A_RECOVERY_CLASSIFICATION } from "../aws/run-production-stage-a-production-artifacts-recovery.mjs";
import {
  assertStageAProductionArtifactsRecoverySourceCompatibility,
  STAGE_A_RECOVERY_CONTINUATION_REVIEWED_DIGESTS,
  STAGE_A_RECOVERY_CONTINUATION_SAFE_FILES,
} from "../aws/production-stage-a-production-artifacts-recovery-governance.mjs";

const desired = buildStageAProductionArtifactsBucketPolicy();
const clone = () => structuredClone(desired);
const statement = (value, sid) => value.Statement.find((entry) => entry.Sid === sid);

test("Stage-A policy canonicalization preserves the historical desired hash and accepts AWS singleton readback", () => {
  const live = clone();
  for (const entry of live.Statement) if (Array.isArray(entry.Resource) && entry.Resource.length === 1) entry.Resource = entry.Resource[0];
  assert.equal(stageAProductionArtifactsPolicySha256(desired), "765e091f99ee56e186741aa2fd849d755dc19f0b668779801855105350db8ff3");
  assert.equal(stageAProductionArtifactsPolicySha256(live), stageAProductionArtifactsPolicySha256(desired));
  assert.equal(stageAProductionArtifactsPolicySemanticallyEqual(live, desired), true);
  assert.equal(canonicalizeStageAProductionArtifactsPolicy(live).Statement.length, desired.Statement.length);
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
  assert.equal(classifyStageAProductionArtifactsRecovery({ livePolicy: predecessor, attempt: {} }), STAGE_A_RECOVERY_CLASSIFICATION.ATTEMPT_PENDING_BEFORE_WRITE);
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
  const protectedSource = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: protectedSource, recoverySourceSha: "d4d8ef5cf23bfff6be425d957bf7fb4dc74b2a39", proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === "d4d8ef5cf23bfff6be425d957bf7fb4dc74b2a39" && descendantSha === protectedSource }));
  assert.doesNotThrow(() => assertStageAProductionArtifactsRecoverySourceCompatibility({
    ...args,
    readContinuationChangedFiles: () => exactRepairDelta,
    readContinuationReviewedDigests: () => STAGE_A_RECOVERY_CONTINUATION_REVIEWED_DIGESTS,
  }));
  for (const file of exactRepairDelta) {
    const changedContents = { ...STAGE_A_RECOVERY_CONTINUATION_REVIEWED_DIGESTS, [file]: "f".repeat(64) };
    assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({
      ...args,
      readContinuationChangedFiles: () => exactRepairDelta,
      readContinuationReviewedDigests: () => changedContents,
    }), /reviewed governed executable contents/);
  }
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({
    ...args,
    readContinuationChangedFiles: () => exactRepairDelta,
    readContinuationReviewedDigests: () => Object.fromEntries(exactRepairDelta.slice(1).map((file) => [file, STAGE_A_RECOVERY_CONTINUATION_REVIEWED_DIGESTS[file]])),
  }), /reviewed governed executable contents/);
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ ...args, readContinuationChangedFiles: () => exactRepairDelta.filter((file) => !file.endsWith("recovery-governance.mjs")) }), /unsafe governed/);
  for (const file of [
    "scripts/aws/authorize-production-stage-a-production-artifacts-recovery.mjs",
    "scripts/aws/run-production-green-stage-b-preflight.mjs",
    "scripts/aws/production-dual-slot-rebaseline-contract.mjs",
    "infra/aws/terraform/production-green-stage-a/main.tf",
    "scripts/aws/dispatch-production-green-stage-b-images.mjs",
    "scripts/aws/production-github-environment-approval.mjs",
  ]) assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility({ ...args, readContinuationChangedFiles: () => [...exactRepairDelta, file] }), /unsafe governed/);
  assert.throws(() => assertStageAProductionArtifactsRecoverySourceCompatibility(args), /changed the governed/);
});

test("recovery CAS reads the exact raw Terraform backend bytes", () => {
  const raw = Buffer.from('{"serial":54,"lineage":"02afb75a-f902-ab8a-f4c1-751d4aef7837"}\n');
  const identity = readRawTerraformStateIdentity((args) => fs.writeFileSync(args.at(-1), raw, { mode: 0o600, flag: "wx" }));
  assert.deepEqual(identity, { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 54, stateSha256: createHash("sha256").update(raw).digest("hex") });
});
