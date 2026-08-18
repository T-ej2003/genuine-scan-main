import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  TEMPORARY_KMS_CAPABILITY,
  assertPreCutoverTemporaryCapabilityAbsent,
  assertRootDropOwnershipEvidence,
  assertSteadyStateReleasePolicy,
  assertTemporaryCapabilityEvidence,
  assertTemporaryCapabilityTransition,
  assertTemporaryReleasePolicy,
  buildRootDropOwnershipEvidence,
  buildTemporaryCapabilityEvidence,
  buildTemporaryReleasePolicy,
  temporaryKmsCapabilityStatement,
} from "../aws/production-stage-a-temporary-kms-capability.mjs";
import { ensureStageBPrivateFile } from "../aws/stage-b-artifact-contract.mjs";
import { createTemporaryKmsCapabilityRunner } from "../aws/reconcile-production-stage-a-temporary-kms-capability.mjs";

const policy = JSON.parse(readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const sourceSha = "72c2c7e9bc45213b2655bbbcaaf2a45a5b5aa0c7";
const transitionId = "stage-a-root-drop-20260818";
const planSha256 = "a".repeat(64);

function stateFixture() {
  return {
    version: 4,
    serial: 44,
    lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837",
    resources: [
      { address: "aws_kms_key.root_drop", type: "aws_kms_key", instances: [{ attributes: { id: "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111" } }] },
      { address: "aws_kms_alias.root_drop", type: "aws_kms_alias", instances: [{ attributes: { target_key_id: "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111" } }] },
    ],
  };
}

test("steady state contains no permanent wildcard KMS TagResource authority", () => {
  assert.doesNotThrow(() => assertSteadyStateReleasePolicy(policy));
  assert.equal(policy.Statement.some(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes("kms:TagResource")), false);
});

test("temporary capability is exact-purpose, source-bound, and non-signing", () => {
  const temporary = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  assert.doesNotThrow(() => assertTemporaryReleasePolicy(temporary, { steadyStatePolicy: policy, sourceSha, transitionId }));
  const statement = temporaryKmsCapabilityStatement({ sourceSha, transitionId });
  assert.deepEqual(statement.Condition.StringEquals, {
    "aws:RequestedRegion": TEMPORARY_KMS_CAPABILITY.region,
    "aws:RequestTag/Environment": "production",
    "aws:RequestTag/ManagedBy": "Terraform",
    "aws:RequestTag/Component": "full-rls-green-stage-a",
    "aws:RequestTag/Stack": "production-green-stage-a",
    "kms:CallerAccount": TEMPORARY_KMS_CAPABILITY.accountId,
    "kms:KeySpec": "RSA_3072",
    "kms:KeyUsage": "SIGN_VERIFY",
  });
  assert.equal(temporary.Statement.some(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes("kms:Sign")), false);
  assert.throws(() => assertTemporaryReleasePolicy(buildTemporaryReleasePolicy(policy, { sourceSha, transitionId: "different-transition" }), { steadyStatePolicy: policy, sourceSha, transitionId }), /not exact/);
  assert.throws(() => assertTemporaryReleasePolicy({ ...temporary, Statement: [...temporary.Statement, { Effect: "Allow", Action: "kms:TagResource", Resource: "*" }] }, { steadyStatePolicy: policy, sourceSha, transitionId }), /changes more/);
});

test("capability lifecycle rejects residue and requires ownership before revocation", () => {
  const authorized = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId, planSha256, defaultVersionId: "v2", temporaryVersionId: "v2", observedAt: "2026-08-18T12:00:00.000Z" });
  const applying = buildTemporaryCapabilityEvidence({ ...authorized, state: "STAGE_A_APPLY", planSha256, observedAt: "2026-08-18T12:01:00.000Z" });
  const ownership = buildRootDropOwnershipEvidence({ terraformState: stateFixture(), sourceSha, transitionId, planSha256, observedAt: "2026-08-18T12:02:00.000Z" });
  const owned = buildTemporaryCapabilityEvidence({ ...applying, state: "ROOT_DROP_OWNERSHIP_VERIFIED", ownership, observedAt: "2026-08-18T12:03:00.000Z" });
  const revoked = buildTemporaryCapabilityEvidence({ ...owned, state: "REVOKED", temporaryVersionId: null, defaultVersionId: "v3", observedAt: "2026-08-18T12:04:00.000Z" });
  const absent = buildTemporaryCapabilityEvidence({ ...revoked, state: "ABSENCE_VERIFIED", observedAt: "2026-08-18T12:05:00.000Z" });
  for (const [value, state] of [[authorized, authorized.state], [applying, applying.state], [owned, owned.state], [revoked, revoked.state], [absent, absent.state]]) assert.doesNotThrow(() => assertTemporaryCapabilityEvidence(value, { sourceSha, state }));
  assert.doesNotThrow(() => assertTemporaryCapabilityTransition("AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY", { sourceSha }));
  assert.doesNotThrow(() => assertTemporaryCapabilityTransition("STAGE_A_APPLY", "ROOT_DROP_OWNERSHIP_VERIFIED", { sourceSha }));
  assert.throws(() => assertTemporaryCapabilityTransition("AUTHORIZED_FOR_ROOT_DROP_CREATION", "ROOT_DROP_OWNERSHIP_VERIFIED", { sourceSha }), /invalid transition/);
  assert.throws(() => assertPreCutoverTemporaryCapabilityAbsent(owned, { sourceSha }), /state/);
  assert.doesNotThrow(() => assertPreCutoverTemporaryCapabilityAbsent(absent, { sourceSha }));
});

test("root-drop ownership is exact and both Terraform resources are required", () => {
  const ownership = buildRootDropOwnershipEvidence({ terraformState: stateFixture(), sourceSha, transitionId, planSha256, observedAt: "2026-08-18T12:00:00.000Z" });
  assert.doesNotThrow(() => assertRootDropOwnershipEvidence(ownership, { sourceSha, planSha256 }));
  assert.throws(() => buildRootDropOwnershipEvidence({ terraformState: { resources: stateFixture().resources.slice(0, 1) }, sourceSha, transitionId, planSha256, observedAt: "2026-08-18T12:00:00.000Z" }), /key and alias/);
  assert.throws(() => assertRootDropOwnershipEvidence({ ...ownership, aliasResolves: false }, { sourceSha, planSha256 }), /not exact/);
});

test("private capability evidence is not replaceable through a symlink", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-test-"));
  try {
    const target = path.join(directory, "evidence.json");
    const link = path.join(directory, "link.json");
    writeFileSync(target, "{}\n", { mode: 0o600 });
    chmodSync(target, 0o600);
    const evidence = buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha, transitionId, defaultVersionId: "v3", observedAt: "2026-08-18T12:00:00.000Z" });
    assert.equal(JSON.stringify(evidence).includes("secret"), false);
    symlinkSync(target, link);
    assert.throws(() => ensureStageBPrivateFile({ filePath: link, repositoryRoot: process.cwd(), label: "test evidence" }), /must be a regular non-symlink file/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("launch handoff resolves the canonical manifest path", () => {
  const handoff = readFileSync("documents/ops/MSCQR_PRODUCTION_LAUNCH_HANDOFF-v1.md", "utf8");
  const manifestPath = "documents/ops/MSCQR_PRODUCTION_LAUNCH_HANDOFF_MANIFEST-v1.json";
  assert.equal(JSON.parse(readFileSync(manifestPath, "utf8")).schemaVersion, 1);
  assert.match(handoff, new RegExp(manifestPath.replaceAll(".", "\\.")));
  assert.doesNotMatch(handoff, /launch-handoff-manifest\.json/);
});

test("canonical producer replays authorization and safely aborts a failed apply", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-runner-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = path.join(directory, "plan.json");
  writeFileSync(planJsonFile, JSON.stringify({ resource_changes: [{ address: "aws_kms_key.root_drop", change: { actions: ["create"] } }, { address: "aws_kms_alias.root_drop", change: { actions: ["create"] } }] }), { mode: 0o600 });
  let defaultVersionId = "v1";
  let nextVersion = 2;
  const versions = new Map([["v1", policy]]);
  let policyWrites = 0;
  const run = (args) => {
    const operation = args[1];
    if (operation === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: defaultVersionId } });
    if (operation === "list-policy-versions") return JSON.stringify({ Versions: [...versions.keys()].map((VersionId) => ({ VersionId })) });
    if (operation === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: encodeURIComponent(JSON.stringify(versions.get(args[args.indexOf("--version-id") + 1]))) } });
    if (operation === "create-policy-version") {
      const policyDocument = JSON.parse(readFileSync(args[args.indexOf("--policy-document") + 1].slice("file://".length), "utf8"));
      const versionId = `v${nextVersion++}`;
      versions.set(versionId, policyDocument); defaultVersionId = versionId; policyWrites += 1;
      return JSON.stringify({ PolicyVersion: { VersionId: versionId } });
    }
    if (operation === "delete-policy-version") { versions.delete(args[args.indexOf("--version-id") + 1]); return "{}"; }
    throw new Error(`unexpected AWS operation: ${args.join(" ")}`);
  };
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run, now: () => "2026-08-18T12:00:00.000Z" });
    const authorized = runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    const replay = runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(authorized.evidence.state, "AUTHORIZED_FOR_ROOT_DROP_CREATION");
    assert.equal(replay.writes, 0);
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const revoked = runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, applyFailed: true, partialOperationCensus: true });
    assert.equal(revoked.evidence.state, "REVOKED");
    assert.equal(runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile }).writes, 0);
    const absent = runner.runPhase({ phase: "verify-absent", sourceSha, transitionId, stateFile });
    assert.equal(absent.evidence.state, "ABSENCE_VERIFIED");
    assert.equal(runner.runPhase({ phase: "verify-absent", sourceSha, transitionId, stateFile }).writes, 0);
    assert.equal(policyWrites, 2);
    assert.doesNotThrow(() => assertPreCutoverTemporaryCapabilityAbsent(absent.evidence, { sourceSha }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an unrecorded post-write capability can be recovered only with exact failed-apply inputs", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-recovery-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = path.join(directory, "plan.json");
  writeFileSync(planJsonFile, JSON.stringify({ resource_changes: [{ address: "aws_kms_key.root_drop", change: { actions: ["create"] } }, { address: "aws_kms_alias.root_drop", change: { actions: ["create"] } }] }), { mode: 0o600 });
  let defaultVersionId = "v1";
  let nextVersion = 2;
  const versions = new Map([["v1", policy]]);
  const run = (args) => {
    const operation = args[1];
    if (operation === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: defaultVersionId } });
    if (operation === "list-policy-versions") return JSON.stringify({ Versions: [...versions.keys()].map((VersionId) => ({ VersionId })) });
    if (operation === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: encodeURIComponent(JSON.stringify(versions.get(args[args.indexOf("--version-id") + 1]))) } });
    if (operation === "create-policy-version") {
      const policyDocument = JSON.parse(readFileSync(args[args.indexOf("--policy-document") + 1].slice("file://".length), "utf8"));
      const versionId = `v${nextVersion++}`;
      versions.set(versionId, policyDocument); defaultVersionId = versionId;
      return JSON.stringify({ PolicyVersion: { VersionId: versionId } });
    }
    if (operation === "delete-policy-version") { versions.delete(args[args.indexOf("--version-id") + 1]); return "{}"; }
    throw new Error(`unexpected AWS operation: ${args.join(" ")}`);
  };
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run, now: () => "2026-08-18T12:00:00.000Z" });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    rmSync(stateFile);
    const recovered = runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true });
    assert.equal(recovered.evidence.state, "REVOKED");
    assert.equal(recovered.writes, 2);
    assert.throws(() => runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, applyFailed: true, partialOperationCensus: true }), /apply failure and authenticated partial-operation census/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
