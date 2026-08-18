import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  TEMPORARY_KMS_CAPABILITY,
  AWS_MANAGED_POLICY_DOCUMENT_LIMIT,
  TEMPORARY_POLICY_MIN_HEADROOM,
  TEMPORARY_POLICY_MAX_BYTES,
  IAM_STATEMENT_SID_MAX_LENGTH,
  IAM_STATEMENT_SID_PATTERN,
  assertPreCutoverTemporaryCapabilityAbsent,
  assertRootDropOwnershipEvidence,
  assertSteadyStateReleasePolicy,
  assertTemporaryCapabilityEvidence,
  assertTemporaryCapabilityTransition,
  assertStageARootDropCreationPlan,
  assertTemporaryReleasePolicy,
  buildRootDropOwnershipEvidence,
  buildTemporaryCapabilityEvidence,
  buildTemporaryReleasePolicy,
  canonicalTemporaryKmsStatementSid,
  isTemporaryTagResourceStatement,
  temporaryKmsCapabilityStatement,
} from "../aws/production-stage-a-temporary-kms-capability.mjs";
import { ensureStageBPrivateFile } from "../aws/stage-b-artifact-contract.mjs";
import { AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES, classifyTemporaryKmsPolicyVersion, createTemporaryKmsCapabilityRunner, runCli } from "../aws/reconcile-production-stage-a-temporary-kms-capability.mjs";
import { buildStageAStateIdentity } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { buildStageARootDropKeyPolicy } from "../aws/production-stage-a-control-plane.mjs";

const policy = JSON.parse(readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const sourceSha = "72c2c7e9bc45213b2655bbbcaaf2a45a5b5aa0c7";
const transitionId = "stage-a-root-drop-20260818";
const planSha256 = "a".repeat(64);
const historicalPolicyFixtures = JSON.parse(readFileSync("scripts/tests/fixtures/production-stage-a-historical-policies.json", "utf8"));
const historicalPolicies = new Map(historicalPolicyFixtures.map(({ versionId, document }) => [versionId, document]));
const canonicalPolicy = (value) => Array.isArray(value) ? `[${value.map(canonicalPolicy).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalPolicy(value[key])}`).join(",")}}` : JSON.stringify(value);
const policySha256 = (value) => createHash("sha256").update(canonicalPolicy(value)).digest("hex");

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

function writePlanFile(directory) {
  const planJsonFile = path.join(directory, "plan.json");
  writeFileSync(planJsonFile, JSON.stringify({ resource_changes: rootDropPlanChanges() }), { mode: 0o600 });
  return planJsonFile;
}

function rootDropPlanChanges() {
  return [
    { address: "aws_kms_key.root_drop", change: { actions: ["create"], after: { policy: JSON.stringify(buildStageARootDropKeyPolicy()), customer_master_key_spec: "RSA_3072", key_usage: "SIGN_VERIFY", bypass_policy_lockout_safety_check: false } } },
    { address: "aws_kms_alias.root_drop", change: { actions: ["create"], after: { name: "alias/mscqr-production-root-drop", region: "eu-west-2" } } },
  ];
}

function writeCliStageAInputs(directory) {
  const state = { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 44, resources: [] };
  const stateBytes = Buffer.from(JSON.stringify(state));
  const stageAStateFile = path.join(directory, "stage-a.tfstate");
  const stageAStateIdentityFile = path.join(directory, "stage-a-state-identity.json");
  writeFileSync(stageAStateFile, stateBytes, { mode: 0o600 });
  writeFileSync(stageAStateIdentityFile, `${JSON.stringify(buildStageAStateIdentity(state, { stateBytes }))}\n`, { mode: 0o600 });
  return { stageAStateFile, stageAStateIdentityFile };
}

function cliArgs({ phase = "authorize", stateFile, planJsonFile, stageAStateFile, stageAStateIdentityFile }) {
  return [
    "--admin-profile", "administrator", "--release-profile", "release", "--phase", phase,
    "--source-sha", sourceSha, "--transition-id", transitionId, "--state-file", stateFile,
    ...(planJsonFile ? ["--plan-sha256", planSha256, "--plan-json", planJsonFile] : []),
    ...(stageAStateFile ? ["--stage-a-state", stageAStateFile] : []),
    ...(stageAStateIdentityFile ? ["--stage-a-state-identity", stageAStateIdentityFile] : []),
  ];
}

function runCliAndReadFailure(argv, run) {
  let output = "";
  assert.throws(() => runCli(argv, { run, write: (value) => { output += value; } }));
  return JSON.parse(output);
}

function capacityFixture() {
  return {
    defaultVersionId: "v8",
    documents: new Map([["v8", policy], ["v4", policy], ["v5", policy], ["v6", policy], ["v7", policy]]),
    dates: new Map([
      ["v8", "2026-01-06T00:00:00.000Z"],
      ["v4", "2026-01-02T00:00:00.000Z"],
      ["v5", "2026-01-03T00:00:00.000Z"],
      ["v6", "2026-01-04T00:00:00.000Z"],
      ["v7", "2026-01-05T00:00:00.000Z"],
    ]),
  };
}

function createPolicyVersionRunner({ fixture = capacityFixture(), onGetPolicy, onList, onCreate, failCreate = false, loseCreateResponse = false, loseCreateResponseOn = null, createResponse = ({ versionId }) => JSON.stringify({ PolicyVersion: { VersionId: versionId } }), createResponseOn = null, failDeleteVersion = null, loseDeleteResponse = false } = {}) {
  const documents = fixture.documents;
  const dates = fixture.dates;
  let defaultVersionId = fixture.defaultVersionId;
  let nextVersion = Math.max(...[...documents.keys()].map((id) => Number(id.slice(1)))) + 1;
  let listCalls = 0;
  let getPolicyCalls = 0;
  let createCalls = 0;
  let pendingDeleteFailure = failDeleteVersion;
  const calls = [];
  const run = (args) => {
    const operation = args[1];
    calls.push(operation);
    if (operation === "get-policy") {
      getPolicyCalls += 1;
      onGetPolicy?.({ getPolicyCalls });
      return JSON.stringify({ Policy: { DefaultVersionId: defaultVersionId } });
    }
    if (operation === "list-policy-versions") {
      listCalls += 1;
      onList?.({ listCalls, documents, dates, setDefaultVersionId(value) { defaultVersionId = value; } });
      return JSON.stringify({ Versions: [...documents.keys()].map((VersionId) => ({ VersionId, IsDefaultVersion: VersionId === defaultVersionId || VersionId === fixture.extraDefaultVersionId, CreateDate: dates.get(VersionId) })) });
    }
    if (operation === "get-policy-version") {
      const versionId = args[args.indexOf("--version-id") + 1];
      return JSON.stringify({ PolicyVersion: { Document: documents.get(versionId) } });
    }
    if (operation === "delete-policy-version") {
      const versionId = args[args.indexOf("--version-id") + 1];
      if (versionId === defaultVersionId) throw new Error("InvalidInput: cannot delete default policy version");
      if (versionId === pendingDeleteFailure) {
        pendingDeleteFailure = null;
        throw new Error("AccessDenied: delete policy version test failure");
      }
      documents.delete(versionId);
      dates.delete(versionId);
      if (loseDeleteResponse) throw new Error("network response lost after DeletePolicyVersion acceptance");
      return "{}";
    }
    if (operation === "create-policy-version") {
      if (failCreate) throw new Error("LimitExceeded: create policy version test failure");
      createCalls += 1;
      const policyDocument = JSON.parse(readFileSync(args[args.indexOf("--policy-document") + 1].slice("file://".length), "utf8"));
      const versionId = `v${nextVersion++}`;
      documents.set(versionId, policyDocument);
      defaultVersionId = versionId;
      onCreate?.({ versionId, documents, dates, setDefaultVersionId(value) { defaultVersionId = value; } });
      if (loseCreateResponse || loseCreateResponseOn === createCalls) throw new Error("network response lost after CreatePolicyVersion acceptance");
      return createResponseOn === createCalls ? createResponse({ versionId }) : JSON.stringify({ PolicyVersion: { VersionId: versionId } });
    }
    throw new Error(`unexpected AWS operation: ${args.join(" ")}`);
  };
  return { run, documents, dates, calls, get defaultVersionId() { return defaultVersionId; }, set defaultVersionId(value) { defaultVersionId = value; }, get listCalls() { return listCalls; } };
}

function priorTemporaryPolicy() {
  const current = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  return { ...current, Statement: current.Statement.map((statement) => Array.isArray(statement.Action) && statement.Action.includes("kms:PutKeyPolicy") ? { ...statement, Action: TEMPORARY_KMS_CAPABILITY.aliasAction } : statement) };
}

function legacyTemporaryPolicy() {
  const current = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  const keyStatement = current.Statement.find(({ Sid }) => Sid?.startsWith("TemporaryStageARootDropKeyTagAtCreation"));
  const legacySid = `TemporaryStageARootDropKeyTagAtCreation_${sourceSha}_${createHash("sha256").update(transitionId).digest("hex").slice(0, 16)}`;
  return { ...current, Statement: [...current.Statement.filter((statement) => !isTemporaryTagResourceStatement(statement)), { ...keyStatement, Sid: legacySid, Action: TEMPORARY_KMS_CAPABILITY.action }] };
}

function writeAuthorizedEvidence(stateFile, { temporaryVersionId = "v2", actions = ["kms:CreateKey", "kms:TagResource", "kms:PutKeyPolicy", "kms:CreateAlias"] } = {}) {
  const evidence = buildTemporaryCapabilityEvidence({ state: "AUTHORIZED_FOR_ROOT_DROP_CREATION", sourceSha, transitionId, planSha256, defaultVersionId: temporaryVersionId, temporaryVersionId, observedAt: "2026-08-18T12:00:00.000Z" });
  evidence.actions = actions;
  const { evidenceSha256, ...unsigned } = evidence;
  evidence.evidenceSha256 = createHash("sha256").update(canonicalPolicy(unsigned)).digest("hex");
  writeFileSync(stateFile, `${JSON.stringify(evidence)}\n`, { mode: 0o600 });
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
  const evidence = buildTemporaryCapabilityEvidence({ state: "ABSENT", sourceSha, transitionId, observedAt: "2026-08-18T12:00:00.000Z" });
  assert.deepEqual(evidence.actions, ["kms:CreateKey", "kms:TagResource", "kms:PutKeyPolicy", "kms:CreateAlias"]);
  assert.throws(() => assertTemporaryReleasePolicy(buildTemporaryReleasePolicy(policy, { sourceSha, transitionId: "different-transition" }), { steadyStatePolicy: policy, sourceSha, transitionId }), /not exact/);
  assert.throws(() => assertTemporaryReleasePolicy({ ...temporary, Statement: [...temporary.Statement, { Effect: "Allow", Action: "kms:TagResource", Resource: "*" }] }, { steadyStatePolicy: policy, sourceSha, transitionId }), /changes more/);
});

test("temporary capability SID is AWS-compatible, deterministic, bounded, and collision-resistant", () => {
  const productionTransitionId = "stage-a-root-drop-9aa12fd-20260818";
  const sid = canonicalTemporaryKmsStatementSid({ sourceSha: "9aa12fdfa3ca24f9055a700dc58a0319cb5f8db9", transitionId: productionTransitionId });
  assert.match(sid, IAM_STATEMENT_SID_PATTERN);
  assert.ok(sid.length <= IAM_STATEMENT_SID_MAX_LENGTH);
  assert.equal(sid, canonicalTemporaryKmsStatementSid({ sourceSha: "9aa12fdfa3ca24f9055a700dc58a0319cb5f8db9", transitionId: productionTransitionId }));
  assert.notEqual(canonicalTemporaryKmsStatementSid({ sourceSha, transitionId: "a-b" }), canonicalTemporaryKmsStatementSid({ sourceSha, transitionId: "ab" }));
  for (const value of ["stage-a", "stage_a", "stage:a", "stage/a", "stage.a", "a b", "--stage--", "MixedCase", "x".repeat(128)]) {
    const candidate = canonicalTemporaryKmsStatementSid({ sourceSha, transitionId: value });
    assert.match(candidate, IAM_STATEMENT_SID_PATTERN, value);
    assert.ok(candidate.length <= IAM_STATEMENT_SID_MAX_LENGTH, value);
  }
});

test("the production failure-case statement is accepted without changing the logical transition identity", () => {
  const productionTransitionId = "stage-a-root-drop-9aa12fd-20260818";
  const statement = temporaryKmsCapabilityStatement({ sourceSha: "9aa12fdfa3ca24f9055a700dc58a0319cb5f8db9", transitionId: productionTransitionId });
  assert.match(statement.Sid, IAM_STATEMENT_SID_PATTERN);
  assert.equal(statement.Sid.length, 111);
  const evidence = buildTemporaryCapabilityEvidence({ state: "ABSENT", sourceSha, transitionId: productionTransitionId, observedAt: "2026-08-18T12:00:00.000Z" });
  assert.equal(evidence.transitionId, productionTransitionId);
});

test("legacy temporary SID remains narrowly recognizable for revoke/recovery compatibility", () => {
  const temporary = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  const legacySid = `TemporaryStageARootDropKeyTagAtCreation_${sourceSha}_${createHash("sha256").update(transitionId).digest("hex").slice(0, 16)}`;
  temporary.Statement = temporary.Statement.map((statement) => statement.Sid?.startsWith("TemporaryStageARootDropKeyTagAtCreation") ? { ...statement, Sid: legacySid } : statement);
  assert.doesNotThrow(() => assertTemporaryReleasePolicy(temporary, { steadyStatePolicy: policy, sourceSha, transitionId }));
  assert.throws(() => assertTemporaryReleasePolicy(temporary, { steadyStatePolicy: policy, sourceSha: "0".repeat(40), transitionId }), /not exact/);
});

test("temporary policy compacts representation-only statement IDs with meaningful AWS size headroom", () => {
  const temporary = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  const sourceAuthorization = policy.Statement.map(({ Sid, ...statement }) => statement);
  const temporaryAuthorization = temporary.Statement.filter((statement) => !isTemporaryTagResourceStatement(statement)).map(({ Sid, ...statement }) => statement);
  assert.deepEqual(temporaryAuthorization, sourceAuthorization);
  const bytes = Buffer.byteLength(JSON.stringify(temporary));
  assert.equal(AWS_MANAGED_POLICY_DOCUMENT_LIMIT, 6144);
  assert.ok(bytes <= TEMPORARY_POLICY_MAX_BYTES);
  assert.ok(AWS_MANAGED_POLICY_DOCUMENT_LIMIT - bytes >= TEMPORARY_POLICY_MIN_HEADROOM);
});

test("temporary policy allows only the exact root-drop tag-on-create context", () => {
  const temporary = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  const statement = temporary.Statement.find(({ Sid }) => Sid?.startsWith("TemporaryStageARootDropKeyTagAtCreation"));
  const asArray = (value) => Array.isArray(value) ? value : [value];
  const context = {
    "aws:RequestedRegion": "eu-west-2",
    "aws:RequestTag/Environment": "production",
    "aws:RequestTag/ManagedBy": "Terraform",
    "aws:RequestTag/Component": "full-rls-green-stage-a",
    "aws:RequestTag/Stack": "production-green-stage-a",
    "aws:TagKeys": ["Environment", "ManagedBy", "Component", "Stack"],
    "kms:CallerAccount": "368992683803",
    "kms:KeySpec": "RSA_3072",
    "kms:KeyUsage": "SIGN_VERIFY",
  };
  const allows = (action, resource, values) => statement.Effect === "Allow"
    && asArray(statement.Action).includes(action)
    && asArray(statement.Resource).includes(resource)
    && Object.entries(statement.Condition).every(([operator, entries]) => Object.entries(entries).every(([key, expected]) => {
      const actual = values[key];
      if (operator === "ForAllValues:StringEquals") return Array.isArray(actual) && actual.every((value) => expected.includes(value));
      return actual !== undefined && actual === expected;
    }));
  assert.equal(allows("kms:TagResource", "*", context), true);
  for (const mutation of [
    { "kms:CallerAccount": "111111111111" },
    { "aws:RequestedRegion": "us-east-1" },
    { "kms:KeySpec": "ECC_NIST_P256" },
    { "kms:KeyUsage": "ENCRYPT_DECRYPT" },
    { "aws:RequestTag/Stack": "legacy" },
    { "aws:TagKeys": ["Environment", "ManagedBy", "Component", "Stack", "Owner"] },
    { "kms:CallerAccount": undefined },
  ]) assert.equal(allows("kms:TagResource", "*", { ...context, ...mutation }), false);
  assert.equal(allows("kms:TagResource", "arn:aws:kms:eu-west-2:368992683803:key/unrelated", context), false);
  assert.equal(allows("kms:Sign", "*", context), false);
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

test("fresh Stage-A plan accepts only the exact two-create root-drop envelope", () => {
  const create = (address) => ({ address, change: { actions: ["create"] } });
  const valid = { resource_changes: rootDropPlanChanges() };
  assert.doesNotThrow(() => assertStageARootDropCreationPlan(valid));
  const missingRead = structuredClone(valid); missingRead.resource_changes[0].change.after.policy = JSON.stringify({ ...buildStageARootDropKeyPolicy(), Statement: buildStageARootDropKeyPolicy().Statement.map((statement) => statement.Sid === "ReleaseReadsRootDropKey" ? { ...statement, Action: statement.Action.filter((action) => action !== "kms:GetKeyRotationStatus") } : statement) });
  assert.throws(() => assertStageARootDropCreationPlan(missingRead), /provider read/);
  for (const plan of [
    { resource_changes: [...valid.resource_changes, create("aws_s3_bucket.unrelated")] },
    { resource_changes: [{ address: "aws_kms_key.root_drop", change: { actions: ["delete", "create"] } }, valid.resource_changes[1]] },
    { resource_changes: [{ address: "aws_kms_key.root_drop", change: { actions: ["delete"] } }, valid.resource_changes[1]] },
    { resource_changes: [valid.resource_changes[0]] },
    { resource_changes: [{ address: "aws_kms_key.root_drop", change: { actions: ["unknown"] } }, valid.resource_changes[1]] },
  ]) assert.throws(() => assertStageARootDropCreationPlan(plan), /exact two-resource root-drop creation envelope/);
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
  const node = JSON.parse(readFileSync(manifestPath, "utf8")).nodes.find(({ id }) => id === 8);
  assert.match(node.canonicalCommandOrFunction, /--stage-a-state <fresh-stage-a-state>/);
  assert.match(node.canonicalCommandOrFunction, /--stage-a-state-identity <fresh-stage-a-state-identity>/);
});

test("historical steady-state recognition is exact, repository-bound, and default-protected", () => {
  for (const source of AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES) {
    const fixture = historicalPolicyFixtures.find(({ sourceCommitSha }) => sourceCommitSha === source.repositoryCommit);
    const versionId = fixture?.versionId;
    const document = fixture?.document;
    assert.equal(fixture?.canonicalSha256, source.policySha256);
    assert.equal(policySha256(document), fixture?.canonicalSha256);
    assert.equal(classifyTemporaryKmsPolicyVersion({ VersionId: versionId, IsDefaultVersion: false, document }, { steadyStatePolicy: policy, sourceSha, transitionId }), "RECOGNIZED_STALE_STEADY_STATE");
    assert.equal(classifyTemporaryKmsPolicyVersion({ VersionId: versionId, IsDefaultVersion: true, document }, { steadyStatePolicy: policy, sourceSha, transitionId }), "UNKNOWN");
  }
  const modified = structuredClone(historicalPolicies.get("v7"));
  modified.Statement = [...modified.Statement, { Effect: "Allow", Action: "kms:GetKeyPolicy", Resource: "*" }];
  assert.equal(classifyTemporaryKmsPolicyVersion({ VersionId: "v7", IsDefaultVersion: false, document: modified }, { steadyStatePolicy: policy, sourceSha, transitionId }), "UNKNOWN");
  const temporary = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  assert.equal(classifyTemporaryKmsPolicyVersion({ VersionId: "v9", IsDefaultVersion: true, document: temporary }, { steadyStatePolicy: policy, sourceSha, transitionId }), "CURRENT_ACTIVE_TEMPORARY");
});

test("live four-version historical topology creates without cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-historical-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = {
    defaultVersionId: "v8",
    documents: new Map([["v5", historicalPolicies.get("v5")], ["v6", historicalPolicies.get("v6")], ["v7", historicalPolicies.get("v7")], ["v8", policy]]),
    dates: new Map([["v5", "2026-08-12T21:40:45.000Z"], ["v6", "2026-08-13T00:53:22.000Z"], ["v7", "2026-08-13T07:23:15.000Z"], ["v8", "2026-08-17T19:39:34.000Z"]]),
  };
  const fake = createPolicyVersionRunner({ fixture });
  try {
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.writes, 1);
    assert.equal(result.mutationAccounting.policyVersionDeletions, 0);
    assert.equal(result.mutationAccounting.policyVersionCreations, 1);
    assert.deepEqual(fake.calls.filter((operation) => operation === "delete-policy-version"), []);
    assert.deepEqual(fake.calls.filter((operation) => operation === "create-policy-version"), ["create-policy-version"]);
    for (const versionId of ["v5", "v6", "v7", "v8"]) assert.equal(fake.documents.has(versionId), true);
    assert.deepEqual(fake.documents.get("v8"), policy);
    assert.equal(fake.defaultVersionId, "v9");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("five-version historical topology deletes exactly the oldest authenticated stale version", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-historical-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = {
    defaultVersionId: "v8",
    documents: new Map([["v4", historicalPolicies.get("v4")], ["v5", historicalPolicies.get("v5")], ["v6", historicalPolicies.get("v6")], ["v7", historicalPolicies.get("v7")], ["v8", policy]]),
    dates: new Map([["v4", "2026-08-12T20:34:36.000Z"], ["v5", "2026-08-12T21:40:45.000Z"], ["v6", "2026-08-13T00:53:22.000Z"], ["v7", "2026-08-13T07:23:15.000Z"], ["v8", "2026-08-17T19:39:34.000Z"]]),
  };
  const fake = createPolicyVersionRunner({ fixture });
  try {
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.mutationAccounting.policyVersionDeletions, 1);
    assert.deepEqual(fake.calls.filter((operation) => operation === "delete-policy-version"), ["delete-policy-version"]);
    assert.equal(fake.documents.has("v4"), false);
    for (const versionId of ["v5", "v6", "v7", "v8", "v9"]) assert.equal(fake.documents.has(versionId), true);
    assert.equal(fake.defaultVersionId, "v9");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("canonical producer replays authorization and safely aborts a failed apply", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-runner-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = path.join(directory, "plan.json");
  writeFileSync(planJsonFile, JSON.stringify({ resource_changes: rootDropPlanChanges() }), { mode: 0o600 });
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
    const revoked = runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true });
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

test("revoke recovery cannot reconstruct REVOKED before root-drop ownership verification", () => {
  for (const phase of ["authorized", "stage-a-apply"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-revoke-state-"));
    const stateFile = path.join(directory, "capability.json");
    const planJsonFile = writePlanFile(directory);
    const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
    try {
      const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
      runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      if (phase === "stage-a-apply") runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
      fake.documents.delete("v2");
      fake.dates.delete("v2");
      fake.defaultVersionId = "v1";
      assert.throws(() => runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile }), /authenticated temporary capability is not the live default version/);
      assert.notEqual(JSON.parse(readFileSync(stateFile, "utf8")).state, "REVOKED");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("canonical producer accepts an AWS CLI parsed PolicyVersion.Document object", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-object-document-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = path.join(directory, "plan.json");
  writeFileSync(planJsonFile, JSON.stringify({ resource_changes: rootDropPlanChanges() }), { mode: 0o600 });
  let defaultVersionId = "v1";
  let nextVersion = 2;
  const versions = new Map([["v1", policy]]);
  let policyWrites = 0;
  let submittedDocument;
  const run = (args) => {
    const operation = args[1];
    if (operation === "get-policy") return JSON.stringify({ Policy: { DefaultVersionId: defaultVersionId } });
    if (operation === "list-policy-versions") return JSON.stringify({ Versions: [...versions.keys()].map((VersionId) => ({ VersionId })) });
    if (operation === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: versions.get(args[args.indexOf("--version-id") + 1]) } });
    if (operation === "create-policy-version") {
      const policyDocument = JSON.parse(readFileSync(args[args.indexOf("--policy-document") + 1].slice("file://".length), "utf8"));
      submittedDocument = policyDocument;
      const versionId = `v${nextVersion++}`;
      versions.set(versionId, policyDocument); defaultVersionId = versionId; policyWrites += 1;
      return JSON.stringify({ PolicyVersion: { VersionId: versionId } });
    }
    throw new Error(`unexpected AWS operation: ${args.join(" ")}`);
  };
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run, now: () => "2026-08-18T12:00:00.000Z" });
    const result = runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.evidence.state, "AUTHORIZED_FOR_ROOT_DROP_CREATION");
    assert.equal(policyWrites, 1);
    const submittedBytes = Buffer.byteLength(JSON.stringify(submittedDocument));
    assert.ok(submittedBytes <= TEMPORARY_POLICY_MAX_BYTES);
    assert.ok(AWS_MANAGED_POLICY_DOCUMENT_LIMIT - submittedBytes >= TEMPORARY_POLICY_MIN_HEADROOM);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an unrecorded post-write capability can be recovered only with exact failed-apply inputs", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-recovery-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = path.join(directory, "plan.json");
  writeFileSync(planJsonFile, JSON.stringify({ resource_changes: rootDropPlanChanges() }), { mode: 0o600 });
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
    assert.throws(() => runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, applyFailed: true, partialOperationCensus: true }), /apply failure.*partial-operation census/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("abort recovery reconstructs completed aborts after temporary deletion without new IAM writes", () => {
  for (const lifecycle of ["AUTHORIZED_FOR_ROOT_DROP_CREATION", "STAGE_A_APPLY"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-abort-recovery-"));
    const stateFile = path.join(directory, "capability.json");
    const planJsonFile = writePlanFile(directory);
    const fixture = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
    let failRevokedWrite = true;
    const persist = (filePath, value) => {
      if (value.state === "REVOKED" && failRevokedWrite) { failRevokedWrite = false; throw new Error("simulated process death after abort revocation"); }
      writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    };
    try {
      const runner = createTemporaryKmsCapabilityRunner({ run: fixture.run, writeEvidence: persist, now: () => "2026-08-18T12:00:00.000Z" });
      runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      if (lifecycle === "STAGE_A_APPLY") runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
      const beforeAbort = fixture.calls.length;
      assert.throws(() => runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true }), /simulated process death/);
      const afterAbort = fixture.calls.length;
      assert.equal(fixture.calls.filter((operation) => operation === "create-policy-version").length, 2);
      assert.equal(fixture.calls.filter((operation) => operation === "delete-policy-version").length, 1);
      assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fixture.run }).runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /apply failure/);
      assert.equal(fixture.calls.filter((operation) => ["create-policy-version", "delete-policy-version"].includes(operation)).length, 3);
      const recovered = createTemporaryKmsCapabilityRunner({ run: fixture.run }).runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true });
      assert.equal(recovered.recovery, "AUTHENTICATED_ABORT_ALREADY_REVOKED");
      assert.equal(recovered.evidence.state, "REVOKED");
      assert.equal(recovered.writes, 0);
      assert.ok(fixture.calls.length > afterAbort);
      assert.equal(fixture.calls.filter((operation) => operation === "create-policy-version").length, 2);
      assert.equal(fixture.calls.filter((operation) => operation === "delete-policy-version").length, 1);
      assert.ok(fixture.calls.length > beforeAbort);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("completed abort recovery rejects missing or mismatched authenticated bindings", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-abort-bindings-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
  let failRevokedWrite = true;
  const persist = (filePath, value) => {
    if (value.state === "REVOKED" && failRevokedWrite) { failRevokedWrite = false; throw new Error("simulated process death after abort revocation"); }
    writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  };
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fixture.run, writeEvidence: persist });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.throws(() => runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true }), /simulated process death/);
    const mutationCountsAfterCompletion = fixture.calls.filter((operation) => ["create-policy-version", "delete-policy-version"].includes(operation)).length;
    for (const input of [
      { sourceSha: "b".repeat(40) },
      { transitionId: "different-transition" },
      { planSha256: "b".repeat(64) },
      { partialOperationCensus: false },
    ]) {
      assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fixture.run }).runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true, ...input }), /abort recovery|evidence identity|authenticated partial-operation census|different transition or plan/);
      assert.equal(fixture.calls.filter((operation) => ["create-policy-version", "delete-policy-version"].includes(operation)).length, mutationCountsAfterCompletion);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("completed abort recovery fails closed for unknown or ambiguous policy topology", () => {
  for (const mode of ["unknown", "ambiguous"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-abort-topology-"));
    const stateFile = path.join(directory, "capability.json");
    const planJsonFile = writePlanFile(directory);
    const fixtureConfig = { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) };
    const fixture = createPolicyVersionRunner({ fixture: fixtureConfig });
    try {
      const runner = createTemporaryKmsCapabilityRunner({ run: fixture.run });
      runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      if (mode === "unknown") fixture.documents.set("v3", ["malformed"]);
      if (mode === "ambiguous") fixtureConfig.extraDefaultVersionId = "v1";
      const mutationsBefore = fixture.calls.filter((operation) => ["create-policy-version", "delete-policy-version"].includes(operation)).length;
      assert.throws(() => runner.runPhase({ phase: "abort", sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true }), /policy version document|default-version topology/);
      assert.equal(fixture.calls.filter((operation) => ["create-policy-version", "delete-policy-version"].includes(operation)).length, mutationsBefore);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("five-version production topology deletes exactly the oldest authenticated stale version", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner();
  try {
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.writes, 2);
    assert.deepEqual(fake.calls.filter((operation) => operation === "delete-policy-version"), ["delete-policy-version"]);
    assert.equal(fake.documents.has("v4"), false);
    assert.equal(fake.documents.has("v5"), true);
    assert.equal(fake.documents.has("v9"), true);
    assert.equal(fake.defaultVersionId, "v9");
    assert.equal(result.mutationAccounting.policyVersionDeletions, 1);
    assert.equal(result.mutationAccounting.policyVersionCreations, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("four-version topology creates without cleanup and never prunes history early", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.documents.delete("v7");
  fixture.dates.delete("v7");
  const fake = createPolicyVersionRunner({ fixture });
  try {
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.writes, 1);
    assert.deepEqual(fake.calls.filter((operation) => operation === "delete-policy-version"), []);
    assert.equal(fake.documents.has("v4"), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("default policy version is never selected for cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.dates.set("v8", "2025-01-01T00:00:00.000Z");
  const fake = createPolicyVersionRunner({ fixture });
  try {
    createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(fake.documents.has("v8"), true);
    assert.equal(fake.defaultVersionId, "v9");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("unknown policy version state fails closed before any cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  const unknown = structuredClone(policy);
  unknown.Statement = [...unknown.Statement, { Effect: "Allow", Action: "kms:GetKeyPolicy", Resource: "*" }];
  fixture.documents.set("v7", unknown);
  const fake = createPolicyVersionRunner({ fixture });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /unknown or ambiguous/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("ambiguous default topology fails closed before cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = { ...capacityFixture(), extraDefaultVersionId: "v7" };
  const fake = createPolicyVersionRunner({ fixture });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /default-version topology is ambiguous/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("missing authoritative creation metadata fails closed", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.dates.delete("v4");
  const fake = createPolicyVersionRunner({ fixture });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /authoritative CreateDate/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("topology change between census and delete fails closed", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ onList: ({ listCalls, documents, dates }) => {
    if (listCalls === 2) {
      documents.delete("v4");
      documents.set("v99", policy);
      dates.set("v99", "2026-01-02T00:00:00.000Z");
    }
  } });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /topology changed before capacity cleanup/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("topology change after deletion blocks creation without deleting another version", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ onList: ({ listCalls, documents, dates }) => {
    if (listCalls === 3) {
      documents.set("v99", policy);
      dates.set("v99", "2026-01-06T00:00:00.000Z");
    }
  } });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /capacity cleanup|outside AWS limits/);
    assert.deepEqual(fake.calls.filter((operation) => operation === "delete-policy-version"), ["delete-policy-version"]);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("pre-create readState failure does not enter CreatePolicyVersion recovery", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-pre-create-read-failure-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.documents.delete("v7");
  fixture.dates.delete("v7");
  const fake = createPolicyVersionRunner({ fixture, onList: ({ listCalls }) => { if (listCalls === 2) throw new Error("pre-create topology read failed"); } });
  try {
    let error;
    try { createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }); } catch (caught) { error = caught; }
    assert.match(error?.message || "", /pre-create topology read failed/);
    assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 0);
    assert.equal(fake.listCalls, 2);
    assert.equal(error.mutationAccounting?.iamWriteAttempts, 0);
    assert.equal(error.mutationAccounting?.unknownMutations, 0);
    assert.deepEqual(error.mutationAccounting?.mutationOutcomes, []);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("pre-create topology fingerprint failure does not enter CreatePolicyVersion recovery", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-pre-create-topology-change-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.documents.delete("v7");
  fixture.dates.delete("v7");
  const fake = createPolicyVersionRunner({ fixture, onList: ({ listCalls, documents, dates }) => {
    if (listCalls === 2) { documents.delete("v4"); dates.delete("v4"); }
  } });
  try {
    let error;
    try { createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }); } catch (caught) { error = caught; }
    assert.match(error?.message || "", /topology changed before policy-version creation/);
    assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 0);
    assert.equal(fake.listCalls, 2);
    assert.equal(error.mutationAccounting?.iamWriteAttempts, 0);
    assert.equal(error.mutationAccounting?.unknownMutations, 0);
    assert.deepEqual(error.mutationAccounting?.mutationOutcomes, []);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("pre-create GetPolicy failure does not enter CreatePolicyVersion recovery", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-pre-create-policy-failure-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.documents.delete("v7");
  fixture.dates.delete("v7");
  const fake = createPolicyVersionRunner({ fixture, onGetPolicy: ({ getPolicyCalls }) => { if (getPolicyCalls === 2) throw new Error("pre-create policy read failed"); } });
  try {
    let error;
    try { createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }); } catch (caught) { error = caught; }
    assert.match(error?.message || "", /pre-create policy read failed/);
    assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 0);
    assert.equal(error.mutationAccounting?.iamWriteAttempts, 0);
    assert.equal(error.mutationAccounting?.unknownMutations, 0);
    assert.deepEqual(error.mutationAccounting?.mutationOutcomes, []);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("delete failure prevents create and reports the failed mutation attempt", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ failDeleteVersion: "v4" });
  try {
    let error;
    try {
      createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      assert.fail("expected policy-version deletion failure");
    } catch (caught) {
      error = caught;
    }
    assert.equal(error.mutationAccounting.iamWriteAttempts, 1);
    assert.equal(error.mutationAccounting.iamWrites, 0);
    assert.equal(error.mutationAccounting.policyVersionDeletions, 0);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("cleanup can succeed while create fails, and retry creates without another deletion", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  const failed = createPolicyVersionRunner({ fixture, failCreate: true });
  try {
    let error;
    try {
      createTemporaryKmsCapabilityRunner({ run: failed.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      assert.fail("expected policy-version creation failure");
    } catch (caught) {
      error = caught;
    }
    assert.equal(error.mutationAccounting.iamWrites, 1);
    assert.deepEqual(error.capacityRecovery.deletedVersionIds, ["v4"]);
    assert.equal(failed.documents.has("v4"), false);
    const retryRunner = createPolicyVersionRunner({ fixture });
    const retry = createTemporaryKmsCapabilityRunner({ run: retryRunner.run, now: () => "2026-08-18T12:01:00.000Z" }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(retry.writes, 1);
    assert.deepEqual(failed.calls.filter((operation) => operation === "delete-policy-version"), ["delete-policy-version"]);
    assert.equal(retryRunner.defaultVersionId, "v9");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("revocation manages capacity and removes only the stale and temporary versions", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner();
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const terraformStateFile = path.join(directory, "terraform.tfstate");
    writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
    const result = runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile });
    assert.equal(result.writes, 3);
    assert.deepEqual(fake.calls.filter((operation) => operation === "delete-policy-version").length, 3);
    assert.equal(fake.documents.has("v5"), false, [...fake.documents.keys()].join(","));
    assert.equal(fake.documents.has("v9"), false, [...fake.documents.keys()].join(","));
    assert.equal(fake.defaultVersionId, "v10");
    const absent = runner.runPhase({ phase: "verify-absent", sourceSha, transitionId, stateFile });
    assert.equal(absent.evidence.state, "ABSENCE_VERIFIED");
    assert.doesNotThrow(() => assertPreCutoverTemporaryCapabilityAbsent(absent.evidence, { sourceSha }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("revoke retries after temporary-version deletion failure without creating another steady version", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) };
  const fake = createPolicyVersionRunner({ fixture, failDeleteVersion: "v2" });
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fake.run, now: () => "2026-08-18T12:00:00.000Z" });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const terraformStateFile = path.join(directory, "terraform.tfstate");
    writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
    assert.throws(() => runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile }), /delete policy version test failure/);
    assert.equal(fake.defaultVersionId, "v3");
    const retry = runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile });
    assert.equal(retry.evidence.state, "REVOKED");
    assert.equal(retry.writes, 1);
    assert.equal(fake.defaultVersionId, "v3");
    assert.equal(fake.documents.has("v2"), false);
    assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 2);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("reversed AWS version ordering still uses creation date and VersionId tie-breakers", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.documents = new Map([...fixture.documents].reverse());
  fixture.dates.set("v4", "2026-01-02T00:00:00.000Z");
  fixture.dates.set("v5", "2026-01-02T00:00:00.000Z");
  const fake = createPolicyVersionRunner({ fixture });
  try {
    createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(fake.documents.has("v4"), false);
    assert.equal(fake.documents.has("v5"), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an authenticated active temporary version is protected during authorization replay", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner();
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    const replay = runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(replay.writes, 0);
    assert.equal(fake.calls.filter((operation) => operation === "delete-policy-version").length, 1);
    assert.equal(fake.documents.has("v5"), true);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("authorization replay replaces the recognized pre-PutKeyPolicy temporary policy", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-prior-replay-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const prior = priorTemporaryPolicy();
  const fake = createPolicyVersionRunner({ fixture: {
    defaultVersionId: "v2",
    documents: new Map([["v1", policy], ["v2", prior]]),
    dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"]]),
  } });
  try {
    writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.evidence.temporaryVersionId, "v3");
    assert.deepEqual(result.evidence.actions, ["kms:CreateKey", "kms:TagResource", "kms:PutKeyPolicy", "kms:CreateAlias"]);
    assert.equal(result.writes, 2);
    assert.equal(result.mutationAccounting.policyVersionCreations, 1);
    assert.equal(result.mutationAccounting.policyVersionDeletions, 1);
    assert.equal(fake.documents.has("v2"), false);
    assert.equal(fake.defaultVersionId, "v3");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("obsolete authorization replacement records a known old-version delete rejection", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-prior-replay-reject-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const prior = priorTemporaryPolicy();
  const fake = createPolicyVersionRunner({ fixture: {
    defaultVersionId: "v2",
    documents: new Map([["v1", policy], ["v2", prior]]),
    dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"]]),
  }, failDeleteVersion: "v2" });
  try {
    writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
    let failure;
    try {
      createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    } catch (error) { failure = error; }
    assert.match(failure?.message || "", /delete policy version test failure/);
    assert.equal(fake.defaultVersionId, "v3");
    assert.equal(fake.documents.has("v2"), true);
    assert.equal(failure.mutationAccounting.iamWriteAttempts, 2);
    assert.equal(failure.mutationAccounting.iamWrites, 1);
    assert.equal(failure.mutationAccounting.unknownMutations, 0);
    assert.deepEqual(failure.mutationAccounting.mutationOutcomes, [
      { action: "CreatePolicyVersion", outcome: "CONFIRMED_SUCCESS" },
      { action: "DeletePolicyVersion", outcome: "ATTEMPTED_REJECTED" },
    ]);
    assert.deepEqual(failure.capacityRecovery.attemptedVersionIds, ["v2"]);
    assert.deepEqual(failure.capacityRecovery.createdVersionIds, ["v3"]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("interrupted replay cleanup records a known old-version delete rejection", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-interrupted-replay-reject-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const prior = priorTemporaryPolicy();
  const current = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  const fake = createPolicyVersionRunner({ fixture: {
    defaultVersionId: "v3",
    documents: new Map([["v1", policy], ["v2", prior], ["v3", current]]),
    dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"], ["v3", "2026-01-03T00:00:00.000Z"]]),
  }, failDeleteVersion: "v2" });
  try {
    writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
    let failure;
    try {
      createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    } catch (error) { failure = error; }
    assert.match(failure?.message || "", /delete policy version test failure/);
    assert.equal(fake.defaultVersionId, "v3");
    assert.equal(fake.documents.has("v2"), true);
    assert.equal(failure.mutationAccounting.iamWriteAttempts, 1);
    assert.equal(failure.mutationAccounting.iamWrites, 0);
    assert.equal(failure.mutationAccounting.unknownMutations, 0);
    assert.deepEqual(failure.mutationAccounting.mutationOutcomes, [{ action: "DeletePolicyVersion", outcome: "ATTEMPTED_REJECTED" }]);
    assert.deepEqual(failure.capacityRecovery.attemptedVersionIds, ["v2"]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("obsolete authorization replacement confirms an accepted old-version delete after response loss", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-prior-replay-lost-delete-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const prior = priorTemporaryPolicy();
  const fake = createPolicyVersionRunner({ fixture: {
    defaultVersionId: "v2",
    documents: new Map([["v1", policy], ["v2", prior]]),
    dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"]]),
  }, loseDeleteResponse: true });
  try {
    writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.evidence.temporaryVersionId, "v3");
    assert.equal(fake.documents.has("v2"), false);
    assert.equal(result.mutationAccounting.iamWriteAttempts, 2);
    assert.equal(result.mutationAccounting.iamWrites, 2);
    assert.equal(result.mutationAccounting.unknownMutations, 0);
    assert.deepEqual(result.mutationAccounting.mutationOutcomes, [
      { action: "CreatePolicyVersion", outcome: "CONFIRMED_SUCCESS" },
      { action: "DeletePolicyVersion", outcome: "CONFIRMED_SUCCESS_READBACK" },
    ]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("interrupted replay cleanup confirms an accepted old-version delete after response loss", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-interrupted-replay-lost-delete-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const prior = priorTemporaryPolicy();
  const current = buildTemporaryReleasePolicy(policy, { sourceSha, transitionId });
  const fake = createPolicyVersionRunner({ fixture: {
    defaultVersionId: "v3",
    documents: new Map([["v1", policy], ["v2", prior], ["v3", current]]),
    dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"], ["v3", "2026-01-03T00:00:00.000Z"]]),
  }, loseDeleteResponse: true });
  try {
    writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.evidence.temporaryVersionId, "v3");
    assert.equal(fake.documents.has("v2"), false);
    assert.equal(result.mutationAccounting.iamWriteAttempts, 1);
    assert.equal(result.mutationAccounting.iamWrites, 1);
    assert.equal(result.mutationAccounting.unknownMutations, 0);
    assert.deepEqual(result.mutationAccounting.mutationOutcomes, [{ action: "DeletePolicyVersion", outcome: "CONFIRMED_SUCCESS_READBACK" }]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("obsolete authorization replacement preserves an ambiguous old-version delete outcome", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-prior-replay-ambiguous-delete-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const prior = priorTemporaryPolicy();
  const fake = createPolicyVersionRunner({ fixture: {
    defaultVersionId: "v2",
    documents: new Map([["v1", policy], ["v2", prior]]),
    dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"]]),
  }, loseDeleteResponse: true, onList: ({ documents }) => {
    if (!documents.has("v2")) throw new Error("policy topology read unavailable");
  } });
  try {
    writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
    let failure;
    try {
      createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    } catch (error) { failure = error; }
    assert.match(failure?.message || "", /network response lost after DeletePolicyVersion acceptance/);
    assert.equal(fake.defaultVersionId, "v3");
    assert.equal(fake.documents.has("v2"), false);
    assert.equal(failure.mutationAccounting.iamWriteAttempts, 2);
    assert.equal(failure.mutationAccounting.iamWrites, 1);
    assert.equal(failure.mutationAccounting.unknownMutations, 1);
    assert.deepEqual(failure.mutationAccounting.mutationOutcomes, [
      { action: "CreatePolicyVersion", outcome: "CONFIRMED_SUCCESS" },
      { action: "DeletePolicyVersion", outcome: "OUTCOME_UNKNOWN" },
    ]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("recognized pre-PutKeyPolicy temporary policy remains abort- and revoke-revocable", () => {
  for (const phase of ["abort", "revoke"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-prior-recovery-"));
    const stateFile = path.join(directory, "capability.json");
    const planJsonFile = writePlanFile(directory);
    const prior = priorTemporaryPolicy();
    const fake = createPolicyVersionRunner({ fixture: {
      defaultVersionId: "v2",
      documents: new Map([["v1", policy], ["v2", prior]]),
      dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"]]),
    } });
    try {
      writeAuthorizedEvidence(stateFile, { actions: ["kms:CreateKey", "kms:TagResource", "kms:CreateAlias"] });
      const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
      if (phase === "revoke") {
        runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
        const terraformStateFile = path.join(directory, "terraform.tfstate");
        writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
        runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
      }
      const result = runner.runPhase({ phase, sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: phase === "abort", partialOperationCensus: phase === "abort" });
      assert.equal(result.evidence.state, "REVOKED");
      assert.equal(fake.defaultVersionId, "v3");
      assert.equal(fake.documents.has("v2"), false);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("legacy TagResource-only temporary policy cannot authorize but remains abort- and revoke-revocable", () => {
  for (const phase of ["authorize", "abort", "revoke"]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-legacy-replay-"));
    const stateFile = path.join(directory, "capability.json");
    const planJsonFile = writePlanFile(directory);
    const legacy = legacyTemporaryPolicy();
    const fake = createPolicyVersionRunner({ fixture: {
      defaultVersionId: "v2",
      documents: new Map([["v1", policy], ["v2", legacy]]),
      dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v2", "2026-01-02T00:00:00.000Z"]]),
    } });
    try {
      writeAuthorizedEvidence(stateFile);
      if (phase === "authorize") {
        assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase, sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /legacy temporary policy cannot authorize/);
        assert.equal(fake.defaultVersionId, "v2");
        assert.deepEqual(fake.calls.filter((operation) => ["create-policy-version", "delete-policy-version"].includes(operation)), []);
      } else {
        if (phase === "revoke") {
          const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
          runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
          const terraformStateFile = path.join(directory, "terraform.tfstate");
          writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
          runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
        }
        const result = createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase, sourceSha, transitionId, stateFile, planSha256, planJsonFile, applyFailed: true, partialOperationCensus: true });
        assert.equal(result.evidence.state, "REVOKED");
        assert.equal(fake.defaultVersionId, "v3");
        assert.equal(fake.documents.has("v2"), false);
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("AWS list failure prevents all capacity mutations", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner();
  const run = (args) => args[1] === "list-policy-versions" ? (() => { throw new Error("network list failure"); })() : fake.run(args);
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /network list failure/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("AWS policy-document read failure prevents all capacity mutations", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner();
  const run = (args) => args[1] === "get-policy-version" ? (() => { throw new Error("network document failure"); })() : fake.run(args);
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /network document failure/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("unexpected policy version after creation fails closed with creation accounting", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ onCreate: ({ documents, dates }) => {
    documents.set("v99", policy);
    dates.set("v99", "2026-01-07T00:00:00.000Z");
  } });
  try {
    let error;
    try {
      createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      assert.fail("expected post-create topology failure");
    } catch (caught) {
      error = caught;
    }
    assert.equal(error.mutationAccounting.policyVersionCreations, 1);
    assert.deepEqual(error.capacityRecovery.createdVersionIds, ["v9"]);
    assert.equal(fake.calls.filter((operation) => operation === "delete-policy-version").length, 1);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("zero-default topology fails closed", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.defaultVersionId = "v999";
  const fake = createPolicyVersionRunner({ fixture });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /default-version topology is ambiguous/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("malformed policy document fails closed before capacity cleanup", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-capacity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = capacityFixture();
  fixture.documents.set("v7", ["not", "a", "policy"]);
  const fake = createPolicyVersionRunner({ fixture });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), /policy version document/);
    assert.equal(fake.calls.includes("delete-policy-version"), false);
    assert.equal(fake.calls.includes("create-policy-version"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("revocation reconstructs authenticated REVOKED evidence after the final write is lost", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-revoke-recovery-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
  let failRevokedWrite = true;
  const persist = (filePath, value) => {
    if (value.state === "REVOKED" && failRevokedWrite) { failRevokedWrite = false; throw new Error("simulated process death after AWS revocation"); }
    writeFileSync(filePath, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  };
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fixture.run, writeEvidence: persist, now: () => "2026-08-18T12:00:00.000Z" });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    writeFileSync(path.join(directory, "state.json"), JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile: path.join(directory, "state.json") });
    assert.throws(() => runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile }), /simulated process death/);
    const recovered = createTemporaryKmsCapabilityRunner({ run: fixture.run, now: () => "2026-08-18T12:01:00.000Z" }).runPhase({ phase: "revoke", sourceSha, transitionId, stateFile });
    assert.equal(recovered.recovery, "AUTHENTICATED_ALREADY_REVOKED");
    assert.equal(recovered.evidence.state, "REVOKED");
    assert.equal(recovered.writes, 0);
    assert.equal(fixture.calls.filter((operation) => operation === "create-policy-version").length, 2);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("strict authorization binds the temporary capability to the current Stage-A state identity", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-state-binding-"));
  const stateFile = path.join(directory, "capability.json");
  const stageAStateFile = path.join(directory, "stage-a.tfstate");
  const planJsonFile = writePlanFile(directory);
  const state = { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 44, resources: [] };
  const bytes = Buffer.from(JSON.stringify(state));
  writeFileSync(stageAStateFile, bytes, { mode: 0o600 });
  const fixture = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
  const identity = buildStageAStateIdentity(state, { stateBytes: bytes });
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fixture.run, requireStageAStateBinding: true });
    const result = runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile, stageAStateFile, stageAStateIdentity: identity });
    assert.deepEqual(result.evidence.stageAStateIdentity, identity);
    const advanced = { ...state, serial: 45 };
    writeFileSync(stageAStateFile, JSON.stringify(advanced), { mode: 0o600 });
    assert.throws(() => runner.runPhase({ phase: "authorize", sourceSha, transitionId: "stage-a-root-drop-20260819", stateFile: path.join(directory, "other.json"), planSha256, planJsonFile, stageAStateFile, stageAStateIdentity: identity }), /state identity binding/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI authorization rejects state without an independently produced identity before AWS", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-missing-state-identity-"));
  const stateFile = path.join(directory, "capability.json");
  const stageAStateFile = path.join(directory, "stage-a.tfstate");
  const planJsonFile = writePlanFile(directory);
  writeFileSync(stageAStateFile, JSON.stringify({ lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 44 }), { mode: 0o600 });
  try {
    const result = spawnSync(process.execPath, [
      path.resolve("scripts/aws/reconcile-production-stage-a-temporary-kms-capability.mjs"),
      "--phase", "authorize", "--source-sha", sourceSha, "--transition-id", transitionId,
      "--state-file", stateFile, "--admin-profile", "administrator", "--release-profile", "release",
      "--plan-sha256", planSha256, "--plan-json", planJsonFile, "--stage-a-state", stageAStateFile,
    ], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /--stage-a-state-identity is required/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI emits a zero-mutation machine-readable failure before any IAM mutation", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-cli-zero-failure-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const inputs = writeCliStageAInputs(directory);
  try {
    const failure = runCliAndReadFailure(cliArgs({ stateFile, planJsonFile, ...inputs }), () => { throw new Error("pre-mutation read failed"); });
    assert.equal(failure.writes, 0);
    assert.equal(failure.mutationAccounting.iamWriteAttempts, 0);
    assert.equal(failure.mutationAccounting.unknownMutations, 0);
    assert.deepEqual(failure.mutationAccounting.mutationOutcomes, []);
    assert.match(failure.failure.message, /pre-mutation read failed/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI failure output preserves confirmed mutation accounting after a later failure", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-cli-confirmed-failure-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const inputs = writeCliStageAInputs(directory);
  const fake = createPolicyVersionRunner({ onCreate: ({ documents, dates }) => {
    documents.set("v99", policy);
    dates.set("v99", "2026-01-07T00:00:00.000Z");
  } });
  try {
    const failure = runCliAndReadFailure(cliArgs({ stateFile, planJsonFile, ...inputs }), fake.run);
    assert.equal(failure.writes, 2);
    assert.equal(failure.mutationAccounting.policyVersionCreations, 1);
    assert.equal(failure.mutationAccounting.iamWrites, 2);
    assert.deepEqual(failure.capacityRecovery.deletedVersionIds, ["v4"]);
    assert.deepEqual(failure.capacityRecovery.createdVersionIds, ["v9"]);
    assert.equal(failure.failure.operation, "CreatePolicyVersion");
    assert.deepEqual(failure.failure.affectedVersionIds, ["v4", "v9"]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI failure output preserves unknown CreatePolicyVersion accounting and recovery metadata", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-cli-create-unknown-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const inputs = writeCliStageAInputs(directory);
  const fake = createPolicyVersionRunner({ failCreate: true });
  try {
    const failure = runCliAndReadFailure(cliArgs({ stateFile, planJsonFile, ...inputs }), fake.run);
    assert.equal(failure.writes, 1);
    assert.equal(failure.mutationAccounting.iamWriteAttempts, 2);
    assert.equal(failure.mutationAccounting.unknownMutations, 1);
    assert.deepEqual(failure.capacityRecovery.deletedVersionIds, ["v4"]);
    assert.equal(failure.failure.operation, "CreatePolicyVersion");
    assert.equal(failure.failure.mutationOutcome, "OUTCOME_UNKNOWN");
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI failure output preserves unknown DeletePolicyVersion accounting and affected versions", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-cli-delete-unknown-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) }, loseDeleteResponse: true });
  const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
  try {
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const terraformStateFile = path.join(directory, "terraform.tfstate");
    writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
    let deleteAccepted = false;
    const run = (args) => {
      if (args[1] === "delete-policy-version") { deleteAccepted = true; return fake.run(args); }
      if (deleteAccepted && args[1] === "get-policy") throw new Error("ambiguous delete recovery read");
      return fake.run(args);
    };
    const failure = runCliAndReadFailure(cliArgs({ phase: "revoke", stateFile }), run);
    assert.equal(failure.writes, 1);
    assert.equal(failure.mutationAccounting.iamWriteAttempts, 2);
    assert.equal(failure.mutationAccounting.unknownMutations, 1);
    assert.equal(failure.failure.operation, "DeletePolicyVersion");
    assert.equal(failure.failure.mutationOutcome, "OUTCOME_UNKNOWN");
    assert.deepEqual(failure.failure.affectedVersionIds, ["v2", "v3"]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI success output remains compatible while enforcing valid Stage-A private inputs", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-cli-success-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const inputs = writeCliStageAInputs(directory);
  const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
  let output = "";
  try {
    const result = runCli(cliArgs({ stateFile, planJsonFile, ...inputs }), { run: fake.run, write: (value) => { output += value; } });
    const success = JSON.parse(output);
    assert.deepEqual(Object.keys(success).sort(), ["evidenceSha256", "mutationAccounting", "state", "writes"].sort());
    assert.equal(success.state, "AUTHORIZED_FOR_ROOT_DROP_CREATION");
    assert.equal(success.writes, result.writes);
    assert.equal(success.mutationAccounting.iamWrites, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("CLI rejects every registered Stage-A private-input violation before AWS", () => {
  const cases = [
    ["repository-resident identity", (files) => { files.stageAStateIdentityFile = path.resolve("package.json"); }, /outside the repository/],
    ["repository-resident state", (files) => { files.stageAStateFile = path.resolve("package.json"); }, /outside the repository/],
    ["identity symlink", (files, directory) => { const link = path.join(directory, "identity-link"); symlinkSync(files.stageAStateIdentityFile, link); files.stageAStateIdentityFile = link; }, /regular non-symlink file/],
    ["state symlink", (files, directory) => { const link = path.join(directory, "state-link"); symlinkSync(files.stageAStateFile, link); files.stageAStateFile = link; }, /regular non-symlink file/],
    ["permissive identity mode", (files) => chmodSync(files.stageAStateIdentityFile, 0o644), /mode 0600/],
    ["permissive state mode", (files) => chmodSync(files.stageAStateFile, 0o644), /mode 0600/],
    ["non-private parent directory", (files, directory) => { chmodSync(directory, 0o755); }, /mode 0700/],
  ];
  for (const [, mutate, expected] of cases) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-cli-contract-"));
    const files = { ...writeCliStageAInputs(directory), stateFile: path.join(directory, "capability.json"), planJsonFile: writePlanFile(directory) };
    try {
      mutate(files, directory);
      const failure = runCliAndReadFailure(cliArgs(files), () => { throw new Error("AWS must not be called"); });
      assert.match(failure.failure.message, expected);
      assert.equal(failure.mutationAccounting.iamWriteAttempts, 0);
      assert.equal(failure.mutationAccounting.unknownMutations, 0);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("state identity binding rejects same metadata with changed bytes and each identity dimension", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-state-identity-dimensions-"));
  const stateFile = path.join(directory, "capability.json");
  const stageAStateFile = path.join(directory, "stage-a.tfstate");
  const planJsonFile = writePlanFile(directory);
  const state = { lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial: 44, resources: [] };
  const bytes = Buffer.from(JSON.stringify(state));
  writeFileSync(stageAStateFile, bytes, { mode: 0o600 });
  const identity = buildStageAStateIdentity(state, { stateBytes: bytes });
  const fixture = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) } });
  const mismatches = [
    { stateSha256: "f".repeat(64) },
    { stateObject: "wrong-stage-a.tfstate" },
    { lineage: "wrong-lineage" },
    { serial: 45 },
    { account: "000000000000" },
    { region: "us-east-1" },
  ];
  try {
    for (const mismatch of mismatches) assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fixture.run, requireStageAStateBinding: true }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile, stageAStateFile, stageAStateIdentity: { ...identity, ...mismatch } }), /state identity binding/);
    writeFileSync(stageAStateFile, JSON.stringify({ ...state, changed: true }), { mode: 0o600 });
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fixture.run, requireStageAStateBinding: true }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile: path.join(directory, "changed-capability.json"), planSha256, planJsonFile, stageAStateFile, stageAStateIdentity: identity }), /state identity binding/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("ambiguous CreatePolicyVersion response is never reported as zero IAM writes", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-unknown-mutation-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) }, failCreate: true });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fixture.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), (error) => error.mutationAccounting?.unknownMutations === 1 && error.mutationAccounting.iamWriteAttempts === 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("accepted CreatePolicyVersion with a lost response is recovered by exact readback", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-unknown-create-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) }, loseCreateResponse: true });
  try {
    const result = createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    assert.equal(result.mutationAccounting.iamWrites, 1);
    assert.equal(result.mutationAccounting.unknownMutations, 0);
    assert.equal(result.mutationAccounting.policyVersionCreations, 1);
    assert.equal(result.mutationAccounting.policyDefaultChanges, 1);
    assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 1);
    assert.deepEqual(result.mutationAccounting.mutationOutcomes, [{ action: "CreatePolicyVersion", outcome: "CONFIRMED_SUCCESS_READBACK" }]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("malformed CreatePolicyVersion responses recover one accepted mutation exactly once", () => {
  for (const response of [JSON.stringify({ PolicyVersion: {} }), JSON.stringify({ PolicyVersion: { VersionId: "invalid" } })]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-malformed-create-response-"));
    const stateFile = path.join(directory, "capability.json"); const planJsonFile = writePlanFile(directory);
    const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) }, createResponse: () => response, createResponseOn: 1 });
    try {
      const result = createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      assert.equal(result.mutationAccounting.iamWrites, 1); assert.equal(result.mutationAccounting.policyVersionCreations, 1); assert.equal(result.mutationAccounting.policyDefaultChanges, 1); assert.equal(result.mutationAccounting.unknownMutations, 0);
      assert.deepEqual(result.mutationAccounting.mutationOutcomes, [{ action: "CreatePolicyVersion", outcome: "CONFIRMED_SUCCESS_READBACK" }]);
      assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 1);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("malformed CreatePolicyVersion response with ambiguous readback remains unknown", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-malformed-create-ambiguous-"));
  const stateFile = path.join(directory, "capability.json"); const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) }, createResponse: () => JSON.stringify({ PolicyVersion: {} }), createResponseOn: 1, onCreate: ({ setDefaultVersionId }) => setDefaultVersionId("v1") });
  try {
    assert.throws(() => createTemporaryKmsCapabilityRunner({ run: fake.run }).runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile }), (error) => error.mutationAccounting?.unknownMutations === 1 && error.mutationAccounting.iamWriteAttempts === 1 && error.mutationAccounting.policyVersionCreations === 0 && error.mutationAccounting.policyDefaultChanges === 0);
    assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("lost revoke CreatePolicyVersion response uses the authenticated active default with duplicate steady history", () => {
  for (const versionIds of [["v1", "v3"], ["v1", "v3", "v5"]]) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-revoke-create-recovery-"));
    const stateFile = path.join(directory, "capability.json");
    const planJsonFile = writePlanFile(directory);
    const fixture = {
      defaultVersionId: "v1",
      documents: new Map(versionIds.map((versionId) => [versionId, policy])),
      dates: new Map(versionIds.map((versionId, index) => [versionId, `2026-01-0${index + 1}T00:00:00.000Z`])),
    };
    const fake = createPolicyVersionRunner({ fixture, loseCreateResponseOn: 2 });
    try {
      const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
      runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
      runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
      const terraformStateFile = path.join(directory, "terraform.tfstate");
      writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
      runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
      const result = runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile });
      assert.equal(result.evidence.state, "REVOKED");
      assert.equal(fake.defaultVersionId, `v${Math.max(...versionIds.map((id) => Number(id.slice(1)))) + 2}`);
      assert.equal(fake.documents.has(`v${Math.max(...versionIds.map((id) => Number(id.slice(1)))) + 1}`), false);
      assert.equal(fake.calls.filter((operation) => operation === "create-policy-version").length, 2);
      assert.equal(fake.calls.filter((operation) => operation === "delete-policy-version").length, 1);
      assert.equal(result.mutationAccounting.policyVersionCreations, 1);
      assert.equal(result.mutationAccounting.policyDefaultChanges, 1);
      assert.equal(result.mutationAccounting.mutationOutcomes.filter(({ action }) => action === "CreatePolicyVersion").length, 1);
      assert.ok(result.mutationAccounting.mutationOutcomes.some(({ action, outcome }) => action === "CreatePolicyVersion" && outcome === "CONFIRMED_SUCCESS_READBACK"));
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("lost revoke CreatePolicyVersion response fails closed when active default is not the intended steady state", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-revoke-create-mismatch-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = { defaultVersionId: "v1", documents: new Map([["v1", policy], ["v3", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v3", "2026-01-02T00:00:00.000Z"]]) };
  let createCount = 0;
  const fake = createPolicyVersionRunner({ fixture, loseCreateResponseOn: 2, onCreate: ({ versionId, documents }) => {
    createCount += 1;
    if (createCount === 2) documents.set(versionId, { ...policy, Statement: [...policy.Statement, { Effect: "Deny", Action: "kms:Sign", Resource: "*" }] });
  } });
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const terraformStateFile = path.join(directory, "terraform.tfstate");
    writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
    assert.throws(() => runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile }), (error) => error.mutationAccounting?.unknownMutations === 1 && error.mutationAccounting?.iamWriteAttempts === 1);
    assert.equal(fake.documents.has("v4"), true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("lost revoke CreatePolicyVersion response fails closed when active default identity is missing", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-revoke-create-identity-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fixture = { defaultVersionId: "v1", documents: new Map([["v1", policy], ["v3", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"], ["v3", "2026-01-02T00:00:00.000Z"]]) };
  let createCount = 0;
  const fake = createPolicyVersionRunner({ fixture, loseCreateResponseOn: 2, onCreate: ({ setDefaultVersionId }) => {
    createCount += 1;
    if (createCount === 2) setDefaultVersionId("v999");
  } });
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const terraformStateFile = path.join(directory, "terraform.tfstate");
    writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
    assert.throws(() => runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile }), (error) => error.mutationAccounting?.unknownMutations === 1 && error.mutationAccounting?.iamWriteAttempts === 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("accepted DeletePolicyVersion with a lost response is recovered by exact readback", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-temp-kms-unknown-delete-"));
  const stateFile = path.join(directory, "capability.json");
  const planJsonFile = writePlanFile(directory);
  const fake = createPolicyVersionRunner({ fixture: { defaultVersionId: "v1", documents: new Map([["v1", policy]]), dates: new Map([["v1", "2026-01-01T00:00:00.000Z"]]) }, loseDeleteResponse: true });
  try {
    const runner = createTemporaryKmsCapabilityRunner({ run: fake.run });
    runner.runPhase({ phase: "authorize", sourceSha, transitionId, stateFile, planSha256, planJsonFile });
    runner.runPhase({ phase: "mark-stage-a-apply", sourceSha, transitionId, stateFile, planSha256 });
    const terraformStateFile = path.join(directory, "terraform.tfstate");
    writeFileSync(terraformStateFile, JSON.stringify(stateFixture()), { mode: 0o600 });
    runner.runPhase({ phase: "mark-root-drop-owned", sourceSha, transitionId, stateFile, planSha256, terraformStateFile });
    const result = runner.runPhase({ phase: "revoke", sourceSha, transitionId, stateFile });
    assert.equal(result.mutationAccounting.unknownMutations, 0);
    assert.ok(result.mutationAccounting.mutationOutcomes.some(({ action, outcome }) => action === "DeletePolicyVersion" && outcome === "CONFIRMED_SUCCESS_READBACK"));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
