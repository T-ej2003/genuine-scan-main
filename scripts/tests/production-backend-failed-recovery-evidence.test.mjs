import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAuthenticatedFailedRecoveryEvidence, assertAuthenticatedFailedRecoveryEvidence } from "../aws/production-backend-failed-recovery-evidence.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { signRuntimeConsumabilityEvidence } from "../aws/production-ecs-runtime-consumability.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { prepareProductionBackendFailedRecoveryEvidence } from "../aws/prepare-production-backend-failed-recovery-evidence.mjs";
import { assertFailedRecoveryEvidenceReference } from "../aws/production-backend-failed-recovery-evidence-reference.mjs";
import { publishProductionBackendFailedRecoveryEvidence } from "../aws/publish-production-backend-failed-recovery-evidence.mjs";
import { resolveProductionBackendFailedRecoveryEvidence } from "../aws/resolve-production-backend-failed-recovery-evidence.mjs";
import { EMPTY_RECOVERY_HISTORY_LINEAGE_SHA256, RECOVERY_HISTORY_LINEAGE_PROJECTION_VERSION } from "../aws/production-backend-health-recovery-contract.mjs";

const sourceSha = "b64274e155434ae9390d28762d40a37801be5362";
const digest = `sha256:${"6".repeat(64)}`;
const currentArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const failedArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49";
const now = Date.parse("2026-08-24T18:02:00.000Z");
const bytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const rehash = (value) => ({ ...value, evidenceSha256: canonicalSha256(Object.fromEntries(Object.entries(value).filter(([key]) => key !== "evidenceSha256"))) });

function artifacts(overrides = {}) {
  const environment = createProductionEnvironmentApprovalEvidence({ repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRunId: "32759665989", workflowRunAttempt: "1", workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", eventName: "workflow_dispatch", executionActor: "operator", observedAt: "2026-08-24T18:00:00.000Z", environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "reviewer" } }] }] } });
  const environmentBytes = bytes(overrides.environment ? rehash({ ...environment, ...overrides.environment }) : environment);
  const runtimeBody = { schemaVersion: 1, kind: "PRODUCTION_ECS_RUNTIME_CONSUMABILITY", sourceSha, candidateFingerprint: "9".repeat(64), candidateCanonicalSha256: "8".repeat(64), dependencySha256: "7".repeat(64), dependencies: [], results: [], resourceMetadata: {}, livePolicyIdentity: {}, generatedAt: "2026-08-24T18:00:30.000Z", ...overrides.runtime };
  const runtime = signRuntimeConsumabilityEvidence({ ...runtimeBody, evidenceSha256: canonicalSha256(runtimeBody) }, { sign: () => "AQ==", signedAt: "2026-08-24T18:01:00.000Z" });
  const recoveryBody = { schemaVersion: 5, kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha, authorizationFileSha256: "a".repeat(64), authorizationSha256: "b".repeat(64), environmentApprovalFileSha256: hash(environmentBytes), environmentApprovalSha256: JSON.parse(environmentBytes).evidenceSha256, imageAuthorizationFileSha256: "c".repeat(64), imageAuthorizationSha256: "d".repeat(64), artifactSigningBindingSha256: "e".repeat(64), runtimeConsumabilitySha256: runtime.evidence.evidenceSha256, rollbackProofSha256: null, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest, imageReleaseSha: sourceSha, account: "368992683803", region: "eu-west-2", status: "SERVICE_STABILIZATION_FAILED", targetArn: failedArn, registrations: 1, updates: 1, artifactSigningVerification: "VERIFIED", artifactSigningFailure: null, knownFailedRevisions: [], generatedAt: "2026-08-24T18:01:30.000Z", ...overrides.recovery };
  return { recoveryEvidenceBytes: bytes({ ...recoveryBody, evidenceSha256: canonicalSha256(recoveryBody) }), environmentApprovalBytes: environmentBytes, runtimeConsumabilityBytes: bytes(runtime) };
}

function interruptedArtifacts(status, recovery = {}, overrides = {}) {
  const attempted = status === "TASK_DEFINITION_REGISTRATION_ATTEMPTED";
  return artifacts({ ...overrides, recovery: {
    schemaVersion: 6,
    status,
    targetArn: attempted ? null : failedArn,
    registrations: attempted ? 0 : 1,
    updates: status === "SERVICE_UPDATE_CONFIRMED" ? 1 : 0,
    candidateFingerprint: "9".repeat(64),
    initialRevisionCensusSha256: "1".repeat(64),
    expectedRevisionCensusSha256: attempted ? null : "2".repeat(64),
    ...recovery,
  } });
}

const create = (records = [artifacts()]) => createAuthenticatedFailedRecoveryEvidence({ records, verifyRuntime: () => true, sign: () => "AQ==", signedAt: new Date(now).toISOString() });
const verify = (envelope) => assertAuthenticatedFailedRecoveryEvidence(envelope, { verify: () => true, now });

class FakeEvidenceRelease {
  constructor(evidenceBytes, state = "ABSENT") {
    this.evidenceBytes = evidenceBytes;
    this.envelopeSha256 = JSON.parse(evidenceBytes).envelopeSha256;
    this.tag = `mscqr-backend-failed-recovery-evidence-${this.envelopeSha256}`;
    this.name = `backend-failed-recovery-evidence-${this.envelopeSha256}.json`;
    this.asset = { id: 202, name: this.name, state: "uploaded", size: evidenceBytes.length, digest: `sha256:${hash(evidenceBytes)}` };
    this.release = null;
    this.mutations = { create: 0, upload: 0, publish: 0 };
    this.failAfter = {};
    this.failRead = 0;
    this.concurrentAssetBeforeUpload = null;
    this.concurrentImmutableBeforePublish = false;
    this.setState(state);
  }

  setState(state) {
    if (state === "ABSENT") { this.release = null; return; }
    const ready = ["DRAFT_READY", "IMMUTABLE"].includes(state);
    this.release = { id: 101, immutable: state === "IMMUTABLE", draft: state !== "IMMUTABLE", tag_name: this.tag, target_commitish: sourceSha, name: this.tag, body: "KMS-authenticated MSCQR backend failed-recovery history.", assets: ready ? [structuredClone(this.asset)] : [] };
  }

  snapshot() { return structuredClone(this.release); }

  view() {
    const release = this.snapshot();
    return { databaseId: release.id, tagName: release.tag_name, targetCommitish: release.target_commitish, name: release.name, body: release.body, isDraft: release.draft, isImmutable: release.immutable, assets: release.assets.map((asset) => ({ ...asset, id: `node-${asset.id}`, apiUrl: `https://api.github.com/repos/T-ej2003/genuine-scan-main/releases/assets/${asset.id}` })) };
  }

  throwAfter(name) {
    if (this.failAfter[name]) { this.failAfter[name] -= 1; throw new Error(`${name} response lost`); }
  }

  run = (_command, args, options = {}) => {
    if (args[0] === "release" && args[1] === "view") {
      if (!this.release) { const error = new Error("release not found"); error.releaseNotFound = true; throw error; }
      if (this.concurrentImmutableBeforePublish && this.release.assets.length) { this.concurrentImmutableBeforePublish = false; this.release.draft = false; this.release.immutable = true; }
      return JSON.stringify(this.view());
    }
    if (args[0] === "api") {
      if (this.failRead) { this.failRead -= 1; throw new Error("transient readback failure"); }
      const endpoint = args[1];
      if (endpoint.endsWith(`/releases/${this.release?.id}`)) return JSON.stringify(this.snapshot());
      if (endpoint.endsWith(`/assets/${this.asset.id}`) && options.encoding === null) return Buffer.from(this.evidenceBytes);
      if (endpoint.endsWith(`/assets/${this.asset.id}`)) return JSON.stringify(this.asset);
      throw new Error(`unexpected endpoint ${endpoint}`);
    }
    if (args[0] !== "release") throw new Error(`unexpected command ${args.join(" ")}`);
    if (args[1] === "create") {
      if (this.release) throw new Error("release already exists");
      this.setState("DRAFT_EMPTY"); this.mutations.create += 1; this.throwAfter("create"); return "";
    }
    if (args[1] === "upload") {
      if (this.concurrentAssetBeforeUpload) { this.release.assets = [structuredClone(this.concurrentAssetBeforeUpload)]; throw new Error("asset already exists"); }
      this.release.assets = [structuredClone(this.asset)]; this.mutations.upload += 1; this.throwAfter("upload"); return "";
    }
    if (args[1] === "edit") {
      this.release.draft = false; this.release.immutable = true; this.mutations.publish += 1; this.throwAfter("publish"); return "";
    }
    throw new Error(`unexpected release command ${args.join(" ")}`);
  };
}

function publicationFixture(context, state = "ABSENT") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-failed-recovery-reference-")); fs.chmodSync(directory, 0o700);
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const evidenceBytes = bytes(create());
  const evidenceFile = path.join(directory, "evidence.json"); fs.writeFileSync(evidenceFile, evidenceBytes, { mode: 0o600 });
  return { directory, evidenceBytes, evidenceFile, evidenceFileSha256: hash(evidenceBytes), referenceFile: path.join(directory, "reference.json"), remote: new FakeEvidenceRelease(evidenceBytes, state) };
}

const publishFixture = (fixture, overrides = {}) => publishProductionBackendFailedRecoveryEvidence({ sourceSha, evidenceFile: fixture.evidenceFile, evidenceFileSha256: fixture.evidenceFileSha256, outputFile: fixture.referenceFile, protectedMain: () => {}, run: fixture.remote.run, ...overrides });

test("actual terminal evidence bytes derive the only trusted failed-revision summary", () => {
  const envelope = create(); const result = verify(envelope);
  assert.deepEqual(result.knownFailedRevisions.map(({ taskDefinitionArn, workflowRunId, status }) => ({ taskDefinitionArn, workflowRunId, status })), [{ taskDefinitionArn: failedArn, workflowRunId: "32759665989", status: "SERVICE_STABILIZATION_FAILED" }]);
  assert.equal(result.knownFailedRevisions[0].evidenceFileSha256, hash(artifacts().recoveryEvidenceBytes));
  assert.equal(result.recoveryHistory[0].predecessorHistoryReferenceSha256, null);
});

test("historical evidence count and bytes remain operationally bounded", () => {
  assert.throws(() => createAuthenticatedFailedRecoveryEvidence({ records: Array.from({ length: 33 }, () => artifacts()), verifyRuntime: () => true, sign: () => "AQ==", signedAt: new Date(now).toISOString() }), /bounded history limit/);
  const oversized = { ...structuredClone(create()), padding: "x".repeat(8 * 1024 * 1024) };
  assert.throws(() => verify(oversized), /signature|stale|tampered/);
});

test("authenticated records preserve ordered predecessor reference and census continuity", () => {
  const first = interruptedArtifacts("SERVICE_UPDATE_CONFIRMED");
  const firstResult = verify(create([first]));
  const legacyFirst = { ...firstResult.recoveryHistory[0] }; delete legacyFirst.imageReleaseSha;
  const predecessorHistoryLineageSha256 = canonicalSha256({ predecessorLineageSha256: EMPTY_RECOVERY_HISTORY_LINEAGE_SHA256, record: legacyFirst });
  assert.equal(RECOVERY_HISTORY_LINEAGE_PROJECTION_VERSION, 1);
  assert.equal(firstResult.lineageSha256, predecessorHistoryLineageSha256);
  assert.equal(firstResult.interruptedRecoveries[0].imageReleaseSha, sourceSha);
  const second = interruptedArtifacts("SERVICE_UPDATE_CONFIRMED", {
    schemaVersion: 7,
    currentTaskDefinitionArn: failedArn,
    targetArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50",
    failedRecoveryEvidenceReferenceSha256: "f".repeat(64),
    initialRevisionCensusSha256: "2".repeat(64),
    expectedRevisionCensusSha256: "3".repeat(64),
    candidateFingerprint: "8".repeat(64),
    predecessorHistoryLineageSha256,
  }, { environment: { workflowRunId: "32759665990" }, runtime: { candidateFingerprint: "8".repeat(64) } });
  const result = verify(create([first, second]));
  assert.equal(result.recoveryHistory[1].imageReleaseSha, sourceSha);
  assert.equal(result.lineageSha256, verify(create([first, second])).lineageSha256);
  assert.deepEqual(result.recoveryHistory.map(({ predecessorHistoryReferenceSha256 }) => predecessorHistoryReferenceSha256), [null, "f".repeat(64)]);
  assert.throws(() => create([second]), /predecessor reference chain/);
  assert.throws(() => create([second, first]), /predecessor reference chain|reordered/);
  const forked = interruptedArtifacts("SERVICE_UPDATE_CONFIRMED", {
    schemaVersion: 7,
    currentTaskDefinitionArn: failedArn,
    targetArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50",
    failedRecoveryEvidenceReferenceSha256: "f".repeat(64),
    initialRevisionCensusSha256: "4".repeat(64),
    expectedRevisionCensusSha256: "5".repeat(64),
    candidateFingerprint: "8".repeat(64),
    predecessorHistoryLineageSha256: "0".repeat(64),
  }, { environment: { workflowRunId: "32759665990" }, runtime: { candidateFingerprint: "8".repeat(64) } });
  assert.throws(() => create([first, forked]), /census lineage/);
});

test("image release identity remains authenticated outside the stable lineage projection", () => {
  const envelope = structuredClone(create([interruptedArtifacts("SERVICE_UPDATE_CONFIRMED")]));
  const component = envelope.records[0].recoveryEvidence;
  const evidence = JSON.parse(Buffer.from(component.bytesBase64, "base64"));
  evidence.imageReleaseSha = "a".repeat(40);
  const changed = bytes(evidence);
  component.bytesBase64 = changed.toString("base64"); component.byteSha256 = hash(changed);
  assert.throws(() => verify(envelope), /signature|tampered/);
});

test("every governed terminal mutation combination is admitted and impossible counts fail closed", () => {
  const validCounts = [[1, 1], [0, 1], [0, 0], [1, 0]];
  const terminalStatuses = ["SERVICE_STABILIZATION_FAILED", "RUNNING_DIGEST_VERIFICATION_FAILED", "HEALTH_VERIFICATION_FAILED"];
  for (const [registrations, updates] of validCounts) {
    for (const status of terminalStatuses) {
      const result = verify(create([artifacts({ recovery: { registrations, updates, status } })]));
      assert.deepEqual([result.knownFailedRevisions[0].registrations, result.knownFailedRevisions[0].updates], [registrations, updates]);
    }
  }
  for (const [registrations, updates] of [[-1, 0], [0, -1], [2, 0], [0, 2], [1.5, 1], ["1", 1]]) {
    assert.throws(() => create([artifacts({ recovery: { registrations, updates } })]), /terminal failed recovery|malformed/);
  }
});

test("immutable historical failure facts remain verifiable beyond transient workflow retention", () => {
  const signedAt = "2026-01-01T00:00:00.000Z";
  const envelope = createAuthenticatedFailedRecoveryEvidence({ records: [artifacts()], verifyRuntime: () => true, sign: () => "AQ==", signedAt });
  assert.equal(assertAuthenticatedFailedRecoveryEvidence(envelope, { verify: () => true, now: Date.parse("2027-01-01T00:00:00.000Z") }).knownFailedRevisions.length, 1);
});

test("forged summaries, byte mutation, malformed evidence, and missing evidence fail closed", () => {
  const envelope = structuredClone(create());
  for (const mutate of [
    (value) => { value.records[0].recoveryEvidence.byteSha256 = "0".repeat(64); },
    (value) => { value.records[0].recoveryEvidence.bytesBase64 = Buffer.from("{}").toString("base64"); },
    (value) => { value.records = []; },
    (value) => { value.records[0].workflowRunId = "1"; },
  ]) { const changed = structuredClone(envelope); mutate(changed); assert.throws(() => verify(changed), /invalid|tampered|malformed|hash|record/i); }
});

test("every historical transaction binding and terminal status is authenticated", () => {
  const cases = [
    { environment: { repository: "other/repository" } },
    { recovery: { sourceSha: "a".repeat(40) } },
    { recovery: { kind: "OTHER_MODE" } },
    { runtime: { candidateFingerprint: "bad" } },
    { recovery: { status: "RECOVERY_COMPLETE", backendHealthy: true } },
  ];
  for (const changed of cases) assert.throws(() => create([artifacts(changed)]), /evidence|terminal|invalid|different|malformed|tampered/i);
});

test("signed mutation interruptions remain distinct from terminal failed revisions", () => {
  for (const status of ["TASK_DEFINITION_REGISTRATION_ATTEMPTED", "TASK_DEFINITION_REGISTERED_ONLY", "SERVICE_UPDATE_ATTEMPTED", "SERVICE_UPDATE_CONFIRMED"]) {
    const result = verify(create([interruptedArtifacts(status)]));
    assert.equal(result.knownFailedRevisions.length, 0);
    assert.equal(result.interruptedRecoveries[0].status, status);
    assert.equal(result.interruptedRecoveries[0].classification, "INTERRUPTED_MUTATION");
    assert.equal(result.interruptedRecoveries[0].imageReleaseSha, sourceSha);
  }
  assert.throws(() => create([interruptedArtifacts("SERVICE_UPDATE_CONFIRMED", { imageReleaseSha: undefined })]), /release|malformed/);
  assert.equal(verify(create([interruptedArtifacts("SERVICE_UPDATE_CONFIRMED", { imageReleaseSha: "a".repeat(40) })])).interruptedRecoveries[0].imageReleaseSha, "a".repeat(40));
  assert.throws(() => create([interruptedArtifacts("SERVICE_UPDATE_CONFIRMED", { expectedRevisionCensusSha256: null })]), /crash-reconcilable|census|malformed/);
});

test("duplicate or conflicting evidence for one task definition is rejected", () => {
  const second = artifacts({ environment: { workflowRunId: "32759665990" } });
  assert.throws(() => create([artifacts(), artifacts()]), /duplicated|conflicting|predecessor/);
  assert.throws(() => create([artifacts(), second]), /duplicated|conflicting|predecessor/);
  assert.throws(() => create([interruptedArtifacts("TASK_DEFINITION_REGISTRATION_ATTEMPTED"), interruptedArtifacts("TASK_DEFINITION_REGISTRATION_ATTEMPTED", {}, { environment: { workflowRunId: "32759665990" } })]), /duplicated|conflicting|predecessor/);
});

test("a healthy newer revision cannot be admitted by a caller-authored summary", () => {
  const forged = { taskDefinitionArn: failedArn, taskDefinitionFingerprint: "9".repeat(64), evidenceSha256: "f".repeat(64), status: "SERVICE_STABILIZATION_FAILED" };
  assert.throws(() => verify(forged), /signature|tampered/);
});

test("canonical producer persists the exact self-contained evidence bundle", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-failed-recovery-evidence-")); fs.chmodSync(directory, 0o700);
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = artifacts(); const files = {};
  for (const [name, value] of Object.entries(input)) { const file = path.join(directory, `${name}.json`); fs.writeFileSync(file, value, { mode: 0o600 }); files[name] = { file, sha256: hash(value) }; }
  const manifest = { schemaVersion: 1, records: [{ recoveryEvidence: files.recoveryEvidenceBytes, environmentApproval: files.environmentApprovalBytes, runtimeConsumability: files.runtimeConsumabilityBytes }] };
  const manifestFile = path.join(directory, "manifest.json"); const manifestBytes = bytes(manifest); fs.writeFileSync(manifestFile, manifestBytes, { mode: 0o600 });
  const outputFile = path.join(directory, "bundle.json");
  const result = prepareProductionBackendFailedRecoveryEvidence({ sourceSha, manifestFile, manifestSha256: hash(manifestBytes), outputFile, now, protectedMain: () => {}, run: (_command, args) => JSON.stringify(args[1] === "verify" ? { SignatureValid: true } : { Signature: "AQ==" }) });
  const persisted = JSON.parse(fs.readFileSync(outputFile));
  assert.equal(result.envelopeSha256, persisted.envelopeSha256);
  assert.equal(verify(persisted).knownFailedRevisions[0].taskDefinitionArn, failedArn);
});

test("publication creates, authenticates, resolves, and reuses one immutable release", (context) => {
  const fixture = publicationFixture(context);
  const published = publishFixture(fixture);
  assert.deepEqual(fixture.remote.mutations, { create: 1, upload: 1, publish: 1 });
  const referenceBytes = fs.readFileSync(fixture.referenceFile); const reference = JSON.parse(referenceBytes);
  assert.equal(published.referenceSha256, reference.referenceSha256);
  assert.equal(reference.assetSize, fixture.evidenceBytes.length);
  assert.ok(referenceBytes.length < fixture.evidenceBytes.length, "dispatch reference must remain bounded as history grows");
  const reused = publishFixture(fixture);
  assert.equal(reused.referenceSha256, published.referenceSha256);
  assert.equal(reused.mutationCount, 0);
  assert.deepEqual(fixture.remote.mutations, { create: 1, upload: 1, publish: 1 });

  const resolvedFile = path.join(fixture.directory, "resolved.json");
  const resolved = resolveProductionBackendFailedRecoveryEvidence({ sourceSha, referenceFile: fixture.referenceFile, referenceFileSha256: hash(referenceBytes), outputFile: resolvedFile, run: fixture.remote.run });
  assert.equal(resolved.referenceSha256, reference.referenceSha256);
  assert.deepEqual(fs.readFileSync(resolvedFile), fixture.evidenceBytes);
  assert.equal(verify(JSON.parse(fs.readFileSync(resolvedFile))).knownFailedRevisions[0].taskDefinitionArn, failedArn);

  const tampered = Buffer.from(fixture.evidenceBytes); tampered[tampered.length - 2] ^= 1;
  assert.throws(() => assertFailedRecoveryEvidenceReference(reference, { sourceSha, evidenceBytes: tampered }), /do not match/);
});

test("every remote partial-success state resumes without replacing evidence", (context) => {
  for (const [state, expectedMutations] of [["DRAFT_EMPTY", { create: 0, upload: 1, publish: 1 }], ["DRAFT_READY", { create: 0, upload: 0, publish: 1 }], ["IMMUTABLE", { create: 0, upload: 0, publish: 0 }]]) {
    const fixture = publicationFixture(context, state);
    const result = publishFixture(fixture);
    assert.equal(result.referenceSha256, JSON.parse(fs.readFileSync(fixture.referenceFile)).referenceSha256);
    assert.deepEqual(fixture.remote.mutations, expectedMutations);
  }
});

test("remote success followed by local reference failure is recoverable without remote mutation", (context) => {
  const fixture = publicationFixture(context);
  assert.throws(() => publishFixture(fixture, { writeReference: () => { throw new Error("local persistence failed"); } }), /local persistence failed/);
  assert.deepEqual(fixture.remote.mutations, { create: 1, upload: 1, publish: 1 });
  const recovered = publishFixture(fixture);
  assert.equal(recovered.mutationCount, 0);
  assert.ok(fs.existsSync(fixture.referenceFile));
  assert.deepEqual(fixture.remote.mutations, { create: 1, upload: 1, publish: 1 });
});

test("response-loss failures after each remote mutation converge on retry", (context) => {
  for (const step of ["create", "upload", "publish"]) {
    const fixture = publicationFixture(context); fixture.remote.failAfter[step] = 1;
    assert.throws(() => publishFixture(fixture), /response lost/);
    const recovered = publishFixture(fixture);
    assert.equal(recovered.referenceSha256, JSON.parse(fs.readFileSync(fixture.referenceFile)).referenceSha256);
    assert.deepEqual(fixture.remote.mutations, { create: 1, upload: 1, publish: 1 });
  }
});

test("failure before release creation leaves no remote residue and retry starts cleanly", (context) => {
  const fixture = publicationFixture(context); const original = fixture.remote.run; let rejectCreate = true;
  fixture.remote.run = (...args) => {
    if (rejectCreate && args[1][0] === "release" && args[1][1] === "create") throw new Error("create rejected before mutation");
    return original(...args);
  };
  assert.throws(() => publishFixture(fixture), /create rejected/);
  assert.equal(fixture.remote.release, null);
  assert.deepEqual(fixture.remote.mutations, { create: 0, upload: 0, publish: 0 });
  rejectCreate = false;
  assert.equal(publishFixture(fixture).mutationCount, 3);
});

test("transient final immutable readback failure preserves a retryable remote success", (context) => {
  const fixture = publicationFixture(context, "DRAFT_READY");
  const original = fixture.remote.run; let publishSeen = false;
  fixture.remote.run = (...args) => {
    const result = original(...args);
    if (args[1][0] === "release" && args[1][1] === "edit") { publishSeen = true; fixture.remote.failRead = 1; }
    return result;
  };
  assert.throws(() => publishFixture(fixture), /transient readback/);
  assert.equal(publishSeen, true);
  fixture.remote.run = original;
  assert.equal(publishFixture(fixture).mutationCount, 0);
});

test("conflicting release and asset states always fail without mutation", (context) => {
  const cases = [
    (remote) => { remote.release.target_commitish = "a".repeat(40); },
    (remote) => { remote.release.tag_name = `${remote.tag}-other`; },
    (remote) => { remote.release.name = "other"; },
    (remote) => { remote.release.body = "other"; },
    (remote) => { remote.asset.digest = `sha256:${"0".repeat(64)}`; remote.release.assets = [structuredClone(remote.asset)]; },
    (remote) => { remote.asset.size += 1; remote.release.assets = [structuredClone(remote.asset)]; },
    (remote) => { remote.release.assets.push({ ...remote.asset, id: 203 }); },
    (remote) => { remote.release.assets.push({ id: 204, name: "unrelated", state: "uploaded", size: 1, digest: `sha256:${"1".repeat(64)}` }); },
    (remote) => { remote.release.immutable = false; remote.release.draft = false; },
  ];
  for (const [index, mutate] of cases.entries()) {
    const fixture = publicationFixture(context, "IMMUTABLE"); mutate(fixture.remote);
    assert.throws(() => publishFixture(fixture, { outputFile: path.join(fixture.directory, `conflict-${index}.json`) }), /conflict|immutable|reconciled/i);
    assert.deepEqual(fixture.remote.mutations, { create: 0, upload: 0, publish: 0 });
  }
});

test("wrong downloaded bytes, malformed readback, and missing release fail closed", (context) => {
  const wrongBytes = publicationFixture(context, "IMMUTABLE"); wrongBytes.remote.evidenceBytes = Buffer.from("{}");
  assert.throws(() => publishFixture(wrongBytes), /bytes conflict/);
  const malformed = publicationFixture(context, "IMMUTABLE"); malformed.remote.run = () => "not-json";
  assert.throws(() => publishFixture(malformed), /malformed/);
  const unavailable = publicationFixture(context); unavailable.remote.run = () => { throw new Error("network unavailable"); };
  assert.throws(() => publishFixture(unavailable), /network unavailable/);
});

test("concurrent release or asset changes are rejected at the mutation boundary", (context) => {
  const appeared = publicationFixture(context); let reads = 0; const original = appeared.remote.run;
  appeared.remote.run = (...args) => {
    if (args[1][0] === "release" && args[1][1] === "view" && ++reads === 2) appeared.remote.setState("DRAFT_EMPTY");
    return original(...args);
  };
  assert.throws(() => publishFixture(appeared), /changed concurrently/);
  assert.deepEqual(appeared.remote.mutations, { create: 0, upload: 0, publish: 0 });

  const replaced = publicationFixture(context, "DRAFT_EMPTY"); let replacementReads = 0; const replacedRun = replaced.remote.run;
  replaced.remote.run = (...args) => {
    if (args[1][0] === "release" && args[1][1] === "view" && ++replacementReads === 2) replaced.remote.release.id = 999;
    return replacedRun(...args);
  };
  assert.throws(() => publishFixture(replaced), /changed concurrently/);
  assert.deepEqual(replaced.remote.mutations, { create: 0, upload: 0, publish: 0 });

  const assetRace = publicationFixture(context, "DRAFT_EMPTY"); assetRace.remote.concurrentAssetBeforeUpload = { ...assetRace.remote.asset, digest: `sha256:${"0".repeat(64)}` };
  assert.throws(() => publishFixture(assetRace), /asset already exists/);
  assert.throws(() => publishFixture(assetRace), /conflict/);
  assert.deepEqual(assetRace.remote.mutations, { create: 0, upload: 0, publish: 0 });

  const immutableRace = publicationFixture(context, "DRAFT_READY"); immutableRace.remote.concurrentImmutableBeforePublish = true;
  assert.equal(publishFixture(immutableRace).mutationCount, 0);
  assert.deepEqual(immutableRace.remote.mutations, { create: 0, upload: 0, publish: 0 });
});
