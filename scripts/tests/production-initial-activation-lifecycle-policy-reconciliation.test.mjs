import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INITIAL_ACTIVATION_POLICY_RECONCILIATION as CONTRACT, assertInitialActivationLifecyclePolicyReconciliationAuthorization, assertInitialActivationLifecyclePolicyState, buildInitialActivationLifecyclePolicyReconciliationResult, createInitialActivationLifecyclePolicyReconciliationAuthorization, createInitialActivationLifecyclePolicyReservation, createInitialActivationLifecyclePolicyReservationStore, executeInitialActivationLifecyclePolicyReconciliation as executeCore, initialActivationLifecyclePolicyReservationKey, readInitialActivationLifecycleDesiredPolicy, resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact, waitForInitialActivationLifecyclePolicyConvergence } from "../aws/production-initial-activation-policy-reconciliation.mjs";
import { readInitialActivationLifecyclePolicyLiveState, runInitialActivationLifecyclePolicyReconciliation } from "../aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs";
import { writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";
import { canonicalJson, canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { sourcePolicyEvidence } from "../aws/validate-production-green-stage-b-permissions.mjs";

const sourceSha = "a".repeat(40);
const desired = readInitialActivationLifecycleDesiredPolicy();
const predecessor = { Version: "2012-10-17", Statement: desired.document.Statement.slice(0, 4).concat(desired.document.Statement.slice(8)) };
const approval = (observedAt = new Date().toISOString()) => createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] },
  repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha,
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/authorize-production-initial-activation-lifecycle-policy-reconciliation.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "1", workflowRunAttempt: "1", executionActor: "operator", observedAt,
});
const releaseRolePolicyArns = sourcePolicyEvidence().map(({ arn }) => arn).sort();
const state = (overrides = {}) => ({ policyArn: CONTRACT.policyArn, defaultVersionId: "v1", document: predecessor, policyVersionCount: 1, releaseRolePolicyArns, targetPolicyRoles: ["mscqr-production-release-deployer"], targetPolicyUsers: [], targetPolicyGroups: [], permissionsBoundaryUsageCount: 0, ...overrides });
const authorization = (live = state()) => createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: live, protectedEnvironmentApprovalEvidence: approval(), desired });
const executeInitialActivationLifecyclePolicyReconciliation = (input) => executeCore({ reserve: () => ({ owned: true }), ...input });

test("exact predecessor authorizes only the fixed target and exact tracked desired policy", () => {
  const value = authorization();
  assert.equal(value.expectedAction, "iam:CreatePolicyVersion"); assert.equal(value.setAsDefault, true);
  assert.deepEqual([value.maxCreatePolicyVersionCount, value.maxSetDefaultPolicyVersionCount, value.maxDeletePolicyVersionCount, value.maxPolicyAttachmentMutations], [1, 0, 0, 0]);
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha }));
  for (const changed of [{ sourceSha: "b".repeat(40) }, { targetPolicyArn: "arn:aws:iam::368992683803:policy/other" }, { predecessorDefaultVersionId: "v2" }, { predecessorPolicySha256: "b".repeat(64) }, { desiredPolicySha256: "b".repeat(64) }, { expectedAction: "iam:SetDefaultPolicyVersion" }, { setAsDefault: false }, { maxDeletePolicyVersionCount: 1 }]) {
    const candidate = { ...value, ...changed }; const { authorizationSha256, ...body } = candidate; candidate.authorizationSha256 = canonicalSha256(body);
    assert.throws(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(candidate, { sourceSha }), /authorization/);
  }
});

test("live policy validation keeps the complete release-role set separate from the target policy entity boundary", () => {
  assert.equal(assertInitialActivationLifecyclePolicyState(state(), { desired }).status, "AUTHENTICATED_PREDECESSOR");
  assert.equal(assertInitialActivationLifecyclePolicyState(state({ document: desired.document, defaultVersionId: "v2" }), { desired }).status, "ALREADY_RECONCILED");
  for (const changed of [
    { policyArn: "arn:aws:iam::368992683803:policy/unrelated" }, { defaultVersionId: "v2" },
    { document: { ...predecessor, Statement: [...predecessor.Statement, { Sid: "extra", Effect: "Allow", Action: "*", Resource: "*" }] } },
    { document: "not-json" }, { releaseRolePolicyArns: releaseRolePolicyArns.slice(1) }, { releaseRolePolicyArns: [...releaseRolePolicyArns, "arn:aws:iam::368992683803:policy/other"] }, { targetPolicyRoles: [] }, { targetPolicyRoles: ["mscqr-production-release-deployer", "other-role"] }, { targetPolicyUsers: ["other-user"] }, { targetPolicyGroups: ["other-group"] }, { permissionsBoundaryUsageCount: 1 },
  ]) assert.throws(() => assertInitialActivationLifecyclePolicyState(state(changed), { desired }));
  assert.throws(() => createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state({ policyVersionCount: 5 }), protectedEnvironmentApprovalEvidence: approval(), desired }), /pruning/);
  assert.throws(() => createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(), desired: { ...desired, policySha256: "b".repeat(64) } }));
});

test("policy-centric entity discovery consumes every page and fails closed on incomplete evidence", () => {
  const run = (args) => {
    const operation = args.slice(0, 2).join(" "); const marker = args.includes("--marker") ? args.at(-1) : undefined;
    if (operation === "iam get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: "v1", PermissionsBoundaryUsageCount: 0 } });
    if (operation === "iam get-policy-version") return JSON.stringify({ PolicyVersion: { Document: predecessor } });
    if (operation === "iam list-policy-versions") return JSON.stringify({ Versions: [{ VersionId: "v1" }] });
    if (operation === "iam get-role") return JSON.stringify({ Role: { Arn: CONTRACT.releaseRoleArn } });
    if (operation === "iam list-attached-role-policies") return JSON.stringify(marker ? { AttachedPolicies: releaseRolePolicyArns.slice(4).map((PolicyArn) => ({ PolicyArn })), IsTruncated: false } : { AttachedPolicies: releaseRolePolicyArns.slice(0, 4).map((PolicyArn) => ({ PolicyArn })), IsTruncated: true, Marker: "attached-next" });
    if (operation === "iam list-entities-for-policy") return JSON.stringify(marker ? { PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false } : { PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: true, Marker: "entities-next" });
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.equal(assertInitialActivationLifecyclePolicyState(readInitialActivationLifecyclePolicyLiveState(run), { desired }).status, "AUTHENTICATED_PREDECESSOR");
  const incomplete = (args) => args[1] === "list-entities-for-policy" ? JSON.stringify({ PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: true }) : run(args);
  assert.throws(() => readInitialActivationLifecyclePolicyLiveState(incomplete), /incomplete/);
});

test("approval freshness uses a fresh write-boundary clock after live reads", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const entryTime = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs - 1);
  const writeTime = new Date(entryTime.getTime() + 2);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: entryTime });
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now: entryTime }));
  let clockReads = 0; let liveReads = 0; let creates = 0;
  assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, now: () => { if (clockReads === 1) assert.equal(liveReads, 2, "clock must be read after the final live-state read"); return [entryTime, writeTime][clockReads++]; }, readLiveState: () => { liveReads += 1; return state(); }, createPolicyVersion: () => { creates += 1; } }), /stale/);
  assert.equal(clockReads, 2); assert.equal(liveReads, 2); assert.equal(creates, 0);
});

test("approval valid at the write boundary permits exactly one transition", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const entryTime = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs - 1);
  const writeTime = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: entryTime });
  let live = state(); let clockReads = 0; let creates = 0;
  const result = executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, now: () => [entryTime, writeTime][clockReads++], readLiveState: () => live, createPolicyVersion: () => { creates += 1; live = state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }); return { PolicyVersion: { VersionId: "v2" } }; } });
  assert.equal(result.status, "RECONCILED"); assert.equal(clockReads, 2); assert.equal(creates, 1);
});

test("approval freshness remains exact at the configured maximum age", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const boundary = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: boundary });
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now: boundary }));
});

test("result destination is fully preflighted before entering the mutation executor", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "initial-activation-result-preflight-")); fs.chmodSync(directory, 0o700);
  const auth = authorization(); let executorCalls = 0;
  const deps = { readProtectedCheckout: () => ({ toolingSha: sourceSha }), run: () => JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" }), resolveAuthorizationArtifact: () => ({ authorization: auth }), executeReconciliation: () => { executorCalls += 1; return { status: "ALREADY_RECONCILED", createPolicyVersionCount: 0, postState: assertInitialActivationLifecyclePolicyState(state({ document: desired.document, defaultVersionId: "v2" }), { desired }) }; } };
  const baseArgs = (resultOut) => ["--execute", "--source-sha", sourceSha, "--admin-profile", "root", "--workflow-run-id", "1", "--workflow-run-attempt", "1", ...(resultOut === undefined ? [] : ["--result-out", resultOut])];
  const invoke = (args) => runInitialActivationLifecyclePolicyReconciliation(args, deps);
  for (const [index, args] of [baseArgs(undefined), baseArgs(""), baseArgs(path.join(directory, "missing", "result.json")), baseArgs(process.cwd()), baseArgs(path.join(directory, "insecure", "result.json")), baseArgs(path.join(directory, "existing.json")), baseArgs(path.join(directory, "result-link.json")), baseArgs(path.join(process.cwd(), "..", path.basename(process.cwd()), "escaped.json")), baseArgs(path.join(directory, "unwritable", "result.json"))].entries()) {
    if (args.some((arg) => arg.endsWith("/insecure/result.json"))) { fs.mkdirSync(path.join(directory, "insecure")); fs.chmodSync(path.join(directory, "insecure"), 0o755); }
    if (args.some((arg) => arg.endsWith("/existing.json"))) fs.writeFileSync(path.join(directory, "existing.json"), "existing");
    if (args.some((arg) => arg.endsWith("/result-link.json"))) fs.symlinkSync(path.join(directory, "other.json"), path.join(directory, "result-link.json"));
    if (args.some((arg) => arg.endsWith("/unwritable/result.json"))) { fs.mkdirSync(path.join(directory, "unwritable")); fs.chmodSync(path.join(directory, "unwritable"), 0o500); }
    assert.throws(() => invoke(args), undefined, `invalid result destination case ${index}`);
  }
  assert.equal(executorCalls, 0);
  const valid = path.join(directory, "valid", "result.json"); fs.mkdirSync(path.dirname(valid)); fs.chmodSync(path.dirname(valid), 0o700);
  assert.doesNotThrow(() => invoke(baseArgs(valid))); assert.equal(executorCalls, 1); assert.equal(fs.existsSync(valid), true);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("the final exclusive result writer still rejects a target created after preflight", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "initial-activation-result-race-")); fs.chmodSync(directory, 0o700);
  const result = path.join(directory, "result.json"); fs.writeFileSync(result, "race", { mode: 0o600 });
  assert.throws(() => writeStageBPrivateFileExclusive({ filePath: result, bytes: Buffer.from("new"), repositoryRoot: process.cwd(), label: "Initial activation lifecycle policy result" }));
  fs.rmSync(directory, { recursive: true, force: true });
});

test("one atomic CreatePolicyVersion transitions the exact predecessor and preserves both attachment boundaries", () => {
  let live = state(); let creates = 0;
  const result = executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => live, createPolicyVersion: (request) => {
    creates += 1; assert.deepEqual(request, { PolicyArn: CONTRACT.policyArn, PolicyDocument: desired.document, SetAsDefault: true });
    live = state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }); return { PolicyVersion: { VersionId: "v2" } };
  } });
  assert.equal(result.status, "RECONCILED"); assert.equal(result.createPolicyVersionCount, 1); assert.equal(creates, 1);
  const replay = executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => live, createPolicyVersion: () => { creates += 1; throw new Error("must not create"); } });
  assert.equal(replay.status, "ALREADY_RECONCILED"); assert.equal(replay.createPolicyVersionCount, 0); assert.equal(creates, 1);
  const completion = buildInitialActivationLifecyclePolicyReconciliationResult({ authorization: authorization(), outcome: result });
  assert.equal(completion.postPolicySha256, desired.policySha256);
});

test("execution rejects every non-equivalent pre or post mutation state and never targets another policy", () => {
  const cases = [
    { name: "wrong source", source: "b".repeat(40), live: state(), matcher: /identity/ },
    { name: "unexpected pre drift", source: sourceSha, live: state({ document: { ...predecessor, Statement: [] } }), matcher: /neither/ },
    { name: "wrong version", source: sourceSha, live: state({ defaultVersionId: "v2" }), matcher: /neither/ },
    { name: "wrong policy arn", source: sourceSha, live: state({ policyArn: "arn:aws:iam::368992683803:policy/nope" }), matcher: /identity/ },
  ];
  for (const item of cases) assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha: item.source, desired, readLiveState: () => item.live, createPolicyVersion: () => { throw new Error("write prohibited"); } }), item.matcher);
  for (const after of [
    state({ defaultVersionId: "v1", document: desired.document, policyVersionCount: 2 }),
    state({ defaultVersionId: "v2", document: predecessor, policyVersionCount: 2 }),
    state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2, targetPolicyRoles: ["mscqr-production-release-deployer", "other-role"] }),
  ]) {
    let reads = 0;
    assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => (++reads === 1 ? state() : after), createPolicyVersion: () => ({ PolicyVersion: { VersionId: "v2" } }) }));
  }
});

test("ambiguous successful create converges by exact desired readback without a second version", () => {
  let live = state(); let creates = 0;
  const outcome = executeInitialActivationLifecyclePolicyReconciliation({ authorization: authorization(), sourceSha, desired, readLiveState: () => live, createPolicyVersion: () => {
    creates += 1; live = state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 }); throw new Error("transport response lost");
  } });
  assert.equal(outcome.status, "COMPLETED_BY_READBACK"); assert.equal(outcome.createPolicyVersionCount, 1); assert.equal(creates, 1);
});

function reservationMemoryS3() {
  const objects = new Map(); const calls = []; let conflictNext = false; let conflictObject;
  const run = (args) => {
    calls.push([...args]); const operation = args[1]; const key = args[args.indexOf("--key") + 1];
    if (operation === "get-object") {
      if (!objects.has(key)) { const error = new Error("AccessDenied"); error.stderr = "NoSuchKey"; throw error; }
      fs.writeFileSync(args.at(-1), objects.get(key)); return "{}";
    }
    if (operation === "put-object") {
      assert.equal(args[args.indexOf("--if-none-match") + 1], "*");
      if (conflictNext || objects.has(key)) { if (conflictNext && conflictObject) objects.set(key, conflictObject); conflictNext = false; conflictObject = undefined; const error = new Error("PreconditionFailed"); error.stderr = "PreconditionFailed"; throw error; }
      objects.set(key, fs.readFileSync(args[args.indexOf("--body") + 1])); return "{}";
    }
    throw new Error(`unexpected S3 operation ${operation}`);
  };
  return { run, objects, calls, conflict(bytes) { conflictNext = true; conflictObject = bytes; } };
}

const reservationInput = () => ({ sourceSha, authorizationSha256: authorization().authorizationSha256, predecessorDefaultVersionId: CONTRACT.predecessorVersionId, predecessorPolicySha256: CONTRACT.predecessorPolicySha256, desiredPolicySha256: CONTRACT.desiredPolicySha256 });

test("reservation is exact-key, conditional, immutable, and matching replay-safe", () => {
  const s3 = reservationMemoryS3(); const store = createInitialActivationLifecyclePolicyReservationStore({ run: s3.run }); const identity = reservationInput();
  const first = store.reserve(identity); assert.equal(first.owned, true); assert.equal(first.created, true);
  const key = initialActivationLifecyclePolicyReservationKey(createInitialActivationLifecyclePolicyReservation(identity));
  assert.equal(first.key, key); assert.match(key, /production-initial-activation-lifecycle-policy-reconciliation\/reservations\/[a-f0-9]{64}\.json$/);
  const replay = store.reserve(identity); assert.equal(replay.owned, true); assert.equal(replay.created, false); assert.deepEqual(replay.reservation, first.reservation);
  assert.equal(s3.calls.filter((args) => args[1] === "put-object").length, 1); assert.equal(s3.calls.filter((args) => args[1] === "put-object")[0].includes("--if-none-match"), true);
  assert.throws(() => store.reserve({ ...identity, desiredPolicySha256: "b".repeat(64) }), /reservation|desired/);
});

test("conditional reservation conflict authenticates the exact existing bytes and never overwrites", () => {
  const s3 = reservationMemoryS3(); const store = createInitialActivationLifecyclePolicyReservationStore({ run: s3.run }); const identity = reservationInput();
  const reservation = createInitialActivationLifecyclePolicyReservation(identity); const key = initialActivationLifecyclePolicyReservationKey(reservation); const bytes = Buffer.from(`${canonicalJson(reservation)}\n`);
  s3.conflict(bytes);
  const result = store.reserve(identity); assert.equal(result.created, false); assert.deepEqual(result.reservation, reservation);
  assert.equal(s3.calls.filter((args) => args[1] === "put-object").length, 1);
  assert.equal(bytes.equals(s3.objects.get(key)), true); assert.equal(s3.calls.filter((args) => args[1] === "get-object").at(-1).includes(key), true);
});

test("IAM convergence accepts temporary predecessor visibility, bounds polling, and rejects unexpected state", () => {
  const value = authorization(); let reads = 0; const sleeps = []; const states = [state(), state(), state(), state(), state(), state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 2 })];
  const result = waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => states[reads++], before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: value, desired, expectedVersionId: "v2", sleep: (milliseconds) => sleeps.push(milliseconds) });
  assert.equal(result.status, "ALREADY_RECONCILED"); assert.deepEqual(sleeps, [100, 200, 400, 800, 1000]); assert.equal(reads, 6);
  assert.throws(() => waitForInitialActivationLifecyclePolicyConvergence({ readLiveState: () => state({ defaultVersionId: "v2", document: desired.document, policyVersionCount: 3 }), before: assertInitialActivationLifecyclePolicyState(state(), { desired }), authorization: value, desired, expectedVersionId: "v2", sleep: () => {} }), /unexpected default version/);
});

test("IAM convergence exhaustion never authorizes a second policy version", () => {
  const value = authorization(); let creates = 0; const sleeps = [];
  assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, readLiveState: () => state(), sleep: (milliseconds) => sleeps.push(milliseconds), createPolicyVersion: () => { creates += 1; return { PolicyVersion: { VersionId: "v2" } }; } }), /did not converge/);
  assert.equal(creates, 1); assert.deepEqual(sleeps, [100, 200, 400, 800, 1000]);
});

test("only the exact successful workflow artifact is accepted as authorization", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "initial-activation-policy-authorization-"));
  try {
    const file = path.join(directory, "authorization.json"); const archive = path.join(directory, "authorization.zip");
    const exactAuthorization = authorization();
    fs.writeFileSync(file, `${JSON.stringify(exactAuthorization)}\n`); execFileSync("zip", ["-q", archive, "authorization.json"], { cwd: directory });
    const bytes = fs.readFileSync(archive); const digest = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
    const run = (command, args, options = {}) => {
      if (command === "gh" && /actions\/runs\/1$/.test(args.at(-1))) return JSON.stringify({ id: 1, repository: { full_name: "T-ej2003/genuine-scan-main" }, path: CONTRACT.workflowPath, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1 });
      if (command === "gh" && /actions\/runs\/1\/artifacts$/.test(args.at(-1))) return JSON.stringify({ artifacts: [{ id: 2, name: "production-initial-activation-lifecycle-policy-reconciliation-authorization", expired: false, digest, workflow_run: { id: 1, head_sha: sourceSha } }] });
      if (command === "gh") return bytes;
      return execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8" });
    };
    assert.equal(resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact({ workflowRunId: "1", workflowRunAttempt: "1", sourceSha, run }).authorization.authorizationSha256, exactAuthorization.authorizationSha256);
    assert.throws(() => resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact({ workflowRunId: "1", workflowRunAttempt: "1", sourceSha, now: new Date(new Date(exactAuthorization.protectedEnvironmentApprovalEvidence.observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs + 1), run }), /stale/);
    assert.throws(() => resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact({ workflowRunId: "1", workflowRunAttempt: "2", sourceSha, run }));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
