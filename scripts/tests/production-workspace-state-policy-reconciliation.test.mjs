import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { WORKSPACE_STATE_RECONCILIATION as CONTRACT, assertWorkspaceStateAuthorization, createWorkspaceStateAuthorization, createWorkspaceStateJournal, createWorkspaceStatePreparation, executeWorkspaceStateReconciliation, readWorkspaceStateDesiredPolicy, WorkspaceStateRetryableObservationError, workspaceStateJournalKey } from "../aws/production-workspace-state-policy-reconciliation.mjs";
import { readWorkspaceStateLiveState } from "../aws/reconcile-production-workspace-state-policy.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-10-07T12:00:00.000Z");
const desired = readWorkspaceStateDesiredPolicy();
const hash = value => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : canonicalJson(value)).digest("hex");
const oldDocument = index => index === 5 ? desired.predecessor : { Version: "2012-10-17", Statement: [{ Sid: `Historical${index}`, Effect: "Allow", Action: "sts:GetCallerIdentity", Resource: "*" }] };
const versions = () => [1, 2, 3, 4, 5].map(index => ({ versionId: `v${index}`, isDefault: index === 5, createDate: `2026-0${index}-01T00:00:00.000Z`, document: oldDocument(index) }));
const state = (change = {}) => ({ policyArn: CONTRACT.policyArn, defaultVersionId: "v5", versions: versions(), attachedRoles: [CONTRACT.releaseRoleName], attachedUsers: [], attachedGroups: [], permissionsBoundaryUsageCount: 0, ...change });
const afterDelete = (change = {}) => state({ versions: versions().filter(({ versionId }) => versionId !== "v1"), ...change });
const post = (change = {}) => state({ defaultVersionId: "v6", versions: [...versions().filter(({ versionId }) => versionId !== "v1").map(version => ({ ...version, isDefault: false })), { versionId: "v6", isDefault: true, createDate: "2026-10-07T12:05:00.000Z", document: desired.document }], ...change });
const approval = (at = now, workflowRunId = "123", approvedSourceSha = sourceSha) => createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "T-ej2003" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha: approvedSourceSha, workflowRef: CONTRACT.workflowRef, eventName: "workflow_dispatch", workflowRunId, workflowRunAttempt: "1", executionActor: "release-operator", observedAt: at.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "T-ej2003" } });
const preparation = () => createWorkspaceStatePreparation({ sourceSha, liveState: state(), desired, preparedAt: now.toISOString() });
const authorization = (prep, at = now, workflowRunId = "123") => createWorkspaceStateAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: approval(at, workflowRunId, prep.sourceSha), now: at });
const provenance = auth => { const body = { schemaVersion: 1, kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE", repository: "T-ej2003/genuine-scan-main", workflowPath: CONTRACT.workflowPath, workflowRunId: auth.protectedEnvironmentApprovalEvidence.workflowRunId, workflowRunAttempt: "1", event: "workflow_dispatch", status: "completed", conclusion: "success", headSha: auth.sourceSha, artifactId: 456, artifactName: CONTRACT.artifactName, artifactDigest: `sha256:${"b".repeat(64)}`, authorizationFileSha256: "c".repeat(64), authorizationSha256: auth.authorizationSha256, approvedBy: auth.approvedBy }; return { ...body, provenanceSha256: hash(body) }; };
const memoryJournal = () => { const values = new Map(); return { values, journal: createWorkspaceStateJournal({ read: async key => values.get(key) || null, create: async (key, bytes) => { if (values.has(key)) return false; values.set(key, Buffer.from(bytes)); return true; } }) }; };
const executor = ({ prep = preparation(), live = state(), journal = memoryJournal(), authorization: auth = authorization(prep), ...overrides } = {}) => {
  const box = { live, deletes: 0, creates: 0 };
  const args = { sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: journal.journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => box.live, deletePolicyVersion: async ({ PolicyArn, VersionId }) => { box.deletes += 1; assert.equal(PolicyArn, CONTRACT.policyArn); assert.equal(VersionId, prep.deletionCandidate.versionId); box.live = afterDelete(); }, createPolicyVersion: async ({ PolicyArn, PolicyDocument, SetAsDefault }) => { box.creates += 1; assert.equal(PolicyArn, CONTRACT.policyArn); assert.deepEqual(PolicyDocument, desired.document); assert.equal(SetAsDefault, true); box.live = post(); return { PolicyVersion: { VersionId: "v6" } }; }, ...overrides };
  return { args, box, journal };
};
const recordBody = (kind, prep, auth, createdAt, postState) => ({ schemaVersion: 1, kind, operationId: prep.operationId, sourceSha: prep.sourceSha, targetPolicyArn: prep.targetPolicyArn, preparationSha256: prep.preparationSha256, authorizationSha256: auth.authorizationSha256, authorizationProvenanceSha256: provenance(auth).provenanceSha256, currentDefaultVersionId: prep.currentDefaultVersionId, currentDefaultDocumentSha256: prep.currentDefaultDocumentSha256, desiredDocumentSha256: prep.desiredDocumentSha256, permissionDeltaSha256: prep.permissionDeltaSha256, versionInventorySha256: prep.versionInventorySha256, deletionCandidate: prep.deletionCandidate, expectedWritePlanSha256: prep.expectedWritePlanSha256, ...(postState ? { createdPolicyVersionId: postState.defaultVersionId, postVersionInventorySha256: postState.inventorySha256, status: "COMPLETED", authorizationConsumed: true } : {}), createdAt });
const seedRecord = (run, auth, prep, record, kind, createdAt = now.toISOString(), postState) => run.journal.journal.create(auth, record, recordBody(kind, prep, auth, createdAt, postState));
const freshAuthorization = () => { const at = new Date(now.getTime() + 31 * 60 * 1000); const prep = createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: at.toISOString(), liveState: state() }); return { prep, auth: authorization(prep, at, "124"), at }; };

test("target and declared permission delta are exact", () => {
  assert.equal(CONTRACT.policyName, "MSCQRProductionGreenStageBWorkspaceState");
  assert.deepEqual(desired.delta, { add: [{ Sid: "ReadStageBApplyAttemptVersions", Effect: "Allow", Action: "s3:GetObjectVersion", Resource: "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/apply-attempts/*" }], remove: [], change: [] });
  assert.equal(desired.document.Statement.some(({ Action }) => [Action].flat().includes("s3:ListBucketVersions")), false);
  assert.equal(desired.delta.add.some(({ Action }) => [Action].flat().some(action => /^s3:(?:Put|Delete)/.test(action))), false);
});

test("five-version preparation binds one uniquely oldest non-default deletion and one exact successor", () => {
  const prep = preparation();
  assert.equal(prep.versionInventory.length, 5);
  assert.equal(prep.currentDefaultVersionId, "v5");
  assert.equal(prep.deletionCandidate.versionId, "v1");
  assert.notEqual(prep.deletionCandidate.versionId, prep.currentDefaultVersionId);
  assert.deepEqual(prep.expectedWritePlan.map(({ action }) => action), ["iam:DeletePolicyVersion", "iam:CreatePolicyVersion"]);
  assert.equal(prep.desiredDocumentSha256, desired.desiredDocumentSha256);
});

test("oldest default is protected and the oldest non-default becomes the reviewed candidate", () => {
  const inventory = versions().map((version, index) => ({ ...version, isDefault: index === 0, document: index === 0 ? desired.predecessor : version.document }));
  const prep = createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ defaultVersionId: "v1", versions: inventory }) });
  assert.equal(prep.currentDefaultVersionId, "v1");
  assert.equal(prep.deletionCandidate.versionId, "v2");
});

test("duplicate timestamps among newer versions do not obscure the unique oldest non-default", () => {
  const inventory = versions().map(version => ["v2", "v3"].includes(version.versionId) ? { ...version, createDate: "2026-02-01T00:00:00.000Z" } : version);
  const prep = createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ versions: inventory }) });
  assert.equal(prep.deletionCandidate.versionId, "v1");
});

test("a tie for the oldest eligible non-default fails closed", () => {
  const inventory = versions().map((version, index) => ({ ...version, createDate: index < 2 ? "2026-01-01T00:00:00.000Z" : version.createDate }));
  assert.throws(() => createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ versions: inventory }) }), /uniquely oldest/);
});

test("default timestamp ties do not affect a uniquely oldest eligible non-default", () => {
  const inventory = versions().map(version => version.versionId === "v1" || version.versionId === "v5" ? { ...version, createDate: "2026-01-01T00:00:00.000Z" } : version);
  const prep = createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ versions: inventory }) });
  assert.equal(prep.deletionCandidate.versionId, "v1");
  assert.notEqual(prep.deletionCandidate.versionId, prep.currentDefaultVersionId);
});

test("duplicate version identities and zero or multiple defaults fail closed", () => {
  const duplicateId = versions(); duplicateId[1] = { ...duplicateId[1], versionId: "v1" };
  assert.throws(() => createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ versions: duplicateId }) }), /topology is ambiguous/);
  for (const defaults of [[false, false, false, false, false], [true, false, false, false, true]]) {
    const inventory = versions().map((version, index) => ({ ...version, isDefault: defaults[index] }));
    assert.throws(() => createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ versions: inventory }) }), /topology is ambiguous/);
  }
});

test("live reader authenticates every policy version document and exact attachment topology", () => {
  const calls = [];
  const run = args => {
    calls.push(args);
    if (args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: "v5", PermissionsBoundaryUsageCount: 0 } });
    if (args[1] === "list-policy-versions") return JSON.stringify({ Versions: versions().map(({ versionId, isDefault, createDate }) => ({ VersionId: versionId, IsDefaultVersion: isDefault, CreateDate: createDate })) });
    if (args[1] === "get-policy-version") { const versionId = args[args.indexOf("--version-id") + 1]; const item = versions().find(version => version.versionId === versionId); return JSON.stringify({ PolicyVersion: { VersionId: item.versionId, IsDefaultVersion: item.isDefault, Document: item.document } }); }
    if (args[1] === "list-entities-for-policy") return JSON.stringify({ PolicyRoles: [{ RoleName: CONTRACT.releaseRoleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false });
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.equal(readWorkspaceStateLiveState(run).versions.length, 5);
  assert.equal(calls.filter(args => args[1] === "get-policy-version").length, 5);
  assert.equal(calls.some(args => ["delete-policy-version", "create-policy-version"].includes(args[1])), false);
});

test("live reader classifies only explicit transient IAM read failures and mixed snapshots as retryable", () => {
  assert.throws(() => readWorkspaceStateLiveState(() => { throw new Error("An error occurred (ThrottlingException) when calling GetPolicy"); }), WorkspaceStateRetryableObservationError);
  assert.throws(() => readWorkspaceStateLiveState(() => { throw new Error("An error occurred (AccessDenied) when calling GetPolicy"); }), error => !(error instanceof WorkspaceStateRetryableObservationError));
  assert.throws(() => readWorkspaceStateLiveState(args => { if (args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: "v5", PermissionsBoundaryUsageCount: 0 } }); if (args[1] === "list-policy-versions") return JSON.stringify({ Versions: [{ VersionId: "v5", IsDefaultVersion: true, CreateDate: "2026-01-01T00:00:00.000Z" }] }); if (args[1] === "list-entities-for-policy") return JSON.stringify({ PolicyRoles: [{ RoleName: CONTRACT.releaseRoleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }); throw new Error("An error occurred (NoSuchEntity) when calling GetPolicyVersion"); }), WorkspaceStateRetryableObservationError);
  let first = true;
  const stableRun = args => {
    if (args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: first ? "v4" : "v5", PermissionsBoundaryUsageCount: 0 } });
    first = false;
    if (args[1] === "list-policy-versions") return JSON.stringify({ Versions: versions().map(({ versionId, isDefault, createDate }) => ({ VersionId: versionId, IsDefaultVersion: isDefault, CreateDate: createDate })) });
    if (args[1] === "get-policy-version") { const item = versions().find(version => version.versionId === args[args.indexOf("--version-id") + 1]); return JSON.stringify({ PolicyVersion: { VersionId: item.versionId, IsDefaultVersion: item.isDefault, Document: item.document } }); }
    if (args[1] === "list-entities-for-policy") return JSON.stringify({ PolicyRoles: [{ RoleName: CONTRACT.releaseRoleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false });
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  assert.throws(() => readWorkspaceStateLiveState(stableRun), WorkspaceStateRetryableObservationError);
});

test("default, inventory, candidate document, successor, target, and authorization changes fail closed", () => {
  assert.throws(() => createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ defaultVersionId: "v4" }) }));
  assert.throws(() => createWorkspaceStatePreparation({ sourceSha, desired, preparedAt: now.toISOString(), liveState: state({ versions: versions().slice(1) }) }));
  const prep = preparation(); const auth = authorization(prep);
  for (const change of [{ targetPolicyArn: "arn:aws:iam::368992683803:policy/other" }, { versionInventorySha256: "d".repeat(64) }, { deletionCandidate: { ...prep.deletionCandidate, documentSha256: "e".repeat(64) } }, { desiredDocumentSha256: "f".repeat(64) }]) assert.throws(() => assertWorkspaceStateAuthorization({ ...auth, ...change }, prep, { sourceSha, now }));
});

test("fresh authorization performs exactly one delete and one successor publication; replay performs none", async () => {
  const run = executor();
  const result = await executeWorkspaceStateReconciliation(run.args);
  assert.equal(result.status, "COMPLETED"); assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "CONSUMED"); assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("changed complete inventory at the final deletion CAS performs no IAM mutation", async () => {
  let reads = 0; const run = executor({ readLiveState: async () => ++reads < 2 ? state() : state({ versions: versions().map(version => version.versionId === "v1" ? { ...version, document: oldDocument(2) } : version) }) });
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), /CAS changed|drift/);
  assert.deepEqual([run.box.deletes, run.box.creates], [0, 0]);
});

test("interruption after deletion reconciles without a second deletion", async () => {
  const run = executor({ deletePolicyVersion: async () => { run.box.deletes += 1; run.box.live = afterDelete(); throw new Error("response lost"); } });
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED");
  assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("ambiguous deletion pre-state is never retried", async () => {
  const run = executor({ deletePolicyVersion: async () => { run.box.deletes += 1; throw new Error("unknown"); } });
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), error => error.mutationOutcome === "DELETE_OUTCOME_AMBIGUOUS");
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), error => error.mutationOutcome === "DELETE_OUTCOME_AMBIGUOUS");
  assert.deepEqual([run.box.deletes, run.box.creates], [1, 0]);
});

test("ambiguous successful creation is recovered without a second CreatePolicyVersion", async () => {
  const run = executor({ createPolicyVersion: async () => { run.box.creates += 1; run.box.live = post(); throw new Error("response lost"); } });
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED");
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "CONSUMED");
  assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("ambiguous creation pre-state is never retried", async () => {
  const run = executor({ createPolicyVersion: async () => { run.box.creates += 1; throw new Error("unknown"); } });
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), error => error.mutationOutcome === "CREATE_OUTCOME_AMBIGUOUS");
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), error => error.mutationOutcome === "CREATE_OUTCOME_AMBIGUOUS");
  assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("an untouched reservation continues under its original live authorization", async () => {
  const run = executor();
  await seedRecord(run, run.args.authorization, run.args.preparation, "reservation.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION");
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED");
  assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("fresh matching authorization adopts a zero-write reservation without rewriting it", async () => {
  const original = executor(); await seedRecord(original, original.args.authorization, original.args.preparation, "reservation.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION");
  const { prep, auth, at } = freshAuthorization(); const originalBytes = original.journal.values.get(workspaceStateJournalKey(auth.operationId, "reservation.json"));
  assert.throws(() => assertWorkspaceStateAuthorization(original.args.authorization, original.args.preparation, { sourceSha, now: at }), /stale/);
  assert.doesNotThrow(() => assertWorkspaceStateAuthorization(auth, prep, { sourceSha, now: at }));
  const resumed = executor({ prep, authorization: auth, journal: original.journal, now: () => at });
  assert.equal((await executeWorkspaceStateReconciliation(resumed.args)).status, "COMPLETED");
  assert.deepEqual([resumed.box.deletes, resumed.box.creates], [1, 1]);
  assert.deepEqual(original.journal.values.get(workspaceStateJournalKey(auth.operationId, "reservation.json")), originalBytes);
});

test("zero-write reservation adoption rejects changed pre-state, successor, or deletion candidate", async () => {
  for (const mutate of [
    run => { run.box.live = state({ versions: versions().map(version => version.versionId === "v2" ? { ...version, document: oldDocument(7) } : version) }); },
    (run, prep) => { const record = JSON.parse(run.journal.values.get(workspaceStateJournalKey(prep.operationId, "reservation.json"))); record.desiredDocumentSha256 = "d".repeat(64); delete record.recordSha256; run.journal.values.set(workspaceStateJournalKey(prep.operationId, "reservation.json"), Buffer.from(`${canonicalJson({ ...record, recordSha256: hash(record) })}\n`)); },
    (run, prep) => { const record = JSON.parse(run.journal.values.get(workspaceStateJournalKey(prep.operationId, "reservation.json"))); record.deletionCandidate = { ...record.deletionCandidate, versionId: "v2" }; delete record.recordSha256; run.journal.values.set(workspaceStateJournalKey(prep.operationId, "reservation.json"), Buffer.from(`${canonicalJson({ ...record, recordSha256: hash(record) })}\n`)); },
  ]) {
    const original = executor(); await seedRecord(original, original.args.authorization, original.args.preparation, "reservation.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION");
    const { prep, auth, at } = freshAuthorization(); const resumed = executor({ prep, authorization: auth, journal: original.journal, now: () => at }); mutate(resumed, prep);
    await assert.rejects(() => executeWorkspaceStateReconciliation(resumed.args));
    assert.deepEqual([resumed.box.deletes, resumed.box.creates], [0, 0]);
  }
});

test("zero-write reservation adoption rejects every recorded mutation boundary and terminal state", async () => {
  for (const record of ["deletion-attempt.json", "deletion-complete.json", "creation-attempt.json"]) {
    const original = executor(); await seedRecord(original, original.args.authorization, original.args.preparation, "reservation.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION");
    const kind = ({ "deletion-attempt.json": "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_ATTEMPT", "deletion-complete.json": "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_DELETION_COMPLETE", "creation-attempt.json": "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_CREATION_ATTEMPT" })[record];
    await seedRecord(original, original.args.authorization, original.args.preparation, record, kind);
    const { prep, auth, at } = freshAuthorization(); const resumed = executor({ prep, authorization: auth, journal: original.journal, now: () => at });
    await assert.rejects(() => executeWorkspaceStateReconciliation(resumed.args), /cannot be adopted after a mutation-attempt/);
    assert.deepEqual([resumed.box.deletes, resumed.box.creates], [0, 0]);
  }
  const original = executor(); const terminal = post();
  await seedRecord(original, original.args.authorization, original.args.preparation, "reservation.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION");
  await seedRecord(original, original.args.authorization, original.args.preparation, "terminal.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_TERMINAL", now.toISOString(), { ...terminal, inventorySha256: hash(terminal.versions) });
  const { prep, auth, at } = freshAuthorization(); const resumed = executor({ prep, authorization: auth, journal: original.journal, live: terminal, now: () => at });
  await assert.rejects(() => executeWorkspaceStateReconciliation(resumed.args));
  assert.deepEqual([resumed.box.deletes, resumed.box.creates], [0, 0]);
});

test("zero-write reservation adoption rejects tampering and a different operation identity", async () => {
  const original = executor(); await seedRecord(original, original.args.authorization, original.args.preparation, "reservation.json", "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_RESERVATION");
  const { prep, auth, at } = freshAuthorization(); const key = workspaceStateJournalKey(auth.operationId, "reservation.json");
  const record = JSON.parse(original.journal.values.get(key)); original.journal.values.set(key, Buffer.from(`${canonicalJson({ ...record, desiredDocumentSha256: "e".repeat(64) })}\n`));
  const resumed = executor({ prep, authorization: auth, journal: original.journal, now: () => at });
  await assert.rejects(() => executeWorkspaceStateReconciliation(resumed.args)); assert.deepEqual([resumed.box.deletes, resumed.box.creates], [0, 0]);
  const otherSource = "b".repeat(40); const otherPrep = createWorkspaceStatePreparation({ sourceSha: otherSource, desired, preparedAt: now.toISOString(), liveState: state() });
  const otherAuth = authorization(otherPrep); const wrongOperation = executor({ prep: otherPrep, authorization: otherAuth });
  await assert.rejects(() => executeWorkspaceStateReconciliation(wrongOperation.args), /binding is invalid/);
});

test("bounded post-delete observations retry a transient snapshot and never repeat deletion", async () => {
  const run = executor(); let transientReads = 0; const originalRead = run.args.readLiveState;
  run.args.readLiveState = async () => { if (run.box.deletes && transientReads++ < 2) throw new WorkspaceStateRetryableObservationError("transient read"); return originalRead(); };
  const delays = []; run.args.sleep = async milliseconds => delays.push(milliseconds);
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED");
  assert.deepEqual(delays, [100, 300]); assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("a single transient post-delete observation resolves on the next bounded read", async () => {
  const run = executor(); let failedOnce = false; const originalRead = run.args.readLiveState;
  run.args.readLiveState = async () => { if (run.box.deletes && !failedOnce) { failedOnce = true; throw new WorkspaceStateRetryableObservationError("one transient snapshot"); } return originalRead(); };
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED");
  assert.equal(failedOnce, true); assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("bounded transient observations exhaust into a fail-closed deletion ambiguity", async () => {
  const run = executor(); let reads = 0; const originalRead = run.args.readLiveState;
  run.args.readLiveState = async () => { if (run.box.deletes) { reads += 1; throw new WorkspaceStateRetryableObservationError("propagation pending"); } return originalRead(); };
  const delays = []; run.args.sleep = async milliseconds => delays.push(milliseconds);
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), error => error.mutationOutcome === "DELETE_OUTCOME_AMBIGUOUS" && /bounded retry budget/.test(error.message) && error.cause?.message === "propagation pending");
  assert.equal(reads, 4); assert.deepEqual(delays, [100, 300, 700]); assert.deepEqual([run.box.deletes, run.box.creates], [1, 0]);
});

test("authenticated contradiction and permanent read errors are not retried", async () => {
  const contradiction = executor({ deletePolicyVersion: async () => { contradiction.box.deletes += 1; contradiction.box.live = state({ policyArn: "arn:aws:iam::368992683803:policy/other" }); } });
  let contradictionReads = 0; const priorRead = contradiction.args.readLiveState;
  contradiction.args.readLiveState = async () => { if (contradiction.box.deletes) contradictionReads += 1; return priorRead(); };
  await assert.rejects(() => executeWorkspaceStateReconciliation(contradiction.args), error => error.mutationOutcome === "DELETE_OUTCOME_AMBIGUOUS");
  assert.equal(contradictionReads, 1); assert.equal(contradiction.box.creates, 0);
  const permanent = executor(); let permanentReads = 0; const baseRead = permanent.args.readLiveState;
  permanent.args.readLiveState = async () => { if (permanent.box.deletes) { permanentReads += 1; throw new Error("AccessDenied: not authorized"); } return baseRead(); };
  await assert.rejects(() => executeWorkspaceStateReconciliation(permanent.args), error => error.mutationOutcome === "DELETE_OUTCOME_AMBIGUOUS");
  assert.equal(permanentReads, 1); assert.equal(permanent.box.creates, 0);
});

test("transient create observations reconcile the exact successor without a duplicate create", async () => {
  const run = executor(); let transientReads = 0; const originalRead = run.args.readLiveState;
  run.args.readLiveState = async () => { if (run.box.creates && transientReads++ < 1) throw new WorkspaceStateRetryableObservationError("mixed create snapshot"); return originalRead(); };
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED");
  assert.equal(transientReads, 2); assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
});

test("interruption after deletion-complete resumes with one create; terminal-write interruption resumes read-only", async () => {
  const run = executor(); const originalJournal = run.args.journal; const originalCreate = originalJournal.create; let failDeletionComplete = true;
  run.args.journal = { read: originalJournal.read, create: async (auth, record, body) => { if (record === "deletion-complete.json" && failDeletionComplete) { failDeletionComplete = false; return false; } return originalCreate(auth, record, body); } };
  await assert.rejects(() => executeWorkspaceStateReconciliation(run.args), /deletion completion raced/);
  assert.deepEqual([run.box.deletes, run.box.creates], [1, 0]);
  run.args.journal = originalJournal;
  assert.equal((await executeWorkspaceStateReconciliation(run.args)).status, "COMPLETED"); assert.deepEqual([run.box.deletes, run.box.creates], [1, 1]);
  const completed = executor(); const originalTerminalJournal = completed.args.journal; const createTerminal = originalTerminalJournal.create; let failTerminal = true;
  completed.args.journal = { read: originalTerminalJournal.read, create: async (auth, record, body) => { if (record === "terminal.json" && failTerminal) { failTerminal = false; return false; } return createTerminal(auth, record, body); } };
  await assert.rejects(() => executeWorkspaceStateReconciliation(completed.args), /terminal consumption raced/);
  assert.deepEqual([completed.box.deletes, completed.box.creates], [1, 1]); completed.args.journal = originalTerminalJournal;
  assert.equal((await executeWorkspaceStateReconciliation(completed.args)).status, "EXPECTED_POST_STATE_RECOVERED");
  assert.deepEqual([completed.box.deletes, completed.box.creates], [1, 1]);
});

test("protected-environment maker cannot self-authorize", () => {
  const prep = preparation();
  const self = createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "T-ej2003" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: CONTRACT.workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "T-ej2003", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "T-ej2003" } });
  assert.throws(() => createWorkspaceStateAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: self, now }), /self-approved/);
});
