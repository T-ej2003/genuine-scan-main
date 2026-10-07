import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { WORKSPACE_STATE_RECONCILIATION as CONTRACT, assertWorkspaceStateAuthorization, createWorkspaceStateAuthorization, createWorkspaceStateJournal, createWorkspaceStatePreparation, executeWorkspaceStateReconciliation, readWorkspaceStateDesiredPolicy } from "../aws/production-workspace-state-policy-reconciliation.mjs";
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
const approval = () => createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "T-ej2003" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: CONTRACT.workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "release-operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "T-ej2003" } });
const preparation = () => createWorkspaceStatePreparation({ sourceSha, liveState: state(), desired, preparedAt: now.toISOString() });
const authorization = prep => createWorkspaceStateAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: approval(), now });
const provenance = auth => { const body = { schemaVersion: 1, kind: "PRODUCTION_WORKSPACE_STATE_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE", repository: "T-ej2003/genuine-scan-main", workflowPath: CONTRACT.workflowPath, workflowRunId: "123", workflowRunAttempt: "1", event: "workflow_dispatch", status: "completed", conclusion: "success", headSha: sourceSha, artifactId: 456, artifactName: CONTRACT.artifactName, artifactDigest: `sha256:${"b".repeat(64)}`, authorizationFileSha256: "c".repeat(64), authorizationSha256: auth.authorizationSha256, approvedBy: auth.approvedBy }; return { ...body, provenanceSha256: hash(body) }; };
const memoryJournal = () => { const values = new Map(); return { values, journal: createWorkspaceStateJournal({ read: async key => values.get(key) || null, create: async (key, bytes) => { if (values.has(key)) return false; values.set(key, Buffer.from(bytes)); return true; } }) }; };
const executor = ({ prep = preparation(), live = state(), journal = memoryJournal(), authorization: auth = authorization(prep), ...overrides } = {}) => {
  const box = { live, deletes: 0, creates: 0 };
  const args = { sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: journal.journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => box.live, deletePolicyVersion: async ({ PolicyArn, VersionId }) => { box.deletes += 1; assert.equal(PolicyArn, CONTRACT.policyArn); assert.equal(VersionId, prep.deletionCandidate.versionId); box.live = afterDelete(); }, createPolicyVersion: async ({ PolicyArn, PolicyDocument, SetAsDefault }) => { box.creates += 1; assert.equal(PolicyArn, CONTRACT.policyArn); assert.deepEqual(PolicyDocument, desired.document); assert.equal(SetAsDefault, true); box.live = post(); return { PolicyVersion: { VersionId: "v6" } }; }, ...overrides };
  return { args, box, journal };
};

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

test("protected-environment maker cannot self-authorize", () => {
  const prep = preparation();
  const self = createProductionEnvironmentApprovalEvidence({ environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "T-ej2003" } }] }] }, repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: CONTRACT.workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "T-ej2003", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "T-ej2003" } });
  assert.throws(() => createWorkspaceStateAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: self, now }), /self-approved/);
});
