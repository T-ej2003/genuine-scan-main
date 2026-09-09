import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import JSZip from "jszip";
import { canonicalJson } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { PROVIDER_READONLY_RECONCILIATION as CONTRACT, assertProviderReadonlyAuthorization, authenticateProviderReadonlyLiveState, createProviderReadonlyAuthorization, createProviderReadonlyJournal, createProviderReadonlyPreparation, executeProviderReadonlyReconciliation, providerReadonlyOperationId, providerReadonlyProductionSleep, readProviderReadonlyDesiredPolicy, resolveProviderReadonlyAuthorizationArtifact } from "../aws/production-provider-readonly-policy-reconciliation.mjs";
import { readProviderReadonlyLiveState, runProviderReadonlyReconciliation } from "../aws/reconcile-production-provider-readonly-policy.mjs";

const sourceSha = "a".repeat(40);
const now = new Date("2026-09-09T10:00:00.000Z");
const desired = readProviderReadonlyDesiredPolicy();
const hash = (value) => crypto.createHash("sha256").update(Buffer.isBuffer(value) ? value : canonicalJson(value)).digest("hex");
const state = (change = {}) => ({ policyArn: CONTRACT.policyArn, defaultVersionId: "v3", document: desired.predecessorDocument, versions: [{ versionId: "v1", isDefault: false }, { versionId: "v2", isDefault: false }, { versionId: "v3", isDefault: true }], attachedRoles: [CONTRACT.releaseRoleName], attachedUsers: [], attachedGroups: [], permissionsBoundaryUsageCount: 0, ...change });
const approval = (change = {}) => createProductionEnvironmentApprovalEvidence({
  environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "T-ej2003" } }] }] },
  repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: CONTRACT.workflowRef, eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "release-operator", observedAt: now.toISOString(), actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "T-ej2003" }, ...change,
});
const preparation = () => createProviderReadonlyPreparation({ sourceSha, liveState: state(), desired, preparedAt: now.toISOString() });
const authorization = (prep = preparation()) => createProviderReadonlyAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: approval(), now });
const provenance = (auth) => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE", repository: "T-ej2003/genuine-scan-main", workflowPath: CONTRACT.workflowPath, workflowRunId: auth.protectedEnvironmentApprovalEvidence.workflowRunId, workflowRunAttempt: "1", event: "workflow_dispatch", status: "completed", conclusion: "success", headSha: sourceSha, artifactId: 456, artifactName: CONTRACT.artifactName, artifactDigest: `sha256:${"b".repeat(64)}`, authorizationFileSha256: "c".repeat(64), authorizationSha256: auth.authorizationSha256, approvedBy: auth.approvedBy };
  return { ...body, provenanceSha256: hash(body) };
};
const memoryJournal = () => {
  const values = new Map();
  return { values, journal: createProviderReadonlyJournal({ read: async (key) => values.get(key) || null, create: async (key, bytes) => { if (values.has(key)) return false; values.set(key, Buffer.from(bytes)); return true; } }) };
};
const postState = (change = {}) => state({ defaultVersionId: "v4", document: desired.document, versions: [...state().versions.map((version) => ({ ...version, isDefault: false })), { versionId: "v4", isDefault: true }], ...change });
const operationBindings = (prep) => ({ sourceSha: prep.sourceSha, currentDefaultVersionId: prep.currentDefaultVersionId, currentDefaultDocumentSha256: prep.currentDefaultDocumentSha256, desiredDocumentSha256: prep.desiredDocumentSha256, versionInventorySha256: prep.versionInventorySha256, attachmentTopologySha256: prep.attachmentTopologySha256 });
const journalIdentity = (kind, prep, auth, prov, createdAt = prep.createdAt) => ({ schemaVersion: 1, kind, operationId: prep.operationId, sourceSha: prep.sourceSha, account: prep.account, targetPolicyArn: prep.targetPolicyArn, sourcePolicySha256: prep.sourcePolicySha256, preparationSha256: prep.preparationSha256, authorizationSha256: auth.authorizationSha256, authorizationProvenanceSha256: prov.provenanceSha256, currentDefaultVersionId: prep.currentDefaultVersionId, currentDefaultDocumentSha256: prep.currentDefaultDocumentSha256, desiredDocumentSha256: prep.desiredDocumentSha256, semanticDeltaSha256: prep.semanticDeltaSha256, versionInventorySha256: prep.versionInventorySha256, attachmentTopologySha256: prep.attachmentTopologySha256, expectedWritePlanSha256: prep.expectedWritePlanSha256, createdAt });
const workflowEnvironment = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_WORKFLOW_REF: CONTRACT.executionWorkflowRef, GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ATTEMPT: "1", AWS_ACCESS_KEY_ID: "fixture", AWS_SECRET_ACCESS_KEY: "fixture", AWS_SESSION_TOKEN: "fixture" };

async function githubAuthorization(auth, change = {}) {
  const zip = new JSZip(); zip.file(CONTRACT.authorizationFilename, `${JSON.stringify(change.authorization || auth, null, 2)}\n`);
  const archive = await zip.generateAsync({ type: "nodebuffer", platform: "UNIX" });
  const workflow = { id: 123, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: CONTRACT.workflowPath, event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", run_attempt: 1, actor: { login: "release-operator" }, ...change.workflow };
  const artifact = { id: 456, name: CONTRACT.artifactName, expired: false, workflow_run: { id: 123, head_sha: sourceSha, repository_id: 9 }, digest: `sha256:${hash(archive)}`, ...change.artifact };
  const environment = { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "T-ej2003" } }] }] };
  const approvals = change.approvals || [{ state: "approved", environments: [{ id: 1, name: "production" }], user: { id: 2, login: "T-ej2003" } }];
  return (_command, args, options = {}) => {
    const endpoint = args[1];
    if (endpoint.endsWith("/actions/runs/123")) return JSON.stringify(workflow);
    if (endpoint.endsWith("/actions/runs/123/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]);
    if (endpoint.endsWith("/actions/artifacts/456/zip")) return options.encoding === null ? (change.archive || archive) : (change.archive || archive).toString();
    if (endpoint.endsWith("/environments/production")) return JSON.stringify(environment);
    if (endpoint.endsWith("/actions/runs/123/approvals")) return JSON.stringify(approvals);
    throw new Error(`unexpected GitHub endpoint ${endpoint}`);
  };
}

test("target and semantic delta are exact; unexpected live drift and the five-version limit fail closed", () => {
  const prep = preparation();
  assert.equal(prep.targetPolicyArn, CONTRACT.policyArn);
  assert.deepEqual(prep.semanticDelta, { add: [{ effect: "Allow", action: "ecr:DescribeImages", resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker", condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } }], remove: [], change: [] });
  assert.deepEqual(prep.expectedWritePlan, [{ action: "iam:CreatePolicyVersion", policyArn: CONTRACT.policyArn, policyDocumentSha256: desired.sourcePolicySha256, setAsDefault: true }]);
  for (const change of [
    { policyArn: "arn:aws:iam::368992683803:policy/other" }, { attachedRoles: [] }, { attachedRoles: [CONTRACT.releaseRoleName, "other"] }, { attachedUsers: ["user"] }, { permissionsBoundaryUsageCount: 1 },
    { document: { ...desired.predecessorDocument, Statement: [...desired.predecessorDocument.Statement, { Effect: "Allow", Action: "*", Resource: "*" }] } },
  ]) assert.throws(() => createProviderReadonlyPreparation({ sourceSha, liveState: state(change), desired, preparedAt: now.toISOString() }));
  assert.throws(() => createProviderReadonlyPreparation({ sourceSha, liveState: state({ versions: [1, 2, 3, 4, 5].map((value) => ({ versionId: `v${value}`, isDefault: value === 3 })) }), desired, preparedAt: now.toISOString() }), /no reviewed retention rule/);
  assert.equal(CONTRACT.retentionRule, "NONE_FAIL_CLOSED");
  for (let count = 1; count <= 4; count += 1) assert.equal(createProviderReadonlyPreparation({ sourceSha, liveState: state({ defaultVersionId: `v${count}`, versions: Array.from({ length: count }, (_, index) => ({ versionId: `v${index + 1}`, isDefault: index + 1 === count })) }), desired, preparedAt: now.toISOString() }).policyVersionCount, count);
});

test("authorization binds the complete transaction and actual independent reviewer", () => {
  const prep = preparation(); const auth = authorization(prep);
  assert.doesNotThrow(() => assertProviderReadonlyAuthorization(auth, prep, { sourceSha, now }));
  const mutations = [
    { sourceSha: "b".repeat(40) }, { targetPolicyArn: "arn:aws:iam::368992683803:policy/other" }, { currentDefaultVersionId: "v2" }, { desiredDocumentSha256: "d".repeat(64) }, { preparationSha256: "e".repeat(64) }, { authorizationConsumed: true }, { approvedBy: "release-operator" },
  ];
  for (const change of mutations) assert.throws(() => assertProviderReadonlyAuthorization({ ...auth, ...change }, prep, { sourceSha, now }));
  assert.throws(() => createProviderReadonlyAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: approval({ workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main" }), now }), /dedicated/);
  assert.throws(() => createProviderReadonlyAuthorization({ preparation: prep, protectedEnvironmentApprovalEvidence: approval({ executionActor: "T-ej2003" }), now }), /self-approved/);
  assert.throws(() => assertProviderReadonlyAuthorization(auth, prep, { sourceSha, now: "not-a-time" }), /stale/);
  assert.throws(() => assertProviderReadonlyAuthorization(auth, prep, { sourceSha, now: new Date(prep.expiresAt).getTime() + 1 }), /stale/);
});

test("logical operation identity excludes evidence time and changes with every authenticated state binding", () => {
  const first = preparation();
  const second = createProviderReadonlyPreparation({ sourceSha, liveState: state(), desired, preparedAt: new Date(now.getTime() + 1).toISOString() });
  assert.equal(first.operationId, second.operationId);
  assert.notEqual(first.preparationSha256, second.preparationSha256);
  const stable = operationBindings(first);
  for (const [field, value] of [
    ["sourceSha", "b".repeat(40)],
    ["currentDefaultDocumentSha256", "c".repeat(64)],
    ["desiredDocumentSha256", "d".repeat(64)],
    ["versionInventorySha256", "e".repeat(64)],
    ["attachmentTopologySha256", "f".repeat(64)],
  ]) assert.notEqual(providerReadonlyOperationId({ ...stable, [field]: value }), first.operationId, field);
  const forged = { ...first, operationId: "9".repeat(64) }; delete forged.preparationSha256; forged.preparationSha256 = hash(forged);
  assert.throws(() => createProviderReadonlyAuthorization({ preparation: forged, protectedEnvironmentApprovalEvidence: approval(), now }), /binding/);
});

test("fresh exact transaction performs one write, persists consumption, and rejects replay", async () => {
  const prep = preparation(); const auth = authorization(prep); const prov = provenance(auth); const store = memoryJournal();
  let live = state(); let writes = 0;
  const execute = () => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: store.journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => live, createPolicyVersion: async (input) => {
    writes += 1; assert.equal(input.PolicyArn, CONTRACT.policyArn); assert.deepEqual(input.PolicyDocument, desired.document); assert.equal(input.SetAsDefault, true);
    live = state({ defaultVersionId: "v4", document: desired.document, versions: [...state().versions.map((version) => ({ ...version, isDefault: false })), { versionId: "v4", isDefault: true }] });
    return { PolicyVersion: { VersionId: "v4" } };
  } });
  assert.equal((await execute()).status, "COMPLETED"); assert.equal(writes, 1);
  assert.equal((await execute()).status, "CONSUMED"); assert.equal(writes, 1);
  assert.equal([...store.values.keys()].filter((key) => key.endsWith("terminal.json")).length, 1);
});

test("final CAS drift produces zero writes", async () => {
  for (const changed of [
    state({ defaultVersionId: "v2", versions: [{ versionId: "v2", isDefault: true }] }),
    state({ document: { Version: "2012-10-17", Statement: [] } }),
    state({ attachedRoles: [CONTRACT.releaseRoleName, "unexpected"] }),
  ]) {
    const prep = preparation(); const auth = authorization(prep); const store = memoryJournal(); let writes = 0; let reads = 0;
    await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: store.journal, reauthenticateSource: () => true, now: () => now, readLiveState: async () => reads++ === 0 ? state() : changed, createPolicyVersion: async () => { writes += 1; } }), /write boundary|invalid|drift/);
    assert.equal(writes, 0);
    assert.equal([...store.values.keys()].filter((key) => key.endsWith("write-attempt.json")).length, 1);
  }
});

test("ambiguous successful write is recovered without a second IAM write", async () => {
  const prep = preparation(); const auth = authorization(prep); const store = memoryJournal(); let live = state(); let writes = 0;
  const args = { sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: store.journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => live, createPolicyVersion: async () => {
    writes += 1; live = state({ defaultVersionId: "v4", document: desired.document, versions: [...state().versions.map((version) => ({ ...version, isDefault: false })), { versionId: "v4", isDefault: true }] }); throw new Error("response lost");
  } };
  assert.equal((await executeProviderReadonlyReconciliation(args)).status, "COMPLETED"); assert.equal(writes, 1);
  assert.equal((await executeProviderReadonlyReconciliation(args)).status, "CONSUMED"); assert.equal(writes, 1);
});

test("pre-state after a durable write attempt is ambiguous and never retried", async () => {
  const prep = preparation(); const auth = authorization(prep); const prov = provenance(auth); const store = memoryJournal();
  const reservation = journalIdentity("PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_RESERVATION", prep, auth, prov);
  await store.journal.create(auth, "reservation.json", reservation);
  await store.journal.create(auth, "write-attempt.json", { ...reservation, kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_WRITE_ATTEMPT" });
  let writes = 0;
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: store.journal, reauthenticateSource: () => true, now: () => now, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), (error) => error.mutationOutcome === "WRITE_OUTCOME_AMBIGUOUS");
  assert.equal(writes, 0);
});

test("production IAM reader authenticates complete version and attachment topology", () => {
  const calls = [];
  const run = (args) => {
    calls.push(args);
    if (args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: "v3", PermissionsBoundaryUsageCount: 0 } });
    if (args[1] === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: desired.predecessorDocument } });
    if (args[1] === "list-policy-versions") return JSON.stringify({ Versions: state().versions.map(({ versionId, isDefault }) => ({ VersionId: versionId, IsDefaultVersion: isDefault })) });
    if (args[1] === "list-entities-for-policy") return JSON.stringify({ PolicyRoles: [{ RoleName: CONTRACT.releaseRoleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false });
    throw new Error(args.join(" "));
  };
  assert.equal(authenticateProviderReadonlyLiveState(readProviderReadonlyLiveState(run), { desired }).status, "AUTHENTICATED_PRE_STATE");
  assert.deepEqual(calls.map((args) => args[1]), ["get-policy", "get-policy-version", "list-policy-versions", "list-entities-for-policy"]);
});

test("real prepare CLI performs only identity and IAM metadata reads", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-provider-readonly-prepare-")); fs.chmodSync(directory, 0o700);
  const calls = [];
  const run = (args) => {
    calls.push(args);
    if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" });
    if (args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: CONTRACT.policyArn, DefaultVersionId: "v3", PermissionsBoundaryUsageCount: 0 } });
    if (args[1] === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: desired.predecessorDocument } });
    if (args[1] === "list-policy-versions") return JSON.stringify({ Versions: state().versions.map(({ versionId, isDefault }) => ({ VersionId: versionId, IsDefaultVersion: isDefault })) });
    if (args[1] === "list-entities-for-policy") return JSON.stringify({ PolicyRoles: [{ RoleName: CONTRACT.releaseRoleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false });
    throw new Error(`unexpected prepare call ${args.join(" ")}`);
  };
  try {
    const result = await runProviderReadonlyReconciliation(["--mode", "prepare", "--source-sha", sourceSha, "--admin-profile", "fixture-admin", "--preparation-out", path.join(directory, "preparation.json")], { readProtectedCheckout: () => ({ toolingSha: sourceSha }), awsRun: run, now });
    assert.equal(result.iamWriteCount, 0);
    assert.deepEqual(calls.map((args) => `${args[0]}:${args[1]}`), ["sts:get-caller-identity", "iam:get-policy", "iam:get-policy-version", "iam:list-policy-versions", "iam:list-entities-for-policy"]);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("post-write verification rejects missing or broadened worker authority and frontend authority", async () => {
  const statements = desired.document.Statement;
  for (const document of [
    { ...desired.document, Statement: statements.filter(({ Sid }) => Sid !== "ReadExactStageBWorkerPublicationImage") },
    { ...desired.document, Statement: statements.map((statement) => statement.Sid === "ReadExactStageBWorkerPublicationImage" ? { ...statement, Resource: "*" } : statement) },
    { ...desired.document, Statement: [...statements, { Sid: "UnexpectedFrontend", Effect: "Allow", Action: "ecr:DescribeImages", Resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-frontend" }] },
  ]) {
    const prep = preparation(); const auth = authorization(prep); const store = memoryJournal(); let reads = 0;
    await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: store.journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => (++reads <= 2 ? state() : postState({ document })), createPolicyVersion: async () => ({ PolicyVersion: { VersionId: "v4" } }) }));
  }
});

test("CLI fails closed before credential construction on mode/source errors", async () => {
  let awsCalls = 0;
  await assert.rejects(() => runProviderReadonlyReconciliation([], { awsRun: () => { awsCalls += 1; } }), /--mode/);
  await assert.rejects(() => runProviderReadonlyReconciliation(["--mode", "prepare", "--source-sha", sourceSha, "--policy-arn", "arn:aws:iam::368992683803:policy/other"], { awsRun: () => { awsCalls += 1; } }), /arguments are not exact/);
  await assert.rejects(() => runProviderReadonlyReconciliation(["--mode", "execute", "--source-sha", sourceSha], { readProtectedCheckout: () => ({ toolingSha: "b".repeat(40) }), awsRun: () => { awsCalls += 1; } }), /protected source/);
  assert.equal(awsCalls, 0);
});

test("execution CLI is workflow-only and authenticates GitHub authorization before AWS credentials", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-provider-readonly-cli-")); fs.chmodSync(directory, 0o700);
  try {
    const prep = preparation(); const bytes = Buffer.from(`${JSON.stringify(prep, null, 2)}\n`); const prepPath = path.join(directory, "preparation.json"); fs.writeFileSync(prepPath, bytes, { mode: 0o600 });
    const events = [];
    const args = ["--mode", "execute", "--source-sha", sourceSha, "--preparation", prepPath, "--preparation-file-sha256", hash(bytes), "--authorization-workflow-run-id", "123", "--authorization-workflow-run-attempt", "1"];
    await assert.rejects(() => runProviderReadonlyReconciliation([...args, "--executor-profile", "forbidden"], { env: workflowEnvironment, readProtectedCheckout: () => ({ toolingSha: sourceSha }) }), /local executor profile/);
    await runProviderReadonlyReconciliation(args, { env: workflowEnvironment, readProtectedCheckout: () => ({ toolingSha: sourceSha }), resolveAuthorization: async () => { events.push("authorization"); return { authorization: authorization(prep), provenance: provenance(authorization(prep)) }; }, awsRun: (command) => { events.push("aws"); assert.equal(command[0], "sts"); return JSON.stringify({ Arn: `arn:aws:sts::368992683803:assumed-role/${CONTRACT.executorRoleName}/run` }); }, execute: async () => ({ status: "TEST", iamWriteCount: 0 }) });
    assert.deepEqual(events, ["authorization", "aws"]);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("authorization provenance is independently fetched and every forged dimension fails", async () => {
  const prep = preparation(); const auth = authorization(prep);
  const resolved = await resolveProviderReadonlyAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation: prep, run: await githubAuthorization(auth), now });
  assert.equal(resolved.provenance.status, "completed");
  for (const change of [
    { workflow: { path: ".github/workflows/other.yml" } }, { workflow: { head_sha: "b".repeat(40) } }, { workflow: { conclusion: "failure" } }, { workflow: { run_attempt: 2 } },
    { artifact: { name: "other" } }, { artifact: { workflow_run: { id: 999, head_sha: sourceSha, repository_id: 9 } } }, { archive: Buffer.from("changed") },
    { approvals: [{ state: "approved", environments: [{ id: 1, name: "production" }], user: { id: 3, login: "attacker" } }] },
  ]) {
    const run = await githubAuthorization(auth, change);
    await assert.rejects(() => resolveProviderReadonlyAuthorizationArtifact({ workflowRunId: "123", workflowRunAttempt: "1", sourceSha, preparation: prep, run, now }), /provenance|artifact|approval|digest|exact|invalid/i);
  }
});

test("expiry, source drift, forged records, and unexpected post-state all fail before duplicate mutation", async () => {
  const prep = preparation(); const auth = authorization(prep); const prov = provenance(auth);
  let writes = 0;
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: memoryJournal().journal, reauthenticateSource: () => true, now: () => new Date(new Date(prep.expiresAt).getTime() + 1), readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), /stale/);
  assert.equal(writes, 0);
  const sourceStore = memoryJournal(); let sourceChecks = 0;
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: sourceStore.journal, reauthenticateSource: () => { sourceChecks += 1; if (sourceChecks === 3) throw new Error("source drift"); }, now: () => now, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), /source drift/);
  assert.equal(writes, 0);
  const forged = memoryJournal();
  const key = `${CONTRACT.journalPrefix}${auth.operationId}/reservation.json`; forged.values.set(key, Buffer.from('{"kind":"forged"}\n'));
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: forged.journal, reauthenticateSource: () => true, now: () => now, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), /canonical|schema|match/);
  const altered = memoryJournal();
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: altered.journal, reauthenticateSource: () => { throw new Error("stop after reservation"); }, now: () => now, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), /stop after reservation/);
  const record = JSON.parse(altered.values.get(key)); delete record.recordSha256; record.currentDefaultVersionId = "v2"; record.recordSha256 = hash(record); altered.values.set(key, Buffer.from(`${canonicalJson(record)}\n`));
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: prov, journal: altered.journal, reauthenticateSource: () => true, now: () => now, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), /does not match/);
  assert.equal(writes, 0);
});

test("an expired zero-write reservation accepts only a fresh authorization for the same operation", async () => {
  const firstPreparation = preparation(); const firstAuthorization = authorization(firstPreparation); const firstProvenance = provenance(firstAuthorization); const store = memoryJournal();
  const reservation = journalIdentity("PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_RESERVATION", firstPreparation, firstAuthorization, firstProvenance);
  await store.journal.create(firstAuthorization, "reservation.json", reservation);
  const reservationKey = `${CONTRACT.journalPrefix}${firstPreparation.operationId}/reservation.json`; const originalReservation = Buffer.from(store.values.get(reservationKey));
  const refreshedAt = new Date(new Date(firstPreparation.expiresAt).getTime() + 1);
  const refreshedPreparation = createProviderReadonlyPreparation({ sourceSha, liveState: state(), desired, preparedAt: refreshedAt.toISOString() });
  const refreshedAuthorization = createProviderReadonlyAuthorization({ preparation: refreshedPreparation, protectedEnvironmentApprovalEvidence: approval({ workflowRunId: "124", observedAt: refreshedAt.toISOString() }), now: refreshedAt });
  assert.equal(firstPreparation.operationId, refreshedPreparation.operationId);
  assert.notEqual(firstPreparation.preparationSha256, refreshedPreparation.preparationSha256);
  assert.notEqual(firstAuthorization.authorizationSha256, refreshedAuthorization.authorizationSha256);
  let live = state(); let writes = 0;
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: firstPreparation, authorization: firstAuthorization, provenance: firstProvenance, journal: store.journal, reauthenticateSource: () => true, now: () => refreshedAt, readLiveState: async () => live, createPolicyVersion: async () => { writes += 1; } }), /stale/);
  const result = await executeProviderReadonlyReconciliation({ sourceSha, preparation: refreshedPreparation, authorization: refreshedAuthorization, provenance: provenance(refreshedAuthorization), journal: store.journal, reauthenticateSource: () => true, now: () => refreshedAt, sleep: async () => {}, readLiveState: async () => live, createPolicyVersion: async () => { writes += 1; live = postState(); return { PolicyVersion: { VersionId: "v4" } }; } });
  assert.equal(result.reservationMatch, "REFRESHED_AUTHORIZATION");
  assert.equal(writes, 1);
  assert.deepEqual(store.values.get(reservationKey), originalReservation);
  assert.equal(new Set([...store.values.keys()].map((key) => key.slice(0, key.lastIndexOf("/") + 1))).size, 1);
});

test("a completed logical operation cannot write again through a repeated preparation", async () => {
  const firstPreparation = preparation(); const firstAuthorization = authorization(firstPreparation); const store = memoryJournal(); let live = state(); let writes = 0;
  await executeProviderReadonlyReconciliation({ sourceSha, preparation: firstPreparation, authorization: firstAuthorization, provenance: provenance(firstAuthorization), journal: store.journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => live, createPolicyVersion: async () => { writes += 1; live = postState(); return { PolicyVersion: { VersionId: "v4" } }; } });
  const repeatedPreparation = createProviderReadonlyPreparation({ sourceSha, liveState: state(), desired, preparedAt: new Date(now.getTime() + 1).toISOString() });
  const repeatedAuthorization = createProviderReadonlyAuthorization({ preparation: repeatedPreparation, protectedEnvironmentApprovalEvidence: approval({ workflowRunId: "124", observedAt: new Date(now.getTime() + 1).toISOString() }), now: new Date(now.getTime() + 1) });
  assert.equal((await executeProviderReadonlyReconciliation({ sourceSha, preparation: repeatedPreparation, authorization: repeatedAuthorization, provenance: provenance(repeatedAuthorization), journal: store.journal, reauthenticateSource: () => true, now: () => new Date(now.getTime() + 1), readLiveState: async () => live, createPolicyVersion: async () => { writes += 1; } })).status, "CONSUMED");
  assert.equal(writes, 1);
});

test("crashes at reservation, successful write, and terminal persistence resume without a second IAM write", async () => {
  const prep = preparation(); const auth = authorization(prep); const prov = provenance(auth);
  const base = memoryJournal(); let reservationCrash = true; let live = state(); let writes = 0; let readsFail = false; let terminalRace = false;
  const journal = { read: base.journal.read, create: async (authorizationValue, record, body) => {
    const value = await base.journal.create(authorizationValue, record, body);
    if (record === "reservation.json" && reservationCrash) { reservationCrash = false; throw new Error("crash after reservation"); }
    if (record === "terminal.json" && terminalRace) { terminalRace = false; return false; }
    return value;
  } };
  const args = { sourceSha, preparation: prep, authorization: auth, provenance: prov, journal, reauthenticateSource: () => true, now: () => now, sleep: async () => {}, readLiveState: async () => { if (readsFail) throw new Error("read unavailable"); return live; }, createPolicyVersion: async () => { writes += 1; live = postState(); readsFail = true; throw new Error("response lost"); } };
  await assert.rejects(() => executeProviderReadonlyReconciliation(args), /crash after reservation/); assert.equal(writes, 0);
  await assert.rejects(() => executeProviderReadonlyReconciliation(args), /response lost/); assert.equal(writes, 1);
  readsFail = false; terminalRace = true;
  await assert.rejects(() => executeProviderReadonlyReconciliation(args), /terminal consumption raced/); assert.equal(writes, 1);
  assert.equal((await executeProviderReadonlyReconciliation(args)).status, "CONSUMED"); assert.equal(writes, 1);
});

test("zero-write reservation refresh rejects attempts and every incompatible authenticated binding", async () => {
  const firstPreparation = preparation(); const firstAuthorization = authorization(firstPreparation); const firstProvenance = provenance(firstAuthorization); const store = memoryJournal();
  const reservation = journalIdentity("PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_RESERVATION", firstPreparation, firstAuthorization, firstProvenance);
  await store.journal.create(firstAuthorization, "reservation.json", reservation);
  await store.journal.create(firstAuthorization, "write-attempt.json", { ...reservation, kind: "PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_WRITE_ATTEMPT" });
  const refreshedAt = new Date(now.getTime() + 1); const refreshedPreparation = createProviderReadonlyPreparation({ sourceSha, liveState: state(), desired, preparedAt: refreshedAt.toISOString() });
  const refreshedAuthorization = createProviderReadonlyAuthorization({ preparation: refreshedPreparation, protectedEnvironmentApprovalEvidence: approval({ workflowRunId: "124", observedAt: refreshedAt.toISOString() }), now: refreshedAt });
  let writes = 0;
  await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: refreshedPreparation, authorization: refreshedAuthorization, provenance: provenance(refreshedAuthorization), journal: store.journal, reauthenticateSource: () => true, now: () => refreshedAt, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; } }), /does not match/);
  assert.equal(writes, 0);

  for (const changed of [
    state({ defaultVersionId: "v2", versions: [{ versionId: "v2", isDefault: true }] }),
    state({ versions: [...state().versions, { versionId: "v4", isDefault: false }] }),
    state({ attachedRoles: [CONTRACT.releaseRoleName, "unexpected"] }),
  ]) {
    const zeroWriteStore = memoryJournal(); await zeroWriteStore.journal.create(firstAuthorization, "reservation.json", reservation);
    await assert.rejects(() => executeProviderReadonlyReconciliation({ sourceSha, preparation: refreshedPreparation, authorization: refreshedAuthorization, provenance: provenance(refreshedAuthorization), journal: zeroWriteStore.journal, reauthenticateSource: () => true, now: () => refreshedAt, readLiveState: async () => changed, createPolicyVersion: async () => { writes += 1; } }));
  }
  assert.equal(writes, 0);
});

test("concurrent fresh authorizations share one reservation and permit at most one policy version", async () => {
  const firstPreparation = preparation(); const firstAuthorization = authorization(firstPreparation); const store = memoryJournal();
  await store.journal.create(firstAuthorization, "reservation.json", journalIdentity("PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_RESERVATION", firstPreparation, firstAuthorization, provenance(firstAuthorization)));
  const refreshedAt = new Date(now.getTime() + 1); const refreshedPreparation = createProviderReadonlyPreparation({ sourceSha, liveState: state(), desired, preparedAt: refreshedAt.toISOString() });
  const makeAuthorization = (runId) => createProviderReadonlyAuthorization({ preparation: refreshedPreparation, protectedEnvironmentApprovalEvidence: approval({ workflowRunId: runId, observedAt: refreshedAt.toISOString() }), now: refreshedAt });
  const authorizations = [makeAuthorization("124"), makeAuthorization("125")]; let live = state(); let writes = 0;
  const settled = await Promise.allSettled(authorizations.map((auth) => executeProviderReadonlyReconciliation({ sourceSha, preparation: refreshedPreparation, authorization: auth, provenance: provenance(auth), journal: store.journal, reauthenticateSource: () => true, now: () => refreshedAt, sleep: async () => {}, readLiveState: async () => live, createPolicyVersion: async () => { writes += 1; live = postState(); return { PolicyVersion: { VersionId: "v4" } }; } })));
  assert.equal(writes, 1);
  assert.equal(settled.length, 2);
  assert.equal([...store.values.keys()].filter((key) => key.endsWith("write-attempt.json")).length, 1);
});

test("bounded convergence awaits exact delays, stops on success, and never retries the write", async () => {
  const prep = preparation(); const auth = authorization(prep); const store = memoryJournal(); const delays = []; let writes = 0; let reads = 0;
  const result = await executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: store.journal, reauthenticateSource: () => true, now: () => now, sleep: async (milliseconds) => { delays.push(milliseconds); }, readLiveState: async () => (++reads <= 5 ? state() : postState()), createPolicyVersion: async () => { writes += 1; return { PolicyVersion: { VersionId: "v4" } }; } });
  assert.equal(result.status, "COMPLETED");
  assert.deepEqual(delays, [100, 200, 400]);
  assert.equal(writes, 1);
  assert.ok([...CONTRACT.ambiguousWriteReadDelaysMs, ...CONTRACT.postWriteReadDelaysMs].every((delay) => Number.isSafeInteger(delay) && delay > 0 && delay <= 1000));

  const ambiguousStore = memoryJournal(); const ambiguousDelays = []; let ambiguousReads = 0; let ambiguousWrites = 0;
  const recovered = await executeProviderReadonlyReconciliation({ sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: ambiguousStore.journal, reauthenticateSource: () => true, now: () => now, sleep: async (milliseconds) => { ambiguousDelays.push(milliseconds); }, readLiveState: async () => (++ambiguousReads <= 4 ? state() : postState()), createPolicyVersion: async () => { ambiguousWrites += 1; throw new Error("response lost"); } });
  assert.equal(recovered.status, "COMPLETED");
  assert.deepEqual(ambiguousDelays, [100, 300]);
  assert.equal(ambiguousWrites, 1);
});

test("convergence exhaustion and timer failure remain ambiguous without another write", async () => {
  for (const timerFails of [false, true]) {
    const prep = preparation(); const auth = authorization(prep); const store = memoryJournal(); let writes = 0;
    const delays = []; const sleep = async (milliseconds) => { delays.push(milliseconds); if (timerFails) throw new Error("timer failed"); };
    const args = { sourceSha, preparation: prep, authorization: auth, provenance: provenance(auth), journal: store.journal, reauthenticateSource: () => true, now: () => now, sleep, readLiveState: async () => state(), createPolicyVersion: async () => { writes += 1; return { PolicyVersion: { VersionId: "v4" } }; } };
    await assert.rejects(() => executeProviderReadonlyReconciliation(args), (error) => error.mutationOutcome === "WRITE_OUTCOME_AMBIGUOUS");
    await assert.rejects(() => executeProviderReadonlyReconciliation(args));
    assert.equal(writes, 1);
    assert.deepEqual(delays, timerFails ? [100] : [100, 200, 400, 800, 1000]);
  }
});

test("production timer is asynchronous and the production CLI passes it explicitly", async () => {
  let settled = false; const sleeping = providerReadonlyProductionSleep(1).then(() => { settled = true; });
  await Promise.resolve(); assert.equal(settled, false); await sleeping; assert.equal(settled, true);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-provider-readonly-sleep-")); fs.chmodSync(directory, 0o700);
  try {
    const prep = preparation(); const bytes = Buffer.from(`${JSON.stringify(prep, null, 2)}\n`); const prepPath = path.join(directory, "preparation.json"); fs.writeFileSync(prepPath, bytes, { mode: 0o600 });
    await runProviderReadonlyReconciliation(["--mode", "execute", "--source-sha", sourceSha, "--preparation", prepPath, "--preparation-file-sha256", hash(bytes), "--authorization-workflow-run-id", "123", "--authorization-workflow-run-attempt", "1"], { env: workflowEnvironment, readProtectedCheckout: () => ({ toolingSha: sourceSha }), resolveAuthorization: async () => ({ authorization: authorization(prep), provenance: provenance(authorization(prep)) }), awsRun: () => JSON.stringify({ Arn: `arn:aws:sts::368992683803:assumed-role/${CONTRACT.executorRoleName}/run` }), execute: async ({ sleep }) => { assert.equal(sleep, providerReadonlyProductionSleep); return { status: "TEST", iamWriteCount: 0 }; } });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("workflow is authorization-only and target contract exposes no arbitrary policy input", () => {
  const workflowText = fs.readFileSync(CONTRACT.workflowPath, "utf8"); const workflow = yaml.load(workflowText);
  assert.equal(workflow.jobs.authorize.environment, "production");
  assert.match(workflowText, /--require-actual-approval/);
  assert.match(workflowText, /test "\$GITHUB_RUN_ATTEMPT" = "1"/);
  assert.equal((workflowText.match(/git status --porcelain=v1 --untracked-files=all/g) || []).length, 2);
  assert.doesNotMatch(workflowText, /configure-aws-credentials|create-policy-version|policy_arn|policy_document/);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs).sort(), ["preparation_file_sha256", "preparation_json_base64", "source_sha"]);
  const cli = fs.readFileSync("scripts/aws/reconcile-production-provider-readonly-policy.mjs", "utf8");
  assert.doesNotMatch(cli, /required\(argv, "--policy-(?:arn|document)"\)/);
  const executeWorkflow = fs.readFileSync(".github/workflows/execute-production-provider-readonly-policy-reconciliation.yml", "utf8");
  assert.match(executeWorkflow, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-initial-activation-policy-reconciler/);
  assert.equal((executeWorkflow.match(/git status --porcelain=v1 --untracked-files=all/g) || []).length, 2);
  assert.doesNotMatch(executeWorkflow, /policy_arn|policy_document|executor-profile/);
});

test("executor policy is exact and grants no deletion, default setter, or arbitrary IAM mutation", () => {
  const policy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json", "utf8"));
  const actions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  const targetCreate = policy.Statement.filter(({ Action, Resource }) => Action === "iam:CreatePolicyVersion" && Resource === CONTRACT.policyArn);
  assert.equal(targetCreate.length, 1);
  for (const forbidden of ["iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:CreatePolicy", "iam:AttachRolePolicy", "iam:*"]) assert.equal(actions.includes(forbidden), false);
  const readJournal = policy.Statement.find(({ Sid }) => Sid === "ReadExactProviderReadOnlyReconciliationJournal");
  const writeJournal = policy.Statement.find(({ Sid }) => Sid === "PersistExactProviderReadOnlyReconciliationJournal");
  assert.equal(readJournal.Action, "s3:GetObject");
  assert.equal(writeJournal.Action, "s3:PutObject");
  assert.deepEqual(writeJournal.Condition, { StringEquals: { "s3:if-none-match": "*", "s3:x-amz-server-side-encryption": "AES256" } });
  assert.equal(readJournal.Resource, `arn:aws:s3:::${CONTRACT.journalBucket}/${CONTRACT.journalPrefix}*`);
  assert.equal(writeJournal.Resource, readJournal.Resource);
});
