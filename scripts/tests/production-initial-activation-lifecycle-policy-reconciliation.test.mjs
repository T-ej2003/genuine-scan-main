import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { INITIAL_ACTIVATION_POLICY_RECONCILIATION as CONTRACT, assertInitialActivationLifecyclePolicyReconciliationAuthorization, assertInitialActivationLifecyclePolicyState, buildInitialActivationLifecyclePolicyReconciliationResult, createInitialActivationLifecyclePolicyReconciliationAuthorization, executeInitialActivationLifecyclePolicyReconciliation, readInitialActivationLifecycleDesiredPolicy, resolveInitialActivationLifecyclePolicyReconciliationAuthorizationArtifact } from "../aws/production-initial-activation-policy-reconciliation.mjs";
import { readInitialActivationLifecyclePolicyLiveState } from "../aws/run-production-initial-activation-lifecycle-policy-reconciliation.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
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

test("approval freshness is enforced at artifact validation and immediately before the only write", () => {
  const observedAt = "2026-09-04T12:00:00.000Z";
  const boundary = new Date(new Date(observedAt).getTime() + PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs);
  const value = createInitialActivationLifecyclePolicyReconciliationAuthorization({ sourceSha, liveState: state(), protectedEnvironmentApprovalEvidence: approval(observedAt), desired, now: boundary });
  assert.doesNotThrow(() => assertInitialActivationLifecyclePolicyReconciliationAuthorization(value, { sourceSha, now: boundary }));
  let creates = 0;
  assert.throws(() => executeInitialActivationLifecyclePolicyReconciliation({ authorization: value, sourceSha, desired, now: new Date(boundary.getTime() + 1), readLiveState: () => state(), createPolicyVersion: () => { creates += 1; } }), /stale/);
  assert.equal(creates, 0);
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
