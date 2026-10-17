import test from "node:test";
import assert from "node:assert/strict";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyProductionOidcTrust,
  appOnlyVerifierBoundaryPolicy, appOnlyVerifierLauncherPolicy } from "../aws/production-app-only-policy.mjs";
import { APP_ONLY_BOUNDARY_RECONCILIATION, readAppOnlyBoundaryState, prepareAppOnlyBoundaryReconciliation,
  assertAppOnlyBoundaryPreparation, executeAppOnlyBoundaryReconciliation } from "../aws/production-app-only-boundary-reconciliation.mjs";
import { createAppOnlyAuthorization } from "../aws/production-app-only-authorization.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";

const sourceSha = "a".repeat(40), now = Date.parse("2026-10-17T00:00:00.000Z");
const verifierArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:1`;
const roleId = "AROAEXACTVERIFIER";

function iam({ boundary = "old", inline = "old", versionIds = ["v1"], loseCreate = false,
  losePut = false, rejectCreate = false, rejectPut = false, roleOverride = {} } = {}) {
  const state = { boundary, inline, versionIds: [...versionIds], calls: [], roleOverride };
  const run = (args) => {
    const op = args[1]; state.calls.push(op);
    const value = (old, current) => state.boundary === "old" ? old : current;
    const selectedInline = state.inline === "old" ? false : true;
    switch (op) {
      case "get-caller-identity": return { Account: APP_ONLY.account,
        Arn: `arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_BOUNDARY_RECONCILIATION.writerRole}/test` };
      case "get-policy": return { Policy: { Arn: APP_ONLY_BOUNDARY_RECONCILIATION.policyArn,
        PolicyName: "MSCQRProductionAppOnlyVerifierBoundary", Path: "/",
        DefaultVersionId: value("v1", state.versionIds.at(-1)), PermissionsBoundaryUsageCount: 1 } };
      case "list-policy-versions": return { Versions: state.versionIds.map((VersionId) => ({ VersionId,
        IsDefaultVersion: VersionId === value("v1", state.versionIds.at(-1)) })), IsTruncated: false };
      case "get-policy-version": return { PolicyVersion: { VersionId: value("v1", state.versionIds.at(-1)), IsDefaultVersion: true,
        Document: appOnlyVerifierBoundaryPolicy({ includeRotationSelectors: state.boundary !== "old" }) } };
      case "list-entities-for-policy": return { PolicyUsers: [], PolicyGroups: [], PolicyRoles: [{ RoleName: APP_ONLY_VERIFIER.roleName }], IsTruncated: false };
      case "get-role": return { Role: { Arn: APP_ONLY_BOUNDARY_RECONCILIATION.roleArn, RoleName: APP_ONLY_VERIFIER.roleName,
        Path: "/", MaxSessionDuration: 3600, PermissionsBoundary: { PermissionsBoundaryArn: APP_ONLY_BOUNDARY_RECONCILIATION.policyArn },
        AssumeRolePolicyDocument: appOnlyProductionOidcTrust(APP_ONLY_VERIFIER.roleName), RoleId: roleId, ...state.roleOverride } };
      case "list-attached-role-policies": return { AttachedPolicies: [], IsTruncated: false };
      case "list-role-policies": return { PolicyNames: [APP_ONLY_PROVISIONING.inlinePolicyName], IsTruncated: false };
      case "get-role-policy": return { RoleName: APP_ONLY_VERIFIER.roleName, PolicyName: APP_ONLY_PROVISIONING.inlinePolicyName,
        PolicyDocument: appOnlyVerifierLauncherPolicy(verifierArn, { includeRotationSelectors: selectedInline }) };
      case "create-policy-version":
        if (rejectCreate) throw new Error("AccessDenied");
        assert.equal(args[args.indexOf("--policy-arn") + 1], APP_ONLY_BOUNDARY_RECONCILIATION.policyArn);
        assert.deepEqual(JSON.parse(args[args.indexOf("--policy-document") + 1]), appOnlyVerifierBoundaryPolicy());
        assert.ok(args.includes("--set-as-default"));
        state.boundary = "new"; state.versionIds.push(`v${state.versionIds.length + 1}`);
        if (loseCreate) throw new Error("response lost");
        return { PolicyVersion: { VersionId: state.versionIds.at(-1) } };
      case "put-role-policy":
        if (rejectPut) throw new Error("AccessDenied");
        assert.equal(args[args.indexOf("--role-name") + 1], APP_ONLY_VERIFIER.roleName);
        assert.deepEqual(JSON.parse(args[args.indexOf("--policy-document") + 1]), appOnlyVerifierLauncherPolicy(verifierArn));
        state.inline = "new";
        if (losePut) throw new Error("response lost");
        return "";
      default: throw new Error(`Unexpected IAM operation: ${op}`);
    }
  };
  return { state, run };
}

function approved(preparation) {
  const approvedSourceSha = preparation.sourceSha;
  const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_SHA: approvedSourceSha,
    GITHUB_REF: "refs/heads/main", GITHUB_WORKFLOW_REF: APP_ONLY_BOUNDARY_RECONCILIATION.workflowRef,
    GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1", GITHUB_ACTOR: "operator" };
  const approval = createProductionEnvironmentApprovalEvidence({ sourceSha: approvedSourceSha, repository: env.GITHUB_REPOSITORY,
    environment: "production", workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME,
    workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT,
    executionActor: env.GITHUB_ACTOR, observedAt: new Date(now).toISOString(),
    environmentConfig: { id: 1, name: "production", can_admins_bypass: false,
      protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2, login: "reviewer" } }] }] },
    actualApproval: { state: "approved", environmentId: 1, environmentName: "production", userId: 2, userLogin: "reviewer" } });
  const authorization = createAppOnlyAuthorization({ phase: "BOUNDARY", preparation, approval, env, now });
  return { preparation, authorization, approval, env, now: () => now,
    authenticate: async () => {}, writeEvidence: async () => {} };
}

test("nine-selector boundary and inline policy reconcile once under exact approval", async () => {
  assert.equal(APP_ONLY_BOUNDARY_RECONCILIATION.oldBoundaryHash,
    "a528f7f13fb930cc78595371f1f3ddf84279bdec7e5422f64689ebde9c24fe0c");
  const aws = iam();
  const preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run: aws.run, now });
  assert.equal(preparation.predecessor.status, "PREDECESSOR");
  const events = [];
  const result = await executeAppOnlyBoundaryReconciliation({ ...approved(preparation), run: aws.run,
    writeEvidence: async (event) => events.push(event.status), sleep: () => {} });
  assert.deepEqual([result.status, result.createPolicyVersionCount, result.putRolePolicyCount], ["CONVERGED", 1, 1]);
  assert.deepEqual(events, ["BOUNDARY_VERSION_INTENT", "BOUNDARY_VERSION_VERIFIED", "VERIFIER_INLINE_INTENT", "BOUNDARY_AND_INLINE_VERIFIED"]);
  assert.deepEqual(["create-policy-version", "put-role-policy"].map((op) => aws.state.calls.filter((call) => call === op).length), [1, 1]);
  assert.equal(readAppOnlyBoundaryState(aws.run).status, "CONVERGED");
});

test("lost policy-version response is reconciled without a duplicate version", async () => {
  const aws = iam({ loseCreate: true, losePut: true });
  const preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run: aws.run, now });
  await executeAppOnlyBoundaryReconciliation({ ...approved(preparation), run: aws.run, sleep: () => {} });
  assert.deepEqual(aws.state.versionIds, ["v1", "v2"]);
  assert.equal(aws.state.calls.filter((op) => op === "put-role-policy").length, 1);
});

test("restart after boundary write requires a fresh exact preparation and approval", async () => {
  const aws = iam({ boundary: "new", inline: "old", versionIds: ["v1", "v2"] });
  const preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run: aws.run, now });
  const result = await executeAppOnlyBoundaryReconciliation({ ...approved(preparation), run: aws.run, sleep: () => {} });
  assert.deepEqual([result.createPolicyVersionCount, result.putRolePolicyCount], [0, 1]);
  assert.equal(aws.state.calls.includes("create-policy-version"), false);
});

test("future protected-main source has a distinct preparation and approval", async () => {
  const aws = iam(), futureSha = "c".repeat(40);
  const preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha: futureSha, run: aws.run, now });
  const authorized = approved(preparation);
  await executeAppOnlyBoundaryReconciliation({ ...authorized, run: aws.run, sleep: () => {} });
  assert.equal(readAppOnlyBoundaryState(aws.run).status, "CONVERGED");
  const oldSource = { ...authorized.env, GITHUB_SHA: sourceSha };
  await assert.rejects(executeAppOnlyBoundaryReconciliation({ ...authorized, env: oldSource, run: aws.run }));
});

test("expired, wrong-source, altered predecessor and changed IAM fail before writes", async () => {
  const aws = iam(), preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run: aws.run, now });
  assert.throws(() => assertAppOnlyBoundaryPreparation(preparation, { sourceSha, now: now + APP_ONLY.maxEvidenceAgeMs + 1 }), /expired/);
  assert.throws(() => assertAppOnlyBoundaryPreparation(preparation, { sourceSha: "b".repeat(40), now }));
  assert.throws(() => assertAppOnlyBoundaryPreparation({ ...preparation, predecessor: { ...preparation.predecessor, roleId: "FORGED" } }, { sourceSha, now }));
  aws.state.roleOverride = { RoleId: "OTHER" };
  await assert.rejects(executeAppOnlyBoundaryReconciliation({ ...approved(preparation), run: aws.run }), /predecessor changed/);
  assert.equal(aws.state.calls.includes("create-policy-version"), false);
});

test("failed or ambiguous mutation cannot retry automatically", async () => {
  for (const options of [{ rejectCreate: true }, { boundary: "new", inline: "old", versionIds: ["v1", "v2"], rejectPut: true }]) {
    const aws = iam(options), preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run: aws.run, now });
    await assert.rejects(executeAppOnlyBoundaryReconciliation({ ...approved(preparation), run: aws.run, sleep: () => {} }), /readback|outcome/);
    assert.equal(aws.state.calls.filter((op) => op === "create-policy-version").length, options.rejectCreate ? 1 : 0);
    assert.equal(aws.state.calls.filter((op) => op === "put-role-policy").length, options.rejectPut ? 1 : 0);
  }
});

test("concurrent managed-version replacement is not mistaken for this write", async () => {
  const aws = iam(), preparation = prepareAppOnlyBoundaryReconciliation({ sourceSha, run: aws.run, now });
  const run = (args) => {
    const result = aws.run(args);
    if (args[1] === "create-policy-version") aws.state.versionIds = ["v2", "v3"];
    return result;
  };
  await assert.rejects(executeAppOnlyBoundaryReconciliation({ ...approved(preparation), run, sleep: () => {} }), /readback/);
  assert.equal(aws.state.calls.filter((op) => op === "put-role-policy").length, 0);
});

test("managed-version quota, foreign role and unreviewed boundary fail closed", () => {
  const full = iam({ versionIds: ["v1", "v2", "v3", "v4", "v5"] });
  assert.throws(() => prepareAppOnlyBoundaryReconciliation({ sourceSha, run: full.run, now }), /version quota/);
  const foreign = iam({ roleOverride: { PermissionsBoundary: { PermissionsBoundaryArn: "arn:aws:iam::368992683803:policy/foreign" } } });
  assert.throws(() => readAppOnlyBoundaryState(foreign.run));
});
