import test from "node:test";
import assert from "node:assert/strict";
import { APP_ONLY, APP_ONLY_DOMAINS } from "../aws/production-app-only-contract.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyCompatibilityReadPolicy, appOnlyDeployerPolicy, appOnlyVerifierBoundaryPolicy,
  appOnlyVerifierLauncherPolicy, appOnlyProductionOidcTrust } from "../aws/production-app-only-policy.mjs";
import { observeAppOnlyProvisioning, prepareAppOnlyProvisioning, executeAppOnlyProvisioning, verifyAppOnlyEffectivePermissions } from "../aws/production-app-only-provisioning.mjs";
const sourceSha = "a".repeat(40), now = Date.now();
const verifierArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:2`;

function fixture() {
  const roles = new Map(), policies = new Map(), calls = [], evidence = [];
  const boundaries = new Map([[APP_ONLY_PROVISIONING.deployerBoundaryArn, appOnlyDeployerPolicy()],
    [APP_ONLY_PROVISIONING.verifierBoundaryArn, appOnlyVerifierBoundaryPolicy()]]);
  const run = (args) => {
    calls.push(args); const field = (key) => args[args.indexOf(key) + 1], name = field("--role-name");
    switch (args[1]) {
      case "get-caller-identity": return { Account: APP_ONLY.account, Arn: `arn:aws:sts::${APP_ONLY.account}:assumed-role/${APP_ONLY_PROVISIONING.roleName}/test` };
      case "get-policy": assert.ok(boundaries.has(field("--policy-arn"))); return { Policy: { Arn: field("--policy-arn"), DefaultVersionId: "v1" } };
      case "get-policy-version": return { PolicyVersion: { VersionId: "v1", IsDefaultVersion: true, Document: boundaries.get(field("--policy-arn")) } };
      case "get-role": if (!roles.has(name)) throw new Error("NoSuchEntity"); return { Role: structuredClone(roles.get(name)) };
      case "list-attached-role-policies": return { AttachedPolicies: [] };
      case "list-role-policies": return { PolicyNames: policies.has(name) ? [APP_ONLY_PROVISIONING.inlinePolicyName] : [] };
      case "get-role-policy": return { RoleName: name, PolicyName: APP_ONLY_PROVISIONING.inlinePolicyName, PolicyDocument: policies.get(name) };
      case "create-role": {
        assert.ok(!roles.has(name));
        const role = { Arn: `arn:aws:iam::${APP_ONLY.account}:role/${name}`, RoleName: name, RoleId: `unique-${name}`, Path: field("--path"),
          MaxSessionDuration: Number(field("--max-session-duration")), PermissionsBoundary: { PermissionsBoundaryType: "Policy", PermissionsBoundaryArn: field("--permissions-boundary") },
          AssumeRolePolicyDocument: JSON.parse(field("--assume-role-policy-document")) };
        roles.set(name, role); return { Role: role };
      }
      case "put-role-policy": policies.set(name, JSON.parse(field("--policy-document"))); return {};
      default: assert.fail(`Unexpected API ${args[1]}`);
    }
  };
  const body = { schemaVersion: 1, kind: "APP_ONLY_DEPLOYMENT_PREPARATION", sourceSha, generatedAt: new Date(now).toISOString(), eligible: true,
    domains: Object.fromEntries(APP_ONLY_DOMAINS.map((domain) => [domain, "ALREADY_APPLIED_COMPATIBLE"])),
    evidence: Object.fromEntries(["images", "iam", "runtime", "database", "requirements", "verificationContractSha256"].map((key) => [key, "c".repeat(64)])) };
  const eligibility = { ...body, preparationSha256: canonicalSha256(body) };
  const input = { sourceSha, verifierArn, phase: "VERIFIER", run, now };
  const execution = (preparation) => ({ preparation, sourceSha, run, now: () => now, ...(preparation.phase === "DEPLOYER" ? { eligibility } : {}),
    authenticate: async () => {}, writeEvidence: async (item) => evidence.push(item), verifyEffective: async () => ({ verified: true }) });
  return { roles, policies, boundaries, calls, evidence, run, input, execution, eligibility };
}
const mutations = (f) => f.calls.filter((c) => ["create-role", "put-role-policy"].includes(c[1]));

test("separate provisioner installs only exact bounded roles/policies and reads back every write", async () => {
  const f = fixture(), prep = prepareAppOnlyProvisioning(f.input);
  const result = await executeAppOnlyProvisioning(f.execution(prep));
  assert.equal(result.status, "VERIFIED"); assert.equal(result.writesAttempted, 2);
  assert.equal(f.roles.has(APP_ONLY.roleArn.split("/").at(-1)), false, "Verifier phase cannot provision deployment permissions");
  const deployment = prepareAppOnlyProvisioning({ ...f.input, phase: "DEPLOYER", eligibility: f.eligibility });
  await executeAppOnlyProvisioning(f.execution(deployment));
  assert.deepEqual(mutations(f).map((c) => c[1]), ["create-role", "put-role-policy", "create-role", "put-role-policy"]);
  assert.deepEqual(f.policies.get(APP_ONLY.roleArn.split("/").at(-1)), appOnlyDeployerPolicy());
  assert.deepEqual(f.policies.get(APP_ONLY_VERIFIER.roleName), appOnlyVerifierLauncherPolicy(verifierArn));
  for (const role of f.roles.values()) assert.deepEqual(role.AssumeRolePolicyDocument, appOnlyProductionOidcTrust());
  assert.equal(f.evidence.at(-1).status, "VERIFIED");
  const before = mutations(f).length;
  await executeAppOnlyProvisioning(f.execution(prepareAppOnlyProvisioning(f.input)));
  assert.equal(mutations(f).length, before, "Already exact provisioning must not repeat IAM writes");
});

test("wrong source, stale preparation, failed approval and changed outer boundary stop before writes", async () => {
  for (const mutate of [
    (f, args) => { args.sourceSha = "b".repeat(40); },
    (f, args) => { args.now = () => now + APP_ONLY.maxEvidenceAgeMs + 1; },
    (f, args) => { args.authenticate = async () => { throw new Error("Missing protected approval"); }; },
    (f) => { f.boundaries.get(APP_ONLY_PROVISIONING.deployerBoundaryArn).Statement[0].Resource = "*"; },
  ]) {
    const f = fixture(), args = f.execution(prepareAppOnlyProvisioning(f.input)); mutate(f, args);
    await assert.rejects(executeAppOnlyProvisioning(args)); assert.equal(mutations(f).length, 0);
  }
});

test("unexpected predecessor trust/boundary/policy cannot be silently repaired", async () => {
  for (const mutate of [
    (f) => { f.roles.get(APP_ONLY_VERIFIER.roleName).PermissionsBoundary.PermissionsBoundaryArn = APP_ONLY_PROVISIONING.deployerBoundaryArn; },
    (f) => { f.roles.get(APP_ONLY_VERIFIER.roleName).AssumeRolePolicyDocument.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] = "repo:other:environment:production"; },
    (f) => { f.policies.get(APP_ONLY_VERIFIER.roleName).Statement.push({ Effect: "Allow", Action: "ecs:UpdateService", Resource: "*" }); },
  ]) {
    const f = fixture(); await executeAppOnlyProvisioning(f.execution(prepareAppOnlyProvisioning(f.input)));
    const count = mutations(f).length; mutate(f);
    assert.throws(() => observeAppOnlyProvisioning(f.input)); assert.equal(mutations(f).length, count);
  }
});

test("verifier revision changes replace only exact launcher policy and never recreate roles", async () => {
  const f = fixture();
  f.input.verifierArn = verifierArn.replace(/:2$/, ":1");
  await executeAppOnlyProvisioning(f.execution(prepareAppOnlyProvisioning(f.input)));
  const count = mutations(f).length; f.input.verifierArn = verifierArn;
  await executeAppOnlyProvisioning(f.execution(prepareAppOnlyProvisioning(f.input)));
  assert.deepEqual(mutations(f).slice(count).map((c) => c[1]), ["put-role-policy"]);
});

test("bootstrap read-only verifier transitions to one reviewed launch revision without provisioning app authority", async () => {
  const f = fixture();
  await executeAppOnlyProvisioning(f.execution(prepareAppOnlyProvisioning(f.input)));
  f.policies.set(APP_ONLY_VERIFIER.roleName, appOnlyCompatibilityReadPolicy());
  const count = mutations(f).length;
  await executeAppOnlyProvisioning(f.execution(prepareAppOnlyProvisioning(f.input)));
  assert.deepEqual(mutations(f).slice(count).map((c) => c[1]), ["put-role-policy"]);
  assert.equal(f.roles.has(APP_ONLY.roleArn.split("/").at(-1)), false);
  assert.deepEqual(f.policies.get(APP_ONLY_VERIFIER.roleName), appOnlyVerifierLauncherPolicy(verifierArn));
});

test("ambiguous IAM writes preserve durable intent and never automatically retry", async () => {
  const f = fixture(), args = f.execution(prepareAppOnlyProvisioning(f.input));
  args.run = (command) => { const result = f.run(command); if (command[1] === "create-role") throw new Error("Timed out after AWS accepted request"); return result; };
  await assert.rejects(executeAppOnlyProvisioning(args), /do not retry/);
  assert.equal(mutations(f).length, 1); assert.equal(f.roles.size, 1);
  assert.deepEqual(f.evidence.map((e) => e.status), ["PRE_MUTATION", "CREATE_ROLE_INTENT", "PROVISIONING_OUTCOME_REQUIRES_READBACK"]);
});

test("failed effective permission verification cannot claim successful provisioning", async () => {
  const f = fixture(), args = f.execution(prepareAppOnlyProvisioning(f.input));
  args.verifyEffective = async () => ({ verified: false });
  await assert.rejects(executeAppOnlyProvisioning(args));
  assert.equal(f.evidence.at(-1).status, "PROVISIONING_OUTCOME_REQUIRES_READBACK");
});

test("effective verification checks fixed positive and negative scopes and rejects incomplete simulation", () => {
  const predecessorArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:14`;
  const calls = [];
  const run = (args) => {
    calls.push(args); const value = (key) => args[args.indexOf(key) + 1];
    assert.deepEqual(args.slice(0, 2), ["iam", "simulate-principal-policy"]);
    const action = value("--action-names"), resource = value("--resource-arns"), role = value("--policy-source-arn");
    const ctx = Object.fromEntries(JSON.parse(value("--context-entries")).map((e) => [e.ContextKeyName, e.ContextKeyValues[0]]));
    const isApp = role === APP_ONLY.roleArn;
    assert.equal(action, action.toLowerCase());
    const allowed = isApp ? action === "ecs:updateservice" && resource === APP_ONLY.serviceArn && ctx["ecs:cluster"] === APP_ONLY.clusterArn && ctx["ecs:task-definition"].includes(`/${APP_ONLY.family}:`)
      || action === "ecs:registertaskdefinition" && resource.includes(`/${APP_ONLY.family}:`)
      || action === "iam:passrole" && [APP_ONLY.taskRoleArn, APP_ONLY.executionRoleArn].includes(resource) && ctx["iam:PassedToService"] === "ecs-tasks.amazonaws.com"
      : action === "ecs:runtask" && resource === verifierArn && ctx["ecs:cluster"] === APP_ONLY.clusterArn;
    return { EvaluationResults: [{ EvalActionName: action, EvalResourceName: resource, EvalDecision: allowed ? "allowed" : "implicitDeny",
      MissingContextValues: [], PermissionsBoundaryDecisionDetail: { AllowedByPermissionsBoundary: allowed } }] };
  };
  const result = verifyAppOnlyEffectivePermissions({ run, verifierArn, predecessorArn, phase: "DEPLOYER" });
  assert.equal(result.verified, true); assert.equal(result.observations.length, 15);
  const verifier = verifyAppOnlyEffectivePermissions({ run, verifierArn, predecessorArn, phase: "VERIFIER" });
  assert.equal(verifier.observations.length, 4);
  assert.ok(verifier.observations.every((o) => o.roleArn !== APP_ONLY.roleArn));
  assert.ok(result.observations.some((o) => o.id === "app-state-write" && o.resource.includes("mscqr-production-terraform-state")));
  for (const mutate of [
    (r) => { r.IsTruncated = true; },
    (r) => { r.EvaluationResults[0].MissingContextValues = ["ecs:cluster"]; },
    (r) => { r.EvaluationResults[0].EvalResourceName = "*"; },
    (r) => { r.EvaluationResults[0].EvalDecision = "implicitDeny"; },
    (r) => { r.EvaluationResults[0].PermissionsBoundaryDecisionDetail.AllowedByPermissionsBoundary = false; },
  ]) assert.throws(() => verifyAppOnlyEffectivePermissions({ run: (args) => { const result = run(args); mutate(result); return result; }, verifierArn, predecessorArn, phase: "DEPLOYER" }));
});

test("provisioning phase and deployment eligibility cannot be omitted or substituted", async () => {
  const f = fixture();
  for (const phase of [undefined, "BOTH", "DEPLOYER"])
    assert.throws(() => prepareAppOnlyProvisioning({ ...f.input, phase }));
  const preparation = prepareAppOnlyProvisioning({ ...f.input, phase: "DEPLOYER", eligibility: f.eligibility });
  for (const change of [
    (e) => { e.sourceSha = "b".repeat(40); },
    (e) => { e.eligible = false; },
    (e) => { e.domains.RLS = "INCOMPATIBLE_OR_UNPROVEN"; },
    (e) => { e.generatedAt = new Date(now - APP_ONLY.maxEvidenceAgeMs - 1).toISOString(); },
    (e) => { e.evidence.database = "d".repeat(64); },
  ]) {
    const eligibility = structuredClone(f.eligibility); change(eligibility);
    const { preparationSha256: _ignored, ...body } = eligibility;
    eligibility.preparationSha256 = canonicalSha256(body);
    await assert.rejects(executeAppOnlyProvisioning({ ...f.execution(preparation), eligibility }));
  }
  assert.equal(mutations(f).length, 0);
});
