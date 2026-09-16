import test from "node:test";
import assert from "node:assert/strict";
import { appOnlyBootstrapTerraform, appOnlyBootstrapPlanConfiguration, assertAppOnlyBootstrapPlan, verifyAppOnlyBootstrapSource } from "../aws/generate-production-app-only-infrastructure.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER } from "../aws/production-app-only-policy.mjs";
import { createAppOnlyBootstrapPreparation, assertAppOnlyBootstrapInputs, assertAppOnlyBootstrapAbsent, appOnlyBytesSha256 } from "../aws/production-app-only-bootstrap-contract.mjs";
import { parseAppOnlyBootstrapArgs, verifyAppOnlyBootstrapReadback } from "../aws/run-production-app-only-bootstrap.mjs";
function fixture() {
  return { terraform_version: "1.15.8", format_version: "1.2", errored: false, applyable: true, complete: true,
    configuration: appOnlyBootstrapPlanConfiguration(), resource_changes: Object.entries(appOnlyBootstrapTerraform().resource).flatMap(([type, resources]) => Object.entries(resources).map(([name, fields]) => {
    const after = structuredClone(fields); delete after.depends_on;
    if (type === "aws_iam_role_policy") after.role = name === "verifier" ? APP_ONLY_VERIFIER.roleName : APP_ONLY_PROVISIONING.roleName;
    if (type === "aws_iam_role" && name === "verifier") after.permissions_boundary = APP_ONLY_PROVISIONING.verifierBoundaryArn;
    return { address: `${type}.${name}`, mode: "managed", type, name, provider_name: "registry.terraform.io/hashicorp/aws",
      change: { before: null, after, actions: ["create"], after_unknown: {} } };
  })) };
}
test("bootstrap binds exact saved bytes, generated source and fresh create-only predecessor", () => {
  const repositoryRoot = process.cwd(), sourceSha = "a".repeat(40), now = Date.now();
  const planBytes = Buffer.from("opaque saved Terraform plan fixture"), planJsonBytes = Buffer.from(JSON.stringify(fixture()));
  const preparation = createAppOnlyBootstrapPreparation({ repositoryRoot, sourceSha, generatedAt: new Date(now).toISOString(),
    callerArn: "arn:aws:iam::368992683803:user/reviewed-bootstrap-operator", planSha256: appOnlyBytesSha256(planBytes), planJsonSha256: appOnlyBytesSha256(planJsonBytes) });
  const input = { preparation, repositoryRoot, sourceSha, planBytes, planJsonBytes, now };
  assert.equal(assertAppOnlyBootstrapInputs(input), true);
  for (const field of ["planBytes", "planJsonBytes"]) assert.throws(() => assertAppOnlyBootstrapInputs({ ...input, [field]: Buffer.from("substituted") }));
  assert.throws(() => assertAppOnlyBootstrapInputs({ ...input, sourceSha: "f".repeat(40) }));
  assert.throws(() => assertAppOnlyBootstrapInputs({ ...input, now: now + 16 * 60 * 1000 }));
  assert.throws(() => assertAppOnlyBootstrapInputs({ ...input, preparation: { ...preparation, predecessor: "EXISTS" } }));
  let calls = 0;
  assertAppOnlyBootstrapAbsent(() => { calls++; const error = new Error("not found"); error.stderr = "NoSuchEntity"; throw error; });
  assert.equal(calls, 4);
  assert.throws(() => assertAppOnlyBootstrapAbsent(() => "{}"));
  assert.throws(() => assertAppOnlyBootstrapAbsent(() => { const error = new Error("NoSuchEntity in untrusted message"); error.stderr = "AccessDenied"; throw error; }));
});
test("isolated bootstrap installs bounded read-only verifier and separate provisioner, not an app deployer or state backend", () => {
  assert.equal(verifyAppOnlyBootstrapSource(process.cwd()), true);
  const root = appOnlyBootstrapTerraform();
  assert.equal(root.terraform.backend, undefined);
  assert.deepEqual(Object.keys(root.resource).sort(), ["aws_iam_policy", "aws_iam_role", "aws_iam_role_policy"]);
  const result = assertAppOnlyBootstrapPlan(fixture());
  assert.deepEqual(result.maxAwsMutations, { "iam:CreatePolicy": 2, "iam:CreateRole": 2, "iam:PutRolePolicy": 2 });
  const initial = JSON.parse(root.resource.aws_iam_role_policy.verifier.policy);
  assert.ok(initial.Statement.every((s) => ![].concat(s.Action).includes("ecs:RunTask")));
});

test("bootstrap CLI accepts no arbitrary Terraform command, resource, output root or state backend", () => {
  const args = ["--mode", "prepare", "--source-sha", "a".repeat(40), "--admin-profile", "reviewed-bootstrap"];
  assert.equal(parseAppOnlyBootstrapArgs(args).mode, "prepare");
  for (const key of ["--command", "--target", "--root", "--backend", "--role", "--auto-approve", "--plan"])
    assert.throws(() => parseAppOnlyBootstrapArgs([...args, key, "attacker"]));
  assert.throws(() => parseAppOnlyBootstrapArgs([...args.slice(0, -1), "$(id)"]));
});

test("bootstrap live readback requires exact policies, trust, boundaries and zero unexpected attachments", () => {
  const source = appOnlyBootstrapTerraform();
  const reader = (mutate = () => {}) => (args) => {
    const option = (name) => args[args.indexOf(name) + 1];
    const roleName = option("--role-name"), policyArn = option("--policy-arn");
    const roleEntry = Object.entries(source.resource.aws_iam_role).find(([, r]) => r.name === roleName);
    const policy = Object.values(source.resource.aws_iam_policy).find((p) => policyArn?.endsWith(`/${p.name}`));
    let result;
    switch (args[1]) {
      case "get-policy": result = { Policy: { Arn: policyArn, PolicyName: policy.name, Path: "/", DefaultVersionId: "v1", AttachmentCount: 0 } }; break;
      case "list-policy-versions": result = { Versions: [{ VersionId: "v1", IsDefaultVersion: true }] }; break;
      case "get-policy-version": result = { PolicyVersion: { VersionId: "v1", IsDefaultVersion: true, Document: JSON.parse(policy.policy) } }; break;
      case "get-role": result = { Role: { Arn: `arn:aws:iam::368992683803:role/${roleName}`, RoleName: roleName, Path: "/", MaxSessionDuration: 3600,
        AssumeRolePolicyDocument: JSON.parse(roleEntry[1].assume_role_policy), ...(roleEntry[1].permissions_boundary ? { PermissionsBoundary: { PermissionsBoundaryArn: roleEntry[1].permissions_boundary, PermissionsBoundaryType: "Policy" } } : {}) } }; break;
      case "list-attached-role-policies": result = { AttachedPolicies: [] }; break;
      case "list-role-policies": result = { PolicyNames: [source.resource.aws_iam_role_policy[roleEntry[0]].name] }; break;
      case "get-role-policy": result = { RoleName: roleName, PolicyName: option("--policy-name"), PolicyDocument: JSON.parse(source.resource.aws_iam_role_policy[roleEntry[0]].policy) }; break;
      default: assert.fail("Readback must not call mutation APIs");
    }
    mutate(result); return JSON.stringify(result);
  };
  assert.deepEqual(verifyAppOnlyBootstrapReadback(reader()), { verified: true, resources: 6 });
  for (const mutate of [
    (r) => { if (r.Policy) r.Policy.DefaultVersionId = "v2"; },
    (r) => { if (r.PolicyVersion) r.PolicyVersion.Document.Statement = []; },
    (r) => { if (r.Role) r.Role.MaxSessionDuration = 43200; },
    (r) => { if (r.AttachedPolicies) r.AttachedPolicies.push({ PolicyArn: "unreviewed" }); },
    (r) => { if (r.PolicyNames) r.IsTruncated = true; },
    (r) => { if (r.PolicyDocument) r.PolicyDocument.Statement = []; },
  ]) assert.throws(() => verifyAppOnlyBootstrapReadback(reader(mutate)));
});
test("bootstrap rejects replacement, update, unrelated resources, policy substitution, unknown identity and extra grants", () => {
  for (const mutate of [
    (p) => { p.configuration.root_module.resources[0].provisioners = [{ type: "local-exec", expressions: { command: { constant_value: "unreviewed" } } }]; },
    (p) => { p.configuration.provider_config.aws.expressions.endpoints = [{ iam: { constant_value: "https://untrusted.invalid" } }]; },
    (p) => { p.configuration.root_module.module_calls = { hidden: {} }; },
    (p) => { p.configuration.root_module.resources[0].provider_config_key = "untrusted"; },
    (p) => { p.configuration.root_module.resources[0].expressions.policy = { constant_value: "untrusted" }; },
    (p) => { p.complete = false; },
    (p) => { p.prior_state = { values: { root_module: { resources: [{}] } } }; },
    (p) => { p.terraform_version = "unreviewed"; },
    (p) => { p.resource_changes[0].change.actions = ["update"]; },
    (p) => { p.resource_changes[0].change.actions = ["delete", "create"]; },
    (p) => { p.resource_changes[0].change.before = {}; },
    (p) => { p.resource_changes[0].change.after.name = "UnrelatedPolicy"; },
    (p) => { p.resource_changes[0].change.after_unknown.policy = true; },
    (p) => { p.resource_changes[0].change.after.policy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }] }); },
    (p) => { p.resource_changes[0].change.after.tags = { Admin: "true" }; },
    (p) => { p.resource_changes[2].change.after.managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]; },
    (p) => { p.resource_changes[3].change.after.permissions_boundary = APP_ONLY_PROVISIONING.deployerBoundaryArn; },
    (p) => { p.resource_changes.push(structuredClone(p.resource_changes[0])); },
    (p) => { p.resource_changes.pop(); },
    (p) => { p.resource_drift = [{}]; },
    (p) => { p.deferred_changes = [{}]; },
  ]) { const plan = fixture(); mutate(plan); assert.throws(() => assertAppOnlyBootstrapPlan(plan)); }
});
