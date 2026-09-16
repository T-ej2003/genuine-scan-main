#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { APP_ONLY_PROVISIONING, APP_ONLY_VERIFIER, appOnlyCompatibilityReadPolicy, appOnlyDeployerPolicy, appOnlyVerifierBoundaryPolicy,
  appOnlyPermissionProvisionerPolicy, appOnlyProductionOidcTrust } from "./production-app-only-policy.mjs";
import { canonicalJson, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

export const APP_ONLY_BOOTSTRAP_ROOT = "infra/aws/terraform/production-app-only-permissions";

// Source-controlled installation only: no application task/service or production
// Terraform backend is part of this isolated root. The governed bootstrap must
// authenticate an exact six-resource create plan and preserve its local state.
export function appOnlyBootstrapTerraform() {
  return {
    terraform: { required_version: ">= 1.6.0, < 2.0.0", required_providers: { aws: { source: "hashicorp/aws", version: ">= 6.41.0, < 7.0" } } },
    provider: { aws: { region: APP_ONLY.region, allowed_account_ids: [APP_ONLY.account] } },
    resource: {
      aws_iam_policy: {
        deployer_boundary: { name: APP_ONLY_PROVISIONING.deployerBoundaryArn.split("/").at(-1), path: "/", policy: JSON.stringify(appOnlyDeployerPolicy()) },
        verifier_boundary: { name: APP_ONLY_PROVISIONING.verifierBoundaryArn.split("/").at(-1), path: "/", policy: JSON.stringify(appOnlyVerifierBoundaryPolicy()) },
      },
      aws_iam_role: {
        provisioner: { name: APP_ONLY_PROVISIONING.roleName, path: "/", max_session_duration: 3600,
          assume_role_policy: JSON.stringify(appOnlyProductionOidcTrust(APP_ONLY_PROVISIONING.roleName)) },
        verifier: { name: APP_ONLY_VERIFIER.roleName, path: "/", max_session_duration: 3600,
          assume_role_policy: JSON.stringify(appOnlyProductionOidcTrust(APP_ONLY_VERIFIER.roleName)), permissions_boundary: APP_ONLY_PROVISIONING.verifierBoundaryArn,
          depends_on: ["aws_iam_policy.verifier_boundary"] },
      },
      aws_iam_role_policy: { provisioner: { name: "app-only-bounded-provisioning", role: "${aws_iam_role.provisioner.name}",
        policy: JSON.stringify(appOnlyPermissionProvisionerPolicy()),
        depends_on: ["aws_iam_policy.deployer_boundary", "aws_iam_policy.verifier_boundary"] },
        verifier: { name: APP_ONLY_PROVISIONING.inlinePolicyName, role: "${aws_iam_role.verifier.name}", policy: JSON.stringify(appOnlyCompatibilityReadPolicy()) },
      },
    },
  };
}

export function verifyAppOnlyBootstrapSource(repositoryRoot) {
  const expected = `${JSON.stringify(appOnlyBootstrapTerraform(), null, 2)}\n`;
  assert.equal(fs.readFileSync(path.join(repositoryRoot, APP_ONLY_BOOTSTRAP_ROOT, "main.tf.json"), "utf8"), expected,
    "Generated app-only permission root differs from reviewed policy builders");
  return true;
}

// Bind the executable configuration, not only its resource diff. A plan with
// six apparently correct IAM creates can still hide a local-exec provisioner
// or substitute a provider endpoint. Terraform JSON expressions retain their
// literal interpolation plus references, unlike the equivalent HCL form.
export function appOnlyBootstrapPlanConfiguration() {
  const source = appOnlyBootstrapTerraform();
  return { provider_config: { aws: { name: "aws", full_name: "registry.terraform.io/hashicorp/aws",
    version_constraint: ">= 6.41.0, < 7.0.0", expressions: Object.fromEntries(Object.entries(source.provider.aws).map(([key, value]) => [key, { constant_value: value }])) } },
  root_module: { resources: Object.entries(source.resource).flatMap(([type, entries]) => Object.entries(entries).map(([name, fields]) => ({
    address: `${type}.${name}`, mode: "managed", type, name, provider_config_key: "aws", schema_version: 0,
    expressions: Object.fromEntries(Object.entries(fields).filter(([key]) => key !== "depends_on").map(([key, value]) => [key,
      { constant_value: value, ...(key === "role" ? { references: [`aws_iam_role.${name}.name`, `aws_iam_role.${name}`] } : {}) }])),
    ...(fields.depends_on ? { depends_on: fields.depends_on } : {}),
  }))) } };
}

export function assertAppOnlyBootstrapPlan(plan) {
  const source = appOnlyBootstrapTerraform();
  const expected = Object.entries(source.resource).flatMap(([type, resources]) => Object.entries(resources).map(([name, fields]) => ({ type, name, fields, address: `${type}.${name}` })));
  const changes = plan.resource_changes;
  assert.equal(plan.terraform_version, "1.15.8");
  assert.equal(plan.format_version, "1.2");
  assert.equal(plan.errored, false); assert.equal(plan.applyable, true); assert.equal(plan.complete, true);
  assert.equal((plan.checks || []).length, 0);
  assert.equal(Object.keys(plan.variables || {}).length, 0);
  assert.equal(Object.keys(plan.output_changes || {}).length, 0);
  assert.equal((plan.prior_state?.values?.root_module?.resources || []).length, 0, "Bootstrap cannot reuse an existing Terraform state");
  assert.equal((plan.prior_state?.values?.root_module?.child_modules || []).length, 0);
  const configuration = structuredClone(plan.configuration);
  assert.ok(Array.isArray(configuration?.root_module?.resources));
  configuration.root_module.resources.sort((a, b) => a.address.localeCompare(b.address));
  const expectedConfiguration = appOnlyBootstrapPlanConfiguration();
  expectedConfiguration.root_module.resources.sort((a, b) => a.address.localeCompare(b.address));
  assert.deepEqual(configuration, expectedConfiguration, "Bootstrap plan executable configuration is not exact");
  assert.ok(Array.isArray(changes));
  assert.deepEqual(changes.map((r) => r.address).sort(), expected.map((r) => r.address).sort(), "Bootstrap plan must contain exactly six IAM creates");
  assert.equal((plan.resource_drift || []).length, 0);
  assert.equal((plan.deferred_changes || []).length, 0);
  for (const spec of expected) {
    const resource = changes.find((r) => r.address === spec.address);
    assert.equal(resource.mode, "managed"); assert.equal(resource.type, spec.type); assert.equal(resource.name, spec.name);
    assert.equal(resource.provider_name, "registry.terraform.io/hashicorp/aws");
    assert.deepEqual(resource.change.actions, ["create"]); assert.equal(resource.change.before, null);
    const after = resource.change.after; assert.ok(after);
    for (const [field, desired] of Object.entries(spec.fields)) {
      if (field === "depends_on") continue;
      assert.ok(!resource.change.after_unknown?.[field], `Unknown bootstrap identity: ${spec.address}.${field}`);
      const value = field === "role" ? (spec.name === "verifier" ? APP_ONLY_VERIFIER.roleName : APP_ONLY_PROVISIONING.roleName)
        : field === "permissions_boundary" ? APP_ONLY_PROVISIONING.verifierBoundaryArn : desired;
      if (["policy", "assume_role_policy"].includes(field)) {
        assert.equal(canonicalJson(normalizeIamPolicyDocument(after[field], "Planned bootstrap policy")), canonicalJson(JSON.parse(value)));
      } else assert.deepEqual(after[field], value);
    }
    for (const field of ["tags", "tags_all"]) assert.equal(Object.keys(after[field] || {}).length, 0, "Bootstrap cannot add tag-based authority");
    if (spec.type === "aws_iam_role") {
      assert.equal(after.permissions_boundary ?? null, spec.name === "verifier" ? APP_ONLY_PROVISIONING.verifierBoundaryArn : null);
      assert.equal(after.force_detach_policies ?? false, false);
      assert.equal((after.managed_policy_arns || []).length, 0);
      assert.equal((after.inline_policy || []).length, 0);
    }
  }
  return { planSha256: canonicalSha256(plan), exactAddresses: expected.map((r) => r.address).sort(),
    maxAwsMutations: { "iam:CreatePolicy": 2, "iam:CreateRole": 2, "iam:PutRolePolicy": 2 } };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  assert.ok(process.argv.length === 2 || process.argv.length === 3 && process.argv[2] === "--write");
  if (process.argv[2] === "--write") {
    fs.mkdirSync(path.join(root, APP_ONLY_BOOTSTRAP_ROOT), { recursive: true });
    fs.writeFileSync(path.join(root, APP_ONLY_BOOTSTRAP_ROOT, "main.tf.json"), `${JSON.stringify(appOnlyBootstrapTerraform(), null, 2)}\n`);
  }
  verifyAppOnlyBootstrapSource(root);
  console.log("App-only isolated permission source verified; no AWS operations performed.");
}
