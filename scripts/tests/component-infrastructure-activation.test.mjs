import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertBackend, assertInitialPlan, assertAuthorization, assertEnvironment, contract, stack, run, hash } from "../aws/component-infrastructure-activation.mjs";

const backend = () => ({ type: "s3", config: { ...contract, allowed_account_ids: [contract.account] } });
const readPolicy = (name) => fs.readFileSync(`${stack}/${name}.json`, "utf8");
const plan = () => {
  const values = {
    "aws_dynamodb_table.component_deployment_state": { name: "mscqr-production-component-deployment-state", hash_key: "stateKey", billing_mode: "PAY_PER_REQUEST", server_side_encryption: [{ enabled: true }], point_in_time_recovery: [{ enabled: true }] },
    "aws_iam_role.normal_deployer": { name: "mscqr-production-normal-deployer", path: "/", max_session_duration: 3600, assume_role_policy: readPolicy("normal-deployer-trust-policy") },
    "aws_iam_role.bootstrap": { name: "mscqr-production-component-state-bootstrap", path: "/", max_session_duration: 3600, assume_role_policy: readPolicy("bootstrap-trust-policy") },
    "aws_iam_role_policy.normal_deployer": { name: "MSCQRProductionNormalDeployment", policy: readPolicy("normal-deployer-policy") },
    "aws_iam_role_policy.bootstrap": { name: "MSCQRProductionComponentStateBootstrap", policy: readPolicy("bootstrap-policy") },
    "aws_iam_role_policy.release_terminal_state": { name: "MSCQRProductionComponentStateTerminalWriter", role: "mscqr-production-release-deployer", policy: readPolicy("release-terminal-state-policy") },
  };
  return {
    errored: false, applyable: true,
    configuration: { provider_config: { aws: { full_name: "registry.terraform.io/hashicorp/aws", expressions: { allowed_account_ids: { constant_value: [contract.account] }, region: { constant_value: contract.region } } } }, root_module: { resources: ["normal_deployer", "bootstrap"].map((name) => ({ address: `aws_iam_role_policy.${name}`, expressions: { role: { references: [`aws_iam_role.${name}.id`, `aws_iam_role.${name}`] } } })) } },
    resource_changes: contract.expectedManagedAddresses.map((address) => ({ address, mode: "managed", change: { actions: ["create"], after: values[address] } })),
  };
};
test("fixed backend never accepts local state, other keys, bucket, account, region or workspace", () => {
  assertBackend(backend(), "default");
  for (const [field, value] of [["bucket", "other"], ["key", "mscqr/production/rls-green/stage-a/terraform.tfstate"], ["region", "eu-west-1"], ["allowed_account_ids", ["000000000000"]], ["use_lockfile", false], ["encrypt", false]]) {
    const changed = backend(); changed.config[field] = value;
    assert.throws(() => assertBackend(changed, "default"));
  }
  assert.throws(() => assertBackend({ ...backend(), type: "local" }, "default"));
  assert.throws(() => assertBackend(backend(), "production"));
  const versions = fs.readFileSync(`${stack}/versions.tf`, "utf8");
  assert.match(versions, /backend "s3"/);
  assert(versions.includes(`key                 = "${contract.key}"`));
  assert.equal(contract.key, "mscqr/production/component-deployment-state/terraform.tfstate");
});
test("only the six initial creates can be authorized", () => {
  assertInitialPlan(plan());
  for (const actions of [["update"], ["delete", "create"], ["no-op"]]) {
    const changed = plan(); changed.resource_changes[0].change.actions = actions;
    assert.throws(() => assertInitialPlan(changed));
  }
  const changed = plan(); changed.resource_changes.push({ address: "aws_iam_role.unrelated", mode: "managed", change: { actions: ["create"] } });
  assert.throws(() => assertInitialPlan(changed));
  const wrongTrust = plan();
  wrongTrust.resource_changes.find(({address}) => address === "aws_iam_role.normal_deployer").change.after.assume_role_policy = '{}';
  assert.throws(() => assertInitialPlan(wrongTrust));
  const wrongProvider = plan(); wrongProvider.configuration.provider_config.aws.expressions.region.constant_value = "eu-west-1";
  assert.throws(() => assertInitialPlan(wrongProvider));
});
test("authorization binds exact source, plan bytes, preparation and absent remote state", () => {
  const binding = { sourceSha: "a".repeat(40), planSha256: "b".repeat(64), preparationSha256: "c".repeat(64) };
  const preparation = { sourceSha: binding.sourceSha, planSha256: binding.planSha256, backend: contract, stateIdentity: "ABSENT" };
  assertAuthorization(binding, preparation, binding);
  assert.throws(() => assertAuthorization(null, preparation, binding));
  for (const field of Object.keys(binding)) assert.throws(() => assertAuthorization({ ...binding, [field]: "d".repeat(64) }, preparation, binding));
  assert.throws(() => assertAuthorization(binding, { ...preparation, stateIdentity: "changed" }, binding));
});
test("environment requires exact main branch and independent real reviewer without bypass", () => {
  const config = { can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1 } }] }] };
  const branches = { branch_policies: [{ name: "main", type: "branch" }] };
  assertEnvironment(config, branches);
  assert.throws(() => assertEnvironment({ ...config, can_admins_bypass: true }, branches));
  assert.throws(() => assertEnvironment(config, { branch_policies: [{ name: "main", type: "tag" }] }));
  assert.throws(() => assertEnvironment(config, { branch_policies: [...branches.branch_policies, { name: "*", type: "branch" }] }));
});

function installation(t, { changedSource = false, changedPlan = false, existingState = false, replay = false, approval = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "component-install-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true }));
  const calls = [];
  const sourceSha = "a".repeat(40);
  let applying = false;
  const config = { id: 20, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 2 } }] }] };
  const branches = { branch_policies: [{ name: "main", type: "branch" }] };
  const execute = (name, args, { env }) => {
    calls.push([name, ...args]);
    let value;
    if (name === "git") {
      if (args[0] === "rev-parse") return sourceSha;
      if (args[0] === "ls-files") return fs.readdirSync(stack).filter((file) => /\.tf$/.test(file)).map((file) => `${stack}/${file}`).join("\n");
      return "";
    }
    if (name === "gh") {
      const endpoint = args[1];
      if (args[0] === "run") {
        const preparationPath = path.join(dir, "preparation.json");
        const preparation = JSON.parse(fs.readFileSync(preparationPath));
        fs.writeFileSync(path.join(args.at(-1), "authorization.json"), JSON.stringify({ sourceSha, planSha256: preparation.planSha256, preparationSha256: hash(fs.readFileSync(preparationPath)) }));
        return "";
      }
      if (endpoint.endsWith("branches/main")) value = { commit: { sha: applying && changedSource ? "b".repeat(40) : sourceSha } };
      else if (endpoint.endsWith("deployment-branch-policies")) value = branches;
      else if (endpoint.includes("/environments/")) value = config;
      else if (endpoint.endsWith("/approvals")) value = approval ? [{ state: "approved", environments: [{ id: 20 }], user: { id: 2 } }] : [];
      else value = { path: ".github/workflows/authorize-component-infrastructure-activation.yml", head_sha: sourceSha, head_branch: "main", head_repository: { full_name: "T-ej2003/genuine-scan-main" }, event: "workflow_dispatch", conclusion: "success", run_attempt: 1, created_at: new Date().toISOString(), actor: { id: 1 } };
    } else if (name === "aws") {
      if (["iam", "dynamodb"].includes(args[0])) throw Object.assign(new Error("Missing"), { stderr: `(${args[0] === "iam" ? "NoSuchEntity" : "ResourceNotFoundException"})` });
      if (args[0] === "sts") value = { Account: contract.account, Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test" };
      else if (args[1] === "get-bucket-versioning") value = { Status: "Enabled" };
      else if (args[1] === "list-objects-v2") value = applying && existingState ? { Contents: [{ Key: contract.key }] } : {};
      else if (args[1] === "put-object") {
        if (replay) throw new Error("PreconditionFailed");
        assert(args.includes("--if-none-match") && args.includes("*")); value = {};
      } else value = {};
    } else if (name === "terraform") {
      if (args[0] === "version") value = { terraform_version: "1.15.8" };
      else if (args[1] === "init") {
        fs.mkdirSync(env.TF_DATA_DIR, { recursive: true });
        fs.writeFileSync(path.join(env.TF_DATA_DIR, "terraform.tfstate"), JSON.stringify({ backend: backend() })); return "";
      } else if (args[1] === "workspace") return "default";
      else if (args[1] === "show") value = plan();
      else if (args[1] === "plan" && args.some((arg) => arg.startsWith("-out="))) { fs.writeFileSync(path.join(dir, "activation.tfplan"), "saved plan bytes"); return ""; }
      else return "";
    } else throw new Error(`Unexpected tool ${name}`);
    return JSON.stringify(value);
  };
  run(["prepare", dir], { execute, env: {} });
  applying = true;
  if (changedPlan) fs.appendFileSync(path.join(dir, "activation.tfplan"), "modified");
  return { calls, apply: () => run(["apply", dir, "123"], { execute, env: {} }) };
}

test("mocked installation binds approval, reserves once, applies only saved binary, then verifies", (t) => {
  const { calls, apply } = installation(t);
  apply();
  const writes = calls.filter(([name, , operation]) => name === "aws" && operation === "put-object");
  assert.equal(writes.length, 1);
  const applies = calls.filter(([name, , operation]) => name === "terraform" && operation === "apply");
  assert.equal(applies.length, 1);
  assert(applies[0].at(-1).endsWith("/activation.tfplan"));
  assert(calls.indexOf(writes[0]) < calls.indexOf(applies[0]));
});
for (const scenario of [{ changedSource: true }, { changedPlan: true }, { existingState: true }, { replay: true }, { approval: false }]) {
  test(`mocked installation rejects before apply: ${JSON.stringify(scenario)}`, (t) => {
    const { calls, apply } = installation(t, scenario);
    assert.throws(apply);
    assert(!calls.some(([name, , operation]) => name === "terraform" && operation === "apply"));
  });
}
