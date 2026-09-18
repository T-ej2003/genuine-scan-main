import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assertBackend, assertInitialPlan, assertAuthorization, assertEnvironment, contract, stack, run, hash } from "../aws/component-infrastructure-activation.mjs";
const backend = () => ({ type: "s3", config: { ...contract, allowed_account_ids: [contract.account], max_retries: 0 } });
const plan = () => {
  const values = {
    "aws_dynamodb_table.component_deployment_state": { name: "mscqr-production-component-deployment-state", hash_key: "stateKey", attribute: [{ name: "stateKey", type: "S" }], billing_mode: "PAY_PER_REQUEST", server_side_encryption: [{ enabled: true }], point_in_time_recovery: [{ enabled: true }] },
  };
  return {
    errored: false, applyable: true,
    configuration: { provider_config: { aws: { full_name: "registry.terraform.io/hashicorp/aws", expressions: { allowed_account_ids: { constant_value: [contract.account] }, region: { constant_value: contract.region }, max_retries: { constant_value: 0 } } } }, root_module: { resources: contract.expectedManagedAddresses.map((address) => ({ address })) } },
    resource_changes: contract.expectedManagedAddresses.map((address) => ({ address, mode: "managed", type: "aws_dynamodb_table", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["create"], after: values[address] } })),
  };
};
test("fixed backend never accepts local state, other keys, bucket, account, region or workspace", () => {
  assertBackend(backend(), "default");
  for (const [field, value] of [["bucket", "other"], ["key", "mscqr/production/rls-green/stage-a/terraform.tfstate"], ["region", "eu-west-1"], ["allowed_account_ids", ["000000000000"]], ["use_lockfile", false], ["encrypt", false], ["max_retries", 5]]) {
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
test("only the initial table create can be authorized; all IAM configuration and changes fail", () => {
  assertInitialPlan(plan());
  for (const actions of [["update"], ["delete", "create"], ["no-op"]]) {
    const changed = plan(); changed.resource_changes[0].change.actions = actions;
    assert.throws(() => assertInitialPlan(changed));
  }
  const changed = plan(); changed.resource_changes.push({ address: "aws_iam_role.unrelated", mode: "managed", change: { actions: ["create"] } });
  assert.throws(() => assertInitialPlan(changed));
  const iamConfig = plan(); iamConfig.configuration.root_module.resources.push({ address: "aws_iam_role.normal_deployer" });
  assert.throws(() => assertInitialPlan(iamConfig));
  const iamRead = plan(); iamRead.resource_changes.push({ address: "data.aws_iam_role.release", mode: "data", change: { actions: ["read"] } });
  assert.throws(() => assertInitialPlan(iamRead));
  const wrongProvider = plan(); wrongProvider.configuration.provider_config.aws.expressions.region.constant_value = "eu-west-1";
  assert.throws(() => assertInitialPlan(wrongProvider));
});
test("table create rejects wrong schema, encryption, recovery and provider", () => {
  for (const mutate of [
    (p) => { p.resource_changes[0].change.after.name = "other"; },
    (p) => { p.resource_changes[0].change.after.attribute[0].type = "N"; },
    (p) => { p.resource_changes[0].change.after.server_side_encryption[0].enabled = false; },
    (p) => { p.resource_changes[0].change.after.point_in_time_recovery[0].enabled = false; },
    (p) => { p.resource_changes[0].provider_name = "other/aws"; },
    (p) => { p.configuration.root_module.module_calls = { hidden: {} }; },
    (p) => { p.configuration.root_module.resources[0].provisioners = [{}]; },
    (p) => { p.prior_state = { values: { root_module: { child_modules: [{}] } } }; },
  ]) { const p = plan(); mutate(p); assert.throws(() => assertInitialPlan(p)); }
});
test("authorization binds exact source, plan bytes, preparation and absent remote state", () => {
  const binding = { sourceSha: "a".repeat(40), planSha256: "b".repeat(64), preparationSha256: "c".repeat(64) };
  const preparation = { sourceSha: binding.sourceSha, planSha256: binding.planSha256, backend: contract, stateIdentity: "ABSENT" };
  assertAuthorization(binding, preparation, binding);
  assert.throws(() => assertAuthorization(null, preparation, binding));
  for (const field of Object.keys(binding)) assert.throws(() => assertAuthorization({ ...binding, [field]: "d".repeat(64) }, preparation, binding));
  assert.throws(() => assertAuthorization(binding, { ...preparation, stateIdentity: "changed" }, binding));
});
for (const environment of ["production-normal-deploy", "production-component-state-bootstrap", "production-component-infrastructure-activation"]) test(`${environment} requires exact main branch and explicit sole-operator reviewer without bypass`, () => {
  assert(JSON.parse(fs.readFileSync(`${stack}/github-environment-contract.json`)).environments.includes(environment));
  const config = { can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 183396573, login: "T-ej2003" } }] }] };
  const branches = { branch_policies: [{ name: "main", type: "branch" }] };
  assertEnvironment(config, branches);
  assert.throws(() => assertEnvironment({ ...config, can_admins_bypass: true }, branches));
  assert.throws(() => assertEnvironment(config, { branch_policies: [{ name: "main", type: "tag" }] }));
  assert.throws(() => assertEnvironment(config, { branch_policies: [...branches.branch_policies, { name: "*", type: "branch" }] }));
  for (const rule of [
    { ...config.protection_rules[0], prevent_self_review: true },
    { ...config.protection_rules[0], reviewers: [] },
    { ...config.protection_rules[0], reviewers: [{ type: "User", reviewer: { id: 1, login: "T-ej2003" } }] },
    { ...config.protection_rules[0], reviewers: [{ type: "User", reviewer: { id: 1, login: "other", site_admin: true } }] },
    { ...config.protection_rules[0], reviewers: [{ type: "User", reviewer: { id: 183396573, login: "other" } }] },
    { ...config.protection_rules[0], reviewers: [{ type: "Team", reviewer: { id: 183396573, login: "T-ej2003" } }] },
  ]) assert.throws(() => assertEnvironment({ ...config, protection_rules: [rule] }, branches));
  assert.throws(() => assertEnvironment(config, { branch_policies: [{ name: "feature", type: "branch" }] }));
});


function fixture(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "component-isolated-activation-test-")));
  t.after(() => fs.rmSync(directory, { recursive: true }));
  const sourceSha = "a".repeat(40), transitionId = "12345678-1234-4234-8234-123456789abc", authorizationSha256 = "b".repeat(64);
  const bytes = Buffer.from("exact-saved-plan"), planSha256 = hash(bytes);
  const f = { sourceSha, directory, calls: [], reservations: 0, applies: 0, before: () => {}, receiptSha256: "c".repeat(64) };
  const config = { can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
    protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { login: "T-ej2003", id: 183396573 } }] }] };
  const branches = { branch_policies: [{ name: "main", type: "branch" }] };
  const dependencies = {
    source: () => f.sourceSha,
    environments: () => [1,2,3].map(() => ({ config, branches })),
    planApproval: () => {
      f.calls.push("plan-approval");
      if (f.rejectApproval) throw new Error("missing or wrong approval");
      return { sourceSha, planSha256, preparationSha256: f.preparationSha256 };
    },
    session: async requested => {
      f.calls.push("MFA");
      assert.deepEqual(requested, { sourceSha, transitionId });
      const binding = { sourceSha, transitionId, authorizationSha256, purpose: "TERRAFORM" };
      assert.deepEqual(binding, { sourceSha, transitionId, authorizationSha256, purpose: "TERRAFORM" });
      const issued = Date.now();
      const proof = { ...binding, account: contract.account, region: contract.region,
        principal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-component-table-installer/component-" + transitionId,
        issuedAt: new Date(issued).toISOString(), expiresAt: new Date(issued + 900000).toISOString(),
        issuanceEventId: "12345678-1234-4234-8234-123456789def", issuanceEventTime: new Date(issued).toISOString(),
        operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
      return {
        inspect: async () => {
          f.calls.push("inspect");
          if (f.existingState) throw new Error("state exists");
          if (f.missingReceipt) throw new Error("AWS receipt absent");
          return { stateIdentity: "ABSENT", iamInstallation: { receiptSha256: f.receiptSha256, sourceSha, transitionId, authorizationSha256, documentBindingsSha256: "d".repeat(64) } };
        },
        reserve: async record => {
          f.calls.push("reserve");
          if (f.replay) throw new Error("attempt consumed");
          assert.equal(record.planSha256, planSha256); assert.equal(record.preparationSha256, f.preparationSha256);
          assert.equal(record.sourceSha, sourceSha); assert.equal(record.iamReceiptSha256, f.receiptSha256);
          f.reservations++;
        },
        execute: async ({ mode, plan: saved }, { checkpoint }) => {
          f.calls.push("isolated-" + mode);
          await checkpoint({ stage: "backend", backend: backend(), workspace: "default" });
          f.before(mode);
          await checkpoint({ stage: mode === "prepare" ? "plan" : "apply", planSha256, planJson: plan() });
          if (mode === "apply") {
            assert.deepEqual(saved, bytes); f.applies++;
            if (f.ambiguousApply) throw new Error("ambiguous apply");
            return { session: proof, result: { type: "result", appliedPlanSha256: planSha256, driftVerified: true } };
          }
          return { session: proof, result: { type: "result", plan: bytes.toString("base64"), planSha256, planJson: plan() } };
        },
        close: () => { f.calls.push("close-session"); },
      };
    },
  };
  f.prepare = async () => { const result = await run(["prepare", directory, transitionId], dependencies); f.preparationSha256 = result.preparationSha256; return result; };
  f.apply = () => run(["apply", directory, "456"], dependencies);
  return f;
}

test("sole operator prepares an isolated plan and explicitly approves its exact bytes once", async t => {
  const f = fixture(t), prepared = await f.prepare();
  assert.equal(prepared.planSha256, hash(Buffer.from("exact-saved-plan")));
  assert.equal(f.reservations, 0); assert.equal(f.applies, 0);
  assert.equal((await f.apply()).state, "INFRA_ACTIVATION_VERIFIED");
  assert.equal(f.reservations, 1); assert.equal(f.applies, 1);
  assert(!f.calls.includes("installation-approval"));
  assert(f.calls.indexOf("plan-approval") < f.calls.lastIndexOf("MFA"));
  assert.equal(f.calls.at(-1), "close-session");
});

for (const scenario of ["source", "plan", "preparation", "approval", "state", "receipt", "replay"]) test("activation rejects changed " + scenario + " before apply", async t => {
  const f = fixture(t); await f.prepare();
  if (scenario === "source") f.sourceSha = "e".repeat(40);
  if (scenario === "plan") fs.writeFileSync(path.join(f.directory, "activation.tfplan"), "different plan");
  if (scenario === "preparation") fs.appendFileSync(path.join(f.directory, "preparation.json"), "\n");
  if (scenario === "approval") f.rejectApproval = true;
  if (scenario === "state") f.existingState = true;
  if (scenario === "receipt") f.receiptSha256 = "e".repeat(64);
  if (scenario === "replay") f.replay = true;
  await assert.rejects(f.apply()); assert.equal(f.applies, 0); assert.equal(f.reservations, 0);
});
for (const scenario of ["source", "plan", "receipt", "approval"]) test("movement at isolated apply barrier rejects " + scenario + " before reservation", async t => {
  const f = fixture(t); await f.prepare();
  f.before = () => {
    if (scenario === "source") f.sourceSha = "f".repeat(40);
    if (scenario === "plan") fs.writeFileSync(path.join(f.directory, "activation.tfplan"), "moved");
    if (scenario === "receipt") f.receiptSha256 = "f".repeat(64);
    if (scenario === "approval") f.rejectApproval = true;
  };
  await assert.rejects(f.apply()); assert.equal(f.reservations, 0); assert.equal(f.applies, 0);
});
test("forged local IAM receipt cannot replace the fixed AWS readback", async t => {
  const f = fixture(t); f.missingReceipt = true;
  fs.writeFileSync(path.join(f.directory, "iam-installation.json"), JSON.stringify({ state: "IAM_VERIFIED" }));
  await assert.rejects(f.prepare(), /AWS receipt absent/);
  assert(!fs.existsSync(path.join(f.directory, "activation.tfplan")));
});
test("ambiguous apply is not replayed and session cleanup still runs", async t => {
  const f = fixture(t); await f.prepare(); f.ambiguousApply = true;
  await assert.rejects(f.apply(), /ambiguous apply/);
  assert.equal(f.applies, 1); assert.equal(f.reservations, 1); assert.equal(f.calls.at(-1), "close-session");
});
test("legacy administrator, host Terraform and credential-export execution paths are absent", () => {
  const source = fs.readFileSync("scripts/aws/component-infrastructure-activation.mjs", "utf8");
  for (const forbidden of [/execFileSync/, /profile:\s*"default"/, /auditEnv/, /exec\("terraform"/, /authenticateOperatorSession/, /createAssumedRoleSessionEnvironment/]) assert(!forbidden.test(source));
});
for (const argv of [[], ["prepare", "/tmp"], ["apply"], ["root", "123"], ["prepare", "/tmp", "123", "../transition"], ["prepare", "/tmp", "123", "12345678-1234-4234-8234-123456789abc"]]) test("actual activation CLI rejects malformed or obsolete command " + JSON.stringify(argv), () => {
  const result = spawnSync(process.execPath, ["scripts/aws/component-infrastructure-activation.mjs", ...argv], { env: { PATH: "/usr/bin:/bin" }, encoding: "utf8", timeout: 15000 });
  assert.equal(result.status, 1); assert.equal(result.stdout, "");
  assert.equal(result.stderr, "Component infrastructure activation rejected; reconcile exact state before retry.\n");
});
