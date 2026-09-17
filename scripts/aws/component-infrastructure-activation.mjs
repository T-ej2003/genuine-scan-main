#!/usr/bin/env node
// Source-bound one-time table activation. Terraform executes only in isolation.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { cleanSource } from "./component-iam-installation.mjs";
import { establishComponentSession } from "./component-installation-session.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";
import { authenticatePublishedComponentAuthorization, authenticateTerraformActivationAuthorization, readComponentActivationEnvironments } from "./component-iam-authorization.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const stack = "infra/aws/terraform/production-component-deployment-state";
export const contract = JSON.parse(fs.readFileSync(path.join(root, stack, "state-backend-contract.json")));
const environmentContract = JSON.parse(fs.readFileSync(path.join(root, stack, "github-environment-contract.json")));
export const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");

export function assertBackend(backend, workspace) {
  assert.equal(backend.type, "s3");
  for (const field of ["bucket", "key", "region", "encrypt", "use_lockfile"]) assert.deepEqual(backend.config[field], contract[field], `Wrong backend ${field}`);
  assert.deepEqual(backend.config.allowed_account_ids, [contract.account]);
  assert.equal(workspace, "default");
  assert.equal(backend.config.max_retries, 0, "Backend retries must be disabled");
  for (const field of ["endpoint", "endpoints", "assume_role", "assume_role_with_web_identity", "profile", "skip_credentials_validation", "skip_requesting_account_id", "skip_region_validation"]) assert(!backend.config[field], `Backend override: ${field}`);
}

export function assertInitialPlan(plan) {
  assert.equal(plan.errored, false);
  assert.equal(plan.applyable, true);
  const providers = plan.configuration.provider_config;
  assert.deepEqual(Object.keys(providers), ["aws"]);
  assert.equal(providers.aws.full_name, "registry.terraform.io/hashicorp/aws");
  assert.deepEqual(providers.aws.expressions, { allowed_account_ids: { constant_value: [contract.account] }, region: { constant_value: contract.region }, max_retries: { constant_value: 0 } });
  const configuration = plan.configuration.root_module;
  assert.equal(Object.keys(configuration.module_calls || {}).length, 0);
  assert(configuration.resources.every((resource) => !resource.provisioners?.length));
  assert.deepEqual(contract.expectedManagedAddresses, ["aws_dynamodb_table.component_deployment_state"]);
  assert.deepEqual(configuration.resources.map(({ address }) => address), contract.expectedManagedAddresses);
  const changes = plan.resource_changes || [];
  assert.deepEqual(changes.map((item) => item.address).sort(), [...contract.expectedManagedAddresses].sort());
  for (const item of changes) {
    assert.equal(item.mode, "managed");
    assert.equal(item.type, "aws_dynamodb_table");
    assert.equal(item.provider_name, "registry.terraform.io/hashicorp/aws");
    assert.deepEqual(item.change.actions, ["create"], `Not initial create: ${item.address}`);
  }
  assert.equal((plan.resource_drift || []).length, 0);
  assert.equal((plan.prior_state?.values?.root_module?.resources || []).length, 0);
  assert.equal((plan.prior_state?.values?.root_module?.child_modules || []).length, 0);
  const get = (address) => changes.find((item) => item.address === address).change.after;
  const table = get("aws_dynamodb_table.component_deployment_state");
  assert.equal(table.name, "mscqr-production-component-deployment-state");
  assert.equal(table.hash_key, "stateKey");
  assert.equal(table.billing_mode, "PAY_PER_REQUEST");
  assert.deepEqual(table.attribute, [{ name: "stateKey", type: "S" }]);
  assert.equal(table.server_side_encryption[0].enabled, true);
  assert.equal(table.point_in_time_recovery[0].enabled, true);
}

export function assertAuthorization(authorization, preparation, { sourceSha, planSha256, preparationSha256 }) {
  assert.deepEqual(authorization, { sourceSha, planSha256, preparationSha256 });
  assert.equal(preparation.sourceSha, sourceSha);
  assert.equal(preparation.planSha256, planSha256);
  assert.deepEqual(preparation.backend, contract);
  assert.equal(preparation.stateIdentity, "ABSENT");
}

export function assertEnvironment(config, branches) {
  assert.equal(config.can_admins_bypass, false);
  assert.deepEqual(config.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.deepEqual(branches.branch_policies.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]);
  const rules = config.protection_rules.filter((rule) => rule.type === "required_reviewers");
  assert.equal(rules.length, 1);
  assert.equal(rules[0].prevent_self_review, false);
  assert.deepEqual(rules[0].reviewers.map(({ type, reviewer }) => ({ type, login: reviewer.login, id: reviewer.id })), [environmentContract.requiredReviewer]);
  return rules[0].reviewers.map(({ reviewer }) => reviewer.id);
}

function privateBytes(file, limit) {
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && stat.nlink === 1 && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 && stat.size > 0 && stat.size <= limit, "Private regular artifact required");
  return fs.readFileSync(file);
}

export async function run(argv = process.argv.slice(2), { source = cleanSource, installApproval = authenticatePublishedComponentAuthorization,
  planApproval = authenticateTerraformActivationAuthorization, environments = readComponentActivationEnvironments, session = establishComponentSession } = {}) {
  const [mode, directory, runId, transition] = argv;
  assert(["prepare", "apply"].includes(mode), "Unsupported activation operation");
  assert.equal(argv.length, mode === "prepare" ? 4 : 3);
  assert.match(runId || "", /^[1-9][0-9]*$/);
  if (mode === "prepare") assert.match(transition || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert(path.isAbsolute(directory || ""));
  const work = fs.realpathSync(directory), stat = fs.statSync(work);
  assert(stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0);
  assert(work !== root && !work.startsWith(root + "/"), "Plan artifacts must be outside source");
  const sourceSha = source();
  const sourceGuard = () => assert.equal(source(), sourceSha, "Protected source moved");
  const settings = environments(sourceSha); assert.equal(settings.length, 3);
  for (const { config, branches } of settings) assertEnvironment(config, branches);
  const preparationPath = path.join(work, "preparation.json"), planPath = path.join(work, "activation.tfplan");
  let preparation, preparationSha256, plan, approved, binding;
  const approvePlan = () => {
    const value = planApproval({ runId, sourceSha, transitionId: binding.transitionId, planSha256: hash(plan), preparationSha256 });
    assertAuthorization(value, preparation, { sourceSha, planSha256: hash(plan), preparationSha256 });
    return value;
  };
  if (mode === "prepare") {
    assert(!fs.existsSync(preparationPath) && !fs.existsSync(planPath), "Use a fresh private plan directory");
    const authorized = installApproval({ runId, sourceSha, transitionId: transition });
    assert.equal(authorized.sourceSha, sourceSha); assert.equal(authorized.transitionId, transition);
    assert.match(authorized.authorizationSha256 || "", /^[a-f0-9]{64}$/);
    binding = { sourceSha, transitionId: transition, authorizationSha256: authorized.authorizationSha256, purpose: "TERRAFORM" };
  } else {
    const bytes = privateBytes(preparationPath, 1024 * 1024);
    preparationSha256 = hash(bytes); preparation = JSON.parse(bytes);
    assert.deepEqual(Object.keys(preparation).sort(), ["backend", "iamInstallation", "operatorProvenance", "planSha256", "schemaVersion", "sourceSha", "stateIdentity"]);
    assert.equal(preparation.schemaVersion, 1); assert.equal(preparation.sourceSha, sourceSha);
    assertComponentSessionRecord(preparation.operatorProvenance);
    assert.equal(preparation.operatorProvenance.purpose, "TERRAFORM");
    plan = privateBytes(planPath, 16 * 1024 * 1024);
    binding = { sourceSha, transitionId: preparation.iamInstallation.transitionId, authorizationSha256: preparation.iamInstallation.authorizationSha256, purpose: "TERRAFORM" };
    for (const field of Object.keys(binding)) assert.equal(preparation.operatorProvenance[field], binding[field]);
    approved = approvePlan();
  }
  sourceGuard();
  const client = await session(binding);
  try {
    const baseline = await client.inspect();
    assert.equal(baseline.stateIdentity, "ABSENT");
    if (preparation) assert.deepEqual(baseline.iamInstallation, preparation.iamInstallation, "IAM installation changed");
    sourceGuard();
    const executed = await client.execute({ mode, plan: plan || null }, { checkpoint: async value => {
      sourceGuard();
      assert.deepEqual(await client.inspect(), baseline, "State or IAM installation changed");
      if (value.stage === "backend") assertBackend(value.backend, value.workspace);
      else {
        assert.equal(value.stage, mode === "prepare" ? "plan" : "apply");
        assertInitialPlan(value.planJson);
        if (mode === "apply") {
          assert.equal(value.planSha256, hash(plan));
          assert.equal(hash(privateBytes(planPath, 16 * 1024 * 1024)), approved.planSha256, "Saved plan moved");
          assert.equal(hash(privateBytes(preparationPath, 1024 * 1024)), preparationSha256, "Preparation moved");
          assert.deepEqual(approvePlan(), approved);
          sourceGuard();
          await client.reserve({ sourceSha, transitionId: binding.transitionId, planSha256: approved.planSha256, preparationSha256,
            iamReceiptSha256: baseline.iamInstallation.receiptSha256, authorizationRunId: runId });
        }
      }
    } });
    sourceGuard();
    assertComponentSessionRecord(executed.session);
    for (const field of Object.keys(binding)) assert.equal(executed.session[field], binding[field]);
    if (mode === "prepare") {
      const result = executed.result;
      assertInitialPlan(result.planJson);
      const bytes = Buffer.from(result.plan, "base64"); assert.equal(bytes.toString("base64"), result.plan);
      assert.equal(hash(bytes), result.planSha256);
      preparation = { schemaVersion: 1, sourceSha, backend: contract, stateIdentity: "ABSENT", iamInstallation: baseline.iamInstallation,
        operatorProvenance: executed.session, planSha256: result.planSha256 };
      const evidence = Buffer.from(JSON.stringify(preparation, null, 2) + "\n");
      fs.writeFileSync(planPath, bytes, { flag: "wx", mode: 0o600 });
      fs.writeFileSync(preparationPath, evidence, { flag: "wx", mode: 0o600 });
      return { ...preparation, preparationSha256: hash(evidence) };
    }
    assert.deepEqual(executed.result, { type: "result", appliedPlanSha256: approved.planSha256, driftVerified: true });
    return { state: "INFRA_ACTIVATION_VERIFIED", sourceSha, planSha256: approved.planSha256, bootstrapExecuted: false };
  } finally { client.close(); }
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run().then(result => process.stdout.write(JSON.stringify(result) + "\n")).catch(() => {
  process.stderr.write("Component infrastructure activation rejected; reconcile exact state before retry.\n"); process.exitCode = 1;
});
