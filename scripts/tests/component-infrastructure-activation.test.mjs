import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertBackend, assertInitialPlan, assertAuthorization, assertEnvironment, authenticateOperatorSession, contract, stack, run, hash } from "../aws/component-infrastructure-activation.mjs";
import { productionAwsCredentialSourceContract } from "../aws/production-credential-source-contract.mjs";
import { installationDocuments, documentBindings, digest } from "../aws/component-iam-installation-contract.mjs";

const backend = () => ({ type: "s3", config: { ...contract, allowed_account_ids: [contract.account] } });
const caller = { Account: contract.account, Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-component-table-installer/test", UserId: "role-id:test" };
const credentials = { AccessKeyId: "fixture-session-key", SecretAccessKey: "fixture-secret", SessionToken: "fixture-token", Expiration: new Date(Date.now() + 50 * 60 * 1000).toISOString() };
const issuance = () => ({
  eventID: "12345678-1234-1234-1234-123456789abc", eventSource: "sts.amazonaws.com", eventName: "AssumeRole", eventTime: new Date(Date.now() - 1000).toISOString(), recipientAccountId: contract.account,
  userIdentity: { type: "IAMUser", arn: `arn:aws:iam::${contract.account}:user/mscqr-production-bootstrap-operator`, accountId: contract.account, sessionContext: { attributes: { mfaAuthenticated: "true" } } },
  requestParameters: { roleArn: `arn:aws:iam::${contract.account}:role/mscqr-production-component-table-installer` },
  responseElements: { assumedRoleUser: { arn: caller.Arn, assumedRoleId: caller.UserId }, credentials: { accessKeyId: credentials.AccessKeyId, expiration: credentials.Expiration } },
});

test("operator provenance accepts only exact AWS MFA-backed human issuance, not role shape or markers", () => {
  const verify = (event = issuance(), identity = caller) => authenticateOperatorSession({ caller: identity, credentials, events: [event] });
  assert.equal(verify().operatorArn, issuance().userIdentity.arn);
  for (const mutate of [
    (e) => { e.eventName = "AssumeRoleWithWebIdentity"; },
    (e) => { e.userIdentity.type = "AssumedRole"; },
    (e) => { e.userIdentity.sessionContext.attributes.mfaAuthenticated = "false"; },
    (e) => { delete e.userIdentity.sessionContext; e.mfaVerified = true; },
    (e) => { e.userIdentity.arn = "arn:aws:iam::368992683803:user/other"; },
    (e) => { e.recipientAccountId = "000000000000"; },
    (e) => { e.requestParameters.roleArn += "other"; },
    (e) => { e.responseElements.credentials.accessKeyId += "other"; },
    (e) => { e.responseElements.assumedRoleUser.assumedRoleId += "other"; },
    (e) => { e.eventTime = new Date(Date.now() - 61 * 60 * 1000).toISOString(); },
  ]) { const event = issuance(); mutate(event); assert.throws(() => verify(event)); }
  assert.throws(() => verify(issuance(), { ...caller, Account: "000000000000" }));
  assert.throws(() => verify(issuance(), { ...caller, Arn: caller.Arn.replace("component-table-installer", "other") }));
  assert.throws(() => authenticateOperatorSession({ caller, credentials, events: [] }));
});
test("IAM bootstrap purpose authenticates only the original MFA human release role", () => {
  const identity = { ...caller, Arn: caller.Arn.replace("component-table-installer", "release-deployer") };
  const event = issuance();
  event.requestParameters.roleArn = event.requestParameters.roleArn.replace("component-table-installer", "release-deployer");
  event.responseElements.assumedRoleUser.arn = identity.Arn;
  const input = { caller: identity, credentials, events: [event], purpose: "IAM_BOOTSTRAP" };
  assert.equal(authenticateOperatorSession(input).operatorArn, event.userIdentity.arn);
  assert.throws(() => authenticateOperatorSession({ ...input, purpose: "TERRAFORM" }));
  assert.throws(() => authenticateOperatorSession({ ...input, purpose: "arbitrary-role" }));
  assert.throws(() => authenticateOperatorSession({ caller, credentials, events: [issuance()], purpose: "IAM_BOOTSTRAP" }));
  event.userIdentity.sessionContext.attributes.mfaAuthenticated = "false";
  assert.throws(() => authenticateOperatorSession(input));
});
const plan = () => {
  const values = {
    "aws_dynamodb_table.component_deployment_state": { name: "mscqr-production-component-deployment-state", hash_key: "stateKey", attribute: [{ name: "stateKey", type: "S" }], billing_mode: "PAY_PER_REQUEST", server_side_encryption: [{ enabled: true }], point_in_time_recovery: [{ enabled: true }] },
  };
  return {
    errored: false, applyable: true,
    configuration: { provider_config: { aws: { full_name: "registry.terraform.io/hashicorp/aws", expressions: { allowed_account_ids: { constant_value: [contract.account] }, region: { constant_value: contract.region } } } }, root_module: { resources: contract.expectedManagedAddresses.map((address) => ({ address })) } },
    resource_changes: contract.expectedManagedAddresses.map((address) => ({ address, mode: "managed", type: "aws_dynamodb_table", provider_name: "registry.terraform.io/hashicorp/aws", change: { actions: ["create"], after: values[address] } })),
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

const receipt = () => ({ schemaVersion: 1, sourceSha: "a".repeat(40), transitionId: "12345678-1234-1234-1234-123456789abc", authorizationSha256: "b".repeat(64), documentBindingsSha256: digest(documentBindings()), state: "IAM_VERIFIED", live: installationDocuments().map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })) });

function installation(t, { changedSource = false, changedPlan = false, existingState = false, replay = false, approval = true, wrongReviewer = false, wrongInitiator = false, wrongApprovalEnvironment = false, inherited = {}, provenance = () => issuance(), rejectedProvenance = false, storedReceipt = () => receipt(), liveMutation = () => {}, rejectPrepare = false, forgedLocal = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "component-install-test-"));
  t.after(() => fs.rmSync(dir, { recursive: true }));
  const calls = [];
  const children = [];
  const sourceSha = "a".repeat(40);
  if (forgedLocal) fs.writeFileSync(path.join(dir, "iam-installation.json"), JSON.stringify(receipt()));
  let applying = false;
  const operator = { id: 183396573, login: "T-ej2003" };
  const config = { id: 20, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: operator }] }] };
  const branches = { branch_policies: [{ name: "main", type: "branch" }] };
  const execute = (name, args, { env }) => {
    calls.push([name, ...args]);
    children.push({ name, args, env });
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
      else if (endpoint.endsWith("/approvals")) value = approval ? [{ state: "approved", environments: [{ id: wrongApprovalEnvironment ? 21 : 20 }], user: wrongReviewer ? { id: 1, login: "other" } : operator }] : [];
      else value = { path: ".github/workflows/authorize-component-infrastructure-activation.yml", head_sha: sourceSha, head_branch: "main", head_repository: { full_name: "T-ej2003/genuine-scan-main" }, event: "workflow_dispatch", conclusion: "success", run_attempt: 1, created_at: new Date().toISOString(), actor: wrongInitiator ? { id: 1, login: "other" } : operator };
    } else if (name === "aws") {
      if (args[0] === "dynamodb") throw Object.assign(new Error("Missing"), { stderr: "(ResourceNotFoundException)" });
      if (args[0] === "iam") {
        const target = installationDocuments().find(({ role }) => role === args[args.indexOf("--role-name") + 1]);
        assert(target);
        if (args[1] === "get-role") value = { Role: { Arn: target.arn, RoleName: target.role, ...(target.trust ? { AssumeRolePolicyDocument: encodeURIComponent(JSON.stringify(target.trust)), Path: "/", MaxSessionDuration: 3600, Tags: [{ Key: "Transition", Value: receipt().transitionId }] } : {}) } };
        else if (args[1] === "list-attached-role-policies") value = { AttachedPolicies: [], IsTruncated: false };
        else if (args[1] === "list-role-policies") value = { PolicyNames: [target.policyName], IsTruncated: false };
        else { assert.equal(args[1], "get-role-policy"); assert.equal(args[args.indexOf("--policy-name") + 1], target.policyName); value = { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: target.policy }; }
        liveMutation(value, target, applying);
      } else if (args[1] === "get-object") {
        assert.equal(args[args.indexOf("--bucket") + 1], "mscqr-production-terraform-state-368992683803-eu-west-2");
        assert.equal(args[args.indexOf("--key") + 1], "mscqr/production/component-deployment-state/iam-installation.json");
        const file = args[args.indexOf("--key") + 2];
        assert.equal(fs.statSync(file).mode & 0o077, 0);
        assert.equal(fs.statSync(path.dirname(file)).mode & 0o077, 0);
        const stored = storedReceipt(applying, calls);
        if (!stored) throw new Error("NoSuchKey");
        fs.writeFileSync(file, JSON.stringify(stored)); value = {};
      } else if (args[0] === "configure") value = credentials;
      else if (args[0] === "sts") value = env.AWS_PROFILE === "default" ? { Account: contract.account, Arn: `arn:aws:iam::${contract.account}:root` } : caller;
      else if (args[0] === "cloudtrail") value = { Events: provenance(applying) ? [{ CloudTrailEvent: JSON.stringify(provenance(applying)) }] : [] };
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
  if (rejectedProvenance || rejectPrepare) {
    assert.throws(() => run(["prepare", dir], { execute, env: inherited }));
    assert(!calls.some(([name]) => name === "terraform"));
    assert(!calls.some(([name, , operation]) => name === "aws" && operation === "put-object"));
    return;
  }
  run(["prepare", dir], { execute, env: inherited });
  applying = true;
  if (changedPlan) fs.appendFileSync(path.join(dir, "activation.tfplan"), "modified");
  return { calls, children, dir, apply: () => run(["apply", dir, "123"], { execute, env: inherited }) };
}

test("activation child environments use canonical safelists and pin production values", (t) => {
  const redirects = [...productionAwsCredentialSourceContract.namedProfileStrips,
    "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL_IAM", "AWS_ENDPOINT_URL_DYNAMODB",
    "TF_CLI_CONFIG_FILE", "TF_CLI_ARGS", "TF_CLI_ARGS_apply", "TF_VAR_region", "TERRAFORM_CONFIG",
    "GH_HOST", "GH_CONFIG_DIR", "NODE_OPTIONS", "HTTPS_PROXY", "UNREVIEWED_FUTURE_VARIABLE"];
  const safe = { HOME: "/operator", PATH: "/usr/bin", TMPDIR: "/tmp", TERM: "xterm", LANG: "C", LC_ALL: "C", LC_CTYPE: "C", NODE_EXTRA_CA_CERTS: "/operator/trusted-ca" };
  const inherited = { ...Object.fromEntries(redirects.map((key) => [key, "hostile-value"])), ...safe,
    GH_TOKEN: "fixture-gh-token", GITHUB_TOKEN: "fixture-github-token",
    AWS_REGION: "us-east-1", AWS_DEFAULT_REGION: "us-east-1", AWS_EC2_METADATA_DISABLED: "false",
    TF_WORKSPACE: "hostile", TF_DATA_DIR: "/hostile" };
  const { children, dir, apply } = installation(t, { inherited });
  apply();
  assert(children.some(({ name }) => name === "aws"));
  assert(children.some(({ name }) => name === "terraform"));
  for (const { name, args, env } of children) {
    if (name === "gh") {
      assert.deepEqual(env, { ...safe, GH_TOKEN: inherited.GH_TOKEN, GITHUB_TOKEN: inherited.GITHUB_TOKEN });
    } else {
      const base = { ...safe, AWS_REGION: contract.region, AWS_DEFAULT_REGION: contract.region, AWS_EC2_METADATA_DISABLED: "true", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true" };
      if (env.AWS_PROFILE === "default") {
        assert.equal(name, "aws");
        assert(["sts", "cloudtrail"].includes(args[0]));
        assert.deepEqual(env, { ...base, AWS_PROFILE: "default" });
      } else {
        const identity = env.AWS_PROFILE ? { AWS_PROFILE: "mscqr-production-component-table-installer" } : { AWS_ACCESS_KEY_ID: credentials.AccessKeyId, AWS_SECRET_ACCESS_KEY: credentials.SecretAccessKey, AWS_SESSION_TOKEN: credentials.SessionToken };
        assert.deepEqual(env, { ...base, ...identity, TF_WORKSPACE: "default", TF_DATA_DIR: path.join(fs.realpathSync(dir), "terraform-data") });
        if (name === "terraform") assert.equal(env.AWS_PROFILE, undefined, "Terraform uses only authenticated pinned session");
      }
      for (const key of redirects.filter((key) => !["AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"].includes(key))) assert.equal(env[key], undefined, key);
    }
  }
});

test("OIDC and missing/forged provenance stop installer before Terraform", (t) => {
  for (const provenance of [() => null, () => ({ ...issuance(), eventName: "AssumeRoleWithWebIdentity" }), () => ({ mfaVerified: true })]) {
    installation(t, { provenance, rejectedProvenance: true });
  }
});

test("apply rejects different issuance even with identical session ARN before reservation", (t) => {
  const { calls, apply, dir } = installation(t, { provenance: (applying) => ({ ...issuance(), ...(applying ? { eventID: "abcdefab-1234-1234-1234-123456789abc" } : {}) }) });
  const preparation = fs.readFileSync(path.join(dir, "preparation.json"), "utf8");
  for (const value of Object.values(credentials)) assert(!preparation.includes(value));
  assert.throws(apply, /Operator issuance changed/);
  assert(!calls.some(([name, , operation]) => name === "aws" && operation === "put-object"));
  assert(!calls.some(([name, , operation]) => name === "terraform" && operation === "apply"));
});

test("sole initiator may explicitly approve exact plan; installation reserves once and verifies", (t) => {
  const { calls, apply, dir } = installation(t);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(dir, "preparation.json"))).iamInstallation, { receiptSha256: hash(JSON.stringify(receipt())), transitionId: receipt().transitionId, documentBindingsSha256: digest(documentBindings()) });
  apply();
  const writes = calls.filter(([name, , operation]) => name === "aws" && operation === "put-object");
  assert.equal(writes.length, 1);
  const applies = calls.filter(([name, , operation]) => name === "terraform" && operation === "apply");
  assert.equal(applies.length, 1);
  assert(applies[0].at(-1).endsWith("/activation.tfplan"));
  assert(calls.indexOf(writes[0]) < calls.indexOf(applies[0]));
  assert.equal(writes[0][writes[0].indexOf("--key") + 1], `${contract.key}.initial-activation-attempt`);
  assert(calls.some(([name, , operation, ...args]) => name === "terraform" && operation === "plan" && args.includes("-detailed-exitcode")));
});
for (const [label, mutate] of [
  ["schema", (r) => { r.schemaVersion = 2; }],
  ["stale source", (r) => { r.sourceSha = "c".repeat(40); }],
  ["transition", (r) => { r.transitionId = "not-uuid"; }],
  ["authorization", (r) => { r.authorizationSha256 = "bad"; }],
  ["documents", (r) => { r.documentBindingsSha256 = "c".repeat(64); }],
  ["unverified", (r) => { r.state = "IAM_INSTALLING"; }],
  ["missing target", (r) => { r.live.pop(); }],
  ["forged target", (r) => { r.live[0].arn += "other"; }],
  ["absent policy", (r) => { r.live[0].policy = "ABSENT"; }],
]) test(`receipt rejects ${label} before any Terraform`, (t) => {
  installation(t, { rejectPrepare: true, storedReceipt: () => { const r = receipt(); mutate(r); return r; } });
});
test("missing AWS receipt rejects even when a caller provides valid local JSON", (t) => {
  installation(t, { rejectPrepare: true, forgedLocal: true, storedReceipt: () => null });
});
for (const [label, mutate] of [
  ["wrong policy", (value) => { if (value.PolicyDocument) value.PolicyDocument = {}; }],
  ["wrong release policy", (value, target) => { if (!target.trust && value.PolicyDocument) value.PolicyDocument = {}; }],
  ["wrong trust", (value) => { if (value.Role?.AssumeRolePolicyDocument) value.Role.AssumeRolePolicyDocument = {}; }],
  ["wrong path", (value) => { if (value.Role) value.Role.Path = "/other/"; }],
  ["wrong duration", (value) => { if (value.Role) value.Role.MaxSessionDuration = 7200; }],
  ["boundary", (value) => { if (value.Role) value.Role.PermissionsBoundary = {}; }],
  ["additional managed policy", (value) => { if (value.AttachedPolicies) value.AttachedPolicies.push({ PolicyArn: "unexpected" }); }],
  ["additional inline policy", (value) => { if (value.PolicyNames) value.PolicyNames.push("unexpected"); }],
  ["truncated policy inventory", (value) => { if (value.PolicyNames) value.IsTruncated = true; }],
  ["wrong transition", (value) => { if (value.Role) value.Role.Tags = [{ Key: "Transition", Value: "other" }]; }],
  ["missing IAM", () => { throw new Error("NoSuchEntity"); }],
]) test(`live IAM rejects ${label} before any Terraform`, (t) => {
  installation(t, { rejectPrepare: true, liveMutation: mutate });
});
test("apply rejects changed receipt bytes before any apply-time Terraform", (t) => {
  const { calls, apply } = installation(t, { storedReceipt: (applying) => ({ ...receipt(), ...(applying ? { authorizationSha256: "c".repeat(64) } : {}) }) });
  const before = calls.length;
  assert.throws(apply, /IAM installation changed/);
  assert(!calls.slice(before).some(([name]) => name === "terraform"));
  assert(!calls.some(([name, , operation]) => name === "aws" && operation === "put-object"));
});
test("receipt is re-read after approval and a mid-apply change prevents reservation", (t) => {
  const { calls, apply } = installation(t, { storedReceipt: (applying, calls) => ({ ...receipt(), ...(applying && calls.some(([name, operation]) => name === "gh" && operation === "run") ? { authorizationSha256: "c".repeat(64) } : {}) }) });
  assert.throws(apply, /IAM installation changed/);
  assert(!calls.some(([name, , operation]) => name === "aws" && operation === "put-object"));
});
test("live IAM is reauthenticated at apply even if receipt is unchanged", (t) => {
  const { calls, apply } = installation(t, { liveMutation: (value, target, applying) => { if (applying && value.PolicyDocument) value.PolicyDocument = {}; } });
  const before = calls.length;
  assert.throws(apply);
  assert(!calls.slice(before).some(([name]) => name === "terraform"));
});
for (const scenario of [{ changedSource: true }, { changedPlan: true }, { existingState: true }, { replay: true }, { approval: false }, { wrongReviewer: true }, { wrongInitiator: true }, { wrongApprovalEnvironment: true }]) {
  test(`mocked installation rejects before apply: ${JSON.stringify(scenario)}`, (t) => {
    const { calls, apply } = installation(t, scenario);
    assert.throws(apply);
    assert(!calls.some(([name, , operation]) => name === "terraform" && operation === "apply"));
  });
}
