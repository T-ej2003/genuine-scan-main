#!/usr/bin/env node
// One-time installation only. No application deployment or component bootstrap.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCredentialEnvironment, createProductionGithubCredentialEnvironment, createAssumedRoleSessionEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const stack = "infra/aws/terraform/production-component-deployment-state";
export const contract = JSON.parse(fs.readFileSync(path.join(root, stack, "state-backend-contract.json")));
const repository = "T-ej2003/genuine-scan-main";
const workflow = "authorize-component-infrastructure-activation.yml";
export const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const json = (file) => JSON.parse(fs.readFileSync(file));

// Only an AWS-authenticated issuance event proves how this exact session arose.
// Session names, local profile configuration and operator-supplied receipts do not.
export function authenticateOperatorSession({ caller, credentials, events, now = Date.now() }) {
  assert.equal(caller.Account, contract.account);
  assert.match(caller.Arn, /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  assert(typeof caller.UserId === "string" && caller.UserId.length > 0, "Session principal ID required");
  assert(typeof credentials.AccessKeyId === "string" && credentials.AccessKeyId.length > 0, "Session key identity required");
  assert(Date.parse(credentials.Expiration) > now + 10 * 60 * 1000, "Operator session needs at least ten minutes remaining");
  const matches = events.filter((event) => event.responseElements?.credentials?.accessKeyId === credentials.AccessKeyId);
  assert.equal(matches.length, 1, "Unique AWS session issuance evidence required");
  const event = matches[0];
  assert.equal(event.eventSource, "sts.amazonaws.com");
  assert.equal(event.eventName, "AssumeRole");
  assert.equal(event.recipientAccountId, contract.account);
  assert.equal(event.errorCode, undefined);
  assert.equal(event.userIdentity?.type, "IAMUser");
  assert.equal(event.userIdentity?.arn, `arn:aws:iam::${contract.account}:user/mscqr-production-bootstrap-operator`);
  assert.equal(event.userIdentity?.accountId, contract.account);
  assert.equal(event.userIdentity?.sessionContext?.attributes?.mfaAuthenticated, "true");
  assert.equal(event.requestParameters?.roleArn, `arn:aws:iam::${contract.account}:role/mscqr-production-release-deployer`);
  assert.equal(event.responseElements?.assumedRoleUser?.arn, caller.Arn);
  assert.equal(event.responseElements?.assumedRoleUser?.assumedRoleId, caller.UserId);
  assert.equal(Date.parse(event.responseElements.credentials.expiration), Date.parse(credentials.Expiration));
  assert(now - Date.parse(event.eventTime) >= 0 && now - Date.parse(event.eventTime) < 60 * 60 * 1000, "Operator issuance evidence expired");
  assert.match(event.eventID || "", /^[a-f0-9-]{36}$/);
  return { eventId: event.eventID, operatorArn: event.userIdentity.arn, sessionKeySha256: hash(credentials.AccessKeyId) };
}

export function assertBackend(backend, workspace) {
  assert.equal(backend.type, "s3");
  for (const field of ["bucket", "key", "region", "encrypt", "use_lockfile"]) assert.deepEqual(backend.config[field], contract[field], `Wrong backend ${field}`);
  assert.deepEqual(backend.config.allowed_account_ids, [contract.account]);
  assert.equal(workspace, "default");
  for (const field of ["endpoint", "endpoints", "assume_role", "assume_role_with_web_identity", "profile", "skip_credentials_validation", "skip_requesting_account_id", "skip_region_validation"]) assert(!backend.config[field], `Backend override: ${field}`);
}

export function assertInitialPlan(plan) {
  assert.equal(plan.errored, false);
  assert.equal(plan.applyable, true);
  const providers = plan.configuration.provider_config;
  assert.deepEqual(Object.keys(providers), ["aws"]);
  assert.equal(providers.aws.full_name, "registry.terraform.io/hashicorp/aws");
  assert.deepEqual(providers.aws.expressions, { allowed_account_ids: { constant_value: [contract.account] }, region: { constant_value: contract.region } });
  const configuration = plan.configuration.root_module;
  assert.equal(Object.keys(configuration.module_calls || {}).length, 0);
  assert(configuration.resources.every((resource) => !resource.provisioners?.length));
  for (const name of ["normal_deployer", "bootstrap"]) {
    const resource = configuration.resources.find(({ address }) => address === `aws_iam_role_policy.${name}`);
    assert.deepEqual(resource.expressions.role.references, [`aws_iam_role.${name}.id`, `aws_iam_role.${name}`]);
  }
  const changes = (plan.resource_changes || []).filter((item) => item.mode === "managed");
  assert.deepEqual(changes.map((item) => item.address).sort(), [...contract.expectedManagedAddresses].sort());
  for (const item of changes) assert.deepEqual(item.change.actions, ["create"], `Not initial create: ${item.address}`);
  assert.equal((plan.resource_drift || []).length, 0);
  assert.equal((plan.prior_state?.values?.root_module?.resources || []).filter((item) => item.mode === "managed").length, 0);
  const get = (address) => changes.find((item) => item.address === address).change.after;
  for (const [name, role, policy] of [
    ["normal_deployer", "mscqr-production-normal-deployer", "MSCQRProductionNormalDeployment"],
    ["bootstrap", "mscqr-production-component-state-bootstrap", "MSCQRProductionComponentStateBootstrap"],
  ]) {
    const value = get(`aws_iam_role.${name}`);
    assert.equal(value.name, role);
    assert.equal(value.path, "/");
    assert.equal(value.max_session_duration, 3600);
    const prefix = name === "normal_deployer" ? "normal-deployer" : "bootstrap";
    assert.deepEqual(JSON.parse(value.assume_role_policy), json(path.join(root, stack, `${prefix}-trust-policy.json`)));
    assert.equal(get(`aws_iam_role_policy.${name}`).name, policy);
    assert.deepEqual(JSON.parse(get(`aws_iam_role_policy.${name}`).policy), json(path.join(root, stack, `${prefix}-policy.json`)));
  }
  const terminal = get("aws_iam_role_policy.release_terminal_state");
  assert.equal(terminal.name, "MSCQRProductionComponentStateTerminalWriter");
  assert.equal(terminal.role, "mscqr-production-release-deployer");
  assert.deepEqual(JSON.parse(terminal.policy), json(path.join(root, stack, "release-terminal-state-policy.json")));
  const table = get("aws_dynamodb_table.component_deployment_state");
  assert.equal(table.name, "mscqr-production-component-deployment-state");
  assert.equal(table.hash_key, "stateKey");
  assert.equal(table.billing_mode, "PAY_PER_REQUEST");
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
  assert.equal(rules[0].prevent_self_review, true);
  assert(rules[0].reviewers.length > 0);
  assert(rules[0].reviewers.every(({ type, reviewer }) => type === "User" && Number.isSafeInteger(reviewer.id)));
  return rules[0].reviewers.map(({ reviewer }) => reviewer.id);
}

export function run(argv = process.argv.slice(2), deps = {}) {
  const [mode, directory, approvalRun] = argv;
  assert(["prepare", "apply"].includes(mode), "Expected prepare or apply");
  assert.equal(argv.length, mode === "prepare" ? 2 : 3);
  const work = fs.realpathSync(directory);
  assert(!work.startsWith(`${root}/`) && work !== root, "Plan directory must be outside checkout");
  assert.equal(fs.statSync(work).mode & 0o077, 0, "Private plan directory required");
  // Canonical safelists isolate AWS/Terraform from redirects and GitHub tokens.
  const inherited = deps.env || process.env;
  let env = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: contract.region, env: inherited }), AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true", TF_WORKSPACE: "default", TF_DATA_DIR: path.join(work, "terraform-data") };
  const localEnvironment = env;
  const githubEnvironment = createProductionGithubCredentialEnvironment({ env: inherited });
  const exec = (name, args) => (deps.execute || execFileSync)(name, args, { cwd: root, env: name === "gh" ? githubEnvironment : name === "git" ? localEnvironment : env, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }).trim();
  const aws = (...args) => JSON.parse(exec("aws", [...args, "--region", contract.region, "--no-cli-pager", "--output", "json"]) || "{}");
  const gh = (endpoint) => JSON.parse(exec("gh", ["api", `repos/${repository}/${endpoint}`]));
  const tf = (...args) => exec("terraform", [`-chdir=${stack}`, ...args]);
  const source = () => {
    exec("git", ["fetch", "origin", "main"]);
    const sha = exec("git", ["rev-parse", "HEAD"]);
    assert.equal(sha, exec("git", ["rev-parse", "origin/main"]));
    assert.equal(sha, gh("branches/main").commit.sha);
    assert.equal(exec("git", ["status", "--porcelain", "--untracked-files=all"]), "");
    return sha;
  };
  const sourceSha = source();
  const tracked = new Set(exec("git", ["ls-files", stack]).split("\n").map((file) => path.basename(file)));
  for (const file of fs.readdirSync(path.join(root, stack))) {
    if (/\.(tf|tf\.json|tfvars|tfvars\.json)$/.test(file)) assert(tracked.has(file), `Untracked Terraform input: ${file}`);
  }
  // Resolve once, privately, then pin the verified session for all AWS/Terraform
  // children so a profile refresh cannot substitute credentials after the check.
  let credentials;
  try { credentials = aws("configure", "export-credentials", "--format", "process"); }
  catch { throw new Error("Unable to resolve the pinned operator session"); }
  env = { ...createAssumedRoleSessionEnvironment({ credentials, env: inherited, region: contract.region }), AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true", TF_WORKSPACE: "default", TF_DATA_DIR: path.join(work, "terraform-data") };
  const caller = aws("sts", "get-caller-identity");
  // CloudTrail is an existing administrator read boundary, never an added
  // release-role permission. Administrator credentials never reach Terraform.
  const auditEnv = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", env: inherited, region: contract.region }), AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true" };
  const audit = (args, region = contract.region) => {
    try { return JSON.parse((deps.execute || execFileSync)("aws", [...args, "--region", region, "--no-cli-pager", "--output", "json"], { cwd: root, env: auditEnv, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 })); }
    catch { throw new Error("Administrator session provenance read failed; no installation permitted"); }
  };
  const administrator = audit(["sts", "get-caller-identity"]);
  assert.equal(administrator.Account, contract.account);
  assert.equal(administrator.Arn, `arn:aws:iam::${contract.account}:root`);
  const events = new Map();
  const now = Date.now();
  // Regional STS and the existing global STS operator path have distinct logs.
  for (const region of [contract.region, "us-east-1"]) {
    let token;
    for (let page = 0; page < 20; page++) {
      const response = audit(["cloudtrail", "lookup-events", "--lookup-attributes", "AttributeKey=EventName,AttributeValue=AssumeRole", "--start-time", new Date(now - 60 * 60 * 1000).toISOString(), "--end-time", new Date(now).toISOString(), "--no-paginate", ...(token ? ["--next-token", token] : [])], region);
      for (const entry of response.Events || []) {
        let event;
        try { event = JSON.parse(entry.CloudTrailEvent); }
        catch { throw new Error("Malformed AWS issuance event; no installation permitted"); }
        events.set(event.eventID, event);
      }
      token = response.NextToken;
      if (!token) break;
    }
    assert(!token, "Operator provenance pagination exceeded bound");
  }
  const operatorProvenance = authenticateOperatorSession({ caller, credentials, events: [...events.values()], now });
  const absent = () => {
    const listing = aws("s3api", "list-objects-v2", "--bucket", contract.bucket, "--prefix", contract.key);
    assert(!(listing.Contents || []).some(({ Key }) => Key === contract.key || Key === `${contract.key}.tflock`), "State/lock already exists: stop and reconcile");
    const history = aws("s3api", "list-object-versions", "--bucket", contract.bucket, "--prefix", contract.key);
    assert(![...(history.Versions || []), ...(history.DeleteMarkers || [])].some(({ Key }) => Key === contract.key), "Historical state exists: not a first initialization");
  };
  const liveAbsent = () => {
    for (const [args, code] of [
      [["iam", "get-role", "--role-name", "mscqr-production-normal-deployer"], "NoSuchEntity"],
      [["iam", "get-role", "--role-name", "mscqr-production-component-state-bootstrap"], "NoSuchEntity"],
      [["iam", "get-role-policy", "--role-name", "mscqr-production-release-deployer", "--policy-name", "MSCQRProductionComponentStateTerminalWriter"], "NoSuchEntity"],
      [["dynamodb", "describe-table", "--table-name", "mscqr-production-component-deployment-state"], "ResourceNotFoundException"],
    ]) {
      let missing = false;
      try { aws(...args); } catch (error) {
        if (!String(error.stderr).includes(`(${code})`)) throw error;
        missing = true;
      }
      assert(missing, `Live prerequisite already exists: ${args[1]}`);
    }
  };
  assert.equal(aws("s3api", "get-bucket-versioning", "--bucket", contract.bucket).Status, "Enabled");
  for (const name of ["production-normal-deploy", "production-component-state-bootstrap", contract.authorizationEnvironment]) {
    assertEnvironment(gh(`environments/${name}`), gh(`environments/${name}/deployment-branch-policies`));
  }
  absent();
  liveAbsent();
  assert.equal(JSON.parse(exec("terraform", ["version", "-json"])).terraform_version, "1.15.8");
  tf("init", "-input=false", "-upgrade=false", "-lockfile=readonly");
  assertBackend(json(path.join(env.TF_DATA_DIR, "terraform.tfstate")).backend, tf("workspace", "show"));
  tf("validate");
  const planPath = path.join(work, "activation.tfplan");
  const preparationPath = path.join(work, "preparation.json");
  if (mode === "prepare") {
    assert(!fs.existsSync(planPath) && !fs.existsSync(preparationPath), "Use a fresh private plan directory");
    tf("plan", "-input=false", "-lock-timeout=0s", `-out=${planPath}`);
    assertInitialPlan(JSON.parse(tf("show", "-json", planPath)));
    absent();
    assert.equal(source(), sourceSha);
    const preparation = { sourceSha, backend: contract, stateIdentity: "ABSENT", operatorArn: caller.Arn, operatorProvenance, planSha256: hash(fs.readFileSync(planPath)) };
    fs.writeFileSync(preparationPath, `${JSON.stringify(preparation, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    process.stdout.write(`${JSON.stringify({ ...preparation, preparationSha256: hash(fs.readFileSync(preparationPath)) }, null, 2)}\n`);
    return;
  }
  assert.match(approvalRun || "", /^[1-9][0-9]*$/);
  const run = gh(`actions/runs/${approvalRun}`);
  assert.equal(run.path, `.github/workflows/${workflow}`);
  assert.equal(run.head_sha, sourceSha);
  assert.equal(run.head_branch, "main");
  assert.equal(run.head_repository.full_name, repository);
  assert.equal(run.event, "workflow_dispatch");
  assert.equal(run.conclusion, "success");
  assert.equal(run.run_attempt, 1, "Rerun authorization is forbidden");
  assert(Date.now() - Date.parse(run.created_at) >= 0 && Date.now() - Date.parse(run.created_at) < 30 * 60 * 1000, "Authorization expired");
  const config = gh(`environments/${contract.authorizationEnvironment}`);
  const reviewers = assertEnvironment(config, gh(`environments/${contract.authorizationEnvironment}/deployment-branch-policies`));
  const approvals = gh(`actions/runs/${approvalRun}/approvals`).filter((item) => item.state === "approved" && item.environments.some(({ id }) => id === config.id));
  assert.equal(approvals.length, 1);
  assert(reviewers.includes(approvals[0].user.id));
  assert.notEqual(approvals[0].user.id, run.actor.id);
  const download = fs.mkdtempSync(path.join(os.tmpdir(), "component-activation-approval-"));
  exec("gh", ["run", "download", approvalRun, "--repo", repository, "--name", "component-infrastructure-authorization", "--dir", download]);
  const authorization = json(path.join(download, "authorization.json"));
  const preparation = json(preparationPath);
  const planSha256 = hash(fs.readFileSync(planPath));
  assertAuthorization(authorization, preparation, { sourceSha, planSha256, preparationSha256: hash(fs.readFileSync(preparationPath)) });
  assert.equal(preparation.operatorArn, caller.Arn, "Operator session changed: prepare and authorize again");
  assert.deepEqual(preparation.operatorProvenance, operatorProvenance, "Operator issuance changed: prepare and authorize again");
  assertInitialPlan(JSON.parse(tf("show", "-json", planPath)));
  absent();
  liveAbsent();
  assert.equal(source(), sourceSha);
  // Permanent one-time reservation, before apply. An ambiguous result requires
  // read-only investigation, never another apply or deletion of this record.
  aws("s3api", "put-object", "--bucket", contract.bucket, "--key", `${contract.key}.initial-activation-attempt`, "--body", preparationPath, "--if-none-match", "*", "--server-side-encryption", "AES256");
  assert.equal(hash(fs.readFileSync(planPath)), planSha256);
  tf("apply", "-input=false", "-lock-timeout=0s", planPath);
  // Terraform drift readback is required, and must not become a second apply.
  tf("plan", "-input=false", "-lock-timeout=0s", "-detailed-exitcode");
  process.stdout.write("INFRA_ACTIVATION_VERIFIED=true\nBOOTSTRAP_EXECUTED=false\n");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) run();
