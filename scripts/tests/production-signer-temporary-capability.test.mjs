import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import { assertCanonicalPolicyHistory, assertSignerBootstrapIdentity, assertSignerCliArguments, assertSignerInstallerIdentity } from "../aws/reconcile-production-signer-temporary-capability.mjs";
import {
  SIGNER_TEMPORARY_CAPABILITY as C, assertSignerCapabilityEvidence, assertSignerCreationPlan, assertSignerRevocation,
  assertSignerInitializedBackendMetadata, assertSignerPolicySoleConsumer, assertSignerTemporaryPolicy, buildSignerCapabilityEvidence, buildSignerTemporaryPolicy,
  resolveSignerTemporaryVersionId, signerTemporaryStatements,
} from "../aws/production-signer-temporary-capability.mjs";

const sourceSha = "0cbce2080bf38f7f071047fef3b982805336ffb5", transitionId = "signer-once-20260927";
const steady = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const historicalPolicies = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-stage-a-historical-policies.json", "utf8"));
const trust = JSON.parse(fs.readFileSync("infra/aws/terraform/production-security-rebaseline-signer/trust-policy.json", "utf8"));
const expectedOps = new Map([
  ["s3:GetObject", [`arn:aws:s3:::${C.bucket}/${C.stateKey}`, `arn:aws:s3:::${C.bucket}/${C.lockKey}`]],
  ["s3:PutObject", [`arn:aws:s3:::${C.bucket}/${C.stateKey}`, `arn:aws:s3:::${C.bucket}/${C.lockKey}`]],
  ["s3:DeleteObject", [`arn:aws:s3:::${C.bucket}/${C.lockKey}`]],
  ["s3:ListBucket", [`arn:aws:s3:::${C.bucket}`]],
  ["iam:CreateRole", [C.roleArn]], ["iam:PutRolePolicy", [C.roleArn]], ["iam:ListAttachedRolePolicies", [C.roleArn]],
  ["kms:CreateKey", ["*"]], ["kms:PutKeyPolicy", ["arn:aws:kms:eu-west-2:368992683803:key/*"]],
  ["kms:GetKeyRotationStatus", ["arn:aws:kms:eu-west-2:368992683803:key/*"]],
  ["kms:CreateAlias", [`arn:aws:kms:eu-west-2:368992683803:alias/${C.alias.slice(6)}`]],
]);
const grants = (policy, action, resource) => policy.Statement.some((statement) => {
  const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
  const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
  return statement.Effect === "Allow" && actions.includes(action) && resources.some((candidate) => candidate === "*" || candidate === resource);
});

test("policy-version mutations require the independent workflow installer, while release work requires the MFA bootstrap operator", () => {
  assert.equal(assertSignerBootstrapIdentity("mscqr-production-bootstrap-mfa", { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator` }), `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator`);
  for (const [profile, caller] of [
    ["default", { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:root` }],
    ["mscqr-production-release-deployer", { Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/mscqr-production-release-deployer/session` }],
    ["another-profile", { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator` }],
    ["mscqr-production-bootstrap-mfa", { Account: "111111111111", Arn: "arn:aws:iam::111111111111:user/mscqr-production-bootstrap-operator" }],
  ]) assert.throws(() => assertSignerBootstrapIdentity(profile, caller));
  assert.equal(assertSignerInstallerIdentity({ Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/${C.installerRoleName}/workflow` }), `arn:aws:sts::${C.accountId}:assumed-role/${C.installerRoleName}/workflow`);
  for (const caller of [{ Account: "111111111111", Arn: `arn:aws:sts::111111111111:assumed-role/${C.installerRoleName}/workflow` }, { Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/mscqr-production-release-deployer/workflow` }, { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:root` }]) assert.throws(() => assertSignerInstallerIdentity(caller));
  const base = ["--phase", "policy-install", "--source-sha", sourceSha, "--transition-id", transitionId, "--state-file", "/tmp/capability.json"];
  assert.doesNotThrow(() => assertSignerCliArguments(base, "policy-install"));
  const prepare = [...base]; prepare[1] = "policy-install-prepare";
  assert.doesNotThrow(() => assertSignerCliArguments(prepare, "policy-install-prepare"));
  assert.throws(() => assertSignerCliArguments(["--phase", "install", "--source-sha", sourceSha, "--transition-id", transitionId, "--bootstrap-profile", "mscqr-production-bootstrap-mfa", "--state-file", "/tmp/capability.json"], "install"), /unsupported phase/);
  assert.throws(() => assertSignerCliArguments(base.slice(0, -2), "policy-install"), /--state-file is required/);
  const planArgs = ["--phase", "plan", "--source-sha", sourceSha, "--transition-id", transitionId, "--bootstrap-profile", "mscqr-production-bootstrap-mfa", "--state-file", "/tmp/capability.json"];
  assert.throws(() => assertSignerCliArguments(planArgs, "plan"), /--plan-output is required/);
  const revocation = [...base]; revocation[1] = "policy-revoke";
  assert.doesNotThrow(() => assertSignerCliArguments(revocation, "policy-revoke"));
  assert.doesNotThrow(() => assertSignerCliArguments([...revocation, "--abort-before-apply-confirmed"], "policy-revoke"));
  assert.throws(() => assertSignerCliArguments([...base, "--abort-before-apply-confirmed"], "policy-install"));
  const local = ["--phase", "verify-absent", "--source-sha", sourceSha, "--transition-id", transitionId, "--bootstrap-profile", "mscqr-production-bootstrap-mfa", "--state-file", "/tmp/capability.json"];
  assert.doesNotThrow(() => assertSignerCliArguments(local, "verify-absent"));
  for (const option of ["--admin-profile", "--policy-arn", "--policy-name", "--policy-document", "--policy-file", "--state-key", "--role-arn", "--kms-key"]) assert.throws(() => assertSignerCliArguments([...base, option, "attacker-value"], "policy-install"));
  assert.throws(() => assertSignerCliArguments([...base, "--bootstrap-profile", "attacker-profile"], "policy-install"));
});

test("bootstrap cannot create policy versions; the independent installer can transition only the canonical policy", () => {
  const predecessor = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionBootstrapOperator-v1.json", "utf8"));
  const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionBootstrapOperator-v2.json", "utf8"));
  const target = "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageARelease";
  assert.equal(predecessor.Statement.some(({ Action, Resource }) => (Array.isArray(Action) ? Action : [Action]).includes("iam:CreatePolicyVersion") && Resource === target), false, "the pre-fix bootstrap policy could not install or revoke the signer version");
  assert.equal(policy.Statement.some(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes("iam:CreatePolicyVersion")), false);
  assert.equal(grants(steady, "iam:CreatePolicyVersion", target), false, "release-deployer cannot write the signer policy directly");
  const publisherBootstrap = JSON.parse(fs.readFileSync("infra/aws/terraform/production-green-stage-b-publisher-bootstrap/permissions-policy.json", "utf8"));
  const installerRoleArn = `arn:aws:iam::${C.accountId}:role/${C.installerRoleName}`;
  for (const action of ["iam:CreateRole", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PassRole", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]) {
    assert.equal(grants(publisherBootstrap, action, target), false, `bootstrap's other assumable role cannot ${action} the signer policy`);
    assert.equal(grants(publisherBootstrap, action, installerRoleArn), false, `bootstrap's other assumable role cannot ${action} the installer`);
  }
  for (const action of ["iam:CreateRole", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PassRole", "sts:AssumeRole"]) {
    assert.equal(grants(policy, action, installerRoleArn), false, `bootstrap cannot ${action} the installer role`);
    assert.equal(grants(steady, action, installerRoleArn), false, `release policy cannot ${action} the installer role`);
  }
  for (const denied of ["iam:*", "iam:CreatePolicy", "iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:PassRole", "iam:DeletePolicyVersion", "kms:ListKeys", "kms:ListResourceTags", "kms:PutKeyPolicy", "kms:Decrypt", "kms:CreateGrant"]) assert.equal(policy.Statement.some(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes(denied)), false, denied);
  assert.equal(JSON.stringify(policy).replace(/\s/g, "").length <= 2048, true);
  assert.equal(grants(policy, "s3:GetObject", `arn:aws:s3:::${C.bucket}/${C.stateKey}`), false);
  assert.equal(grants(policy, "s3:PutObject", `arn:aws:s3:::${C.bucket}/${C.stateKey}`), false);
  assert.equal(JSON.stringify(policy).replace(/\s/g, "").length <= 2048, true, "bootstrap's single canonical inline policy fits IAM's aggregate user quota");
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.match(source, /policy-install-prepare[\s\S]*?protect\(stateFile, pending\)[\s\S]*?return pending/);
  assert.match(source, /evidence\.state !== "INSTALLING"[\s\S]*?writePolicyVersion\(undefined, temporary/);
  assert.match(source, /current\.active\.VersionId !== temporaryVersionId\)[\s\S]*?canonical\(current\.active\.document\) !== canonical\(steadyPolicy\)[\s\S]*?recovered: true/);
  assert.doesNotMatch(source, /--admin-profile|admin\s*=\s*opt\(/);
  assert.doesNotMatch(source, /writePolicyVersion\(bootstrap,/);
  assert.match(source, /writePolicyVersion\(undefined, temporary, current\.active\.VersionId, env\)/);
  assert.match(source, /writePolicyVersion\(undefined, steadyPolicy, temporaryVersionId, env\)/);
  const installer = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-permissions-policy.json", "utf8"));
  assert.deepEqual(installer.Statement.find(({ Sid }) => Sid === "CreateExactCanonicalSignerPolicyVersions").Action, "iam:CreatePolicyVersion");
  assert.equal(grants(installer, "iam:CreatePolicyVersion", target), true);
  assert.equal(grants(installer, "iam:CreatePolicyVersion", "arn:aws:iam::368992683803:policy/other"), false);
  for (const denied of ["iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy", "kms:PutKeyPolicy", "kms:Decrypt", "s3:PutObject", "ecs:UpdateService", "rds:ModifyDBInstance", "secretsmanager:PutSecretValue"]) assert.equal(installer.Statement.some(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes(denied)), false, denied);
  const trustPolicy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-trust-policy.json", "utf8"));
  assert.deepEqual(trustPolicy.Statement[0].Principal, { Federated: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" });
  assert.equal(trustPolicy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production-signer-policy-transition");
  assert.equal(trustPolicy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:job_workflow_ref"], "T-ej2003/genuine-scan-main/.github/workflows/production-signer-policy-transition-operation.yml@refs/heads/main");
  assert.deepEqual(Object.keys(trustPolicy.Statement[0].Condition.StringEquals).sort(), ["token.actions.githubusercontent.com:aud", "token.actions.githubusercontent.com:job_workflow_ref", "token.actions.githubusercontent.com:ref", "token.actions.githubusercontent.com:repository_id", "token.actions.githubusercontent.com:repository_owner_id", "token.actions.githubusercontent.com:sub"].sort());

  const transitionWorkflow = fs.readFileSync(".github/workflows/production-signer-policy-transition.yml", "utf8");
  const transitionOperation = fs.readFileSync(".github/workflows/production-signer-policy-transition-operation.yml", "utf8");
  assert.match(transitionWorkflow, /type: choice[\s\S]*?options: \[policy-install, policy-revoke\]/);
  assert.match(transitionWorkflow, /abort_before_apply:[\s\S]*?type: boolean/);
  assert.match(transitionOperation, /args\+=\(--abort-before-apply-confirmed\)/);
  const approvalStep = transitionOperation.split("- name: Authenticate independent production approval")[1].split("\n      - ")[0];
  const mutationStep = transitionOperation.split("- name: Apply canonical transition only")[1].split("\n      - ")[0];
  assert.match(approvalStep, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
  assert.match(mutationStep, /ABORT_BEFORE_APPLY: \$\{\{ inputs\.abort_before_apply \}\}/);
  assert.match(transitionWorkflow, /uses: \.\/\.github\/workflows\/production-signer-policy-transition-operation\.yml/);
  assert.match(transitionOperation, /workflow_call:/);
  assert.match(transitionOperation, /environment: production-signer-policy-transition/);
  assert.match(transitionOperation, /--require-actual-approval/);
  assert.match(transitionOperation, /deployment-branch-policies/);
  assert.match(transitionOperation, /test "\$branch_policies" = '\[\{"type":"branch","name":"main"\}\]'/);
  assert.match(transitionOperation, /assertSignerSource\(process\.env\.SOURCE_SHA, \{ cleanupReadback: process\.env\.PHASE === 'policy-revoke' \}\)/);
  assert.match(transitionOperation, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-signer-policy-installer/);
  assert.match(transitionOperation, /EVIDENCE_BASE64\}" -le 16384[\s\S]*?EVIDENCE_SHA256\" =~ \^\[a-f0-9\]\{64\}\$/);
  assert.ok(transitionOperation.indexOf("Validate canonical transition inputs") < transitionOperation.indexOf("Configure exact signer policy installer role"));
  assert.match(transitionOperation, /Invalid transition phase/);
  assert.doesNotMatch(transitionWorkflow + transitionOperation, /policy-document|policy-arn|policy-file|admin-profile/);

  const bootstrapProvisioner = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationPolicyReconcilerBootstrapPermissions-v1.json", "utf8"));
  const roleArn = `arn:aws:iam::${C.accountId}:role/${C.installerRoleName}`;
  const signerStatements = bootstrapProvisioner.Statement.filter((statement) => JSON.stringify(statement.Resource).includes(roleArn));
  assert.deepEqual(signerStatements.find(({ Action }) => Action === "iam:CreateRole"), { Sid: "SignerRoleCreate", Effect: "Allow", Action: "iam:CreateRole", Resource: roleArn });
  assert.deepEqual(signerStatements.find(({ Action }) => Action === "iam:PutRolePolicy"), { Sid: "SignerPolicyPut", Effect: "Allow", Action: "iam:PutRolePolicy", Resource: roleArn, Condition: { StringEquals: { "iam:PolicyName": "ProductionSignerPolicyInstaller" } } });
  assert.deepEqual(signerStatements.find(({ Sid }) => Sid === "MixedRecoveryRoleRead").Action, ["iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:ListRoleTags"]);
  assert.deepEqual(signerStatements.find(({ Sid }) => Sid === "BootstrapInlineRead"), { Sid: "BootstrapInlineRead", Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"], Resource: ["arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler-bootstrap", roleArn] });
  assert.equal(signerStatements.find(({ Action }) => Action === "iam:PutRolePolicy").Condition.StringEquals["iam:PolicyName"], "ProductionSignerPolicyInstaller");
  assert.equal(signerStatements.some(({ Action }) => (Array.isArray(Action) ? Action : [Action]).some((action) => ["iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:PassRole"].includes(action))), false);
  const bootstrapTrust = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationPolicyReconcilerBootstrapTrust-v1.json", "utf8"));
  assert.equal(bootstrapTrust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"], "repo:T-ej2003/genuine-scan-main:environment:production-initial-activation-reconciler-bootstrap");
});

test("temporary delta is source/nonce bound and excludes unrelated state, IAM, and KMS data actions", () => {
  const statements = signerTemporaryStatements({ sourceSha, transitionId });
  assert.equal(statements.length, 15);
  const temporary = buildSignerTemporaryPolicy(steady, { sourceSha, transitionId });
  assertSignerTemporaryPolicy(temporary, { steadyPolicy: steady, sourceSha, transitionId });
  const stateArn = `arn:aws:s3:::${C.bucket}/${C.stateKey}`;
  const otherStateArn = `arn:aws:s3:::${C.bucket}/mscqr/production/other/terraform.tfstate`;
  assert.equal(grants(steady, "s3:GetObject", stateArn), false, "pre-fix release operator lacks signer state access");
  assert.equal(grants(steady, "iam:CreateRole", C.roleArn), false, "pre-fix release operator lacks signer role creation");
  assert.equal(grants(steady, "kms:CreateKey", "*"), false, "pre-fix release operator lacks signer key creation");
  assert.equal(grants(temporary, "s3:GetObject", stateArn), true);
  assert.equal(grants(temporary, "s3:GetObject", otherStateArn), false);
  const list = statements.find(({ Action }) => Action === "s3:ListBucket");
  assert.deepEqual(list.Condition.StringLike["s3:prefix"], [C.stateKey, C.lockKey]);
  assert.equal(grants(temporary, "iam:CreateRole", C.roleArn), true);
  assert.equal(grants(temporary, "iam:CreateRole", "arn:aws:iam::368992683803:role/unrelated"), false);
  assert.equal(grants(temporary, "iam:GetRole", C.roleArn), true);
  assert.equal(grants(temporary, "kms:ListKeys", "*"), true);
  const census = statements.find(({ Action, Sid }) => Action === "kms:ListResourceTags" && Sid.startsWith("TemporarySignerKeyCensus"));
  assert.deepEqual(census.Resource, "arn:aws:kms:eu-west-2:368992683803:key/*");
  assert.deepEqual(census.Condition, { StringEquals: { "aws:RequestedRegion": C.region } });
  assert.equal(grants(temporary, "kms:Decrypt", "arn:aws:kms:eu-west-2:368992683803:key/unrelated"), false);
  assert.throws(() => assertSignerRevocation({ activePolicy: temporary, temporaryPolicy: temporary, activeVersionId: "v2", temporaryVersionId: "v2", steadyPolicy: steady, identity: { sourceSha, transitionId } }));
  assert.equal(assertSignerRevocation({ activePolicy: steady, temporaryPolicy: temporary, activeVersionId: "v3", temporaryVersionId: "v2", steadyPolicy: steady, identity: { sourceSha, transitionId } }), true);
  assert.throws(() => assertSignerRevocation({ activePolicy: steady, temporaryPolicy: temporary, activeVersionId: "v3", temporaryVersionId: "v2", steadyPolicy: steady, identity: { sourceSha, transitionId: "different-transition" } }));
  assert.equal(grants(steady, "s3:GetObject", stateArn), false, "revocation restores the prior operator boundary");
  for (const [action, resources] of expectedOps) {
    const grants = statements.filter((item) => (Array.isArray(item.Action) ? item.Action : [item.Action]).includes(action));
    assert.ok(grants.length, action);
    const actual = grants.flatMap(({ Resource }) => Array.isArray(Resource) ? Resource : [Resource]);
    for (const resource of resources) assert.ok(actual.includes(resource), `${action} missing ${resource}`);
  }
  const rotationRead = statements.find(({ Action }) => (Array.isArray(Action) ? Action : [Action]).includes("kms:GetKeyRotationStatus"));
  assert.equal(rotationRead.Condition.StringEquals["aws:RequestedRegion"], C.region);
  assert.equal(rotationRead.Condition.StringEquals["kms:KeySpec"], "RSA_3072");
  assert.equal(rotationRead.Condition.StringEquals["kms:KeyUsage"], "SIGN_VERIFY");
  assert.equal(statements.some(({ Resource }) => JSON.stringify(Resource).includes("stage-a/terraform.tfstate")), false);
  assert.equal(statements.some(({ Action }) => JSON.stringify(Action).match(/kms:(Decrypt|Encrypt|GenerateDataKey|CreateGrant)/)), false);
  assert.throws(() => assertSignerTemporaryPolicy({ ...temporary, Statement: [...temporary.Statement, { Effect: "Allow", Action: "iam:CreateRole", Resource: "*" }] }, { steadyPolicy: steady, sourceSha, transitionId }));
  assert.throws(() => signerTemporaryStatements({ sourceSha: "z".repeat(40), transitionId: "different" }));
  assert.ok(Buffer.byteLength(JSON.stringify(temporary)) < 6144, "temporary policy fits the AWS managed-policy limit");
});

test("INSTALLING recovery identifies only the active canonical temporary version for revocation", () => {
  const identity = { sourceSha, transitionId };
  const temporary = buildSignerTemporaryPolicy(steady, identity);
  const versions = [{ VersionId: "v1", document: steady }, { VersionId: "v2", document: temporary }];
  const pending = buildSignerCapabilityEvidence({ state: "INSTALLING", ...identity, steadyVersionId: "v1", observedAt: "2026-09-27T00:00:00.000Z" });
  assert.equal(resolveSignerTemporaryVersionId({ versions, activeVersionId: "v2", evidence: pending, steadyPolicy: steady, identity }), "v2");
  assert.equal(resolveSignerTemporaryVersionId({ versions, activeVersionId: "v1", evidence: pending, steadyPolicy: steady, identity }), "v2", "recover a completed revocation from its retained non-default marker");
  assert.equal(resolveSignerTemporaryVersionId({ versions: [versions[0]], activeVersionId: "v1", evidence: pending, steadyPolicy: steady, identity }), null);
  assert.equal(resolveSignerTemporaryVersionId({ versions, activeVersionId: "v2", evidence: { ...pending, state: "INSTALLED" }, steadyPolicy: steady, identity }), null);
  assert.throws(() => resolveSignerTemporaryVersionId({ versions: [{ VersionId: "v2", document: { ...temporary, Statement: [] } }], activeVersionId: "v2", evidence: { ...pending, temporaryVersionId: "v2" }, steadyPolicy: steady, identity }));
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.match(source, /resolveSignerTemporaryVersionId\(\{ versions: current\.versions, activeVersionId: current\.active\.VersionId, evidence, steadyPolicy, identity \}\)/);
  assert.match(source, /state: "REVOKED", steadyVersionId: current\.active\.VersionId, temporaryVersionId/);
  const workflow = fs.readFileSync(".github/workflows/production-signer-policy-transition-operation.yml", "utf8");
  assert.ok(workflow.indexOf("Prepare and durably record canonical install transition") < workflow.indexOf("Preserve pending install recovery evidence before policy mutation"));
  assert.ok(workflow.indexOf("Preserve pending install recovery evidence before policy mutation") < workflow.indexOf("Apply canonical transition only"));
  assert.ok(workflow.indexOf("Preserve revoke recovery evidence before policy mutation") < workflow.indexOf("Apply canonical transition only"));
  assert.match(workflow, /name: production-signer-policy-transition-recovery[\s\S]*?retention-days: 7/);
});

test("signer environment-approval API permission and private evidence path reach every workflow step", () => {
  const workflowDirectory = ".github/workflows";
  const callerName = "production-signer-policy-transition.yml";
  const operationName = "production-signer-policy-transition-operation.yml";
  const caller = yaml.load(fs.readFileSync(path.join(workflowDirectory, callerName), "utf8"));
  const operation = yaml.load(fs.readFileSync(path.join(workflowDirectory, operationName), "utf8"));
  const permissions = (workflow) => Object.fromEntries(Object.entries(workflow.permissions || {}).sort(([a], [b]) => a.localeCompare(b)));
  assert.deepEqual(permissions(operation), { "actions": "read", "contents": "read", "id-token": "write" });

  const callerJobs = fs.readdirSync(workflowDirectory).filter((name) => /\.ya?ml$/.test(name)).flatMap((name) => {
    const parsed = yaml.load(fs.readFileSync(path.join(workflowDirectory, name), "utf8"));
    return Object.entries(parsed.jobs || {}).filter(([, job]) => job.uses === `./.github/workflows/${operationName}`).map(([id, job]) => ({ name, id, permissions: job.permissions }));
  });
  assert.deepEqual(callerJobs.map(({ name }) => name), [callerName]);
  assert.deepEqual(permissions(caller), { "actions": "read", "contents": "read", "id-token": "write" });
  for (const job of callerJobs) if (job.permissions) assert.equal(job.permissions.actions, "read", `${job.name}:${job.id} must not strip actions:read`);

  const steps = operation.jobs.transition.steps;
  const approval = steps.find(({ name }) => name === "Authenticate independent production approval");
  assert.equal(approval.env.GITHUB_TOKEN, "${{ github.token }}");
  const setup = approval.run;
  const approvalInvocation = setup.indexOf("production-github-environment-approval.mjs");
  assert.ok(setup.indexOf('mkdir -p -m 700 "$approval_dir"') < approvalInvocation);
  assert.ok(setup.indexOf('chmod 700 "$approval_dir"') < approvalInvocation);
  assert.ok(setup.indexOf("stat -c '%a' \"$approval_dir\"") < approvalInvocation);
  assert.ok(setup.includes('test "$(stat -c \'%a\' "$approval_dir")" = 700'));
  assert.ok(setup.includes('test "$(stat -c \'%u\' "$approval_dir")" = "$(id -u)"'));
  assert.ok(setup.includes('--output "$approval_dir/approval.json"'));
  assert.equal(setup.includes('--output "$RUNNER_TEMP/signer-policy-environment-approval.json"'), false);
  const approvalSource = fs.readFileSync("scripts/aws/production-github-environment-approval.mjs", "utf8");
  assert.ok(approvalSource.includes("actions/runs/${input.workflowRunId}/approvals"));
  assert.ok(approvalSource.includes("token: (deps.env || process.env).GITHUB_TOKEN"));
  assert.ok(approvalSource.includes("ensureStageBPrivateDirectory({ directory: path.dirname(output)"));
});

test("signer transitions accept only authenticated historical steady policy versions", () => {
  const identity = { sourceSha, transitionId };
  const versions = [
    ...historicalPolicies.map(({ versionId: VersionId, document }) => ({ VersionId, document, IsDefaultVersion: false })),
    { VersionId: "v8", document: steady, IsDefaultVersion: true },
  ];
  assert.equal(assertCanonicalPolicyHistory({ versions }, identity, false), true);
  const modified = structuredClone(versions[0]);
  modified.document.Statement.push({ Effect: "Allow", Action: "iam:CreateRole", Resource: "*" });
  assert.throws(() => assertCanonicalPolicyHistory({ versions: [modified, versions.at(-1)] }, identity, false));
  assert.throws(() => assertCanonicalPolicyHistory({ versions: [{ ...versions[0], IsDefaultVersion: true }, ...versions.slice(1, -1), versions.at(-1)] }, identity, false));
  const temporary = buildSignerTemporaryPolicy(steady, identity);
  assert.throws(() => assertCanonicalPolicyHistory({ versions: [...versions.slice(0, -1), { VersionId: "v9", document: temporary, IsDefaultVersion: false }, versions.at(-1)] }, identity, false));
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.match(source, /phase === "revoke" && argv\.includes\("--abort-before-apply-confirmed"\).*evidence\?\.state === "INSTALLING".*canonical\(current\.active\.document\) === canonical\(steadyPolicy\)/);
  assert.match(source, /temporaryCapabilityInstalled: false/);
  assert.match(source, /phase === "verify-absent" && evidence\.state === "REVOKED" && evidence\.temporaryVersionId === null/);
  assert.match(source, /if \(evidence\?\.state === "INSTALLING" && canonical\(current\.active\.document\) === canonical\(steadyPolicy\) && !current\.versions\.some/);
  assert.match(source, /temporaryCapabilityInstalled: false/);
  assert.match(source, /const abortable = \["INSTALLING", "INSTALLED", "PLAN_GENERATED", "PLAN_REVIEWED"\]/);
  assert.doesNotMatch(source, /const abortable = \[[^\]]*APPLY_STARTED/);
});

test("apply remains unreachable unless the exact temporary policy is still active", () => {
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.match(source, /arn:aws:iam::\$\{C\.accountId\}:user\/mscqr-production-bootstrap-operator/);
  assert.match(source, /\["plan", "verify-plan", "apply", "verify-convergence"\]\.includes\(phase\).*current\.active\.VersionId !== temporaryVersionId/);
  assert.match(source, /"init", "-input=false", "-lockfile=readonly"/);
  assert.match(source, /"--policy-arns", `arn=\$\{C\.sourcePolicyArn\}`/);
  assert.match(source, /createAssumedRoleSessionEnvironment\(\{ credentials \}\)/);
  assert.match(source, /list-aliases", "--no-paginate"/);
  assert.match(source, /list-keys", "--no-paginate"/);
  assert.match(source, /verifySignerResourceCensus\(undefined, session\)/);
  assert.match(source, /evidence\.state === "INSTALLING" && exactSignerTemporaryVersion\(current\.active\.document, identity\)\) verifySignerResourceCensus\(undefined, signerSession\(bootstrap, transitionId\), \{ allowExisting: true \}\)/);
  assert.match(source, /if \(abort && evidence\.state !== "INSTALLING"\) verifySignerResourceCensus\(undefined, signerSession\(bootstrap, transitionId\)\)/);
  assert.match(source, /workspace", "show"\].*, env: sessionEnv/);
  assert.match(source, /terraformSessionEnvironment\(session\)/);
  assert.doesNotMatch(source, /--release-profile/);
  assert.ok(source.indexOf("protect(stateFile, pending)") < source.indexOf("writePolicyVersion(undefined, temporary"), "transition identity is durable before the policy mutation");
  assert.ok(source.indexOf("writePolicyVersion(undefined, temporary") < source.indexOf("verifySignerResourceCensus(undefined, session)"), "signer absence census uses the temporary session before init or plan");
  assert.match(source, /phase === "recover-install" && \(!evidence \|\| evidence\.state === "INSTALLING"\)/);
  assert.match(source, /const started = buildSignerCapabilityEvidence\(\{ \.\.\.evidence, state: "APPLY_STARTED"/);
  assert.ok(source.indexOf("protect(stateFile, started)") < source.indexOf('"apply", "-input=false", savedPlanFile'), "apply intent is durable before Terraform can mutate");
});

test("policy transitions reject other consumers and make CreatePolicyVersion a single AWS CLI attempt", () => {
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  const policy = { PermissionsBoundaryUsageCount: 0 };
  const onlyDeployer = { PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [] };
  assert.equal(assertSignerPolicySoleConsumer({ policy, entities: onlyDeployer }), true);
  for (const entities of [
    { ...onlyDeployer, PolicyRoles: [...onlyDeployer.PolicyRoles, { RoleName: "unrelated" }] },
    { ...onlyDeployer, PolicyUsers: [{ UserName: "unrelated" }] },
    { ...onlyDeployer, PolicyGroups: [{ GroupName: "unrelated" }] },
  ]) assert.throws(() => assertSignerPolicySoleConsumer({ policy, entities }));
  assert.throws(() => assertSignerPolicySoleConsumer({ policy: { PermissionsBoundaryUsageCount: 1 }, entities: onlyDeployer }));
  assert.throws(() => assertSignerPolicySoleConsumer({ policy: {}, entities: onlyDeployer }));
  assert.match(source, /list-entities-for-policy", "--no-paginate"/);
  assert.match(source, /typeof page\.IsTruncated !== "boolean"[\s\S]*?typeof page\.Marker !== "string"/);
  assert.match(source, /assertSignerPolicySoleConsumer\(\{ policy: before\.policy, entities \}\)/);
  assert.match(source, /AWS_RETRY_MODE: "standard", AWS_MAX_ATTEMPTS: "1"/);
  assert.match(source, /"create-policy-version"[\s\S]*?\], sessionEnv, true\)/);
});

test("only the exact four create-only signer Terraform plan is accepted", () => {
  const keyPolicy = { Version: "2012-10-17", Statement: [
    { Sid: "AccountBreakGlassAdministration", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: ["kms:*"] , Resource: ["*"] },
    { Sid: "ProtectedWorkflowImageAuthorizationSigningOnly", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-production-security-rebaseline-image-signer" }, Action: ["kms:Sign"], Resource: ["*"], Condition: { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": C.alias } } },
  ] };
  const inlinePolicy = { Version: "2012-10-17", Statement: [{ Sid: "SignPurposeSpecificAuthorizationDigestsOnly", Effect: "Allow", Action: ["kms:Sign"], Resource: "${aws_kms_key.image_authorization.arn}", Condition: { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": C.alias } } }] };
  const after = {
    aws_iam_role: { name: C.roleName, description: "Purpose-limited GitHub OIDC signer for read-only production security-rebaseline image authorizations.", max_session_duration: 3600, tags: C.tags, assume_role_policy: JSON.stringify(trust) },
    aws_kms_key: { description: "Purpose-specific production security-rebaseline image authorization signer", deletion_window_in_days: 30, customer_master_key_spec: "RSA_3072", key_usage: "SIGN_VERIFY", bypass_policy_lockout_safety_check: false, tags: C.tags, policy: JSON.stringify(keyPolicy) },
    aws_kms_alias: { name: C.alias }, aws_iam_role_policy: { name: C.inlinePolicyName, role: C.roleName, policy: JSON.stringify(inlinePolicy) },
  };
  const addresses = ["aws_iam_role.signer", "aws_kms_key.image_authorization", "aws_kms_alias.image_authorization", "aws_iam_role_policy.sign_only"];
  const types = ["aws_iam_role", "aws_kms_key", "aws_kms_alias", "aws_iam_role_policy"];
  const plan = { prior_state: { values: { root_module: { resources: [], child_modules: [] } } }, configuration: { provider_config: { aws: { expressions: { region: { constant_value: "eu-west-2" }, allowed_account_ids: { constant_value: ["368992683803"] } } } }, root_module: { resources: addresses.map((address, i) => ({ address, mode: "managed", type: types[i], name: address.split(".").at(-1) })), child_modules: [] } }, resource_changes: addresses.map((address, i) => ({ address, change: { actions: ["create"], after: after[types[i]], ...(address === "aws_kms_alias.image_authorization" ? { after_unknown: { target_key_id: true } } : {}) } })) };
  assertSignerCreationPlan(plan, { trustPolicy: trust });
  const omittedEmptyResources = structuredClone(plan); delete omittedEmptyResources.prior_state.values.root_module.resources;
  assertSignerCreationPlan(omittedEmptyResources, { trustPolicy: trust });
  assert.throws(() => assertSignerCreationPlan({ ...plan, prior_state: { values: { root_module: { resources: {}, child_modules: [] } } } }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ ...plan, configuration: { ...plan.configuration, root_module: { ...plan.configuration.root_module, resources: [addresses[0], addresses[0], ...addresses.slice(2)].map((address, i) => ({ address, mode: "managed", type: types[i], name: address.split(".").at(-1) })) } } }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ ...plan, prior_state: { values: { root_module: { resources: [{ address: "aws_iam_role.unrelated" }] } } } }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ resource_changes: [...plan.resource_changes, { address: "aws_ecs_service.production", change: { actions: ["update"] } }] }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ resource_changes: plan.resource_changes.map((x) => x.address === addresses[0] ? { ...x, change: { ...x.change, after: { ...x.change.after, assume_role_policy: "{}" } } } : x) }, { trustPolicy: trust }));
});

test("evidence binds one source, account, region, purpose, root, state key, and transition", () => {
  const evidence = buildSignerCapabilityEvidence({ state: "INSTALLED", sourceSha, transitionId, steadyVersionId: "v1", temporaryVersionId: "v2", observedAt: "2026-09-27T00:00:00.000Z" });
  assertSignerCapabilityEvidence(evidence, { state: "INSTALLED", sourceSha, transitionId });
  assert.throws(() => assertSignerCapabilityEvidence(evidence, { state: "INSTALLED", sourceSha: "f".repeat(40), transitionId }));
  assert.throws(() => assertSignerCapabilityEvidence(evidence, { state: "INSTALLED", sourceSha, transitionId: "other-signer-transition" }));
  assert.throws(() => assertSignerCapabilityEvidence({ ...evidence, stateKey: "other/terraform.tfstate" }, { state: "INSTALLED", sourceSha, transitionId }));
  const pending = buildSignerCapabilityEvidence({ state: "INSTALLING", sourceSha, transitionId, steadyVersionId: "v1", observedAt: "2026-09-27T00:00:00.000Z" });
  assertSignerCapabilityEvidence(pending, { state: "INSTALLING", sourceSha, transitionId });
  const applyStarted = buildSignerCapabilityEvidence({ state: "APPLY_STARTED", sourceSha, transitionId, steadyVersionId: "v1", temporaryVersionId: "v2", planSha256: "a".repeat(64), approvalReference: "change:signer-approved", observedAt: "2026-09-27T00:00:00.000Z" });
  assertSignerCapabilityEvidence(applyStarted, { state: "APPLY_STARTED", sourceSha, transitionId });
  const incompleteApply = buildSignerCapabilityEvidence({ state: "APPLY_STARTED", sourceSha, transitionId, steadyVersionId: "v1", temporaryVersionId: "v2", observedAt: "2026-09-27T00:00:00.000Z" });
  assert.throws(() => assertSignerCapabilityEvidence(incompleteApply, { state: "APPLY_STARTED", sourceSha, transitionId }), /incomplete/);
  assert.notDeepEqual(signerTemporaryStatements({ sourceSha, transitionId }), signerTemporaryStatements({ sourceSha, transitionId: "signer-once-replayed" }));
});

test("initialized Terraform backend is pinned to the canonical signer state and rejects auth/endpoint overrides", () => {
  const metadata = { type: "s3", hash: 1, config: { bucket: C.bucket, key: C.stateKey, region: C.region, encrypt: true, use_lockfile: true, profile: "", endpoint: "", dynamodb_table: "" } };
  assertSignerInitializedBackendMetadata(metadata);
  assert.throws(() => assertSignerInitializedBackendMetadata({ ...metadata, config: { ...metadata.config, key: "mscqr/production/other/terraform.tfstate" } }));
  assert.throws(() => assertSignerInitializedBackendMetadata({ ...metadata, config: { ...metadata.config, endpoint: "http://localhost" } }));
  assert.throws(() => assertSignerInitializedBackendMetadata({ ...metadata, config: { ...metadata.config, access_key: "static" } }));
});
