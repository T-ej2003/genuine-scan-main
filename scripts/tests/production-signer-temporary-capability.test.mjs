import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import yaml from "js-yaml";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { buildSignerBrokerRequest } from "../aws/publish-production-signer-policy-transition-authorization.mjs";
import { assertCanonicalPolicyHistory, assertSignerBootstrapIdentity, assertSignerCliArguments, completeInstallingSignerAbort } from "../aws/reconcile-production-signer-temporary-capability.mjs";
import { brokerSignerSuccessorManagedIdentities, componentBrokerArn } from "../aws/component-installation-identity-contract.mjs";
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

test("normal production identities cannot mutate policy versions and the OIDC role can only invoke broker authorization", () => {
  assert.equal(assertSignerBootstrapIdentity("mscqr-production-bootstrap-mfa", { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator` }), `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator`);
  for (const [profile, caller] of [
    ["default", { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:root` }],
    ["mscqr-production-release-deployer", { Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/mscqr-production-release-deployer/session` }],
    ["another-profile", { Account: C.accountId, Arn: `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator` }],
  ]) assert.throws(() => assertSignerBootstrapIdentity(profile, caller));
  const planArgs = ["--phase", "plan", "--source-sha", sourceSha, "--transition-id", transitionId, "--bootstrap-profile", "mscqr-production-bootstrap-mfa", "--state-file", "/tmp/capability.json", "--broker-state-file", "/tmp/broker.json"];
  assert.throws(() => assertSignerCliArguments(planArgs, "plan"), /--plan-output is required/);
  for (const option of ["--admin-profile", "--policy-arn", "--policy-name", "--policy-document", "--policy-file", "--state-key", "--role-arn", "--kms-key"]) assert.throws(() => assertSignerCliArguments([...planArgs, option, "attacker-value"], "plan"));

  const bootstrap = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionBootstrapOperator-v2.json", "utf8"));
  const target = C.sourcePolicyArn;
  assert.equal(grants(bootstrap, "iam:CreatePolicyVersion", target), false);
  assert.equal(grants(steady, "iam:CreatePolicyVersion", target), false);
  const oidc = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-permissions-policy.json", "utf8"));
  assert.deepEqual(oidc, { Version: "2012-10-17", Statement: [{ Sid: "PublishExactSignerTransitionAuthorizationToBroker", Effect: "Allow", Action: "lambda:InvokeFunction", Resource: `${componentBrokerArn}:15`, Condition: { StringEquals: { "aws:RequestedRegion": C.region } } }] });
  assert.equal(oidc.Statement.some(({ Action }) => [].concat(Action).includes("iam:CreatePolicyVersion")), false);

  const broker = brokerSignerSuccessorManagedIdentities().find(({ role }) => role === "mscqr-production-component-iam-provisioner").policy;
  assert.equal(grants(broker, "iam:CreatePolicyVersion", target), true);
  assert.equal(grants(broker, "iam:CreatePolicyVersion", "arn:aws:iam::368992683803:policy/other"), false);
  const mutation = broker.Statement.find(({ Action }) => [].concat(Action).includes("iam:CreatePolicyVersion"));
  assert.deepEqual(mutation.Condition, { ArnEquals: { "lambda:SourceFunctionArn": componentBrokerArn } });
});

test("solo-operator workflow archives only a fixed broker authorization request", () => {
  const caller = fs.readFileSync(".github/workflows/production-signer-policy-transition.yml", "utf8");
  const operation = fs.readFileSync(".github/workflows/production-signer-policy-transition-operation.yml", "utf8");
  assert.match(caller, /permissions:[\s\S]*?contents: read[\s\S]*?actions: read[\s\S]*?id-token: write/);
  assert.match(operation, /permissions:[\s\S]*?contents: read[\s\S]*?actions: read[\s\S]*?id-token: write/);
  assert.match(operation, /mkdir -p -m 700 "\$approval_dir"[\s\S]*?chmod 700 "\$approval_dir"[\s\S]*?production-github-environment-approval\.mjs/);
  assert.match(operation, /--function-name arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer:15/);
  assert.doesNotMatch(caller + operation, /policy-document|policy-arn|policy-file|admin-profile|create-policy-version/);
  assert.match(operation, /role-to-assume: arn:aws:iam::368992683803:role\/mscqr-production-signer-policy-installer/);
  assert.match(operation, /SIGNER_AUTHORIZE|publish-production-signer-policy-transition-authorization/);
  const trustPolicy = JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-trust-policy.json", "utf8"));
  assert.equal(trustPolicy.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:job_workflow_ref"], "T-ej2003/genuine-scan-main/.github/workflows/production-signer-policy-transition-operation.yml@refs/heads/main");
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

test("INSTALLING recovery delegates policy mutation to the authoritative broker", () => {
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.doesNotMatch(source, /create-policy-version|writePolicyVersion/);
  assert.match(source, /phase === "recover-install"/);
  const broker = fs.readFileSync("scripts/aws/component-signer-policy-transition.mjs", "utf8");
  assert.match(broker, /SIGNER_ABORT_BOUNDARY = "APPLY_STARTED"/);
  assert.match(broker, /event\.evidenceState, ledger\.state/);
  assert.match(broker, /Submitted evidence is stale/);
})

test("no-write INSTALLING abort reaches the broker before local evidence or a temporary policy exists", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "signer-no-write-abort-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const identity = { sourceSha, transitionId }, current = { active: { VersionId: "v1", document: steady },
    versions: [{ VersionId: "v1", IsDefaultVersion: true, document: steady }] };
  const ledger = { state: "INSTALLING" }, revoked = { state: "REVOKED", history: [{ state: "INSTALLING" }] };
  const calls = [];
  const deps = { transition: (...args) => calls.push(args), readLedger: () => revoked, readPolicy: () => current };
  const stateFile = path.join(directory, "capability.json");
  const input = { phase: "revoke", abort: true, evidence: null, brokerLedger: ledger, current, identity,
    bootstrap: "mscqr-production-bootstrap-mfa", brokerStateFile: "broker.json", stateFile,
    now: () => "2026-09-28T12:00:00.000Z", write: () => {} };
  const result = completeInstallingSignerAbort(input, deps);
  assert.equal(result.state, "REVOKED"); assert.equal(result.temporaryVersionId, null);
  assert.deepEqual(calls, [["broker.json", "revoke", { abortBeforeApplyConfirmed: true }]]);
  assertSignerCapabilityEvidence(JSON.parse(fs.readFileSync(stateFile, "utf8")), { state: "REVOKED", ...identity });
  assert.equal(fs.statSync(stateFile).mode & 0o077, 0);
  assert.equal(completeInstallingSignerAbort({ ...input, brokerLedger: revoked }, deps).state, "REVOKED", "lost acknowledgement is recoverable");
  assert.equal(completeInstallingSignerAbort({ ...input, abort: false }, deps), false);
  assert.equal(completeInstallingSignerAbort({ ...input, brokerLedger: { state: "APPLY_STARTED" } }, deps), false);
  assert.throws(() => completeInstallingSignerAbort({ ...input, evidence: buildSignerCapabilityEvidence({ ...identity, state: "INSTALLING", steadyVersionId: "v2", observedAt: input.now() }) }, deps), /original steady policy/);
  const temporary = buildSignerTemporaryPolicy(steady, identity), withMarker = { active: current.active, versions: [...current.versions,
    { VersionId: "v2", IsDefaultVersion: false, document: temporary }] };
  assert.equal(completeInstallingSignerAbort({ ...input, current: withMarker }, { ...deps, readPolicy: () => withMarker }).temporaryVersionId, "v2",
    "lost acknowledgement after an IAM write retains the exact temporary marker for absence verification");
  const temporaryActive = { ...withMarker, active: { VersionId: "v2", IsDefaultVersion: true, document: temporary },
    versions: withMarker.versions.map(version => ({ ...version, IsDefaultVersion: version.VersionId === "v2" })) };
  assert.equal(completeInstallingSignerAbort({ ...input, current: temporaryActive }, { ...deps, readPolicy: () => withMarker }).temporaryVersionId, "v2",
    "an interrupted install can be broker-revoked without a local capability file");
  assert.throws(() => completeInstallingSignerAbort(input, { ...deps, readLedger: () => ledger }), /authoritative steady state/);
  assert.throws(() => completeInstallingSignerAbort({ ...input, current: { ...current, versions: [...current.versions, { VersionId: "v2", document: { Statement: [] } }] } }, deps), /unexpected version/);
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.ok(source.indexOf("const installingAbort = completeInstallingSignerAbort") < source.indexOf('if (!evidence) fail("private authorization evidence is required")'));
});

test("signer environment-approval API permission and private evidence path reach every workflow step", () => {
  const workflowDirectory = ".github/workflows", callerName = "production-signer-policy-transition.yml", operationName = "production-signer-policy-transition-operation.yml";
  const caller = yaml.load(fs.readFileSync(path.join(workflowDirectory, callerName), "utf8"));
  const operation = yaml.load(fs.readFileSync(path.join(workflowDirectory, operationName), "utf8"));
  const permissions = workflow => Object.fromEntries(Object.entries(workflow.permissions || {}).sort(([a], [b]) => a.localeCompare(b)));
  assert.deepEqual(permissions(operation), { actions: "read", contents: "read", "id-token": "write" });
  assert.deepEqual(permissions(caller), { actions: "read", contents: "read", "id-token": "write" });
  const steps = operation.jobs.authorize.steps;
  const approval = steps.find(({ name }) => name === "Authenticate solo-operator protected-environment approval");
  assert.equal(approval.env.GITHUB_TOKEN, "${{ github.token }}");
  const invocation = approval.run.indexOf("production-github-environment-approval.mjs");
  for (const expected of ['mkdir -p -m 700 "$approval_dir"', 'chmod 700 "$approval_dir"', "stat -c '%a' \"$approval_dir\""]) assert.ok(approval.run.indexOf(expected) < invocation);
  assert.match(approval.run, /--output "\$approval_dir\/approval\.json"/);
  const authenticate = steps.find(({ name }) => name === "Authenticate exact protected source and fixed operation");
  assert.match(authenticate.run, /git merge-base --is-ancestor "\$TRANSITION_SOURCE_SHA" "\$SOURCE_SHA"/);
  assert.match(authenticate.run, /git diff --quiet "\$TRANSITION_SOURCE_SHA\.\.\$SOURCE_SHA"/);
  const request = steps.find(({ name }) => name === "Build canonical broker request");
  assert.match(request.run, /--transition-source-sha "\$TRANSITION_SOURCE_SHA"/);
})

test("actual GitHub approval observation produces a fresh fixed broker request", () => {
  const observedAt = "2026-09-28T12:00:00.000Z", environment = "production-signer-policy-transition", workflowRunId = "42";
  const approvalEvidence = createProductionEnvironmentApprovalEvidence({ repository: "T-ej2003/genuine-scan-main", environment, sourceSha,
    workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/production-signer-policy-transition.yml@refs/heads/main", eventName: "workflow_dispatch",
    workflowRunId, workflowRunAttempt: "1", executionActor: "T-ej2003", observedAt,
    environmentConfig: { id: 8, name: environment, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 183396573, login: "T-ej2003" } }] }] },
    actualApproval: { state: "approved", environmentId: 8, environmentName: environment, userId: 183396573, userLogin: "T-ej2003" } });
  const request = buildSignerBrokerRequest({ sourceSha, transitionId: "123e4567-e89b-42d3-a456-426614174000", operation: "INSTALL", workflowRunId, approvalEvidence, now: Date.parse(observedAt) + 1000 });
  assert.equal(request.operation, "SIGNER_AUTHORIZE"); assert.equal(request.authorization.approvedAt, observedAt); assert.equal(request.authorization.workflowRunId, workflowRunId);
  assert.equal(request.authorization.sourceSha, sourceSha); assert.equal(request.authorization.protectedMainSha, sourceSha);
  assert.equal(Object.hasOwn(request.authorization, "policyDocument"), false); assert.equal(Object.hasOwn(request.authorization, "policyArn") && request.authorization.policyArn !== C.sourcePolicyArn, false);
  const predecessor = "a".repeat(40), cleanup = buildSignerBrokerRequest({ sourceSha, transitionSourceSha: predecessor, transitionId: "123e4567-e89b-42d3-a456-426614174000", operation: "REVOKE", workflowRunId, approvalEvidence, now: Date.parse(observedAt) + 1000 });
  assert.equal(cleanup.authorization.sourceSha, predecessor); assert.equal(cleanup.authorization.protectedMainSha, sourceSha);
  const recovery = buildSignerBrokerRequest({ sourceSha, transitionSourceSha: predecessor, transitionId: "123e4567-e89b-42d3-a456-426614174000", operation: "RECOVER", workflowRunId, approvalEvidence, now: Date.parse(observedAt) + 1000 });
  assert.equal(recovery.authorization.operation, "RECOVER"); assert.equal(recovery.authorization.protectedMainSha, sourceSha);
  assert.throws(() => buildSignerBrokerRequest({ sourceSha, transitionSourceSha: predecessor, transitionId: "123e4567-e89b-42d3-a456-426614174000", operation: "INSTALL", workflowRunId, approvalEvidence, now: Date.parse(observedAt) + 1000 }), /current protected main/);
})

test("signer transitions accept only authenticated historical steady policy versions", () => {
  const identity = { sourceSha, transitionId };
  const versions = [...historicalPolicies.map(({ versionId: VersionId, document }) => ({ VersionId, document, IsDefaultVersion: false })), { VersionId: "v8", document: steady, IsDefaultVersion: true }];
  assert.equal(assertCanonicalPolicyHistory({ versions }, identity, false), true);
  const modified = structuredClone(versions[0]); modified.document.Statement.push({ Effect: "Allow", Action: "iam:CreateRole", Resource: "*" });
  assert.throws(() => assertCanonicalPolicyHistory({ versions: [modified, versions.at(-1)] }, identity, false));
  const temporary = buildSignerTemporaryPolicy(steady, identity);
  assert.throws(() => assertCanonicalPolicyHistory({ versions: [...versions.slice(0, -1), { VersionId: "v9", document: temporary, IsDefaultVersion: false }, versions.at(-1)] }, identity, false));
})

test("apply remains unreachable unless the exact temporary policy is still active", () => {
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.match(source, /\["plan", "verify-plan", "apply", "recover-plan", "recover-verify-plan", "recover-apply", "verify-convergence"\]\.includes\(phase\).*current\.active\.VersionId !== temporaryVersionId/);
  assert.match(source, /const started = buildSignerCapabilityEvidence\(\{ \.\.\.evidence, state: "APPLY_STARTED"/);
  assert.ok(source.indexOf("protect(stateFile, started)") < source.indexOf('\"apply\", \"-input=false\", savedPlanFile'));
  assert.match(source, /phase === "recover-plan"/); assert.match(source, /allowPartial: true/);
  assert.ok(source.indexOf('brokerTransition(brokerStateFile, "recovery", { state: "APPLY_STARTED"') < source.indexOf('state: "RECOVERY_APPLY_STARTED"'));
  assert.doesNotMatch(source, /create-policy-version|writePolicyVersion/);
})

test("policy mutation exists only in the immutable broker", () => {
  const policy = { PermissionsBoundaryUsageCount: 0 }, entities = { PolicyRoles: [{ RoleName: "mscqr-production-release-deployer" }], PolicyUsers: [], PolicyGroups: [] };
  assert.equal(assertSignerPolicySoleConsumer({ policy, entities }), true);
  assert.throws(() => assertSignerPolicySoleConsumer({ policy, entities: { ...entities, PolicyRoles: [...entities.PolicyRoles, { RoleName: "other" }] } }));
  const local = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  const broker = fs.readFileSync("scripts/aws/component-signer-policy-transition.mjs", "utf8");
  assert.doesNotMatch(local, /CreatePolicyVersion|create-policy-version/);
  assert.match(broker, /iam\("CreatePolicyVersion"/);
  assert.match(broker, /PolicyArn: C\.sourcePolicyArn/);
})

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
  const partial = structuredClone(plan);
  partial.prior_state.values.root_module.resources = [{ address: addresses[0] }];
  partial.resource_changes[0].change.actions = ["no-op"];
  assertSignerCreationPlan(partial, { trustPolicy: trust, allowPartial: true });
  assert.throws(() => assertSignerCreationPlan(partial, { trustPolicy: trust }));
  const partialMutation = structuredClone(partial); partialMutation.resource_changes[1].change.actions = ["update"];
  assert.throws(() => assertSignerCreationPlan(partialMutation, { trustPolicy: trust, allowPartial: true }));
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
