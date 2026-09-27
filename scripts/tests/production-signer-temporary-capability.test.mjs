import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  SIGNER_TEMPORARY_CAPABILITY as C, assertSignerCapabilityEvidence, assertSignerCreationPlan, assertSignerRevocation,
  assertSignerInitializedBackendMetadata, assertSignerPolicySoleConsumer, assertSignerTemporaryPolicy, buildSignerCapabilityEvidence, buildSignerTemporaryPolicy,
  signerTemporaryStatements,
} from "../aws/production-signer-temporary-capability.mjs";

const sourceSha = "0cbce2080bf38f7f071047fef3b982805336ffb5", transitionId = "signer-once-20260927";
const steady = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
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
  return actions.includes(action) && resources.some((candidate) => candidate === "*" || candidate === resource);
});

test("temporary delta is source/nonce bound and excludes unrelated state, IAM, and KMS data actions", () => {
  const statements = signerTemporaryStatements({ sourceSha, transitionId });
  assert.equal(statements.length, 13);
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
  assert.equal(grants(temporary, "kms:Decrypt", "arn:aws:kms:eu-west-2:368992683803:key/unrelated"), false);
  assert.throws(() => assertSignerRevocation({ activePolicy: temporary, temporaryPolicy: temporary, activeVersionId: "v2", temporaryVersionId: "v2", steadyPolicy: steady, identity: { sourceSha, transitionId } }));
  assert.equal(assertSignerRevocation({ activePolicy: steady, temporaryPolicy: temporary, activeVersionId: "v3", temporaryVersionId: "v2", steadyPolicy: steady, identity: { sourceSha, transitionId } }), true);
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

test("apply remains unreachable unless the exact temporary policy is still active", () => {
  const source = fs.readFileSync("scripts/aws/reconcile-production-signer-temporary-capability.mjs", "utf8");
  assert.match(source, /arn:aws:iam::\$\{C\.accountId\}:user\/mscqr-production-bootstrap-operator/);
  assert.match(source, /\["plan", "verify-plan", "apply", "verify-convergence"\]\.includes\(phase\).*current\.active\.VersionId !== evidence\.temporaryVersionId/);
  assert.match(source, /"--policy-arns", `arn=\$\{C\.sourcePolicyArn\}`/);
  assert.match(source, /createAssumedRoleSessionEnvironment\(\{ credentials \}\)/);
  assert.match(source, /workspace", "show"\].*, env: sessionEnv/);
  assert.match(source, /terraformSessionEnvironment\(session\)/);
  assert.doesNotMatch(source, /--release-profile/);
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
  assert.match(source, /"create-policy-version"[\s\S]*?\], undefined, true\)/);
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
  assert.throws(() => assertSignerCreationPlan({ ...plan, configuration: { ...plan.configuration, root_module: { ...plan.configuration.root_module, resources: [addresses[0], addresses[0], ...addresses.slice(2)].map((address, i) => ({ address, mode: "managed", type: types[i], name: address.split(".").at(-1) })) } } }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ ...plan, prior_state: { values: { root_module: { resources: [{ address: "aws_iam_role.unrelated" }] } } } }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ resource_changes: [...plan.resource_changes, { address: "aws_ecs_service.production", change: { actions: ["update"] } }] }, { trustPolicy: trust }));
  assert.throws(() => assertSignerCreationPlan({ resource_changes: plan.resource_changes.map((x) => x.address === addresses[0] ? { ...x, change: { ...x.change, after: { ...x.change.after, assume_role_policy: "{}" } } } : x) }, { trustPolicy: trust }));
});

test("evidence binds one source, account, region, purpose, root, state key, and transition", () => {
  const evidence = buildSignerCapabilityEvidence({ state: "INSTALLED", sourceSha, transitionId, steadyVersionId: "v1", temporaryVersionId: "v2", observedAt: "2026-09-27T00:00:00.000Z" });
  assertSignerCapabilityEvidence(evidence, { state: "INSTALLED", sourceSha, transitionId });
  assert.throws(() => assertSignerCapabilityEvidence(evidence, { state: "INSTALLED", sourceSha: "f".repeat(40), transitionId }));
  assert.throws(() => assertSignerCapabilityEvidence({ ...evidence, stateKey: "other/terraform.tfstate" }, { state: "INSTALLED", sourceSha, transitionId }));
  assert.notDeepEqual(signerTemporaryStatements({ sourceSha, transitionId }), signerTemporaryStatements({ sourceSha, transitionId: "signer-once-replayed" }));
});

test("initialized Terraform backend is pinned to the canonical signer state and rejects auth/endpoint overrides", () => {
  const metadata = { type: "s3", hash: 1, config: { bucket: C.bucket, key: C.stateKey, region: C.region, encrypt: true, use_lockfile: true, profile: "", endpoint: "", dynamodb_table: "" } };
  assertSignerInitializedBackendMetadata(metadata);
  assert.throws(() => assertSignerInitializedBackendMetadata({ ...metadata, config: { ...metadata.config, key: "mscqr/production/other/terraform.tfstate" } }));
  assert.throws(() => assertSignerInitializedBackendMetadata({ ...metadata, config: { ...metadata.config, endpoint: "http://localhost" } }));
  assert.throws(() => assertSignerInitializedBackendMetadata({ ...metadata, config: { ...metadata.config, access_key: "static" } }));
});
