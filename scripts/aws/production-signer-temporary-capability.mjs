import crypto from "node:crypto";

export const SIGNER_TEMPORARY_CAPABILITY = Object.freeze({
  accountId: "368992683803", region: "eu-west-2", sourcePolicyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageARelease",
  policyName: "MSCQRProductionGreenStageARelease", operation: "production-security-rebaseline-signer-initial-convergence",
  root: "infra/aws/terraform/production-security-rebaseline-signer", bucket: "mscqr-production-terraform-state-368992683803-eu-west-2",
  stateKey: "mscqr/production/security-rebaseline/signer/terraform.tfstate", lockKey: "mscqr/production/security-rebaseline/signer/terraform.tfstate.tflock",
  roleName: "mscqr-production-security-rebaseline-image-signer", roleArn: "arn:aws:iam::368992683803:role/mscqr-production-security-rebaseline-image-signer",
  installerRoleName: "mscqr-production-signer-policy-installer", installerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-signer-policy-installer",
  inlinePolicyName: "ProductionSecurityRebaselineImageAuthorizationSignOnly", alias: "alias/mscqr-production-security-rebaseline-image-evidence",
  tags: { ManagedBy: "Terraform", Environment: "production", Stack: "production-security-rebaseline-signer", Purpose: "read-only-security-rebaseline-image-authorization" },
});

const canonical = (x) => Array.isArray(x) ? `[${x.map(canonical).join(",")}]` : x && typeof x === "object" ? `{${Object.keys(x).sort().map((k) => `${JSON.stringify(k)}:${canonical(x[k])}`).join(",")}}` : JSON.stringify(x);
const sha256 = (x) => crypto.createHash("sha256").update(x).digest("hex");
const fail = (message) => { throw new Error(`Signer temporary capability: ${message}`); };
const same = (a, b) => canonical(a) === canonical(b);

export function signerTemporaryStatements({ sourceSha, transitionId } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "")) fail("exact source SHA and transition nonce are required");
  const suffix = `${sourceSha}${sha256(transitionId).slice(0, 24)}`;
  const s3 = `arn:aws:s3:::${SIGNER_TEMPORARY_CAPABILITY.bucket}/`;
  const state = `${s3}${SIGNER_TEMPORARY_CAPABILITY.stateKey}`;
  const lock = `${s3}${SIGNER_TEMPORARY_CAPABILITY.lockKey}`;
  const keyArn = "arn:aws:kms:eu-west-2:368992683803:key/*";
  const aliasArn = `arn:aws:kms:eu-west-2:368992683803:alias/${SIGNER_TEMPORARY_CAPABILITY.alias.slice("alias/".length)}`;
  const tagConditions = Object.fromEntries(Object.entries(SIGNER_TEMPORARY_CAPABILITY.tags).map(([key, value]) => [`aws:RequestTag/${key}`, value]));
  const resourceTagConditions = Object.fromEntries(Object.entries(SIGNER_TEMPORARY_CAPABILITY.tags).map(([key, value]) => [`aws:ResourceTag/${key}`, value]));
  return [
    { Sid: `TemporarySignerBucket${suffix}`, Effect: "Allow", Action: "s3:GetBucketLocation", Resource: `arn:aws:s3:::${SIGNER_TEMPORARY_CAPABILITY.bucket}`, Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region } } },
    { Sid: `TemporarySignerStateList${suffix}`, Effect: "Allow", Action: "s3:ListBucket", Resource: `arn:aws:s3:::${SIGNER_TEMPORARY_CAPABILITY.bucket}`, Condition: { StringLike: { "s3:prefix": [SIGNER_TEMPORARY_CAPABILITY.stateKey, SIGNER_TEMPORARY_CAPABILITY.lockKey] } } },
    { Sid: `TemporarySignerState${suffix}`, Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject"], Resource: state },
    { Sid: `TemporarySignerLock${suffix}`, Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource: lock },
    { Sid: `TemporarySignerRole${suffix}`, Effect: "Allow", Action: ["iam:CreateRole", "iam:TagRole"], Resource: SIGNER_TEMPORARY_CAPABILITY.roleArn, Condition: { StringEquals: tagConditions, "ForAllValues:StringEquals": { "aws:TagKeys": Object.keys(SIGNER_TEMPORARY_CAPABILITY.tags) } } },
    { Sid: `TemporarySignerRoleRead${suffix}`, Effect: "Allow", Action: "iam:GetRole", Resource: SIGNER_TEMPORARY_CAPABILITY.roleArn },
    { Sid: `TemporarySignerRolePolicy${suffix}`, Effect: "Allow", Action: ["iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:PutRolePolicy"], Resource: SIGNER_TEMPORARY_CAPABILITY.roleArn },
    { Sid: `TemporarySignerKeyCreate${suffix}`, Effect: "Allow", Action: "kms:CreateKey", Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region, "kms:CallerAccount": SIGNER_TEMPORARY_CAPABILITY.accountId, "kms:KeySpec": "RSA_3072", "kms:KeyUsage": "SIGN_VERIFY", ...tagConditions }, "ForAllValues:StringEquals": { "aws:TagKeys": Object.keys(SIGNER_TEMPORARY_CAPABILITY.tags) }, Bool: { "kms:BypassPolicyLockoutSafetyCheck": "false" } } },
    { Sid: `TemporarySignerKeyTag${suffix}`, Effect: "Allow", Action: "kms:TagResource", Resource: keyArn, Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region, "kms:KeySpec": "RSA_3072", "kms:KeyUsage": "SIGN_VERIFY", ...tagConditions }, "ForAllValues:StringEquals": { "aws:TagKeys": Object.keys(SIGNER_TEMPORARY_CAPABILITY.tags) } } },
    { Sid: `TemporarySignerKeyPolicy${suffix}`, Effect: "Allow", Action: ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:PutKeyPolicy", "kms:ListResourceTags", "kms:ListGrants"], Resource: keyArn, Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region, "kms:KeySpec": "RSA_3072", "kms:KeyUsage": "SIGN_VERIFY", ...resourceTagConditions } } },
    { Sid: `TemporarySignerKeyCensus${suffix}`, Effect: "Allow", Action: "kms:ListResourceTags", Resource: keyArn, Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region } } },
    { Sid: `TemporarySignerKeyList${suffix}`, Effect: "Allow", Action: "kms:ListKeys", Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region } } },
    { Sid: `TemporarySignerAlias${suffix}`, Effect: "Allow", Action: "kms:CreateAlias", Resource: aliasArn, Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region } } },
    { Sid: `TemporarySignerAliasKey${suffix}`, Effect: "Allow", Action: "kms:CreateAlias", Resource: keyArn, Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region, "kms:KeySpec": "RSA_3072", "kms:KeyUsage": "SIGN_VERIFY", ...resourceTagConditions } } },
    { Sid: `TemporarySignerAliasReadback${suffix}`, Effect: "Allow", Action: "kms:ListAliases", Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": SIGNER_TEMPORARY_CAPABILITY.region } } },
  ];
}

export function buildSignerTemporaryPolicy(steadyPolicy, identity) {
  assertSignerSteadyPolicy(steadyPolicy);
  // Replace this dedicated managed policy during the short window, rather than
  // append to it; this keeps the temporary document below IAM's 6 KiB limit.
  const policy = { Version: "2012-10-17", Statement: signerTemporaryStatements(identity) };
  if (Buffer.byteLength(JSON.stringify(policy)) > 6144) fail("temporary policy exceeds the AWS managed-policy limit");
  return policy;
}

export function assertSignerSteadyPolicy(policy) {
  if (policy?.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) fail("canonical steady-state release policy is malformed");
  if (policy.Statement.some(({ Sid = "" }) => Sid.startsWith("TemporarySigner"))) fail("steady-state release policy already contains signer capability statements");
  return true;
}

export function assertSignerPolicySoleConsumer({ policy, entities } = {}) {
  const roles = entities?.PolicyRoles, users = entities?.PolicyUsers, groups = entities?.PolicyGroups;
  if (policy?.PermissionsBoundaryUsageCount !== 0 || !Array.isArray(roles) || roles.length !== 1 || roles[0]?.RoleName !== "mscqr-production-release-deployer" || !Array.isArray(users) || users.length !== 0 || !Array.isArray(groups) || groups.length !== 0) fail("release policy must be attached only to the governed release-deployer and unused as a permissions boundary");
  return true;
}

export function assertSignerRevocation({ activePolicy, temporaryPolicy, activeVersionId, temporaryVersionId, steadyPolicy, identity } = {}) {
  if (!same(activePolicy, steadyPolicy) || activeVersionId === temporaryVersionId) fail("steady-state policy is not active or temporary policy remains the default");
  assertSignerTemporaryPolicy(temporaryPolicy, { steadyPolicy, ...identity });
  return true;
}

export function assertSignerTemporaryPolicy(policy, { steadyPolicy, sourceSha, transitionId } = {}) {
  assertSignerSteadyPolicy(steadyPolicy);
  const expected = buildSignerTemporaryPolicy(steadyPolicy, { sourceSha, transitionId });
  if (!same(policy, expected)) fail("temporary policy differs from the exact source-bound signer policy");
  const actions = signerTemporaryStatements({ sourceSha, transitionId }).flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  if (actions.some((action) => /^(?:iam|kms):(?:Delete|Attach|Detach|Update|CreateServiceLinkedRole|Decrypt|Encrypt|GenerateDataKey|CreateGrant|ScheduleKeyDeletion|DisableKey|EnableKey|Replicate|ReEncrypt)/.test(action))) fail("temporary policy includes a forbidden IAM/KMS operation");
  return true;
}

export function resolveSignerTemporaryVersionId({ versions, activeVersionId, evidence, steadyPolicy, identity } = {}) {
  const recoveringInstall = evidence?.temporaryVersionId == null;
  if (recoveringInstall && evidence?.state !== "INSTALLING") return null;
  const matches = (version) => {
    try { assertSignerTemporaryPolicy(version.document, { steadyPolicy, ...identity }); return true; }
    catch { return false; }
  };
  if (!recoveringInstall) {
    const version = versions?.find(({ VersionId }) => VersionId === evidence.temporaryVersionId);
    if (!version) return null;
    assertSignerTemporaryPolicy(version.document, { steadyPolicy, ...identity });
    return version.VersionId;
  }
  const active = versions?.find(({ VersionId }) => VersionId === activeVersionId);
  if (active && matches(active)) return active.VersionId;
  const historical = (versions || []).filter(matches);
  if (historical.length > 1) fail("multiple exact temporary signer policy versions make recovery ambiguous");
  return historical[0]?.VersionId ?? null;
}

const expectedAddresses = new Set(["aws_iam_role.signer", "aws_kms_key.image_authorization", "aws_kms_alias.image_authorization", "aws_iam_role_policy.sign_only"]);
export function assertSignerCreationPlan(plan, { trustPolicy } = {}) {
  if (!Array.isArray(plan?.resource_changes)) fail("machine-readable Terraform plan is required");
  const priorRoot = plan.prior_state?.values?.root_module;
  const priorResources = (module) => [...(module?.resources || []), ...(module?.child_modules || []).flatMap(priorResources)];
  if (!plan.prior_state || !priorRoot || (priorRoot.resources !== undefined && !Array.isArray(priorRoot.resources)) || priorResources(priorRoot).length) fail("signer initial convergence requires a valid empty Terraform state");
  const configured = plan.configuration?.root_module?.resources;
  if (!Array.isArray(configured) || configured.length !== expectedAddresses.size || new Set(configured.map(({ address }) => address)).size !== expectedAddresses.size || configured.some(({ address }) => !expectedAddresses.has(address)) || Object.keys(plan.configuration.root_module.child_modules || {}).length) fail("saved plan configuration is not the exact signer Terraform root");
  const provider = plan.configuration.provider_config?.aws?.expressions;
  if (provider?.region?.constant_value !== SIGNER_TEMPORARY_CAPABILITY.region || !same(provider?.allowed_account_ids?.constant_value, [SIGNER_TEMPORARY_CAPABILITY.accountId])) fail("saved plan provider account or region differs from the signer boundary");
  const changed = plan.resource_changes.filter(({ change }) => JSON.stringify(change?.actions || []) !== '["no-op"]');
  if (changed.length !== 4 || new Set(changed.map(({ address }) => address)).size !== 4 || changed.some(({ address, change }) => !expectedAddresses.has(address) || JSON.stringify(change.actions) !== '["create"]')) fail("Terraform plan must create only the four exact signer resources");
  const change = (address) => changed.find((item) => item.address === address)?.change;
  const roleChange = change("aws_iam_role.signer"), keyChange = change("aws_kms_key.image_authorization"), aliasChange = change("aws_kms_alias.image_authorization"), inlineChange = change("aws_iam_role_policy.sign_only");
  const role = roleChange.after, key = keyChange.after, alias = aliasChange.after, inline = inlineChange.after;
  let trust, keyPolicy, signerPolicy;
  try { trust = JSON.parse(role.assume_role_policy); } catch { fail("Terraform plan contains malformed signer OIDC trust JSON"); }
  if (role.name !== SIGNER_TEMPORARY_CAPABILITY.roleName || role.max_session_duration !== 3600 || !same(role.tags, SIGNER_TEMPORARY_CAPABILITY.tags) || !same(trust, trustPolicy)) fail("signer role name, tags, duration, or OIDC trust differs from protected source");
  if (key.description !== "Purpose-specific production security-rebaseline image authorization signer" || key.deletion_window_in_days !== 30 || key.customer_master_key_spec !== "RSA_3072" || key.key_usage !== "SIGN_VERIFY" || key.bypass_policy_lockout_safety_check !== false || !same(key.tags, SIGNER_TEMPORARY_CAPABILITY.tags)) fail("signer key attributes differ from protected source");
  if (alias.name !== SIGNER_TEMPORARY_CAPABILITY.alias || aliasChange.after_unknown?.target_key_id !== true || inline.name !== SIGNER_TEMPORARY_CAPABILITY.inlinePolicyName || (inline.role !== SIGNER_TEMPORARY_CAPABILITY.roleName && inlineChange.after_unknown?.role !== true)) fail("signer alias or inline-policy identity differs from protected source");
  for (const [label, value, unknown] of [["signer runtime policy", inline.policy, inlineChange.after_unknown?.policy], ["signer key policy", key.policy, keyChange.after_unknown?.policy]]) {
    if (typeof value === "string") {
      let parsed; try { parsed = JSON.parse(value); } catch { fail(`${label} is malformed`); }
      if (label === "signer runtime policy" && (parsed.Statement?.length !== 1 || !same(parsed.Statement[0].Action, ["kms:Sign"]) || parsed.Statement[0].Effect !== "Allow" || !["${aws_kms_key.image_authorization.arn}", `arn:aws:kms:${SIGNER_TEMPORARY_CAPABILITY.region}:${SIGNER_TEMPORARY_CAPABILITY.accountId}:key/*`].includes(parsed.Statement[0].Resource) || !same(parsed.Statement[0].Condition, { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": SIGNER_TEMPORARY_CAPABILITY.alias } }))) fail("signer runtime policy is not exact sign-only");
      if (label === "signer key policy" && (parsed.Statement?.length !== 2 || parsed.Statement[0]?.Sid !== "AccountBreakGlassAdministration" || parsed.Statement[0]?.Effect !== "Allow" || parsed.Statement[0]?.Principal?.AWS !== `arn:aws:iam::${SIGNER_TEMPORARY_CAPABILITY.accountId}:root` || !same(Array.isArray(parsed.Statement[0]?.Action) ? parsed.Statement[0].Action : [parsed.Statement[0]?.Action], ["kms:*"]) || !same(Array.isArray(parsed.Statement[0]?.Resource) ? parsed.Statement[0].Resource : [parsed.Statement[0]?.Resource], ["*"]) || parsed.Statement[1]?.Sid !== "ProtectedWorkflowImageAuthorizationSigningOnly" || parsed.Statement[1]?.Effect !== "Allow" || parsed.Statement[1]?.Principal?.AWS !== SIGNER_TEMPORARY_CAPABILITY.roleArn || !same(Array.isArray(parsed.Statement[1]?.Action) ? parsed.Statement[1].Action : [parsed.Statement[1]?.Action], ["kms:Sign"]) || !same(parsed.Statement[1]?.Condition, { StringEquals: { "kms:SigningAlgorithm": "RSASSA_PSS_SHA_256", "kms:MessageType": "DIGEST", "kms:RequestAlias": SIGNER_TEMPORARY_CAPABILITY.alias } }) || parsed.Statement.some((s) => (Array.isArray(s.Action) ? s.Action : [s.Action]).some((a) => ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:CreateGrant"].includes(a))))) fail("signer key policy has an unexpected statement or data-plane permission");
    } else if (unknown !== true) fail(`${label} is neither source-verifiable nor marked computed by Terraform`);
  }
  return true;
}

const optionalBackendKeys = ["access_key", "acl", "allowed_account_ids", "assume_role", "assume_role_with_web_identity", "custom_ca_bundle", "dynamodb_endpoint", "dynamodb_table", "ec2_metadata_service_endpoint", "ec2_metadata_service_endpoint_mode", "endpoint", "endpoints", "forbidden_account_ids", "force_path_style", "http_proxy", "https_proxy", "iam_endpoint", "insecure", "kms_key_id", "max_retries", "no_proxy", "profile", "retry_mode", "secret_key", "shared_config_files", "shared_credentials_file", "shared_credentials_files", "skip_credentials_validation", "skip_metadata_api_check", "skip_region_validation", "skip_requesting_account_id", "skip_s3_checksum", "sse_customer_key", "sts_endpoint", "sts_region", "token", "use_dualstack_endpoint", "use_fips_endpoint", "use_path_style", "workspace_key_prefix"];
export function assertSignerInitializedBackendMetadata(metadata) {
  const expected = { bucket: SIGNER_TEMPORARY_CAPABILITY.bucket, key: SIGNER_TEMPORARY_CAPABILITY.stateKey, region: SIGNER_TEMPORARY_CAPABILITY.region, encrypt: true, use_lockfile: true };
  if (!metadata || metadata.type !== "s3" || !Number.isSafeInteger(metadata.hash) || !metadata.config || typeof metadata.config !== "object") fail("initialized Terraform backend metadata is malformed");
  const allowed = new Set([...Object.keys(expected), ...optionalBackendKeys]);
  if (Object.keys(metadata.config).some((key) => !allowed.has(key)) || Object.entries(expected).some(([key, value]) => metadata.config[key] !== value)) fail("initialized backend differs from the exact signer state contract");
  for (const key of optionalBackendKeys) {
    const value = metadata.config[key];
    if (value !== undefined && value !== null && value !== "" && value !== false && value !== 0 && (!Array.isArray(value) || value.length !== 0)) fail(`initialized backend override ${key} is forbidden`);
  }
  return true;
}

export function buildSignerCapabilityEvidence(fields = {}) {
  const value = { schemaVersion: 1, kind: "MSCQR_PRODUCTION_SIGNER_TEMPORARY_CAPABILITY", state: fields.state, sourceSha: fields.sourceSha, transitionId: fields.transitionId,
    accountId: SIGNER_TEMPORARY_CAPABILITY.accountId, region: SIGNER_TEMPORARY_CAPABILITY.region, purpose: SIGNER_TEMPORARY_CAPABILITY.operation, terraformRoot: SIGNER_TEMPORARY_CAPABILITY.root,
    stateKey: SIGNER_TEMPORARY_CAPABILITY.stateKey, lockKey: SIGNER_TEMPORARY_CAPABILITY.lockKey, policyArn: SIGNER_TEMPORARY_CAPABILITY.sourcePolicyArn,
    steadyVersionId: fields.steadyVersionId ?? null, temporaryVersionId: fields.temporaryVersionId ?? null, planSha256: fields.planSha256 ?? null, approvalReference: fields.approvalReference ?? null,
    observedAt: fields.observedAt, ...(fields.signerReadbackSha256 ? { signerReadbackSha256: fields.signerReadbackSha256 } : {}) };
  if (!/^[a-f0-9]{40}$/.test(value.sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(value.transitionId || "") || !value.observedAt) fail("authorization evidence identity is incomplete");
  return { ...value, evidenceSha256: sha256(canonical(value)) };
}

export function assertSignerCapabilityEvidence(value, { state, sourceSha, transitionId } = {}) {
  if (value?.schemaVersion !== 1 || value.kind !== "MSCQR_PRODUCTION_SIGNER_TEMPORARY_CAPABILITY" || (state && value.state !== state) || value.sourceSha !== sourceSha || value.transitionId !== transitionId
    || value.accountId !== SIGNER_TEMPORARY_CAPABILITY.accountId || value.region !== SIGNER_TEMPORARY_CAPABILITY.region || value.purpose !== SIGNER_TEMPORARY_CAPABILITY.operation || value.terraformRoot !== SIGNER_TEMPORARY_CAPABILITY.root
    || value.stateKey !== SIGNER_TEMPORARY_CAPABILITY.stateKey || value.lockKey !== SIGNER_TEMPORARY_CAPABILITY.lockKey || value.policyArn !== SIGNER_TEMPORARY_CAPABILITY.sourcePolicyArn) fail("evidence is stale, replayed, or outside the exact signer boundary");
  const { evidenceSha256, ...body } = value;
  if (evidenceSha256 !== sha256(canonical(body))) fail("evidence integrity hash is invalid");
  if (!/^[a-f0-9]{40}$/.test(value.sourceSha) || !/^[A-Za-z0-9._-]{8,128}$/.test(value.transitionId) || !["INSTALLING", "INSTALLED", "PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_COMPLETED", "CONVERGED", "REVOKED", "ABSENCE_VERIFIED"].includes(value.state)) fail("evidence lifecycle identity or state is invalid");
  if (["PLAN_GENERATED", "PLAN_REVIEWED", "APPLY_COMPLETED", "CONVERGED"].includes(value.state) && !/^[a-f0-9]{64}$/.test(value.planSha256 || "")) fail("plan-bound evidence is incomplete");
  if (["PLAN_REVIEWED", "APPLY_COMPLETED", "CONVERGED"].includes(value.state) && !/^[A-Za-z0-9._:/-]{6,160}$/.test(value.approvalReference || "")) fail("separate plan approval reference is missing");
  if (value.state === "CONVERGED" && !/^[a-f0-9]{64}$/.test(value.signerReadbackSha256 || "")) fail("signer live readback evidence is missing");
  return true;
}
