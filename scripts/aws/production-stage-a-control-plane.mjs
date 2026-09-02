import { createHash, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { PRODUCTION_ACTIVATION_LIFECYCLE, STAGE_B } from "./production-green-stage-b-contract.mjs";
const REQUIRED_LOGICAL_ADDRESS = "aws_vpc_security_group_ingress_rule.runtime_endpoints_https";
const SHA256 = /^[a-f0-9]{64}$/;
const RDS_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const exact = (value, expected, message) => { if (value !== expected) throw new Error(message); };

export function assertStageARdsLatestRestorableTimeRefresh(before, after) {
  if (!before || typeof before !== "object" || Array.isArray(before) || !after || typeof after !== "object" || Array.isArray(after)) throw new Error("Stage A plan contains malformed RDS before/after state.");
  const parseTimestamp = (value) => {
    const milliseconds = typeof value === "string" && RDS_UTC_TIMESTAMP.test(value) ? Date.parse(value) : NaN;
    if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value.replace("Z", ".000Z")) throw new Error("Stage A plan contains a malformed RDS latest_restorable_time.");
    return milliseconds;
  };
  if (parseTimestamp(after.latest_restorable_time) <= parseTimestamp(before.latest_restorable_time)) throw new Error("Stage A plan contains a non-forward RDS latest_restorable_time.");
  const withoutTimestamp = (value) => Object.fromEntries(Object.entries(value).filter(([field]) => field !== "latest_restorable_time"));
  if (!isDeepStrictEqual(withoutTimestamp(before), withoutTimestamp(after))) throw new Error("Stage A plan changes RDS state outside latest_restorable_time.");
  return true;
}

export function assertStageAResourceDrift(plan) {
  if (plan?.resource_drift === undefined) return true;
  if (!Array.isArray(plan.resource_drift) || plan.resource_drift.length > 1) throw new Error("Stage A plan contains uncontracted provider drift.");
  if (plan.resource_drift.length === 0) return true;
  const [entry] = plan.resource_drift;
  const change = entry?.change;
  const emptyObject = (value) => value === undefined || value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;
  if (entry?.address !== "aws_db_instance.green" || entry.mode !== "managed" || entry.type !== "aws_db_instance" || entry.name !== "green"
    || !change || !isDeepStrictEqual(change.actions, ["update"])
    || change.replace_paths !== undefined && (!Array.isArray(change.replace_paths) || change.replace_paths.length)
    || !emptyObject(change.before_unknown) || !emptyObject(change.after_unknown)) throw new Error("Stage A plan contains uncontracted provider drift.");
  return assertStageARdsLatestRestorableTimeRefresh(change.before, change.after);
}
export const STAGE_A_CHECKER_POLICY = Object.freeze({
  address: "aws_iam_role_policy.checker_assume_target",
  type: "aws_iam_role_policy",
  role: "mscqr-production-independent-checker",
  name: "mscqr-production-independent-checker-role-chain",
  sid: "AssumeExactRlsIndependentChecker",
  action: "sts:AssumeRole",
  resource: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
});
export const STAGE_A_CHECKER_ROLE_TRUST = Object.freeze({
  address: "aws_iam_role.checker",
  type: "aws_iam_role",
  name: "mscqr-production-rls-independent-checker",
  principal: "arn:aws:iam::368992683803:role/mscqr-production-independent-checker",
  action: "sts:AssumeRole",
});
export const STAGE_A_CHECKER_PUBLICATION_POLICY = Object.freeze({
  address: "aws_iam_role_policy.checker",
  type: "aws_iam_role_policy",
  role: "mscqr-production-rls-independent-checker",
  name: "mscqr-production-rls-independent-checker",
  kmsAction: ["kms:GetPublicKey", "kms:Sign", "kms:Verify"],
  kmsResource: STAGE_B.approvalKmsKeyArn,
  publishAction: "secretsmanager:PutSecretValue",
  publishResource: STAGE_B.approvalSecretArn,
});
export const STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY = Object.freeze({
  address: "aws_s3_bucket_policy.production_artifacts",
  type: "aws_s3_bucket_policy",
  bucket: PRODUCTION_ACTIVATION_LIFECYCLE.bucket,
});
export function buildStageAProductionArtifactsBucketPolicyPredecessor() {
  const objects = [PRODUCTION_ACTIVATION_LIFECYCLE.claimArn, PRODUCTION_ACTIVATION_LIFECYCLE.completionArn];
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "AllowReleaseDeployerReadActivationLifecycle", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:GetObject", Resource: objects },
      { Sid: "AllowReleaseDeployerConditionalActivationLifecycleCreate", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:PutObject", Resource: objects, Condition: { StringEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyNonConditionalActivationLifecycleWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: objects, Condition: { StringNotEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyOtherPrincipalsActivationLifecycleWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: objects, Condition: { StringNotEquals: { "aws:PrincipalArn": PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn } } },
      { Sid: "DenyActivationLifecycleDeletion", Effect: "Deny", Principal: "*", Action: ["s3:DeleteObject", "s3:DeleteObjectVersion"], Resource: objects },
      { Sid: "DenyProductionArtifactsBucketPolicyMutation", Effect: "Deny", Principal: "*", Action: ["s3:PutBucketPolicy", "s3:DeleteBucketPolicy"], Resource: `arn:aws:s3:::${PRODUCTION_ACTIVATION_LIFECYCLE.bucket}` },
    ],
  };
}
export function buildStageAProductionArtifactsBucketPolicy() {
  const predecessor = buildStageAProductionArtifactsBucketPolicyPredecessor();
  const immutableEvidence = [PRODUCTION_ACTIVATION_LIFECYCLE.rebaselineEvidenceArn];
  return {
    ...predecessor,
    Statement: [
      ...predecessor.Statement,
      { Sid: "AllowReleaseDeployerReadRebaselineEvidence", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:GetObject", Resource: immutableEvidence },
      { Sid: "AllowReleaseDeployerConditionalRebaselineEvidenceCreate", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:PutObject", Resource: immutableEvidence, Condition: { StringEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyNonConditionalRebaselineEvidenceWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: immutableEvidence, Condition: { StringNotEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyOtherPrincipalsRebaselineEvidenceWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: immutableEvidence, Condition: { StringNotEquals: { "aws:PrincipalArn": PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn } } },
      { Sid: "DenyRebaselineEvidenceDeletion", Effect: "Deny", Principal: "*", Action: ["s3:DeleteObject", "s3:DeleteObjectVersion"], Resource: immutableEvidence },
    ],
  };
}
const STAGE_A_CHECKER_PUBLICATION_PREDECESSOR = Object.freeze({
  Version: "2012-10-17",
  Statement: [{
    Action: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction,
    Effect: "Allow",
    Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsResource,
  }],
});
const STAGE_A_CHECKER_PUBLICATION_DESIRED = Object.freeze({
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "SignExactStageBApproval",
      Effect: "Allow",
      Action: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsAction,
      Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.kmsResource,
    },
    {
      Sid: "PublishExactStageBApproval",
      Effect: "Allow",
      Action: STAGE_A_CHECKER_PUBLICATION_POLICY.publishAction,
      Resource: STAGE_A_CHECKER_PUBLICATION_POLICY.publishResource,
    },
  ],
});
const exactActions = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const stable = (value) => value && typeof value === "object" && !Array.isArray(value)
  ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]))
  : Array.isArray(value) ? value.map(stable) : value;
const stableJson = (value) => JSON.stringify(stable(value));
const stablePolicy = (value, key) => {
  if (Array.isArray(value)) {
    const entries = value.map((entry) => stablePolicy(entry));
    return ["Action", "NotAction", "NotResource", "Resource", "Statement"].includes(key)
      ? entries.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))
      : entries;
  }
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((entry) => [entry, stablePolicy(value[entry], entry)]));
  return value;
};
const stablePolicyJson = (value) => JSON.stringify(stablePolicy(value));
export const STAGE_A_ROOT_DROP_RELEASE_ROLE_ARN = "arn:aws:iam::368992683803:role/mscqr-production-release-deployer";
export const STAGE_A_ROOT_DROP_PROVIDER_READ_ACTIONS = Object.freeze([
  "kms:DescribeKey",
  "kms:GetKeyPolicy",
  "kms:GetKeyRotationStatus",
  "kms:ListResourceTags",
]);

export function buildStageAApprovalKeyPolicy() {
  const checkerArn = `arn:aws:iam::368992683803:role/${STAGE_A_CHECKER_ROLE_TRUST.name}`;
  return { Version: "2012-10-17", Statement: [
    { Sid: "AccountAdministration", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: "kms:*", Resource: "*" },
    { Sid: "IndependentCheckerSigns", Effect: "Allow", Principal: { AWS: checkerArn }, Action: ["kms:GetPublicKey", "kms:Sign", "kms:Verify"], Resource: "*" },
    { Sid: "DenyNonCheckerApprovalSigning", Effect: "Deny", Principal: "*", Action: "kms:Sign", Resource: "*", Condition: { StringNotEquals: { "aws:PrincipalArn": checkerArn } } },
  ] };
}

export function assertStageAApprovalKeyPolicyDocument(document) {
  if (stablePolicyJson(document) !== stablePolicyJson(buildStageAApprovalKeyPolicy())) throw new Error("Stage A approval key policy is not checker-sign-exclusive.");
  return true;
}

export function buildStageARootDropKeyPolicy({ releaseRoleArn = STAGE_A_ROOT_DROP_RELEASE_ROLE_ARN } = {}) {
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "AccountAdministration", Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: "kms:*", Resource: "*" },
      { Sid: "DenyNonRootRootDropSigning", Effect: "Deny", Principal: "*", Action: ["kms:Sign", "kms:Verify"], Resource: "*", Condition: { StringNotEquals: { "aws:PrincipalArn": "arn:aws:iam::368992683803:root" } } },
      { Sid: "ReleaseReadsRootDropKey", Effect: "Allow", Principal: { AWS: releaseRoleArn }, Action: [...STAGE_A_ROOT_DROP_PROVIDER_READ_ACTIONS, "kms:GetPublicKey"], Resource: "*" },
    ],
  };
}

export function assertStageARootDropKeyPolicyDocument(document, { releaseRoleArn = STAGE_A_ROOT_DROP_RELEASE_ROLE_ARN } = {}) {
  if (stablePolicyJson(document) !== stablePolicyJson(buildStageARootDropKeyPolicy({ releaseRoleArn }))) throw new Error("Stage A root-drop key policy does not match the provider read and signing contract.");
  return true;
}

export function assertStageARootDropKeyPolicySource(source, { releaseRoleArn = STAGE_A_ROOT_DROP_RELEASE_ROLE_ARN } = {}) {
  if (typeof source !== "string") throw new Error("Stage A root-drop Terraform source is missing.");
  const block = source.match(/resource "aws_kms_key" "root_drop" \{([\s\S]*?)\n\}/)?.[1];
  if (!block) throw new Error("Stage A root-drop Terraform resource is missing.");
  const expectedActions = `Action = ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:GetPublicKey", "kms:ListResourceTags"]`;
  if (!block.includes(expectedActions)) throw new Error("Stage A root-drop Terraform key policy omits a required provider read action.");
  if (!block.includes(`Principal = { AWS = var.release_role_arn }`) || releaseRoleArn !== STAGE_A_ROOT_DROP_RELEASE_ROLE_ARN) throw new Error("Stage A root-drop Terraform release principal is not the reviewed role.");
  if (/release_role_arn[^\n]*(?:kms:\*|kms:PutKeyPolicy)/.test(block) || /(?:kms:\*|kms:PutKeyPolicy)[^\n]*release_role_arn/.test(block)) throw new Error("Stage A root-drop Terraform release principal has permanent administration.");
  if (!block.includes('Action = "kms:*"') || !block.includes('AWS = "arn:aws:iam::368992683803:root"')) throw new Error("Stage A root-drop Terraform account administration path is missing.");
  return true;
}
export function normalizeStageACheckerPrincipalAws(value) {
  if (typeof value === "string") return value;
  if (Array.isArray(value) && value.length === 1 && typeof value[0] === "string") return value[0];
  throw new Error("Stage A checker role trust AWS principal must be a string or singleton string array.");
}
const exactPrincipal = (value, expected) => {
  try { return normalizeStageACheckerPrincipalAws(value) === expected; } catch { return false; }
};
const decodePolicy = (value, label) => {
  if (typeof value !== "string") throw new Error(`${label} is missing.`);
  try { return JSON.parse(value); } catch { throw new Error(`${label} is malformed.`); }
};

export function assertStageACheckerRoleTrustDocument(document, { allowObsoleteSecondHopMfa = false } = {}) {
  if (!document || document.Version !== "2012-10-17" || !Array.isArray(document.Statement) || document.Statement.length !== 1
    || Object.keys(document).sort().join(",") !== "Statement,Version") throw new Error("Stage A checker role trust envelope is not exact.");
  const [statement] = document.Statement;
  const expectedKeys = allowObsoleteSecondHopMfa ? "Action,Condition,Effect,Principal" : "Action,Effect,Principal";
  if (!statement || Object.keys(statement).sort().join(",") !== expectedKeys
    || statement.Effect !== "Allow" || statement.Action !== STAGE_A_CHECKER_ROLE_TRUST.action
    || !statement.Principal || Object.keys(statement.Principal).length !== 1
    || !exactPrincipal(statement.Principal.AWS, STAGE_A_CHECKER_ROLE_TRUST.principal)) {
    throw new Error("Stage A checker role trust semantics are not exact.");
  }
  if (allowObsoleteSecondHopMfa) {
    if (stableJson(statement.Condition) !== stableJson({ Bool: { "aws:MultiFactorAuthPresent": "true" } })) throw new Error("Stage A checker role trust does not match the only recognized obsolete second-hop MFA state.");
  } else if (statement.Condition !== undefined) throw new Error("Stage A checker role trust must not require second-hop MFA.");
  return { exact: true, principal: STAGE_A_CHECKER_ROLE_TRUST.principal, action: STAGE_A_CHECKER_ROLE_TRUST.action, secondHopMfaRequired: allowObsoleteSecondHopMfa };
}

function assertStageACheckerRoleTrustChange(entry) {
  if (entry.type !== STAGE_A_CHECKER_ROLE_TRUST.type) throw new Error("Stage A checker role trust resource type is wrong.");
  const change = entry.change;
  if (!exactActions(change?.actions, ["update"]) && !exactActions(change?.actions, ["no-op"])) throw new Error("Stage A checker role trust must be an update-only or converged no-op change.");
  const before = change?.before;
  const after = change?.after;
  if (!before || typeof before !== "object" || Array.isArray(before) || !after || typeof after !== "object" || Array.isArray(after)) throw new Error("Stage A checker role trust before/after values are missing.");
  for (const value of [before, after]) if (value.name !== STAGE_A_CHECKER_ROLE_TRUST.name) throw new Error("Stage A checker role identity is wrong.");
  const beforeWithoutTrust = { ...before }; delete beforeWithoutTrust.assume_role_policy;
  const afterWithoutTrust = { ...after }; delete afterWithoutTrust.assume_role_policy;
  if (stableJson(beforeWithoutTrust) !== stableJson(afterWithoutTrust)) throw new Error("Stage A checker role trust change contains unrelated role mutations.");
  if (exactActions(change.actions, ["update"])) {
    assertStageACheckerRoleTrustDocument(decodePolicy(before.assume_role_policy, "Stage A checker role previous trust"), { allowObsoleteSecondHopMfa: true });
    assertStageACheckerRoleTrustDocument(decodePolicy(after.assume_role_policy, "Stage A checker role next trust"));
    return { valid: true, alreadyConverged: false, mutationCount: 1 };
  }
  assertStageACheckerRoleTrustDocument(decodePolicy(before.assume_role_policy, "Stage A checker role converged previous trust"));
  assertStageACheckerRoleTrustDocument(decodePolicy(after.assume_role_policy, "Stage A checker role converged trust"));
  return { valid: true, alreadyConverged: true, mutationCount: 0 };
}

function decodePolicyDocument(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is missing.`);
  try { return JSON.parse(value); } catch { throw new Error(`${label} is malformed.`); }
}

function assertStageACheckerPublicationPolicyChange(entry) {
  if (entry.type !== STAGE_A_CHECKER_PUBLICATION_POLICY.type) throw new Error("Stage A checker publication policy resource type is wrong.");
  const change = entry.change;
  if (!exactActions(change?.actions, ["update"]) && !exactActions(change?.actions, ["no-op"])) throw new Error("Stage A checker publication policy must be an update-only or converged no-op change.");
  if (change.replace_paths?.length) throw new Error("Stage A checker publication policy must not be replaced.");
  const before = change?.before;
  const after = change?.after;
  if (!before || typeof before !== "object" || Array.isArray(before) || !after || typeof after !== "object" || Array.isArray(after)) throw new Error("Stage A checker publication policy before/after values are missing.");
  for (const value of [before, after]) {
    if (value.name !== STAGE_A_CHECKER_PUBLICATION_POLICY.name || value.role !== STAGE_A_CHECKER_PUBLICATION_POLICY.role) throw new Error("Stage A checker publication policy identity is wrong.");
  }
  const beforeWithoutPolicy = { ...before }; delete beforeWithoutPolicy.policy;
  const afterWithoutPolicy = { ...after }; delete afterWithoutPolicy.policy;
  if (stableJson(beforeWithoutPolicy) !== stableJson(afterWithoutPolicy)) throw new Error("Stage A checker publication policy contains unrelated mutations.");
  const beforePolicy = decodePolicyDocument(before.policy, "Stage A checker publication predecessor policy");
  const afterPolicy = decodePolicyDocument(after.policy, "Stage A checker publication desired policy");
  const expectedAfter = stablePolicyJson(afterPolicy) === stablePolicyJson(STAGE_A_CHECKER_PUBLICATION_DESIRED);
  if (!expectedAfter) throw new Error("Stage A checker publication policy desired semantics are not exact.");
  if (exactActions(change.actions, ["update"]) && stablePolicyJson(beforePolicy) !== stablePolicyJson(STAGE_A_CHECKER_PUBLICATION_PREDECESSOR)) {
    throw new Error("Stage A checker publication policy predecessor semantics are not the reviewed state.");
  }
  if (exactActions(change.actions, ["no-op"]) && stablePolicyJson(beforePolicy) !== stablePolicyJson(STAGE_A_CHECKER_PUBLICATION_DESIRED)) {
    throw new Error("Stage A checker publication policy converged predecessor semantics are not exact.");
  }
  return { valid: true, alreadyConverged: exactActions(change.actions, ["no-op"]), mutationCount: exactActions(change.actions, ["update"]) ? 1 : 0 };
}

function assertStageAProductionArtifactsBucketPolicyChange(entry) {
  if (entry.type !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type) throw new Error("Stage A production-artifacts bucket-policy resource type is wrong.");
  const change = entry.change;
  if (!exactActions(change?.actions, ["create"]) && !exactActions(change?.actions, ["update"]) && !exactActions(change?.actions, ["no-op"])) throw new Error("Stage A production-artifacts bucket policy must be an exact create, reviewed update, or converged no-op.");
  if (change.replace_paths?.length || change.after?.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket) throw new Error("Stage A production-artifacts bucket-policy identity is wrong.");
  const expected = stablePolicyJson(buildStageAProductionArtifactsBucketPolicy());
  if (stablePolicyJson(decodePolicyDocument(change.after?.policy, "Stage A production-artifacts bucket policy")) !== expected) throw new Error("Stage A production-artifacts bucket-policy semantics are not exact.");
  if (exactActions(change.actions, ["create"])) {
    if (change.before !== null) throw new Error("Stage A production-artifacts bucket policy does not have the authenticated absent predecessor.");
  } else if (exactActions(change.actions, ["update"])) {
    if (change.before?.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket
      || stablePolicyJson(decodePolicyDocument(change.before?.policy, "Stage A production-artifacts bucket policy predecessor")) !== stablePolicyJson(buildStageAProductionArtifactsBucketPolicyPredecessor())) {
      throw new Error("Stage A production-artifacts bucket policy update predecessor is not the exact reviewed six-statement policy.");
    }
  } else if (stablePolicyJson(decodePolicyDocument(change.before?.policy, "Stage A converged production-artifacts bucket policy")) !== expected
    || change.before?.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket) throw new Error("Stage A converged production-artifacts bucket-policy predecessor is not exact.");
  return { alreadyConverged: exactActions(change.actions, ["no-op"]), mutationCount: exactActions(change.actions, ["create"]) || exactActions(change.actions, ["update"]) ? 1 : 0 };
}

function readAndVerifyPlanSha256(planPath, expectedSha256) {
  if (!SHA256.test(expectedSha256 || "")) throw new Error("Stage A preserved plan SHA-256 is missing or malformed.");
  let bytes;
  try { bytes = fs.readFileSync(planPath); } catch { throw new Error("Stage A preserved plan is missing or unreadable."); }
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  const expected = Buffer.from(expectedSha256, "hex");
  const actual = Buffer.from(actualSha256, "hex");
  if (!timingSafeEqual(actual, expected)) throw new Error("Stage A preserved plan SHA-256 does not match the bootstrap binding.");
  return actualSha256;
}

export function assertStageAPlan(plan, { endpointSecurityGroupId, runtimeSecurityGroupId } = {}) {
  if (!plan || !Array.isArray(plan.resource_changes) || !endpointSecurityGroupId || !runtimeSecurityGroupId) throw new Error("Stage A plan inputs are incomplete.");
  assertStageAResourceDrift(plan);
  const expectedAddress = `${REQUIRED_LOGICAL_ADDRESS}[${JSON.stringify(runtimeSecurityGroupId)}]`;
  const changes = plan.resource_changes.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || typeof entry.address !== "string" || !entry.address.trim()) throw new Error("Stage A plan contains a malformed resource entry.");
    if (!entry.change || typeof entry.change !== "object" || Array.isArray(entry.change)) throw new Error("Stage A plan resource change is malformed.");
    const actions = entry.change.actions;
    if (!Array.isArray(actions) || actions.length === 0 || !actions.every((action) => typeof action === "string")) throw new Error("Stage A plan resource actions are malformed.");
    return { entry, actions };
  });
  const checkerRole = changes.filter(({ entry }) => entry.address === STAGE_A_CHECKER_ROLE_TRUST.address);
  if (checkerRole.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed checker role trust resource.");
  const checkerRoleValidation = assertStageACheckerRoleTrustChange(checkerRole[0].entry);
  const checkerPublication = changes.filter(({ entry }) => entry.address === STAGE_A_CHECKER_PUBLICATION_POLICY.address);
  if (checkerPublication.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed checker publication policy resource.");
  const checkerPublicationValidation = assertStageACheckerPublicationPolicyChange(checkerPublication[0].entry);
  const artifactsBucketPolicy = changes.filter(({ entry }) => entry.address === STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address);
  if (artifactsBucketPolicy.length !== 1) throw new Error("Stage A plan must contain exactly one complete production-artifacts bucket policy.");
  const artifactsBucketPolicyValidation = assertStageAProductionArtifactsBucketPolicyChange(artifactsBucketPolicy[0].entry);
  const unexpected = changes.filter(({ entry, actions }) => entry.address !== expectedAddress && entry.address !== STAGE_A_CHECKER_POLICY.address
    && entry.address !== STAGE_A_CHECKER_ROLE_TRUST.address
    && entry.address !== STAGE_A_CHECKER_PUBLICATION_POLICY.address
    && entry.address !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address
    && !exactActions(actions, ["no-op"]) && !exactActions(actions, ["read"]));
  if (unexpected.length) throw new Error("Stage A plan contains an unreviewed mutation.");
  const reviewed = changes.filter(({ entry }) => entry.address === expectedAddress);
  if (reviewed.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed ingress instance.");
  const checker = changes.filter(({ entry }) => entry.address === STAGE_A_CHECKER_POLICY.address);
  if (checker.length !== 1) throw new Error("Stage A plan must contain exactly one reviewed checker role-chain policy.");
  const { entry: change, actions } = reviewed[0];
  if (!exactActions(actions, ["create"]) && !exactActions(actions, ["no-op"])) throw new Error("Stage A plan contains an unreviewed ingress action.");
  const { entry: checkerChange, actions: checkerActions } = checker[0];
  exact(checkerChange.type, STAGE_A_CHECKER_POLICY.type, "Stage A checker role-chain policy type is wrong.");
  if (!exactActions(checkerActions, ["create"]) && !exactActions(checkerActions, ["no-op"])) throw new Error("Stage A checker role-chain policy action is wrong.");
  const checkerAfter = checkerChange.change?.after;
  if (!checkerAfter || typeof checkerAfter !== "object" || Array.isArray(checkerAfter)) throw new Error("Stage A checker role-chain policy body is missing.");
  exact(checkerAfter.role, STAGE_A_CHECKER_POLICY.role, "Stage A checker role is wrong.");
  exact(checkerAfter.name, STAGE_A_CHECKER_POLICY.name, "Stage A checker policy name is wrong.");
  if (typeof checkerAfter.policy !== "string") throw new Error("Stage A checker policy document is missing.");
  let checkerPolicy;
  try { checkerPolicy = JSON.parse(checkerAfter.policy); } catch { throw new Error("Stage A checker policy document is malformed."); }
  if (!checkerPolicy || checkerPolicy.Version !== "2012-10-17" || !Array.isArray(checkerPolicy.Statement) || checkerPolicy.Statement.length !== 1
    || Object.keys(checkerPolicy).sort().join(",") !== "Statement,Version") throw new Error("Stage A checker policy envelope is not exact.");
  const [statement] = checkerPolicy.Statement;
  if (!statement || Object.keys(statement).sort().join(",") !== "Action,Effect,Resource,Sid"
    || statement.Sid !== STAGE_A_CHECKER_POLICY.sid || statement.Effect !== "Allow"
    || statement.Action !== STAGE_A_CHECKER_POLICY.action || statement.Resource !== STAGE_A_CHECKER_POLICY.resource) {
    throw new Error("Stage A checker policy semantics are not exact.");
  }
  const after = change.change?.after || {};
  exact(after.security_group_id, endpointSecurityGroupId, "Stage A plan endpoint security group is wrong.");
  exact(after.referenced_security_group_id, runtimeSecurityGroupId, "Stage A plan runtime security group is wrong.");
  exact(String(after.from_port), "443", "Stage A plan ingress port is wrong.");
  exact(String(after.to_port), "443", "Stage A plan ingress port is wrong.");
  exact(after.ip_protocol, "tcp", "Stage A plan ingress protocol is wrong.");
  if (after.cidr_ipv4 !== null || after.cidr_ipv6 !== null || after.prefix_list_id !== null) throw new Error("Stage A plan ingress source is not the reviewed security group.");
  const mutationCount = [actions, checkerActions].filter((value) => exactActions(value, ["create"])).length + checkerRoleValidation.mutationCount + checkerPublicationValidation.mutationCount + artifactsBucketPolicyValidation.mutationCount;
  return { valid: true, changes: mutationCount, address: change.address, actions, checkerActions, checkerRoleActions: checkerRole[0].actions, checkerPublicationActions: checkerPublication[0].actions, alreadyConverged: exactActions(actions, ["no-op"]) && exactActions(checkerActions, ["no-op"]) && checkerRoleValidation.alreadyConverged && checkerPublicationValidation.alreadyConverged && artifactsBucketPolicyValidation.alreadyConverged };
}

export async function runStageAControlPlane({ adapter, endpointSecurityGroupId, runtimeSecurityGroupId, sourceSha } = {}) {
  if (!adapter || typeof adapter.createSavedPlan !== "function" || typeof adapter.applySavedPlan !== "function" || typeof adapter.describeIngress !== "function") throw new Error("Stage A control-plane adapter is incomplete.");
  const saved = await adapter.createSavedPlan();
  if (sourceSha && saved?.sourceSha !== sourceSha) throw new Error("Stage A saved plan is not bound to the protected-main source SHA.");
  if (!/^[a-f0-9]{64}$/.test(saved?.savedPlanSha256 || "")) throw new Error("Stage A saved plan bytes are not hash-bound.");
  const plan = saved?.plan;
  const validation = assertStageAPlan(plan, { endpointSecurityGroupId, runtimeSecurityGroupId });
  if (!validation.alreadyConverged) await adapter.applySavedPlan(saved);
  const rule = await adapter.describeIngress({ endpointSecurityGroupId, runtimeSecurityGroupId, protocol: "tcp", fromPort: 443, toPort: 443 });
  if (rule?.present !== true) throw new Error("Stage A endpoint ingress postcondition is absent.");
  return { valid: true, ...validation, appliedExactSavedPlan: !validation.alreadyConverged, postconditionVerified: true, evidenceRef: saved.evidenceRef, evidenceSha256: saved.evidenceSha256, mutationCount: validation.changes };
}

export function createTerraformStageAAdapter({ terraform = "terraform", root = "infra/aws/terraform/production-green-stage-a", backendArgs = [], planPath, stageAPlanSha256, run, describeIngress, sourceSha, region = "eu-west-2" } = {}) {
  if (typeof run !== "function" || typeof describeIngress !== "function" || !path.isAbsolute(planPath || "")) throw new Error("Stage A Terraform adapter is incomplete.");
  if (sourceSha && !/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Stage A source SHA is invalid.");
  if (!/^[a-z]{2}-[a-z]+-[0-9]$/.test(region)) throw new Error("Stage A region is invalid.");
  let savedPlanSha256 = null;
  return {
    async createSavedPlan() {
      if (fs.existsSync(planPath)) {
        readAndVerifyPlanSha256(planPath, stageAPlanSha256);
        await run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", "-backend=false"]);
      } else {
        if (stageAPlanSha256 !== undefined) throw new Error("Stage A preserved plan is missing.");
        await run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", ...backendArgs]);
        await run([terraform, `-chdir=${root}`, "plan", "-input=false", "-out", planPath]);
      }
      const plan = JSON.parse(await run([terraform, `-chdir=${root}`, "show", "-json", planPath]));
      const bytes = fs.readFileSync(planPath);
      savedPlanSha256 = createHash("sha256").update(bytes).digest("hex");
      if (stageAPlanSha256 !== undefined) readAndVerifyPlanSha256(planPath, stageAPlanSha256);
      return { plan, planPath, savedPlanSha256, sourceSha, region, terraformRoot: root, evidenceRef: `terraform-plan:${planPath}`, evidenceSha256: savedPlanSha256 };
    },
    async applySavedPlan(saved) {
      if (!saved || saved.planPath !== planPath || saved.savedPlanSha256 !== savedPlanSha256) throw new Error("Stage A saved plan changed after validation.");
      const currentSha256 = stageAPlanSha256 === undefined ? createHash("sha256").update(fs.readFileSync(planPath)).digest("hex") : readAndVerifyPlanSha256(planPath, stageAPlanSha256);
      if (currentSha256 !== savedPlanSha256) throw new Error("Stage A saved plan changed after validation.");
      await run([terraform, `-chdir=${root}`, "apply", "-input=false", planPath]);
    },
    describeIngress,
  };
}
