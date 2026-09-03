import { createHash, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { PRODUCTION_ACTIVATION_LIFECYCLE, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { assertStageAProductionArtifactsJournalResult, assertStageAProductionArtifactsPostApplyEvidence, assertStageAProductionArtifactsReservation, STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION } from "./production-stage-a-production-artifacts-journal.mjs";
const REQUIRED_LOGICAL_ADDRESS = "aws_vpc_security_group_ingress_rule.runtime_endpoints_https";
const SHA256 = /^[a-f0-9]{64}$/;
const RDS_UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const exact = (value, expected, message) => { if (value !== expected) throw new Error(message); };
const STAGE_A_STATE_LINEAGE = "02afb75a-f902-ab8a-f4c1-751d4aef7837";
export const STAGE_A_TERRAFORM_VERSION = "1.15.8";
const STAGE_A_POLICY_RESOURCE_KEYS = ["bucket", "expected_bucket_owner", "id", "policy", "region"];
const STAGE_A_RDS_SENSITIVITY_MASK = Object.freeze({
  blue_green_update: [], domain_dns_ips: [], enabled_cloudwatch_logs_exports: [], listener_endpoint: [], master_user_secret: [{}], password: true, password_wo: true, replicas: [], restore_to_point_in_time: [], s3_import: [], tags: {}, tags_all: {}, vpc_security_group_ids: [false],
});

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

const emptyObject = (value) => value === undefined || value === null || value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;

export function assertStageARdsLatestRestorableTimeDrift(entry) {
  const change = entry?.change;
  if (entry?.address !== "aws_db_instance.green" || entry.mode !== "managed" || entry.type !== "aws_db_instance" || entry.name !== "green"
    || entry.provider_name !== "registry.terraform.io/hashicorp/aws" || !change || !isDeepStrictEqual(change.actions, ["update"])
    || !Array.isArray(change.replace_paths) || change.replace_paths.length
    || !emptyObject(change.before_unknown) || !emptyObject(change.after_unknown)
    || !isDeepStrictEqual(change.before_sensitive, STAGE_A_RDS_SENSITIVITY_MASK)
    || !isDeepStrictEqual(change.after_sensitive, STAGE_A_RDS_SENSITIVITY_MASK)) throw new Error("Stage A plan contains uncontracted RDS drift.");
  return assertStageARdsLatestRestorableTimeRefresh(change.before, change.after);
}

export function assertStageAResourceDrift(plan) {
  if (plan?.resource_drift === undefined) return true;
  if (!Array.isArray(plan.resource_drift) || plan.resource_drift.length > 1) throw new Error("Stage A plan contains uncontracted provider drift.");
  if (plan.resource_drift.length === 0) return true;
  const [entry] = plan.resource_drift;
  return assertStageARdsLatestRestorableTimeDrift(entry);
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
// `terraform providers schema -json` from the locked Terraform 1.15.8 / AWS 6.56.0 envelope.
export const STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS = Object.freeze({
  [STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address]: 0,
  "aws_db_instance.green": 2,
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
  const reconciliationJournal = [PRODUCTION_ACTIVATION_LIFECYCLE.stageAProductionArtifactsReconciliationArn];
  return {
    ...predecessor,
    Statement: [
      ...predecessor.Statement,
      { Sid: "AllowReleaseDeployerReadRebaselineEvidence", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:GetObject", Resource: immutableEvidence },
      { Sid: "AllowReleaseDeployerConditionalRebaselineEvidenceCreate", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:PutObject", Resource: immutableEvidence, Condition: { StringEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyNonConditionalRebaselineEvidenceWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: immutableEvidence, Condition: { StringNotEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyOtherPrincipalsRebaselineEvidenceWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: immutableEvidence, Condition: { StringNotEquals: { "aws:PrincipalArn": PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn } } },
      { Sid: "DenyRebaselineEvidenceDeletion", Effect: "Deny", Principal: "*", Action: ["s3:DeleteObject", "s3:DeleteObjectVersion"], Resource: immutableEvidence },
      { Sid: "AllowReleaseDeployerReadStageAProductionArtifactsReconciliation", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:GetObject", Resource: reconciliationJournal },
      { Sid: "AllowReleaseDeployerConditionalStageAProductionArtifactsReconciliationCreate", Effect: "Allow", Principal: { AWS: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn }, Action: "s3:PutObject", Resource: reconciliationJournal, Condition: { StringEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyNonConditionalStageAProductionArtifactsReconciliationWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: reconciliationJournal, Condition: { StringNotEquals: { "s3:if-none-match": "*" } } },
      { Sid: "DenyOtherPrincipalsStageAProductionArtifactsReconciliationWrites", Effect: "Deny", Principal: "*", Action: "s3:PutObject", Resource: reconciliationJournal, Condition: { StringNotEquals: { "aws:PrincipalArn": PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn } } },
      { Sid: "DenyStageAProductionArtifactsReconciliationDeletion", Effect: "Deny", Principal: "*", Action: ["s3:DeleteObject", "s3:DeleteObjectVersion"], Resource: reconciliationJournal },
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
const stablePolicySha256 = (value) => createHash("sha256").update(stablePolicyJson(value)).digest("hex");
const stableJsonSha256 = (value) => createHash("sha256").update(stableJson(value)).digest("hex");
export const stageAProductionArtifactsPolicySha256 = stablePolicySha256;

export const STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY = Object.freeze({
  schemaVersion: 1,
  kind: "STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY_RECOVERY_COMPLETION",
  address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address,
  type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type,
  maxRefreshOnlyApplies: 1,
});

export const STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION = Object.freeze({
  schemaVersion: 1,
  kind: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION_AUTHORIZATION",
  maxRefreshOnlyApplies: 1,
});

const STAGE_A_RECOVERY_COMPLETION_FIELDS = Object.freeze([
  "schemaVersion", "kind", "sourceSha", "account", "region", "bucket", "address", "type",
  "recoveryAuthorizationSha256", "predecessorPolicySha256", "desiredPolicySha256",
  "livePolicySha256", "stateLineage", "preStateSerial", "preStateSha256", "completionSha256",
]);

export function createStageAProductionArtifactsRecoveryCompletion({ sourceSha, recoveryAuthorizationSha256, livePolicy, stateLineage = STAGE_A_STATE_LINEAGE, preStateSerial, preStateSha256 } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !SHA256.test(recoveryAuthorizationSha256 || "") || stateLineage !== STAGE_A_STATE_LINEAGE || !Number.isSafeInteger(preStateSerial) || preStateSerial < 1 || !SHA256.test(preStateSha256 || "") || stablePolicySha256(livePolicy) !== stablePolicySha256(buildStageAProductionArtifactsBucketPolicy())) throw new Error("Stage A production-artifacts recovery completion inputs are invalid.");
  const body = {
    schemaVersion: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY.schemaVersion,
    kind: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY.kind,
    sourceSha,
    account: STAGE_B.account,
    region: STAGE_B.region,
    bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket,
    address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address,
    type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type,
    recoveryAuthorizationSha256,
    predecessorPolicySha256: stablePolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()),
    desiredPolicySha256: stablePolicySha256(buildStageAProductionArtifactsBucketPolicy()),
    livePolicySha256: stablePolicySha256(livePolicy),
    stateLineage,
    preStateSerial,
    preStateSha256,
  };
  return Object.freeze({ ...body, completionSha256: stableJsonSha256(body) });
}

export function assertStageAProductionArtifactsRecoveryCompletion(completion, { sourceSha, stateLineage = STAGE_A_STATE_LINEAGE, preStateSerial, preStateSha256, verifyRecoveryCompletion } = {}) {
  if (!completion || typeof completion !== "object" || Array.isArray(completion) || JSON.stringify(Object.keys(completion).sort()) !== JSON.stringify([...STAGE_A_RECOVERY_COMPLETION_FIELDS].sort())) throw new Error("Stage A production-artifacts recovery completion schema is not exact.");
  if (completion.schemaVersion !== STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY.schemaVersion || completion.kind !== STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY.kind || completion.sourceSha !== sourceSha || completion.account !== STAGE_B.account || completion.region !== STAGE_B.region || completion.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket || completion.address !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address || completion.type !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type || completion.stateLineage !== stateLineage || completion.stateLineage !== STAGE_A_STATE_LINEAGE || completion.preStateSerial !== preStateSerial || completion.preStateSha256 !== preStateSha256 || !/^[a-f0-9]{40}$/.test(completion.sourceSha || "") || !SHA256.test(completion.recoveryAuthorizationSha256 || "") || !SHA256.test(completion.preStateSha256 || "") || completion.predecessorPolicySha256 !== stablePolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()) || completion.desiredPolicySha256 !== stablePolicySha256(buildStageAProductionArtifactsBucketPolicy()) || completion.livePolicySha256 !== completion.desiredPolicySha256 || !SHA256.test(completion.completionSha256 || "")) throw new Error("Stage A production-artifacts recovery completion binding is invalid.");
  const { completionSha256, ...body } = completion;
  if (stableJsonSha256(body) !== completionSha256) throw new Error("Stage A production-artifacts recovery completion hash is invalid.");
  if (typeof verifyRecoveryCompletion !== "function") throw new Error("Stage A production-artifacts recovery completion requires an independent verifier.");
  const verified = verifyRecoveryCompletion(completion);
  if (verified && typeof verified.then === "function") throw new Error("Stage A production-artifacts recovery completion verifier must be synchronous.");
  if (!verified || verified.authorizationSha256 !== completion.recoveryAuthorizationSha256 || verified.livePolicySha256 !== completion.livePolicySha256 || verified.completed !== true) throw new Error("Stage A production-artifacts recovery completion is not independently authenticated.");
  return completion;
}

const STAGE_A_RECONCILIATION_AUTHORIZATION_FIELDS = Object.freeze([
  "schemaVersion", "kind", "sourceSha", "account", "region", "bucket", "address", "type",
  "recoveryCompletionSha256", "savedPlanSha256", "predecessorPolicySha256", "desiredPolicySha256",
  "stateLineage", "preStateSerial", "preStateSha256", "maxRefreshOnlyApplies", "authorizationSha256",
]);

export function createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, recoverySourceSha, recoveryCompletion, savedPlanSha256, stateLineage = STAGE_A_STATE_LINEAGE, preStateSerial, preStateSha256, verifyRecoveryCompletion } = {}) {
  recoverySourceSha ||= recoveryCompletion?.sourceSha;
  assertStageAProductionArtifactsRecoveryCompletion(recoveryCompletion, { sourceSha: recoverySourceSha, stateLineage, preStateSerial, preStateSha256, verifyRecoveryCompletion });
  if (!SHA256.test(savedPlanSha256 || "")) throw new Error("Stage A production-artifacts reconciliation saved plan hash is invalid.");
  const body = {
    schemaVersion: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION.schemaVersion,
    kind: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION.kind,
    sourceSha,
    account: STAGE_B.account,
    region: STAGE_B.region,
    bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket,
    address: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address,
    type: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type,
    recoveryCompletionSha256: recoveryCompletion.completionSha256,
    savedPlanSha256,
    predecessorPolicySha256: stablePolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()),
    desiredPolicySha256: stablePolicySha256(buildStageAProductionArtifactsBucketPolicy()),
    stateLineage,
    preStateSerial,
    preStateSha256,
    maxRefreshOnlyApplies: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION.maxRefreshOnlyApplies,
  };
  return Object.freeze({ ...body, authorizationSha256: stableJsonSha256(body) });
}

export function assertStageAProductionArtifactsReconciliationAuthorization(authorization, { sourceSha, recoverySourceSha, recoveryCompletion, savedPlanSha256, stateLineage = STAGE_A_STATE_LINEAGE, preStateSerial, preStateSha256, verifyRecoveryCompletion, verifyReconciliationAuthorization } = {}) {
  recoverySourceSha ||= recoveryCompletion?.sourceSha;
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization) || JSON.stringify(Object.keys(authorization).sort()) !== JSON.stringify([...STAGE_A_RECONCILIATION_AUTHORIZATION_FIELDS].sort())) throw new Error("Stage A production-artifacts reconciliation authorization schema is not exact.");
  assertStageAProductionArtifactsRecoveryCompletion(recoveryCompletion, { sourceSha: recoverySourceSha, stateLineage, preStateSerial, preStateSha256, verifyRecoveryCompletion });
  if (authorization.schemaVersion !== STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION.schemaVersion || authorization.kind !== STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_AUTHORIZATION.kind || authorization.sourceSha !== sourceSha || authorization.account !== STAGE_B.account || authorization.region !== STAGE_B.region || authorization.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket || authorization.address !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address || authorization.type !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type || authorization.recoveryCompletionSha256 !== recoveryCompletion.completionSha256 || authorization.savedPlanSha256 !== savedPlanSha256 || !SHA256.test(authorization.savedPlanSha256 || "") || authorization.predecessorPolicySha256 !== stablePolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor()) || authorization.desiredPolicySha256 !== stablePolicySha256(buildStageAProductionArtifactsBucketPolicy()) || authorization.stateLineage !== stateLineage || authorization.stateLineage !== STAGE_A_STATE_LINEAGE || authorization.preStateSerial !== preStateSerial || authorization.preStateSha256 !== preStateSha256 || !SHA256.test(authorization.preStateSha256 || "") || authorization.maxRefreshOnlyApplies !== 1 || !SHA256.test(authorization.authorizationSha256 || "")) throw new Error("Stage A production-artifacts reconciliation authorization binding is invalid.");
  const { authorizationSha256, ...body } = authorization;
  if (stableJsonSha256(body) !== authorizationSha256) throw new Error("Stage A production-artifacts reconciliation authorization hash is invalid.");
  if (typeof verifyReconciliationAuthorization !== "function") throw new Error("Stage A production-artifacts reconciliation requires independent authorization.");
  const verified = verifyReconciliationAuthorization(authorization);
  if (verified && typeof verified.then === "function" || !verified || verified.authorizationSha256 !== authorization.authorizationSha256 || verified.approved !== true || verified.independent !== true) throw new Error("Stage A production-artifacts reconciliation authorization is not independently authenticated.");
  return authorization;
}

function assertStageAProductionArtifactsPolicyResource(value, label, expectedPolicy) {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...STAGE_A_POLICY_RESOURCE_KEYS].sort()) || value.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket || value.expected_bucket_owner !== null || value.id !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket || value.region !== STAGE_B.region || stablePolicySha256(decodePolicyDocument(value.policy, `${label} policy`)) !== stablePolicySha256(expectedPolicy)) throw new Error(`Stage A production-artifacts ${label} is not exact.`);
}

export function assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(plan, { sourceSha, recoverySourceSha, recoveryCompletion, stateLineage = STAGE_A_STATE_LINEAGE, preStateSerial, preStateSha256, verifyRecoveryCompletion } = {}) {
  recoverySourceSha ||= recoveryCompletion?.sourceSha;
  preStateSha256 ||= recoveryCompletion?.preStateSha256;
  assertStageAProductionArtifactsRecoveryCompletion(recoveryCompletion, { sourceSha: recoverySourceSha, stateLineage, preStateSerial, preStateSha256, verifyRecoveryCompletion });
  if (!plan || plan.complete !== true || plan.errored !== false || plan.applyable !== true || plan.resource_changes !== undefined && (!Array.isArray(plan.resource_changes) || plan.resource_changes.some(({ change } = {}) => !exactActions(change?.actions, ["no-op"]) && !exactActions(change?.actions, ["read"]))) || !Array.isArray(plan.resource_drift) || plan.resource_drift.length < 1 || plan.resource_drift.length > 2) throw new Error("Stage A production-artifacts refresh-only plan is not exact.");
  const bucketDrift = plan.resource_drift.filter(({ address }) => address === STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address);
  const rdsDrift = plan.resource_drift.filter(({ address }) => address === "aws_db_instance.green");
  if (bucketDrift.length !== 1 || rdsDrift.length > 1 || bucketDrift.length + rdsDrift.length !== plan.resource_drift.length) throw new Error("Stage A production-artifacts refresh-only plan contains uncontracted drift.");
  const entry = bucketDrift[0]; const change = entry.change;
  if (entry.mode !== "managed" || entry.type !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.type || entry.name !== "production_artifacts" || entry.provider_name !== "registry.terraform.io/hashicorp/aws" || !change || !exactActions(change.actions, ["update"]) || change.replace_paths?.length || !emptyObject(change.before_unknown) || !emptyObject(change.after_unknown) || !emptyObject(change.before_sensitive) || !emptyObject(change.after_sensitive)) throw new Error("Stage A production-artifacts refresh-only bucket drift is not exact.");
  assertStageAProductionArtifactsPolicyResource(change.before, "predecessor", buildStageAProductionArtifactsBucketPolicyPredecessor());
  assertStageAProductionArtifactsPolicyResource(change.after, "desired", buildStageAProductionArtifactsBucketPolicy());
  if (rdsDrift.length) assertStageARdsLatestRestorableTimeDrift(rdsDrift[0]);
  return Object.freeze({ valid: true, stateReconciliationRequired: true, address: entry.address, actions: change.actions, resourceDriftCount: plan.resource_drift.length, rdsLatestRestorableTimeRefreshed: rdsDrift.length === 1 });
}

function assertStageAProductionArtifactsAuthorizedPostState(state, plan) {
  if (!state || typeof state !== "object" || Array.isArray(state) || !Array.isArray(state.resources)) throw new Error("Stage A reconciliation post-state content is malformed.");
  for (const entry of plan.resource_drift) {
    const expected = entry.change.after;
    const expectedSchemaVersion = STAGE_A_LOCKED_AWS_RESOURCE_STATE_SCHEMA_VERSIONS[entry.address];
    const resources = state.resources.filter((resource) => resource?.module === undefined && resource?.mode === entry.mode && resource.type === entry.type && resource.name === entry.name && resource.provider === `provider[\"${entry.provider_name}\"]`);
    if (!Number.isSafeInteger(expectedSchemaVersion) || resources.length !== 1 || !Array.isArray(resources[0].instances) || resources[0].instances.length !== 1 || resources[0].instances[0]?.schema_version !== expectedSchemaVersion || resources[0].instances[0]?.index_key !== undefined) throw new Error("Stage A reconciliation post-state resource identity is not exact.");
    const actual = resources[0].instances[0].attributes;
    if (entry.address === STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.address) assertStageAProductionArtifactsPolicyResource(actual, "post-apply", buildStageAProductionArtifactsBucketPolicy());
    else if (entry.address === "aws_db_instance.green") { if (!isDeepStrictEqual(actual, expected)) throw new Error("Stage A reconciliation post-state RDS values are not the authorized refresh result."); }
    else throw new Error("Stage A reconciliation post-state contains an uncontracted resource.");
  }
  return true;
}

const STAGE_A_PREPARE_EVIDENCE_FIELDS = Object.freeze([
  "schemaVersion", "kind", "operation", "sourceSha", "account", "region", "executionPrincipal", "bucket",
  "recoveryAuthorizationSha256", "recoveryCompletionSha256", "desiredPolicySha256", "preStateLineage", "preStateSerial",
  "preStateSha256", "savedPlanSha256", "savedPlanByteLength", "terraformVersion", "awsProviderVersion", "terraformRoot", "prepareEvidenceSha256",
]);

export function createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, recoveryCompletion, saved, preState, awsProviderVersion = "6.56.0", terraformRoot = "infra/aws/terraform/production-green-stage-a" } = {}) {
  const terraformVersion = saved?.terraformVersion;
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !recoveryCompletion || !saved || saved.refreshOnly !== true || !preState
    || !SHA256.test(saved.savedPlanSha256 || "") || !Number.isSafeInteger(saved.savedPlanByteLength) || saved.savedPlanByteLength < 1
    || preState.lineage !== STAGE_A_STATE_LINEAGE || !Number.isSafeInteger(preState.serial) || preState.serial < 1 || !SHA256.test(preState.stateSha256 || "")
    || terraformVersion !== STAGE_A_TERRAFORM_VERSION || typeof awsProviderVersion !== "string" || !awsProviderVersion || typeof terraformRoot !== "string" || !terraformRoot) throw new Error("Stage A reconciliation prepare evidence inputs are invalid.");
  const body = {
    schemaVersion: 1, kind: "STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_PREPARE_EVIDENCE", operation: "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION", sourceSha,
    account: STAGE_B.account, region: STAGE_B.region, executionPrincipal: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn, bucket: STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket,
    recoveryAuthorizationSha256: recoveryCompletion.recoveryAuthorizationSha256, recoveryCompletionSha256: recoveryCompletion.completionSha256, desiredPolicySha256: recoveryCompletion.desiredPolicySha256,
    preStateLineage: preState.lineage, preStateSerial: preState.serial, preStateSha256: preState.stateSha256, savedPlanSha256: saved.savedPlanSha256, savedPlanByteLength: saved.savedPlanByteLength,
    terraformVersion, awsProviderVersion, terraformRoot,
  };
  return Object.freeze({ ...body, prepareEvidenceSha256: stableJsonSha256(body) });
}

export function assertStageAProductionArtifactsReconciliationPrepareEvidence(value, { sourceSha, recoveryCompletion, preState, savedPlanSha256, savedPlanByteLength, terraformRoot = "infra/aws/terraform/production-green-stage-a" } = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...STAGE_A_PREPARE_EVIDENCE_FIELDS].sort())) throw new Error("Stage A reconciliation prepare evidence schema is not exact.");
  if (value.schemaVersion !== 1 || value.kind !== "STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_PREPARE_EVIDENCE" || value.operation !== "STAGE_A_PRODUCTION_ARTIFACTS_STATE_RECONCILIATION" || value.sourceSha !== sourceSha || value.account !== STAGE_B.account || value.region !== STAGE_B.region || value.executionPrincipal !== PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn || value.bucket !== STAGE_A_PRODUCTION_ARTIFACTS_BUCKET_POLICY.bucket || value.recoveryAuthorizationSha256 !== recoveryCompletion?.recoveryAuthorizationSha256 || value.recoveryCompletionSha256 !== recoveryCompletion?.completionSha256 || value.desiredPolicySha256 !== recoveryCompletion?.desiredPolicySha256 || value.preStateLineage !== preState?.lineage || value.preStateSerial !== preState?.serial || value.preStateSha256 !== preState?.stateSha256 || value.savedPlanSha256 !== savedPlanSha256 || value.savedPlanByteLength !== savedPlanByteLength || value.terraformRoot !== terraformRoot || value.terraformVersion !== "1.15.8" || value.awsProviderVersion !== "6.56.0" || !SHA256.test(value.prepareEvidenceSha256 || "")) throw new Error("Stage A reconciliation prepare evidence binding is invalid.");
  const { prepareEvidenceSha256, ...body } = value;
  if (prepareEvidenceSha256 !== stableJsonSha256(body)) throw new Error("Stage A reconciliation prepare evidence hash is invalid.");
  return Object.freeze(value);
}

export async function prepareStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoverySourceSha, recoveryCompletion, verifyRecoveryCompletion, preState: expectedPreState, assertSourceIntegrity } = {}) {
  recoverySourceSha ||= recoveryCompletion?.sourceSha;
  if (!adapter || typeof adapter.createSavedRefreshOnlyPlan !== "function" || typeof adapter.readStateIdentity !== "function") throw new Error("Stage A production-artifacts preparation adapter is incomplete.");
  const preState = expectedPreState || await adapter.readStateIdentity();
  if (preState?.lineage !== STAGE_A_STATE_LINEAGE || !Number.isSafeInteger(preState.serial) || preState.serial < 1 || !SHA256.test(preState.stateSha256 || "")) throw new Error("Stage A reconciliation state identity is invalid.");
  assertStageAProductionArtifactsRecoveryCompletion(recoveryCompletion, { sourceSha: recoverySourceSha, preStateSerial: preState.serial, preStateSha256: preState.stateSha256, verifyRecoveryCompletion });
  if (assertSourceIntegrity !== undefined) { if (typeof assertSourceIntegrity !== "function") throw new Error("Stage A reconciliation source-integrity check is invalid."); assertSourceIntegrity(); }
  const saved = await adapter.createSavedRefreshOnlyPlan();
  if (saved?.preState?.lineage !== preState.lineage || saved?.preState?.serial !== preState.serial || saved?.preState?.stateSha256 !== preState.stateSha256 || saved?.sourceSha !== sourceSha || saved?.refreshOnly !== true || saved?.terraformVersion !== STAGE_A_TERRAFORM_VERSION || !path.isAbsolute(saved?.planPath || "") || !SHA256.test(saved?.savedPlanSha256 || "") || !Number.isSafeInteger(saved.savedPlanByteLength) || saved.savedPlanByteLength < 1) throw new Error("Stage A refresh-only plan is not source-, runtime-, or operation-bound.");
  assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(saved.plan, { sourceSha, recoverySourceSha, recoveryCompletion, preStateSerial: preState.serial, preStateSha256: preState.stateSha256, verifyRecoveryCompletion });
  const prepareEvidence = createStageAProductionArtifactsReconciliationPrepareEvidence({ sourceSha, recoveryCompletion, saved, preState });
  return Object.freeze({ preState, saved, prepareEvidence });
}
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
  const recoveryRequired = exactActions(change.actions, ["update"]);
  return {
    alreadyConverged: exactActions(change.actions, ["no-op"]),
    recoveryRequired,
    executionDisposition: recoveryRequired ? "RECOVERY_REQUIRED" : "ORDINARY_STAGE_A",
    mutationCount: exactActions(change.actions, ["create"]) || recoveryRequired ? 1 : 0,
  };
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

export async function runStageAProductionArtifactsStateReconciliation({ adapter, sourceSha, recoverySourceSha, recoveryCompletion, verifyRecoveryCompletion, reconciliationAuthorization, verifyReconciliationAuthorization, authorizationIdentity, recoveryCompletionSha256, reserveConsumption, finalizeConsumption, abortConsumption, recordPostApply, readConsumptionEvidence, saved, preparedState, resumeReservation, resumeResult, postApplyEvidence, assertSourceIntegrity } = {}) {
  recoverySourceSha ||= recoveryCompletion?.sourceSha;
  if (!adapter || typeof adapter.applySavedRefreshOnlyPlan !== "function" || typeof adapter.readStateIdentity !== "function" || typeof adapter.readProductionArtifactsPolicy !== "function" || typeof reserveConsumption !== "function" || typeof finalizeConsumption !== "function" || typeof abortConsumption !== "function" || typeof recordPostApply !== "function" || typeof readConsumptionEvidence !== "function" || !saved) throw new Error("Stage A production-artifacts reconciliation requires a prepared saved plan.");
  const currentState = await adapter.readStateIdentity();
  const before = preparedState || saved.preState || currentState;
  if (before?.lineage !== STAGE_A_STATE_LINEAGE || !Number.isSafeInteger(before.serial) || before.serial < 1 || !SHA256.test(before.stateSha256 || "")) throw new Error("Stage A reconciliation state identity is invalid.");
  if (!resumeReservation && (currentState.lineage !== before.lineage || currentState.serial !== before.serial || currentState.stateSha256 !== before.stateSha256)) throw new Error("Stage A prepared state identity changed before execution.");
  if (resumeResult && !resumeReservation) throw new Error("Stage A reconciliation completion result is missing its reservation.");
  const assertStateCas = (state, label) => {
    if (state?.lineage !== before.lineage || state.serial !== before.serial || state.stateSha256 !== before.stateSha256) throw new Error(`Stage A reconciliation state changed ${label}.`);
  };
  assertStageAProductionArtifactsRecoveryCompletion(recoveryCompletion, { sourceSha: recoverySourceSha, preStateSerial: before.serial, preStateSha256: before.stateSha256, verifyRecoveryCompletion });
  if (saved?.preState?.lineage !== before.lineage || saved?.preState?.serial !== before.serial || saved?.preState?.stateSha256 !== before.stateSha256 || saved?.sourceSha !== sourceSha || saved?.refreshOnly !== true || !path.isAbsolute(saved?.planPath || "") || !SHA256.test(saved?.savedPlanSha256 || "") || !Number.isSafeInteger(saved.savedPlanByteLength) || saved.savedPlanByteLength < 1) throw new Error("Stage A prepared refresh-only plan is not source- or operation-bound.");
  assertStageAProductionArtifactsRecoveryRefreshOnlyPlan(saved.plan, { sourceSha, recoverySourceSha, recoveryCompletion, preStateSerial: before.serial, preStateSha256: before.stateSha256, verifyRecoveryCompletion });
  assertStageAProductionArtifactsReconciliationAuthorization(reconciliationAuthorization, { sourceSha, recoverySourceSha, recoveryCompletion, savedPlanSha256: saved.savedPlanSha256, preStateSerial: before.serial, preStateSha256: before.stateSha256, verifyRecoveryCompletion, verifyReconciliationAuthorization });
  if (authorizationIdentity !== undefined && !SHA256.test(authorizationIdentity || "")) throw new Error("Stage A reconciliation governance authorization identity is invalid.");
  const consumption = { authorizationSha256: authorizationIdentity || reconciliationAuthorization.authorizationSha256, completionSha256: recoveryCompletionSha256 || recoveryCompletion.completionSha256, savedPlanSha256: saved.savedPlanSha256, preStateSha256: before.stateSha256 };
  const assertLivePolicyCas = (policy) => {
    const policySha256 = stablePolicySha256(policy);
    if (policySha256 !== recoveryCompletion.livePolicySha256 || policySha256 !== recoveryCompletion.desiredPolicySha256 || stablePolicyJson(policy) !== stablePolicyJson(buildStageAProductionArtifactsBucketPolicy())) throw new Error("Stage A production-artifacts live policy changed before refresh-only apply.");
  };
  const reservationValue = (value) => value?.reservation || value;
  const assertReservationIdentity = (value) => {
    const reservation = reservationValue(value);
    assertStageAProductionArtifactsReservation(reservation, { operation: STAGE_A_PRODUCTION_ARTIFACTS_RECONCILIATION_OPERATION, sourceSha, account: STAGE_B.account, region: STAGE_B.region, executionPrincipal: PRODUCTION_ACTIVATION_LIFECYCLE.releaseRoleArn, authorizationSha256: consumption.authorizationSha256, recoveryCompletionSha256: consumption.completionSha256, savedPlanSha256: consumption.savedPlanSha256, preStateLineage: before.lineage, preStateSerial: before.serial, preStateSha256: before.stateSha256, desiredPolicySha256: recoveryCompletion.desiredPolicySha256 });
    return reservation;
  };
  const exactPreState = (state) => state?.lineage === before.lineage && state.serial === before.serial && state.stateSha256 === before.stateSha256;
  const exactPostState = (state) => state?.lineage === before.lineage && state.serial === before.serial + 1 && SHA256.test(state?.stateSha256 || "");
  const readPostStateSnapshot = async (identity) => {
    if (typeof adapter.readStateSnapshot !== "function") throw new Error("Stage A reconciliation post-state authentication requires an authoritative state snapshot.");
    const snapshot = await adapter.readStateSnapshot();
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot) || snapshot.lineage !== identity.lineage || snapshot.serial !== identity.serial || snapshot.stateSha256 !== identity.stateSha256 || snapshot.state?.lineage !== identity.lineage || snapshot.state?.serial !== identity.serial) throw new Error("Stage A reconciliation post-state snapshot does not match the authenticated state identity.");
    return snapshot;
  };
  const assertPostEvidence = (evidence, reservation, state) => {
    assertStageAProductionArtifactsPostApplyEvidence(evidence, { reservation });
    if (evidence.postStateLineage !== state.lineage || evidence.postStateSerial !== state.serial || evidence.postStateSha256 !== state.stateSha256 || evidence.postLivePolicySha256 !== recoveryCompletion.desiredPolicySha256) throw new Error("Stage A reconciliation post-apply evidence does not match the authenticated post-state.");
  };
  const assertCompletedResult = (result, reservation, state) => {
    assertStageAProductionArtifactsJournalResult(result, { reservation });
    if (result.status !== "COMPLETED" || result.postStateLineage !== state.lineage || result.postStateSerial !== state.serial || result.postStateSha256 !== state.stateSha256 || result.postLivePolicySha256 !== recoveryCompletion.desiredPolicySha256) throw new Error("Stage A reconciliation completion result does not match the authenticated post-apply state.");
  };
  const readDurableConsumption = async () => {
    const durable = await readConsumptionEvidence(consumption.authorizationSha256);
    if (!durable || typeof durable !== "object" || Array.isArray(durable)) throw new Error("Stage A reconciliation durable consumption evidence is invalid.");
    return durable;
  };
  const completeExactPostState = async ({ state, snapshot, reservation: candidate, durable } = {}) => {
    if (!exactPostState(state)) throw new Error("Stage A reconciliation state serial did not advance exactly once.");
    if (!snapshot?.state) throw new Error("Stage A reconciliation post-state snapshot is missing.");
    assertStageAProductionArtifactsAuthorizedPostState(snapshot.state, saved.plan);
    const reservation = durable ? assertReservationIdentity(durable.reservation) : reservationValue(candidate);
    if (!reservation) throw new Error("Stage A reconciliation post-state lacks its immutable reservation.");
    const livePolicy = await adapter.readProductionArtifactsPolicy();
    assertLivePolicyCas(livePolicy);
    if (durable?.result) {
      assertCompletedResult(durable.result, reservation, state);
      return Object.freeze({ reservation, livePolicy, alreadyCompleted: true });
    }
    if (durable?.postApplyEvidence) assertPostEvidence(durable.postApplyEvidence, reservation, state);
    else await recordPostApply({ ...consumption, reservation: candidate || { reservation }, postState: state, postLivePolicySha256: stablePolicySha256(livePolicy) });
    await finalizeConsumption({ ...consumption, reservation: candidate || { reservation }, status: "COMPLETED", postState: state, postLivePolicySha256: stablePolicySha256(livePolicy) });
    return Object.freeze({ reservation, livePolicy, alreadyCompleted: false });
  };
  if (resumeReservation) {
    const reservation = assertReservationIdentity(resumeReservation);
    if (assertSourceIntegrity !== undefined) { if (typeof assertSourceIntegrity !== "function") throw new Error("Stage A reconciliation source-integrity check is invalid."); assertSourceIntegrity(); }
    const durable = { reservation, postApplyEvidence, result: resumeResult };
    if (exactPostState(currentState)) {
      const completed = await completeExactPostState({ state: currentState, snapshot: await readPostStateSnapshot(currentState), reservation, durable });
      return Object.freeze({ valid: true, applied: false, resumed: true, alreadyCompleted: completed.alreadyCompleted, refreshOnly: true, savedPlanSha256: saved.savedPlanSha256, preState: before, postState: currentState, livePolicySha256: stablePolicySha256(completed.livePolicy), awsResourceMutations: 0, terraformStateMutations: 0 });
    }
    const livePolicy = await adapter.readProductionArtifactsPolicy(); assertLivePolicyCas(livePolicy);
    if (!exactPreState(currentState) || postApplyEvidence || resumeResult) throw new Error("Stage A reconciliation completion-only resume state is neither the exact pre-state nor authenticated post-state.");
    await finalizeConsumption({ ...consumption, reservation: { reservation }, status: "FAILED_OR_INDETERMINATE" });
    throw new Error("Stage A reconciliation reserved execution did not persist the authorized state transition.");
  }
  const beforeReservation = await adapter.readStateIdentity();
  assertStateCas(beforeReservation, "after the refresh-only plan was saved");
  assertLivePolicyCas(await adapter.readProductionArtifactsPolicy());
  let reservation;
  let applyInvoked = false;
  let finalized = false;
  try {
    reservation = await reserveConsumption(consumption);
    if (!reservation || typeof reservation !== "object" || Array.isArray(reservation)) throw new Error("Stage A reconciliation consumption reservation is invalid.");
    if (assertSourceIntegrity !== undefined) { if (typeof assertSourceIntegrity !== "function") throw new Error("Stage A reconciliation source-integrity check is invalid."); assertSourceIntegrity(); }
    const beforeApply = await adapter.readStateIdentity();
    assertStateCas(beforeApply, "after exclusive reservation");
    assertStageAProductionArtifactsRecoveryCompletion(recoveryCompletion, { sourceSha: recoverySourceSha, preStateSerial: before.serial, preStateSha256: before.stateSha256, verifyRecoveryCompletion });
    assertStageAProductionArtifactsReconciliationAuthorization(reconciliationAuthorization, { sourceSha, recoverySourceSha, recoveryCompletion, savedPlanSha256: saved.savedPlanSha256, preStateSerial: before.serial, preStateSha256: before.stateSha256, verifyRecoveryCompletion, verifyReconciliationAuthorization });
    assertLivePolicyCas(await adapter.readProductionArtifactsPolicy());
    applyInvoked = true;
    let applyError;
    try { await adapter.applySavedRefreshOnlyPlan(saved); } catch (error) { applyError = error; }
    const after = await adapter.readStateIdentity();
    if (exactPostState(after)) {
      const durable = applyError ? await readDurableConsumption() : undefined;
      const completed = await completeExactPostState({ state: after, snapshot: await readPostStateSnapshot(after), reservation, durable });
      finalized = true;
      return Object.freeze({ valid: true, applied: true, applyProcessExitSuccess: !applyError, refreshOnly: true, savedPlanSha256: saved.savedPlanSha256, preState: before, postState: after, livePolicySha256: stablePolicySha256(completed.livePolicy), awsResourceMutations: 0, terraformStateMutations: 1 });
    }
    if (applyError && exactPreState(after)) {
      const durable = await readDurableConsumption();
      const persistedReservation = assertReservationIdentity(durable.reservation);
      const livePolicy = await adapter.readProductionArtifactsPolicy(); assertLivePolicyCas(livePolicy);
      if (durable.postApplyEvidence || durable.result) throw new Error("Stage A reconciliation exact pre-state conflicts with durable post-apply evidence.");
      await finalizeConsumption({ ...consumption, reservation: { reservation: persistedReservation }, status: "FAILED_OR_INDETERMINATE" });
      finalized = true;
      throw applyError;
    }
    if (applyError) throw new Error("Stage A reconciliation apply outcome is neither the exact pre-state nor authenticated post-state.", { cause: applyError });
    throw new Error("Stage A reconciliation state serial did not advance exactly once.");
  } catch (error) {
    if (reservation && !finalized) {
      if (!applyInvoked) await abortConsumption({ ...consumption, reservation, status: "ABORTED" });
    }
    throw error;
  }
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
  return { valid: true, changes: mutationCount, address: change.address, actions, checkerActions, checkerRoleActions: checkerRole[0].actions, checkerPublicationActions: checkerPublication[0].actions, alreadyConverged: exactActions(actions, ["no-op"]) && exactActions(checkerActions, ["no-op"]) && checkerRoleValidation.alreadyConverged && checkerPublicationValidation.alreadyConverged && artifactsBucketPolicyValidation.alreadyConverged, recoveryRequired: artifactsBucketPolicyValidation.recoveryRequired, executionDisposition: artifactsBucketPolicyValidation.recoveryRequired ? "RECOVERY_REQUIRED" : "ORDINARY_STAGE_A" };
}

export async function runStageAControlPlane({ adapter, endpointSecurityGroupId, runtimeSecurityGroupId, sourceSha } = {}) {
  if (!adapter || typeof adapter.createSavedPlan !== "function" || typeof adapter.applySavedPlan !== "function" || typeof adapter.describeIngress !== "function") throw new Error("Stage A control-plane adapter is incomplete.");
  const saved = await adapter.createSavedPlan();
  if (sourceSha && saved?.sourceSha !== sourceSha) throw new Error("Stage A saved plan is not bound to the protected-main source SHA.");
  if (!/^[a-f0-9]{64}$/.test(saved?.savedPlanSha256 || "")) throw new Error("Stage A saved plan bytes are not hash-bound.");
  const plan = saved?.plan;
  const validation = assertStageAPlan(plan, { endpointSecurityGroupId, runtimeSecurityGroupId });
  if (validation.recoveryRequired) throw new Error("Stage A production-artifacts bucket policy predecessor requires a separately governed recovery transition; ordinary release-deployer Terraform apply is forbidden.");
  if (!validation.alreadyConverged) await adapter.applySavedPlan(saved);
  const rule = await adapter.describeIngress({ endpointSecurityGroupId, runtimeSecurityGroupId, protocol: "tcp", fromPort: 443, toPort: 443 });
  if (rule?.present !== true) throw new Error("Stage A endpoint ingress postcondition is absent.");
  return { valid: true, ...validation, appliedExactSavedPlan: !validation.alreadyConverged, postconditionVerified: true, evidenceRef: saved.evidenceRef, evidenceSha256: saved.evidenceSha256, mutationCount: validation.changes };
}

export function createTerraformStageAAdapter({ terraform = "terraform", root = "infra/aws/terraform/production-green-stage-a", backendArgs = [], planPath, refreshOnlyPlanPath = `${planPath || ""}.refresh-only.tfplan`, stageAPlanSha256, run, describeIngress, readProductionArtifactsPolicy, sourceSha, region = "eu-west-2" } = {}) {
  if (typeof run !== "function" || typeof describeIngress !== "function" || !path.isAbsolute(planPath || "")) throw new Error("Stage A Terraform adapter is incomplete.");
  if (sourceSha && !/^[a-f0-9]{40}$/.test(sourceSha)) throw new Error("Stage A source SHA is invalid.");
  if (!/^[a-z]{2}-[a-z]+-[0-9]$/.test(region)) throw new Error("Stage A region is invalid.");
  if (!path.isAbsolute(refreshOnlyPlanPath) || path.resolve(refreshOnlyPlanPath) === path.resolve(planPath)) throw new Error("Stage A refresh-only plan path is incomplete or collides with the deployable plan.");
  let savedPlanSha256 = null;
  let savedRefreshOnlyPlanSha256 = null;
  let refreshOnlyApplyAttempted = false;
  let backendInitialization;
  let terraformVersionVerification;
  const readStateSnapshot = async () => {
    await ensureBackendInitialized();
    const bytes = Buffer.from(await run([terraform, `-chdir=${root}`, "state", "pull"]));
    const state = parseAuthenticatedStateBytes(bytes);
    return { state, lineage: state.lineage, serial: state.serial, stateSha256: createHash("sha256").update(bytes).digest("hex") };
  };
  const ensureTerraformRuntimeVersion = () => terraformVersionVerification ||= Promise.resolve(run([terraform, "version", "-json"])).then((output) => {
    let parsed; try { parsed = JSON.parse(output); } catch { throw new Error("Stage A Terraform runtime version output is malformed."); }
    if (parsed?.terraform_version !== STAGE_A_TERRAFORM_VERSION) throw new Error(`Stage A requires Terraform ${STAGE_A_TERRAFORM_VERSION}; observed ${parsed?.terraform_version || "unknown"}.`);
    return parsed.terraform_version;
  });
  const ensureBackendInitialized = () => backendInitialization ||= ensureTerraformRuntimeVersion().then(() => run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", ...backendArgs]));
  return {
    async createSavedPlan() {
      if (fs.existsSync(planPath)) {
        readAndVerifyPlanSha256(planPath, stageAPlanSha256);
        await run([terraform, `-chdir=${root}`, "init", "-upgrade=false", "-input=false", "-backend=false"]);
      } else {
        if (stageAPlanSha256 !== undefined) throw new Error("Stage A preserved plan is missing.");
        await ensureBackendInitialized();
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
    async createSavedRefreshOnlyPlan() {
      const terraformVersion = await ensureTerraformRuntimeVersion();
      await ensureBackendInitialized();
      const preState = await this.readStateIdentity();
      await run([terraform, `-chdir=${root}`, "plan", "-refresh-only", "-input=false", "-lock=true", "-no-color", "-out", refreshOnlyPlanPath]);
      const plan = JSON.parse(await run([terraform, `-chdir=${root}`, "show", "-json", refreshOnlyPlanPath]));
      const bytes = fs.readFileSync(refreshOnlyPlanPath);
      savedRefreshOnlyPlanSha256 = createHash("sha256").update(bytes).digest("hex");
      return { plan, planPath: refreshOnlyPlanPath, savedPlanSha256: savedRefreshOnlyPlanSha256, savedPlanByteLength: bytes.length, sourceSha, region, terraformRoot: root, terraformVersion, refreshOnly: true, preState, evidenceRef: `terraform-refresh-only:${refreshOnlyPlanPath}`, evidenceSha256: savedRefreshOnlyPlanSha256 };
    },
    async applySavedRefreshOnlyPlan(saved) {
      if (refreshOnlyApplyAttempted) throw new Error("Stage A refresh-only reconciliation has already been attempted.");
      if (!saved || saved.refreshOnly !== true || saved.planPath !== refreshOnlyPlanPath || saved.savedPlanSha256 !== savedRefreshOnlyPlanSha256) throw new Error("Stage A refresh-only saved plan changed after validation.");
      const currentSha256 = createHash("sha256").update(fs.readFileSync(refreshOnlyPlanPath)).digest("hex");
      if (currentSha256 !== savedRefreshOnlyPlanSha256) throw new Error("Stage A refresh-only saved plan changed after validation.");
      refreshOnlyApplyAttempted = true;
      await run([terraform, `-chdir=${root}`, "apply", "-input=false", refreshOnlyPlanPath]);
    },
    async readSavedRefreshOnlyPlan(planPath = refreshOnlyPlanPath) {
      if (planPath !== refreshOnlyPlanPath || !path.isAbsolute(planPath)) throw new Error("Stage A prepared refresh-only plan path is invalid.");
      await ensureBackendInitialized();
      const bytes = fs.readFileSync(planPath);
      savedRefreshOnlyPlanSha256 = createHash("sha256").update(bytes).digest("hex");
      return JSON.parse(await run([terraform, `-chdir=${root}`, "show", "-json", planPath]));
    },
    async readStateIdentity() {
      const { state, ...identity } = await readStateSnapshot();
      return identity;
    },
    readStateSnapshot,
    ...(typeof readProductionArtifactsPolicy === "function" ? { readProductionArtifactsPolicy } : {}),
    describeIngress,
  };
}
