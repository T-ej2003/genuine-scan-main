import crypto from "node:crypto";
import { assertStageARootDropKeyPolicyDocument } from "./production-stage-a-control-plane.mjs";

export const TEMPORARY_KMS_CAPABILITY_STATES = Object.freeze([
  "ABSENT",
  "AUTHORIZED_FOR_ROOT_DROP_CREATION",
  "STAGE_A_APPLY",
  "ROOT_DROP_OWNERSHIP_VERIFIED",
  "REVOKED",
  "ABSENCE_VERIFIED",
]);

export const TEMPORARY_KMS_CAPABILITY = Object.freeze({
  schemaVersion: 1,
  accountId: "368992683803",
  region: "eu-west-2",
  policyName: "MSCQRProductionGreenStageARelease",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageARelease",
  sourcePolicyPath: "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json",
  operation: "stage-a-root-drop-key-creation",
  action: "kms:TagResource",
  keyActions: Object.freeze(["kms:CreateKey", "kms:TagResource"]),
  administrationAction: "kms:PutKeyPolicy",
  aliasAction: "kms:CreateAlias",
  resource: "*",
  keyResource: "arn:aws:kms:eu-west-2:368992683803:key/*",
  aliasResource: "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-drop",
  tags: Object.freeze({ Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-a", Stack: "production-green-stage-a" }),
  keySpec: "RSA_3072",
  keyUsage: "SIGN_VERIFY",
});

export const AWS_MANAGED_POLICY_DOCUMENT_LIMIT = 6144;
export const TEMPORARY_POLICY_MIN_HEADROOM = 256;
export const TEMPORARY_POLICY_MAX_BYTES = AWS_MANAGED_POLICY_DOCUMENT_LIMIT - TEMPORARY_POLICY_MIN_HEADROOM;
export const IAM_STATEMENT_SID_MAX_LENGTH = 128;
export const IAM_STATEMENT_SID_PATTERN = /^[A-Za-z0-9]+$/;

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const VERSION = /^v[1-9][0-9]*$/;
const TEMPORARY_KMS_STATEMENT_SID_PREFIX = "TemporaryStageARootDropKeyTagAtCreation";
const canonical = (value) => Array.isArray(value)
  ? `[${value.map(canonical).join(",")}]`
  : value && typeof value === "object"
    ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const equal = (left, right) => canonical(left) === canonical(right);
const exactLegacyTagAction = (value) => value === TEMPORARY_KMS_CAPABILITY.action || (Array.isArray(value) && value.length === 1 && value[0] === TEMPORARY_KMS_CAPABILITY.action);
const withoutStatementIds = (policy) => ({ ...policy, Statement: statements(policy).map(({ Sid, ...statement }) => statement) });

export function policyDocumentBytes(policy) {
  return Buffer.byteLength(JSON.stringify(policy));
}

export function assertManagedPolicyDocumentSize(policy, { label = "IAM managed policy document" } = {}) {
  const bytes = policyDocumentBytes(policy);
  if (bytes > TEMPORARY_POLICY_MAX_BYTES) fail(`${label} is ${bytes} bytes; maximum is ${TEMPORARY_POLICY_MAX_BYTES} bytes to retain ${TEMPORARY_POLICY_MIN_HEADROOM} bytes of AWS policy-size headroom`);
  return bytes;
}

function fail(message) { throw new Error(`Temporary Stage-A KMS capability: ${message}`); }

export function canonicalTemporaryKmsStatementSid({ sourceSha, transitionId } = {}) {
  const suffix = sourceSha && transitionId ? `${sourceSha}${sha256(transitionId).slice(0, 32)}` : "";
  const sid = `${TEMPORARY_KMS_STATEMENT_SID_PREFIX}${suffix}`;
  if (sid.length > IAM_STATEMENT_SID_MAX_LENGTH || !IAM_STATEMENT_SID_PATTERN.test(sid)) fail("temporary KMS statement SID is not AWS-compatible");
  return sid;
}

function legacyTemporaryKmsStatementSid({ sourceSha, transitionId } = {}) {
  return sourceSha && transitionId ? `${TEMPORARY_KMS_STATEMENT_SID_PREFIX}_${sourceSha}_${sha256(transitionId).slice(0, 16)}` : TEMPORARY_KMS_STATEMENT_SID_PREFIX;
}

export function temporaryKmsCapabilityStatement({ sourceSha, transitionId } = {}) {
  return {
    Sid: canonicalTemporaryKmsStatementSid({ sourceSha, transitionId }),
    Effect: "Allow",
    Action: TEMPORARY_KMS_CAPABILITY.keyActions,
    Resource: TEMPORARY_KMS_CAPABILITY.resource,
    Condition: {
      StringEquals: {
        "aws:RequestedRegion": TEMPORARY_KMS_CAPABILITY.region,
        "aws:RequestTag/Environment": TEMPORARY_KMS_CAPABILITY.tags.Environment,
        "aws:RequestTag/ManagedBy": TEMPORARY_KMS_CAPABILITY.tags.ManagedBy,
        "aws:RequestTag/Component": TEMPORARY_KMS_CAPABILITY.tags.Component,
        "aws:RequestTag/Stack": TEMPORARY_KMS_CAPABILITY.tags.Stack,
        "kms:CallerAccount": TEMPORARY_KMS_CAPABILITY.accountId,
        "kms:KeySpec": TEMPORARY_KMS_CAPABILITY.keySpec,
        "kms:KeyUsage": TEMPORARY_KMS_CAPABILITY.keyUsage,
      },
      "ForAllValues:StringEquals": { "aws:TagKeys": Object.keys(TEMPORARY_KMS_CAPABILITY.tags) },
    },
  };
}

export function temporaryKmsCapabilityAliasStatement({ sourceSha, transitionId } = {}) {
  return {
    Effect: "Allow",
    Action: TEMPORARY_KMS_CAPABILITY.aliasAction,
    Resource: TEMPORARY_KMS_CAPABILITY.aliasResource,
  };
}

export function temporaryKmsCapabilityAliasKeyStatement() {
  return {
    Effect: "Allow",
    Action: [TEMPORARY_KMS_CAPABILITY.aliasAction, TEMPORARY_KMS_CAPABILITY.administrationAction],
    Resource: TEMPORARY_KMS_CAPABILITY.keyResource,
    Condition: {
      StringEquals: {
        "aws:ResourceTag/Environment": TEMPORARY_KMS_CAPABILITY.tags.Environment,
        "aws:ResourceTag/ManagedBy": TEMPORARY_KMS_CAPABILITY.tags.ManagedBy,
        "aws:ResourceTag/Component": TEMPORARY_KMS_CAPABILITY.tags.Component,
        "aws:ResourceTag/Stack": TEMPORARY_KMS_CAPABILITY.tags.Stack,
        "kms:KeySpec": TEMPORARY_KMS_CAPABILITY.keySpec,
        "kms:KeyUsage": TEMPORARY_KMS_CAPABILITY.keyUsage,
      },
    },
  };
}

function statements(policy) {
  if (!policy || policy.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) fail("policy document is malformed");
  return policy.Statement;
}

export function assertSteadyStateReleasePolicy(policy) {
  for (const statement of statements(policy)) {
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    if (actions.some((action) => TEMPORARY_KMS_CAPABILITY.keyActions.includes(action) || action === TEMPORARY_KMS_CAPABILITY.administrationAction || action === TEMPORARY_KMS_CAPABILITY.aliasAction || action === "kms:*")) fail("steady-state policy retains temporary KMS capability");
  }
  return true;
}

export function buildTemporaryReleasePolicy(steadyStatePolicy, identity) {
  assertSteadyStateReleasePolicy(steadyStatePolicy);
  const compactSteadyState = withoutStatementIds(structuredClone(steadyStatePolicy));
  const policy = { ...compactSteadyState, Statement: [...compactSteadyState.Statement, temporaryKmsCapabilityStatement(identity), temporaryKmsCapabilityAliasStatement(identity), temporaryKmsCapabilityAliasKeyStatement()] };
  assertManagedPolicyDocumentSize(policy, { label: "Temporary Stage-A KMS policy" });
  return policy;
}

export function assertTemporaryReleasePolicy(policy, { steadyStatePolicy, sourceSha, transitionId, allowLegacyTemporary = true } = {}) {
  if (!steadyStatePolicy) fail("steady-state source policy is required");
  assertSteadyStateReleasePolicy(steadyStatePolicy);
  const temporary = statements(policy).filter(isTemporaryTagResourceStatement);
  const expected = [temporaryKmsCapabilityStatement({ sourceSha, transitionId }), temporaryKmsCapabilityAliasStatement({ sourceSha, transitionId }), temporaryKmsCapabilityAliasKeyStatement()];
  const legacyKey = { ...expected[0], Sid: legacyTemporaryKmsStatementSid({ sourceSha, transitionId }) };
  const legacyTag = { ...legacyKey, Action: TEMPORARY_KMS_CAPABILITY.action };
  const exactCurrent = temporary.length === expected.length
    && temporary.some((statement) => equal(statement, expected[0]) || equal(statement, legacyKey))
    && expected.slice(1).every((candidate) => temporary.some((statement) => equal(statement, candidate)));
  const priorCurrent = [expected[0], expected[1], { ...expected[2], Action: TEMPORARY_KMS_CAPABILITY.aliasAction }];
  const exactPriorCurrent = temporary.length === priorCurrent.length
    && temporary.some((statement) => equal(statement, priorCurrent[0]) || equal(statement, legacyKey))
    && priorCurrent.slice(1).every((candidate) => temporary.some((statement) => equal(statement, candidate)));
  const exactLegacy = temporary.length === 1 && equal(temporary[0], legacyTag);
  if (!exactCurrent && !(allowLegacyTemporary && (exactPriorCurrent || exactLegacy))) fail("temporary policy statements are not exact");
  const withoutTemporary = statements(policy).filter((statement) => !isTemporaryTagResourceStatement(statement));
  if (!equal(withoutStatementIds({ ...policy, Statement: withoutTemporary }), withoutStatementIds(steadyStatePolicy))) fail("temporary policy changes more than the exact creation capability");
  if (statements(policy).some((statement) => (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).some((action) => ["kms:Sign", "kms:Decrypt", "kms:Encrypt", "kms:CreateGrant", "kms:ScheduleKeyDeletion", "kms:DisableKey"].includes(action)))) fail("temporary policy grants an unrelated KMS capability");
  assertManagedPolicyDocumentSize(policy, { label: "Temporary Stage-A KMS policy" });
  return true;
}

export function isCurrentTemporaryReleasePolicy(policy, { steadyStatePolicy, sourceSha, transitionId } = {}) {
  try {
    assertTemporaryReleasePolicy(policy, { steadyStatePolicy, sourceSha, transitionId, allowLegacyTemporary: false });
    return true;
  } catch {
    return false;
  }
}

export function buildTemporaryCapabilityEvidence(fields = {}) {
  const value = {
    schemaVersion: TEMPORARY_KMS_CAPABILITY.schemaVersion,
    kind: "MSCQR_TEMPORARY_STAGE_A_KMS_CAPABILITY",
    state: fields.state,
    sourceSha: fields.sourceSha,
    transitionId: fields.transitionId,
    policyArn: TEMPORARY_KMS_CAPABILITY.policyArn,
    policyName: TEMPORARY_KMS_CAPABILITY.policyName,
    accountId: TEMPORARY_KMS_CAPABILITY.accountId,
    region: TEMPORARY_KMS_CAPABILITY.region,
    operation: TEMPORARY_KMS_CAPABILITY.operation,
    action: TEMPORARY_KMS_CAPABILITY.action,
    actions: [...TEMPORARY_KMS_CAPABILITY.keyActions, TEMPORARY_KMS_CAPABILITY.administrationAction, TEMPORARY_KMS_CAPABILITY.aliasAction],
    ...(fields.stageAStateIdentity === undefined ? {} : { stageAStateIdentity: fields.stageAStateIdentity }),
    defaultVersionId: fields.defaultVersionId ?? null,
    temporaryVersionId: fields.temporaryVersionId ?? null,
    planSha256: fields.planSha256 ?? null,
    ownership: fields.ownership ?? null,
    observedAt: fields.observedAt,
  };
  if (!SHA40.test(value.sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(value.transitionId || "") || !value.observedAt) fail("evidence identity is incomplete");
  return { ...value, evidenceSha256: sha256(canonical(value)) };
}

export function assertTemporaryCapabilityEvidence(value, { sourceSha, state } = {}) {
  if (!value || value.schemaVersion !== 1 || value.kind !== "MSCQR_TEMPORARY_STAGE_A_KMS_CAPABILITY" || value.state !== state || value.sourceSha !== sourceSha) fail("evidence identity or state is wrong");
  const currentActions = [...TEMPORARY_KMS_CAPABILITY.keyActions, TEMPORARY_KMS_CAPABILITY.administrationAction, TEMPORARY_KMS_CAPABILITY.aliasAction];
  const priorActions = [...TEMPORARY_KMS_CAPABILITY.keyActions, TEMPORARY_KMS_CAPABILITY.aliasAction];
  if (!SHA40.test(value.sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(value.transitionId || "") || value.policyArn !== TEMPORARY_KMS_CAPABILITY.policyArn || value.policyName !== TEMPORARY_KMS_CAPABILITY.policyName || value.accountId !== TEMPORARY_KMS_CAPABILITY.accountId || value.region !== TEMPORARY_KMS_CAPABILITY.region || value.operation !== TEMPORARY_KMS_CAPABILITY.operation || value.action !== TEMPORARY_KMS_CAPABILITY.action || (value.actions !== undefined && !equal(value.actions, currentActions) && !equal(value.actions, priorActions)) || !SHA256.test(value.evidenceSha256 || "")) fail("evidence fields are not exact");
  const { evidenceSha256, ...unsigned } = value;
  if (sha256(canonical(unsigned)) !== evidenceSha256) fail("evidence integrity hash is wrong");
  if (state === "AUTHORIZED_FOR_ROOT_DROP_CREATION" && (!VERSION.test(value.temporaryVersionId || "") || !SHA256.test(value.planSha256 || ""))) fail("authorized evidence lacks the exact Stage-A plan binding");
  if (state === "STAGE_A_APPLY" && (!VERSION.test(value.temporaryVersionId || "") || !SHA256.test(value.planSha256 || ""))) fail("Stage-A apply evidence is incomplete");
  if (state === "ROOT_DROP_OWNERSHIP_VERIFIED" && (!SHA256.test(value.planSha256 || "") || value.ownership?.keyOwned !== true || value.ownership?.aliasOwned !== true || value.ownership?.aliasResolves !== true)) fail("root-drop ownership evidence is incomplete");
  if (["REVOKED", "ABSENCE_VERIFIED"].includes(state) && (value.temporaryVersionId !== null || !VERSION.test(value.defaultVersionId || ""))) fail("revoked evidence retains a temporary version or lacks the active steady-state version");
  return true;
}

export function assertTemporaryCapabilityTransition(previous, next, { sourceSha, evidence } = {}) {
  const allowed = {
    ABSENT: ["AUTHORIZED_FOR_ROOT_DROP_CREATION"],
    AUTHORIZED_FOR_ROOT_DROP_CREATION: ["STAGE_A_APPLY", "REVOKED"],
    STAGE_A_APPLY: ["ROOT_DROP_OWNERSHIP_VERIFIED", "REVOKED"],
    ROOT_DROP_OWNERSHIP_VERIFIED: ["REVOKED"],
    REVOKED: ["ABSENCE_VERIFIED"],
    ABSENCE_VERIFIED: ["ABSENCE_VERIFIED"],
  };
  if (!TEMPORARY_KMS_CAPABILITY_STATES.includes(previous) || !allowed[previous]?.includes(next)) fail(`invalid transition ${previous} -> ${next}`);
  if (next === "ABSENCE_VERIFIED") assertTemporaryCapabilityEvidence(evidence, { sourceSha, state: next });
  return true;
}

export function buildRootDropOwnershipEvidence({ terraformState, sourceSha, transitionId, planSha256, observedAt } = {}) {
  const resources = terraformState?.resources;
  if (!Array.isArray(resources)) fail("Terraform state resources are required for root-drop ownership evidence");
  const key = resources.find(({ address }) => address === "aws_kms_key.root_drop");
  const alias = resources.find(({ address }) => address === "aws_kms_alias.root_drop");
  if (key?.type !== "aws_kms_key" || !Array.isArray(key.instances) || key.instances.length !== 1 || alias?.type !== "aws_kms_alias" || !Array.isArray(alias.instances) || alias.instances.length !== 1) fail("exact Terraform-owned root-drop key and alias instances are required");
  const keyId = key.instances[0]?.attributes?.id;
  const aliasTarget = alias.instances[0]?.attributes?.target_key_id;
  if (typeof keyId !== "string" || keyId.length === 0 || aliasTarget !== keyId) fail("root-drop alias does not resolve to the Terraform-owned key");
  const value = {
    schemaVersion: 1,
    kind: "MSCQR_ROOT_DROP_TERRAFORM_OWNERSHIP",
    sourceSha,
    transitionId,
    planSha256,
    keyAddress: "aws_kms_key.root_drop",
    aliasAddress: "aws_kms_alias.root_drop",
    keyId,
    keyOwned: true,
    aliasOwned: true,
    aliasResolves: true,
    observedAt,
  };
  if (!SHA40.test(sourceSha || "") || !SHA256.test(planSha256 || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(transitionId || "") || !observedAt) fail("root-drop ownership evidence identity is incomplete");
  return { ...value, evidenceSha256: sha256(canonical(value)) };
}

export function assertRootDropOwnershipEvidence(value, { sourceSha, planSha256 } = {}) {
  if (!value || value.schemaVersion !== 1 || value.kind !== "MSCQR_ROOT_DROP_TERRAFORM_OWNERSHIP" || value.sourceSha !== sourceSha || value.planSha256 !== planSha256 || value.keyAddress !== "aws_kms_key.root_drop" || value.aliasAddress !== "aws_kms_alias.root_drop" || value.keyOwned !== true || value.aliasOwned !== true || value.aliasResolves !== true || typeof value.keyId !== "string" || !SHA256.test(value.evidenceSha256 || "")) fail("root-drop ownership evidence is not exact");
  const { evidenceSha256, ...unsigned } = value;
  if (sha256(canonical(unsigned)) !== evidenceSha256) fail("root-drop ownership evidence integrity is wrong");
  return true;
}

export function assertStageARootDropCreationPlan(plan) {
  const changes = plan?.resource_changes;
  if (!Array.isArray(changes)) fail("machine-readable Stage-A plan is required");
  const actionable = changes.filter(({ change }) => JSON.stringify(change?.actions || []) !== JSON.stringify(["no-op"]));
  const expected = new Set(["aws_kms_key.root_drop", "aws_kms_alias.root_drop"]);
  if (actionable.length !== 2 || new Set(actionable.map(({ address }) => address)).size !== 2 || actionable.some(({ address, change }) => !expected.has(address) || JSON.stringify(change?.actions || []) !== JSON.stringify(["create"]))) fail("Stage-A plan is not the exact two-resource root-drop creation envelope");
  const key = actionable.find(({ address }) => address === "aws_kms_key.root_drop");
  const alias = actionable.find(({ address }) => address === "aws_kms_alias.root_drop");
  let keyPolicy;
  try { keyPolicy = JSON.parse(key.change.after?.policy); } catch { fail("Stage-A root-drop key policy is missing or malformed"); }
  assertStageARootDropKeyPolicyDocument(keyPolicy);
  if (key.change.after?.customer_master_key_spec !== TEMPORARY_KMS_CAPABILITY.keySpec || key.change.after?.key_usage !== TEMPORARY_KMS_CAPABILITY.keyUsage || key.change.after?.bypass_policy_lockout_safety_check !== false) fail("Stage-A root-drop key creation attributes are not exact");
  if (alias.change.after?.name !== "alias/mscqr-production-root-drop") fail("Stage-A root-drop alias creation attributes are not exact");
  return true;
}

export function assertPreCutoverTemporaryCapabilityAbsent(value, { sourceSha } = {}) {
  assertTemporaryCapabilityEvidence(value, { sourceSha, state: "ABSENCE_VERIFIED" });
  return true;
}

export const isTemporaryTagResourceStatement = (statement) => {
  if (typeof statement?.Sid === "string" && statement.Sid.startsWith(TEMPORARY_KMS_STATEMENT_SID_PREFIX)) return equal(statement.Action, TEMPORARY_KMS_CAPABILITY.keyActions) || exactLegacyTagAction(statement.Action);
  const actions = Array.isArray(statement?.Action) ? statement.Action : [statement?.Action];
  return (actions.includes(TEMPORARY_KMS_CAPABILITY.aliasAction) || actions.includes(TEMPORARY_KMS_CAPABILITY.administrationAction))
    && (statement.Resource === TEMPORARY_KMS_CAPABILITY.aliasResource || statement.Resource === TEMPORARY_KMS_CAPABILITY.keyResource);
};
