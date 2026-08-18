import crypto from "node:crypto";

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
  resource: "*",
  tags: Object.freeze({ Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-a", Stack: "production-green-stage-a" }),
  keySpec: "RSA_3072",
  keyUsage: "SIGN_VERIFY",
});

export const AWS_MANAGED_POLICY_DOCUMENT_LIMIT = 6144;
export const TEMPORARY_POLICY_MIN_HEADROOM = 512;
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
const exactAction = (value) => value === TEMPORARY_KMS_CAPABILITY.action || (Array.isArray(value) && value.length === 1 && value[0] === TEMPORARY_KMS_CAPABILITY.action);
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
    Action: TEMPORARY_KMS_CAPABILITY.action,
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

function statements(policy) {
  if (!policy || policy.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) fail("policy document is malformed");
  return policy.Statement;
}

export function assertSteadyStateReleasePolicy(policy) {
  for (const statement of statements(policy)) {
    const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
    if (actions.includes(TEMPORARY_KMS_CAPABILITY.action) || actions.includes("kms:*")) fail("steady-state policy retains KMS tagging capability");
  }
  return true;
}

export function buildTemporaryReleasePolicy(steadyStatePolicy, identity) {
  assertSteadyStateReleasePolicy(steadyStatePolicy);
  const compactSteadyState = withoutStatementIds(structuredClone(steadyStatePolicy));
  const policy = { ...compactSteadyState, Statement: [...compactSteadyState.Statement, temporaryKmsCapabilityStatement(identity)] };
  assertManagedPolicyDocumentSize(policy, { label: "Temporary Stage-A KMS policy" });
  return policy;
}

export function assertTemporaryReleasePolicy(policy, { steadyStatePolicy, sourceSha, transitionId } = {}) {
  if (!steadyStatePolicy) fail("steady-state source policy is required");
  assertSteadyStateReleasePolicy(steadyStatePolicy);
  const temporary = statements(policy).filter(isTemporaryTagResourceStatement);
  const expected = temporaryKmsCapabilityStatement({ sourceSha, transitionId });
  const legacy = { ...expected, Sid: legacyTemporaryKmsStatementSid({ sourceSha, transitionId }) };
  if (temporary.length !== 1 || ![expected, legacy].some((candidate) => equal(temporary[0], candidate))) fail("temporary policy statement is not exact");
  const withoutTemporary = statements(policy).filter((statement) => !isTemporaryTagResourceStatement(statement));
  if (!equal(withoutStatementIds({ ...policy, Statement: withoutTemporary }), withoutStatementIds(steadyStatePolicy))) fail("temporary policy changes more than the exact creation capability");
  if (statements(policy).some((statement) => (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).some((action) => ["kms:Sign", "kms:Decrypt", "kms:Encrypt", "kms:CreateGrant", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey"].includes(action)))) fail("temporary policy grants an unrelated KMS capability");
  assertManagedPolicyDocumentSize(policy, { label: "Temporary Stage-A KMS policy" });
  return true;
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
  if (!SHA40.test(value.sourceSha || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(value.transitionId || "") || value.policyArn !== TEMPORARY_KMS_CAPABILITY.policyArn || value.policyName !== TEMPORARY_KMS_CAPABILITY.policyName || value.accountId !== TEMPORARY_KMS_CAPABILITY.accountId || value.region !== TEMPORARY_KMS_CAPABILITY.region || value.operation !== TEMPORARY_KMS_CAPABILITY.operation || value.action !== TEMPORARY_KMS_CAPABILITY.action || !SHA256.test(value.evidenceSha256 || "")) fail("evidence fields are not exact");
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
  return true;
}

export function assertPreCutoverTemporaryCapabilityAbsent(value, { sourceSha } = {}) {
  assertTemporaryCapabilityEvidence(value, { sourceSha, state: "ABSENCE_VERIFIED" });
  return true;
}

export const isTemporaryTagResourceStatement = (statement) => typeof statement?.Sid === "string" && statement.Sid.startsWith("TemporaryStageARootDropKeyTagAtCreation") && exactAction(statement.Action);
