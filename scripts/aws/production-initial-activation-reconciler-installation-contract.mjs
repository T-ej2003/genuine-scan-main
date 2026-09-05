import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { INITIAL_ACTIVATION_RECONCILER } from "./verify-production-initial-activation-policy-reconciler.mjs";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentApprovalIdentity } from "./production-github-environment-approval.mjs";

export const INSTALLATION = Object.freeze({
  schemaVersion: 1,
  kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION",
  operation: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION",
  repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
  environment: "production",
  region: "eu-west-2",
  administratorArn: "arn:aws:iam::368992683803:root",
  terraformRoot: "infra/aws/terraform/production-initial-activation-policy-reconciler",
  backend: Object.freeze({ bucket: "mscqr-production-terraform-state-368992683803-eu-west-2", key: "mscqr/production/initial-activation-policy-reconciler/terraform.tfstate", lockKey: "mscqr/production/initial-activation-policy-reconciler/terraform.tfstate.tflock" }),
  roleArn: INITIAL_ACTIVATION_RECONCILER.roleArn,
  policyArn: INITIAL_ACTIVATION_RECONCILER.policyArn,
  expectedAddresses: Object.freeze(["aws_iam_role.reconciler", "aws_iam_policy.reconciler", "aws_iam_role_policy_attachment.reconciler"]),
  maxAwsMutations: Object.freeze({ "iam:CreateRole": 1, "iam:CreatePolicy": 1, "iam:AttachRolePolicy": 1, "iam:UpdateAssumeRolePolicy": 0, "iam:PutRolePolicy": 0, "iam:CreatePolicyVersion": 0 }),
});

export const INSTALLATION_BACKEND = Object.freeze({ type: "s3", bucket: INSTALLATION.backend.bucket, key: INSTALLATION.backend.key, region: INSTALLATION.region, use_lockfile: true, workspace: "default" });

const SHA256 = /^[a-f0-9]{64}$/;
const SHA40 = /^[a-f0-9]{40}$/;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const read = (file) => fs.readFileSync(file);
const sourceRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const sourceFile = (relative) => path.join(sourceRoot, relative);
const sourceJson = (relative) => JSON.parse(read(sourceFile(relative)));
const sourceHashes = () => Object.freeze({
  trustPolicySha256: sha256(read(sourceFile(`${INSTALLATION.terraformRoot}/trust-policy.json`))),
  permissionsPolicySha256: sha256(read(sourceFile(`${INSTALLATION.terraformRoot}/permissions-policy.json`))),
  installationContractSha256: sha256(read(sourceFile(`${INSTALLATION.terraformRoot}/installation-contract.json`))),
  backendContractSha256: sha256(read(sourceFile(`${INSTALLATION.terraformRoot}/state-backend-contract.json`))),
});

export const canonicalSha256 = (value) => sha256(Buffer.from(canonicalJson(value)));
const exactFields = (value, fields, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((field) => !fields.has(field)) || Object.keys(value).length !== fields.size) throw new Error(`${label} fields are not exact.`);
};
const text = (value, label) => { if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is required.`); return value.trim(); };
const sha = (value, label) => { if (!SHA256.test(value || "")) throw new Error(`${label} must be a SHA-256 digest.`); return value; };
const policyValue = (value, label) => {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    return parsed;
  } catch { throw new Error(`${label} is not a valid IAM policy document.`); }
};

export function assertInstallationInitializedBackendMetadata(metadata) {
  const backend = metadata?.backend || metadata;
  if (!backend || typeof backend !== "object" || Array.isArray(backend) || backend.type !== INSTALLATION_BACKEND.type || !backend.config || typeof backend.config !== "object" || Array.isArray(backend.config)) throw new Error("Installation initialized backend metadata is malformed.");
  const config = backend.config;
  const allowed = new Set(["access_key", "acl", "allowed_account_ids", "assume_role", "assume_role_with_web_identity", "bucket", "custom_ca_bundle", "dynamodb_endpoint", "dynamodb_table", "ec2_metadata_service_endpoint", "ec2_metadata_service_endpoint_mode", "encrypt", "endpoint", "endpoints", "forbidden_account_ids", "force_path_style", "http_proxy", "https_proxy", "iam_endpoint", "insecure", "key", "kms_key_id", "max_retries", "no_proxy", "profile", "region", "retry_mode", "secret_key", "shared_config_files", "shared_credentials_file", "shared_credentials_files", "skip_credentials_validation", "skip_metadata_api_check", "skip_region_validation", "skip_s3_checksum", "sse_customer_key", "sts_endpoint", "sts_region", "token", "use_dualstack_endpoint", "use_fips_endpoint", "use_lockfile", "use_path_style", "workspace_key_prefix"]);
  const unknown = Object.keys(config).find((key) => !allowed.has(key));
  if (unknown) throw new Error(`Installation initialized backend has unreviewed key: ${unknown}.`);
  if (config.bucket !== INSTALLATION_BACKEND.bucket || config.key !== INSTALLATION_BACKEND.key || config.region !== INSTALLATION_BACKEND.region || config.use_lockfile !== true) throw new Error("Installation initialized backend is not exact.");
  const defaultFalse = new Set(["encrypt", "force_path_style", "use_path_style"]);
  for (const key of [...allowed].filter((candidate) => !["bucket", "key", "region", "use_lockfile"].includes(candidate))) {
    if (config[key] !== undefined && config[key] !== null && config[key] !== "" && !(defaultFalse.has(key) && config[key] === false)) throw new Error(`Installation initialized backend ${key} must use the Terraform default.`);
  }
  return true;
}

export function classifyInstallationStatePullError(error) {
  const messages = [error?.stderr, error?.message].filter((value) => value !== undefined && value !== null).map(String).map((value) => value.trim());
  if (messages.some((message) => /^No state file was found!?$/i.test(message) || /^Error:\s*No state file was found!?$/i.test(message))) return undefined;
  throw error;
}

export function assertInstallationPlan(plan, { expectedAddresses = INSTALLATION.expectedAddresses } = {}) {
  if (!plan || typeof plan !== "object" || !Array.isArray(plan.resource_changes)) throw new Error("Installation Terraform plan JSON is malformed.");
  const changes = plan.resource_changes;
  if (changes.length > expectedAddresses.length) throw new Error("Installation plan resource count is not exact.");
  const addresses = changes.map((entry) => entry?.address);
  if (new Set(addresses).size !== addresses.length || addresses.some((address) => !expectedAddresses.includes(address))) throw new Error("Installation plan contains an unreviewed or duplicate resource address.");
  for (const entry of changes) {
    if (entry.mode !== "managed" || !Array.isArray(entry.change?.actions) || JSON.stringify(entry.change.actions) !== JSON.stringify(["create"])) throw new Error("Installation plan contains an unreviewed resource action.");
    if (!["aws_iam_role", "aws_iam_policy", "aws_iam_role_policy_attachment"].includes(entry.type)) throw new Error("Installation plan contains an unreviewed resource type.");
    if (entry.change.before !== null) throw new Error("Installation plan is not bound to the absent predecessor.");
    const after = entry.change.after;
    if (!after || typeof after !== "object" || Array.isArray(after)) throw new Error("Installation plan resource values are missing.");
    if (entry.address === "aws_iam_role.reconciler") {
      if (after.name !== "mscqr-production-initial-activation-policy-reconciler" || after.max_session_duration !== 3600 || Object.hasOwn(after, "permissions_boundary") && after.permissions_boundary !== null || canonicalJson(policyValue(after.assume_role_policy, "Installation plan trust policy")) !== canonicalJson(sourceJson(`${INSTALLATION.terraformRoot}/trust-policy.json`))) throw new Error("Installation plan role contract is not exact.");
    } else if (entry.address === "aws_iam_policy.reconciler") {
      if (after.name !== "MSCQRProductionInitialActivationPolicyReconciler" || canonicalJson(policyValue(after.policy, "Installation plan permissions policy")) !== canonicalJson(sourceJson(`${INSTALLATION.terraformRoot}/permissions-policy.json`))) throw new Error("Installation plan policy contract is not exact.");
    } else if (entry.address === "aws_iam_role_policy_attachment.reconciler" && (after.role !== "mscqr-production-initial-activation-policy-reconciler" || after.policy_arn !== INSTALLATION.policyArn)) throw new Error("Installation plan attachment contract is not exact.");
  }
  return Object.freeze({ resourceChangeCount: changes.length, createCount: changes.length, updateCount: 0, deleteCount: 0, replaceCount: 0, changedAddresses: [...addresses].sort() });
}

export function stateIdentity(rawBytes) {
  if (rawBytes === undefined || rawBytes === null || rawBytes.length === 0) return Object.freeze({ stateExists: false });
  const bytes = Buffer.isBuffer(rawBytes) ? rawBytes : Buffer.from(rawBytes);
  let state;
  try { state = JSON.parse(bytes.toString("utf8")); } catch { throw new Error("Terraform state is not valid UTF-8 JSON."); }
  if (!state || typeof state !== "object" || Array.isArray(state) || typeof state.lineage !== "string" || !state.lineage || !Number.isSafeInteger(state.serial) || state.serial < 0) throw new Error("Terraform state identity is malformed.");
  return Object.freeze({ stateExists: true, lineage: state.lineage, serial: state.serial, stateSha256: sha256(bytes) });
}

export function assertInstallationStateResources(rawBytes, { requiredAddresses = INSTALLATION.expectedAddresses } = {}) {
  const identity = stateIdentity(rawBytes);
  if (!identity.stateExists) {
    if (requiredAddresses.length) throw new Error("Installation Terraform state is absent for required resources.");
    return identity;
  }
  let state;
  try { state = JSON.parse(Buffer.from(rawBytes).toString("utf8")); } catch { throw new Error("Installation Terraform state is not valid UTF-8 JSON."); }
  if (!Array.isArray(state.resources)) throw new Error("Installation Terraform state resources are malformed.");
  const addresses = state.resources.filter((resource) => resource?.mode === "managed").map((resource) => `${resource.module ? `${resource.module}.` : ""}${resource.type}.${resource.name}`);
  if (new Set(addresses).size !== addresses.length) throw new Error("Installation Terraform state contains duplicate resource addresses.");
  for (const address of requiredAddresses) {
    const resource = state.resources.find((candidate) => candidate?.mode === "managed" && `${candidate.module ? `${candidate.module}.` : ""}${candidate.type}.${candidate.name}` === address);
    if (!resource || !Array.isArray(resource.instances) || resource.instances.length < 1) throw new Error("Installation Terraform state does not contain the authenticated resource set.");
  }
  return identity;
}

export function createInstallationPreparation({ sourceSha, state, livePredecessor, planJson, planBytes, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "")) throw new Error("Installation source SHA is invalid.");
  if (!state || typeof state.stateExists !== "boolean") throw new Error("Installation predecessor state identity is required.");
  if (livePredecessor === "EXACT_PARTIAL" && !state.stateExists) throw new Error("Partial installation requires an authenticated Terraform state predecessor.");
  if (state.stateExists ? (Object.keys(state).sort().join(",") !== "lineage,serial,stateExists,stateSha256" || typeof state.lineage !== "string" || !Number.isSafeInteger(state.serial) || !SHA256.test(state.stateSha256 || "")) : Object.keys(state).length !== 1) throw new Error("Installation predecessor state identity is malformed.");
  if (!["ABSENT", "EXACT_PARTIAL", "EXACT_COMPLETE"].includes(livePredecessor)) throw new Error("Installation live predecessor classification is invalid.");
  if (livePredecessor === "UNEXPECTED") throw new Error("Unexpected installation predecessor must fail closed.");
  const semantics = assertInstallationPlan(planJson);
  if (livePredecessor === "ABSENT" && semantics.resourceChangeCount !== INSTALLATION.expectedAddresses.length || livePredecessor === "EXACT_PARTIAL" && semantics.resourceChangeCount < 1) throw new Error("Installation plan does not match the authenticated live predecessor.");
  if (!Buffer.isBuffer(planBytes) || planBytes.length < 1) throw new Error("Saved Terraform plan bytes are required.");
  const body = {
    schemaVersion: INSTALLATION.schemaVersion, kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_PREPARATION", operation: INSTALLATION.operation,
    repository: INSTALLATION.repository, environment: INSTALLATION.environment, sourceSha, terraformRoot: INSTALLATION.terraformRoot, backend: INSTALLATION.backend,
    administratorArn: INSTALLATION.administratorArn, roleArn: INSTALLATION.roleArn, policyArn: INSTALLATION.policyArn, sourceContractHashes: sourceHashes(),
    predecessorState: state, livePredecessor, savedPlanSha256: sha256(planBytes), savedPlanByteLength: planBytes.length, planSemantics: semantics,
    maxAwsMutations: INSTALLATION.maxAwsMutations, preparedAt,
  };
  if (!Number.isFinite(Date.parse(preparedAt))) throw new Error("Preparation timestamp is invalid.");
  return Object.freeze({ ...body, preparationArtifactSha256: canonicalSha256(body) });
}

const PREPARATION_FIELDS = new Set(["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "terraformRoot", "backend", "administratorArn", "roleArn", "policyArn", "sourceContractHashes", "predecessorState", "livePredecessor", "savedPlanSha256", "savedPlanByteLength", "planSemantics", "maxAwsMutations", "preparedAt", "preparationArtifactSha256"]);
export function assertInstallationPreparation(value, { sourceSha, planBytes } = {}) {
  exactFields(value, PREPARATION_FIELDS, "Installation preparation");
  const { preparationArtifactSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_PREPARATION" || value.operation !== INSTALLATION.operation || value.repository !== INSTALLATION.repository || value.environment !== INSTALLATION.environment || value.sourceSha !== sourceSha || value.terraformRoot !== INSTALLATION.terraformRoot || canonicalSha256(body) !== preparationArtifactSha256) throw new Error("Installation preparation identity or hash is invalid.");
  if (JSON.stringify(value.backend) !== JSON.stringify(INSTALLATION.backend) || JSON.stringify(value.sourceContractHashes) !== JSON.stringify(sourceHashes()) || JSON.stringify(value.maxAwsMutations) !== JSON.stringify(INSTALLATION.maxAwsMutations) || value.administratorArn !== INSTALLATION.administratorArn || value.roleArn !== INSTALLATION.roleArn || value.policyArn !== INSTALLATION.policyArn || value.livePredecessor === "UNEXPECTED" || !SHA256.test(value.savedPlanSha256 || "") || !Number.isSafeInteger(value.savedPlanByteLength) || value.savedPlanByteLength < 1 || !SHA40.test(value.sourceSha || "") || !value.predecessorState || typeof value.predecessorState.stateExists !== "boolean" || value.predecessorState.stateExists && (!SHA256.test(value.predecessorState.stateSha256 || "") || !Number.isSafeInteger(value.predecessorState.serial) || typeof value.predecessorState.lineage !== "string") || !value.predecessorState.stateExists && Object.keys(value.predecessorState).length !== 1) throw new Error("Installation preparation binding is invalid.");
  if (planBytes !== undefined && (sha256(planBytes) !== value.savedPlanSha256 || planBytes.length !== value.savedPlanByteLength)) throw new Error("Installation saved plan bytes changed after preparation.");
  if (value.livePredecessor === "EXACT_PARTIAL" && !value.predecessorState.stateExists) throw new Error("Partial installation requires an authenticated Terraform state predecessor.");
  if (!value.planSemantics || !Array.isArray(value.planSemantics.changedAddresses) || !Number.isSafeInteger(value.planSemantics.resourceChangeCount) || value.planSemantics.resourceChangeCount < 0 || value.planSemantics.resourceChangeCount > INSTALLATION.expectedAddresses.length || value.planSemantics.createCount !== value.planSemantics.resourceChangeCount || value.planSemantics.updateCount !== 0 || value.planSemantics.deleteCount !== 0 || value.planSemantics.replaceCount !== 0 || JSON.stringify(value.planSemantics.changedAddresses) !== JSON.stringify([...value.planSemantics.changedAddresses].sort()) || value.planSemantics.changedAddresses.some((address) => !INSTALLATION.expectedAddresses.includes(address)) || value.livePredecessor === "ABSENT" && value.planSemantics.resourceChangeCount !== INSTALLATION.expectedAddresses.length || value.livePredecessor === "EXACT_PARTIAL" && value.planSemantics.resourceChangeCount < 1 || value.livePredecessor === "EXACT_COMPLETE" && value.planSemantics.resourceChangeCount !== 0) throw new Error("Installation preparation plan semantics are not exact.");
  return value;
}

export function createInstallationAuthorization({ preparation, preparationArtifactSha256, protectedEnvironmentApprovalEvidence, sourceSha, now = new Date().toISOString() } = {}) {
  assertInstallationPreparation(preparation, { sourceSha });
  if (preparation.preparationArtifactSha256 !== preparationArtifactSha256) throw new Error("Installation preparation artifact digest is invalid.");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository: INSTALLATION.repository });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef) throw new Error("Installation approval workflow binding is invalid.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_AUTHORIZATION", operation: INSTALLATION.operation, repository: INSTALLATION.repository, environment: INSTALLATION.environment, sourceSha, preparationArtifactSha256, terraformRoot: INSTALLATION.terraformRoot, backend: INSTALLATION.backend, predecessorState: preparation.predecessorState, livePredecessor: preparation.livePredecessor, administratorArn: INSTALLATION.administratorArn, roleArn: INSTALLATION.roleArn, policyArn: INSTALLATION.policyArn, savedPlanSha256: preparation.savedPlanSha256, sourceContractHashes: preparation.sourceContractHashes, maxAwsMutations: INSTALLATION.maxAwsMutations, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, authorizedAt: now };
  return Object.freeze({ ...body, authorizationArtifactSha256: canonicalSha256(body) });
}

const AUTH_FIELDS = new Set(["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "preparationArtifactSha256", "terraformRoot", "backend", "predecessorState", "livePredecessor", "administratorArn", "roleArn", "policyArn", "savedPlanSha256", "sourceContractHashes", "maxAwsMutations", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizedAt", "authorizationArtifactSha256"]);
export function assertInstallationAuthorization(value, { sourceSha, preparation } = {}) {
  exactFields(value, AUTH_FIELDS, "Installation authorization");
  const { authorizationArtifactSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_AUTHORIZATION" || value.operation !== INSTALLATION.operation || value.repository !== INSTALLATION.repository || value.environment !== INSTALLATION.environment || value.sourceSha !== sourceSha || value.preparationArtifactSha256 !== preparation.preparationArtifactSha256 || value.savedPlanSha256 !== preparation.savedPlanSha256 || canonicalSha256(body) !== authorizationArtifactSha256) throw new Error("Installation authorization binding or hash is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: INSTALLATION.repository });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || JSON.stringify(value.sourceContractHashes) !== JSON.stringify(sourceHashes()) || JSON.stringify(value.maxAwsMutations) !== JSON.stringify(INSTALLATION.maxAwsMutations) || value.terraformRoot !== INSTALLATION.terraformRoot || JSON.stringify(value.backend) !== JSON.stringify(INSTALLATION.backend) || value.administratorArn !== INSTALLATION.administratorArn || value.roleArn !== INSTALLATION.roleArn || value.policyArn !== INSTALLATION.policyArn) throw new Error("Installation authorization is not bound to the exact operation.");
  return value;
}

export function assertFreshInstallationAuthorization(value, { sourceSha, preparation, now = new Date() } = {}) {
  assertInstallationAuthorization(value, { sourceSha, preparation });
  assertProductionEnvironmentApprovalEvidence(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: INSTALLATION.repository, environment: INSTALLATION.environment, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: value.protectedEnvironmentApprovalEvidence.workflowRunId, workflowRunAttempt: value.protectedEnvironmentApprovalEvidence.workflowRunAttempt, executionActor: value.protectedEnvironmentApprovalEvidence.executionActor, githubActions: "true", now });
  return value;
}

export function assertInstallationResult(value, { sourceSha, authorization } = {}) {
  if (!value || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_RESULT" || value.sourceSha !== sourceSha || value.authorizationArtifactSha256 !== authorization.authorizationArtifactSha256 || value.status !== "COMPLETE" || ![0, 1].includes(value.applyCount) || value.targetPolicyCreatePolicyVersionCount !== 0 || value.verifier !== "PASS") throw new Error("Installation result evidence is invalid.");
  return value;
}
