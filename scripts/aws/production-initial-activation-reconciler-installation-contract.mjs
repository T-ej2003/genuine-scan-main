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
  terraformVersion: "1.15.8",
  executionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler-bootstrap",
  terraformRoot: "infra/aws/terraform/production-initial-activation-policy-reconciler",
  backend: Object.freeze({ bucket: "mscqr-production-terraform-state-368992683803-eu-west-2", key: "mscqr/production/initial-activation-policy-reconciler/terraform.tfstate", lockKey: "mscqr/production/initial-activation-policy-reconciler/terraform.tfstate.tflock", region: "eu-west-2", encrypt: true, useLockfile: true, workspace: "default" }),
  roleArn: INITIAL_ACTIVATION_RECONCILER.roleArn,
  policyArn: INITIAL_ACTIVATION_RECONCILER.policyArn,
  authorizationWorkflowPath: ".github/workflows/authorize-production-initial-activation-policy-reconciler-installation.yml",
  authorizationArtifactName: "production-initial-activation-policy-reconciler-installation-authorization",
  expectedAddresses: Object.freeze(["aws_iam_role.reconciler", "aws_iam_policy.reconciler", "aws_iam_role_policy_attachment.reconciler"]),
  maxAwsMutations: Object.freeze({ "iam:CreateRole": 1, "iam:CreatePolicy": 1, "iam:AttachRolePolicy": 1, "iam:UpdateAssumeRolePolicy": 0, "iam:PutRolePolicy": 0, "iam:CreatePolicyVersion": 0 }),
});

export const INSTALLATION_BACKEND = Object.freeze({ type: "s3", bucket: INSTALLATION.backend.bucket, key: INSTALLATION.backend.key, region: INSTALLATION.backend.region, encrypt: INSTALLATION.backend.encrypt, use_lockfile: INSTALLATION.backend.useLockfile, workspace: INSTALLATION.backend.workspace });

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
const EXPECTED_TAGS = Object.freeze({ ManagedBy: "Terraform", Environment: "production", Component: "initial-activation-policy-reconciliation", Stack: "production-initial-activation-policy-reconciler" });
const ROLE_NAME = "mscqr-production-initial-activation-policy-reconciler";
const POLICY_NAME = "MSCQRProductionInitialActivationPolicyReconciler";
const ROLE_DESCRIPTION = "GitHub OIDC-only writer for the exact InitialActivationLifecycle policy reconciliation.";
const POLICY_DESCRIPTION = "Exact readback and CreatePolicyVersion capability for InitialActivationLifecycle reconciliation.";
const EXPECTED_PROVIDER_CONFIGURATION = Object.freeze({
  aws: {
    name: "aws",
    full_name: "registry.terraform.io/hashicorp/aws",
    version_constraint: ">= 6.41.0, < 7.0.0",
    expressions: {
      allowed_account_ids: { constant_value: ["368992683803"] },
      region: { constant_value: INSTALLATION.region },
    },
  },
});
const EXPECTED_OUTPUT_CONFIGURATION = Object.freeze({
  permissions_policy_sha256: { expression: { references: ["path.module"] } },
  policy_arn: { expression: { references: ["aws_iam_policy.reconciler.arn", "aws_iam_policy.reconciler"] } },
  policy_name: { expression: { references: ["aws_iam_policy.reconciler.name", "aws_iam_policy.reconciler"] } },
  role_arn: { expression: { references: ["aws_iam_role.reconciler.arn", "aws_iam_role.reconciler"] } },
  role_name: { expression: { references: ["aws_iam_role.reconciler.name", "aws_iam_role.reconciler"] } },
  trust_policy_sha256: { expression: { references: ["path.module"] } },
});
const EXPECTED_RESOURCE_CONFIGURATION = Object.freeze({
  "aws_iam_policy.reconciler": {
    address: "aws_iam_policy.reconciler", mode: "managed", type: "aws_iam_policy", name: "reconciler", provider_config_key: "aws", schema_version: 0,
    expressions: {
      description: { constant_value: POLICY_DESCRIPTION },
      name: { references: ["local.policy_name"] },
      policy: { references: ["path.module"] },
      tags: { references: ["local.tags"] },
    },
  },
  "aws_iam_role.reconciler": {
    address: "aws_iam_role.reconciler", mode: "managed", type: "aws_iam_role", name: "reconciler", provider_config_key: "aws", schema_version: 0,
    expressions: {
      assume_role_policy: { references: ["path.module"] },
      description: { constant_value: ROLE_DESCRIPTION },
      max_session_duration: { constant_value: 3600 },
      name: { references: ["local.role_name"] },
      tags: { references: ["local.tags"] },
    },
  },
  "aws_iam_role_policy_attachment.reconciler": {
    address: "aws_iam_role_policy_attachment.reconciler", mode: "managed", type: "aws_iam_role_policy_attachment", name: "reconciler", provider_config_key: "aws", schema_version: 0,
    expressions: {
      policy_arn: { references: ["aws_iam_policy.reconciler.arn", "aws_iam_policy.reconciler"] },
      role: { references: ["aws_iam_role.reconciler.name", "aws_iam_role.reconciler"] },
    },
  },
});

const INITIALIZED_BACKEND_REQUIRED_KEYS = Object.freeze(["bucket", "key", "region", "encrypt", "use_lockfile"]);
const INITIALIZED_BACKEND_OPTIONAL_KEYS = Object.freeze([
  "access_key", "acl", "allowed_account_ids", "assume_role", "assume_role_with_web_identity", "custom_ca_bundle", "dynamodb_endpoint", "dynamodb_table", "ec2_metadata_service_endpoint", "ec2_metadata_service_endpoint_mode", "endpoint", "endpoints", "forbidden_account_ids", "force_path_style", "http_proxy", "https_proxy", "iam_endpoint", "insecure", "kms_key_id", "max_retries", "no_proxy", "profile", "retry_mode", "secret_key", "shared_config_files", "shared_credentials_file", "shared_credentials_files", "skip_credentials_validation", "skip_metadata_api_check", "skip_region_validation", "skip_requesting_account_id", "skip_s3_checksum", "sse_customer_key", "sts_endpoint", "sts_region", "token", "use_dualstack_endpoint", "use_fips_endpoint", "use_path_style", "workspace_key_prefix",
]);
const assertKnownKeys = (value, allowed, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Installation initialized backend ${label} is malformed.`);
  const unknown = Object.keys(value).find((key) => !allowed.includes(key));
  if (unknown) throw new Error(`Installation initialized backend ${label} has unreviewed key: ${unknown}.`);
};

export function assertInstallationInitializedBackendMetadata(metadata) {
  assertKnownKeys(metadata, ["type", "hash", "config"], "metadata");
  if (metadata.type !== INSTALLATION_BACKEND.type || !Number.isSafeInteger(metadata.hash)) throw new Error("Installation initialized backend metadata is not exact.");
  assertKnownKeys(metadata.config, [...INITIALIZED_BACKEND_REQUIRED_KEYS, ...INITIALIZED_BACKEND_OPTIONAL_KEYS], "config");
  for (const key of INITIALIZED_BACKEND_REQUIRED_KEYS) if (metadata.config[key] !== INSTALLATION_BACKEND[key]) throw new Error(`Installation initialized backend ${key} is not exact.`);
  for (const key of INITIALIZED_BACKEND_OPTIONAL_KEYS) if (metadata.config[key] !== undefined && metadata.config[key] !== null && metadata.config[key] !== "") throw new Error(`Installation initialized backend ${key} must use the Terraform default.`);
  return true;
}

export function classifyInstallationStatePullError(error) {
  const diagnostic = String(error?.stderr ?? error?.message ?? "")
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/^[│╷╵]\s*/, ""))
    .filter(Boolean);
  const errors = diagnostic.filter((line) => /^Error:\s*/i.test(line));
  const noStateTitle = errors.length === 1 ? /^Error:\s*No state file was found!?$/i.test(errors[0]) : errors.length === 0 && /^No state file was found!?$/i.test(diagnostic[0] || "");
  const canonicalTail = diagnostic.length === 1 || diagnostic.some((line) => /^State management commands require a state file\./i.test(line));
  if (noStateTitle && canonicalTail) return undefined;
  throw error;
}

export function assertInstallationPlan(plan) {
  if (!plan || typeof plan !== "object" || !Array.isArray(plan.resource_changes)) throw new Error("Installation Terraform plan JSON is malformed.");
  if (plan.format_version !== "1.2" || plan.terraform_version !== INSTALLATION.terraformVersion || plan.errored !== false || plan.complete !== true || plan.applyable !== true || plan.resource_drift !== undefined && plan.resource_drift !== null && (!Array.isArray(plan.resource_drift) || plan.resource_drift.length !== 0)) throw new Error("Installation Terraform plan envelope is not exact.");
  if (!plan.configuration || Object.keys(plan.configuration).sort().join(",") !== "provider_config,root_module") throw new Error("Installation Terraform configuration boundary is not exact.");
  if (canonicalJson(plan.configuration?.provider_config) !== canonicalJson(EXPECTED_PROVIDER_CONFIGURATION)) throw new Error("Installation plan provider configuration is not exact.");
  const rootModule = plan.configuration?.root_module;
  if (!rootModule || Object.keys(rootModule).sort().join(",") !== "outputs,resources" || canonicalJson(rootModule.outputs) !== canonicalJson(EXPECTED_OUTPUT_CONFIGURATION) || !Array.isArray(rootModule.resources)) throw new Error("Installation Terraform root configuration is not exact.");
  if (rootModule.resources.length !== INSTALLATION.expectedAddresses.length) throw new Error("Installation plan configured resource count is not exact.");
  const configuredAddresses = rootModule.resources.map((resource) => resource?.address);
  if (new Set(configuredAddresses).size !== configuredAddresses.length || INSTALLATION.expectedAddresses.some((address) => !configuredAddresses.includes(address))) throw new Error("Installation plan configured resource ownership is not exact.");
  for (const configured of rootModule.resources) {
    if (!configured?.address || canonicalJson(configured) !== canonicalJson(EXPECTED_RESOURCE_CONFIGURATION[configured.address])) throw new Error("Installation plan resource configuration, provider binding, or provisioner boundary is not exact.");
  }
  const changes = plan.resource_changes;
  if (changes.length !== INSTALLATION.expectedAddresses.length) throw new Error("Installation plan resource count is not exact.");
  const addresses = changes.map((entry) => entry?.address);
  if (new Set(addresses).size !== addresses.length || addresses.some((address) => !INSTALLATION.expectedAddresses.includes(address)) || INSTALLATION.expectedAddresses.some((address) => !addresses.includes(address))) throw new Error("Installation plan contains an unreviewed, missing, or duplicate resource address.");
  const policyCreated = JSON.stringify(changes.find((entry) => entry?.address === "aws_iam_policy.reconciler")?.change?.actions) === JSON.stringify(["create"]);
  const createdAddresses = [];
  const noOpAddresses = [];
  let noOpCount = 0;
  for (const entry of changes) {
    const action = JSON.stringify(entry.change?.actions);
    if (entry.mode !== "managed" || ![JSON.stringify(["create"]), JSON.stringify(["no-op"])].includes(action)) throw new Error("Installation plan contains an unreviewed resource action.");
    const expectedType = entry.address === "aws_iam_role.reconciler" ? "aws_iam_role" : entry.address === "aws_iam_policy.reconciler" ? "aws_iam_policy" : "aws_iam_role_policy_attachment";
    if (entry.type !== expectedType || entry.name !== "reconciler" || entry.provider_name !== "registry.terraform.io/hashicorp/aws") throw new Error("Installation plan resource identity is not exact.");
    const create = action === JSON.stringify(["create"]);
    if (create ? entry.change.before !== null : canonicalJson(entry.change.before) !== canonicalJson(entry.change.after)) throw new Error("Installation plan action predecessor is not exact.");
    if (create) createdAddresses.push(entry.address); else { noOpAddresses.push(entry.address); noOpCount += 1; }
    const after = entry.change.after;
    if (!after || typeof after !== "object" || Array.isArray(after)) throw new Error("Installation plan resource values are missing.");
    if (entry.address === "aws_iam_role.reconciler") {
      if (after.name !== ROLE_NAME || after.path !== "/" || after.description !== ROLE_DESCRIPTION || after.force_detach_policies !== false || after.max_session_duration !== 3600 || after.permissions_boundary !== null || canonicalJson(after.tags) !== canonicalJson(EXPECTED_TAGS) || canonicalJson(after.tags_all) !== canonicalJson(EXPECTED_TAGS) || canonicalJson(policyValue(after.assume_role_policy, "Installation plan trust policy")) !== canonicalJson(sourceJson(`${INSTALLATION.terraformRoot}/trust-policy.json`)) || !create && after.arn !== INSTALLATION.roleArn) throw new Error("Installation plan role contract is not exact.");
    } else if (entry.address === "aws_iam_policy.reconciler") {
      if (after.name !== POLICY_NAME || after.path !== "/" || after.description !== POLICY_DESCRIPTION || after.delay_after_policy_creation_in_ms !== null || canonicalJson(after.tags) !== canonicalJson(EXPECTED_TAGS) || canonicalJson(after.tags_all) !== canonicalJson(EXPECTED_TAGS) || canonicalJson(policyValue(after.policy, "Installation plan permissions policy")) !== canonicalJson(sourceJson(`${INSTALLATION.terraformRoot}/permissions-policy.json`)) || !create && after.arn !== INSTALLATION.policyArn) throw new Error("Installation plan policy contract is not exact.");
    } else if (entry.address === "aws_iam_role_policy_attachment.reconciler") {
      const policyArnKnown = !policyCreated && after.policy_arn === INSTALLATION.policyArn && entry.change.after_unknown?.policy_arn === undefined;
      const policyArnComputed = policyCreated && !Object.hasOwn(after, "policy_arn") && entry.change.after_unknown?.policy_arn === true;
      if (after.role !== ROLE_NAME || !(policyArnKnown || policyArnComputed)) throw new Error("Installation plan attachment contract is not exact.");
    }
  }
  return Object.freeze({ plannedResourceCount: changes.length, resourceChangeCount: createdAddresses.length, actionableResourceChangeCount: createdAddresses.length, createCount: createdAddresses.length, noOpCount, updateCount: 0, deleteCount: 0, replaceCount: 0, changedAddresses: createdAddresses.sort(), noOpAddresses: noOpAddresses.sort() });
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

export function createInstallationPreparation({ sourceSha, state, livePredecessor, livePredecessorAddresses, planJson, planBytes, preparedAt = new Date().toISOString() } = {}) {
  if (!SHA40.test(sourceSha || "")) throw new Error("Installation source SHA is invalid.");
  if (!state || typeof state.stateExists !== "boolean") throw new Error("Installation predecessor state identity is required.");
  if (livePredecessor === "EXACT_PARTIAL" && !state.stateExists) throw new Error("Partial installation requires an authenticated Terraform state predecessor.");
  if (state.stateExists ? (Object.keys(state).sort().join(",") !== "lineage,serial,stateExists,stateSha256" || typeof state.lineage !== "string" || !Number.isSafeInteger(state.serial) || !SHA256.test(state.stateSha256 || "")) : Object.keys(state).length !== 1) throw new Error("Installation predecessor state identity is malformed.");
  if (!["ABSENT", "EXACT_PARTIAL", "EXACT_COMPLETE"].includes(livePredecessor)) throw new Error("Installation live predecessor classification is invalid.");
  if (livePredecessor === "UNEXPECTED") throw new Error("Unexpected installation predecessor must fail closed.");
  if (!Array.isArray(livePredecessorAddresses) || new Set(livePredecessorAddresses).size !== livePredecessorAddresses.length || livePredecessorAddresses.some((address) => !INSTALLATION.expectedAddresses.includes(address)) || JSON.stringify(livePredecessorAddresses) !== JSON.stringify([...livePredecessorAddresses].sort())) throw new Error("Installation live predecessor resource set is invalid.");
  const semantics = assertInstallationPlan(planJson);
  if (livePredecessor === "ABSENT" && (semantics.createCount !== INSTALLATION.expectedAddresses.length || semantics.noOpCount !== 0)
    || livePredecessor === "EXACT_PARTIAL" && (semantics.createCount < 1 || semantics.createCount >= INSTALLATION.expectedAddresses.length || semantics.noOpCount !== INSTALLATION.expectedAddresses.length - semantics.createCount)
    || livePredecessor === "EXACT_COMPLETE" && (semantics.createCount !== 0 || semantics.noOpCount !== INSTALLATION.expectedAddresses.length)
    || JSON.stringify(livePredecessorAddresses) !== JSON.stringify(semantics.noOpAddresses)) throw new Error("Installation plan does not match the authenticated live predecessor.");
  if (!Buffer.isBuffer(planBytes) || planBytes.length < 1) throw new Error("Saved Terraform plan bytes are required.");
  const body = {
    schemaVersion: INSTALLATION.schemaVersion, kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_PREPARATION", operation: INSTALLATION.operation,
    repository: INSTALLATION.repository, environment: INSTALLATION.environment, sourceSha, terraformRoot: INSTALLATION.terraformRoot, backend: INSTALLATION.backend,
    executionRoleArn: INSTALLATION.executionRoleArn, roleArn: INSTALLATION.roleArn, policyArn: INSTALLATION.policyArn, sourceContractHashes: sourceHashes(),
    predecessorState: state, livePredecessor, livePredecessorAddresses, savedPlanSha256: sha256(planBytes), savedPlanByteLength: planBytes.length, planSemantics: semantics,
    maxAwsMutations: INSTALLATION.maxAwsMutations, preparedAt,
  };
  if (!Number.isFinite(Date.parse(preparedAt))) throw new Error("Preparation timestamp is invalid.");
  return Object.freeze({ ...body, preparationArtifactSha256: canonicalSha256(body) });
}

const PREPARATION_FIELDS = new Set(["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "terraformRoot", "backend", "executionRoleArn", "roleArn", "policyArn", "sourceContractHashes", "predecessorState", "livePredecessor", "livePredecessorAddresses", "savedPlanSha256", "savedPlanByteLength", "planSemantics", "maxAwsMutations", "preparedAt", "preparationArtifactSha256"]);
export function assertInstallationPreparation(value, { sourceSha, planBytes } = {}) {
  exactFields(value, PREPARATION_FIELDS, "Installation preparation");
  const { preparationArtifactSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_PREPARATION" || value.operation !== INSTALLATION.operation || value.repository !== INSTALLATION.repository || value.environment !== INSTALLATION.environment || value.sourceSha !== sourceSha || value.terraformRoot !== INSTALLATION.terraformRoot || canonicalSha256(body) !== preparationArtifactSha256) throw new Error("Installation preparation identity or hash is invalid.");
  if (JSON.stringify(value.backend) !== JSON.stringify(INSTALLATION.backend) || JSON.stringify(value.sourceContractHashes) !== JSON.stringify(sourceHashes()) || JSON.stringify(value.maxAwsMutations) !== JSON.stringify(INSTALLATION.maxAwsMutations) || value.executionRoleArn !== INSTALLATION.executionRoleArn || value.roleArn !== INSTALLATION.roleArn || value.policyArn !== INSTALLATION.policyArn || value.livePredecessor === "UNEXPECTED" || !SHA256.test(value.savedPlanSha256 || "") || !Number.isSafeInteger(value.savedPlanByteLength) || value.savedPlanByteLength < 1 || !SHA40.test(value.sourceSha || "") || !value.predecessorState || typeof value.predecessorState.stateExists !== "boolean" || value.predecessorState.stateExists && (!SHA256.test(value.predecessorState.stateSha256 || "") || !Number.isSafeInteger(value.predecessorState.serial) || typeof value.predecessorState.lineage !== "string") || !value.predecessorState.stateExists && Object.keys(value.predecessorState).length !== 1) throw new Error("Installation preparation binding is invalid.");
  if (planBytes !== undefined && (sha256(planBytes) !== value.savedPlanSha256 || planBytes.length !== value.savedPlanByteLength)) throw new Error("Installation saved plan bytes changed after preparation.");
  if (value.livePredecessor === "EXACT_PARTIAL" && !value.predecessorState.stateExists) throw new Error("Partial installation requires an authenticated Terraform state predecessor.");
  if (!value.planSemantics || !Array.isArray(value.planSemantics.changedAddresses) || !Array.isArray(value.planSemantics.noOpAddresses)
    || value.planSemantics.plannedResourceCount !== INSTALLATION.expectedAddresses.length
    || !Number.isSafeInteger(value.planSemantics.resourceChangeCount) || value.planSemantics.resourceChangeCount < 0 || value.planSemantics.resourceChangeCount > INSTALLATION.expectedAddresses.length
    || value.planSemantics.actionableResourceChangeCount !== value.planSemantics.resourceChangeCount || value.planSemantics.createCount !== value.planSemantics.resourceChangeCount
    || value.planSemantics.noOpCount !== INSTALLATION.expectedAddresses.length - value.planSemantics.createCount
    || value.planSemantics.updateCount !== 0 || value.planSemantics.deleteCount !== 0 || value.planSemantics.replaceCount !== 0
    || value.planSemantics.changedAddresses.length !== value.planSemantics.createCount || JSON.stringify(value.planSemantics.changedAddresses) !== JSON.stringify([...value.planSemantics.changedAddresses].sort()) || value.planSemantics.changedAddresses.some((address) => !INSTALLATION.expectedAddresses.includes(address))
    || value.planSemantics.noOpAddresses.length !== value.planSemantics.noOpCount || JSON.stringify(value.planSemantics.noOpAddresses) !== JSON.stringify([...value.planSemantics.noOpAddresses].sort()) || value.planSemantics.noOpAddresses.some((address) => !INSTALLATION.expectedAddresses.includes(address))
    || JSON.stringify(value.livePredecessorAddresses) !== JSON.stringify(value.planSemantics.noOpAddresses)
    || value.livePredecessor === "ABSENT" && value.planSemantics.createCount !== INSTALLATION.expectedAddresses.length
    || value.livePredecessor === "EXACT_PARTIAL" && (value.planSemantics.createCount < 1 || value.planSemantics.createCount >= INSTALLATION.expectedAddresses.length)
    || value.livePredecessor === "EXACT_COMPLETE" && value.planSemantics.createCount !== 0) throw new Error("Installation preparation plan semantics are not exact.");
  return value;
}

export function createInstallationAuthorization({ preparation, preparationArtifactSha256, protectedEnvironmentApprovalEvidence, sourceSha, now = new Date().toISOString() } = {}) {
  assertInstallationPreparation(preparation, { sourceSha });
  if (preparation.preparationArtifactSha256 !== preparationArtifactSha256) throw new Error("Installation preparation artifact digest is invalid.");
  assertProductionEnvironmentApprovalIdentity(protectedEnvironmentApprovalEvidence, { sourceSha, repository: INSTALLATION.repository });
  if (protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef) throw new Error("Installation approval workflow binding is invalid.");
  const body = { schemaVersion: 1, kind: "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_AUTHORIZATION", operation: INSTALLATION.operation, repository: INSTALLATION.repository, environment: INSTALLATION.environment, sourceSha, preparationArtifactSha256, terraformRoot: INSTALLATION.terraformRoot, backend: INSTALLATION.backend, predecessorState: preparation.predecessorState, livePredecessor: preparation.livePredecessor, livePredecessorAddresses: preparation.livePredecessorAddresses, executionRoleArn: INSTALLATION.executionRoleArn, roleArn: INSTALLATION.roleArn, policyArn: INSTALLATION.policyArn, savedPlanSha256: preparation.savedPlanSha256, sourceContractHashes: preparation.sourceContractHashes, maxAwsMutations: INSTALLATION.maxAwsMutations, protectedEnvironmentApprovalEvidence, protectedEnvironmentApprovalEvidenceSha256: protectedEnvironmentApprovalEvidence.evidenceSha256, authorizedAt: now };
  return Object.freeze({ ...body, authorizationArtifactSha256: canonicalSha256(body) });
}

const AUTH_FIELDS = new Set(["schemaVersion", "kind", "operation", "repository", "environment", "sourceSha", "preparationArtifactSha256", "terraformRoot", "backend", "predecessorState", "livePredecessor", "livePredecessorAddresses", "executionRoleArn", "roleArn", "policyArn", "savedPlanSha256", "sourceContractHashes", "maxAwsMutations", "protectedEnvironmentApprovalEvidence", "protectedEnvironmentApprovalEvidenceSha256", "authorizedAt", "authorizationArtifactSha256"]);
export function assertInstallationAuthorization(value, { sourceSha, preparation } = {}) {
  exactFields(value, AUTH_FIELDS, "Installation authorization");
  const { authorizationArtifactSha256, ...body } = value;
  if (value.schemaVersion !== 1 || value.kind !== "PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION_AUTHORIZATION" || value.operation !== INSTALLATION.operation || value.repository !== INSTALLATION.repository || value.environment !== INSTALLATION.environment || value.sourceSha !== sourceSha || value.preparationArtifactSha256 !== preparation.preparationArtifactSha256 || value.savedPlanSha256 !== preparation.savedPlanSha256 || JSON.stringify(value.livePredecessorAddresses) !== JSON.stringify(preparation.livePredecessorAddresses) || canonicalSha256(body) !== authorizationArtifactSha256) throw new Error("Installation authorization binding or hash is invalid.");
  assertProductionEnvironmentApprovalIdentity(value.protectedEnvironmentApprovalEvidence, { sourceSha, repository: INSTALLATION.repository });
  if (value.protectedEnvironmentApprovalEvidence.workflowRef !== PRODUCTION_ENVIRONMENT_APPROVAL.installationWorkflowRef || value.protectedEnvironmentApprovalEvidenceSha256 !== value.protectedEnvironmentApprovalEvidence.evidenceSha256 || JSON.stringify(value.sourceContractHashes) !== JSON.stringify(sourceHashes()) || JSON.stringify(value.maxAwsMutations) !== JSON.stringify(INSTALLATION.maxAwsMutations) || value.terraformRoot !== INSTALLATION.terraformRoot || JSON.stringify(value.backend) !== JSON.stringify(INSTALLATION.backend) || value.executionRoleArn !== INSTALLATION.executionRoleArn || value.roleArn !== INSTALLATION.roleArn || value.policyArn !== INSTALLATION.policyArn) throw new Error("Installation authorization is not bound to the exact operation.");
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
