import crypto from "node:crypto";
import { canonicalSha256, taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM } from "./production-green-stage-b-contract.mjs";
import { deriveEcsRuntimeDependencies, RUNTIME_ACCOUNT as ACCOUNT, RUNTIME_REGION as REGION, RUNTIME_ROLE_ARN as ROLE_ARN } from "./production-ecs-runtime-dependencies.mjs";
export { deriveEcsRuntimeDependencies } from "./production-ecs-runtime-dependencies.mjs";

const SHA = /^[a-f0-9]{40}$/;
const HEX = /^[a-f0-9]{64}$/;
export const RUNTIME_AUTHORIZATION_MAX_AGE_MS = 35 * 24 * 60 * 60 * 1000;
export const LIVE_RUNTIME_EVIDENCE_MAX_AGE_MS = 60 * 1000;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const AWS_MANAGED_EXECUTION_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy";
const LEGACY_RUNTIME_POLICY_NAME = "mscqr-ecs-secrets-read";
const ECR_REPOSITORY_ARN = new RegExp(`^arn:aws:ecr:${REGION}:${ACCOUNT}:repository/([a-z0-9][a-z0-9._/-]*)$`);
const ECS_TASK_TRUST = Object.freeze({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "ecs-tasks.amazonaws.com" }, Action: "sts:AssumeRole" }] });
const ECS_TASK_TRUST_SHA256 = canonicalSha256(ECS_TASK_TRUST);
const SOURCE_OWNED_RUNTIME_KMS_KEYS = new Set([STAGE_B.approvalKmsKeyArn]);
const SECRET_VERSION_PAGE_SIZE = 100;
const SECRET_VERSION_MAX_PAGES = 100;
const SECRET_VERSION_MAX_RESULTS = SECRET_VERSION_PAGE_SIZE * SECRET_VERSION_MAX_PAGES;
const SECRET_VERSION_ID = /^[A-Za-z0-9_-]{32,64}$/;
const SECRET_STAGE = /^[A-Za-z0-9/_+=.@-]{1,256}$/;
const SECRET_RESOURCE = new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+$`);
const LOG_GROUP_ARN = new RegExp(`^arn:aws:logs:${REGION}:${ACCOUNT}:log-group:(/[^*]+)$`);
const AWS_CLI_ENHANCED_ERROR_PREFIX = "aws: [ERROR]: ";
const ECR_REPOSITORY_POLICY_NOT_FOUND_PREFIX = "An error occurred (RepositoryPolicyNotFoundException) when calling the GetRepositoryPolicy operation: ";
const POLICY_EFFECTS = new Set(["Allow", "Deny"]);
const POLICY_STATEMENT_FIELDS = new Set(["Sid", "Effect", "Principal", "NotPrincipal", "Action", "NotAction", "Resource", "NotResource", "Condition"]);
const PRINCIPAL_TYPES = new Set(["AWS", "Federated", "Service", "CanonicalUser"]);
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
const isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
const isStringOrStringList = (value) => isNonEmptyString(value) || (Array.isArray(value) && value.length > 0 && value.every((item, index) => Object.hasOwn(value, index) && isNonEmptyString(item)));
const isPrincipal = (value) => value === "*" || (isPlainObject(value) && Object.keys(value).length > 0
  && Object.entries(value).every(([type, principal]) => PRINCIPAL_TYPES.has(type) && isStringOrStringList(principal)));
const isConditionValue = (value) => isNonEmptyString(value) || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))
  || (Array.isArray(value) && value.length > 0 && value.every((item, index) => Object.hasOwn(value, index)
    && (isNonEmptyString(item) || typeof item === "boolean" || (typeof item === "number" && Number.isFinite(item)))));
const isCondition = (value) => isPlainObject(value) && Object.keys(value).length > 0
  && Object.entries(value).every(([operator, entries]) => isNonEmptyString(operator) && isPlainObject(entries) && Object.keys(entries).length > 0
    && Object.entries(entries).every(([key, conditionValue]) => isNonEmptyString(key) && isConditionValue(conditionValue)));
const isPolicyStatement = (statement) => {
  if (!isPlainObject(statement) || Object.keys(statement).some((key) => !POLICY_STATEMENT_FIELDS.has(key))
    || !Object.hasOwn(statement, "Effect") || !POLICY_EFFECTS.has(statement.Effect)) return false;
  const action = Object.hasOwn(statement, "Action"); const notAction = Object.hasOwn(statement, "NotAction");
  const resource = Object.hasOwn(statement, "Resource"); const notResource = Object.hasOwn(statement, "NotResource");
  const principal = Object.hasOwn(statement, "Principal"); const notPrincipal = Object.hasOwn(statement, "NotPrincipal");
  return action !== notAction && resource !== notResource && !(principal && notPrincipal)
    && isStringOrStringList(statement[action ? "Action" : "NotAction"])
    && isStringOrStringList(statement[resource ? "Resource" : "NotResource"])
    && (!principal && !notPrincipal || isPrincipal(statement[principal ? "Principal" : "NotPrincipal"]))
    && (!Object.hasOwn(statement, "Sid") || isNonEmptyString(statement.Sid) && /^[A-Za-z0-9]+$/.test(statement.Sid))
    && (!Object.hasOwn(statement, "Condition") || isCondition(statement.Condition));
};
const actionMatches = (value, expected) => [value].flat().some((action) => action === "*" || action === expected || (action?.endsWith("*") && expected.startsWith(action.slice(0, -1))));
const patternMatches = (pattern, value) => typeof pattern === "string" && new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*").replaceAll("?", ".")}$`).test(value);
const principalValues = (value) => [value].flatMap((principal) => typeof principal === "object" && principal ? [principal.AWS].flat() : [principal]);
const resourceMatches = (value, resource) => [value].flat().some((candidate) => patternMatches(candidate, resource));
const policyStatements = (value, label) => {
  let policy = value;
  if (typeof policy === "string") {
    try { policy = JSON.parse(policy); } catch { throw new Error(`${label} is not valid JSON.`); }
  }
  if (!isPlainObject(policy) || !Object.hasOwn(policy, "Version") || !Object.hasOwn(policy, "Statement") || policy.Version !== "2012-10-17"
    || Object.keys(policy).some((key) => !new Set(["Version", "Id", "Statement"]).has(key))
    || Object.hasOwn(policy, "Id") && !isNonEmptyString(policy.Id)
    || !Array.isArray(policy.Statement) || policy.Statement.length === 0
    || !policy.Statement.every((statement, index) => Object.hasOwn(policy.Statement, index) && isPolicyStatement(statement))) throw new Error(`${label} is malformed.`);
  return { policy, statements: policy.Statement };
};

function assertResourcePolicyAllowsRuntime({ policy, principalArn, action, resource, label }) {
  if (!policy) return { resourcePolicySha256: canonicalSha256(null), resourcePolicyAccess: "NO_RESOURCE_POLICY" };
  policyStatements(policy, label);
  throw new Error(`${label} is unsupported for production runtime authorization and fails closed.`);
}

export const isEcrRepositoryPolicyNotFound = (error, { repositoryName, registryId } = {}) => {
  if (!ECR_REPOSITORY_ARN.test(`arn:aws:ecr:${REGION}:${registryId}:repository/${repositoryName}`)) return false;
  const stderr = Buffer.isBuffer(error?.stderr) ? error.stderr.toString("utf8") : typeof error?.stderr === "string" ? error.stderr : "";
  const normalized = stderr.startsWith("\n") && stderr.endsWith("\n") ? stderr.slice(1, -1) : stderr;
  const envelope = normalized.startsWith(AWS_CLI_ENHANCED_ERROR_PREFIX) ? normalized.slice(AWS_CLI_ENHANCED_ERROR_PREFIX.length) : normalized;
  return envelope === `${ECR_REPOSITORY_POLICY_NOT_FOUND_PREFIX}Repository policy does not exist for the repository with name '${repositoryName}' in the registry with id '${registryId}'`;
};

export const assertEcrRepositoryPolicyResponse = (response, { repositoryName, registryId } = {}) => {
  const value = typeof response === "string" ? JSON.parse(response) : response;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(",") !== "policyText,registryId,repositoryName"
    || value.registryId !== registryId || value.repositoryName !== repositoryName || typeof value.policyText !== "string") {
    throw new Error("ECR repository-policy response is incomplete or malformed.");
  }
  policyStatements(value.policyText, `ECR repository policy for ${repositoryName}`);
  return value;
};

async function collectEcrRepositoryPolicyMetadata(dependency, aws, readEcrRepositoryPolicy) {
  const match = ECR_REPOSITORY_ARN.exec(dependency.resource || "");
  if (!match) throw new Error(`Runtime ECR repository identity is invalid for ${dependency.resource}.`);
  const repositoryName = match[1];
  const imageDigest = dependency.context?.imageDigest;
  if (dependency.context?.repositoryName !== repositoryName || !/^sha256:[a-f0-9]{64}$/.test(imageDigest || "")) throw new Error(`Runtime ECR image identity is incomplete for ${dependency.resource}.`);
  let image;
  try { image = await aws(["ecr", "describe-images", "--repository-name", repositoryName, "--image-ids", `imageDigest=${imageDigest}`]); }
  catch { throw new Error(`Runtime ECR image availability is unproven for ${dependency.resource}@${imageDigest}.`); }
  const details = Array.isArray(image?.imageDetails) ? image.imageDetails.filter((value) => value?.imageDigest === imageDigest) : [];
  const detail = details.length === 1 ? details[0] : null;
  if (detail?.registryId !== ACCOUNT || detail?.repositoryName !== repositoryName || detail.imageDigest !== imageDigest) throw new Error(`Runtime ECR image availability is unproven for ${dependency.resource}@${imageDigest}.`);
  let response;
  try {
    response = await (readEcrRepositoryPolicy ? readEcrRepositoryPolicy(repositoryName) : aws(["ecr", "get-repository-policy", "--repository-name", repositoryName]));
  } catch (error) {
    if (!isEcrRepositoryPolicyNotFound(error, { repositoryName, registryId: ACCOUNT })) throw new Error(`Runtime ECR repository-policy state is unavailable for ${dependency.resource}.`);
    const state = { resource: dependency.resource, repositoryName, imageDigest, imageAvailability: "EXISTS", repositoryPolicyState: "NO_POLICY", repositoryPolicySha256: canonicalSha256(null) };
    return Object.freeze({ ...state, metadataSha256: canonicalSha256(state) });
  }
  assertEcrRepositoryPolicyResponse(response, { repositoryName, registryId: ACCOUNT });
  throw new Error(`Runtime ECR repository policy semantics are unsupported for ${dependency.resource} and fail closed.`);
}

function assertKmsKeyPolicyAllowsRuntime({ policy, principalArn, keyArn }) {
  const parsed = policyStatements(policy, `Runtime KMS key policy for ${keyArn}`);
  if (parsed.statements.some((statement) => statement?.Effect === "Deny" || statement?.NotPrincipal || statement?.NotAction || statement?.NotResource)) throw new Error(`Runtime KMS key policy contains unsupported deny or inverse semantics for ${principalArn}.`);
  const access = parsed.statements.some((statement) => statement?.Effect === "Allow" && !statement.Condition && principalValues(statement.Principal).includes(principalArn)
    && actionMatches(statement.Action, "kms:Decrypt") && resourceMatches(statement.Resource, keyArn)) ? "EXACT_ROLE"
    : parsed.statements.some((statement) => statement?.Effect === "Allow" && [statement.Principal?.AWS].flat().includes(`arn:aws:iam::${ACCOUNT}:root`)
      && !statement.Condition && actionMatches(statement.Action, "kms:Decrypt") && resourceMatches(statement.Resource, keyArn)) ? "ACCOUNT_IAM_DELEGATED" : null;
  if (!access) throw new Error(`Runtime KMS key policy does not authorize IAM policy delegation or the exact runtime principal.`);
  return { kmsKeyPolicySha256: canonicalSha256(parsed.policy), kmsKeyPolicyAccess: access };
}

const dependencyId = (value) => canonicalSha256({ principalArn: value.principalArn, action: value.action, resource: value.resource, source: value.source, context: value.context || null });
const assertLivePolicyIdentity = (value) => {
  const { identitySha256, ...body } = value || {};
  if (!Array.isArray(body.roles) || !HEX.test(identitySha256 || "") || canonicalSha256(body) !== identitySha256) throw new Error("Runtime closure live policy identity is incomplete or tampered.");
  return value;
};
export function runtimeDependencyIdentity(candidate, dependencies = deriveEcsRuntimeDependencies(candidate)) {
  return Object.freeze({ candidateCanonicalSha256: canonicalSha256(candidate), candidateFingerprint: taskDefinitionFingerprint(candidate, candidate?.tags || []), dependencySha256: canonicalSha256(dependencies), dependencies });
}

export function runtimeCandidateIdentity(candidate, candidateFileSha256) {
  if (!HEX.test(candidateFileSha256 || "")) throw new Error("Production ECS candidate file SHA-256 is invalid.");
  return Object.freeze({
    candidateFileSha256,
    candidateCanonicalSha256: canonicalSha256(candidate),
    candidateFingerprint: taskDefinitionFingerprint(candidate, candidate?.tags || []),
  });
}

export function buildRuntimeDependencyInventory({ sourceSha, candidate, candidateFileSha256, resourceMetadata, generatedAt = new Date().toISOString() } = {}) {
  if (!SHA.test(sourceSha || "") || !Number.isFinite(Date.parse(generatedAt))) throw new Error("Runtime inventory source identity or timestamp is invalid.");
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  const candidateIdentity = runtimeCandidateIdentity(candidate, candidateFileSha256);
  const dependencySha256 = canonicalSha256(dependencies);
  const body = { schemaVersion: 1, kind: "PRODUCTION_ECS_RUNTIME_DEPENDENCY_INVENTORY", sourceSha, ...candidateIdentity, dependencySha256, dependencies, resourceMetadata, generatedAt };
  return Object.freeze({ ...body, inventorySha256: canonicalSha256(body) });
}

export function assertRuntimeDependencyInventory(inventory, { sourceSha, candidate, candidateFileSha256, resourceMetadata = inventory?.resourceMetadata } = {}) {
  const { inventorySha256, ...body } = inventory || {};
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  const candidateIdentity = runtimeCandidateIdentity(candidate, candidateFileSha256);
  if (inventory?.schemaVersion !== 1 || inventory.kind !== "PRODUCTION_ECS_RUNTIME_DEPENDENCY_INVENTORY" || inventory.sourceSha !== sourceSha
    || !SHA.test(inventory.sourceSha || "") || !Number.isFinite(Date.parse(inventory.generatedAt))
    || inventory.candidateFileSha256 !== candidateIdentity.candidateFileSha256 || inventory.candidateCanonicalSha256 !== candidateIdentity.candidateCanonicalSha256
    || inventory.candidateFingerprint !== candidateIdentity.candidateFingerprint || inventory.dependencySha256 !== canonicalSha256(dependencies)
    || canonicalSha256(inventory.dependencies) !== canonicalSha256(dependencies) || canonicalSha256(inventory.resourceMetadata) !== canonicalSha256(resourceMetadata)
    || !HEX.test(inventorySha256 || "") || canonicalSha256(body) !== inventorySha256) throw new Error("Production ECS runtime dependency inventory is stale, incomplete, or tampered.");
  return inventory;
}

export function signRuntimeDependencyInventory(inventory, { sign, signedAt = new Date().toISOString() } = {}) {
  if (typeof sign !== "function" || !Number.isFinite(Date.parse(signedAt)) || !HEX.test(inventory?.inventorySha256 || "")) throw new Error("Runtime inventory signing inputs are invalid.");
  const binding = { schemaVersion: 1, kind: "SIGNED_PRODUCTION_ECS_RUNTIME_DEPENDENCY_INVENTORY", inventorySha256: inventory.inventorySha256, keyArn: STAGE_B.approvalKmsKeyArn, signingAlgorithm: STAGE_B_APPROVAL_ALGORITHM, signedAt };
  const signedBindingSha256 = canonicalSha256(binding);
  const signatureBase64 = sign({ digest: Buffer.from(signedBindingSha256, "hex"), keyArn: binding.keyArn, signingAlgorithm: binding.signingAlgorithm });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64 || "")) throw new Error("Runtime inventory signature is invalid.");
  const body = { ...binding, inventory, signedBindingSha256, signatureBase64 };
  return Object.freeze({ ...body, envelopeSha256: canonicalSha256(body) });
}

export function assertSignedRuntimeDependencyInventory(envelope, { sourceSha, candidate, candidateFileSha256, verify, now = Date.now() } = {}) {
  const { envelopeSha256, ...body } = envelope || {};
  const nowMs = Number(now); const signedAtMs = Date.parse(envelope?.signedAt);
  const binding = { schemaVersion: envelope?.schemaVersion, kind: envelope?.kind, inventorySha256: envelope?.inventory?.inventorySha256, keyArn: envelope?.keyArn, signingAlgorithm: envelope?.signingAlgorithm, signedAt: envelope?.signedAt };
  if (envelope?.schemaVersion !== 1 || envelope.kind !== "SIGNED_PRODUCTION_ECS_RUNTIME_DEPENDENCY_INVENTORY" || envelope.keyArn !== STAGE_B.approvalKmsKeyArn
    || envelope.signingAlgorithm !== STAGE_B_APPROVAL_ALGORITHM || !HEX.test(envelopeSha256 || "") || canonicalSha256(body) !== envelopeSha256
    || !HEX.test(envelope.signedBindingSha256 || "") || canonicalSha256(binding) !== envelope.signedBindingSha256
    || !Number.isFinite(nowMs) || !Number.isFinite(signedAtMs) || signedAtMs > nowMs + CLOCK_SKEW_MS || nowMs - signedAtMs > RUNTIME_AUTHORIZATION_MAX_AGE_MS
    || typeof verify !== "function" || verify({ digest: Buffer.from(envelope.signedBindingSha256 || "", "hex"), signature: Buffer.from(envelope.signatureBase64 || "", "base64"), keyArn: envelope.keyArn, signingAlgorithm: envelope.signingAlgorithm }) !== true) {
    throw new Error("Runtime inventory signature is invalid, stale, or bound to different bytes.");
  }
  return assertRuntimeDependencyInventory(envelope.inventory, { sourceSha, candidate, candidateFileSha256 });
}

export function addEncryptionDependencies(candidate, dependencies, resourceMetadata) {
  for (const dependency of dependencies.filter(({ action, resource }) => action.startsWith("ecr:") && resource !== "*")) {
    const metadata = resourceMetadata?.[dependency.resource];
    const expected = metadata && canonicalSha256({ resource: metadata.resource, repositoryName: metadata.repositoryName, imageDigest: metadata.imageDigest, imageAvailability: metadata.imageAvailability, repositoryPolicyState: metadata.repositoryPolicyState, repositoryPolicySha256: metadata.repositoryPolicySha256 });
    if (!metadata || metadata.resource !== dependency.resource || metadata.repositoryPolicyState !== "NO_POLICY"
      || metadata.repositoryName !== dependency.context?.repositoryName || metadata.imageDigest !== dependency.context?.imageDigest || metadata.imageAvailability !== "EXISTS"
      || metadata.repositoryPolicySha256 !== canonicalSha256(null) || metadata.metadataSha256 !== expected) throw new Error(`Runtime ECR image or repository-policy metadata is missing or stale for ${dependency.resource}.`);
  }
  for (const dependency of dependencies.filter(({ action }) => action.startsWith("logs:"))) {
    const groupArn = dependency.resource.split(":log-stream:")[0]; const metadata = resourceMetadata?.[groupArn];
    const createGroup = dependencies.some(({ action, resource }) => action === "logs:CreateLogGroup" && resource === groupArn);
    const expected = metadata && canonicalSha256({ resource: groupArn, logGroupName: metadata.logGroupName, availability: metadata.availability, createGroup: metadata.createGroup });
    if (!metadata || metadata.resource !== groupArn || metadata.metadataSha256 !== expected || metadata.createGroup !== createGroup
      || (metadata.availability !== "EXISTENCE_PROVEN" && !(createGroup && metadata.availability === "INTENTIONALLY_CREATED_BY_RUNTIME"))) throw new Error(`Runtime awslogs group metadata is missing or stale for ${groupArn}.`);
  }
  const expanded = new Map(dependencies.map((dependency) => [dependency.dependencyId, dependency]));
  for (const dependency of dependencies.filter(({ action }) => ["secretsmanager:GetSecretValue", "ssm:GetParameters"].includes(action))) {
    const metadata = resourceMetadata?.[dependency.resource];
    if (!metadata || metadata.resource !== dependency.resource || !["AWS_MANAGED", "CUSTOMER_MANAGED"].includes(metadata.encryption)
      || !HEX.test(metadata.metadataSha256 || "") || !HEX.test(metadata.resourcePolicySha256 || "")
      || metadata.resourcePolicyAccess !== "NO_RESOURCE_POLICY" || metadata.resourcePolicySha256 !== canonicalSha256(null)) throw new Error(`Runtime encryption metadata is missing for ${dependency.resource}.`);
    if (dependency.action === "secretsmanager:GetSecretValue") {
      const expected = canonicalSha256({ ARN: metadata.resource, KmsKeyId: metadata.kmsKeyArn || null, availability: metadata.availability, deletedDate: metadata.deletedDate,
        versionIdsToStages: metadata.versionIdsToStages, secretVersions: metadata.secretVersions, selectorResolutions: metadata.selectorResolutions });
      const selector = dependency.context?.secretSelector;
      const resolution = metadata.selectorResolutions?.find((value) => canonicalSha256(value.selector) === canonicalSha256(selector));
      if (metadata.availability !== "AVAILABLE" || metadata.deletedDate !== null || metadata.metadataSha256 !== expected || !resolution?.resolvedVersionId
        || resolution.jsonKeyState !== (selector?.jsonKey ? "PRESENT" : "NOT_REQUESTED"))
        throw new Error(`Runtime secret availability or selector metadata is missing or stale for ${dependency.resource}.`);
    } else {
      const name = dependency.resource.split(":parameter/")[1];
      const expected = canonicalSha256({ ARN: metadata.resource, Name: name, Type: metadata.parameterType, KeyId: metadata.parameterKeyId,
        Version: metadata.parameterVersion, DataType: metadata.parameterDataType, Tier: metadata.parameterTier });
      if (!["String", "StringList", "SecureString"].includes(metadata.parameterType) || !Number.isInteger(metadata.parameterVersion)
        || metadata.parameterVersion < 1 || metadata.metadataSha256 !== expected) throw new Error(`Runtime SSM parameter metadata is missing or stale for ${dependency.resource}.`);
    }
    if (metadata.encryption === "CUSTOMER_MANAGED") {
      if (!SOURCE_OWNED_RUNTIME_KMS_KEYS.has(metadata.kmsKeyArn) || !HEX.test(metadata.kmsKeyPolicySha256 || "")
        || !["EXACT_ROLE", "ACCOUNT_IAM_DELEGATED"].includes(metadata.kmsKeyPolicyAccess)) throw new Error(`Runtime KMS identity or key-policy authority is invalid for ${dependency.resource}.`);
      const service = dependency.action === "ssm:GetParameters" ? "ssm" : "secretsmanager";
      const value = { consumer: dependency.consumer, principalArn: dependency.principalArn, action: "kms:Decrypt", resource: metadata.kmsKeyArn, source: `${dependency.source}.kms`, context: { "kms:ViaService": `${service}.${REGION}.amazonaws.com` } };
      expanded.set(dependencyId(value), Object.freeze({ ...value, dependencyId: dependencyId(value) }));
    }
  }
  return Object.freeze([...expanded.values()].sort((a, b) => a.dependencyId.localeCompare(b.dependencyId)));
}

export function buildRuntimeConsumabilityEvidence({ sourceSha, candidate, resourceMetadata, sourcePolicyOwnership, livePolicyIdentity, simulations, generatedAt = new Date().toISOString() } = {}) {
  if (!SHA.test(sourceSha || "") || !Number.isFinite(Date.parse(generatedAt))) throw new Error("Runtime closure source identity or timestamp is invalid.");
  assertLivePolicyIdentity(livePolicyIdentity);
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  const identity = runtimeDependencyIdentity(candidate, dependencies);
  const results = dependencies.map((dependency) => {
    const owner = sourcePolicyOwnership?.[dependency.dependencyId];
    const simulation = simulations?.[dependency.dependencyId];
    const liveRole = livePolicyIdentity?.roles?.find(({ principalArn }) => principalArn === dependency.principalArn);
    if (!owner || owner.principalArn !== dependency.principalArn || owner.action !== dependency.action || owner.resource !== dependency.resource || owner.sourcePolicyPresent !== true) throw new Error(`Runtime dependency lacks source policy ownership: ${dependency.dependencyId}.`);
    if (!liveRole || liveRole.trustPolicySha256 !== ECS_TASK_TRUST_SHA256 || (owner.policyName && !liveRole.inlinePolicies?.some(({ policyName, policySha256 }) => policyName === owner.policyName && policySha256 === owner.sourcePolicySha256))
      || (owner.policyArn && !liveRole.attachedPolicies?.some(({ policyArn }) => policyArn === owner.policyArn))) throw new Error(`Runtime dependency source policy is not present on the exact live principal: ${dependency.dependencyId}.`);
    if (!simulation || simulation.principalArn !== dependency.principalArn || simulation.action !== dependency.action || simulation.resource !== dependency.resource || simulation.decision !== "allowed") throw new Error(`Runtime dependency is not allowed by live IAM simulation: ${dependency.dependencyId}.`);
    return { dependencyId: dependency.dependencyId, sourcePolicySha256: owner.sourcePolicySha256, liveSimulation: "allowed" };
  });
  const body = { schemaVersion: 1, kind: "PRODUCTION_ECS_RUNTIME_CONSUMABILITY", sourceSha, candidateCanonicalSha256: identity.candidateCanonicalSha256, candidateFingerprint: identity.candidateFingerprint, dependencySha256: identity.dependencySha256, dependencies, results, resourceMetadata, livePolicyIdentity, generatedAt };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertRuntimeConsumabilityEvidence(evidence, { sourceSha, candidate, livePolicyIdentity, resourceMetadata } = {}) {
  const { evidenceSha256, ...body } = evidence || {};
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  const identity = runtimeDependencyIdentity(candidate, dependencies);
  assertLivePolicyIdentity(livePolicyIdentity);
  const ownership = sourceRuntimePolicyOwnership(candidate, resourceMetadata);
  if (evidence?.schemaVersion !== 1 || evidence.kind !== "PRODUCTION_ECS_RUNTIME_CONSUMABILITY" || evidence.sourceSha !== sourceSha || !SHA.test(sourceSha || "")
    || evidence.candidateCanonicalSha256 !== identity.candidateCanonicalSha256 || evidence.candidateFingerprint !== identity.candidateFingerprint || evidence.dependencySha256 !== identity.dependencySha256
    || canonicalSha256(evidence.dependencies) !== canonicalSha256(dependencies) || canonicalSha256(evidence.resourceMetadata) !== canonicalSha256(resourceMetadata)
    || canonicalSha256(evidence.livePolicyIdentity) !== canonicalSha256(livePolicyIdentity)
    || !Array.isArray(evidence.results) || evidence.results.length !== dependencies.length || evidence.results.some((result, index) => {
      const dependency = dependencies[index]; const owner = ownership[dependency.dependencyId];
      const role = livePolicyIdentity.roles.find(({ principalArn }) => principalArn === dependency.principalArn);
      return result.dependencyId !== dependency.dependencyId || result.liveSimulation !== "allowed" || result.sourcePolicySha256 !== owner?.sourcePolicySha256
        || role?.trustPolicySha256 !== ECS_TASK_TRUST_SHA256
        || (owner?.policyName && !role.inlinePolicies?.some(({ policyName, policySha256 }) => policyName === owner.policyName && policySha256 === owner.sourcePolicySha256))
        || (owner?.policyArn && !role.attachedPolicies?.some(({ policyArn }) => policyArn === owner.policyArn));
    })
    || !HEX.test(evidenceSha256 || "") || canonicalSha256(body) !== evidenceSha256) throw new Error("Production ECS runtime consumability evidence is stale, incomplete, or tampered.");
  return Object.freeze({ status: "PASS", evidenceSha256, candidateCanonicalSha256: identity.candidateCanonicalSha256, candidateFingerprint: identity.candidateFingerprint, dependencySha256: identity.dependencySha256, executionRoleRuntimeClosure: "PASS", taskRoleRuntimeClosure: "PASS", secretReferenceClosure: "PASS", kmsRuntimeClosure: "PASS", imageRuntimeClosure: "PASS" });
}

export function signRuntimeConsumabilityEvidence(evidence, { sign, signedAt = new Date().toISOString() } = {}) {
  if (typeof sign !== "function" || !Number.isFinite(Date.parse(signedAt)) || !HEX.test(evidence?.evidenceSha256 || "")) throw new Error("Runtime closure signing inputs are invalid.");
  const binding = { schemaVersion: 2, kind: "SIGNED_PRODUCTION_ECS_RUNTIME_CONSUMABILITY", evidenceSha256: evidence.evidenceSha256, keyArn: STAGE_B.approvalKmsKeyArn, signingAlgorithm: STAGE_B_APPROVAL_ALGORITHM, signedAt };
  const signedBindingSha256 = canonicalSha256(binding);
  const signatureBase64 = sign({ digest: Buffer.from(signedBindingSha256, "hex"), keyArn: STAGE_B.approvalKmsKeyArn, signingAlgorithm: STAGE_B_APPROVAL_ALGORITHM });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64 || "")) throw new Error("Runtime closure signature is invalid.");
  const body = { schemaVersion: binding.schemaVersion, kind: binding.kind, evidence, keyArn: binding.keyArn, signingAlgorithm: binding.signingAlgorithm, signedAt, signedBindingSha256, signatureBase64 };
  return Object.freeze({ ...body, envelopeSha256: canonicalSha256(body) });
}

export function assertSignedRuntimeConsumabilityEvidence(envelope, { sourceSha, candidate, livePolicyIdentity, resourceMetadata, verify, now = Date.now() } = {}) {
  assertRuntimeConsumabilityEnvelopeSignature(envelope, { verify });
  const nowMs = Number(now); const signedAtMs = Date.parse(envelope?.signedAt);
  if (!Number.isFinite(nowMs) || !Number.isFinite(signedAtMs) || signedAtMs > nowMs + CLOCK_SKEW_MS || nowMs - signedAtMs > RUNTIME_AUTHORIZATION_MAX_AGE_MS) throw new Error("Runtime closure signature is invalid, stale, or bound to different bytes.");
  return Object.freeze({ ...assertRuntimeConsumabilityEvidence(envelope.evidence, { sourceSha, candidate, livePolicyIdentity, resourceMetadata }), authorizationSignedAt: envelope.signedAt, liveVerifiedAt: new Date(nowMs).toISOString() });
}

export function assertRuntimeConsumabilityEnvelopeSignature(envelope, { verify } = {}) {
  const { envelopeSha256, ...body } = envelope || {};
  const { evidenceSha256, ...evidenceBody } = envelope?.evidence || {};
  const binding = { schemaVersion: envelope?.schemaVersion, kind: envelope?.kind, evidenceSha256: envelope?.evidence?.evidenceSha256, keyArn: envelope?.keyArn, signingAlgorithm: envelope?.signingAlgorithm, signedAt: envelope?.signedAt };
  if (envelope?.schemaVersion !== 2 || envelope.kind !== "SIGNED_PRODUCTION_ECS_RUNTIME_CONSUMABILITY" || envelope.keyArn !== STAGE_B.approvalKmsKeyArn
    || envelope.signingAlgorithm !== STAGE_B_APPROVAL_ALGORITHM || !HEX.test(envelopeSha256 || "") || canonicalSha256(body) !== envelopeSha256
    || !HEX.test(evidenceSha256 || "") || canonicalSha256(evidenceBody) !== evidenceSha256
    || !HEX.test(envelope.signedBindingSha256 || "") || canonicalSha256(binding) !== envelope.signedBindingSha256
    || typeof verify !== "function" || verify({ digest: Buffer.from(envelope.signedBindingSha256 || "", "hex"), signature: Buffer.from(envelope.signatureBase64 || "", "base64"), keyArn: envelope.keyArn, signingAlgorithm: envelope.signingAlgorithm }) !== true) {
    throw new Error("Runtime closure signature is invalid or bound to different bytes.");
  }
  return envelope;
}

export function assertFreshRuntimeConsumabilityVerification(verification, { evidenceSha256, now = Date.now() } = {}) {
  const nowMs = Number(now); const verifiedAtMs = Date.parse(verification?.liveVerifiedAt);
  if (verification?.status !== "PASS" || verification.evidenceSha256 !== evidenceSha256 || !HEX.test(evidenceSha256 || "")
    || !Number.isFinite(nowMs) || !Number.isFinite(verifiedAtMs) || verifiedAtMs > nowMs || nowMs - verifiedAtMs > LIVE_RUNTIME_EVIDENCE_MAX_AGE_MS) {
    throw new Error("Recovery candidate live runtime dependency verification is stale or invalid.");
  }
  return verification;
}

export function buildLegacyExecutionRuntimePolicy(candidate, resourceMetadata) {
  const roleArn = candidate?.executionRoleArn;
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata).filter(({ principalArn }) => principalArn === roleArn);
  const secretResources = [...new Set(dependencies.filter(({ action }) => action === "secretsmanager:GetSecretValue").map(({ resource }) => resource))].sort();
  if (!secretResources.length || secretResources.some((resource) => !SECRET_RESOURCE.test(resource) || resource.includes("*"))) throw new Error("Legacy execution secret policy requires exact secret ARNs.");
  const statements = [{ Sid: "ReadOnlyExactTaskDefinitionSecrets", Effect: "Allow", Action: ["secretsmanager:GetSecretValue"], Resource: secretResources }];
  const createGroups = [...new Set(dependencies.filter(({ action }) => action === "logs:CreateLogGroup").map(({ resource }) => resource))].sort();
  if (createGroups.length) statements.push({ Sid: "CreateOnlyExactTaskLogGroups", Effect: "Allow", Action: ["logs:CreateLogGroup"], Resource: createGroups });
  const kmsGroups = Map.groupBy(dependencies.filter(({ action }) => action === "kms:Decrypt"), ({ context }) => context?.["kms:ViaService"]);
  for (const [viaService, values] of [...kmsGroups].sort(([left], [right]) => left.localeCompare(right))) {
    if (!/^(?:secretsmanager|ssm)\.eu-west-2\.amazonaws\.com$/.test(viaService || "")) throw new Error("Runtime KMS dependency lacks an exact ViaService context.");
    statements.push({ Sid: viaService.startsWith("ssm.") ? "DecryptOnlyExactSsmRuntimeKeys" : "DecryptOnlyExactSecretRuntimeKeys", Effect: "Allow", Action: ["kms:Decrypt"], Resource: [...new Set(values.map(({ resource }) => resource))].sort(), Condition: { StringEquals: { "kms:ViaService": viaService } } });
  }
  if (statements.some(({ Resource }) => Resource.some((resource) => resource.includes("*")))) throw new Error("Legacy runtime policy cannot broaden runtime resources with wildcards.");
  return Object.freeze({ Version: "2012-10-17", Statement: statements });
}

export function sourceRuntimePolicyOwnership(candidate, resourceMetadata) {
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  const generated = buildLegacyExecutionRuntimePolicy(candidate, resourceMetadata);
  const generatedSha256 = canonicalSha256(generated);
  const managedSha256 = canonicalSha256({ policyArn: AWS_MANAGED_EXECUTION_POLICY, contract: "AWS ECS task execution image pull and log stream delivery" });
  return Object.fromEntries(dependencies.map((dependency) => {
    const generatedAction = ["secretsmanager:GetSecretValue", "logs:CreateLogGroup", "kms:Decrypt"].includes(dependency.action);
    const supportedManagedAction = ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "logs:CreateLogStream", "logs:PutLogEvents"].includes(dependency.action);
    if (!generatedAction && !supportedManagedAction) throw new Error(`Production source policy ownership is unclassified for ${dependency.action}.`);
    return [dependency.dependencyId, { principalArn: dependency.principalArn, action: dependency.action, resource: dependency.resource, sourcePolicyPresent: true, sourcePolicySha256: generatedAction ? generatedSha256 : managedSha256, ...(generatedAction ? { policyName: LEGACY_RUNTIME_POLICY_NAME } : { policyArn: AWS_MANAGED_EXECUTION_POLICY }) }];
  }));
}

async function collectSecretVersions(secretArn, aws) {
  const versions = new Map(); const tokens = new Set(); let nextToken;
  for (let page = 0; page < SECRET_VERSION_MAX_PAGES; page += 1) {
    const args = ["secretsmanager", "list-secret-version-ids", "--secret-id", secretArn, "--include-deprecated",
      "--page-size", String(SECRET_VERSION_PAGE_SIZE), "--max-items", String(SECRET_VERSION_PAGE_SIZE), ...(nextToken ? ["--starting-token", nextToken] : [])];
    const response = await aws(args);
    if (!response || typeof response !== "object" || Array.isArray(response) || !Array.isArray(response.Versions) || Object.hasOwn(response, "nextToken"))
      throw new Error(`Secrets Manager version census is malformed for ${secretArn}.`);
    for (const value of response.Versions) {
      const stages = value?.VersionStages ?? [];
      if (!SECRET_VERSION_ID.test(value?.VersionId || "") || !Array.isArray(stages) || new Set(stages).size !== stages.length
        || stages.some((stage) => typeof stage !== "string" || !SECRET_STAGE.test(stage)) || versions.has(value.VersionId))
        throw new Error(`Secrets Manager version census is malformed or conflicting for ${secretArn}.`);
      versions.set(value.VersionId, Object.freeze({ versionId: value.VersionId, versionStages: Object.freeze([...stages].sort()) }));
      if (versions.size > SECRET_VERSION_MAX_RESULTS) throw new Error(`Secrets Manager version census exceeds its bounded result limit for ${secretArn}.`);
    }
    const token = response.NextToken;
    if (token === undefined || token === null) return Object.freeze([...versions.values()].sort((left, right) => left.versionId.localeCompare(right.versionId)));
    if (typeof token !== "string" || !token || tokens.has(token)) throw new Error(`Secrets Manager version census pagination token is malformed or cyclic for ${secretArn}.`);
    tokens.add(token); nextToken = token;
  }
  throw new Error(`Secrets Manager version census exceeds its bounded page limit for ${secretArn}.`);
}

async function collectLogGroup(groupArn, createGroup, aws) {
  const match = LOG_GROUP_ARN.exec(groupArn); if (!match) throw new Error(`Runtime awslogs group identity is invalid for ${groupArn}.`);
  const logGroupName = match[1]; const groups = new Map(); const tokens = new Set(); let nextToken;
  for (let page = 0; page < 20; page += 1) {
    const args = ["logs", "describe-log-groups", "--log-group-name-prefix", logGroupName, "--page-size", "50", "--max-items", "50", ...(nextToken ? ["--starting-token", nextToken] : [])];
    const response = await aws(args);
    if (!response || !Array.isArray(response.logGroups) || Object.hasOwn(response, "NextToken")) throw new Error(`Runtime awslogs group census is malformed for ${groupArn}.`);
    for (const group of response.logGroups) {
      if (typeof group?.logGroupName !== "string" || typeof group?.logGroupArn !== "string" || groups.has(group.logGroupName)) throw new Error(`Runtime awslogs group census is malformed or conflicting for ${groupArn}.`);
      groups.set(group.logGroupName, group.logGroupArn);
    }
    const token = response.nextToken;
    if (token == null) break;
    if (typeof token !== "string" || !token || tokens.has(token)) throw new Error(`Runtime awslogs pagination token is malformed or cyclic for ${groupArn}.`);
    tokens.add(token); nextToken = token;
    if (page === 19) throw new Error(`Runtime awslogs group census exceeds its bounded page limit for ${groupArn}.`);
  }
  const exists = groups.get(logGroupName) === groupArn;
  if (!exists && !createGroup) throw new Error(`Runtime awslogs group does not exist for ${groupArn}.`);
  const state = { resource: groupArn, logGroupName, availability: exists ? "EXISTENCE_PROVEN" : "INTENTIONALLY_CREATED_BY_RUNTIME", createGroup };
  return Object.freeze({ ...state, metadataSha256: canonicalSha256(state) });
}

export async function collectRuntimeResourceMetadata(candidate, aws, { readKmsKey, readEcrRepositoryPolicy } = {}) {
  if (typeof aws !== "function") throw new Error("Runtime closure requires an authenticated AWS reader.");
  const metadata = {};
  const dependencies = deriveEcsRuntimeDependencies(candidate);
  for (const dependency of dependencies.filter(({ action, resource }) => action.startsWith("ecr:") && resource !== "*")) {
    if (!metadata[dependency.resource]) metadata[dependency.resource] = await collectEcrRepositoryPolicyMetadata(dependency, aws, readEcrRepositoryPolicy);
  }
  for (const dependency of dependencies.filter(({ action }) => action.startsWith("logs:"))) {
    const groupArn = dependency.resource.split(":log-stream:")[0];
    if (!metadata[groupArn]) metadata[groupArn] = await collectLogGroup(groupArn, dependencies.some(({ action, resource }) => action === "logs:CreateLogGroup" && resource === groupArn), aws);
  }
  for (const dependency of dependencies) {
    if (metadata[dependency.resource] || !["secretsmanager:GetSecretValue", "ssm:GetParameters"].includes(dependency.action)) continue;
    if (dependency.action === "secretsmanager:GetSecretValue") {
      const response = await aws(["secretsmanager", "describe-secret", "--secret-id", dependency.resource]);
      if (response?.ARN !== dependency.resource || response.DeletedDate != null || (response.KmsKeyId && !/^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]+$/.test(response.KmsKeyId))) throw new Error(`Secrets Manager resource is unavailable or metadata is incomplete for ${dependency.resource}.`);
      const secretVersions = await collectSecretVersions(dependency.resource, aws);
      const versions = response.VersionIdsToStages;
      if (!versions || typeof versions !== "object" || Array.isArray(versions)) throw new Error(`Secrets Manager version metadata is incomplete for ${dependency.resource}.`);
      const stageOwners = new Map(); const versionIdsToStages = {};
      for (const [versionId, stages] of Object.entries(versions).sort(([left], [right]) => left.localeCompare(right))) {
        if (!SECRET_VERSION_ID.test(versionId) || !Array.isArray(stages) || !stages.length || new Set(stages).size !== stages.length
          || stages.some((stage) => typeof stage !== "string" || !SECRET_STAGE.test(stage) || stageOwners.has(stage))) throw new Error(`Secrets Manager version metadata is malformed or ambiguous for ${dependency.resource}.`);
        stages.forEach((stage) => stageOwners.set(stage, versionId));
        versionIdsToStages[versionId] = [...stages].sort();
      }
      const listedLabels = Object.fromEntries(secretVersions.filter(({ versionStages }) => versionStages.length).map(({ versionId, versionStages }) => [versionId, versionStages]));
      if (canonicalSha256(listedLabels) !== canonicalSha256(versionIdsToStages)) throw new Error(`Secrets Manager version metadata sources disagree for ${dependency.resource}.`);
      const existingVersionIds = new Set(secretVersions.map(({ versionId }) => versionId));
      const selectorDependencies = dependencies.filter((value) => value.action === "secretsmanager:GetSecretValue" && value.resource === dependency.resource);
      const selectorResolutions = [];
      for (const { context } of selectorDependencies) {
        const selector = context?.secretSelector;
        if (!selector) throw new Error(`Secrets Manager selector metadata is missing for ${dependency.resource}.`);
        const stage = selector.versionStage || (selector.selectorMode === "AWSCURRENT" ? "AWSCURRENT" : null);
        const stageVersion = stage ? stageOwners.get(stage) : null;
        const idExists = selector.versionId ? existingVersionIds.has(selector.versionId) : false;
        const resolvedVersionId = selector.versionId || stageVersion;
        if ((stage && !stageVersion) || (selector.versionId && !idExists) || (stageVersion && selector.versionId && stageVersion !== selector.versionId) || !resolvedVersionId)
          throw new Error(`Secrets Manager selector is not resolvable for ${dependency.resource}.`);
        let jsonKeyState = "NOT_REQUESTED";
        if (selector.jsonKey) {
          let selected;
          try { selected = await aws(["secretsmanager", "get-secret-value", "--secret-id", dependency.resource, "--version-id", resolvedVersionId]); }
          catch { throw new Error(`Secrets Manager JSON-key consumability is unproven for ${dependency.resource}.`); }
          let parsed;
          try { parsed = typeof selected?.SecretString === "string" ? JSON.parse(selected.SecretString) : null; } catch { throw new Error(`Secrets Manager JSON-key consumability is unproven for ${dependency.resource}.`); }
          if (selected?.ARN !== dependency.resource || selected.VersionId !== resolvedVersionId || !parsed || Array.isArray(parsed) || typeof parsed !== "object" || !Object.hasOwn(parsed, selector.jsonKey))
            throw new Error(`Secrets Manager JSON-key consumability is unproven for ${dependency.resource}.`);
          jsonKeyState = "PRESENT";
        }
        selectorResolutions.push({ selector, resolvedVersionId, resolvedVersionStage: stage, jsonKeyState });
      }
      selectorResolutions.sort((left, right) => canonicalSha256(left.selector).localeCompare(canonicalSha256(right.selector)));
      const resourcePolicyResponse = await aws(["secretsmanager", "get-resource-policy", "--secret-id", dependency.resource]);
      if (resourcePolicyResponse?.ARN !== dependency.resource) throw new Error(`Secrets Manager resource-policy readback is incomplete for ${dependency.resource}.`);
      const resourcePolicy = assertResourcePolicyAllowsRuntime({ policy: resourcePolicyResponse.ResourcePolicy || null, principalArn: dependency.principalArn, action: dependency.action, resource: dependency.resource, label: `Secrets Manager resource policy for ${dependency.resource}` });
      let kms = {};
      if (response.KmsKeyId) {
        if (!SOURCE_OWNED_RUNTIME_KMS_KEYS.has(response.KmsKeyId)) throw new Error(`Runtime KMS key is not source-owned for ${dependency.resource}.`);
        if (typeof readKmsKey !== "function") throw new Error(`Runtime KMS policy reader is required for ${dependency.resource}.`);
        const { metadata: key, policy: keyPolicy } = await readKmsKey(response.KmsKeyId);
        if (key?.Arn !== response.KmsKeyId || key.KeyState !== "Enabled" || key.KeyUsage !== "ENCRYPT_DECRYPT") throw new Error(`Runtime KMS key is unavailable for ${dependency.resource}.`);
        kms = assertKmsKeyPolicyAllowsRuntime({ policy: keyPolicy, principalArn: dependency.principalArn, keyArn: response.KmsKeyId });
      }
      const state = { ARN: response.ARN, KmsKeyId: response.KmsKeyId || null, availability: "AVAILABLE", deletedDate: null, versionIdsToStages, secretVersions, selectorResolutions };
      metadata[dependency.resource] = { resource: dependency.resource, encryption: response.KmsKeyId ? "CUSTOMER_MANAGED" : "AWS_MANAGED", kmsKeyArn: response.KmsKeyId || null, availability: state.availability, deletedDate: state.deletedDate, versionIdsToStages, secretVersions, selectorResolutions, ...resourcePolicy, ...kms, metadataSha256: canonicalSha256(state) };
    } else {
      const response = await aws(["ssm", "describe-parameters", "--parameter-filters", `Key=Name,Option=Equals,Values=${dependency.resource.split(":parameter/")[1]}`]);
      const parameters = Array.isArray(response?.Parameters) ? response.Parameters.filter(({ ARN }) => ARN === dependency.resource) : [];
      const parameter = parameters.length === 1 && response.NextToken == null ? parameters[0] : null;
      if (!parameter || !["String", "StringList", "SecureString"].includes(parameter.Type) || !Number.isInteger(parameter.Version) || parameter.Version < 1
        || typeof parameter.Name !== "string" || `arn:aws:ssm:${REGION}:${ACCOUNT}:parameter/${parameter.Name}` !== dependency.resource) throw new Error(`SSM metadata is incomplete for ${dependency.resource}.`);
      const custom = parameter.Type === "SecureString" && parameter.KeyId && !/^alias\/aws\/ssm$/.test(parameter.KeyId);
      if (custom && !/^arn:aws:kms:eu-west-2:368992683803:key\/[a-f0-9-]+$/.test(parameter.KeyId)) throw new Error(`SSM custom KMS identity is invalid for ${dependency.resource}.`);
      let kms = {};
      if (custom) {
        if (!SOURCE_OWNED_RUNTIME_KMS_KEYS.has(parameter.KeyId)) throw new Error(`Runtime KMS key is not source-owned for ${dependency.resource}.`);
        if (typeof readKmsKey !== "function") throw new Error(`Runtime KMS policy reader is required for ${dependency.resource}.`);
        const { metadata: key, policy: keyPolicy } = await readKmsKey(parameter.KeyId);
        if (key?.Arn !== parameter.KeyId || key.KeyState !== "Enabled" || key.KeyUsage !== "ENCRYPT_DECRYPT") throw new Error(`Runtime KMS key is unavailable for ${dependency.resource}.`);
        kms = assertKmsKeyPolicyAllowsRuntime({ policy: keyPolicy, principalArn: dependency.principalArn, keyArn: parameter.KeyId });
      }
      metadata[dependency.resource] = { resource: dependency.resource, encryption: custom ? "CUSTOMER_MANAGED" : "AWS_MANAGED", kmsKeyArn: custom ? parameter.KeyId : null, parameterKeyId: parameter.KeyId || null, parameterType: parameter.Type,
        parameterVersion: parameter.Version, parameterDataType: parameter.DataType || "text", parameterTier: parameter.Tier || "Standard",
        resourcePolicySha256: canonicalSha256(null), resourcePolicyAccess: "NO_RESOURCE_POLICY", ...kms,
        metadataSha256: canonicalSha256({ ARN: parameter.ARN, Name: parameter.Name, Type: parameter.Type, KeyId: parameter.KeyId || null, Version: parameter.Version, DataType: parameter.DataType || "text", Tier: parameter.Tier || "Standard" }) };
    }
  }
  return Object.freeze(Object.fromEntries(Object.entries(metadata).sort(([left], [right]) => left.localeCompare(right))));
}

export async function refreshRuntimeResourceMetadata(candidate, signedMetadata, aws, readKmsKey, readEcrRepositoryPolicy) {
  const current = { ...await collectRuntimeResourceMetadata(candidate, aws, { readKmsKey, readEcrRepositoryPolicy }) };
  if (canonicalSha256(current) !== canonicalSha256(signedMetadata)) throw new Error("Runtime resource metadata changed after administrator authorization.");
  return Object.freeze(current);
}

export async function collectLiveRolePolicyIdentity(principalArns, aws) {
  if (typeof aws !== "function") throw new Error("Runtime closure requires an authenticated IAM reader.");
  const roles = [];
  for (const principalArn of [...new Set(principalArns)].sort()) {
    if (!ROLE_ARN.test(principalArn || "")) throw new Error("Runtime closure principal ARN is invalid.");
    const roleName = principalArn.split("/").at(-1);
    const role = (await aws(["iam", "get-role", "--role-name", roleName]))?.Role;
    if (role?.Arn !== principalArn || canonicalSha256(role.AssumeRolePolicyDocument) !== ECS_TASK_TRUST_SHA256) throw new Error(`Runtime role identity or ECS task trust is incomplete for ${principalArn}.`);
    const inlineNames = (await aws(["iam", "list-role-policies", "--role-name", roleName]))?.PolicyNames;
    const attached = (await aws(["iam", "list-attached-role-policies", "--role-name", roleName]))?.AttachedPolicies;
    if (!Array.isArray(inlineNames) || !Array.isArray(attached)) throw new Error(`Runtime role policy census is incomplete for ${principalArn}.`);
    const inlinePolicies = [];
    for (const policyName of [...inlineNames].sort()) {
      const response = await aws(["iam", "get-role-policy", "--role-name", roleName, "--policy-name", policyName]);
      if (response?.RoleName !== roleName || response?.PolicyName !== policyName || !response.PolicyDocument) throw new Error(`Runtime inline policy readback is incomplete for ${principalArn}.`);
      inlinePolicies.push({ policyName, policySha256: canonicalSha256(response.PolicyDocument) });
    }
    const attachedPolicies = [];
    for (const item of [...attached].sort((left, right) => left.PolicyArn.localeCompare(right.PolicyArn))) {
      const policy = (await aws(["iam", "get-policy", "--policy-arn", item.PolicyArn]))?.Policy;
      if (policy?.Arn !== item.PolicyArn || !policy.DefaultVersionId) throw new Error(`Runtime attached policy identity is incomplete for ${principalArn}.`);
      const version = (await aws(["iam", "get-policy-version", "--policy-arn", item.PolicyArn, "--version-id", policy.DefaultVersionId]))?.PolicyVersion;
      if (!version?.Document) throw new Error(`Runtime attached policy document is incomplete for ${principalArn}.`);
      attachedPolicies.push({ policyArn: item.PolicyArn, defaultVersionId: policy.DefaultVersionId, policySha256: canonicalSha256(version.Document) });
    }
    let permissionsBoundary = null;
    if (role.PermissionsBoundary?.PermissionsBoundaryArn) {
      const policyArn = role.PermissionsBoundary.PermissionsBoundaryArn;
      const policy = (await aws(["iam", "get-policy", "--policy-arn", policyArn]))?.Policy;
      if (policy?.Arn !== policyArn || !policy.DefaultVersionId) throw new Error(`Runtime permissions boundary identity is incomplete for ${principalArn}.`);
      const version = (await aws(["iam", "get-policy-version", "--policy-arn", policyArn, "--version-id", policy.DefaultVersionId]))?.PolicyVersion;
      if (!version?.Document) throw new Error(`Runtime permissions boundary document is incomplete for ${principalArn}.`);
      permissionsBoundary = { policyArn, defaultVersionId: policy.DefaultVersionId, policySha256: canonicalSha256(version.Document) };
    }
    roles.push({ principalArn, trustPolicySha256: ECS_TASK_TRUST_SHA256, permissionsBoundary, inlinePolicies, attachedPolicies });
  }
  const body = { roles };
  return Object.freeze({ ...body, identitySha256: canonicalSha256(body) });
}

export async function simulateRuntimeDependencies(dependencies, aws) {
  if (typeof aws !== "function") throw new Error("Runtime closure requires authenticated IAM simulation.");
  const simulations = {};
  for (const dependency of dependencies) {
    const args = ["iam", "simulate-principal-policy", "--policy-source-arn", dependency.principalArn, "--action-names", dependency.action, "--resource-arns", dependency.resource];
    if (dependency.action === "kms:Decrypt") args.push("--context-entries", `ContextKeyName=kms:ViaService,ContextKeyValues=${dependency.context?.["kms:ViaService"]},ContextKeyType=string`);
    const response = await aws(args);
    const result = response?.EvaluationResults?.find(({ EvalActionName, EvalResourceName }) => EvalActionName === dependency.action && EvalResourceName === dependency.resource);
    simulations[dependency.dependencyId] = { principalArn: dependency.principalArn, action: dependency.action, resource: dependency.resource, decision: result?.EvalDecision === "allowed" ? "allowed" : "denied" };
  }
  return Object.freeze(simulations);
}

export async function collectRuntimeConsumabilityEvidence({ sourceSha, candidate, aws, readKmsKey, generatedAt } = {}) {
  const resourceMetadata = await collectRuntimeResourceMetadata(candidate, aws, { readKmsKey });
  const dependencies = addEncryptionDependencies(candidate, deriveEcsRuntimeDependencies(candidate), resourceMetadata);
  const livePolicyIdentity = await collectLiveRolePolicyIdentity(dependencies.map(({ principalArn }) => principalArn), aws);
  const simulations = await simulateRuntimeDependencies(dependencies, aws);
  return buildRuntimeConsumabilityEvidence({ sourceSha, candidate, resourceMetadata, sourcePolicyOwnership: sourceRuntimePolicyOwnership(candidate, resourceMetadata), livePolicyIdentity, simulations, generatedAt });
}

export const RUNTIME_CONSUMABILITY = Object.freeze({ account: ACCOUNT, region: REGION, awsManagedExecutionPolicyArn: AWS_MANAGED_EXECUTION_POLICY, ecsTaskTrust: ECS_TASK_TRUST, ecsTaskTrustSha256: ECS_TASK_TRUST_SHA256, authorizationMaxAgeMs: RUNTIME_AUTHORIZATION_MAX_AGE_MS, liveEvidenceMaxAgeMs: LIVE_RUNTIME_EVIDENCE_MAX_AGE_MS });
