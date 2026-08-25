import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  addEncryptionDependencies,
  assertRuntimeDependencyInventory,
  assertSignedRuntimeDependencyInventory,
  buildRuntimeDependencyInventory,
  buildLegacyExecutionRuntimePolicy,
  buildRuntimeConsumabilityEvidence,
  collectRuntimeResourceMetadata as collectRuntimeResourceMetadataCore,
  collectLiveRolePolicyIdentity,
  deriveEcsRuntimeDependencies,
  refreshRuntimeResourceMetadata,
  runtimeDependencyIdentity,
  sourceRuntimePolicyOwnership,
  assertRuntimeConsumabilityEvidence,
  assertSignedRuntimeConsumabilityEvidence,
  assertFreshRuntimeConsumabilityVerification,
  signRuntimeConsumabilityEvidence,
  signRuntimeDependencyInventory,
  RUNTIME_AUTHORIZATION_MAX_AGE_MS,
  LIVE_RUNTIME_EVIDENCE_MAX_AGE_MS,
  RUNTIME_CONSUMABILITY,
  assertEcrRepositoryPolicyResponse,
  isEcrRepositoryPolicyNotFound,
} from "../aws/production-ecs-runtime-consumability.mjs";
import { buildLegacyBackendRecoveryCandidate } from "../aws/production-backend-health-recovery-contract.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { prepareProductionEcsRuntimeConsumability, prepareProductionEcsRuntimeInventory } from "../aws/prepare-production-ecs-runtime-consumability.mjs";

const sourceSha = "b64274e155434ae9390d28762d40a37801be5362";
const digest = "sha256:6ce8e4eae1a9243c94368e95259a19446fb6c7241e127cf010b66d0611a17189";
const secretVersionId = `fixture_version_${"0".repeat(16)}`;
const describeSecretResponse = (resource, patch = {}) => ({ ARN: resource, KmsKeyId: null, VersionIdsToStages: { [secretVersionId]: ["AWSCURRENT"] }, ...patch });
const listSecretVersionsResponse = (versionIdsToStages = { [secretVersionId]: ["AWSCURRENT"] }) => ({ Versions: Object.entries(versionIdsToStages).map(([VersionId, VersionStages]) => ({ VersionId, VersionStages })) });
const legacy = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const bindings = {
  ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/private-key-current-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-key-current-AbCd12",
  ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/active-key-version-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEYS_JSON: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-keys-json-AbCd12",
};
const candidate = () => buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: legacy, recoveryImageDigest: digest, imageReleaseSha: sourceSha, artifactSigningBindings: bindings });
const describeImagesResponse = (args, detail = {}) => ({
  imageDetails: [{
    registryId: "368992683803",
    repositoryName: args[args.indexOf("--repository-name") + 1],
    imageDigest: args.at(-1).slice("imageDigest=".length),
    ...detail,
  }],
});
const jsonKeysBySecret = (value) => deriveEcsRuntimeDependencies(value)
  .filter(({ action, context }) => action === "secretsmanager:GetSecretValue" && context.secretSelector.jsonKey)
  .reduce((grouped, dependency) => ({ ...grouped, [dependency.resource]: [...(grouped[dependency.resource] || []), dependency] }), {});
const startupAws = (value, aws) => async (args) => {
  const operation = args.slice(0, 2).join(" ");
  if (operation === "logs describe-log-groups") {
    const logGroupName = args[args.indexOf("--log-group-name-prefix") + 1];
    return { logGroups: [{ logGroupName, logGroupArn: `arn:aws:logs:eu-west-2:368992683803:log-group:${logGroupName}`, creationTime: 1, storedBytes: 0 }] };
  }
  if (operation === "secretsmanager get-secret-value") {
    const resource = args[args.indexOf("--secret-id") + 1]; const versionId = args[args.indexOf("--version-id") + 1];
    const keys = (jsonKeysBySecret(value)[resource] || []).map(({ context }) => context.secretSelector.jsonKey);
    return { ARN: resource, VersionId: versionId, SecretString: JSON.stringify(Object.fromEntries(keys.map((key) => [key, "fixture-present"]))) };
  }
  return aws(args);
};
const collectRuntimeResourceMetadata = (value, aws, options) => collectRuntimeResourceMetadataCore(value, startupAws(value, aws), options);
const repositoryName = "mscqr-backend";
const registryId = "368992683803";
const noRepositoryPolicyStderr = (prefix = "aws: [ERROR]: ") => `${prefix}An error occurred (RepositoryPolicyNotFoundException) when calling the GetRepositoryPolicy operation: Repository policy does not exist for the repository with name '${repositoryName}' in the registry with id '${registryId}'`;
const noRepositoryPolicy = (prefix = "aws: [ERROR]: ") => {
  const error = new Error("AWS CLI failed");
  error.stderr = Buffer.from(`\n${noRepositoryPolicyStderr(prefix)}\n`);
  return error;
};
const ecrPolicyResponse = (policy) => ({ registryId, repositoryName, policyText: JSON.stringify(policy) });
const ecrRawPolicyResponse = (policyText) => ({ registryId, repositoryName, policyText });
const currentMscqrRepositoryPolicy = {
  Version: "2012-10-17",
  Statement: [{
    Sid: "AllowRuntimePull",
    Effect: "Allow",
    Principal: { AWS: "arn:aws:iam::368992683803:role/mscqr-ecs-execution-role" },
    Action: ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
    Resource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-backend",
  }],
};

test("ECR no-policy classification accepts only complete observed CLI envelopes", () => {
  const classify = (error) => isEcrRepositoryPolicyNotFound(error, { repositoryName, registryId });
  assert.equal(classify(noRepositoryPolicy()), true);
  assert.equal(classify(noRepositoryPolicy("")), true);
  assert.equal(classify(Object.assign(new Error("AWS CLI failed"), { stderr: noRepositoryPolicyStderr() })), true);
  const valid = noRepositoryPolicyStderr();
  for (const stderr of [
    '{"Code":"RepositoryPolicyNotFoundException"}',
    '{"Code":"RepositoryPolicyNotFoundException","Message":null}',
    '{"Code":"RepositoryPolicyNotFoundException","Message":""}',
    '{"Code":"RepositoryPolicyNotFoundException","Message":"missing"} trailing',
    'prefix {"Code":"RepositoryPolicyNotFoundException","Message":"missing"}',
    `${valid} AccessDeniedException: denied`,
    `${valid}\nAccessDeniedException: denied`,
    `AccessDeniedException: denied ${valid}`,
    `AccessDeniedException: denied\n${valid}`,
    `${valid} {"Code":"AccessDeniedException"}`,
    `{"Code":"AccessDeniedException"} ${valid}`,
    `${valid} {}`,
    `${valid} arbitrary text`,
    `${valid} An error occurred (AccessDeniedException) when calling the GetRepositoryPolicy operation: denied`,
    `${valid}\rAn error occurred (AccessDeniedException) when calling the GetRepositoryPolicy operation: denied`,
    'An error occurred (RepositoryNotFoundException) when calling the GetRepositoryPolicy operation: Repository does not exist',
    'An error occurred (ServerException) when calling the GetRepositoryPolicy operation: unavailable',
    'An error occurred (InvalidParameterException) when calling the GetRepositoryPolicy operation: invalid',
    'An error occurred (AccessDeniedException) when calling the GetRepositoryPolicy operation: denied',
    noRepositoryPolicyStderr().replace("GetRepositoryPolicy operation", "DeleteRepositoryPolicy operation"),
    noRepositoryPolicyStderr().replace("RepositoryPolicyNotFoundException", "AccessDeniedException"),
    'arbitrary RepositoryPolicyNotFoundException text',
    'arbitrary GetRepositoryPolicy text',
    '',
    '   ',
    '{malformed',
    '{"Code":"RepositoryPolicyNotFoundException","Message":"one"}{"Code":"AccessDeniedException","Message":"two"}',
    noRepositoryPolicyStderr("aws: [ERROR]: aws: [ERROR]: "),
    `garbage ${valid}`,
    `${valid} garbage`,
    `${valid}${valid}`,
    valid.slice(0, -1),
    valid.replace(": Repository policy", ":"),
    valid.replace("operation:", "operation;"),
    `${valid}\u001b[31m`,
  ]) {
    const error = new Error("AWS CLI failed"); error.stderr = Buffer.from(stderr);
    assert.equal(classify(error), false, stderr);
  }
  const namedOnly = new Error("missing"); namedOnly.name = "RepositoryPolicyNotFoundException";
  assert.equal(classify(namedOnly), false);
  assert.equal(classify({ stderr: { toString: () => noRepositoryPolicyStderr() } }), false);
  assert.equal(classify({ registryId, repositoryName, policyText: "{}" }), false);
  assert.equal(isEcrRepositoryPolicyNotFound(noRepositoryPolicy(), { repositoryName: "mscqr-worker", registryId }), false);
  assert.equal(isEcrRepositoryPolicyNotFound(noRepositoryPolicy(), { repositoryName, registryId: "000000000000" }), false);
});

test("ECR successful policy responses require complete IAM statement structure", () => {
  const valid = [
    currentMscqrRepositoryPolicy,
    { Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: "*", Action: "ecr:BatchGetImage", Resource: "*" }] },
    { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: ["arn:aws:iam::368992683803:root"] }, Action: ["ecr:BatchGetImage"], Resource: ["*"], Condition: { StringEquals: { "aws:PrincipalAccount": "368992683803" } } }] },
    { Version: "2012-10-17", Statement: [{ Effect: "Deny", NotPrincipal: { Service: "ecs-tasks.amazonaws.com" }, NotAction: "ecr:GetDownloadUrlForLayer", NotResource: "arn:aws:ecr:eu-west-2:368992683803:repository/mscqr-worker" }] },
  ];
  for (const policy of valid) assert.deepEqual(assertEcrRepositoryPolicyResponse(ecrPolicyResponse(policy), { repositoryName, registryId }).repositoryName, repositoryName);

  const allow = currentMscqrRepositoryPolicy.Statement[0];
  const malformed = [
    null, [], "policy", 1, {},
    { Version: "2012-10-17" },
    { Version: "2012-10-17", Statement: [] },
    { Version: "2012-10-17", Statement: null },
    { Version: "2012-10-17", Statement: {} },
    { Version: "2012-10-17", Statement: "statement" },
    ...[null, true, false, 0, 1, "", "statement", [], {}].map((statement) => ({ Version: "2012-10-17", Statement: [statement] })),
    { Version: "2012-10-17", Statement: [allow, null] },
    { Version: "2012-10-17", Statement: [allow, 1] },
    { Version: "2012-10-17", Statement: [[allow]] },
    { Version: "2012-10-17", Statement: [{ ...allow, Effect: "Permit" }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Effect: true }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Action: {} }] },
    { Version: "2012-10-17", Statement: [{ ...allow, NotAction: "ecr:GetDownloadUrlForLayer" }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Action: ["ecr:BatchGetImage", null] }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Action: [] }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Principal: [] }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Principal: { Unknown: "*" } }] },
    { Version: "2012-10-17", Statement: [{ ...allow, NotPrincipal: "*" }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Resource: {} }] },
    { Version: "2012-10-17", Statement: [{ ...allow, NotResource: "*" }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Condition: [] }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Condition: { StringEquals: null } }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Condition: { StringEquals: { "aws:PrincipalAccount": [["368992683803"]] } } }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Sid: "invalid sid" }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Sid: 1 }] },
    { Version: "2012-10-17", Statement: [{ ...allow, Unknown: true }] },
  ];
  for (const [index, policy] of malformed.entries()) assert.throws(() => assertEcrRepositoryPolicyResponse(ecrPolicyResponse(policy), { repositoryName, registryId }), /malformed/, `malformed policy fixture ${index}`);
  for (const policyText of ["{", `${JSON.stringify(currentMscqrRepositoryPolicy)} trailing`]) {
    assert.throws(() => assertEcrRepositoryPolicyResponse(ecrRawPolicyResponse(policyText), { repositoryName, registryId }));
  }
  for (const response of [
    { ...ecrPolicyResponse(currentMscqrRepositoryPolicy), registryId: "000000000000" },
    { ...ecrPolicyResponse(currentMscqrRepositoryPolicy), repositoryName: "mscqr-worker" },
    { registryId, repositoryName },
    { registryId, repositoryName, policyText: currentMscqrRepositoryPolicy },
    { ...ecrPolicyResponse(currentMscqrRepositoryPolicy), extra: true },
  ]) assert.throws(() => assertEcrRepositoryPolicyResponse(response, { repositoryName, registryId }), /incomplete|malformed/);
});
const metadata = (value) => Object.fromEntries(deriveEcsRuntimeDependencies(value).flatMap(({ action, resource }) => {
  if (action === "secretsmanager:GetSecretValue") {
    const selector = deriveEcsRuntimeDependencies(value).find((dependency) => dependency.action === action && dependency.resource === resource).context.secretSelector;
    const versionIdsToStages = { [secretVersionId]: ["AWSCURRENT"] }; const secretVersions = [{ versionId: secretVersionId, versionStages: ["AWSCURRENT"] }];
    const selectorResolutions = [{ selector, resolvedVersionId: secretVersionId, resolvedVersionStage: "AWSCURRENT", jsonKeyState: selector.jsonKey ? "PRESENT" : "NOT_REQUESTED" }];
    const state = { ARN: resource, KmsKeyId: null, availability: "AVAILABLE", deletedDate: null, versionIdsToStages, secretVersions, selectorResolutions };
    return [[resource, { resource, encryption: "AWS_MANAGED", kmsKeyArn: null, availability: state.availability, deletedDate: state.deletedDate, versionIdsToStages, secretVersions, selectorResolutions, resourcePolicySha256: canonicalSha256(null), resourcePolicyAccess: "NO_RESOURCE_POLICY", metadataSha256: canonicalSha256(state) }]];
  }
  if (action.startsWith("ecr:") && resource !== "*") {
    const state = { resource, repositoryName: resource.split("repository/")[1], imageDigest: value.containerDefinitions[0].image.split("@")[1], imageAvailability: "EXISTS", repositoryPolicyState: "NO_POLICY", repositoryPolicySha256: canonicalSha256(null) };
    return [[resource, { ...state, metadataSha256: canonicalSha256(state) }]];
  }
  if (action.startsWith("logs:")) {
    const groupArn = resource.split(":log-stream:")[0]; const logGroupName = groupArn.split(":log-group:")[1];
    const state = { resource: groupArn, logGroupName, availability: "EXISTENCE_PROVEN", createGroup: deriveEcsRuntimeDependencies(value).some((dependency) => dependency.action === "logs:CreateLogGroup" && dependency.resource === groupArn) };
    return [[groupArn, { ...state, metadataSha256: canonicalSha256(state) }]];
  }
  return [];
}));

function passing(value = candidate(), resourceMetadata = metadata(value)) {
  const dependencies = addEncryptionDependencies(value, deriveEcsRuntimeDependencies(value), resourceMetadata);
  const sourcePolicyOwnership = sourceRuntimePolicyOwnership(value, resourceMetadata);
  const simulations = Object.fromEntries(dependencies.map(({ dependencyId, principalArn, action, resource }) => [dependencyId, { principalArn, action, resource, decision: "allowed" }]));
  const generatedSha256 = Object.values(sourcePolicyOwnership).find(({ policyName }) => policyName)?.sourcePolicySha256;
  const livePolicyBody = { roles: [{ principalArn: value.executionRoleArn, trustPolicySha256: RUNTIME_CONSUMABILITY.ecsTaskTrustSha256, inlinePolicies: [{ policyName: "mscqr-ecs-secrets-read", policySha256: generatedSha256 }], attachedPolicies: [{ policyArn: "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy", policySha256: "e".repeat(64) }] }] };
  const livePolicyIdentity = { ...livePolicyBody, identitySha256: canonicalSha256(livePolicyBody) };
  const evidence = buildRuntimeConsumabilityEvidence({ sourceSha, candidate: value, resourceMetadata, sourcePolicyOwnership, livePolicyIdentity, simulations, generatedAt: "2026-08-24T18:00:00.000Z" });
  return { evidence, resourceMetadata, livePolicyIdentity, dependencies, simulations, sourcePolicyOwnership };
}

function signed(evidence, signedAt) {
  let signedDigest;
  const envelope = signRuntimeConsumabilityEvidence(evidence, { signedAt, sign: ({ digest }) => { signedDigest = Buffer.from(digest); return "AQ=="; } });
  return { envelope, verify: ({ digest }) => Buffer.from(digest).equals(signedDigest) };
}

test("candidate-derived closure binds exact execution-role runtime dependencies", () => {
  const value = candidate();
  const result = passing(value);
  assert.equal(assertRuntimeConsumabilityEvidence(result.evidence, { sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata }).status, "PASS");
  const privateKey = result.dependencies.find(({ resource }) => resource === bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT);
  assert.equal(privateKey.consumer, "EXECUTION_ROLE");
  assert.equal(privateKey.principalArn, value.executionRoleArn);
  assert.equal(privateKey.action, "secretsmanager:GetSecretValue");
  assert.equal(result.dependencies.some(({ principalArn }) => principalArn === value.taskRoleArn), false);
  const policy = buildLegacyExecutionRuntimePolicy(value, result.resourceMetadata);
  assert.equal(policy.Statement[0].Resource.includes(bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT), true);
  assert.equal(JSON.stringify(policy).includes("*"), false);
});

test("repeated candidate secret references retain dependency identity but deduplicate IAM resources", () => {
  const value = candidate(); const duplicateArn = bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT;
  value.containerDefinitions[0].secrets.push({ name: "ARTIFACT_SIGN_PRIVATE_KEY_DUPLICATE", valueFrom: duplicateArn });
  const dependencies = deriveEcsRuntimeDependencies(value);
  const repeated = dependencies.filter(({ action, resource }) => action === "secretsmanager:GetSecretValue" && resource === duplicateArn);
  assert.equal(repeated.length, 2);
  assert.equal(new Set(repeated.map(({ dependencyId }) => dependencyId)).size, 2);
  assert.equal(new Set(repeated.map(({ source }) => source)).size, 2);
  const policy = buildLegacyExecutionRuntimePolicy(value, metadata(value));
  const resources = policy.Statement.find(({ Action }) => Action.includes("secretsmanager:GetSecretValue")).Resource;
  assert.equal(resources.filter((resource) => resource === duplicateArn).length, 1);
  assert.equal(resources.includes(bindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT), true);
  const reordered = structuredClone(value); reordered.containerDefinitions[0].secrets.reverse();
  assert.equal(canonicalSha256(buildLegacyExecutionRuntimePolicy(reordered, metadata(reordered))), canonicalSha256(policy));
  for (const invalid of [`${duplicateArn}*`, "not-an-arn"]) {
    const changed = candidate(); changed.containerDefinitions[0].secrets[0].valueFrom = invalid;
    assert.throws(() => buildLegacyExecutionRuntimePolicy(changed, metadata(changed)), /Unknown production ECS runtime reference|outside the canonical production scope/);
  }
});

test("wrong principal, action, resource, denial, and wildcard repair all fail closed", () => {
  for (const mutation of [
    (result, dependency) => { result.simulations[dependency.dependencyId].decision = "denied"; },
    (result, dependency) => { result.simulations[dependency.dependencyId].principalArn = candidate().taskRoleArn; },
    (result, dependency) => { result.simulations[dependency.dependencyId].resource += "-wrong"; },
    (result, dependency) => { result.sourcePolicyOwnership[dependency.dependencyId].action = "secretsmanager:DescribeSecret"; },
    (result, dependency) => { result.sourcePolicyOwnership[dependency.dependencyId].resource = "*"; },
    (result, dependency) => { result.sourcePolicyOwnership[dependency.dependencyId].sourcePolicySha256 = "f".repeat(64); },
  ]) {
    const result = passing();
    const dependency = result.dependencies.find(({ action }) => action === "secretsmanager:GetSecretValue");
    mutation(result, dependency);
    assert.throws(() => buildRuntimeConsumabilityEvidence({ sourceSha, candidate: candidate(), resourceMetadata: result.resourceMetadata, sourcePolicyOwnership: result.sourcePolicyOwnership, livePolicyIdentity: result.livePolicyIdentity, simulations: result.simulations }), /source policy ownership|source policy is not present|not allowed/);
  }
});

test("verification re-derives source ownership and authenticates live policy identity", () => {
  const value = candidate(); const result = passing(value);
  const forged = structuredClone(result.evidence);
  forged.results[0].sourcePolicySha256 = "0".repeat(64);
  const body = { ...forged }; delete body.evidenceSha256;
  forged.evidenceSha256 = canonicalSha256(body);
  assert.throws(() => assertRuntimeConsumabilityEvidence(forged, { sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata }), /stale|tampered/);
  result.livePolicyIdentity.identitySha256 = "0".repeat(64);
  assert.throws(() => assertRuntimeConsumabilityEvidence(passing(value).evidence, { sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata }), /identity/);
});

test("custom KMS dependencies require exact execution-role decrypt authority", () => {
  const value = candidate();
  const resourceMetadata = metadata(value);
  const secret = bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT;
  resourceMetadata[secret] = { ...resourceMetadata[secret], encryption: "CUSTOMER_MANAGED", kmsKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478", kmsKeyPolicySha256: "d".repeat(64), kmsKeyPolicyAccess: "EXACT_ROLE" };
  resourceMetadata[secret].metadataSha256 = canonicalSha256({ ARN: secret, KmsKeyId: resourceMetadata[secret].kmsKeyArn, availability: "AVAILABLE", deletedDate: null,
    versionIdsToStages: resourceMetadata[secret].versionIdsToStages, secretVersions: resourceMetadata[secret].secretVersions, selectorResolutions: resourceMetadata[secret].selectorResolutions });
  const dependencies = addEncryptionDependencies(value, deriveEcsRuntimeDependencies(value), resourceMetadata);
  const kms = dependencies.find(({ action }) => action === "kms:Decrypt");
  assert.equal(kms.principalArn, value.executionRoleArn);
  assert.equal(kms.resource, resourceMetadata[secret].kmsKeyArn);
  const result = passing(value, resourceMetadata);
  result.simulations[kms.dependencyId].decision = "denied";
  assert.throws(() => buildRuntimeConsumabilityEvidence({ sourceSha, candidate: value, resourceMetadata, sourcePolicyOwnership: result.sourcePolicyOwnership, livePolicyIdentity: result.livePolicyIdentity, simulations: result.simulations }), /not allowed/);
  result.simulations[kms.dependencyId] = { ...result.simulations[kms.dependencyId], decision: "allowed", resource: `${kms.resource}-wrong` };
  assert.throws(() => buildRuntimeConsumabilityEvidence({ sourceSha, candidate: value, resourceMetadata, sourcePolicyOwnership: result.sourcePolicyOwnership, livePolicyIdentity: result.livePolicyIdentity, simulations: result.simulations }), /not allowed/);
  resourceMetadata[secret].kmsKeyArn = "arn:aws:kms:eu-west-2:368992683803:key/11111111-2222-3333-4444-555555555555";
  resourceMetadata[secret].metadataSha256 = canonicalSha256({ ARN: secret, KmsKeyId: resourceMetadata[secret].kmsKeyArn, availability: "AVAILABLE", deletedDate: null,
    versionIdsToStages: resourceMetadata[secret].versionIdsToStages, secretVersions: resourceMetadata[secret].secretVersions, selectorResolutions: resourceMetadata[secret].selectorResolutions });
  assert.throws(() => addEncryptionDependencies(value, deriveEcsRuntimeDependencies(value), resourceMetadata), /KMS identity/);
});

test("unknown references and post-authorization candidate changes fail closed", () => {
  for (const mutate of [
    (value) => { value.containerDefinitions[0].secrets.push({ name: "UNKNOWN", valueFrom: "plaintext-or-unknown" }); },
    (value) => { value.executionRoleArn = value.taskRoleArn; },
    (value) => { value.containerDefinitions[0].secrets.push({ name: "LATE", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:late-AbCd12" }); },
  ]) {
    const original = candidate(); const result = passing(original); const changed = structuredClone(original); mutate(changed);
    assert.throws(() => assertRuntimeConsumabilityEvidence(result.evidence, { sourceSha, candidate: changed, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata }), /unknown|stale|incomplete|tampered|metadata/i);
  }
});

test("runtime closure is deterministic for the same candidate and candidate-derived rather than signing-name-derived", () => {
  const value = candidate();
  const first = runtimeDependencyIdentity(value);
  assert.deepEqual(runtimeDependencyIdentity(structuredClone(value)), first);
  const reordered = structuredClone(value);
  reordered.containerDefinitions[0].secrets.reverse();
  const second = runtimeDependencyIdentity(reordered);
  assert.equal(first.dependencySha256, second.dependencySha256);
  assert.equal(first.candidateFingerprint, second.candidateFingerprint);
  assert.equal(first.dependencies.filter(({ action }) => action === "secretsmanager:GetSecretValue").length, value.containerDefinitions[0].secrets.length);
});

test("signed read-only inventory binds file bytes, semantic candidate, dependencies, and metadata before convergence", () => {
  const value = candidate(); const candidateFileSha256 = "c".repeat(64); const resourceMetadata = metadata(value);
  const inventory = buildRuntimeDependencyInventory({ sourceSha, candidate: value, candidateFileSha256, resourceMetadata, generatedAt: "2026-08-24T18:00:00.000Z" });
  assert.equal(assertRuntimeDependencyInventory(inventory, { sourceSha, candidate: value, candidateFileSha256 }), inventory);
  let signedDigest;
  const envelope = signRuntimeDependencyInventory(inventory, { signedAt: "2026-08-24T18:00:00.000Z", sign: ({ digest: valueDigest }) => { signedDigest = Buffer.from(valueDigest); return "AQ=="; } });
  const verify = ({ digest: valueDigest }) => Buffer.from(valueDigest).equals(signedDigest);
  assert.equal(assertSignedRuntimeDependencyInventory(envelope, { sourceSha, candidate: value, candidateFileSha256, verify, now: Date.parse("2026-08-24T18:01:00.000Z") }), inventory);
  assert.throws(() => assertSignedRuntimeDependencyInventory(envelope, { sourceSha, candidate: value, candidateFileSha256: "d".repeat(64), verify, now: Date.parse("2026-08-24T18:01:00.000Z") }), /different bytes|stale|tampered/);
  const changed = structuredClone(value); changed.containerDefinitions[0].image = changed.containerDefinitions[0].image.replace(digest, `sha256:${"f".repeat(64)}`);
  assert.throws(() => assertSignedRuntimeDependencyInventory(envelope, { sourceSha, candidate: changed, candidateFileSha256, verify, now: Date.parse("2026-08-24T18:01:00.000Z") }), /stale|missing|tampered/);
});

test("secret resource policy and customer-managed KMS authority are authenticated without secret values", async () => {
  const value = candidate();
  const keyArn = "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478";
  const exactRolePolicy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: value.executionRoleArn }, Action: "kms:Decrypt", Resource: keyArn }] });
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource, { KmsKeyId: resource === bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT ? keyArn : null });
    if (operation === "secretsmanager list-secret-version-ids") return listSecretVersionsResponse();
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    if (operation === "kms describe-key") return { KeyMetadata: { Arn: keyArn, KeyState: "Enabled", KeyUsage: "ENCRYPT_DECRYPT" } };
    if (operation === "kms get-key-policy") return { Policy: exactRolePolicy };
    throw new Error(operation);
  };
  const readKmsKey = async (keyArnValue) => ({ metadata: (await aws(["kms", "describe-key", "--key-id", keyArnValue])).KeyMetadata, policy: (await aws(["kms", "get-key-policy", "--key-id", keyArnValue, "--policy-name", "default"])).Policy });
  const authenticated = await collectRuntimeResourceMetadata(value, aws, { readKmsKey });
  assert.equal(authenticated[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].kmsKeyPolicyAccess, "EXACT_ROLE");
  const refreshed = await refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, aws), readKmsKey);
  assert.deepEqual(refreshed, authenticated);
  assert.equal(JSON.stringify(authenticated).includes("SecretString"), false);

  const deniedAws = async (args) => args[1] === "get-resource-policy"
    ? { ARN: args.at(-1), ResourcePolicy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: "*", Action: "secretsmanager:GetSecretValue", Resource: args.at(-1) }] }) }
    : aws(args);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, deniedAws, { readKmsKey }), /unsupported/);

  const wildcardDeniedAws = async (args) => args[1] === "get-resource-policy"
    ? { ARN: args.at(-1), ResourcePolicy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: "*", Action: "secretsmanager:GetSecret*", Resource: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/*" }] }) }
    : aws(args);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, wildcardDeniedAws, { readKmsKey }), /unsupported/);

  const allowResourcePolicyAws = async (args) => args[1] === "get-resource-policy"
    ? { ARN: args.at(-1), ResourcePolicy: JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: value.executionRoleArn }, Action: "secretsmanager:GetSecretValue", Resource: args.at(-1) }] }) }
    : aws(args);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, allowResourcePolicyAws, { readKmsKey }), /unsupported/);
  const malformedResourcePolicyAws = async (args) => args[1] === "get-resource-policy"
    ? { ARN: args.at(-1), ResourcePolicy: JSON.stringify({ Version: "2012-10-17", Statement: [null] }) }
    : aws(args);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, malformedResourcePolicyAws, { readKmsKey }), /malformed/);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, aws, { readKmsKey: async () => ({ metadata: { Arn: keyArn, KeyState: "Enabled", KeyUsage: "ENCRYPT_DECRYPT" }, policy: JSON.stringify({ Version: "2012-10-17", Statement: [null] }) }) }), /malformed/);

  const delegatedPolicy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: "arn:aws:iam::368992683803:root" }, Action: "kms:Decrypt", Resource: "*" }] });
  const delegatedReadKmsKey = async () => ({ metadata: { Arn: keyArn, KeyState: "Enabled", KeyUsage: "ENCRYPT_DECRYPT" }, policy: delegatedPolicy });
  const delegated = await collectRuntimeResourceMetadata(value, aws, { readKmsKey: delegatedReadKmsKey });
  assert.equal(delegated[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].kmsKeyPolicyAccess, "ACCOUNT_IAM_DELEGATED");
  await assert.rejects(() => collectRuntimeResourceMetadata(value, aws, { readKmsKey: async () => ({ metadata: { Arn: keyArn, KeyState: "Disabled", KeyUsage: "ENCRYPT_DECRYPT" }, policy: exactRolePolicy }) }), /KMS key is unavailable/);
  const denyPolicy = JSON.stringify({ Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: { AWS: value.executionRoleArn }, Action: "kms:Decrypt", Resource: keyArn }] });
  await assert.rejects(() => collectRuntimeResourceMetadata(value, aws, { readKmsKey: async () => ({ metadata: { Arn: keyArn, KeyState: "Enabled", KeyUsage: "ENCRYPT_DECRYPT" }, policy: denyPolicy }) }), /unsupported deny/);

  const foreignKey = "arn:aws:kms:eu-west-2:368992683803:key/11111111-2222-3333-4444-555555555555";
  const foreignAws = async (args) => args[1] === "describe-secret" ? describeSecretResponse(args.at(-1), { KmsKeyId: foreignKey }) : aws(args);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, foreignAws, { readKmsKey }), /not source-owned/);
});

test("real DescribeImages detail identity and ECR policy state fail closed on every ambiguity", async () => {
  const value = candidate();
  const baseAws = async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource);
    if (operation === "secretsmanager list-secret-version-ids") return listSecretVersionsResponse();
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    throw new Error(operation);
  };
  const authenticated = await collectRuntimeResourceMetadata(value, baseAws);
  const repository = deriveEcsRuntimeDependencies(value).find(({ action }) => action === "ecr:BatchGetImage").resource;
  assert.equal(authenticated[repository].repositoryPolicyState, "NO_POLICY");
  assert.doesNotThrow(() => passing(value, authenticated));

  for (const policy of [
    { Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: { AWS: value.executionRoleArn }, Action: "ecr:BatchGetImage", Resource: repository }] },
    { Version: "2012-10-17", Statement: [{ Effect: "Deny", Principal: "*", Action: ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"], Resource: repository }] },
    { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: value.executionRoleArn }, Action: "ecr:BatchGetImage", Resource: repository, Condition: { StringLike: { "aws:PrincipalArn": "*" } } }] },
  ]) {
    const withPolicy = async (args) => args[1] === "get-repository-policy" ? { registryId: "368992683803", repositoryName: "mscqr-backend", policyText: JSON.stringify(policy) } : baseAws(args);
    await assert.rejects(() => collectRuntimeResourceMetadata(value, withPolicy), /unsupported/);
    await assert.rejects(() => refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, withPolicy)), /unsupported/);
  }
  await assert.rejects(() => collectRuntimeResourceMetadata(value, async (args) => {
    if (args[1] === "get-repository-policy") return { registryId: "368992683803", repositoryName: "mscqr-worker", policyText: "{" };
    return baseAws(args);
  }), /incomplete|valid JSON/);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, async (args) => args[1] === "get-repository-policy"
    ? ecrPolicyResponse({ Version: "2012-10-17", Statement: [null] }) : baseAws(args)), /malformed/);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, async (args) => args[1] === "get-repository-policy" ? {} : baseAws(args)), /incomplete/);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, async (args) => {
    if (args[1] === "get-repository-policy") { const error = new Error("access denied"); error.name = "AccessDeniedException"; throw error; }
    return baseAws(args);
  }), /state is unavailable/);
  for (const response of [
    { imageDetails: [] },
    { imageDetails: [{ registryId: "368992683803", repositoryName: "mscqr-backend" }] },
    { imageDetails: [{ registryId: "000000000000", repositoryName: "mscqr-backend", imageDigest: digest }] },
    { imageDetails: [{ registryId: "368992683803", repositoryName: "mscqr-worker", imageDigest: digest }] },
    { imageDetails: [{ registryId: "368992683803", repositoryName: "mscqr-backend", imageDigest: `sha256:${"0".repeat(64)}` }] },
    {},
    { imageDetails: "malformed" },
  ]) await assert.rejects(() => collectRuntimeResourceMetadata(value, async (args) => args[1] === "describe-images" ? response : baseAws(args)), /image availability is unproven/);

  const stale = structuredClone(authenticated); stale[repository].repositoryPolicySha256 = "0".repeat(64);
  assert.throws(() => passing(value, stale), /repository-policy metadata/);
  const changedRepository = structuredClone(value); changedRepository.containerDefinitions[0].image = changedRepository.containerDefinitions[0].image.replace("mscqr-backend", "mscqr-worker");
  assert.throws(() => assertRuntimeConsumabilityEvidence(passing(value, authenticated).evidence, { sourceSha, candidate: changedRepository, livePolicyIdentity: passing(value, authenticated).livePolicyIdentity, resourceMetadata: authenticated }), /stale|missing/);
  const staleDigest = structuredClone(authenticated); staleDigest[repository].imageDigest = `sha256:${"0".repeat(64)}`;
  assert.throws(() => passing(value, staleDigest), /image or repository-policy metadata/);
});

test("scheduled secret deletion and availability TOCTOU fail before runtime mutation", async () => {
  const value = candidate();
  let deletedDate;
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource, resource === bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT && deletedDate ? { DeletedDate: deletedDate } : {});
    if (operation === "secretsmanager list-secret-version-ids") return listSecretVersionsResponse();
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    throw new Error(operation);
  };
  const authenticated = await collectRuntimeResourceMetadata(value, aws);
  assert.equal(authenticated[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].availability, "AVAILABLE");
  assert.equal(authenticated[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].deletedDate, null);
  deletedDate = "2026-08-25T00:00:00.000Z";
  await assert.rejects(() => collectRuntimeResourceMetadata(value, aws), /unavailable/);
  await assert.rejects(() => refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, aws)), /unavailable/);
  const tampered = structuredClone(authenticated); tampered[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].availability = "AVAILABLE"; tampered[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].deletedDate = deletedDate;
  assert.throws(() => passing(value, tampered), /availability or selector metadata/);
});

test("Secrets Manager JSON keys are proven in the exact selected version without persisting plaintext", async () => {
  const value = candidate(); const selectedSecret = bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT; const selectedVersion = secretVersionId;
  value.containerDefinitions[0].secrets[0].valueFrom = `${selectedSecret}:REDIS_URL::`;
  let secretString = JSON.stringify({ REDIS_URL: "process-local-fixture-value", unrelated: true });
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args[args.indexOf("--secret-id") + 1] || args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "logs describe-log-groups") { const logGroupName = args[args.indexOf("--log-group-name-prefix") + 1]; return { logGroups: [{ logGroupName, logGroupArn: `arn:aws:logs:eu-west-2:368992683803:log-group:${logGroupName}` }] }; }
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource);
    if (operation === "secretsmanager list-secret-version-ids") return listSecretVersionsResponse();
    if (operation === "secretsmanager get-secret-value") return { ARN: resource, VersionId: args[args.indexOf("--version-id") + 1], SecretString: secretString };
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    throw new Error(operation);
  };
  const authenticated = await collectRuntimeResourceMetadataCore(value, aws);
  const resolution = authenticated[selectedSecret].selectorResolutions.find(({ selector }) => selector.jsonKey === "REDIS_URL");
  assert.deepEqual({ version: resolution.resolvedVersionId, key: resolution.jsonKeyState }, { version: selectedVersion, key: "PRESENT" });
  const serialized = JSON.stringify(authenticated);
  assert.equal(serialized.includes("process-local-fixture-value"), false); assert.equal(serialized.includes("SecretString"), false); assert.equal(serialized.includes("SecretBinary"), false);
  for (const invalidValue of [JSON.stringify({ OTHER_KEY: true }), "not-json", JSON.stringify(["REDIS_URL"])]) {
    secretString = invalidValue;
    await assert.rejects(() => collectRuntimeResourceMetadataCore(value, aws), /JSON-key consumability|JSON object|JSON key/);
  }
  secretString = JSON.stringify({ REDIS_URL: "restored" });
  const initial = await collectRuntimeResourceMetadataCore(value, aws);
  secretString = JSON.stringify({ OTHER_KEY: "rotated-away" });
  await assert.rejects(() => refreshRuntimeResourceMetadata(value, initial, aws), /JSON-key consumability|JSON key/);
});

test("awslogs groups are exact, paginated, create-aware, and refreshed before mutation", async () => {
  const value = candidate(); const option = value.containerDefinitions[0].logConfiguration.options;
  option["awslogs-create-group"] = "false";
  const logGroupName = option["awslogs-group"]; const logGroupArn = `arn:aws:logs:eu-west-2:368992683803:log-group:${logGroupName}`;
  let state = "PAGINATED"; const calls = [];
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args[args.indexOf("--secret-id") + 1] || args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource);
    if (operation === "secretsmanager list-secret-version-ids") return listSecretVersionsResponse();
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    if (operation === "logs describe-log-groups") {
      calls.push(args);
      if (state === "MISSING") return { logGroups: [] };
      if (state === "WRONG") return { logGroups: [{ logGroupName: `${logGroupName}-other`, logGroupArn: `${logGroupArn}-other` }] };
      if (state === "CYCLE") return { logGroups: [], nextToken: "cycle" };
      if (!args.includes("--starting-token")) return { logGroups: [{ logGroupName: `${logGroupName}-other`, logGroupArn: `${logGroupArn}-other` }], nextToken: "next-page" };
      return { logGroups: [{ logGroupName, logGroupArn, creationTime: 1, storedBytes: 0 }] };
    }
    throw new Error(operation);
  };
  const authenticated = await collectRuntimeResourceMetadataCore(value, aws);
  assert.equal(authenticated[logGroupArn].availability, "EXISTENCE_PROVEN"); assert.equal(calls.length, 2);
  const fabricatedCreate = structuredClone(authenticated); const fabricatedState = { resource: logGroupArn, logGroupName, availability: "INTENTIONALLY_CREATED_BY_RUNTIME", createGroup: true };
  fabricatedCreate[logGroupArn] = { ...fabricatedState, metadataSha256: canonicalSha256(fabricatedState) };
  assert.throws(() => passing(value, fabricatedCreate), /awslogs group metadata/);
  state = "MISSING";
  await assert.rejects(() => collectRuntimeResourceMetadataCore(value, aws), /does not exist/);
  await assert.rejects(() => refreshRuntimeResourceMetadata(value, authenticated, aws), /does not exist/);
  state = "WRONG"; await assert.rejects(() => collectRuntimeResourceMetadataCore(value, aws), /does not exist/);
  state = "CYCLE"; await assert.rejects(() => collectRuntimeResourceMetadataCore(value, aws), /cyclic/);
  const createValue = candidate(); createValue.containerDefinitions[0].logConfiguration.options["awslogs-create-group"] = "true";
  state = "MISSING";
  const created = await collectRuntimeResourceMetadataCore(createValue, aws);
  assert.equal(created[logGroupArn].availability, "INTENTIONALLY_CREATED_BY_RUNTIME");
  const wrongRegion = candidate(); wrongRegion.containerDefinitions[0].logConfiguration.options["awslogs-region"] = "us-east-1";
  assert.throws(() => deriveEcsRuntimeDependencies(wrongRegion), /awslogs configuration/);
  const malformedCreate = candidate(); malformedCreate.containerDefinitions[0].logConfiguration.options["awslogs-create-group"] = "yes";
  assert.throws(() => deriveEcsRuntimeDependencies(malformedCreate), /awslogs configuration/);
});

test("Secrets Manager selectors resolve complete real version metadata and refresh fail closed", async () => {
  const previous = `fixture-previous-${"1".repeat(15)}`; const custom = `fixture_version_${"2".repeat(16)}`; const unlabeled = `fixture-unlabel-${"3".repeat(16)}`;
  const baseVersions = { [secretVersionId]: ["AWSCURRENT"], [previous]: ["AWSPREVIOUS"], [custom]: ["CUSTOM"] };
  const selected = (valueFrom) => { const value = candidate(); value.containerDefinitions[0].secrets[0].valueFrom = valueFrom; return value; };
  const awsFor = (versions = baseVersions, arnPatch, listedVersions = listSecretVersionsResponse(versions)) => async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(arnPatch || resource, { VersionIdsToStages: versions });
    if (operation === "secretsmanager list-secret-version-ids") return listedVersions;
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    throw new Error(operation);
  };
  const base = bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT;
  for (const [reference, mode, resolved] of [
    [base, "AWSCURRENT", secretVersionId], [`${base}::AWSCURRENT:`, "VERSION_STAGE", secretVersionId],
    [`${base}::AWSPREVIOUS:`, "VERSION_STAGE", previous], [`${base}::CUSTOM:`, "VERSION_STAGE", custom],
    [`${base}:::${previous}`, "VERSION_ID", previous], [`${base}::AWSCURRENT:${secretVersionId}`, "STAGE_AND_VERSION", secretVersionId],
  ]) {
    const value = selected(reference); const result = await collectRuntimeResourceMetadata(value, awsFor());
    const resolution = result[base].selectorResolutions.find(({ selector }) => selector.selectorMode === mode);
    assert.equal(resolution.resolvedVersionId, resolved);
  }
  const unlabeledResult = await collectRuntimeResourceMetadata(selected(`${base}:::${unlabeled}`), awsFor(baseVersions, undefined,
    { Versions: [...listSecretVersionsResponse(baseVersions).Versions, { VersionId: unlabeled }] }));
  assert.equal(unlabeledResult[base].selectorResolutions.some(({ resolvedVersionId }) => resolvedVersionId === unlabeled), true);
  for (const [reference, versions] of [
    [base, { [previous]: ["AWSPREVIOUS"] }], [`${base}::MISSING:`, baseVersions], [`${base}:::${"2".repeat(32)}`, baseVersions],
    [`${base}::AWSCURRENT:${previous}`, baseVersions], [base, { [secretVersionId]: ["AWSCURRENT"], [previous]: ["AWSCURRENT"] }],
    [base, { short: ["AWSCURRENT"] }], [base, { [secretVersionId]: "AWSCURRENT" }],
  ]) await assert.rejects(() => collectRuntimeResourceMetadata(selected(reference), awsFor(versions)), /version metadata|version census|selector is not resolvable/);
  await assert.rejects(() => collectRuntimeResourceMetadata(selected(base), awsFor(baseVersions, `${base}-wrong`)), /metadata is incomplete/);

  const value = selected(base); const authenticated = await collectRuntimeResourceMetadata(value, awsFor());
  const moved = { [previous]: ["AWSCURRENT"], [secretVersionId]: ["AWSPREVIOUS"], [custom]: ["CUSTOM"] };
  await assert.rejects(() => refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, awsFor(moved))), /changed after administrator authorization/);
  const removed = { [previous]: ["AWSPREVIOUS"], [custom]: ["CUSTOM"] };
  await assert.rejects(() => refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, awsFor(removed))), /not resolvable/);
  assert.equal(JSON.stringify(authenticated).includes("SecretString"), false);
  assert.equal(JSON.stringify(authenticated).includes("SecretBinary"), false);
});

test("secret version enumeration is complete, bounded, and cycle-safe", async () => {
  const unlabeled = `fixture-unlabel-${"4".repeat(16)}`; const value = candidate();
  value.containerDefinitions[0].secrets[0].valueFrom = `${bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT}:::${unlabeled}`;
  const calls = [];
  const aws = async (args) => {
    calls.push(args); const operation = args.slice(0, 2).join(" "); const resource = args[args.indexOf("--secret-id") + 1] || args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource);
    if (operation === "secretsmanager list-secret-version-ids") return args.includes("--starting-token")
      ? { Versions: [{ VersionId: unlabeled }] }
      : { Versions: [{ VersionId: secretVersionId, VersionStages: ["AWSCURRENT"] }], NextToken: "fixture-next-page" };
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    throw new Error(operation);
  };
  const result = await collectRuntimeResourceMetadata(value, aws);
  assert.equal(result[bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT].selectorResolutions.some(({ resolvedVersionId }) => resolvedVersionId === unlabeled), true);
  const listCalls = calls.filter((args) => args[1] === "list-secret-version-ids");
  const secretCount = new Set(deriveEcsRuntimeDependencies(value).filter(({ action }) => action === "secretsmanager:GetSecretValue").map(({ resource }) => resource)).size;
  assert.equal(listCalls.length, secretCount * 2);
  assert.equal(listCalls.every((args) => args.includes("--include-deprecated")), true);

  const failing = (page) => collectRuntimeResourceMetadata(value, async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args[args.indexOf("--secret-id") + 1] || args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource);
    if (operation === "secretsmanager list-secret-version-ids") return page(args);
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    throw new Error(operation);
  });
  await assert.rejects(() => failing(() => ({ Versions: null })), /version census is malformed/);
  await assert.rejects(() => failing(() => ({ Versions: [{ VersionId: secretVersionId, VersionStages: ["AWSCURRENT"] }] })), /selector is not resolvable/);
  await assert.rejects(() => failing((args) => args.includes("--starting-token")
    ? { Versions: [{ VersionId: secretVersionId, VersionStages: ["AWSCURRENT"] }] }
    : { Versions: [{ VersionId: secretVersionId, VersionStages: ["AWSCURRENT"] }], NextToken: "fixture-next-page" }), /conflicting/);
  await assert.rejects(() => failing(() => ({ Versions: [], NextToken: "fixture-cycle" })), /cyclic/);
  await assert.rejects(() => failing(() => ({ Versions: [], NextToken: 1 })), /malformed or cyclic/);
  let page = 0;
  await assert.rejects(() => failing(() => ({ Versions: [], NextToken: `fixture-page-${++page}` })), /bounded page limit/);
});

test("SSM parameter ARN grammar accepts canonical paths without the obsolete escape", () => {
  const value = candidate();
  value.containerDefinitions[0].secrets[0].valueFrom = "arn:aws:ssm:eu-west-2:368992683803:parameter/mscqr/runtime/path-with.dots_and/slashes";
  assert.equal(deriveEcsRuntimeDependencies(value).some(({ action }) => action === "ssm:GetParameters"), true);
  for (const invalid of ["arn:aws:ssm:eu-west-2:368992683803:parameter/", "arn:aws:ssm:eu-west-2:368992683803:parameter/path*", "arn:aws:ssm:us-east-1:368992683803:parameter/path", "arn:aws:ssm:eu-west-2:000000000000:parameter/path"]) {
    const changed = candidate(); changed.containerDefinitions[0].secrets[0].valueFrom = invalid;
    assert.throws(() => deriveEcsRuntimeDependencies(changed), /Unknown production ECS runtime reference/);
  }
});

test("exact SSM parameter version metadata is authenticated and refreshed", async () => {
  const value = candidate(); const parameterArn = "arn:aws:ssm:eu-west-2:368992683803:parameter/mscqr/runtime/path-with.dots_and/slashes";
  value.containerDefinitions[0].secrets[0].valueFrom = parameterArn; let version = 7;
  const aws = async (args) => {
    const operation = args.slice(0, 2).join(" "); const resource = args.at(-1);
    if (operation === "ecr describe-images") return describeImagesResponse(args);
    if (operation === "ecr get-repository-policy") throw noRepositoryPolicy();
    if (operation === "secretsmanager describe-secret") return describeSecretResponse(resource);
    if (operation === "secretsmanager list-secret-version-ids") return listSecretVersionsResponse();
    if (operation === "secretsmanager get-resource-policy") return { ARN: resource, ResourcePolicy: null };
    if (operation === "ssm describe-parameters") return { Parameters: [{ Name: "mscqr/runtime/path-with.dots_and/slashes", ARN: parameterArn, Type: "String", Version: version, DataType: "text", Tier: "Standard" }] };
    throw new Error(operation);
  };
  const authenticated = await collectRuntimeResourceMetadata(value, aws);
  assert.equal(authenticated[parameterArn].parameterVersion, 7);
  assert.deepEqual(await refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, aws)), authenticated);
  version = 8;
  await assert.rejects(() => refreshRuntimeResourceMetadata(value, authenticated, startupAws(value, aws)), /changed after administrator authorization/);
  await assert.rejects(() => collectRuntimeResourceMetadata(value, async (args) => args[1] === "describe-parameters"
    ? { Parameters: [{ Name: "mscqr/runtime/path-with.dots_and/slashes", ARN: parameterArn, Type: "String", Version: 7 }], NextToken: "more" } : aws(args)), /SSM metadata is incomplete/);
});

test("consumer identity cannot be substituted by task, release, or administrator authority", () => {
  const value = candidate(); const result = passing(value);
  const secret = result.dependencies.find(({ action }) => action === "secretsmanager:GetSecretValue");
  for (const principalArn of [value.taskRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", "arn:aws:iam::368992683803:root"]) {
    const simulations = structuredClone(result.simulations);
    simulations[secret.dependencyId] = { ...simulations[secret.dependencyId], principalArn };
    assert.throws(() => buildRuntimeConsumabilityEvidence({ sourceSha, candidate: value, resourceMetadata: result.resourceMetadata, sourcePolicyOwnership: result.sourcePolicyOwnership, livePolicyIdentity: result.livePolicyIdentity, simulations }), /not allowed/);
  }
});

test("candidate-derived closure covers optional ECS runtime references and rejects unknown kinds", () => {
  const value = candidate();
  value.containerDefinitions[0].repositoryCredentials = { credentialsParameter: bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT };
  value.containerDefinitions[0].logConfiguration.secretOptions = [{ name: "token", valueFrom: bindings.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT }];
  assert.equal(deriveEcsRuntimeDependencies(value).filter(({ action }) => action === "secretsmanager:GetSecretValue").length >= value.containerDefinitions[0].secrets.length + 2, true);
  value.containerDefinitions[0].environmentFiles = [{ type: "unknown", value: "arn:aws:s3:::bucket/key" }];
  assert.throws(() => deriveEcsRuntimeDependencies(value), /Unknown production ECS environment file/);
});

test("candidate dependency consumers distinguish ECS execution-role injection from task-role application access", () => {
  const value = candidate();
  value.volumes = [{ name: "runtime", efsVolumeConfiguration: { fileSystemId: "fs-1234abcd", authorizationConfig: { iam: "ENABLED" } } }];
  const dependencies = deriveEcsRuntimeDependencies(value);
  assert.equal(dependencies.filter(({ action }) => action === "secretsmanager:GetSecretValue").every(({ consumer, principalArn }) => consumer === "EXECUTION_ROLE" && principalArn === value.executionRoleArn), true);
  assert.equal(dependencies.filter(({ action }) => action.startsWith("elasticfilesystem:")).every(({ consumer, principalArn }) => consumer === "TASK_ROLE" && principalArn === value.taskRoleArn), true);
});

test("runtime role trust and S3 environment-file dependencies fail closed unless source-owned", () => {
  const value = candidate(); const result = passing(value);
  result.livePolicyIdentity.roles[0].trustPolicySha256 = "0".repeat(64);
  result.livePolicyIdentity.identitySha256 = canonicalSha256({ roles: result.livePolicyIdentity.roles });
  assert.throws(() => buildRuntimeConsumabilityEvidence({ sourceSha, candidate: value, resourceMetadata: result.resourceMetadata, sourcePolicyOwnership: result.sourcePolicyOwnership, livePolicyIdentity: result.livePolicyIdentity, simulations: result.simulations }), /source policy is not present/);
  value.containerDefinitions[0].environmentFiles = [{ type: "s3", value: "arn:aws:s3:::mscqr-runtime/config.env" }];
  const dependencies = deriveEcsRuntimeDependencies(value);
  assert.equal(dependencies.some(({ action, resource }) => action === "s3:GetObject" && resource.endsWith("/config.env")), true);
  assert.equal(dependencies.some(({ action, resource }) => action === "s3:GetBucketLocation" && resource === "arn:aws:s3:::mscqr-runtime"), true);
  assert.throws(() => sourceRuntimePolicyOwnership(value, metadata(value)), /unclassified/);
});

test("live role identity requires the exact ECS tasks trust before policy evidence", async () => {
  const principalArn = candidate().executionRoleArn;
  const aws = async (args) => {
    if (args[1] === "get-role") return { Role: { Arn: principalArn, AssumeRolePolicyDocument: RUNTIME_CONSUMABILITY.ecsTaskTrust } };
    if (args[1] === "list-role-policies") return { PolicyNames: [] };
    if (args[1] === "list-attached-role-policies") return { AttachedPolicies: [] };
    throw new Error(args.join(" "));
  };
  const identity = await collectLiveRolePolicyIdentity([principalArn], aws);
  assert.equal(identity.roles[0].trustPolicySha256, RUNTIME_CONSUMABILITY.ecsTaskTrustSha256);
  await assert.rejects(() => collectLiveRolePolicyIdentity([principalArn], async (args) => args[1] === "get-role"
    ? { Role: { Arn: principalArn, AssumeRolePolicyDocument: { Version: "2012-10-17", Statement: [] } } }
    : aws(args)), /ECS task trust/);
});

test("administrator runtime evidence generation requires exact protected main before AWS", async () => {
  let awsCalls = 0;
  await assert.rejects(() => prepareProductionEcsRuntimeInventory({ sourceSha, candidateFile: "/does/not/matter", candidateFileSha256: "0".repeat(64), outputFile: "/does/not/matter", protectedMain: () => { throw new Error("protected main mismatch"); }, run: () => { awsCalls += 1; } }), /protected main mismatch/);
  assert.equal(awsCalls, 0);
});

test("durable authorization survives workflow latency while live verification remains mutation-fresh", () => {
  const value = candidate(); const result = passing(value);
  const signedAt = Date.parse("2026-08-24T18:00:00.000Z");
  const authorization = signed(result.evidence, new Date(signedAt).toISOString()); const { envelope } = authorization;
  const afterQueueAndApproval = signedAt + 16 * 60 * 1000;
  const verified = assertSignedRuntimeConsumabilityEvidence(envelope, {
    sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata,
    now: afterQueueAndApproval, verify: authorization.verify,
  });
  assert.equal(verified.liveVerifiedAt, new Date(afterQueueAndApproval).toISOString());
  assert.equal(assertFreshRuntimeConsumabilityVerification(verified, { evidenceSha256: result.evidence.evidenceSha256, now: afterQueueAndApproval }).status, "PASS");
  assert.throws(() => assertFreshRuntimeConsumabilityVerification({ ...verified, liveVerifiedAt: new Date(afterQueueAndApproval + 1).toISOString() }, { evidenceSha256: result.evidence.evidenceSha256, now: afterQueueAndApproval }), /stale/);
  const afterMaximumEnvironmentWaitAndDeployJob = signedAt + (30 * 24 * 60 + 180) * 60 * 1000;
  assert.equal(assertSignedRuntimeConsumabilityEvidence(envelope, {
    sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata,
    now: afterMaximumEnvironmentWaitAndDeployJob, verify: authorization.verify,
  }).status, "PASS");
  assert.throws(() => assertFreshRuntimeConsumabilityVerification(verified, { evidenceSha256: result.evidence.evidenceSha256, now: afterQueueAndApproval + LIVE_RUNTIME_EVIDENCE_MAX_AGE_MS + 1 }), /stale/);
  assert.throws(() => assertSignedRuntimeConsumabilityEvidence(envelope, {
    sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata,
    now: signedAt + RUNTIME_AUTHORIZATION_MAX_AGE_MS + 1, verify: authorization.verify,
  }), /stale/);
});

test("durable authorization rejects source, candidate, role, dependency, and live-state replay", () => {
  const value = candidate(); const result = passing(value);
  const now = Date.parse("2026-08-24T18:20:00.000Z");
  const authorization = signed(result.evidence, "2026-08-24T18:00:00.000Z"); const { envelope } = authorization;
  const verify = (overrides = {}) => () => assertSignedRuntimeConsumabilityEvidence(envelope, {
    sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata,
    now, verify: authorization.verify, ...overrides,
  });
  assert.throws(verify({ sourceSha: "a".repeat(40) }), /stale|tampered/);
  const changedCandidate = structuredClone(value); changedCandidate.containerDefinitions[0].image = changedCandidate.containerDefinitions[0].image.replace(digest, `sha256:${"f".repeat(64)}`);
  assert.throws(verify({ candidate: changedCandidate }), /stale|tampered/);
  const changedRole = structuredClone(value); changedRole.executionRoleArn = changedRole.taskRoleArn;
  assert.throws(verify({ candidate: changedRole }), /stale|tampered|metadata|identity/);
  const changedDependency = structuredClone(value); changedDependency.containerDefinitions[0].secrets[0].valueFrom = changedDependency.containerDefinitions[0].secrets[1].valueFrom;
  assert.throws(verify({ candidate: changedDependency }), /stale|tampered|metadata|duplicate|exact distinct/);
  const changedPolicy = structuredClone(result.livePolicyIdentity); changedPolicy.roles[0].inlinePolicies[0].policySha256 = "0".repeat(64); changedPolicy.identitySha256 = canonicalSha256({ roles: changedPolicy.roles });
  assert.throws(verify({ livePolicyIdentity: changedPolicy }), /stale|tampered/);
  const changedMetadata = structuredClone(result.resourceMetadata); const secret = bindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT;
  changedMetadata[secret].availability = "SCHEDULED_FOR_DELETION";
  assert.throws(verify({ resourceMetadata: changedMetadata }), /availability|stale|tampered/);
  const repository = deriveEcsRuntimeDependencies(value).find(({ action }) => action === "ecr:BatchGetImage").resource;
  changedMetadata[secret] = result.resourceMetadata[secret]; changedMetadata[repository].repositoryPolicySha256 = "0".repeat(64);
  assert.throws(verify({ resourceMetadata: changedMetadata }), /repository-policy|stale|tampered/);

  const tampered = structuredClone(envelope); tampered.signedAt = "2026-08-24T18:19:00.000Z";
  tampered.signedBindingSha256 = canonicalSha256({ schemaVersion: tampered.schemaVersion, kind: tampered.kind, evidenceSha256: tampered.evidence.evidenceSha256, keyArn: tampered.keyArn, signingAlgorithm: tampered.signingAlgorithm, signedAt: tampered.signedAt });
  const body = { ...tampered }; delete body.envelopeSha256; tampered.envelopeSha256 = canonicalSha256(body);
  assert.throws(() => assertSignedRuntimeConsumabilityEvidence(tampered, {
    sourceSha, candidate: value, livePolicyIdentity: result.livePolicyIdentity, resourceMetadata: result.resourceMetadata, now, verify: authorization.verify,
  }), /signature/);
});
