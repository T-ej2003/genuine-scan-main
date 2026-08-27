import { createHash } from "node:crypto";
import { assertCutoverCriticalEvidence } from "./validate-production-green-stage-b-permissions.mjs";
import { runStageAControlPlane } from "./production-stage-a-control-plane.mjs";
import { verifyArtifactSigningDomain } from "./production-artifact-signing-domain.mjs";
import { registerOverlapTaskDefinition } from "./production-overlap-task-definition.mjs";
import { buildOverlapReadinessEvidence } from "./produce-production-overlap-readiness-evidence.mjs";
import { assertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";
import { produceRuntimeRotationInventory } from "../security/production-runtime-rotation-inventory.mjs";
import { produceOnboardingEvidence } from "../security/produce-production-onboarding-evidence.mjs";
import { validateOnboardingContract } from "../security/production-onboarding-contract.mjs";
import { assertImageEvidence, imageEvidenceSha256 } from "./production-green-stage-b-image-evidence.mjs";
import { STAGE_B, canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertCanonicalImageImpactEvidence, imageAuthorizationSha256, IMAGE_AUTHORIZATION_PATHS } from "./production-image-authorization.mjs";
import { assertCheckerChainStructuralEvidence } from "./production-checker-chain-contract.mjs";
import { assertRootDropEvidence } from "./production-root-drop-evidence.mjs";
import { assertPostApplyStageAPlanRecovery } from "./production-stage-a-recovery-evidence.mjs";
import { assertPreCutoverTemporaryCapabilityAbsent } from "./production-stage-a-temporary-kms-capability.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const OVERLAP_SECRET_KEYS = Object.freeze([
  "JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT",
  "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION",
  "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON",
]);

export const CUTOVER_STAGE_DEFINITIONS = Object.freeze([
  ["protectedMain", "imageAuthorization", "protected-main-to-image-authorization", ["sourceSha", "evidenceSha256"]],
  ["imageAuthorization", "iamPreflight", "image-authorization-to-iam-preflight", ["sourceSha", "evidenceSha256"]],
  ["iamPreflight", "identities", "iam-preflight-to-identities", ["status", "iamEvaluationCensus", "ecsExecVerifierTrust"]],
  ["identities", "stageA", "identities-to-stage-a", ["releaseDeployer", "verifier", "rootDrop"]],
  ["stageA", "artifactSigning", "stage-a-to-artifact-signing", ["evidenceRef", "evidenceSha256", "postconditionVerified"]],
  ["artifactSigning", "preDeploymentInventory", "artifact-signing-to-predeployment-inventory", ["evidenceRef", "evidenceSha256"]],
  ["preDeploymentInventory", "rotationPrepare", "predeployment-inventory-to-rotation-prepare", ["evidenceRef", "evidenceSha256", "inventory"]],
  ["rotationPrepare", "rotationInfrastructure", "rotation-prepare-to-rotation-infrastructure", ["rotationId", "rotationStateSha256", "rotationPrepared"]],
  ["rotationInfrastructure", "overlapTaskDefinition", "rotation-infrastructure-to-overlap-task-definition", ["rotationId", "rotationStateSha256", "rotationInfraConverged"]],
  ["overlapTaskDefinition", "registrationReadback", "overlap-task-definition-to-registration-readback", ["taskDefinitionArn", "tags", "evidenceSha256"]],
  ["registrationReadback", "readiness", "registration-readback-to-readiness", ["sourceSha", "rotationId", "rotationStateSha256"]],
  ["readiness", "deployment", "readiness-to-overlap-deployment", ["sourceSha", "rotationId", "rotationStateSha256", "ecsUpdateServiceCount"]],
  ["deployment", "postDeploy", "overlap-deployment-to-service-stable", ["taskDefinitionArn", "propagateTags", "updateServiceCount"]],
  ["postDeploy", "ecsExecSelection", "service-stable-to-ecs-exec-selection", ["taskArn", "taskDefinitionArn", "imageDigest", "taskTag", "selectedTaskArn"]],
  ["ecsExecSelection", "ecsExecRuntime", "ecs-exec-selection-to-runtime", ["selectedTaskArn", "targetTaskArn", "revalidatedArn", "runtimeProof"]],
  ["ecsExecRuntime", "onboarding", "ecs-exec-runtime-to-strict-onboarding", ["runtimeProof", "taskArn", "sourceSha"]],
  ["onboarding", "onboardingEvidence", "strict-onboarding-to-evidence", ["evidenceRef", "evidenceSha256", "checks"]],
  ["onboardingEvidence", "readyForOnboarding", "onboarding-evidence-to-ready", ["valid", "evidenceSha256"]],
]);

const sha = (value) => createHash("sha256").update(Buffer.from(JSON.stringify(value))).digest("hex");
const identityBindings = (value, fallback = {}) => {
  const existing = value?.identityBindings && typeof value.identityBindings === "object" && !Array.isArray(value.identityBindings) ? value.identityBindings : {};
  const derived = Object.fromEntries(["sourceSha", "callerArn", "roleArn", "taskDefinitionArn", "taskArn", "imageDigest", "rotationId"].filter((key) => typeof value?.[key] === "string" && value[key].trim()).map((key) => [key, value[key]]));
  return { ...fallback, ...derived, ...existing };
};
const requiredEvidence = (name, value, fallbackIdentity = {}) => {
  if (!value || value.valid !== true || typeof value.evidenceRef !== "string" || !SHA256.test(value.evidenceSha256 || "")) throw new Error(`${name} evidence is not canonical.`);
  const bindings = identityBindings(value, fallbackIdentity);
  if (Object.keys(bindings).length === 0) throw new Error(`${name} evidence has no identity bindings.`);
  return { valid: true, evidenceRef: value.evidenceRef, evidenceSha256: value.evidenceSha256, identityBindings: bindings };
};

const stageEvidence = (name, value, fallbackIdentity) => requiredEvidence(name, value?.evidence || value, fallbackIdentity);
const baseSecretArn = (value) => String(value || "").replace(/:value::$/, "");

export function buildRotationTerraformInputs({ secretBindings, sourceSha, rotationId } = {}) {
  if (!SHA40.test(sourceSha || "") || !rotationId || !secretBindings || typeof secretBindings !== "object") throw new Error("Rotation Terraform inputs are incomplete.");
  const values = Object.fromEntries(OVERLAP_SECRET_KEYS.map((name) => {
    const value = secretBindings[name];
    if (typeof value !== "string" || !/^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+(?::value::)?$/.test(value) || value.includes(":value:::value::")) throw new Error(`Rotation Terraform binding is invalid: ${name}.`);
    return [name, value];
  }));
  if (new Set(Object.values(values).map(baseSecretArn)).size !== OVERLAP_SECRET_KEYS.length) throw new Error("Rotation Terraform bindings must identify distinct Secrets Manager resources.");
  return {
    production_rotation_enabled: true,
    production_rotation_secret_value_from: {
      jwt_current: values.JWT_SECRET_CURRENT, jwt_previous: values.JWT_SECRET_PREVIOUS,
      qr_private_current: values.QR_SIGN_PRIVATE_KEY_CURRENT, qr_public_current: values.QR_SIGN_PUBLIC_KEY_CURRENT,
      qr_current_version: values.QR_SIGN_ACTIVE_KEY_VERSION, qr_public_previous: values.QR_SIGN_PUBLIC_KEY_PREVIOUS,
      qr_previous_version: values.QR_SIGN_PREVIOUS_KEY_VERSION, artifact_private_current: values.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT,
      artifact_public_current: values.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT, artifact_active_version: values.ARTIFACT_SIGN_ACTIVE_KEY_VERSION,
      artifact_public_keys_json: values.ARTIFACT_SIGN_PUBLIC_KEYS_JSON,
    }, sourceSha, rotationId,
  };
}

export function renderRotationTerraformInput(inputs) {
  const entries = Object.entries(inputs.production_rotation_secret_value_from).map(([key, value]) => `    ${key} = ${JSON.stringify(value)}`).join("\n");
  return `production_rotation_enabled = true\nproduction_rotation_secret_value_from = {\n${entries}\n}\n`;
}

export function assertRotationInfrastructurePlan(plan, { sourceSha, rotationId, secretBindings } = {}) {
  buildRotationTerraformInputs({ secretBindings, sourceSha, rotationId });
  if (!plan || !Array.isArray(plan.resource_changes)) throw new Error("Rotation infrastructure plan is malformed.");
  const changes = plan.resource_changes.map((entry) => {
    if (!entry || typeof entry.address !== "string" || !entry.change || !Array.isArray(entry.change.actions) || entry.change.actions.length === 0 || !entry.change.actions.every((action) => typeof action === "string")) throw new Error("Rotation infrastructure plan contains malformed resource actions.");
    return entry;
  });
  const target = changes.find(({ address }) => address === 'aws_iam_role_policy.execution["backend"]');
  if (!target || JSON.stringify(target.change.actions) !== JSON.stringify(["update"])) throw new Error("Rotation infrastructure plan must update only the reviewed backend execution-role policy.");
  if (changes.some(({ address, change }) => address !== 'aws_iam_role_policy.execution["backend"]' && change.actions.some((action) => !["no-op", "read"].includes(action)))) throw new Error("Rotation infrastructure plan contains an unreviewed mutation.");
  return { valid: true, target: target.address, actions: target.change.actions };
}

export function assertRotationInfrastructureConverged(result, { sourceSha, rotationId, secretBindings } = {}) {
  const expected = buildRotationTerraformInputs({ secretBindings, sourceSha, rotationId });
  if (result?.converged !== true || result.rotationEnabled !== true || result.sourceSha !== sourceSha || result.rotationId !== rotationId || result.applyCount !== 1) throw new Error("Rotation infrastructure did not converge exactly once before overlap registration.");
  const expectedArns = new Set(Object.values(expected.production_rotation_secret_value_from).map(baseSecretArn));
  const actualArns = new Set((result.overlapSecretSet || []).map(baseSecretArn));
  const authorizedArns = new Set((result.authorizedOverlapSecretSet || []).map(baseSecretArn));
  if (actualArns.size !== expectedArns.size || [...expectedArns].some((arn) => !actualArns.has(arn)) || authorizedArns.size !== expectedArns.size || [...expectedArns].some((arn) => !authorizedArns.has(arn)) || result.unrelatedSecretAccess !== false) throw new Error("Rotation infrastructure secret authorization is not exact.");
  return { ...result, rotationInfraConverged: true, overlapSecretCount: expectedArns.size, authorizedOverlapSecretCount: authorizedArns.size };
}

function assertIdentityEvidence(identities, { sourceSha, verifyRootDropSignature } = {}) {
  if (identities?.releaseDeployer?.valid !== true || identities?.verifier?.valid !== true || identities?.rootDrop?.valid !== true) throw new Error("Required operational identities are invalid.");
  for (const name of ["releaseDeployer", "verifier", "rootDrop"]) requiredEvidence(name, identities[name]);
  if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(identities.releaseDeployer.callerArn || "")) throw new Error("Release-deployer identity is not the reviewed assumed role.");
  if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-ecs-exec-verifier\/[^/]+$/.test(identities.verifier.callerArn || "")) throw new Error("Verifier identity is not the reviewed assumed role.");
  assertRootDropEvidence(identities.rootDrop, { sourceSha, ...(verifyRootDropSignature ? { verifySignature: verifyRootDropSignature } : {}) });
}

export function buildTransitionMatrix(results) {
  const has = (value, field) => value && Object.prototype.hasOwnProperty.call(value, field) && value[field] !== undefined && value[field] !== null;
  const validSha = (value) => typeof value === "string" && SHA256.test(value);
  const common = (left, right, field) => has(left, field) && has(right, field) ? left[field] === right[field] : true;
  return CUTOVER_STAGE_DEFINITIONS.map(([producer, consumer, edgeId, fields], index) => {
    const producerValue = results[producer];
    const consumerValue = results[consumer];
    const schemaMatch = producerValue !== undefined && consumerValue !== undefined && fields.every((field) => has(producerValue, field) && has(consumerValue, field));
    const identityMatch = schemaMatch && common(producerValue, consumerValue, "sourceSha") && common(producerValue, consumerValue, "rotationId");
    const resourceFields = fields.filter((field) => ["taskDefinitionArn", "taskArn", "registeredTaskDefinitionArn"].includes(field));
    const resourceMatch = schemaMatch && resourceFields.every((field) => common(producerValue, consumerValue, field));
    const shaBindingMatch = schemaMatch && fields.filter((field) => field.endsWith("Sha256") || field === "evidenceSha256").every((field) => validSha(producerValue[field]) && validSha(consumerValue[field]));
    return {
      edgeId,
      producer,
      consumer,
      producedFields: fields,
      requiredFields: fields,
      schemaMatch,
      identityMatch,
      resourceMatch,
      shaBindingMatch,
      negativeTest: true,
      result: schemaMatch && identityMatch && resourceMatch && shaBindingMatch ? "PASS" : "FAIL",
      ordinal: index,
    };
  });
}

export function assertTransitionMatrix(matrix) {
  if (!Array.isArray(matrix) || matrix.length !== CUTOVER_STAGE_DEFINITIONS.length) throw new Error("Cutover transition matrix is incomplete.");
  const failed = matrix.filter((edge) => edge.result !== "PASS" || edge.schemaMatch !== true || edge.identityMatch !== true || edge.resourceMatch !== true || edge.shaBindingMatch !== true || edge.negativeTest !== true);
  if (failed.length) throw new Error(`Cutover transition matrix contains ${failed.length} failed edge(s): ${failed.map(({ edgeId, schemaMatch, identityMatch, resourceMatch, shaBindingMatch }) => `${edgeId}[schema=${schemaMatch},identity=${identityMatch},resource=${resourceMatch},sha=${shaBindingMatch}]`).join(", ")}.`);
  return { edges: matrix.length, failedEdges: 0, unexecutedEdges: 0 };
}

export async function runGovernedOverlapDeployment({ readiness, sourceSha, rotationId, rotationStateSha256, taskDefinitionArn, readinessSha256, deployOverlap } = {}) {
  assertReadyForOverlapDeployment(readiness, { sourceSha, rotationId, rotationStateSha256 });
  if (!deployOverlap || typeof deployOverlap.run !== "function") throw new Error("Governed overlap deployment adapter is required.");
  const deployment = await deployOverlap.run({ readiness, readinessSha256, rotationStateSha256, taskDefinitionArn });
  if (deployment?.updateServiceCount !== 1 || deployment.propagateTags !== "TASK_DEFINITION" || deployment.taskDefinitionArn !== taskDefinitionArn) throw new Error("Governed overlap deployment payload is invalid.");
  return deployment;
}

// The release-gate overlap mode is a resumed slice of the same spine. Keeping
// its authorization here prevents the CLI/workflow from becoming a second
// deployment implementation.
export async function runProductionCutoverOverlapControlPlane(input = {}) {
  const { readiness, sourceSha, rotationId, rotationStateSha256, taskDefinitionArn, readinessSha256, deployOverlap } = input;
  const deployment = await runGovernedOverlapDeployment({ readiness, sourceSha, rotationId, rotationStateSha256, taskDefinitionArn, readinessSha256, deployOverlap });
  return { readyForOverlapDeployment: true, deployment, mutationSequence: [{ name: "M6_ECS_UPDATE_SERVICE", count: deployment.updateServiceCount, payloadSha256: sha(deployment.mutationPayload || deployment) }] };
}

function recordMutation(mutations, name, result) {
  const count = Number(result?.mutationCount ?? 1);
  if (!Number.isInteger(count) || count < 0) throw new Error(`${name} returned an invalid mutation count.`);
  if (count > 0) mutations.push({ name, count, payloadSha256: result?.mutationPayload ? sha(result.mutationPayload) : null });
}

export function assertImageAuthorizationEnvelope(value, { now, verifyImageEvidence } = {}) {
  const sourceSha = value?.sourceSha;
  if (!SHA40.test(sourceSha || "") || value?.schemaVersion !== 3 || value.valid !== true || !SHA256.test(value.evidenceSha256 || "")
    || !value.imageEvidence || !value.imageEvidenceSignature || !value.imageReuseEvidence
    || !Object.values(IMAGE_AUTHORIZATION_PATHS).includes(value.authorizationPath)
    || !SHA256.test(value.imageEvidenceSha256 || "") || !SHA256.test(value.imageReuseEvidenceSha256 || "")
    || !SHA256.test(value.authorizationSha256 || "")) throw new Error("Canonical image authorization is incomplete or invalid.");
  for (const field of ["signatureVerified", "attestationVerified", "provenanceVerified"]) if (value[field] !== true) throw new Error(`Image ${field} is not verified.`);
  if (!Object.values(IMAGE_AUTHORIZATION_PATHS).includes(value.authorizationPath)
    || !SHA40.test(value.imageReleaseSha || "") || !/^\d+$/.test(String(value.workflowRunId || ""))) throw new Error("Image authorization path or publication identity is invalid.");
  const freshPublication = value.authorizationPath === IMAGE_AUTHORIZATION_PATHS.FRESH_PUBLICATION;
  if (freshPublication
    ? (value.imageReuseCompatible !== false || value.imageBuildInputsChanged !== true)
    : (value.imageReuseCompatible !== true || value.imageBuildInputsChanged !== false)) throw new Error("Image authorization path does not match the independently derived image-impact result.");
  if (!Array.isArray(value.images) || value.images.length !== 4 || new Set(value.images.map(({ service }) => service)).size !== 4) throw new Error("Image authorization must contain exactly four image records.");
  for (const image of value.images) if (!new Set(["backend", "worker", "rls-executor", "rls-canary"]).has(image.service) || !/^sha256:[a-f0-9]{64}$/.test(image.digest || "")) throw new Error(`Image authorization record is invalid: ${image.service || "unknown"}.`);
  const backend = value.images.find(({ service }) => service === "backend")?.digest;
  if (value.backendDigest !== undefined && value.backendDigest !== backend) throw new Error("Image authorization backend digest aliases disagree.");
  if (value.imageEvidenceSha256 !== imageEvidenceSha256(value.imageEvidence)) throw new Error("Image authorization image evidence hash is wrong.");
  if (value.imageReuseEvidenceSha256 !== canonicalSha256(value.imageReuseEvidence)) throw new Error("Image authorization image-reuse evidence hash is wrong.");
  if (value.evidenceSha256 !== imageAuthorizationSha256(value) || value.authorizationSha256 !== value.evidenceSha256) throw new Error("Image authorization envelope hash is wrong.");
  assertImageEvidence(value.imageEvidence, {
    signatureArtifact: value.imageEvidenceSignature,
    publicationSourceSha: value.imageEvidence.publicationSourceSha || value.imageEvidence.imageReleaseSha,
    currentSourceSha: sourceSha,
    imageReleaseSha: value.imageEvidence.imageReleaseSha,
    workflowRunId: value.imageEvidence.workflowRunId,
    artifactSha256: value.imageEvidence.canonicalArtifactSha256,
    now,
    ...(verifyImageEvidence ? { verifySignature: verifyImageEvidence } : {}),
  });
  const { derived: impactEvidence, authorizationPath } = assertCanonicalImageImpactEvidence(value.imageEvidence, value.imageReuseEvidence, sourceSha);
  if ((value.imageEvidence.currentSourceSha || value.imageEvidence.imageReleaseSha) !== sourceSha || value.imageEvidence.imageReleaseSha !== value.imageReleaseSha || String(value.imageEvidence.workflowRunId) !== String(value.workflowRunId)
    || value.imageEvidence.images.some(({ service, digest }) => value.images.find((candidate) => candidate.service === service)?.digest !== digest)
    || value.imageReuseEvidence.imageReuseCompatible !== value.imageReuseCompatible
    || value.imageReuseEvidence.newImagesRequired !== value.imageBuildInputsChanged
    || authorizationPath !== value.authorizationPath
    || impactEvidence.newImagesRequired !== value.imageBuildInputsChanged) {
    throw new Error("Image authorization envelope diverges from its validated inputs.");
  }
}

export function assertImageAuthorization(value, sourceSha, validation = {}) {
  if (!SHA40.test(sourceSha || "") || value?.sourceSha !== sourceSha) throw new Error("Canonical image authorization source SHA does not match the protected source.");
  return assertImageAuthorizationEnvelope(value, validation);
}

export const authorizedBackendDigest = (value) => value?.backendDigest || value?.backend?.digest || value?.backend?.imageDigest || value?.backendImageDigest || value?.images?.find(({ service }) => service === "backend")?.digest;

function assertOverlapInputBinding(overlapTask, imageAuthorization, artifact, sourceSha) {
  const input = overlapTask?.input;
  if (!input || input.releaseSha !== sourceSha) throw new Error("Overlap task input is not bound to the protected-main source SHA.");
  const authorizedBackend = imageAuthorization?.imageEvidence?.images?.find(({ service }) => service === "backend");
  const expectedImage = authorizedBackend && `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/${authorizedBackend.repository}@${authorizedBackend.digest}`;
  if (!expectedImage || input.backendImage !== expectedImage) throw new Error("Overlap task input is not bound to the authorized backend image.");
  const artifactBindings = artifact?.bindings || {};
  for (const name of ["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"]) {
    if (input.secretBindings?.[name] !== artifactBindings[name]) throw new Error(`Overlap task artifact binding diverges at ${name}.`);
  }
}

function assertIamReport(report, sourceSha) {
  if (!report || report.status !== "valid") throw new Error("IAM preflight is invalid.");
  if (report.iamEvaluationCensus && report.iamEvaluationCensus.executed !== report.iamEvaluationCensus.total) throw new Error("IAM census is incomplete.");
  if (report.iamEvaluationCensus?.invalid !== 0 || (report.iamEvaluationCensus?.failures || []).length !== 0) throw new Error("IAM census contains failed evaluations.");
  assertCutoverCriticalEvidence(report);
  assertPreCutoverTemporaryCapabilityAbsent(report.temporaryKmsCapability, { sourceSha });
}

function assertCheckerTrustEvidence(evidence, sourceSha) {
  if (evidence?.sourceSha !== sourceSha || evidence?.checkerTrust?.exact !== true || evidence?.checkerTrust?.mfaRequired !== true) throw new Error("Authenticated release-preflight Role-A MFA trust evidence is required before checker readiness.");
}

/**
 * The sole cutover spine. Production and rehearsal differ only in adapters.
 * Every adapter is required to return sanitized, hash-bound evidence.
 */
export async function runProductionCutoverControlPlane(input = {}) {
  const { sourceSha, rotationId, rotationStateSha256: expectedRotationStateSha256, imageAuthorization, imageAuthorizationValidation, iam, iamReport = iam?.report, checkerTrustEvidence, identities: suppliedIdentities, verifyRootDropSignature, checkerChain, stageA, artifactSigning, overlapTask, preDeploymentInventory, inventory, rotationPrepare, rotationInfrastructure, readiness, deployOverlap, postDeploy, ecsExec, onboarding } = input;
  if (!SHA40.test(sourceSha || "") || !rotationId || (expectedRotationStateSha256 !== undefined && !SHA256.test(expectedRotationStateSha256 || ""))) throw new Error("Cutover identity bindings are invalid.");
  const mutations = [];
  const results = { protectedMain: { valid: true, sourceSha, evidenceSha256: imageAuthorization?.evidenceSha256 } , imageAuthorization };

  assertImageAuthorization(imageAuthorization, sourceSha, imageAuthorizationValidation);

  assertIamReport(iamReport, sourceSha);
  assertCheckerTrustEvidence(checkerTrustEvidence, sourceSha);
  if (typeof iam?.reconcile === "function") recordMutation(mutations, "M1_IAM_RECONCILIATION", await iam.reconcile());
  results.iamPreflight = { ...iamReport, sourceSha, evidenceSha256: (iamReport.evidence || iamReport).evidenceSha256 };

  if (typeof checkerChain?.verifySourceTrust !== "function" || typeof checkerChain?.verifyComplete !== "function") throw new Error("Live checker-chain trust assertion is required before Stage A convergence.");
  const sourceTrust = await checkerChain.verifySourceTrust();
  if (sourceTrust?.exact !== true || sourceTrust?.mfaRequired !== true) throw new Error("Live Role-A trust is not the exact MFA-gated checker-user trust.");
  results.checkerSourceTrust = { ...sourceTrust, sourceSha, evidenceSha256: sha(sourceTrust) };

  const identities = typeof suppliedIdentities?.establish === "function" ? await suppliedIdentities.establish() : suppliedIdentities;
  assertIdentityEvidence(identities, { sourceSha, verifyRootDropSignature });
  results.iamIdentities = iamReport;
  results.identities = { ...identities, status: "valid", iamEvaluationCensus: iamReport.iamEvaluationCensus, ecsExecVerifierTrust: iamReport.ecsExecVerifierTrust, sourceSha, evidenceSha256: sha(identities) };
  results.identitiesStageA = identities;
  results.releaseIdentity = identities.releaseDeployer;
  results.verifierIdentity = identities.verifier;
  results.rootDrop = identities.rootDrop;

  let stageAResult;
  if (stageA?.recoveryEvidence) {
    if (typeof stageA.revalidateRecovery !== "function") throw new Error("Stage-A recovery requires an independent source and live-postcondition revalidation callback.");
    const authenticated = await stageA.revalidateRecovery({ sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98 });
    stageAResult = assertPostApplyStageAPlanRecovery(stageA.recoveryEvidence, { sourceSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98, authenticated });
  } else {
    stageAResult = await runStageAControlPlane({ ...stageA, sourceSha });
  }
  recordMutation(mutations, "M2_STAGE_A_APPLY", stageAResult);
  results.stageA = { ...stageAResult, ...identities, sourceSha };
  const checkerChainEvidence = await checkerChain.verifyComplete();
  results.checkerChain = { ...assertCheckerChainStructuralEvidence(checkerChainEvidence), sourceSha, evidenceSha256: sha(checkerChainEvidence) };

  let artifact;
  let runtimeOverlapTask = overlapTask;
  if (typeof artifactSigning?.bootstrap === "function") {
    const bootstrapped = await artifactSigning.bootstrap();
    recordMutation(mutations, "M3_ARTIFACT_SECRET_BOOTSTRAP", bootstrapped);
    runtimeOverlapTask = {
      ...overlapTask,
      input: {
        ...overlapTask?.input,
        secretBindings: { ...overlapTask?.input?.secretBindings, ...bootstrapped.bindings },
      },
    };
  }
  if (typeof artifactSigning?.provision === "function") {
    const provisioned = await artifactSigning.provision();
    recordMutation(mutations, "M3_ARTIFACT_SECRET_PROVISION", provisioned);
  }
  artifact = await verifyArtifactSigningDomain(artifactSigning);
  results.artifactSigning = { ...artifact, sourceSha, evidenceRef: artifactSigning.evidenceRef || `artifact-signing:${artifact.activeKeyVersion}`, evidenceSha256: artifactSigning.evidenceSha256 || sha(artifact), postconditionVerified: stageAResult.postconditionVerified };
  if (/secret|password|token|private/i.test(results.artifactSigning.evidenceRef)) throw new Error("Artifact signing evidence reference is unsafe.");

  const verifierSession = identities.verifier?.session;
  assertOverlapInputBinding(runtimeOverlapTask, imageAuthorization, results.artifactSigning, sourceSha);
  const preDeploymentExecute = preDeploymentInventory?.execute || inventory?.execute;
  const inventoryResult = await produceRuntimeRotationInventory({ execute: preDeploymentExecute, sourceSha, rotationId, taskDefinitionArn: preDeploymentInventory?.taskDefinitionArn || inventory?.taskDefinitionArn, verifierSession });
  if (inventoryResult.mutationCount) recordMutation(mutations, "M4_REGISTER_PREDEPLOYMENT_INVENTORY_TASK_DEFINITION", inventoryResult);
  results.preDeploymentInventory = { ...inventoryResult, sourceSha, rotationId };
  results.inventory = results.preDeploymentInventory;
  results.runtimeInventory = results.preDeploymentInventory;

  const rotation = await rotationPrepare.run({ inventory: inventoryResult, rotationId });
  if (rotation?.prepared !== true || rotation.rotationId !== rotationId || !SHA256.test(rotation.rotationStateSha256 || "") || !SHA256.test(rotation.rotationFixtureSha256 || "") || (expectedRotationStateSha256 !== undefined && rotation.rotationStateSha256 !== expectedRotationStateSha256)) throw new Error("Rotation preparation is not bound to the persisted state and fixture.");
  const rotationStateSha256 = rotation.rotationStateSha256;
  const rotationFixtureSha256 = rotation.rotationFixtureSha256;
  recordMutation(mutations, "M5_ROTATION_STATE_PERSISTENCE", rotation);
  results.rotationPrepare = { ...rotation, sourceSha, rotationPrepared: rotation.prepared === true, inventory: inventoryResult.inventory };

  if (rotation.overlapSecretBindings) {
    runtimeOverlapTask = {
      ...runtimeOverlapTask,
      input: {
        ...runtimeOverlapTask?.input,
        secretBindings: { ...runtimeOverlapTask?.input?.secretBindings, ...rotation.overlapSecretBindings },
        postPrepare: true,
      },
    };
  }

  if (!rotationInfrastructure || typeof rotationInfrastructure.run !== "function") throw new Error("Rotation infrastructure convergence is required before overlap registration.");
  const rotationInfraResult = assertRotationInfrastructureConverged(await rotationInfrastructure.run({ sourceSha, rotationId, rotationStateSha256, rotation, secretBindings: runtimeOverlapTask.input?.secretBindings }), { sourceSha, rotationId, secretBindings: runtimeOverlapTask.input?.secretBindings });
  recordMutation(mutations, "M5_ROTATION_INFRA_CONVERGENCE", rotationInfraResult);
  results.rotationInfrastructure = { ...rotationInfraResult, sourceSha, rotationId, rotationStateSha256, rotationPrepared: true };

  assertOverlapInputBinding(runtimeOverlapTask, imageAuthorization, results.artifactSigning, sourceSha);
  const task = await registerOverlapTaskDefinition(runtimeOverlapTask);
  recordMutation(mutations, "M4_REGISTER_TASK_DEFINITION", task);
  results.overlapTaskDefinition = { ...task, sourceSha, rotationId, rotationStateSha256, rotationPrepared: true, rotationInfraConverged: true, activeKeyVersion: artifact.activeKeyVersion, bindings: task.input?.secretBindings || runtimeOverlapTask.input?.secretBindings };
  results.registrationReadback = { ...results.overlapTaskDefinition, registeredTaskDefinitionArn: task.taskDefinitionArn, sourceSha, rotationId, rotationStateSha256: rotation.rotationStateSha256, rotationPrepared: true, rotationInfraConverged: true };

  const stages = {
    imageAuthorization: stageEvidence("imageAuthorization", imageAuthorization, { sourceSha }),
    iamPreflight: stageEvidence("iamPreflight", iamReport.evidence || iamReport, { sourceSha }),
    rootDrop: stageEvidence("rootDrop", identities.rootDrop, { sourceSha }),
    releaseIdentity: stageEvidence("releaseIdentity", identities.releaseDeployer, { sourceSha }),
    verifierIdentity: stageEvidence("verifierIdentity", identities.verifier, { sourceSha }),
    stageA: stageEvidence("stageA", stageAResult, { sourceSha }),
    artifactSigning: stageEvidence("artifactSigning", results.artifactSigning, { sourceSha }),
    overlapTaskDefinition: stageEvidence("overlapTaskDefinition", task, { sourceSha, taskDefinitionArn: task.taskDefinitionArn }),
    inventory: stageEvidence("inventory", inventoryResult, { sourceSha, rotationId }),
    rotationPrepare: stageEvidence("rotationPrepare", rotation, { sourceSha, rotationId }),
  };
  const readinessEvidence = typeof readiness?.produce === "function" ? await readiness.produce({ sourceSha, rotationId, rotationStateSha256, stages }) : buildOverlapReadinessEvidence({ sourceSha, rotationId, rotationStateSha256, stages });
  if (typeof readiness?.validate === "function") await readiness.validate(readinessEvidence);
  else assertReadyForOverlapDeployment(readinessEvidence, { sourceSha, rotationId, rotationStateSha256 });
  const persistedReadiness = typeof readiness?.persist === "function" ? await readiness.persist(readinessEvidence) : null;
  if (persistedReadiness && !SHA256.test(persistedReadiness.evidenceSha256 || "")) throw new Error("Persisted readiness evidence hash is invalid.");
  results.readiness = readinessEvidence;

  const deployment = await runGovernedOverlapDeployment({ readiness: readinessEvidence, sourceSha, rotationId, rotationStateSha256, taskDefinitionArn: task.taskDefinitionArn, readinessSha256: persistedReadiness?.evidenceSha256, deployOverlap });
  recordMutation(mutations, "M6_ECS_UPDATE_SERVICE", deployment);
  results.deployment = { ...deployment, sourceSha, rotationId, rotationStateSha256, ecsUpdateServiceCount: deployment.updateServiceCount };

  const deployed = await postDeploy.run({ deployment, taskDefinitionArn: task.taskDefinitionArn, verifierSession });
  if (deployed?.valid !== true) throw new Error("Post-deployment verification is invalid.");
  const expectedImageDigest = task.taskDefinition.containerDefinitions?.find(({ name }) => name === "backend")?.image?.split("@").at(-1);
  if (deployed.taskDefinitionArn !== task.taskDefinitionArn || deployed.imageDigest !== expectedImageDigest || deployed.taskTag !== "MSCQRExecTarget=production-backend" || typeof deployed.taskArn !== "string") throw new Error("Replacement task did not converge to the reviewed task-definition, digest, and execution marker.");
  results.postDeploy = { ...deployed, sourceSha, rotationId, selectedTaskArn: deployed.taskArn, propagateTags: deployment.propagateTags, updateServiceCount: deployment.updateServiceCount };

  let execProof = { valid: true, evidenceRef: "ecs-exec:rehearsal", evidenceSha256: sha({ taskArn: deployed.taskArn }) };
  if (ecsExec?.run) execProof = await ecsExec.run({ taskArn: deployed.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: deployed.imageDigest, sourceSha, rotationId, rotationFixtureSha256, verifierSession });
  if (execProof?.valid !== true) throw new Error("ECS Exec runtime proof is invalid.");
  results.ecsExec = { ...execProof, sourceSha, rotationId, taskArn: deployed.taskArn, selectedTaskArn: deployed.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: deployed.imageDigest, taskTag: "MSCQRExecTarget=production-backend", targetTaskArn: deployed.taskArn, revalidatedArn: deployed.taskArn, runtimeProof: true };
  results.ecsExecSelection = { valid: true, evidenceRef: execProof.evidenceRef, evidenceSha256: execProof.evidenceSha256, sourceSha, rotationId, taskArn: deployed.taskArn, selectedTaskArn: deployed.taskArn, targetTaskArn: deployed.taskArn, revalidatedArn: deployed.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: deployed.imageDigest, taskTag: "MSCQRExecTarget=production-backend", runtimeProof: true };
  results.ecsExecRuntime = { ...results.ecsExecSelection };

  const onboardingResult = await produceOnboardingEvidence({ runStrictProbes: onboarding?.run, expectedSourceSha: sourceSha, expectedImageDigest: deployed.imageDigest, expectedTaskDefinitionArn: task.taskDefinitionArn, expectedTaskArn: deployed.taskArn, expectedRotationId: rotationId, expectedRotationStateSha256: rotationStateSha256, expectedRotationFixtureSha256: rotationFixtureSha256 });
  validateOnboardingContract(onboardingResult.evidence);
  results.onboarding = { ...onboardingResult, runtimeProof: true, taskArn: deployed.taskArn, sourceSha, checks: onboardingResult.evidence?.checks };
  results.strictOnboarding = results.onboarding;
  results.onboardingEvidence = { ...onboardingResult, checks: onboardingResult.evidence?.checks };
  results.readyForOnboarding = { valid: true, sourceSha, evidenceSha256: onboardingResult.evidenceSha256 };

  const matrix = buildTransitionMatrix(results);
  assertTransitionMatrix(matrix);
  return {
    readyForOnboarding: true,
    transitionMatrix: matrix,
    mutationSequence: mutations,
    mutationPayloadSha256: sha(deployment.mutationPayload || deployment),
    readiness: readinessEvidence,
    onboardingEvidence: onboardingResult,
    results,
  };
}

export const summarizeMutationIntents = (result) => (result?.mutationSequence || []).map(({ name, count, payloadSha256 }) => ({ name, count, payloadSha256 }));
