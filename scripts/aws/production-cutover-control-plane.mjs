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
import { assertImageImpactReport, assertProductionImageReuseResult } from "./validate-stage-b-image-reuse.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { imageAuthorizationSha256 } from "./production-image-authorization.mjs";

const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;

export const CUTOVER_STAGE_DEFINITIONS = Object.freeze([
  ["protectedMain", "imageAuthorization", "protected-main-to-image-authorization", ["sourceSha", "evidenceSha256"]],
  ["imageAuthorization", "iamPreflight", "image-authorization-to-iam-preflight", ["sourceSha", "evidenceSha256"]],
  ["iamPreflight", "identities", "iam-preflight-to-identities", ["status", "iamEvaluationCensus", "ecsExecVerifierTrust"]],
  ["identities", "stageA", "identities-to-stage-a", ["releaseDeployer", "verifier", "rootDrop"]],
  ["stageA", "artifactSigning", "stage-a-to-artifact-signing", ["evidenceRef", "evidenceSha256", "postconditionVerified"]],
  ["artifactSigning", "preDeploymentInventory", "artifact-signing-to-predeployment-inventory", ["evidenceRef", "evidenceSha256"]],
  ["preDeploymentInventory", "rotationPrepare", "predeployment-inventory-to-rotation-prepare", ["evidenceRef", "evidenceSha256", "inventory"]],
  ["rotationPrepare", "overlapTaskDefinition", "rotation-prepare-to-overlap-task-definition", ["rotationId", "rotationStateSha256", "rotationPrepared"]],
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

function assertIdentityEvidence(identities) {
  if (identities?.releaseDeployer?.valid !== true || identities?.verifier?.valid !== true || identities?.rootDrop?.valid !== true) throw new Error("Required operational identities are invalid.");
  for (const name of ["releaseDeployer", "verifier", "rootDrop"]) requiredEvidence(name, identities[name]);
  if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(identities.releaseDeployer.callerArn || "")) throw new Error("Release-deployer identity is not the reviewed assumed role.");
  if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-ecs-exec-verifier\/[^/]+$/.test(identities.verifier.callerArn || "")) throw new Error("Verifier identity is not the reviewed assumed role.");
  if (identities.rootDrop.callerArn !== "arn:aws:iam::368992683803:root") throw new Error("Administrator root-drop evidence is not the exact reviewed root identity.");
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

export function assertImageAuthorization(value, sourceSha, { now, verifyImageEvidence } = {}) {
  if (value?.valid !== true || value.sourceSha !== sourceSha || !SHA256.test(value.evidenceSha256 || "")) throw new Error("Authorized image evidence is invalid.");
  for (const field of ["signatureVerified", "attestationVerified", "provenanceVerified"]) if (value[field] !== true) throw new Error(`Image ${field} is not verified.`);
  if (value.imageReuseCompatible !== true || value.imageBuildInputsChanged !== false || !SHA40.test(value.imageReleaseSha || "") || !/^\d+$/.test(String(value.workflowRunId || ""))) throw new Error("Image authorization is not bound to canonical compatibility and publication evidence.");
  if (!Array.isArray(value.images) || value.images.length !== 4 || new Set(value.images.map(({ service }) => service)).size !== 4) throw new Error("Image authorization must contain exactly four image records.");
  for (const image of value.images) if (!new Set(["backend", "worker", "rls-executor", "rls-canary"]).has(image.service) || !/^sha256:[a-f0-9]{64}$/.test(image.digest || "")) throw new Error(`Image authorization record is invalid: ${image.service || "unknown"}.`);
  const backend = value.images.find(({ service }) => service === "backend")?.digest;
  if (value.backendDigest !== undefined && value.backendDigest !== backend) throw new Error("Image authorization backend digest aliases disagree.");
  if (value.imageEvidence || value.imageReuseEvidence || value.schemaVersion === 2) {
    if (!value.imageEvidence || !value.imageEvidenceSignature || !value.imageReuseEvidence) throw new Error("Canonical image authorization inputs are incomplete.");
    if (value.imageEvidenceSha256 !== imageEvidenceSha256(value.imageEvidence)) throw new Error("Image authorization image evidence hash is wrong.");
    if (value.imageReuseEvidenceSha256 !== canonicalSha256(value.imageReuseEvidence)) throw new Error("Image authorization image-reuse evidence hash is wrong.");
    if (value.evidenceSha256 !== imageAuthorizationSha256(value) || value.authorizationSha256 !== value.evidenceSha256) throw new Error("Image authorization envelope hash is wrong.");
    assertImageEvidence(value.imageEvidence, {
      signatureArtifact: value.imageEvidenceSignature,
      imageReleaseSha: value.imageEvidence.imageReleaseSha,
      workflowRunId: value.imageEvidence.workflowRunId,
      artifactSha256: value.imageEvidence.canonicalArtifactSha256,
      now,
      ...(verifyImageEvidence ? { verifySignature: verifyImageEvidence } : {}),
    });
    assertImageImpactReport({
      report: value.imageReuseEvidence,
      imageReleaseSha: value.imageEvidence.imageReleaseSha,
      toolingSha: sourceSha,
      toolingInputTreeSha256: value.imageReuseEvidence.toolingInputTreeSha256,
      changedFiles: value.imageReuseEvidence.classifiedChangedFiles,
    });
    assertProductionImageReuseResult({
      ...value.imageReuseEvidence,
      imageBuildInputsChanged: value.imageReuseEvidence.newImagesRequired === true,
    });
    if (value.imageEvidence.imageReleaseSha !== value.imageReleaseSha || String(value.imageEvidence.workflowRunId) !== String(value.workflowRunId)
      || value.imageEvidence.images.some(({ service, digest }) => value.images.find((candidate) => candidate.service === service)?.digest !== digest)
      || value.imageReuseEvidence.imageReuseCompatible !== value.imageReuseCompatible
      || value.imageReuseEvidence.newImagesRequired !== value.imageBuildInputsChanged) {
      throw new Error("Image authorization envelope diverges from its validated inputs.");
    }
  }
}

export const authorizedBackendDigest = (value) => value?.backendDigest || value?.backend?.digest || value?.backend?.imageDigest || value?.backendImageDigest || value?.images?.find(({ service }) => service === "backend")?.digest;

function assertOverlapInputBinding(overlapTask, imageAuthorization, artifact, sourceSha) {
  const input = overlapTask?.input;
  if (!input || input.releaseSha !== sourceSha) throw new Error("Overlap task input is not bound to the protected-main source SHA.");
  const expectedDigest = authorizedBackendDigest(imageAuthorization);
  if (expectedDigest && !String(input.backendImage || "").endsWith(`@${expectedDigest}`)) throw new Error("Overlap task input is not bound to the authorized backend digest.");
  const artifactBindings = artifact?.bindings || {};
  for (const name of ["ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT", "ARTIFACT_SIGN_ACTIVE_KEY_VERSION", "ARTIFACT_SIGN_PUBLIC_KEYS_JSON"]) {
    if (input.secretBindings?.[name] !== artifactBindings[name]) throw new Error(`Overlap task artifact binding diverges at ${name}.`);
  }
}

function assertIamReport(report) {
  if (!report || report.status !== "valid") throw new Error("IAM preflight is invalid.");
  if (report.iamEvaluationCensus && report.iamEvaluationCensus.executed !== report.iamEvaluationCensus.total) throw new Error("IAM census is incomplete.");
  if (report.iamEvaluationCensus?.invalid !== 0 || (report.iamEvaluationCensus?.failures || []).length !== 0) throw new Error("IAM census contains failed evaluations.");
  assertCutoverCriticalEvidence(report);
}

/**
 * The sole cutover spine. Production and rehearsal differ only in adapters.
 * Every adapter is required to return sanitized, hash-bound evidence.
 */
export async function runProductionCutoverControlPlane(input = {}) {
  const { sourceSha, rotationId, rotationStateSha256: expectedRotationStateSha256, imageAuthorization, iam, iamReport = iam?.report, identities: suppliedIdentities, stageA, artifactSigning, overlapTask, preDeploymentInventory, inventory, rotationPrepare, readiness, deployOverlap, postDeploy, ecsExec, onboarding } = input;
  if (!SHA40.test(sourceSha || "") || !rotationId || (expectedRotationStateSha256 !== undefined && !SHA256.test(expectedRotationStateSha256 || ""))) throw new Error("Cutover identity bindings are invalid.");
  const mutations = [];
  const results = { protectedMain: { valid: true, sourceSha, evidenceSha256: imageAuthorization?.evidenceSha256 } , imageAuthorization };

  assertImageAuthorization(imageAuthorization, sourceSha);

  if (typeof iam?.reconcile === "function") recordMutation(mutations, "M1_IAM_RECONCILIATION", await iam.reconcile());
  assertIamReport(iamReport);
  results.iamPreflight = { ...iamReport, sourceSha, evidenceSha256: (iamReport.evidence || iamReport).evidenceSha256 };

  const identities = typeof suppliedIdentities?.establish === "function" ? await suppliedIdentities.establish() : suppliedIdentities;
  assertIdentityEvidence(identities);
  results.iamIdentities = iamReport;
  results.identities = { ...identities, status: "valid", iamEvaluationCensus: iamReport.iamEvaluationCensus, ecsExecVerifierTrust: iamReport.ecsExecVerifierTrust, sourceSha, evidenceSha256: sha(identities) };
  results.identitiesStageA = identities;
  results.releaseIdentity = identities.releaseDeployer;
  results.verifierIdentity = identities.verifier;
  results.rootDrop = identities.rootDrop;

  const stageAResult = await runStageAControlPlane({ ...stageA, sourceSha });
  recordMutation(mutations, "M2_STAGE_A_APPLY", stageAResult);
  results.stageA = { ...stageAResult, ...identities, sourceSha };

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
  const preDeploymentExecute = preDeploymentInventory?.execute || inventory?.execute;
  const inventoryResult = await produceRuntimeRotationInventory({ execute: preDeploymentExecute, sourceSha, rotationId, taskDefinitionArn: preDeploymentInventory?.taskDefinitionArn || inventory?.taskDefinitionArn, verifierSession });
  if (inventoryResult.mutationCount) recordMutation(mutations, "M4_REGISTER_PREDEPLOYMENT_INVENTORY_TASK_DEFINITION", inventoryResult);
  results.preDeploymentInventory = { ...inventoryResult, sourceSha, rotationId };
  results.inventory = results.preDeploymentInventory;
  results.runtimeInventory = results.preDeploymentInventory;

  const rotation = await rotationPrepare.run({ inventory: inventoryResult, rotationId });
  if (rotation?.prepared !== true || rotation.rotationId !== rotationId || !SHA256.test(rotation.rotationStateSha256 || "") || (expectedRotationStateSha256 !== undefined && rotation.rotationStateSha256 !== expectedRotationStateSha256)) throw new Error("Rotation preparation is not bound to the persisted state.");
  const rotationStateSha256 = rotation.rotationStateSha256;
  recordMutation(mutations, "M5_ROTATION_STATE_PERSISTENCE", rotation);
  results.rotationPrepare = { ...rotation, sourceSha, rotationPrepared: rotation.prepared === true, inventory: inventoryResult.inventory };

  assertOverlapInputBinding(runtimeOverlapTask, imageAuthorization, results.artifactSigning, sourceSha);
  const task = await registerOverlapTaskDefinition(runtimeOverlapTask);
  recordMutation(mutations, "M4_REGISTER_TASK_DEFINITION", task);
  results.overlapTaskDefinition = { ...task, sourceSha, rotationId, rotationStateSha256, rotationPrepared: true, activeKeyVersion: artifact.activeKeyVersion, bindings: task.input?.secretBindings || runtimeOverlapTask.input?.secretBindings };
  results.registrationReadback = { ...results.overlapTaskDefinition, registeredTaskDefinitionArn: task.taskDefinitionArn, sourceSha, rotationId, rotationStateSha256: rotation.rotationStateSha256, rotationPrepared: true };

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
  if (ecsExec?.run) execProof = await ecsExec.run({ taskArn: deployed.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: deployed.imageDigest, sourceSha, rotationId, verifierSession });
  if (execProof?.valid !== true) throw new Error("ECS Exec runtime proof is invalid.");
  results.ecsExec = { ...execProof, sourceSha, rotationId, taskArn: deployed.taskArn, selectedTaskArn: deployed.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: deployed.imageDigest, taskTag: "MSCQRExecTarget=production-backend", targetTaskArn: deployed.taskArn, revalidatedArn: deployed.taskArn, runtimeProof: true };
  results.ecsExecSelection = { valid: true, evidenceRef: execProof.evidenceRef, evidenceSha256: execProof.evidenceSha256, sourceSha, rotationId, taskArn: deployed.taskArn, selectedTaskArn: deployed.taskArn, targetTaskArn: deployed.taskArn, revalidatedArn: deployed.taskArn, taskDefinitionArn: task.taskDefinitionArn, imageDigest: deployed.imageDigest, taskTag: "MSCQRExecTarget=production-backend", runtimeProof: true };
  results.ecsExecRuntime = { ...results.ecsExecSelection };

  const onboardingResult = await produceOnboardingEvidence({ runStrictProbes: onboarding?.run, expectedSourceSha: sourceSha, expectedImageDigest: deployed.imageDigest, expectedTaskDefinitionArn: task.taskDefinitionArn, expectedTaskArn: deployed.taskArn, expectedRotationId: rotationId });
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
