import crypto from "node:crypto";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "./production-root-attestation-key.mjs";
import { canonicalizeEcsTaskDefinition, assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";

export const WEB_RELEASE = Object.freeze({
  operation: "PRODUCTION_WEB_IMAGE_PUBLICATION",
  account: "368992683803", region: "eu-west-2", repository: "mscqr-web", platform: "linux/amd64",
  dockerfile: "Dockerfile.ecs-frontend", buildContext: ".",
  workflowFile: ".github/workflows/production-web-image.yml", workflowName: "Production Web Image",
  artifactName: "production-web-image", canonicalFilename: "web-image.jsonl",
  environment: "production-web-image-publish", reviewer: "T-ej2003", service: "frontend", container: "frontend",
  cluster: "mscqr-prod-euw2-main", serviceName: "mscqr-frontend-servi-euw2", family: "mscqr-frontend",
});
export const WEB_EVIDENCE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
// Must cover the release-gate job's 180-minute downstream mutation window.
export const WEB_RELEASE_DOWNSTREAM_RESERVE_MS = 180 * 60 * 1000;
const SHA = /^[a-f0-9]{40}$/; const HASH = /^[a-f0-9]{64}$/; const DIGEST = /^sha256:[a-f0-9]{64}$/;
const IMAGE = new RegExp(`^${WEB_RELEASE.account}\\.dkr\\.ecr\\.${WEB_RELEASE.region}\\.amazonaws\\.com/${WEB_RELEASE.repository}@sha256:[a-f0-9]{64}$`);
const TASK_ARN = new RegExp(`^arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:task-definition/${WEB_RELEASE.family}:[1-9][0-9]*$`);
const SERVICE_ARN = `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:service/${WEB_RELEASE.cluster}/${WEB_RELEASE.serviceName}`;
const CLUSTER_ARN = `arn:aws:ecs:${WEB_RELEASE.region}:${WEB_RELEASE.account}:cluster/${WEB_RELEASE.cluster}`;
const nowMs = (value, label) => { const parsed = Date.parse(value); if (!Number.isFinite(parsed)) throw new Error(`${label} is malformed.`); return parsed; };
const exactKeys = (value, keys, label) => { if (!value || Array.isArray(value) || typeof value !== "object" || Object.keys(value).sort().join() !== [...keys].sort().join()) throw new Error(`${label} shape is invalid.`); };
const hashBytes = (value) => crypto.createHash("sha256").update(value).digest("hex");
const authenticatedWebAuthorizations = new WeakSet();
const evidencePayload = (value) => { const { evidenceSha256, ...payload } = value || {}; return payload; };
const authorizationPayload = (value) => { const { authorizationSha256, ...payload } = value || {}; return payload; };
const taskTags = (value) => [...(value || [])].sort((left, right) => String(left.key).localeCompare(String(right.key)));

export function parseWebPublicationArtifact(bytes, sourceSha) {
  if (!Buffer.isBuffer(bytes) || !SHA.test(sourceSha || "")) throw new Error("Web publication artifact binding is invalid.");
  let records; try { records = bytes.toString("utf8").trim().split(/\n/).filter(Boolean).map(JSON.parse); } catch { throw new Error("Web publication artifact is malformed."); }
  if (records.length !== 1) throw new Error("Web publication artifact must contain exactly one record.");
  const record = records[0];
  exactKeys(record, ["service", "repository", "image_uri", "image_tag", "image_digest", "image_ref", "platform", "dockerfile", "build_context", "critical_scan", "sbom_sha256", "provenance_sha256", "cosign_signature_verified", "sbom_attestation_verified", "provenance_attestation_verified"], "Web publication record");
  const uri = `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}:${sourceSha}`;
  const ref = `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}@${record.image_digest}`;
  if (record.service !== WEB_RELEASE.service || record.repository !== WEB_RELEASE.repository || record.image_tag !== sourceSha || !DIGEST.test(record.image_digest || "") || record.image_uri !== uri || record.image_ref !== ref || record.platform !== WEB_RELEASE.platform || record.dockerfile !== WEB_RELEASE.dockerfile || record.build_context !== WEB_RELEASE.buildContext || record.critical_scan !== "pass" || !HASH.test(record.sbom_sha256 || "") || !HASH.test(record.provenance_sha256 || "") || record.cosign_signature_verified !== true || record.sbom_attestation_verified !== true || record.provenance_attestation_verified !== true) throw new Error("Web publication record is outside the canonical contract.");
  return Object.freeze(record);
}

export function assertWebPublicationArtifactBundle({ artifactBytes, sbomBytes, provenanceBytes, sourceSha, workflowRunId, workflowDefinitionSha = sourceSha } = {}) {
  const record = parseWebPublicationArtifact(artifactBytes, sourceSha);
  if (!Buffer.isBuffer(sbomBytes) || !Buffer.isBuffer(provenanceBytes) || hashBytes(sbomBytes) !== record.sbom_sha256 || hashBytes(provenanceBytes) !== record.provenance_sha256) throw new Error("Web publication supply-chain artifact hashes are invalid.");
  let provenance; try { provenance = JSON.parse(provenanceBytes.toString("utf8")); } catch { throw new Error("Web publication provenance is malformed."); }
  exactKeys(provenance, ["releaseSha", "workflowDefinitionSha", "workflowRunId", "repository", "platform", "dockerfile", "buildContext"], "Web publication provenance");
  if (provenance.releaseSha !== sourceSha || !SHA.test(provenance.workflowDefinitionSha || "") || provenance.workflowDefinitionSha !== workflowDefinitionSha || String(provenance.workflowRunId) !== String(workflowRunId) || provenance.repository !== WEB_RELEASE.repository || provenance.platform !== WEB_RELEASE.platform || provenance.dockerfile !== WEB_RELEASE.dockerfile || provenance.buildContext !== WEB_RELEASE.buildContext) throw new Error("Web publication provenance is outside the canonical contract.");
  return record;
}

export function buildWebPublicationIdentity({ observed, artifactBytes, sourceSha, observedAt } = {}) {
  const record = parseWebPublicationArtifact(artifactBytes, sourceSha);
  exactKeys(observed, ["workflowRunId", "workflowDatabaseId", "workflowFile", "workflowName", "event", "workflowDefinitionSha", "headBranch", "conclusion", "artifactId", "artifactName", "artifactExpired", "reviewer"], "Observed web publication");
  if (!/^\d+$/.test(String(observed.workflowRunId || "")) || !/^\d+$/.test(String(observed.workflowDatabaseId || "")) || observed.workflowFile !== WEB_RELEASE.workflowFile || observed.workflowName !== WEB_RELEASE.workflowName || observed.event !== "workflow_dispatch" || !SHA.test(observed.workflowDefinitionSha || "") || observed.headBranch !== "main" || observed.conclusion !== "success" || !/^\d+$/.test(String(observed.artifactId || "")) || observed.artifactName !== WEB_RELEASE.artifactName || observed.artifactExpired !== false || !/^[A-Za-z0-9-]+$/.test(observed.reviewer || "")) throw new Error("Observed web publication identity is invalid.");
  nowMs(observedAt, "Web publication observation");
  return Object.freeze({ schemaVersion: 1, operation: WEB_RELEASE.operation, sourceSha, workflowRunId: String(observed.workflowRunId), workflowDatabaseId: String(observed.workflowDatabaseId), workflowFile: WEB_RELEASE.workflowFile, workflowName: WEB_RELEASE.workflowName, event: "workflow_dispatch", workflowDefinitionSha: observed.workflowDefinitionSha, headBranch: "main", conclusion: "success", artifactId: String(observed.artifactId), artifactName: WEB_RELEASE.artifactName, artifactExpired: false, canonicalFilename: WEB_RELEASE.canonicalFilename, canonicalArtifactSha256: hashBytes(artifactBytes), reviewer: observed.reviewer, record, observedAt });
}

export function buildWebImageEvidence({ publicationIdentity, repositoryEvidence, imageReadback, imageImpactSha256, createdAt, expiresAt } = {}) {
  if (!publicationIdentity || !SHA.test(publicationIdentity.sourceSha || "") || !SHA.test(publicationIdentity.workflowDefinitionSha || "") || !HASH.test(publicationIdentity.canonicalArtifactSha256 || "")) throw new Error("Web publication identity is invalid.");
  const expectedRepoArn = `arn:aws:ecr:${WEB_RELEASE.region}:${WEB_RELEASE.account}:repository/${WEB_RELEASE.repository}`;
  if (repositoryEvidence?.repositoryArn !== expectedRepoArn || repositoryEvidence.repositoryName !== WEB_RELEASE.repository || String(repositoryEvidence.registryId) !== WEB_RELEASE.account || repositoryEvidence.imageTagMutability !== "IMMUTABLE" || repositoryEvidence.imageTagMutabilityExclusionFilters?.length || imageReadback?.digest !== publicationIdentity.record.image_digest || !imageReadback?.imagePushedAt || !HASH.test(imageImpactSha256 || "")) throw new Error("Web image repository, digest, or impact evidence is invalid.");
  const created = nowMs(createdAt, "Web evidence creation time"); const expires = nowMs(expiresAt, "Web evidence expiry");
  if (expires <= created || expires - created > WEB_EVIDENCE_MAX_AGE_MS) throw new Error("Web evidence lifetime is invalid.");
  const evidence = { schemaVersion: 1, operation: WEB_RELEASE.operation, sourceSha: publicationIdentity.sourceSha, account: WEB_RELEASE.account, region: WEB_RELEASE.region, repository: WEB_RELEASE.repository, platform: WEB_RELEASE.platform, dockerfile: WEB_RELEASE.dockerfile, buildContext: WEB_RELEASE.buildContext, workflowRunId: publicationIdentity.workflowRunId, publicationArtifactSha256: publicationIdentity.canonicalArtifactSha256, publicationIdentitySha256: canonicalSha256(publicationIdentity), imageDigest: publicationIdentity.record.image_digest, imageRef: publicationIdentity.record.image_ref, imageImpactSha256, reviewer: publicationIdentity.reviewer, createdAt, expiresAt, publicationIdentity, repositoryEvidence, imageReadback };
  evidence.evidenceSha256 = canonicalSha256(evidencePayload(evidence)); return Object.freeze(evidence);
}

export function signWebImageEvidence(evidence, { sign, signedAt } = {}) {
  assertWebImageEvidence(evidence, { now: signedAt });
  if (typeof sign !== "function") throw new Error("Web evidence signer is required.");
  const signatureBase64 = String(sign({ keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, digest: Buffer.from(evidence.evidenceSha256, "hex") }) || "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)) throw new Error("Web evidence signature is malformed.");
  return Object.freeze({ schemaVersion: 1, keyArn: ROOT_ATTESTATION_KEY_ALIAS_ARN, signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM, evidenceSha256: evidence.evidenceSha256, sourceSha: evidence.sourceSha, workflowRunId: evidence.workflowRunId, signatureBase64, signedAt });
}

export function assertWebImageEvidence(evidence, { signature, verify, now = new Date().toISOString() } = {}) {
  if (evidence?.schemaVersion !== 1 || evidence.operation !== WEB_RELEASE.operation || !SHA.test(evidence.sourceSha || "") || evidence.account !== WEB_RELEASE.account || evidence.region !== WEB_RELEASE.region || evidence.repository !== WEB_RELEASE.repository || evidence.platform !== WEB_RELEASE.platform || evidence.dockerfile !== WEB_RELEASE.dockerfile || evidence.buildContext !== WEB_RELEASE.buildContext || !DIGEST.test(evidence.imageDigest || "") || !IMAGE.test(evidence.imageRef || "") || !HASH.test(evidence.imageImpactSha256 || "") || evidence.evidenceSha256 !== canonicalSha256(evidencePayload(evidence)) || evidence.publicationIdentity?.sourceSha !== evidence.sourceSha || !SHA.test(evidence.publicationIdentity?.workflowDefinitionSha || "") || evidence.publicationIdentitySha256 !== canonicalSha256(evidence.publicationIdentity) || evidence.publicationArtifactSha256 !== evidence.publicationIdentity?.canonicalArtifactSha256 || evidence.imageDigest !== evidence.publicationIdentity?.record?.image_digest || evidence.reviewer !== evidence.publicationIdentity?.reviewer) throw new Error("Web image evidence is invalid.");
  const at = nowMs(now, "Web evidence validation time"); if (at < nowMs(evidence.createdAt, "Web evidence creation time") || at > nowMs(evidence.expiresAt, "Web evidence expiry")) throw new Error("Web image evidence is expired or not yet valid.");
  if (signature) {
    if (signature.schemaVersion !== 1 || signature.keyArn !== ROOT_ATTESTATION_KEY_ALIAS_ARN || signature.signingAlgorithm !== ROOT_ATTESTATION_SIGNING_ALGORITHM || signature.evidenceSha256 !== evidence.evidenceSha256 || signature.sourceSha !== evidence.sourceSha || String(signature.workflowRunId) !== String(evidence.workflowRunId) || !/^[A-Za-z0-9+/]+={0,2}$/.test(signature.signatureBase64 || "") || typeof verify !== "function" || verify({ keyArn: signature.keyArn, signingAlgorithm: signature.signingAlgorithm, digest: Buffer.from(evidence.evidenceSha256, "hex"), signature: Buffer.from(signature.signatureBase64, "base64") }) !== true) throw new Error("Web image evidence signature is invalid.");
  }
  return true;
}

export function buildWebImageAuthorization({ sourceSha, evidence, signature, imageImpact, reviewer, now, verify } = {}) {
  assertWebImageEvidence(evidence, { signature, verify, now });
  if (sourceSha !== evidence.sourceSha || reviewer !== evidence.reviewer || !imageImpact?.webPublicationRequired || imageImpact.toolingSha !== sourceSha || canonicalSha256(imageImpact) !== evidence.imageImpactSha256) throw new Error("Web authorization source, reviewer, or image-impact binding is invalid.");
  const authorization = { schemaVersion: 1, operation: "PRODUCTION_WEB_IMAGE_AUTHORIZATION", valid: true, sourceSha, account: WEB_RELEASE.account, region: WEB_RELEASE.region, repository: WEB_RELEASE.repository, imageDigest: evidence.imageDigest, imageRef: evidence.imageRef, evidenceSha256: evidence.evidenceSha256, signatureSha256: canonicalSha256(signature), imageImpactSha256: evidence.imageImpactSha256, reviewer, createdAt: evidence.createdAt, expiresAt: evidence.expiresAt, evidence, signature, imageImpact };
  authorization.authorizationSha256 = canonicalSha256(authorizationPayload(authorization)); return Object.freeze(authorization);
}

export function assertWebImageAuthorization(value, { sourceSha, now = new Date().toISOString(), verify, minimumRemainingMs } = {}) {
  if (value?.schemaVersion !== 1 || value.operation !== "PRODUCTION_WEB_IMAGE_AUTHORIZATION" || value.valid !== true || value.sourceSha !== sourceSha || value.evidence?.sourceSha !== value.sourceSha || value.createdAt !== value.evidence?.createdAt || value.expiresAt !== value.evidence?.expiresAt || value.authorizationSha256 !== canonicalSha256(authorizationPayload(value)) || value.imageRef !== value.evidence?.imageRef || value.imageDigest !== value.evidence?.imageDigest || value.evidenceSha256 !== value.evidence?.evidenceSha256 || value.signatureSha256 !== canonicalSha256(value.signature) || value.imageImpactSha256 !== canonicalSha256(value.imageImpact) || value.imageImpact?.webPublicationRequired !== true || value.imageImpact?.toolingSha !== sourceSha || value.reviewer !== value.evidence?.reviewer) throw new Error("Web image authorization is invalid.");
  assertWebImageEvidence(value.evidence, { signature: value.signature, verify, now });
  if (minimumRemainingMs !== undefined && (!Number.isSafeInteger(minimumRemainingMs) || minimumRemainingMs < 0 || nowMs(value.expiresAt, "Web authorization expiry") - nowMs(now, "Web authorization validation time") <= minimumRemainingMs)) throw new Error("Web image authorization does not have enough remaining lifetime for the governed release.");
  return true;
}

export function assertCoordinatedImageAuthorization({ sourceSha, stageBAuthorization, webAuthorization, webPublicationRequired, verifyWeb, now, minimumWebAuthorizationRemainingMs } = {}) {
  if (stageBAuthorization?.sourceSha !== sourceSha) throw new Error("Stage-B authorization source does not match coordinated release source.");
  if (!webPublicationRequired) {
    if (webAuthorization !== undefined) throw new Error("Web authorization is forbidden when authenticated Stage-B impact does not require web publication.");
    return Object.freeze({ sourceSha, webRequired: false, stageBAuthorizationSha256: stageBAuthorization.authorizationSha256 });
  }
  if (webAuthorization?.imageImpactSha256 !== canonicalSha256(stageBAuthorization.imageReuseEvidence)) throw new Error("Web authorization does not match the authenticated Stage-B image impact.");
  assertWebImageAuthorization(webAuthorization, { sourceSha, now, verify: verifyWeb, minimumRemainingMs: minimumWebAuthorizationRemainingMs });
  return Object.freeze({ sourceSha, webRequired: true, stageBAuthorizationSha256: stageBAuthorization.authorizationSha256, webAuthorizationSha256: webAuthorization.authorizationSha256, webImageRef: webAuthorization.imageRef });
}

export function authenticateWebImageAuthorization({ sourceSha, webAuthorization, verify, now } = {}) {
  assertWebImageAuthorization(webAuthorization, { sourceSha, verify, now });
  const authenticated = Object.freeze({ sourceSha, imageRef: webAuthorization.imageRef, authorizationSha256: webAuthorization.authorizationSha256 });
  authenticatedWebAuthorizations.add(authenticated);
  return authenticated;
}

export function captureFrontendPredecessor(service, taskDefinition) {
  const deployment = service?.deployments?.find(({ status }) => status === "PRIMARY"); const container = taskDefinition?.containerDefinitions?.find(({ name }) => name === WEB_RELEASE.container);
  if (service?.serviceArn !== SERVICE_ARN || service.clusterArn !== CLUSTER_ARN || service.serviceName !== WEB_RELEASE.serviceName || service.status !== "ACTIVE" || service.desiredCount !== 2 || service.runningCount !== 2 || service.pendingCount !== 0 || service.deployments?.length !== 1 || service.taskDefinition !== taskDefinition?.taskDefinitionArn || !TASK_ARN.test(service.taskDefinition || "") || deployment?.taskDefinition !== service.taskDefinition || deployment.rolloutState !== "COMPLETED" || typeof deployment.id !== "string" || taskDefinition?.status !== "ACTIVE" || taskDefinition.family !== WEB_RELEASE.family || taskDefinition.containerDefinitions?.length !== 1 || !IMAGE.test(container?.image || "")) throw new Error("Frontend predecessor is not the exact stable production service.");
  return Object.freeze({ serviceArn: SERVICE_ARN, clusterArn: CLUSTER_ARN, taskDefinitionArn: service.taskDefinition, deploymentId: deployment.id, desiredCount: 2, runningCount: 2, pendingCount: 0, imageRef: container.image, taskDefinition: structuredClone(taskDefinition) });
}

function buildFrontendCandidateFromImage({ predecessor, imageRef } = {}) {
  if (!predecessor || !TASK_ARN.test(predecessor.taskDefinitionArn || "")) throw new Error("Frontend predecessor is invalid.");
  const candidate = structuredClone(predecessor.taskDefinition); for (const key of ["taskDefinitionArn", "revision", "status", "registeredAt", "registeredBy", "deregisteredAt", "deleteRequestedAt", "requiresAttributes", "compatibilities"]) delete candidate[key];
  const container = candidate.containerDefinitions?.find(({ name }) => name === WEB_RELEASE.container); if (!container) throw new Error("Frontend container is missing."); container.image = imageRef;
  if (!IMAGE.test(container.image) || candidate.family !== WEB_RELEASE.family || candidate.containerDefinitions.length !== predecessor.taskDefinition.containerDefinitions.length) throw new Error("Frontend candidate is outside the reviewed family or image contract.");
  const before = structuredClone(candidate); before.containerDefinitions.find(({ name }) => name === WEB_RELEASE.container).image = predecessor.imageRef;
  if (canonicalizeEcsTaskDefinition(before) !== canonicalizeEcsTaskDefinition(predecessor.taskDefinition)) throw new Error("Frontend candidate contains a semantic change other than the image.");
  return Object.freeze(candidate);
}

export function buildFrontendCandidate({ predecessor, authenticatedWebAuthorization } = {}) {
  if (!authenticatedWebAuthorizations.has(authenticatedWebAuthorization)) throw new Error("Authenticated web image authorization is required.");
  return buildFrontendCandidateFromImage({ predecessor, imageRef: authenticatedWebAuthorization.imageRef });
}

// Normal application releases use the same immutable image and predecessor
// contract, but do not consume the high-assurance web authorization lane.
// The caller still cannot supply a family, service, or mutable image.
export function buildNormalFrontendCandidate({ predecessor, imageRef } = {}) {
  return buildFrontendCandidateFromImage({ predecessor, imageRef });
}

export function assertFrontendCandidateReadback({ definition, taskDefinitionArn, candidate } = {}) {
  if (!TASK_ARN.test(taskDefinitionArn || "")) throw new Error("Frontend candidate ARN is invalid.");
  assertEcsTaskDefinitionReadback({ definition, taskDefinitionArn, expected: candidate, label: "Registered frontend task definition" });
  if (JSON.stringify(taskTags(definition.tags)) !== JSON.stringify(taskTags(candidate.tags))) throw new Error("Registered frontend task-definition tags drifted.");
  return true;
}

export function assertFrontendPredecessorCas({ predecessor, currentService, currentTaskDefinition } = {}) {
  const current = captureFrontendPredecessor(currentService, currentTaskDefinition);
  if (current.taskDefinitionArn !== predecessor?.taskDefinitionArn || current.deploymentId !== predecessor.deploymentId || current.imageRef !== predecessor.imageRef || current.desiredCount !== predecessor.desiredCount) throw new Error("Frontend predecessor CAS failed.");
  return true;
}

export function buildFrontendUpdate({ predecessor, candidateTaskDefinitionArn } = {}) {
  if (!TASK_ARN.test(candidateTaskDefinitionArn || "") || !predecessor || predecessor.serviceArn !== SERVICE_ARN) throw new Error("Frontend activation target is invalid.");
  return Object.freeze({ cluster: WEB_RELEASE.cluster, service: WEB_RELEASE.serviceName, taskDefinition: candidateTaskDefinitionArn });
}

export function buildFrontendRollback({ predecessor, failedCandidateTaskDefinitionArn } = {}) {
  if (!TASK_ARN.test(failedCandidateTaskDefinitionArn || "") || !TASK_ARN.test(predecessor?.taskDefinitionArn || "") || predecessor.taskDefinitionArn === failedCandidateTaskDefinitionArn) throw new Error("Frontend rollback identity is invalid.");
  return Object.freeze({ cluster: WEB_RELEASE.cluster, service: WEB_RELEASE.serviceName, taskDefinition: predecessor.taskDefinitionArn, expectedFailedCandidateTaskDefinitionArn: failedCandidateTaskDefinitionArn });
}

export async function rollbackFrontendCandidate({ predecessor, candidateTaskDefinitionArn, readService, updateService, waitStable } = {}) {
  for (const value of [readService, updateService, waitStable]) if (typeof value !== "function") throw new Error("Frontend rollback adapter is missing.");
  const current = await readService();
  if (current?.taskDefinition !== candidateTaskDefinitionArn) throw new Error("Frontend rollback ownership is lost.");
  await updateService(buildFrontendRollback({ predecessor, failedCandidateTaskDefinitionArn: candidateTaskDefinitionArn }));
  await waitStable({ expectedTaskDefinitionArn: predecessor.taskDefinitionArn });
  const restored = await readService();
  if (restored?.taskDefinition !== predecessor.taskDefinitionArn || restored.desiredCount !== predecessor.desiredCount || restored.runningCount !== predecessor.desiredCount || restored.pendingCount !== 0) throw new Error("Frontend rollback did not restore the exact predecessor.");
  return predecessor.taskDefinitionArn;
}

export async function runGovernedFrontendActivation({ sourceSha, webAuthorization, verifyWebAuthorization, now, readService, describeTaskDefinition, registerTaskDefinition, updateService, waitStable, verifyHealth } = {}) {
  for (const [name, value] of Object.entries({ readService, describeTaskDefinition, registerTaskDefinition, updateService, waitStable, verifyHealth })) if (typeof value !== "function") throw new Error(`Frontend activation adapter is missing: ${name}.`);
  const authenticatedWebAuthorization = authenticateWebImageAuthorization({ sourceSha, webAuthorization, verify: verifyWebAuthorization, now });
  const initialService = await readService(); const initialTask = await describeTaskDefinition(initialService?.taskDefinition);
  const predecessor = captureFrontendPredecessor(initialService, initialTask); const candidate = buildFrontendCandidate({ predecessor, authenticatedWebAuthorization });
  const registration = await registerTaskDefinition(candidate); const candidateArn = registration?.taskDefinition?.taskDefinitionArn || registration?.taskDefinitionArn;
  const readback = await describeTaskDefinition(candidateArn); assertFrontendCandidateReadback({ definition: readback, taskDefinitionArn: candidateArn, candidate });
  const casService = await readService(); const casTask = await describeTaskDefinition(casService?.taskDefinition); assertFrontendPredecessorCas({ predecessor, currentService: casService, currentTaskDefinition: casTask });
  const update = buildFrontendUpdate({ predecessor, candidateTaskDefinitionArn: candidateArn });
  let updateAttempted = false;
  try {
    updateAttempted = true; await updateService(update); await waitStable({ expectedTaskDefinitionArn: candidateArn });
    const health = await verifyHealth({ expectedTaskDefinitionArn: candidateArn, expectedImageRef: webAuthorization.imageRef });
    if (health?.ready !== true || health.loginStatus !== 200) throw new Error("Frontend post-deployment health failed.");
    return Object.freeze({ sourceSha, predecessorTaskDefinitionArn: predecessor.taskDefinitionArn, candidateTaskDefinitionArn: candidateArn, imageRef: webAuthorization.imageRef, updateCount: 1, rollbackCount: 0, health });
  } catch (error) {
    if (updateAttempted) { const current = await readService(); if (current?.taskDefinition === candidateArn) { try { await rollbackFrontendCandidate({ predecessor, candidateTaskDefinitionArn: candidateArn, readService, updateService, waitStable }); } catch (rollbackError) { throw new Error(`Frontend rollback failed after: ${error.message}`, { cause: rollbackError }); } } }
    throw error;
  }
}
