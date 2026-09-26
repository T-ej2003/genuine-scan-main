import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { downloadAppOnlyArtifact } from "./production-app-only-artifacts.mjs";
import { assertImageAuthorizationEnvelope } from "./production-cutover-control-plane.mjs";
import { parseStageBImagePublicationArtifact, readImageEvidence, readImageRepositoryEvidence, verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { buildStageBImagePublicationIdentity } from "./stage-b-image-publication-identity.mjs";
import { deriveStageBImageImpactReport, assertStageBImageReuseResult } from "./validate-stage-b-image-reuse.mjs";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";

export const APP_ONLY_SESSION_RISK_CONTRACT = Object.freeze({
  path: "backend/src/services/auth/sessionRiskService.ts",
  sha256: "13fd24e7427f4e2cb91b6629d5b34a485ae22c8902133442c471fa8270a7c8c9",
  unsetThreshold: 85,
});

export function authenticateAppOnlySessionRiskSource(repositoryRoot, candidateSourceSha) {
  assert.match(candidateSourceSha || "", /^[a-f0-9]{40}$/);
  const bytes = execFileSync("git", ["show", `${candidateSourceSha}:${APP_ONLY_SESSION_RISK_CONTRACT.path}`], { cwd: repositoryRoot, timeout: 30000, stdio: "pipe" });
  assert.equal(createHash("sha256").update(bytes).digest("hex"), APP_ONLY_SESSION_RISK_CONTRACT.sha256,
    "Candidate session-risk implementation differs from the reviewed positive-threshold fallback contract");
  return { ...APP_ONLY_SESSION_RISK_CONTRACT };
}

export function authenticateProtectedMainBackendImage({ sourceSha, response }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const tag = `${sourceSha}-backend-only`, details = response?.imageDetails;
  assert.ok(Array.isArray(details) && details.length === 1, "Protected-main backend image must resolve exactly once");
  const image = details[0]; assert.equal(image.registryId, APP_ONLY.account); assert.equal(image.repositoryName, "mscqr-backend");
  assert.match(image.imageDigest || "", /^sha256:[a-f0-9]{64}$/); assert.ok(Array.isArray(image.imageTags) && image.imageTags.includes(tag));
  return Object.freeze({ sourceSha, digest: image.imageDigest, tag });
}

// A new app approval binds a separately derived current-source reuse proof. It
// does not relabel the signed report's source or extend its 24-hour validity.
// Neither this producer nor its consumers have a signing operation.
export function authenticateAppOnlyImages({ sourceSha, candidateDigest, publicationReference, authorizationReference, repositoryRoot, githubRun, run, now = new Date().toISOString(), verifySignature = createPinnedRootAttestationVerifier() }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(candidateDigest || "", /^sha256:[a-f0-9]{64}$/);
  const ancestry = (ancestor) => {
    assert.match(ancestor || "", /^[a-f0-9]{40}$/);
    execFileSync("git", ["merge-base", "--is-ancestor", ancestor, sourceSha], { cwd: repositoryRoot, timeout: 30000, stdio: "pipe" });
  };
  const authorizationArtifact = downloadAppOnlyArtifact({ kind: "imageAuthorization", reference: authorizationReference, repositoryRoot, githubRun });
  const authorization = JSON.parse(authorizationArtifact.bytes.toString("utf8"));
  assert.equal(authorization.sourceSha, authorizationReference.sourceSha);
  ancestry(authorization.sourceSha); ancestry(authorization.imageReleaseSha);
  assertImageAuthorizationEnvelope(authorization, { now, verifyImageEvidence: (args) => verifyImageEvidenceSignature({ ...args, verify: verifySignature }) });
  const impact = deriveStageBImageImpactReport({ imageReleaseSha: authorization.imageReleaseSha, toolingSha: sourceSha });
  assertStageBImageReuseResult({ ...impact, imageBuildInputsChanged: impact.newImagesRequired });
  const publication = downloadAppOnlyArtifact({ kind: "publication", reference: publicationReference, repositoryRoot, githubRun });
  assert.equal(String(publicationReference.runId), String(authorization.workflowRunId));
  assert.equal(String(publicationReference.artifactId), String(authorization.imageEvidence.publicationIdentity.artifactId));
  assert.equal(publicationReference.sourceSha, authorization.imageEvidence.publicationIdentity.workflowDefinitionSha);
  assert.equal(publicationReference.fileSha256, authorization.imageEvidence.canonicalArtifactSha256);
  const publicationIdentity = buildStageBImagePublicationIdentity({ artifactBytes: publication.bytes,
    expectedPublicationSourceSha: publicationReference.sourceSha, expectedReleaseSha: authorization.imageReleaseSha, observedAt: now,
    observed: { workflowRunId: String(publication.run.id), workflowDatabaseId: String(publication.run.workflow_id),
      workflowFile: publication.run.path, workflowName: publication.run.name, event: publication.run.event,
      workflowDefinitionSha: publication.run.head_sha, imageReleaseSha: authorization.imageReleaseSha,
      headBranch: publication.run.head_branch, conclusion: publication.run.conclusion,
      artifactId: String(publication.artifact.id), artifactName: publication.artifact.name,
      artifactExpired: publication.artifact.expired, artifactArchiveFilename: null } });
  const images = parseStageBImagePublicationArtifact(publication.bytes, { imageReleaseSha: authorization.imageReleaseSha, artifactSha256: publicationReference.fileSha256 });
  assert.equal(images.find((image) => image.service === "backend").digest, candidateDigest);
  const aws = (args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
  assert.equal(aws(["sts", "get-caller-identity"]).Account, APP_ONLY.account);
  const repositories = [...new Set(images.map((image) => image.repository))].map((repository) => readImageRepositoryEvidence(repository, {
    observedAt: now, describe: (name) => aws(["ecr", "describe-repositories", "--registry-id", APP_ONLY.account, "--repository-names", name]),
  }));
  for (const image of images) {
    assert.equal(authorization.images.find((value) => value.service === image.service)?.digest, image.digest);
    const live = readImageEvidence(image.repository, image.tag, { describe: (repository, tag) => aws(["ecr", "describe-images", "--registry-id", APP_ONLY.account, "--repository-name", repository, "--image-ids", `imageTag=${tag}`]) });
    assert.equal(live.digest, image.digest, "Publication digest no longer matches immutable ECR identity");
  }
  const body = { schemaVersion: 1, kind: "APP_ONLY_AUTHENTICATED_IMAGES", sourceSha, candidateSourceSha: authorization.imageReleaseSha,
    sessionRisk: authenticateAppOnlySessionRiskSource(repositoryRoot, authorization.imageReleaseSha),
    candidateDigest, signedEvidenceSourceSha: authorization.sourceSha, signedImageEvidenceSha256: authorization.imageEvidenceSha256,
    imageAuthorizationSha256: authorization.authorizationSha256, authorizationReference, publicationReference,
    publicationIdentity, imageImpact: impact, repositories, images, generatedAt: now };
  return { ...body, evidenceSha256: canonicalSha256(body) };
}
