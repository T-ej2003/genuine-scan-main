import crypto from "node:crypto";
import { generateImageEvidence, signImageEvidence, verifyImageEvidenceSignature } from "../../aws/production-green-stage-b-image-evidence.mjs";
import { buildStageBImagePublicationIdentity } from "../../aws/stage-b-image-publication-identity.mjs";
import { createImageAuthorization } from "../../aws/production-image-authorization.mjs";
import { STAGE_B } from "../../aws/production-green-stage-b-contract.mjs";
import { deriveStageBImageImpactReport } from "../../aws/validate-stage-b-image-reuse.mjs";

const defaultImageReleaseSha = "594bab55f23ff8b2438c12b85b149ba0aebeed1e";
const workflowRunId = "31582010244";
const digests = {
  backend: "sha256:5c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad",
  worker: "sha256:949a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
  "rls-executor": "sha256:6a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
  "rls-canary": "sha256:f26b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
};

export function makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha = defaultImageReleaseSha, impactImageReleaseSha = imageReleaseSha, imageDigests = digests } = {}) {
  const observedAt = new Date().toISOString();
  const records = [
    ["backend", "mscqr-backend", imageReleaseSha],
    ["worker", "mscqr-worker", imageReleaseSha],
    ["rls-executor", "mscqr-backend", `${imageReleaseSha}-rls-executor`],
    ["rls-canary", "mscqr-backend", `${imageReleaseSha}-rls-canary`],
  ].map(([service, repository, tag]) => ({
    service, repository,
    image_uri: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}:${tag}`,
    image_tag: tag,
    image_digest: imageDigests[service],
    image_ref: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}@${imageDigests[service]}`,
  }));
  const artifactBytes = Buffer.from(`${records.map((record) => JSON.stringify(record)).join("\n")}\n`);
  const artifactSha256 = crypto.createHash("sha256").update(artifactBytes).digest("hex");
  const publicationIdentity = buildStageBImagePublicationIdentity({
    expectedPublicationSourceSha: imageReleaseSha,
    expectedReleaseSha: imageReleaseSha,
    artifactBytes,
    observed: {
      workflowRunId, workflowDatabaseId: "401", workflowFile: ".github/workflows/production-green-stage-b-images.yml",
      workflowName: "Production Green Stage B Images", event: "workflow_dispatch", workflowDefinitionSha: imageReleaseSha, imageReleaseSha,
      headBranch: "main", conclusion: "success", artifactId: "501", artifactName: "production-green-stage-b-images",
      artifactExpired: false, artifactArchiveFilename: null,
    },
    observedAt,
  });
  const repositories = ["mscqr-backend", "mscqr-worker"].map((repository) => ({
    repositoryName: repository,
    repositoryArn: `arn:aws:ecr:eu-west-2:${STAGE_B.account}:repository/${repository}`,
    registryId: STAGE_B.account,
    repositoryUri: `${STAGE_B.account}.dkr.ecr.eu-west-2.amazonaws.com/${repository}`,
    imageTagMutability: "IMMUTABLE", encryptionConfiguration: { encryptionType: "AES256" }, createdAt: observedAt, observedAt,
  }));
  const imageReuseEvidence = deriveStageBImageImpactReport({ imageReleaseSha: impactImageReleaseSha, toolingSha: sourceSha });
  const imageEvidence = generateImageEvidence({
    artifactBytes, publicationSourceSha: imageReleaseSha, currentSourceSha: sourceSha, imageReleaseSha, workflowRunId, artifactSha256, publicationIdentity,
    imageReuseEvidence: imageReleaseSha === sourceSha ? undefined : imageReuseEvidence,
    verifierCallerArn: `arn:aws:iam::${STAGE_B.account}:root`, observedAt,
    describe: (repository, tag) => ({ digest: records.find((record) => record.repository === repository && record.image_tag === tag).image_digest, imagePushedAt: observedAt }),
    repositories,
  });
  const imageEvidenceSignature = signImageEvidence(imageEvidence, { now: observedAt, sign: () => "AQ==" });
  const verifyImageEvidence = ({ report, signatureArtifact, now }) => verifyImageEvidenceSignature({ report, signatureArtifact, now, verify: () => true });
  const authorization = createImageAuthorization({ sourceSha, freshProtectedMain: { fetchSucceeded: true, headSha: sourceSha, freshRemoteMainSha: sourceSha }, imageEvidence, imageEvidenceSignature, imageReuseEvidence, now: observedAt, verifyImageEvidence });
  return { authorization, now: observedAt, verifyImageEvidence, imageReleaseSha, workflowRunId, digests: imageDigests };
}
