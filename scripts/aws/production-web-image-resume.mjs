import { WEB_RELEASE } from "./production-web-release-contract.mjs";

const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const IMAGE = `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}`;

export function resolveWebImagePublication({ sourceSha, repository, image, labels, platforms = [] } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Web image source SHA is malformed.");
  if (repository?.repositoryName !== WEB_RELEASE.repository
    || String(repository.registryId) !== WEB_RELEASE.account
    || repository.repositoryUri !== IMAGE
    || repository.imageTagMutability !== "IMMUTABLE"
    || repository.imageTagMutabilityExclusionFilters?.length) {
    throw new Error("Web image repository is not the reviewed immutable target.");
  }
  const imageUri = `${IMAGE}:${sourceSha}`;
  if (!image) return Object.freeze({ mode: "PUBLISH", imageUri });
  if (!Array.isArray(image.imageTags) || image.repositoryName !== WEB_RELEASE.repository
    || String(image.registryId) !== WEB_RELEASE.account || !image.imageTags.includes(sourceSha)
    || !DIGEST.test(image.imageDigest || "")) throw new Error("Existing web image tag readback is invalid.");
  if (!platforms.includes(WEB_RELEASE.platform)) throw new Error("Existing web image does not provide the required platform.");
  if (labels?.["org.opencontainers.image.revision"] !== sourceSha
    || labels?.["org.opencontainers.image.title"] !== "mscqr-frontend") {
    throw new Error("Existing web image is not bound to this protected source.");
  }
  return Object.freeze({ mode: "RESUME", imageUri, imageDigest: image.imageDigest, imageRef: `${IMAGE}@${image.imageDigest}` });
}
