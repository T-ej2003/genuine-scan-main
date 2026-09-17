import assert from "node:assert/strict";
import test from "node:test";
import { WEB_RELEASE } from "../aws/production-web-release-contract.mjs";
import { resolveWebImagePublication } from "../aws/production-web-image-resume.mjs";

const sourceSha = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
const repository = { repositoryName: WEB_RELEASE.repository, repositoryUri: `${WEB_RELEASE.account}.dkr.ecr.${WEB_RELEASE.region}.amazonaws.com/${WEB_RELEASE.repository}`, registryId: WEB_RELEASE.account, imageTagMutability: "IMMUTABLE", imageTagMutabilityExclusionFilters: [] };
const image = (changes = {}) => ({ repositoryName: WEB_RELEASE.repository, registryId: WEB_RELEASE.account, imageTags: [sourceSha], imageDigest: digest, ...changes });
const labels = { "org.opencontainers.image.revision": sourceSha, "org.opencontainers.image.title": "mscqr-frontend" };

test("web publication builds when the immutable SHA tag is absent", () => {
  assert.deepEqual(resolveWebImagePublication({ sourceSha, repository }), { mode: "PUBLISH", imageUri: `${repository.repositoryUri}:${sourceSha}` });
});

test("web publication resumes an authenticated immutable SHA tag by digest", () => {
  assert.deepEqual(resolveWebImagePublication({ sourceSha, repository, image: image(), labels, platforms: ["linux/amd64"] }), { mode: "RESUME", imageUri: `${repository.repositoryUri}:${sourceSha}`, imageDigest: digest, imageRef: `${repository.repositoryUri}@${digest}` });
});

test("web publication rejects unauthenticated existing-image state", () => {
  for (const changes of [
    { imageDigest: "not-a-sha256-digest" },
    { imageTags: ["c".repeat(40)] },
    { repositoryName: "other" },
    { registryId: "111111111111" },
  ]) assert.throws(() => resolveWebImagePublication({ sourceSha, repository, image: image(changes), labels, platforms: ["linux/amd64"] }));
  for (const invalidLabels of [{ ...labels, "org.opencontainers.image.revision": "c".repeat(40) }, { ...labels, "org.opencontainers.image.title": "other" }]) assert.throws(() => resolveWebImagePublication({ sourceSha, repository, image: image(), labels: invalidLabels, platforms: ["linux/amd64"] }));
  assert.throws(() => resolveWebImagePublication({ sourceSha, repository: { ...repository, imageTagMutability: "MUTABLE" }, image: image(), labels, platforms: ["linux/amd64"] }));
  assert.throws(() => resolveWebImagePublication({ sourceSha, repository, image: image(), labels, platforms: ["linux/arm64"] }));
});

test("resume state never authorizes a tag-only or caller-substituted digest", () => {
  assert.throws(() => resolveWebImagePublication({ sourceSha, repository, image: image({ imageDigest: "latest" }), labels, platforms: ["linux/amd64"] }));
  assert.notEqual(resolveWebImagePublication({ sourceSha, repository, image: image(), labels, platforms: ["linux/amd64"] }).imageRef, `${repository.repositoryUri}:latest`);
});

test("every post-publication interruption resumes from the same authenticated digest", () => {
  for (const boundary of ["after-push", "after-scan", "after-sbom", "after-provenance", "after-cosign", "after-sbom-attestation", "after-provenance-attestation", "after-artifact"]) {
    const resumed = resolveWebImagePublication({ sourceSha, repository, image: image(), labels, platforms: ["linux/amd64"] });
    assert.equal(resumed.mode, "RESUME", boundary);
    assert.equal(resumed.imageRef, `${repository.repositoryUri}@${digest}`, boundary);
  }
});
