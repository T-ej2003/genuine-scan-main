import assert from "node:assert/strict";
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TARGETS = Object.freeze({ backend: Object.freeze({ repository: "mscqr-backend", title: "mscqr-backend" }), frontend: Object.freeze({ repository: "mscqr-web", title: "mscqr-frontend" }) });
export function assertNormalImageIdentity({ service, sourceSha, repository, image, labels, platforms = [] } = {}) {
  const target = TARGETS[service];
  assert.ok(target, "Normal release image service is not approved.");
  assert.match(sourceSha || "", SHA, "Normal release source SHA is malformed.");
  const expectedUri = "368992683803.dkr.ecr.eu-west-2.amazonaws.com/" + target.repository;
  assert.equal(repository?.repositoryName, target.repository);
  assert.equal(String(repository?.registryId), "368992683803");
  assert.equal(repository?.repositoryUri, expectedUri);
  assert.equal(repository?.imageTagMutability, "IMMUTABLE");
  assert.deepEqual(repository?.imageTagMutabilityExclusionFilters || [], []);
  assert.equal(image?.repositoryName, target.repository);
  assert.equal(String(image?.registryId), "368992683803");
  assert.ok(Array.isArray(image?.imageTags) && image.imageTags.includes(sourceSha));
  assert.match(image?.imageDigest || "", DIGEST);
  assert.ok(platforms.includes("linux/amd64"), "Normal release image lacks linux/amd64.");
  assert.equal(labels?.["org.opencontainers.image.revision"], sourceSha);
  assert.equal(labels?.["org.opencontainers.image.title"], target.title);
  return expectedUri + "@" + image.imageDigest;
}
