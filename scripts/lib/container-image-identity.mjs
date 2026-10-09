import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { setTimeout as pause } from "node:timers/promises";

const root = path.resolve(import.meta.dirname, "../..");
const digest = value => assert.match(value || "", /^sha256:[a-f0-9]{64}$/);
const hash = bytes => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

export function readApprovedImages(repository = root) {
  const lock = JSON.parse(readFileSync(path.join(repository, "docker/base-image-identities.json")));
  assert.equal(lock.schemaVersion, 1);
  assert.equal(lock.publisher, "Docker Official Images");
  assert.deepEqual(Object.keys(lock.images).sort(), ["alpine", "nginx", "node", "postgres", "postgres-canary", "postgres-certification", "redis"]);
  for (const [name, image] of Object.entries(lock.images)) {
    digest(image.digest);
    assert.match(image.upstream, /^(?:alpine|nginx|node|postgres|redis):[a-zA-Z0-9._-]+(?:@sha256:[a-f0-9]{64})?$/);
    assert.ok(image.upstream.startsWith(`${name.split("-")[0]}:`), "Image family substitution");
    assert.equal(image.reference, `public.ecr.aws/docker/library/${image.upstream.split(":")[0]}@${image.digest}`);
    assert.deepEqual(Object.keys(image.platforms).sort(), ["amd64", "arm64"]);
    for (const platform of Object.values(image.platforms)) {
      digest(platform.manifestDigest); digest(platform.configDigest);
      assert.ok(platform.layerDigests.length > 0);
      platform.layerDigests.forEach(digest);
    }
  }
  return lock.images;
}

export function assertPinnedImageInputs(repository = root) {
  const images = readApprovedImages(repository);
  const counts = (file, pattern, key, count) => {
    const values = [...readFileSync(path.join(repository, file), "utf8").matchAll(pattern)].map(match => match[1]);
    assert.equal(values.filter(value => value === images[key].reference).length, count, `${file}: unapproved ${key} image`);
    return values;
  };
  for (const file of ["Dockerfile", "Dockerfile.ecs-frontend", "backend/Dockerfile"]) {
    const refs = counts(file, /^FROM\s+(\S+)/gm, "node", file === "backend/Dockerfile" ? 3 : 1);
    if (file !== "backend/Dockerfile") counts(file, /^FROM\s+(\S+)/gm, "nginx", 1);
    assert.ok(refs.every(ref => [images.node.reference, images.nginx.reference, "deps", "runtime"].includes(ref)), `${file}: unexpected base image`);
  }
  for (const [file, count] of [[".github/workflows/auth-security-tests.yml", 1], [".github/workflows/quality-gate.yml", 2], [".github/workflows/release-gate.yml", 1], ["docker-compose.p2-test.yml", 1]]) {
    counts(file, /^\s+image:\s+(\S+)\s*$/gm, "postgres", count);
  }
  counts(".github/workflows/quality-gate.yml", /^\s+image:\s+(\S+)\s*$/gm, "redis", 2);
  counts(".github/workflows/release-gate.yml", /^\s+image:\s+(\S+)\s*$/gm, "redis", 1);
  counts("docker-compose.p2-test.yml", /^\s+image:\s+(\S+)\s*$/gm, "redis", 1);
  counts("docker-compose.production-read-only-rls-canary-test.yml", /^\s+image:\s+(\S+)\s*$/gm, "postgres-canary", 1);
  counts("docker-compose.rls-certification.yml", /^\s+image:\s+(\S+)\s*$/gm, "postgres-certification", 1);
  const audit = readFileSync(path.join(repository, ".github/workflows/deployment-audit.yml"), "utf8");
  assert.match(audit, /run: docker build -t deployment-audit:latest -f "\$\{\{ steps\.docker-detect\.outputs\.dockerfile \}\}" "\$\{\{ steps\.docker-detect\.outputs\.context \}\}"/);
  assert.doesNotMatch(audit, /--build-context/);
  const production = readFileSync(path.join(repository, ".github/workflows/production-web-image.yml"), "utf8");
  assert.match(production, /docker buildx build --platform "\$PLATFORM" --file Dockerfile\.ecs-frontend/);
  assert.doesNotMatch(production, /--build-context/);
  return images;
}

export function assertDisposablePostgresImage(instance) {
  const image = readApprovedImages().postgres;
  assert.equal(instance.Config.Image, image.reference);
  // Docker's classic store reports config IDs; its containerd store reports index/manifest IDs.
  const identities = [image.digest, ...Object.values(image.platforms).flatMap(platform => [platform.manifestDigest, platform.configDigest])];
  assert.ok(identities.includes(instance.Image), "Unapproved PostgreSQL content identity");
}

export function assertImageManifest(bytes, expectedDigest) {
  assert.equal(hash(bytes), expectedDigest, "Registry substituted manifest/config bytes");
  return JSON.parse(Buffer.from(bytes));
}

export async function verifyApprovedImage(image, { fetcher = fetch, upstream = false, wait = pause } = {}) {
  const name = image.upstream.split(":")[0];
  const host = upstream ? "registry-1.docker.io" : "public.ecr.aws";
  const repository = upstream ? `library/${name}` : `docker/library/${name}`;
  const get = async (url, headers = {}) => {
    for (let attempt = 0; attempt < 4; attempt++) {
      const response = await fetcher(url, { headers, signal: AbortSignal.timeout(30000) });
      if (response.ok) return Buffer.from(await response.arrayBuffer());
      if (attempt === 3 || ![429, 500, 502, 503, 504].includes(response.status)) {
        assert.fail(`Registry read failed: ${host} HTTP ${response.status}`);
      }
      // Retry read-only requests for the same identity; every returned byte still authenticates.
      const retryAfter = Number(response.headers.get("retry-after"));
      await response.body?.cancel();
      await wait(Math.max(1000 * 2 ** attempt, Math.min(30000, Number.isFinite(retryAfter) ? retryAfter * 1000 : 0)));
    }
  };
  const tokenUrl = upstream
    ? `https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repository}:pull`
    : `https://public.ecr.aws/token/?service=public.ecr.aws&scope=repository:${repository}:pull`;
  const token = JSON.parse(await get(tokenUrl)).token;
  assert.ok(typeof token === "string" && token);
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json" };
  const manifest = ref => get(`https://${host}/v2/${repository}/manifests/${ref}`, headers);
  // Routine builds never resolve a mutable tag; upstream review deliberately does.
  const ref = upstream ? image.upstream.slice(name.length + 1).split("@").at(-1) : image.digest;
  const index = assertImageManifest(await manifest(ref), image.digest);
  for (const [architecture, expected] of Object.entries(image.platforms)) {
    const descriptors = index.manifests.filter(entry => entry.platform?.os === "linux" && entry.platform.architecture === architecture);
    assert.equal(descriptors.length, 1, `Ambiguous/missing linux/${architecture}`);
    assert.equal(descriptors[0].digest, expected.manifestDigest);
    const content = assertImageManifest(await manifest(expected.manifestDigest), expected.manifestDigest);
    assert.equal(content.config.digest, expected.configDigest);
    assert.deepEqual(content.layers.map(layer => layer.digest), expected.layerDigests);
    const config = assertImageManifest(await get(`https://${host}/v2/${repository}/blobs/${expected.configDigest}`, headers), expected.configDigest);
    assert.equal(config.architecture, architecture); assert.equal(config.os, "linux");
  }
  return image.digest;
}
