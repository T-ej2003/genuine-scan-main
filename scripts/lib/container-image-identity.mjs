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

function dockerfileStages(source) {
  assert.doesNotMatch(source, /\u0000|\r(?!\n)/, "Ambiguous Dockerfile control character");
  const stages = [], aliases = new Set();
  let escape = "\\", directives = true, pending = "", continued = false;
  const seenDirectives = new Set();
  for (const raw of source.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = raw.replace(/^[ \t]+|[ \t]+$/g, "");
    const directive = line.match(/^#\s*(syntax|escape|check)\s*=\s*(.+)$/i);
    if (directive) assert.ok(directives && !pending, "Ambiguous/late Dockerfile parser directive");
    if (directives) {
      if (directive) {
        const name = directive[1].toLowerCase(), value = directive[2];
        assert.ok(!seenDirectives.has(name), "Duplicate Dockerfile parser directive");
        seenDirectives.add(name);
        if (name === "escape") { assert.ok(["\\", "`"].includes(value), "Unsupported Dockerfile escape"); escape = value; }
        if (name === "syntax") assert.equal(value, "docker/dockerfile:1.7", "Unapproved Dockerfile parser frontend");
        continue;
      }
      directives = false;
    }
    if (!line || line.startsWith("#")) continue;
    const continuation = line.endsWith(escape);
    continued = continuation;
    assert.ok(!line.endsWith(escape + escape), "Ambiguous Dockerfile continuation");
    pending += continuation ? line.slice(0, -1) : line;
    if (continuation) continue;
    const instruction = pending.match(/^([a-z]+)(?:\s+(.*))?$/i);
    assert.ok(instruction, "Malformed Dockerfile instruction");
    const name = instruction[1].toUpperCase(), argumentsText = instruction[2] || "";
    assert.ok(argumentsText, "Missing Dockerfile instruction arguments");
    assert.ok(["FROM", "ARG", "RUN", "COPY", "ADD", "WORKDIR", "ENV", "LABEL", "EXPOSE", "USER", "CMD", "ENTRYPOINT", "VOLUME", "STOPSIGNAL", "HEALTHCHECK", "SHELL", "MAINTAINER"].includes(name), "Unsupported Dockerfile instruction");
    assert.doesNotMatch(argumentsText, /<</, "Unsupported Dockerfile heredoc");
    pending = "";
    if (name !== "FROM") {
      assert.ok(stages.length || name === "ARG", "Instruction before first FROM");
      if (!stages.length) assert.doesNotMatch(argumentsText, /^(?:BUILDPLATFORM|TARGETPLATFORM)(?:=|$)/, "Unbound automatic platform override");
      const knownStage = reference => {
        const prior = stages.slice(0, -1);
        assert.ok(prior.some(stage => stage.alias?.toLowerCase() === reference.toLowerCase()) || (/^(0|[1-9][0-9]*)$/.test(reference) && Number(reference) < prior.length), "Unapproved external/undeclared stage reference");
      };
      const flags = (argumentsText.match(/^(?:--\S+(?:\s+|$))*/)?.[0] || "").trim().split(/\s+/);
      for (const flag of flags) {
        if (name === "COPY" && /^--from/i.test(flag)) {
          assert.match(flag, /^--from=[a-z0-9_.-]+$/i, "Unsupported COPY stage reference");
          knownStage(flag.slice(7));
        }
        if (name === "RUN" && /^--mount=/i.test(flag)) {
          assert.doesNotMatch(flag, /["'$\\`]/, "Unsupported RUN mount reference syntax");
          for (const option of flag.slice(8).split(",")) if (/^from=/i.test(option)) knownStage(option.slice(5));
        }
      }
      continue;
    }
    const tokens = argumentsText.split(/\s+/).filter(Boolean);
    let platform;
    if (tokens[0]?.startsWith("--")) {
      platform = tokens.shift().match(/^--platform=(linux\/(?:amd64|arm64(?:\/v8)?)|\$(?:BUILDPLATFORM|TARGETPLATFORM)|\$\{(?:BUILDPLATFORM|TARGETPLATFORM)\})$/)?.[1];
      assert.ok(platform, "Unsupported FROM platform argument");
    }
    assert.ok(tokens.length === 1 || (tokens.length === 3 && tokens[1].toUpperCase() === "AS"), "Malformed FROM instruction");
    const [reference, , alias] = tokens;
    // Build-arg defaults do not authenticate overrides supplied by actual builds.
    assert.doesNotMatch(reference, /[$\\`'"#]/, "Unbound/unsupported FROM image reference");
    const internal = aliases.has(reference.toLowerCase());
    if (alias) {
      assert.match(alias, /^[a-z][a-z0-9_.-]*$/i, "Malformed FROM stage alias");
      assert.ok(!aliases.has(alias.toLowerCase()), "Duplicate FROM stage alias");
      aliases.add(alias.toLowerCase());
    }
    stages.push({ reference, internal, alias, platform });
  }
  assert.ok(!continued && pending === "", "Unterminated Dockerfile continuation");
  assert.ok(stages.length, "Dockerfile has no FROM stages");
  return stages;
}

export function assertPinnedImageInputs(repository = root) {
  const images = readApprovedImages(repository);
  const counts = (file, pattern, key, count) => {
    const values = [...readFileSync(path.join(repository, file), "utf8").matchAll(pattern)].map(match => match[1]);
    assert.equal(values.filter(value => value === images[key].reference).length, count, `${file}: unapproved ${key} image`);
    return values;
  };
  for (const file of ["Dockerfile", "Dockerfile.ecs-frontend", "backend/Dockerfile"]) {
    const stages = dockerfileStages(readFileSync(path.join(repository, file), "utf8"));
    const backend = file === "backend/Dockerfile";
    assert.ok(stages.every(stage => stage.internal || [images.node.reference, ...(backend ? [] : [images.nginx.reference])].includes(stage.reference)), `${file}: unapproved base image`);
    assert.equal(stages.length, backend ? 5 : 2, `${file}: unexpected stage count`);
    const external = stages.filter(stage => !stage.internal);
    assert.equal(external.filter(stage => stage.reference === images.node.reference).length, backend ? 3 : 1, `${file}: unapproved node stage set`);
    if (!backend) {
      assert.equal(external.filter(stage => stage.reference === images.nginx.reference).length, 1, `${file}: unapproved nginx stage set`);
      assert.equal(stages[0].reference, images.node.reference, `${file}: unapproved frontend builder family`);
      assert.equal(stages.at(-1).reference, images.nginx.reference, `${file}: unapproved frontend runtime family`);
    }
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
