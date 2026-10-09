import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { load } from "js-yaml";
import { readApprovedImages, assertPinnedImageInputs, assertDisposablePostgresImage, verifyApprovedImage } from "../lib/container-image-identity.mjs";

const images = readApprovedImages();
const sha = value => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const bytes = value => Buffer.from(JSON.stringify(value));
const files = ["Dockerfile", "Dockerfile.ecs-frontend", "backend/Dockerfile", ".github/workflows/auth-security-tests.yml", ".github/workflows/quality-gate.yml", ".github/workflows/release-gate.yml", ".github/workflows/deployment-audit.yml", ".github/workflows/production-web-image.yml", "docker-compose.p2-test.yml", "docker-compose.production-read-only-rls-canary-test.yml", "docker-compose.rls-certification.yml", "docker/base-image-identities.json"];
function checkout(run) {
  const root = mkdtempSync(path.join(os.tmpdir(), "mscqr-image-contract-"));
  try {
    for (const file of files) { mkdirSync(path.dirname(path.join(root, file)), { recursive: true }); writeFileSync(path.join(root, file), readFileSync(file)); }
    return run(root);
  } finally { rmSync(root, { recursive: true, force: true }); }
}
function fixture() {
  const resources = new Map();
  const image = { upstream: "nginx:1.29-alpine", platforms: {} };
  const descriptors = [];
  for (const architecture of ["amd64", "arm64"]) {
    const config = bytes({ architecture, os: "linux" }); const configDigest = sha(config);
    const layers = [sha(`${architecture}:layer`)];
    const manifest = bytes({ config: { digest: configDigest }, layers: layers.map(digest => ({ digest })) });
    const manifestDigest = sha(manifest);
    descriptors.push({ platform: { architecture, os: "linux" }, digest: manifestDigest });
    image.platforms[architecture] = { manifestDigest, configDigest, layerDigests: layers };
    resources.set(manifestDigest, manifest); resources.set(configDigest, config);
  }
  const index = bytes({ manifests: descriptors }); image.digest = sha(index);
  image.reference = `public.ecr.aws/docker/library/nginx@${image.digest}`;
  resources.set(image.digest, index); resources.set("1.29-alpine", index);
  const requests = [];
  const fetcher = async url => {
    requests.push(url);
    if (url.includes("/token")) return new Response(JSON.stringify({ token: "fixture-public-pull-token" }));
    const body = resources.get(url.split("/").at(-1));
    return new Response(body || "missing", { status: body ? 200 : 404 });
  };
  return { image, resources, fetcher, requests };
}

test("public audit builds the same approved nginx and Node bytes as production", () => {
  assertPinnedImageInputs();
  const steps = load(readFileSync(".github/workflows/deployment-audit.yml", "utf8")).jobs.audit.steps;
  const command = steps.find(step => step.name === "Build container for scan").run
    .replaceAll("${{ steps.docker-detect.outputs.dockerfile }}", "Dockerfile")
    .replaceAll("${{ steps.docker-detect.outputs.context }}", ".");
  const output = execFileSync("bash", ["-eu", "-c", `docker() { printf '%s\\n' "$@"; }; ${command}`], { encoding: "utf8" });
  assert.deepEqual(output.trim().split("\n"), ["build", "-t", "deployment-audit:latest", "-f", "Dockerfile", "."]);
  for (const file of ["Dockerfile", "Dockerfile.ecs-frontend"]) {
    assert.ok(readFileSync(file, "utf8").includes(`FROM ${images.nginx.reference}`));
    assert.ok(readFileSync(file, "utf8").includes(`FROM ${images.node.reference} AS builder`));
  }
  assert.equal(steps.find(step => step.name === "Trivy container scan").with["image-ref"], "deployment-audit:latest");
  assert.equal(steps.find(step => step.name === "Trivy IaC scan").with["scan-type"], "config");
  assert.equal(steps.find(step => step.name === "Generate SBOM").with.format, "spdx-json");
  assert.equal(steps.find(step => step.name === "Run OSV Scanner").run, "node scripts/check-osv-runtime.mjs audit-artifacts/osv-source.json");
  assert.equal(load(readFileSync(".github/workflows/deployment-audit.yml", "utf8")).jobs.audit["continue-on-error"], undefined);
  for (const name of ["Trivy container scan", "Trivy IaC scan", "Generate SBOM", "Run OSV Scanner"]) {
    const step = steps.find(value => value.name === name);
    assert.equal(step["continue-on-error"], undefined);
    assert.doesNotMatch(step.if || "", /always|failure|cancelled/);
  }
  assert.equal(steps.find(step => step.name === "Verify approved base image provenance").run, "node scripts/verify-container-image-provenance.mjs");
});

for (const file of ["Dockerfile", "Dockerfile.ecs-frontend", "backend/Dockerfile"]) {
  test(`${file}: unapproved or mutable base substitution fails`, () => checkout(root => {
    const key = file === "backend/Dockerfile" ? "node" : "nginx";
    const target = path.join(root, file);
    writeFileSync(target, readFileSync(target, "utf8").replace(images[key].reference, images[key].upstream));
    assert.throws(() => assertPinnedImageInputs(root), /unapproved/);
  }));
}
test("old audit-only override cannot silently replace production content", () => checkout(root => {
  const target = path.join(root, ".github/workflows/deployment-audit.yml");
  writeFileSync(target, readFileSync(target, "utf8").replace("docker build -t", "docker build --build-context nginx=docker-image://untrusted/image -t"));
  assert.throws(() => assertPinnedImageInputs(root));
}));
test("approved updates advance audit and production together", async () => {
  const f = fixture();
  await verifyApprovedImage(f.image, { fetcher: f.fetcher });
  await verifyApprovedImage(f.image, { fetcher: f.fetcher, upstream: true });
  checkout(root => {
    for (const file of ["Dockerfile", "Dockerfile.ecs-frontend"]) writeFileSync(path.join(root, file), readFileSync(file, "utf8").replace(images.nginx.reference, f.image.reference));
    assert.throws(() => assertPinnedImageInputs(root));
    const lockFile = path.join(root, "docker/base-image-identities.json"); const lock = JSON.parse(readFileSync(lockFile)); lock.images.nginx = f.image;
    writeFileSync(lockFile, JSON.stringify(lock)); assertPinnedImageInputs(root);
  });
});
test("routine mirror reads require immutable approved amd64 and arm64 content, without Docker Hub", async () => {
  const f = fixture(); await verifyApprovedImage(f.image, { fetcher: f.fetcher });
  assert.ok(f.requests.every(url => url.startsWith("https://public.ecr.aws/")));
  assert.ok(!f.requests.some(url => url.endsWith("/manifests/1.29-alpine")));
  for (const platform of Object.values(f.image.platforms)) assert.ok(f.requests.some(url => url.endsWith(platform.configDigest)));
});
test("mutable upstream tag advancement fails explicit image update review", async () => {
  const f = fixture(); f.resources.set("1.29-alpine", bytes({ newer: true }));
  await assert.rejects(verifyApprovedImage(f.image, { fetcher: f.fetcher, upstream: true }), /substituted/);
});
for (const target of ["index", "manifest", "config"]) {
  test(`mirror ${target} substitution fails closed`, async () => {
    const f = fixture(); const digest = target === "index" ? f.image.digest : target === "manifest" ? f.image.platforms.amd64.manifestDigest : f.image.platforms.amd64.configDigest;
    f.resources.set(digest, bytes({ unapproved: true }));
    await assert.rejects(verifyApprovedImage(f.image, { fetcher: f.fetcher }), /substituted/);
  });
}
for (const field of ["manifestDigest", "configDigest", "layerDigests"]) {
  test(`incorrect arm64 ${field} cannot pass approved index verification`, async () => {
    const f = fixture(); f.image.platforms.arm64[field] = field === "layerDigests" ? [sha("foreign")] : sha("foreign");
    await assert.rejects(verifyApprovedImage(f.image, { fetcher: f.fetcher }));
  });
}
for (const status of [401, 429, 500]) {
  test(`registry HTTP ${status} never falls back or passes`, async () => {
    const f = fixture(); await assert.rejects(verifyApprovedImage(f.image, { fetcher: async () => new Response("unavailable", { status }), wait: async () => {} }), /Registry read failed/);
  });
}
test("bounded read-only registry retries still authenticate every immutable byte", async () => {
  const f = fixture(); let attempts = 0; const delays = [];
  await verifyApprovedImage(f.image, { fetcher: async url => attempts++ === 0 ? new Response("throttled", { status: 429, headers: { "retry-after": "2" } }) : f.fetcher(url), wait: async delay => delays.push(delay) });
  assert.deepEqual(delays, [2000]);
  const invalid = fixture(); invalid.resources.set(invalid.image.digest, bytes({ substituted: true }));
  let retry = true;
  await assert.rejects(verifyApprovedImage(invalid.image, { fetcher: async url => { if (retry) { retry = false; return new Response("throttled", { status: 429 }); } return invalid.fetcher(url); }, wait: async () => {} }), /substituted/);
  let reads = 0;
  await assert.rejects(verifyApprovedImage(f.image, { fetcher: async () => { reads++; return new Response("throttled", { status: 429 }); }, wait: async () => {} }), /HTTP 429/);
  assert.equal(reads, 4);
});
test("PostgreSQL mirror keeps strict reference and native content identity assertions", () => {
  const reference = images.postgres.reference;
  for (const platform of Object.values(images.postgres.platforms)) assertDisposablePostgresImage({ Config: { Image: reference }, Image: platform.configDigest });
  assertDisposablePostgresImage({ Config: { Image: reference }, Image: images.postgres.digest });
  assert.throws(() => assertDisposablePostgresImage({ Config: { Image: "postgres:18.4" }, Image: images.postgres.digest }));
  assert.throws(() => assertDisposablePostgresImage({ Config: { Image: reference }, Image: sha("foreign") }));
});
test("PostgreSQL and Node registry/digest substitution cannot masquerade as approved", () => checkout(root => {
  const file = path.join(root, ".github/workflows/auth-security-tests.yml");
  writeFileSync(file, readFileSync(file, "utf8").replace(images.postgres.reference, images.postgres.reference.replace("public.ecr.aws", "foreign.example")));
  assert.throws(() => assertPinnedImageInputs(root));
}));

test("a different official image family cannot replace the Node contract", () => checkout(root => {
  const target = path.join(root, "docker/base-image-identities.json");
  const lock = JSON.parse(readFileSync(target)); lock.images.node = lock.images.nginx;
  writeFileSync(target, JSON.stringify(lock)); assert.throws(() => readApprovedImages(root), /family substitution/);
}));

for (const instruction of ['from', '   FROM', '\tFrOm']) {
  for (const file of ['Dockerfile', 'Dockerfile.ecs-frontend', 'backend/Dockerfile']) {
    test(`${file}: complete enumeration rejects additional ${instruction} stage`, () => checkout(root => {
      const target = path.join(root, file);
      writeFileSync(target, readFileSync(target, 'utf8') + `\n${instruction} unapproved/image AS injected\n`);
      assert.throws(() => assertPinnedImageInputs(root), /unapproved|unexpected|stage/i);
    }));
  }
}
for (const instruction of ['FROM', 'from', '   FrOm']) {
  test(`approved full multi-stage Dockerfiles accept ${instruction} syntax`, () => checkout(root => {
    for (const file of ['Dockerfile', 'Dockerfile.ecs-frontend', 'backend/Dockerfile']) {
      const target = path.join(root, file);
      writeFileSync(target, readFileSync(target, 'utf8').replace(/^FROM /gm, `${instruction} `));
    }
    assertPinnedImageInputs(root);
  }));
}
test('platform arguments, continuations, comments and declared internal stages authenticate', () => checkout(root => {
  const target = path.join(root, 'backend/Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8').replace(/^FROM /gm, '  FrOm --platform=$BUILDPLATFORM ').replace(' AS deps', ' \\\n# skipped Docker comment\n aS deps'));
  assertPinnedImageInputs(root);
}));
for (const instruction of [
  'FROM', 'FROM --platform=linux/amd64', 'FROM --unknown=x deps',
  'FROM --platform=linux/amd64 --platform=linux/arm64 deps',
  'FROM deps AS', 'FROM deps AS repeated extra', 'FROM missing-stage AS another',
  'FROM $UNBOUND AS another', 'FROM ${UNBOUND:-unapproved/image} AS another',
  'FROM deps # not an inline comment', 'FROM deps AS runtime',
  'FROM deps AS 123', 'FROM deps AS unapproved/stage',
]) {
  test(`malformed/ambiguous/unbound stage fails: ${instruction}`, () => checkout(root => {
    const target = path.join(root, 'backend/Dockerfile');
    writeFileSync(target, readFileSync(target, 'utf8') + `\n${instruction}\n`);
    assert.throws(() => assertPinnedImageInputs(root));
  }));
}
test('approved extra stages cannot bypass the required complete stage count', () => checkout(root => {
  const target=path.join(root, 'backend/Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8') + '\nfrom deps AS extra\n');
  assert.throws(() => assertPinnedImageInputs(root), /stage/i);
}));
test('undeclared internal names cannot be mistaken for approved prior stages', () => checkout(root => {
  const target=path.join(root, 'backend/Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8').replace(' AS deps', ' AS dependencies'));
  assert.throws(() => assertPinnedImageInputs(root), /unapproved|unexpected/i);
}));

test('non-ASCII trailing whitespace cannot launder a separate unapproved FROM into RUN', () => checkout(root => {
  const target=path.join(root, 'Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8') + '\nRUN echo inert \\\u00a0\nfrom unapproved/image\n');
  assert.throws(() => assertPinnedImageInputs(root), /unapproved|unexpected/i);
}));
test('alternate Docker escape directive still enumerates every stage', () => checkout(root => {
  const target=path.join(root, 'Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8').replace('# syntax=docker/dockerfile:1.7', '# syntax=docker/dockerfile:1.7\n# escape=`').replace(/\\\n/g, '`\n') + '\nfrOm `\n unapproved/image\n');
  assert.throws(() => assertPinnedImageInputs(root), /unapproved|unexpected/i);
}));
for (const suffix of [
  '\nfrom \\\n  # ignored comment\n unapproved/image\n',
  '\nFROM deps \\\n AS injected\n',
  '\nRUN <<EOF\nfrom unapproved/image\nEOF\n',
  '\nFROM deps \\',
]) {
  test('continued/unsupported syntax cannot hide an additional stage: '+JSON.stringify(suffix), () => checkout(root => {
    const target=path.join(root, 'backend/Dockerfile');
    writeFileSync(target, readFileSync(target, 'utf8') + suffix);
    assert.throws(() => assertPinnedImageInputs(root));
  }));
}
for (const header of ['# syntax=unapproved/frontend', '# escape=x', '# escape=\\\n# escape=`', 'ARG BUILDPLATFORM=linux/s390x']) {
  test('unapproved/ambiguous parser or platform binding fails: '+header, () => checkout(root => {
    const target=path.join(root, 'Dockerfile');
    writeFileSync(target, readFileSync(target, 'utf8').replace('# syntax=docker/dockerfile:1.7', header));
    assert.throws(() => assertPinnedImageInputs(root));
  }));
}
test('variable image defaults cannot authenticate later build-argument overrides', () => checkout(root => {
  const target=path.join(root, 'Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8').replace('\n\nFROM', `\n\nARG BASE=${images.node.reference}\nFROM`).replace(`FROM ${images.node.reference}`, 'FROM ${BASE}'));
  assert.throws(() => assertPinnedImageInputs(root), /Unbound/);
}));

test('a late parser directive cannot change the validated instruction interpretation', () => checkout(root => {
  const target=path.join(root, 'Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8')+'\n# syntax=unapproved/frontend\n');
  assert.throws(() => assertPinnedImageInputs(root), /directive/);
}));

for (const instruction of ['copy --from=unapproved/image /payload /payload', 'RUN --mount=type=bind,from=unapproved/image,target=/source true']) {
  test('implicit external image sources cannot evade the complete stage contract: '+instruction, () => checkout(root => {
    const target=path.join(root, 'Dockerfile');
    writeFileSync(target, readFileSync(target, 'utf8')+'\n'+instruction+'\n');
    assert.throws(() => assertPinnedImageInputs(root), /Unsupported|Unapproved/);
  }));
}
test('COPY stage indexes and RUN mounts may use authenticated prior stages', () => checkout(root => {
  const target=path.join(root, 'Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8').replace('COPY --from=builder', 'copy --from=0')+'\nRUN --mount=type=bind,from=builder,target=/source true\n');
  assertPinnedImageInputs(root);
}));

for (const instruction of ['COPY --FrOm=unapproved/image /payload /payload', 'RUN --mount=type=bind,FrOm=unapproved/image,target=/source true', 'RUN --mount="type=bind,from=unapproved/image,target=/source" true']) {
  test('implicit image reference syntax cannot launder a foreign source: '+instruction, () => checkout(root => {
    const target=path.join(root, 'Dockerfile');
    writeFileSync(target, readFileSync(target, 'utf8')+'\n'+instruction+'\n');
    assert.throws(() => assertPinnedImageInputs(root), /Unsupported|Unapproved/);
  }));
}

test('empty dangling continuation cannot be silently discarded at EOF', () => checkout(root => {
  const target=path.join(root, 'Dockerfile');
  writeFileSync(target, readFileSync(target, 'utf8')+'\n\\\n# no continuation target\n');
  assert.throws(() => assertPinnedImageInputs(root), /Unterminated/);
}));

for (const file of ['Dockerfile', 'Dockerfile.ecs-frontend']) {
  test(file+': exchanging approved builder/runtime families cannot evade identity alignment', () => checkout(root => {
    const target=path.join(root, file);
    writeFileSync(target, readFileSync(target, 'utf8').replace(images.node.reference, 'temporary-builder-placeholder').replace(images.nginx.reference, images.node.reference).replace('temporary-builder-placeholder', images.nginx.reference));
    assert.throws(() => assertPinnedImageInputs(root), /family/);
  }));
}
