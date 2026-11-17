import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reachabilityInputsSha256 } from "./osv-non-runtime-acceptance.mjs";

const probeScript = fileURLToPath(new URL("./osv-browser-build-probe.mjs", import.meta.url));
const javascriptFile = /\.(?:cjs|mjs|js)$/i;

export function installedDevCopies(root, name, version, lockFile = "package-lock.json") {
  const lock = JSON.parse(readFileSync(path.join(root, lockFile), "utf8"));
  const copies = Object.entries(lock.packages || {}).filter(([location, entry]) =>
    (location === `node_modules/${name}` || location.endsWith(`/node_modules/${name}`)) && entry.version === version);
  assert.ok(copies.length, `Missing locked ${name}@${version}`);
  for (const [location, entry] of copies) {
    assert.equal(entry.dev, true, `Runtime dependency in ${lockFile}: ${location}`);
    assert.match(entry.integrity || "", /^sha512-/, `Missing package integrity: ${location}`);
  }
  return copies.map(([location]) => path.join(root, location));
}

function javascriptSources(directory) {
  const files = [];
  function visit(current) {
    const stat = lstatSync(current);
    assert.ok(!stat.isSymbolicLink(), `Untrusted package symlink: ${current}`);
    if (stat.isDirectory()) for (const name of readdirSync(current)) visit(path.join(current, name));
    else if (stat.isFile() && javascriptFile.test(current)) files.push(current);
  }
  visit(directory);
  assert.ok(files.length, `No executable package source: ${directory}`);
  return files;
}

function browserBuildDigest(root) {
  return JSON.parse(execFileSync(process.execPath, [probeScript, root], {
    encoding: "utf8", maxBuffer: 8 * 1024 * 1024,
    env: { ...process.env, NODE_ENV: "production", VITE_API_URL: "/api", VITE_APP_ENV: "production",
      VITE_SENTRY_DSN: "", GIT_SHA: "unknown", RELEASE_GIT_SHA: "unknown" },
  }));
}

// An absent module ID is insufficient: a build plugin can copy package code
// into an emitted chunk. Change every installed package source in a fresh
// process and require the complete executable output to remain byte-identical.
export function proveBrowserPackageNotEmitted(root, findings, buildDigest = browserBuildDigest) {
  if (!findings.length) return { completed: true, packages: [] };
  const inputsSha256 = reachabilityInputsSha256(root);
  const sourceFiles = new Set();
  for (const { name, version } of findings)
    for (const directory of installedDevCopies(root, name, version, "package-lock.json"))
      for (const file of javascriptSources(directory)) sourceFiles.add(file);
  const before = buildDigest(root);
  const originals = [...sourceFiles].map(file => [file, readFileSync(file)]);
  const marker = `__mscqr_osv_provenance_${createHash("sha256").update(JSON.stringify(findings)).digest("hex").slice(0, 24)}`;
  try {
    for (const [file, bytes] of originals)
      writeFileSync(file, Buffer.concat([bytes, Buffer.from(`\n;globalThis["${marker}"]=(globalThis["${marker}"]||0)+1;\n`)]));
    const after = buildDigest(root);
    assert.deepEqual(after, before, "Build-tool package code may be present in executable browser output");
  } finally {
    for (const [file, bytes] of originals) writeFileSync(file, bytes);
  }
  assert.equal(reachabilityInputsSha256(root), inputsSha256, "Executable source changed during browser proof");
  return { completed: true, inputsSha256, packages: findings.map(({ name, version }) => `${name}@${version}`).sort(), outputSha256: before.outputSha256 };
}

function docker(args, options = {}) {
  return execFileSync("docker", args, { encoding: "utf8", maxBuffer: 8 * 1024 * 1024, ...options }).trim();
}

// Build the exact production stages. The worker publishes the backend runtime
// target, so it has the same dependency filesystem as that backend image.
export function proveProductionImagesExclude(root, findings) {
  const inputsSha256 = reachabilityInputsSha256(root);
  const names = [...new Set(findings.map(({ name }) => name))].sort();
  assert.ok(names.length, "Missing vulnerable package identity");
  assert.ok(names.every(name => /^[a-z0-9][a-z0-9._-]*$/.test(name)), "Unsupported package identity in image census");
  const tagBase = `mscqr-osv-${process.pid}-${Date.now()}`;
  const images = [
    ["backend-and-worker", "backend/Dockerfile", "runtime"],
    ["database-executor", "backend/Dockerfile", "production-rls-executor"],
    ["frontend", "Dockerfile.ecs-frontend", null],
  ];
  const results = [];
  try {
    for (const [role, dockerfile, target] of images) {
      const tag = `${tagBase}-${role}`;
      const args = ["build", "--quiet", "-f", dockerfile, "-t", tag];
      if (target) args.push("--target", target);
      args.push(".");
      docker(args, { cwd: root, stdio: ["ignore", "pipe", "inherit"] });
      const imageId = docker(["image", "inspect", tag, "--format", "{{.Id}}"]);
      // Search all package directories, including nested and global npm trees.
      const matches = docker(["run", "--rm", "--entrypoint", "sh", tag, "-c",
        `for base in /app /usr/local/lib/node_modules /usr/share/nginx/html; do if [ -d "$base" ]; then find "$base" -type d \\( ${names.map(name => `-name '${name.replaceAll("'", "")}'`).join(" -o ")} \\) -print; fi; done`]);
      assert.equal(matches, "", `${role} image retains vulnerable package directories: ${matches}`);
      if (role === "backend-and-worker" || role === "database-executor") {
        assert.equal(docker(["run", "--rm", "--entrypoint", "sh", tag, "-c", "test ! -e /usr/local/bin/npm && test ! -e /usr/local/bin/npx && test ! -d /usr/local/lib/node_modules/npm && echo absent"]), "absent", `${role} retains global npm`);
        if (role === "backend-and-worker")
          assert.equal(docker(["run", "--rm", "--entrypoint", "sh", tag, "-c",
            "test -f /app/dist/index.js && test -f /app/node_modules/prisma/build/index.js && node /app/node_modules/prisma/build/index.js --version >/dev/null && echo ready"]), "ready", "Runtime startup prerequisites missing");
      }
      results.push({ role, imageId, excludedPackages: names });
    }
  } finally {
    for (const [role] of images) {
      try { docker(["image", "rm", "-f", `${tagBase}-${role}`]); } catch { /* best-effort local image cleanup */ }
    }
  }
  assert.equal(reachabilityInputsSha256(root), inputsSha256, "Executable source changed during image proof");
  return { completed: true, inputsSha256, images: results };
}
