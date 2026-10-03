import assert from "node:assert/strict";
import { realpathSync, readFileSync, mkdtempSync, rmSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import { parse } from "parse5";

const repository = path.resolve(new URL("..", import.meta.url).pathname);
const readJson = file => JSON.parse(readFileSync(file, "utf8"));

export async function buildBrowserClosure(root, options = {}) {
  root = realpathSync(root);
  const outDir = mkdtempSync(path.join(os.tmpdir(), "mscqr-browser-closure-"));
  const modules = new Set();
  const chunks = new Set();
  let completed = 0;
  const plugin = () => ({
    name: "production-runtime-census",
    resolveDynamicImport(specifier) {
      assert.equal(typeof specifier, "string", "Unknown dynamic import runtime reachability");
      return null;
    },
    generateBundle(_options, bundle) {
      for (const id of this.getModuleIds()) {
        const info = this.getModuleInfo(id);
        assert.ok(info && info.code !== null, `Unknown external runtime module: ${id}`);
        modules.add(id);
      }
      for (const output of Object.values(bundle)) if (output.type === "chunk") {
        for (const imported of [...output.imports, ...output.dynamicImports]) assert.ok(bundle[imported], `Unknown external browser import: ${imported}`);
        chunks.add(output.fileName);
        Object.keys(output.modules).forEach(id => modules.add(id));
      }
      completed++;
    },
  });
  try {
    await build({ root, ...options, plugins: [...(options.plugins || []), { ...plugin(), config(config) {
        const inherited = config.worker?.plugins;
        return { worker: { plugins: () => [...(inherited?.() || []), plugin()] } };
      } }],
      build: { ...options.build, outDir, emptyOutDir: true, write: true },
    });
    assert.ok(completed && chunks.size && modules.size, "Missing completed browser runtime evidence");
    const outputFiles = readdirSync(outDir, { recursive: true });
    const inspectHtml = node => {
      if (node.tagName === "script") {
        const attrs = Object.fromEntries(node.attrs.map(({ name, value }) => [name, value]));
        if (!["application/ld+json", "application/json"].includes(attrs.type)) {
          assert.ok(attrs.src && !/^(?:[a-z]+:|\/\/)/i.test(attrs.src), "Unattributed inline/external browser script");
          assert.ok(chunks.has(attrs.src.replace(/^\//, "")), `Unattributed browser script: ${attrs.src}`);
        }
      }
      for (const child of node.childNodes || []) inspectHtml(child);
    };
    for (const file of outputFiles.filter(file => /\.html$/.test(file))) inspectHtml(parse(readFileSync(path.join(outDir, file), "utf8")));
    const files = outputFiles.filter(file => /\.(?:js|mjs|cjs)$/.test(file));
    assert.ok(files.length, "Missing production browser chunks");
    for (const file of files) assert.ok(chunks.has(file), `Unattributed executable browser asset: ${file}`);
    const lock = readJson(path.join(root, "package-lock.json"));
    const packages = new Set();
    for (const id of modules) {
      const clean = id.replace(/^\0+/, "").split("?")[0];
      const matches = [...clean.matchAll(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)/g)];
      const match = matches.at(-1);
      if (!match) continue;
      const owner = clean.slice(0, match.index) + `/node_modules/${match[1]}`;
      const metadata = readJson(path.join(owner, "package.json"));
      assert.ok(typeof metadata.name === "string" && metadata.name && typeof metadata.version === "string" && metadata.version, `Unknown runtime package identity: ${owner}`);
      const relative = path.relative(root, owner).replaceAll(path.sep, "/");
      assert.equal(lock.packages?.[relative]?.version, metadata.version, `Runtime package missing/mismatched in lockfile: ${relative}`);
      packages.add(`${metadata.name}@${metadata.version}`);
    }
    return { completed: true, packages: [...packages].sort(), chunks: [...chunks].sort(), moduleCount: modules.size };
  } finally { rmSync(outDir, { recursive: true, force: true }); }
}

export function assertRuntimePackaging(root) {
  const backend = readFileSync(path.join(root, "backend/Dockerfile"), "utf8");
  const builder = backend.split("FROM deps AS builder")[1]?.split("FROM node:24-bookworm-slim AS runtime")[0];
  assert.match(builder || "", /npm prune --omit=dev --no-audit --no-fund\s*$/);
  assert.equal((backend.match(/npm ci/g) || []).length, 1);
  assert.doesNotMatch(backend.split("AS runtime")[1], /COPY --from=deps|npm (?:ci|install)(?! --global)/);
  for (const file of ["Dockerfile", "Dockerfile.ecs-frontend"]) {
    const runtime = readFileSync(path.join(root, file), "utf8").split(/^FROM nginx:[^\n]+$/m)[1];
    assert.ok(runtime, "Unknown frontend runtime packaging");
    assert.doesNotMatch(runtime, /node_modules|\bnpm\b|\bnode\b/);
    assert.deepEqual(runtime.match(/^COPY --from=.*$/gm), ["COPY --from=builder /app/dist /usr/share/nginx/html"]);
  }
  assert.match(readFileSync(path.join(root, "scripts/aws/publish-ecs-images.sh"), "utf8"), /backend\|worker\) printf 'runtime'/);
}

export function enforceRuntimeFindings(report, browser, root) {
  assert.ok(browser?.completed && Array.isArray(browser.packages) && browser.chunks?.length && browser.moduleCount > 0, "Missing browser runtime evidence");
  assert.ok(Array.isArray(report?.results), "Invalid unfiltered OSV report");
  const failures = [];
  const buildOnly = [];
  for (const result of report.results) {
    assert.ok(typeof result.source?.path === "string" && Array.isArray(result.packages), "Incomplete OSV source evidence");
    for (const finding of result.packages) {
    assert.ok(Array.isArray(finding.vulnerabilities), "Incomplete OSV vulnerability evidence");
    if (!finding.vulnerabilities.length) continue;
    assert.ok(typeof finding.package?.name === "string" && finding.package.name && typeof finding.package.version === "string" && finding.package.version, "Incomplete OSV package identity");
    const name = finding.package?.name;
    const version = finding.package?.version;
    const source = path.resolve(result.source?.path || "");
    const lock = source === path.join(root, "package-lock.json") || source === path.join(root, "backend/package-lock.json");
    const devOnly = finding.package?.ecosystem === "npm" && finding.dependency_groups?.length === 1 && finding.dependency_groups[0] === "dev";
    const inBrowser = browser.packages.includes(`${name}@${version}`);
    // Keep existing source policy for normal dependencies and all other/nested
    // ecosystems. Only proven non-runtime npm development closures can pass.
    if (!lock || !devOnly || inBrowser) failures.push(`${source}: ${name}@${version}`);
    else {
      const instances = Object.entries(readJson(source).packages || {}).filter(([key, value]) => key.endsWith(`node_modules/${name}`) && value.version === version);
      assert.ok(instances.length && instances.every(([, value]) => value.dev === true), `Unknown/non-dev lockfile reachability: ${name}@${version}`);
      buildOnly.push(`${source}: ${name}@${version}`);
    }
    }
  }
  assert.equal(failures.length, 0, `Production runtime/unknown vulnerabilities: ${failures.join(", ")}`);
  return buildOnly;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 3, "Usage: node scripts/check-osv-runtime.mjs <unfiltered-osv-report.json>");
  assertRuntimePackaging(repository);
  const browser = await buildBrowserClosure(repository);
  const report = readJson(path.resolve(process.argv[2]));
  const buildOnly = enforceRuntimeFindings(report, browser, repository);
  writeFileSync(path.join(path.dirname(path.resolve(process.argv[2])), "browser-runtime-closure.json"), JSON.stringify({ browser, buildOnly }, null, 2));
  console.log(`OSV runtime gate passed; ${buildOnly.length} proven build-only finding(s), ${browser.packages.length} browser packages.`);
}
