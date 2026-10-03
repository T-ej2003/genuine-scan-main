import { reachabilityInputsSha256, validateNonRuntimeAcceptance } from "./lib/osv-non-runtime-acceptance.mjs";
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
  const inputsSha256 = reachabilityInputsSha256(root);
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
    assert.equal(reachabilityInputsSha256(root), inputsSha256, "Inputs changed during production build");
    return { completed: true, inputsSha256, canonicalBuild: Object.keys(options).length === 0, executableProvenance: "INCOMPLETE", packages: [...packages].sort(), chunks: [...chunks].sort(), moduleCount: modules.size };
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

export function enforceRuntimeFindings(report, browser, root, { acceptance = { schemaVersion: 1, entries: [] }, today = new Date().toISOString().slice(0, 10) } = {}) {
  assert.ok(browser?.completed && Array.isArray(browser.packages) && browser.chunks?.length && browser.moduleCount > 0, "Missing browser runtime evidence");
  assert.ok(Array.isArray(report?.results), "Invalid unfiltered OSV report");
  assert.equal(acceptance.schemaVersion, 1);
  assert.ok(Array.isArray(acceptance.entries), "Missing acceptance entries");
  const keys = new Set();
  for (const entry of acceptance.entries) {
    validateNonRuntimeAcceptance(entry, browser, root, today);
    const key = `${entry.scope}/${entry.package}/${entry.affectedVersion}/${entry.advisory.toUpperCase()}`;
    assert.ok(!keys.has(key), "Duplicate acceptance"); keys.add(key);
  }
  const used = new Set();
  const accepted = [];
  const failures = [];
  for (const result of report.results) {
    assert.ok(typeof result.source?.path === "string" && Array.isArray(result.packages), "Incomplete OSV source evidence");
    for (const finding of result.packages) {
      assert.ok(Array.isArray(finding.vulnerabilities), "Incomplete OSV vulnerability evidence");
      if (!finding.vulnerabilities.length) continue;
      assert.ok(typeof finding.package?.name === "string" && finding.package.name && typeof finding.package.version === "string" && finding.package.version, "Incomplete OSV package identity");
      const { name, version } = finding.package;
      const source = path.resolve(result.source.path);
      for (const vulnerability of finding.vulnerabilities) {
        assert.ok(typeof vulnerability.id === "string" && vulnerability.id, "Missing OSV advisory identity");
        assert.ok(vulnerability.aliases === undefined || Array.isArray(vulnerability.aliases), "Malformed OSV aliases");
        const ids = [vulnerability.id, ...(vulnerability.aliases || [])];
        assert.ok(ids.every(id => typeof id === "string" && id), "Malformed OSV alias identity");
        const entry = acceptance.entries.find(entry => entry.package === name && entry.affectedVersion === version && ids.some(id => id.toUpperCase() === entry.advisory.toUpperCase()) && ids.some(id => id.toUpperCase() === entry.cve.toUpperCase()));
        const buildScope = source === path.join(root, "package-lock.json") && finding.package.ecosystem === "npm" && finding.dependency_groups?.length === 1 && finding.dependency_groups[0] === "dev";
        const patchAvailable = vulnerability.affected?.some(affected => affected.ranges?.some(range => range.events?.some(event => event.fixed)));
        if (entry && buildScope && !patchAvailable) {
          used.add(entry);
          accepted.push({ package: name, version, advisory: vulnerability.id, aliases: ids, severity: vulnerability.database_specific?.severity || "UNSPECIFIED", patched: false, disposition: "TIME_BOUNDED_NON_RUNTIME_ACCEPTANCE", owner: entry.owner, expiresOn: entry.expiresOn });
        } else failures.push(`${source}: ${name}@${version} (${browser.packages.includes(`${name}@${version}`) ? "YES: browser module present" : "UNKNOWN: executable provenance incomplete"})`);
      }
    }
  }
  for (const entry of acceptance.entries) assert.ok(used.has(entry), `Stale acceptance: ${entry.package}/${entry.advisory}`);
  assert.equal(failures.length, 0, `Production runtime/unknown vulnerabilities: ${failures.join(", ")}`);
  return accepted;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 3, "Usage: node scripts/check-osv-runtime.mjs <unfiltered-osv-report.json>");
  assertRuntimePackaging(repository);
  const browser = await buildBrowserClosure(repository);
  const report = readJson(path.resolve(process.argv[2]));
  const acceptance = readJson(path.join(repository, "documents/security/osv-non-runtime-acceptance.json"));
  const buildOnly = enforceRuntimeFindings(report, browser, repository, { acceptance });
  for (const entry of buildOnly) console.log(JSON.stringify(entry));
  writeFileSync(path.join(path.dirname(path.resolve(process.argv[2])), "browser-runtime-closure.json"), JSON.stringify({ browser, buildOnly }, null, 2));
  console.log(`OSV runtime gate passed; ${buildOnly.length} visible time-bounded accepted finding(s), ${browser.packages.length} browser packages.`);
}
