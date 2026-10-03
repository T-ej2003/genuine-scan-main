import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildBrowserClosure, enforceRuntimeFindings, assertRuntimePackaging } from "../check-osv-runtime.mjs";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const packageName = "unsafe-runtime-fixture";
const report = (dir, { dev = true, source = "package-lock.json", ecosystem = "npm" } = {}) => ({ results: [{
  source: { path: path.join(dir, source), type: "lockfile" },
  packages: [{ package: { name: packageName, version: "1.0.0", ecosystem }, dependency_groups: dev ? ["dev"] : [],
    vulnerabilities: [{ id: "OSV-TEST-HIGH", database_specific: { severity: "HIGH" } }] }],
}] });
function fixture() {
  const dir = mkdtempSync(path.join(os.tmpdir(), "mscqr-browser-security-"));
  mkdirSync(path.join(dir, "node_modules", packageName), { recursive: true });
  writeFileSync(path.join(dir, "node_modules", packageName, "package.json"), JSON.stringify({ name: packageName, version: "1.0.0", type: "module", main: "index.js" }));
  writeFileSync(path.join(dir, "node_modules", packageName, "index.js"), 'export default () => "runtime";');
  writeFileSync(path.join(dir, "package.json"), JSON.stringify({ type: "module", devDependencies: { [packageName]: "1.0.0" } }));
  writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: {
    "": { devDependencies: { [packageName]: "1.0.0" } }, [`node_modules/${packageName}`]: { version: "1.0.0", dev: true },
  } }));
  writeFileSync(path.join(dir, "index.html"), '<script type="module" src="/main.js"></script>');
  return dir;
}
async function withBuild(source, fn, options = {}) {
  const dir = fixture();
  try {
    writeFileSync(path.join(dir, "main.js"), source);
    const browser = await buildBrowserClosure(dir, { configFile: false, logLevel: "silent", ...options });
    await fn(dir, browser);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
const idle = 'document.body.textContent = "ok";';

test("P1 reproduction: a dev dependency is executable in a browser bundle despite no runtime node_modules", async () => {
  await withBuild(`import unsafe from '${packageName}'; document.body.textContent = unsafe();`, (dir, browser) => {
    assert.ok(browser.packages.includes(`${packageName}@1.0.0`));
    assert.throws(() => enforceRuntimeFindings(report(dir), browser, dir), /Production runtime/);
  });
});
for (const [name, source] of [
  ["static dev dependency", `import unsafe from '${packageName}'; window.result = unsafe();`],
  ["dynamic dev dependency", `import('${packageName}').then(m => window.result = m.default());`],
  ["lazy chunk", `window.load = () => import('${packageName}');`],
]) test(`${name} vulnerability fails`, async () => {
  await withBuild(source, (dir, browser) => assert.throws(() => enforceRuntimeFindings(report(dir), browser, dir)));
});
test("build-only dev dependency absent from fresh browser graph passes", async () => {
  await withBuild(idle, (dir, browser) => assert.equal(enforceRuntimeFindings(report(dir), browser, dir).length, 1));
});
test("browser worker dependency is included in the census", async () => {
  const dir = fixture();
  try {
    writeFileSync(path.join(dir, "main.js"), 'new Worker(new URL("./worker.js", import.meta.url), {type:"module"});');
    writeFileSync(path.join(dir, "worker.js"), `import unsafe from '${packageName}'; postMessage(unsafe());`);
    const browser = await buildBrowserClosure(dir, { configFile: false, logLevel: "silent" });
    assert.ok(browser.packages.includes(`${packageName}@1.0.0`));
    assert.throws(() => enforceRuntimeFindings(report(dir), browser, dir));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
for (const label of ["backend", "worker", "transitive", "frontend normal dependency"]) test(`${label} runtime findings cannot be exempted`, async () => {
  await withBuild(idle, (dir, browser) => assert.throws(() => enforceRuntimeFindings(report(dir, { dev: false, source: label === "frontend normal dependency" ? "package-lock.json" : "backend/package-lock.json" }), browser, dir)));
});
test("same advisory in dev and runtime closures fails", async () => {
  await withBuild(idle, (dir, browser) => {
    const mixed = { results: [...report(dir).results, ...report(dir, { dev: false, source: "backend/package-lock.json" }).results] };
    assert.throws(() => enforceRuntimeFindings(mixed, browser, dir));
  });
});
test("unknown nested lockfile and unknown ecosystem fail closed", async () => {
  await withBuild(idle, (dir, browser) => {
    assert.throws(() => enforceRuntimeFindings(report(dir, { source: "nested/package-lock.json" }), browser, dir));
    assert.throws(() => enforceRuntimeFindings(report(dir, { ecosystem: "PyPI" }), browser, dir));
  });
});
test("missing evidence and malformed scanner report fail closed", () => {
  assert.throws(() => enforceRuntimeFindings({ results: [] }, undefined, root));
  assert.throws(() => enforceRuntimeFindings({}, { completed: true, packages: [], chunks: ["main.js"], moduleCount: 1 }, root));
});
test("failed build cannot produce passing evidence or inspect stale dist", async () => {
  const dir = fixture();
  try {
    mkdirSync(path.join(dir, "dist")); writeFileSync(path.join(dir, "dist/index.js"), "stale");
    writeFileSync(path.join(dir, "main.js"), 'import "missing-package";');
    await assert.rejects(buildBrowserClosure(dir, { configFile: false, logLevel: "silent" }));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("unresolved dynamic imports fail closed", async () => {
  await assert.rejects(withBuild('window.load = name => import(/* @vite-ignore */ name);', () => assert.fail("must not build")));
});
test("external executable imports fail closed", async () => {
  await assert.rejects(withBuild(`import unsafe from '${packageName}'; window.result = unsafe();`, () => assert.fail("must not build"), { build: { rolldownOptions: { external: [packageName] } } }));
});
test("unattributed public executable assets fail closed", async () => {
  const dir = fixture();
  try {
    writeFileSync(path.join(dir, "main.js"), idle); mkdirSync(path.join(dir, "public")); writeFileSync(path.join(dir, "public/vendor.js"), "alert('unattributed')");
    await assert.rejects(buildBrowserClosure(dir, { configFile: false, logLevel: "silent" }), /Unattributed/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("lock/install mismatch cannot hide a browser dependency", async () => {
  const dir = fixture();
  try {
    writeFileSync(path.join(dir, "main.js"), `import unsafe from '${packageName}'; window.result = unsafe();`);
    writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify({ packages: {} }));
    await assert.rejects(buildBrowserClosure(dir, { configFile: false, logLevel: "silent" }), /missing\/mismatched/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("actual production packaging still prunes server dependencies", () => assertRuntimePackaging(root));
test("workflow uses unfiltered report and the same behaviorally-tested gate", () => {
  const workflow = readFileSync(path.join(root, ".github/workflows/deployment-audit.yml"), "utf8");
  assert.match(workflow, /node scripts\/check-osv-runtime.mjs audit-artifacts\/osv-source.json/);
  assert.doesNotMatch(workflow, /osv-production.toml|--ignore-dev/);
});

test("transitive dev dependency reached through a parent is detected", async () => {
  const dir = fixture();
  try {
    mkdirSync(path.join(dir, "node_modules/fixture-parent"));
    writeFileSync(path.join(dir, "node_modules/fixture-parent/package.json"), JSON.stringify({ name: "fixture-parent", version: "1.0.0", type: "module", main: "index.js" }));
    writeFileSync(path.join(dir, "node_modules/fixture-parent/index.js"), `export {default} from '${packageName}';`);
    const lock = JSON.parse(readFileSync(path.join(dir, "package-lock.json")));
    lock.packages["node_modules/fixture-parent"] = { version: "1.0.0", dev: true, dependencies: { [packageName]: "1.0.0" } };
    writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(lock));
    writeFileSync(path.join(dir, "main.js"), 'import unsafe from "fixture-parent"; window.result = unsafe();');
    const browser = await buildBrowserClosure(dir, { configFile: false, logLevel: "silent" });
    assert.throws(() => enforceRuntimeFindings(report(dir), browser, dir));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("empty browser evidence is not authority", () => {
  assert.throws(() => enforceRuntimeFindings({ results: [] }, { completed: true, packages: [], chunks: [], moduleCount: 0 }, root));
});
test("multiple dependency groups cannot qualify as build-only", async () => {
  await withBuild(idle, (dir, browser) => {
    const mixed = report(dir); mixed.results[0].packages[0].dependency_groups = ["dev", "runtime"];
    assert.throws(() => enforceRuntimeFindings(mixed, browser, dir));
  });
});
test("medium findings retain the previous source-gate behavior", async () => {
  await withBuild(idle, (dir, browser) => {
    const medium = report(dir, { dev: false }); medium.results[0].packages[0].vulnerabilities[0].database_specific.severity = "MEDIUM";
    assert.throws(() => enforceRuntimeFindings(medium, browser, dir));
  });
});
test("source maps and chunk names do not control runtime attribution", async () => {
  await withBuild(`import unsafe from '${packageName}'; window.result = unsafe();`, (dir, browser) => {
    assert.throws(() => enforceRuntimeFindings(report(dir), browser, dir));
  }, { build: { sourcemap: false, rolldownOptions: { output: { entryFileNames: "opaque.js", chunkFileNames: "hidden-[hash].js" } } } });
});
test("PostCSS build-only execution does not imply browser execution", async () => {
  const dir = fixture();
  try {
    writeFileSync(path.join(dir, "main.js"), 'import "./main.css"; document.body.textContent = "ok";');
    writeFileSync(path.join(dir, "main.css"), "body { color: red; }");
    writeFileSync(path.join(dir, "vite.config.mjs"), `import unsafe from '${packageName}'; export default {css:{postcss:{plugins:[{postcssPlugin:"build-only",Once(){unsafe();}}]}}};`);
    const browser = await buildBrowserClosure(dir, { logLevel: "silent" });
    assert.equal(browser.packages.includes(`${packageName}@1.0.0`), false);
    assert.equal(enforceRuntimeFindings(report(dir), browser, dir).length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("inline code injected by build tooling cannot bypass attribution", async () => {
  await assert.rejects(withBuild(idle, () => assert.fail("must not pass"), { plugins: [{ name: "unattributed-injection", transformIndexHtml: html => html + "<script>alert('unattributed')</script>" }] }), /Unattributed inline/);
});
test("external script tags cannot bypass attribution", async () => {
  await assert.rejects(withBuild(idle, () => assert.fail("must not pass"), { plugins: [{ name: "external-injection", transformIndexHtml: html => html + '<script src="https://example.invalid/vendor.js"></script>' }] }), /Unattributed inline\/external/);
});

test("incomplete finding identities cannot be called build-only", async () => {
  await withBuild(idle, (dir, browser) => {
    const incomplete = report(dir); delete incomplete.results[0].packages[0].package.name;
    assert.throws(() => enforceRuntimeFindings(incomplete, browser, dir), /Incomplete/);
  });
});
test("OSV dev group cannot override a runtime lockfile instance", async () => {
  await withBuild(idle, (dir, browser) => {
    const lock = JSON.parse(readFileSync(path.join(dir, "package-lock.json")));
    delete lock.packages[`node_modules/${packageName}`].dev;
    writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(lock));
    assert.throws(() => enforceRuntimeFindings(report(dir), browser, dir), /non-dev/);
  });
});
