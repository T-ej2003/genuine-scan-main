import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { enforceRuntimeFindings, buildBrowserClosure } from "../check-osv-runtime.mjs";
import { reachabilityInputsSha256 } from "../lib/osv-non-runtime-acceptance.mjs";

const packageName = "vulnerable-fixture";
function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), "mscqr-acceptance-"));
  mkdirSync(path.join(root, "backend"));
  writeFileSync(path.join(root, "backend/package-lock.json"), JSON.stringify({ packages: {} }));
  writeFileSync(path.join(root, "package-lock.json"), JSON.stringify({ packages: { [`node_modules/${packageName}`]: { version: "1.0.0", dev: true } } }));
  const entry = { scope: "frontend-build-only/non-runtime", package: packageName, affectedVersion: "1.0.0", advisory: "GHSA-AAAA-BBBB-CCCC", cve: "CVE-2026-12345", owner: "@security-owner", rationale: "Reviewed trusted build input; no runtime path.", createdAt: "2026-10-03", expiresOn: "2026-11-02", reachability: { inputsSha256: reachabilityInputsSha256(root), execution: { backend: "NO", worker: "NO", frontendServer: "NO", browser: "NO" }, productionAttackerControlsPattern: "NO" } };
  const browser = { completed: true, canonicalBuild: true, inputsSha256: entry.reachability.inputsSha256, packages: [], chunks: ["app.js"], moduleCount: 1, executableProvenance: "INCOMPLETE" };
  const report = { results: [{ source: { path: path.join(root, "package-lock.json") }, packages: [{ package: { name: packageName, version: "1.0.0", ecosystem: "npm" }, dependency_groups: ["dev"], vulnerabilities: [{ id: entry.advisory, aliases: [entry.cve], database_specific: { severity: "HIGH" } }] }] }] };
  return { root, entry, browser, report, acceptance: { schemaVersion: 1, entries: [entry] } };
}
function run(mutate = () => {}, expected = false, today = "2026-10-03") {
  const f = fixture();
  try { mutate(f); const evaluate = () => enforceRuntimeFindings(f.report, f.browser, f.root, { acceptance: f.acceptance, today });
    if (expected) { const accepted = evaluate(); assert.equal(accepted.length, 1); assert.equal(accepted[0].severity, "HIGH"); assert.equal(accepted[0].disposition, "TIME_BOUNDED_NON_RUNTIME_ACCEPTANCE"); assert.equal(accepted[0].patched, false); }
    else assert.throws(evaluate);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
}
test("exact reviewed acceptance passes without claiming complete module provenance", () => run(() => {}, true));
test("last day before expiry passes", () => run(() => {}, true, "2026-11-01"));
for (const today of ["2026-11-02", "2026-11-03"]) test(`expiry blocks automatically on ${today}`, () => run(() => {}, false, today));
for (const [name, mutate] of [
  ["wrong package", f => f.entry.package = "different"],
  ["wrong advisory", f => f.entry.advisory = "GHSA-DDDD-EEEE-FFFF"],
  ["new version", f => f.entry.affectedVersion = "1.0.1"],
  ["wrong scope", f => f.entry.scope = "backend"],
  ["wildcard package", f => f.entry.package = "*"],
  ["wildcard advisory", f => f.entry.advisory = "GHSA-*"],
  ["missing owner", f => delete f.entry.owner],
  ["missing rationale", f => delete f.entry.rationale],
  ["missing expiry", f => delete f.entry.expiresOn],
  ["malformed expiry", f => f.entry.expiresOn = "tomorrow"],
  ["impossible date", f => f.entry.expiresOn = "2026-02-30"],
  ["creation in future", f => f.entry.createdAt = "2027-01-01"],
  ["missing reachability", f => delete f.entry.reachability],
  ["backend runtime", f => f.entry.reachability.execution.backend = "YES"],
  ["worker runtime", f => f.entry.reachability.execution.worker = "YES"],
  ["browser runtime", f => f.entry.reachability.execution.browser = "YES"],
  ["unknown provenance", f => f.entry.reachability.execution.browser = "UNKNOWN"],
  ["attacker controlled input", f => f.entry.reachability.productionAttackerControlsPattern = "YES"],
  ["positive browser evidence", f => f.browser.packages = [`${packageName}@1.0.0`]],
  ["unknown build options", f => f.browser.canonicalBuild = false],
  ["changed HTML entry", f => writeFileSync(path.join(f.root, "index.html"), "<script>globalThis.injected=true;</script>")],
  ["changed config", f => writeFileSync(path.join(f.root, "vite.config.mjs"), "export default {plugins:[]}")],
  ["changed dependency graph", f => writeFileSync(path.join(f.root, "package-lock.json"), JSON.stringify({ packages: {} }))],
  ["runtime dependency despite dev scan", f => { writeFileSync(path.join(f.root, "package-lock.json"), JSON.stringify({ packages: { [`node_modules/${packageName}`]: { version: "1.0.0" } } })); f.browser.inputsSha256 = f.entry.reachability.inputsSha256 = reachabilityInputsSha256(f.root); }],
  ["backend lock contradiction", f => { writeFileSync(path.join(f.root, "backend/package-lock.json"), JSON.stringify({ packages: { [`node_modules/${packageName}`]: { version: "1.0.0" } } })); f.browser.inputsSha256 = f.entry.reachability.inputsSha256 = reachabilityInputsSha256(f.root); }],
  ["runtime report alongside build finding", f => { const extra = structuredClone(f.report.results[0]); extra.source.path = path.join(f.root, "backend/package-lock.json"); f.report.results.push(extra); }],
  ["multiple groups", f => f.report.results[0].packages[0].dependency_groups.push("runtime")],
  ["stale acceptance", f => f.report.results = []],
  ["missing result", f => delete f.report.results],
  ["missing vulnerability id", f => delete f.report.results[0].packages[0].vulnerabilities[0].id],
  ["malformed aliases", f => f.report.results[0].packages[0].vulnerabilities[0].aliases = {}],
  ["unrelated alias", f => f.report.results[0].packages[0].vulnerabilities[0].aliases = ["CVE-2026-11111"]],
  ["duplicate acceptance", f => f.acceptance.entries.push(structuredClone(f.entry))],
  ["upstream fix needs rereview", f => f.report.results[0].packages[0].vulnerabilities[0].affected = [{ranges:[{events:[{fixed:"1.0.1"}]}]}]],
]) test(`${name} blocks`, () => run(mutate));
test("package case cannot broaden acceptance", () => run(f => f.entry.package = packageName.toUpperCase()));
test("OSV advisory aliases normalize case without broadening package/version/scope", () => run(f => { const v = f.report.results[0].packages[0].vulnerabilities[0]; v.id = "OSV-ALIAS"; v.aliases = [f.entry.advisory.toLowerCase(), f.entry.cve]; }, true));
test("plugin copied code cannot use a reviewed acceptance", async () => {
  const f = fixture();
  try {
    writeFileSync(path.join(f.root, "index.html"), '<script type="module" src="/main.js"></script>');
    writeFileSync(path.join(f.root, "main.js"), 'globalThis.appReady=true;');
    const browser = await buildBrowserClosure(f.root, { configFile: false, logLevel: "silent", plugins: [{ name: "hostile", renderChunk(code) { return code + ';globalThis.vulnerableCopiedCode=true;'; } }] });
    f.entry.reachability.inputsSha256 = browser.inputsSha256;
    assert.throws(() => enforceRuntimeFindings(f.report, browser, f.root, { acceptance: f.acceptance, today: "2026-10-03" }), /Unreviewed build/);
  } finally { rmSync(f.root, { recursive: true, force: true }); }
});
