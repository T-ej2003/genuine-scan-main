import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const read = (file) => fs.readFileSync(path.join(repoRoot, file), "utf8");
const shortContexts = ["rc-trust-critical", "rc-staging-smoke"];
const qualifiedContexts = shortContexts.map((context) => `Release Candidate Gate / ${context}`);

const exactContextSetMatches = (required, configured) =>
  required.length === configured.length && required.every((context) => configured.includes(context));

test("release governance uses the exact emitted job-name contexts", () => {
  const workflow = read(".github/workflows/release-candidate-gate.yml");
  const governance = read("scripts/check-release-governance.mjs");
  const setup = read("documents/RELEASE_CANDIDATE_GATE_SETUP.md");

  assert.match(workflow, /REQUIRED_RELEASE_CHECKS:\s*rc-trust-critical,rc-staging-smoke/);
  assert.match(governance, /process\.env\.REQUIRED_RELEASE_CHECKS \|\| "rc-trust-critical,rc-staging-smoke"/);
  for (const context of shortContexts) assert.ok(setup.includes("\n- `" + context + "`"));
});

test("exact matching accepts a fully qualified configured contract but rejects a shortened mismatch", () => {
  assert.equal(exactContextSetMatches(qualifiedContexts, qualifiedContexts), true);
  assert.equal(exactContextSetMatches(shortContexts, qualifiedContexts), false);
  assert.equal(exactContextSetMatches(qualifiedContexts, shortContexts), false);
});

test("missing or duplicate contexts fail closed", () => {
  assert.equal(exactContextSetMatches(shortContexts, [shortContexts[0]]), false);
  assert.equal(exactContextSetMatches(shortContexts, [shortContexts[0], shortContexts[0]]), false);
  assert.equal(exactContextSetMatches(shortContexts, [...shortContexts, "rc-governance"]), false);
});
