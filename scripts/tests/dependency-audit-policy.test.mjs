import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = path.resolve(new URL("../..", import.meta.url).pathname);
const script = path.join(root, "scripts/check-dependency-audit.mjs");
const clean = { vulnerabilities: {}, metadata: { vulnerabilities: { total: 0 } } };
const vulnerable = {
  vulnerabilities: {
    unsafe: {
      severity: "high",
      via: [{ source: 1234, url: "https://github.com/advisories/GHSA-AAAA-BBBB-CCCC" }],
    },
  },
};

const run = ({ backend = clean, exceptions = [] } = {}) => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "mscqr-audit-policy-"));
  const rootReport = path.join(dir, "root.json");
  const backendReport = path.join(dir, "backend.json");
  const allowlist = path.join(dir, "allowlist.json");
  writeFileSync(rootReport, JSON.stringify(clean));
  writeFileSync(backendReport, JSON.stringify(backend));
  writeFileSync(allowlist, JSON.stringify({ schemaVersion: 1, entries: exceptions }));
  return spawnSync(process.execPath, [script], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      DEPENDENCY_AUDIT_REPORT_ROOT: rootReport,
      DEPENDENCY_AUDIT_REPORT_BACKEND: backendReport,
      DEPENDENCY_AUDIT_ALLOWLIST: allowlist,
    },
  });
};

test("passes clean production trees", () => {
  assert.equal(run().status, 0);
});

test("blocks a high production advisory", () => {
  const result = run({ backend: vulnerable });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /backend: high unsafe \(GHSA-AAAA-BBBB-CCCC\)/);
});

test("accepts only an exact, owned, reasoned, non-expired exception", () => {
  const result = run({
    backend: vulnerable,
    exceptions: [{
      scope: "backend",
      package: "unsafe",
      advisory: "GHSA-AAAA-BBBB-CCCC",
      rationale: "Temporary upstream remediation window.",
      owner: "security@example.invalid",
      expiresOn: "2099-12-31",
    }],
  });
  assert.equal(result.status, 0, result.stderr);
});

test("rejects expired, wildcard, and stale exceptions", () => {
  const common = {
    scope: "backend",
    package: "unsafe",
    advisory: "GHSA-AAAA-BBBB-CCCC",
    rationale: "Temporary upstream remediation window.",
    owner: "security@example.invalid",
  };
  assert.equal(run({ backend: vulnerable, exceptions: [{ ...common, expiresOn: "2000-01-01" }] }).status, 1);
  assert.equal(run({ backend: vulnerable, exceptions: [{ ...common, package: "*", expiresOn: "2099-12-31" }] }).status, 1);
  assert.equal(run({ exceptions: [{ ...common, expiresOn: "2099-12-31" }] }).status, 1);
});
