import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(new URL(".", import.meta.url).pathname, "../..");
const workflow = readFileSync(path.join(root, ".github/workflows/authorize-production-dual-slot-rebaseline.yml"), "utf8");

test("rebaseline authorization workflow keeps dispatch inputs out of executable shell text", () => {
  const runBodies = [...workflow.matchAll(/^[ ]{8}run: \|\n((?:^[ ]{10}.*\n?)*)/gm)].map((match) => match[1]);
  assert.ok(runBodies.length >= 3);
  assert.equal(runBodies.some((body) => body.includes("${{ inputs.")), false);
  assert.equal(workflow.includes("environment: production"), true);
  for (const name of ["SOURCE_SHA", "HISTORICAL_ROTATION_ID", "ROTATION_ID", "ABANDONMENT_EVIDENCE_SHA256", "BASELINE_IDENTITY_SHA256", "RESOURCES_JSON", "WRITE_IDENTITIES_JSON", "EXPECTED_SECRET_VALUE_WRITES", "EXPECTED_SECRET_DELETES", "LIVE_REFERENCE_AUDIT", "REASON", "APPROVED_BY", "APPROVER_ROLE", "VERIFICATION_REF"]) assert.match(workflow, new RegExp(`^          ${name}: \\$\\{\\{ inputs\\.`, "m"));
  assert.equal(/gh api[^\n]*--output/.test(workflow), false);
  assert.equal(/terraform\s+(plan|apply)|UpdateService|RegisterTaskDefinition|aws-access-key/i.test(workflow), false);
  assert.equal(workflow.trimEnd().endsWith("retention-days: 90"), true);
});

test("malicious dispatch values remain environment data at the Node argument boundary", () => {
  const malicious = ["$(command)", "`command`", "\"; command; #", "line-one\nline-two"];
  const shell = workflow.match(/node scripts\/aws\/authorize-production-dual-slot-rebaseline\.mjs[\s\S]*?\n      - uses: actions\/upload-artifact/)[0];
  for (const value of malicious) assert.equal(shell.includes(value), false);
  assert.match(shell, /--source-sha "\$SOURCE_SHA"/);
  assert.match(shell, /--resources-json "\$RESOURCES_JSON"/);
  assert.match(shell, /--write-identities-json "\$WRITE_IDENTITIES_JSON"/);
});
