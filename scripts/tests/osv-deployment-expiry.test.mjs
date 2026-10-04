import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { assertDeploymentAcceptanceWindow } from "../github/osv-acceptance-window.mjs";
const root = path.resolve(new URL("../..", import.meta.url).pathname);
const entry = { scope: "frontend-build-only/non-runtime", package: "fixture", advisory: "GHSA-AAAA-BBBB-CCCC", owner: "@owner", rationale: "Trusted build path", expiresOn: "2026-11-02" };
const record = { schemaVersion: 1, entries: [entry] };
test("a successful November 1 audit cannot authorize deployment after midnight", () => {
  assertDeploymentAcceptanceWindow(record, "2026-11-01");
  const successfulAudit = { conclusion: "success", sourceRecord: record };
  let mutations = 0;
  assert.throws(() => { assertDeploymentAcceptanceWindow(successfulAudit.sourceRecord, "2026-11-02"); mutations++; });
  assert.equal(mutations, 0);
});
test("environment approval delay cannot extend the deadline", () => {
  assertDeploymentAcceptanceWindow(record, "2026-11-01");
  assert.throws(() => assertDeploymentAcceptanceWindow(record, "2026-11-03"));
});
test("unexpired source-bound acceptance remains valid at deployment", () => assert.equal(assertDeploymentAcceptanceWindow(record, "2026-11-01").length, 1));
test("missing/malformed deployment acceptance evidence fails", () => { assert.throws(() => assertDeploymentAcceptanceWindow({})); assert.throws(() => assertDeploymentAcceptanceWindow({schemaVersion:1,entries:[{...entry,expiresOn:"tomorrow"}]})); });
test("final sanity and every production shell boundary recheck exact target expiry", () => {
  const workflow = yaml.load(readFileSync(path.join(root, ".github/workflows/release-gate.yml"), "utf8"));
  const sanity = workflow.jobs['resolve-deploy-target'].steps.find(s => s.name === 'Final required-gate sanity check');
  assert.match(sanity.run, /check-required-workflow-gates\.mjs[\s\S]*osv-acceptance-window\.mjs --revision "\$TARGET_SHA"/);
  let enabled = false;
  for (const step of workflow.jobs['deploy-production-ecs'].steps) {
    if (step.name === 'Install dependencies deterministically') enabled = true;
    if (enabled && step.run) assert.match(step.run, /^set -euo pipefail\nnode scripts\/github\/osv-acceptance-window\.mjs --revision "\$DEPLOY_SHA"\n/, step.name);
  }
});
