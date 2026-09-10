import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import yaml from "js-yaml";

import { validateRotationEvidenceFreshness } from "../security/rotation-evidence-contract.mjs";

const read = (file) => readFileSync(file, "utf8");
const train = read(".github/workflows/release-train.yml");
const audit = read(".github/workflows/deployment-audit.yml");
const gate = read(".github/workflows/release-gate.yml");
const packageJson = JSON.parse(read("package.json"));
const inputs = (workflow) => yaml.load(workflow).on.workflow_dispatch.inputs;
const overlapInputs = ["target_sha", "rotation_id", "rotation_state_json", "rotation_state_sha256", "rotation_task_definition_arn", "rotation_image_digest", "rotation_deployment_sha"];

test("authenticated initial overlap is explicit and fail closed in Release Train and Deployment Audit", () => {
  for (const workflow of [train, audit]) {
    const lifecycle = inputs(workflow).release_lifecycle;
    assert.deepEqual(lifecycle.options, ["strict", "authenticated-initial-overlap"]);
    assert.equal(lifecycle.default, "strict");
  }
  for (const input of overlapInputs) assert.ok(inputs(audit)[input], `Deployment Audit input ${input} is required by the route`);
  for (const input of overlapInputs.slice(1)) assert.ok(inputs(train)[input], `Release Train input ${input} is required by the route`);
  assert.match(train, /Unsupported release lifecycle/);
  assert.match(audit, /Unsupported release lifecycle/);
  assert.match(train, /manage-production-initial-activation-lifecycle\.mjs[\s\S]*--mode validate-candidate/);
  assert.match(train, /production-release-dispatch-contract\.mjs[\s\S]*--source-sha "\$TARGET_SHA"/);
  assert.match(audit, /manage-production-initial-activation-lifecycle\.mjs[\s\S]*--mode validate-candidate/);
  assert.match(audit, /test "\$TARGET_SHA" = "\$GITHUB_SHA"/);
});

test("only the exact initial-overlap route selects the pre-rotation release contract", () => {
  assert.equal(packageJson.scripts["verify:release:pre-rotation"], "npm run verify:release:source");
  assert.match(audit, /strict\)\s+npm run verify:release/);
  assert.match(audit, /authenticated-initial-overlap\)[\s\S]*npm run verify:release:pre-rotation/);
  assert.doesNotMatch(audit, /verify:release \|\| true|SKIP_ROTATION_CHECK|continue-on-error/);
  assert.match(train, /required_workflows=\(quality-gate\.yml secret-scan\.yml deployment-audit\.yml auth-security-tests\.yml release-candidate-gate\.yml\)/);
  assert.match(train, /required_workflows=\(quality-gate\.yml secret-scan\.yml deployment-audit\.yml auth-security-tests\.yml\)/);
});

test("Release Gate remains the independent strict production mutation boundary", () => {
  assert.match(gate, /normal\)[\s\S]*npm run check:rotation-evidence-freshness/);
  assert.match(gate, /manage-production-initial-activation-lifecycle\.mjs[\s\S]*--mode validate-candidate/);
  assert.match(gate, /Authenticate normal release image authorization/);
  assert.match(gate, /environment: production/);
});

test("the historical tracked rotation evidence is still rejected by the generic freshness check", () => {
  const result = spawnSync(process.execPath, ["scripts/check-rotation-evidence-freshness.mjs"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}\n${result.stderr}`, /ROTATION_EVIDENCE_FRESH=false/);
});

test("malformed post-rotation evidence remains rejected", () => {
  assert.ok(validateRotationEvidenceFreshness({ cleanupWindowComplete: false }).length > 0);
});
