import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import yaml from "js-yaml";

import { validateRotationEvidenceFreshness } from "../security/rotation-evidence-contract.mjs";
import { requiredWorkflowFiles, usesLifecycleInputs } from "../github/release-lifecycle-contract.mjs";

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
  assert.deepEqual(requiredWorkflowFiles("strict"), ["quality-gate.yml", "secret-scan.yml", "deployment-audit.yml", "auth-security-tests.yml", "release-candidate-gate.yml"]);
  assert.deepEqual(requiredWorkflowFiles("authenticated-initial-overlap"), ["quality-gate.yml", "secret-scan.yml", "deployment-audit.yml", "auth-security-tests.yml"]);
  for (const workflowFile of requiredWorkflowFiles("strict")) assert.equal(usesLifecycleInputs("strict", workflowFile), false, `${workflowFile} must receive no new inputs on strict historical targets`);
  assert.equal(usesLifecycleInputs("authenticated-initial-overlap", "deployment-audit.yml"), true);
  assert.throws(() => requiredWorkflowFiles("unknown"), /Unsupported release lifecycle/);
  assert.match(train, /release-lifecycle-contract\.mjs --lifecycle/);
  const qualityGate = read(".github/workflows/quality-gate.yml");
  for (const input of overlapInputs) assert.ok(inputs(qualityGate)[input], `Quality Gate input ${input} is required by the route`);
  assert.match(qualityGate, /authenticated-initial-overlap\)[\s\S]*manage-production-initial-activation-lifecycle\.mjs[\s\S]*verify:ci:security:source/);
  assert.match(qualityGate, /test "\$TARGET_SHA" = "\$GITHUB_SHA"/);
});

test("Release Gate remains the independent strict production mutation boundary", () => {
  assert.deepEqual(inputs(gate).release_lifecycle.options, ["strict", "authenticated-initial-overlap"]);
  assert.ok(inputs(gate).required_gate_run_ids_json);
  assert.match(gate, /release-lifecycle-contract\.mjs --lifecycle/);
  assert.match(gate, /EXPECTED_WORKFLOW_RUN_IDS_JSON/);
  assert.match(gate, /Normal Release Gate requires the exact workflow-run IDs dispatched by its Release Train/);
  assert.match(gate, /Authenticated initial overlap is valid only for normal Release Gate mode/);
  assert.match(gate, /Strict normal releases must not supply authenticated-initial-overlap bindings/);
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
