import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";

test("all GitHub workflow YAML is parseable before CI", () => {
  const directory = path.resolve(".github/workflows");
  for (const file of fs.readdirSync(directory).filter((name) => /\.ya?ml$/.test(name))) assert.doesNotThrow(() => yaml.load(fs.readFileSync(path.join(directory, file), "utf8")), file);
});

test("Stage-A reconciliation authorization exports every shell input in its producing step", () => {
  const workflowPath = path.resolve(".github/workflows/authorize-production-stage-a-production-artifacts-reconciliation.yml");
  const workflowText = fs.readFileSync(workflowPath, "utf8");
  const workflow = yaml.load(workflowText);
  const dispatch = workflow.on?.workflow_dispatch || workflow[true]?.workflow_dispatch;
  const steps = workflow.jobs.authorize.steps;
  const sourceStep = steps.find(({ name }) => name === "Authenticate protected source");
  const authorizationStep = steps.find(({ name }) => name === "Produce exact independently approved authorization");
  assert.equal(dispatch?.inputs?.recovery_source_sha?.required, true);
  assert.equal(sourceStep?.env?.RECOVERY_SOURCE_SHA, "${{ inputs.recovery_source_sha }}");
  assert.equal(authorizationStep?.env?.RECOVERY_SOURCE_SHA, "${{ inputs.recovery_source_sha }}");
  assert.match(authorizationStep?.run || "", /--recovery-source-sha "\$RECOVERY_SOURCE_SHA"/);
  const inherited = new Set(["GITHUB_REPOSITORY", "GITHUB_WORKFLOW_REF", "GITHUB_EVENT_NAME", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_ACTOR", "RUNNER_TEMP"]);
  const referenced = [...new Set([...((authorizationStep?.run || "").matchAll(/\$([A-Z][A-Z0-9_]*)\b/g))].map(([, name]) => name))];
  assert.deepEqual(referenced.filter((name) => !Object.hasOwn(authorizationStep?.env || {}, name) && !inherited.has(name)), []);
});
