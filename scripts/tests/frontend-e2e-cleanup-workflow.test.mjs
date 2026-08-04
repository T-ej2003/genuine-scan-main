import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";

const workflow = yaml.load(fs.readFileSync(".github/workflows/quality-gate.yml", "utf8"));
const frontend = workflow.jobs.frontend;
const steps = frontend.steps;
const indexOf = (predicate) => steps.findIndex(predicate);

test("frontend E2E cleanup is guarded by checkout and database setup", () => {
  const checkoutIndex = indexOf((step) => step.id === "checkout");
  const setupNodeIndex = indexOf((step) => step.id === "setup_node");
  const frontendDependenciesIndex = indexOf((step) => step.id === "frontend_dependencies");
  const cleanupContractIndex = indexOf((step) => step.id === "cleanup_contract");
  const setupIndex = indexOf((step) => step.id === "enterprise_db_setup");
  const cleanupIndex = indexOf((step) => step.name === "Clean disposable enterprise E2E database");
  const cleanup = steps[cleanupIndex];

  assert.ok(checkoutIndex >= 0);
  assert.ok(setupNodeIndex > checkoutIndex);
  assert.ok(frontendDependenciesIndex > setupNodeIndex);
  assert.ok(cleanupContractIndex > frontendDependenciesIndex);
  assert.ok(setupIndex > checkoutIndex);
  assert.ok(setupIndex > cleanupContractIndex);
  assert.ok(cleanupIndex > setupIndex);
  assert.equal(cleanup.if, "always() && steps.checkout.outcome == 'success' && steps.enterprise_db_setup.outcome != 'skipped'");
  assert.match(cleanup.run, /test -f scripts\/enterprise-e2e-db\.mjs/);
  assert.match(cleanup.run, /node scripts\/enterprise-e2e-db\.mjs cleanup/);
});

test("frontend E2E cleanup remains enabled after Playwright failure", () => {
  const cleanup = steps.find((step) => step.name === "Clean disposable enterprise E2E database");
  const playwrightIndex = indexOf((step) => step.name === "Playwright smoke suite");
  const cleanupIndex = indexOf((step) => step.name === "Clean disposable enterprise E2E database");

  assert.equal(cleanup.shell, "bash");
  assert.ok(cleanupIndex > playwrightIndex);
  assert.match(cleanup.if, /always\(\)/);
});
