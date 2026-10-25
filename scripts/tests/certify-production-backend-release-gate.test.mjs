import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { assertBackendRecoveryWorkflowGraph } from "../aws/certify-production-backend-release-gate.mjs";

const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/release-gate.yml", import.meta.url), "utf8"));
const copy = () => structuredClone(workflow);

test("backend recovery certification accepts the actual protected workflow", () => {
  assert.equal(assertBackendRecoveryWorkflowGraph(copy()), true);
});

for (const [name, change] of [
  ["concurrent production writers", (gate) => { gate.concurrency["cancel-in-progress"] = true; }],
  ["missing production environment", (gate) => { gate.jobs["deploy-production-ecs"].environment = "staging"; }],
  ["OIDC removed", (gate) => { delete gate.jobs["deploy-production-ecs"].permissions["id-token"]; }],
  ["wrong AWS account", (gate) => { gate.jobs["deploy-production-ecs"].env.AWS_ACCOUNT_ID_EXPECTED = "000000000000"; }],
  ["mutable PostgreSQL image", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = "postgres:18"; }],
  ["RLS certification skipped", (gate) => { gate.jobs["deploy-production-ecs"].steps = gate.jobs["deploy-production-ecs"].steps.filter((step) => step.name !== "Full RLS verification and PostgreSQL 18.4 certification"); }],
  ["RLS certification made conditional", (gate) => { gate.jobs["deploy-production-ecs"].steps.find((step) => step.name === "Full RLS verification and PostgreSQL 18.4 certification").if = "${{ false }}"; }],
  ["component commit before smoke", (gate) => { const steps = gate.jobs["deploy-production-ecs"].steps;
    const commit = steps.findIndex((step) => step.name === "Commit authenticated backend recovery component state");
    const smoke = steps.findIndex((step) => step.name === "Verify backend health");
    [steps[commit], steps[smoke]] = [steps[smoke], steps[commit]]; }],
  ["green lane disabled", (gate) => { gate.jobs["deploy-production-ecs"].steps.find((step) => step.name === "Execute governed green backend health recovery with verified Terraform source").if = "${{ false }}"; }],
]) test(`backend recovery certification rejects ${name}`, () => {
  const gate = copy(); change(gate);
  assert.throws(() => assertBackendRecoveryWorkflowGraph(gate));
});
