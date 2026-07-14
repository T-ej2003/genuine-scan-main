import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  buildGateEntries,
  evaluateGateState,
  selectMatchingRun,
} from "../github/check-required-workflow-gates.mjs";

const requiredWorkflowFiles = ["quality-gate.yml", "secret-scan.yml", "deployment-audit.yml"];
const targetSha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const targetEvents = ["push", "workflow_dispatch"];

function run(overrides = {}) {
  return {
    id: 1001,
    event: "push",
    head_sha: targetSha,
    head_branch: "main",
    status: "completed",
    conclusion: "success",
    html_url: "https://github.example/run/1001",
    created_at: "2026-06-02T12:00:00Z",
    ...overrides,
  };
}

function payloads() {
  return Object.fromEntries(
    requiredWorkflowFiles.map((workflowFile, index) => [
      workflowFile,
      {
        workflow: { path: `.github/workflows/${workflowFile}` },
        runs: [run({ id: 1000 + index, html_url: `https://github.example/run/${1000 + index}` })],
      },
    ]),
  );
}

function state(workflowPayloads) {
  return evaluateGateState(
    buildGateEntries({
      requiredWorkflowFiles,
      workflowPayloads,
      targetSha,
      targetEvents,
    }),
  );
}

test("all required workflows found and successful", () => {
  const result = state(payloads());

  assert.equal(result.ok, true);
  assert.deepEqual(result.passed.map((entry) => entry.workflowFile), requiredWorkflowFiles);
  assert.equal(result.pending.length, 0);
  assert.equal(result.failed.length, 0);
});

test("missing deployment-audit.yml is reported as workflow missing", () => {
  const workflowPayloads = payloads();
  workflowPayloads["deployment-audit.yml"] = { workflow: null, runs: [] };

  const result = state(workflowPayloads);

  assert.equal(result.ok, false);
  assert.deepEqual(result.workflowMissing.map((entry) => entry.workflowFile), ["deployment-audit.yml"]);
});

test("workflow exists but wrong SHA stays pending with diagnostics", () => {
  const workflowPayloads = payloads();
  workflowPayloads["deployment-audit.yml"] = {
    workflow: { path: ".github/workflows/deployment-audit.yml" },
    runs: [run({ head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" })],
  };

  const result = state(workflowPayloads);

  assert.equal(result.ok, false);
  assert.deepEqual(result.pending.map((entry) => entry.workflowFile), ["deployment-audit.yml"]);
  assert.equal(result.pending[0].run, null);
  assert.equal(result.pending[0].latestRuns[0].head_sha, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
});

test("failed workflow blocks the gate", () => {
  const workflowPayloads = payloads();
  workflowPayloads["secret-scan.yml"] = {
    workflow: { path: ".github/workflows/secret-scan.yml" },
    runs: [run({ conclusion: "failure", html_url: "https://github.example/run/fail" })],
  };

  const result = state(workflowPayloads);

  assert.equal(result.ok, false);
  assert.deepEqual(result.failed.map((entry) => entry.workflowFile), ["secret-scan.yml"]);
  assert.equal(result.failed[0].run.conclusion, "failure");
});

test("skipped workflow blocks the gate", () => {
  const workflowPayloads = payloads();
  workflowPayloads["quality-gate.yml"] = {
    workflow: { path: ".github/workflows/quality-gate.yml" },
    runs: [run({ conclusion: "skipped" })],
  };

  const result = state(workflowPayloads);

  assert.equal(result.ok, false);
  assert.deepEqual(result.failed.map((entry) => entry.workflowFile), ["quality-gate.yml"]);
  assert.equal(result.failed[0].run.conclusion, "skipped");
});

test("manual workflow_dispatch run matching the target SHA passes", () => {
  const selected = selectMatchingRun(
    [
      run({ id: 1, event: "push", head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }),
      run({ id: 2, event: "workflow_dispatch", head_sha: targetSha }),
    ],
    { targetSha, targetEvents },
  );

  assert.equal(selected.id, 2);
});

test("deployment audit keeps scanners blocking while skipping unsupported private-user CodeQL upload", () => {
  const workflow = fs.readFileSync(".github/workflows/deployment-audit.yml", "utf8");
  assert.match(workflow, /output: audit-artifacts\/codeql/);
  assert.match(workflow, /repository\.private && github\.event\.repository\.owner\.type == 'User' && 'never' \|\| 'always'/);
  assert.match(workflow, /SARIF upload was skipped because code scanning is unavailable for this private personal-account repository/);
  assert.doesNotMatch(workflow, /continue-on-error/);
  for (const requiredStep of ["Run OSV Scanner", "Gitleaks secrets scan", "Trivy IaC scan", "Trivy container scan", "Generate SBOM"]) {
    assert.match(workflow, new RegExp(`- name: ${requiredStep}`));
  }
});
