#!/usr/bin/env node
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const REPOSITORY = "T-ej2003/genuine-scan-main";
const WORKFLOW = ".github/workflows/quality-gate.yml";
const required = new Map([
  ["backend", ["Backend quality contract"]],
  ["frontend", ["Frontend quality contract", "Playwright smoke suite"]],
  ["integration", ["Disposable system integration suite"]],
  ["Backend recovery Release Gate certification", [
    "Certify exact-source graph without production credentials",
    "Certify full RLS on disposable PostgreSQL 18.4",
  ]],
  ["Full RLS package verification", ["Full RLS verification"]],
]);

export async function assertBackendRecoveryCiCertification({ sourceSha, repository, getJson }) {
  assert.equal(repository, REPOSITORY);
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const workflow = await getJson(`/actions/workflows/quality-gate.yml`);
  assert.equal(workflow?.path, WORKFLOW);
  assert.match(String(workflow?.id || ""), /^[1-9][0-9]*$/);
  const runs = await getJson(`/actions/workflows/quality-gate.yml/runs?head_sha=${sourceSha}&per_page=100`);
  assert.ok(Array.isArray(runs?.workflow_runs) && runs.total_count === runs.workflow_runs.length
    && runs.total_count <= 100, "Quality Gate run list is incomplete");
  const matching = runs.workflow_runs.filter((run) => run.head_sha === sourceSha && run.event === "push"
    && run.head_branch === "main" && run.path === WORKFLOW && String(run.workflow_id) === String(workflow.id)
    && run.repository?.full_name === REPOSITORY && run.head_repository?.full_name === REPOSITORY);
  assert.ok(matching.length > 0, "Exact-main Quality Gate run is missing");
  assert.ok(matching.every((run) => Number.isFinite(Date.parse(run.created_at))), "Quality Gate run time is invalid");
  const run = matching.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0];
  assert.equal(run.status, "completed");
  assert.equal(run.conclusion, "success", "Exact-main Quality Gate did not pass");
  assert.match(String(run.id), /^[1-9][0-9]*$/);
  assert.match(String(run.run_attempt), /^[1-9][0-9]*$/);
  const result = await getJson(`/actions/runs/${run.id}/attempts/${run.run_attempt}/jobs?per_page=100`);
  assert.ok(Array.isArray(result?.jobs) && result.total_count === result.jobs.length && result.jobs.length <= 100,
    "Quality Gate job list is incomplete");
  for (const [name, steps] of required) {
    const matches = result.jobs.filter((job) => job.name === name);
    assert.equal(matches.length, 1, `Quality Gate job ${name} is missing or duplicated`);
    const job = matches[0];
    assert.equal(String(job.run_id), String(run.id));
    assert.equal(job.head_sha, sourceSha);
    assert.equal(job.status, "completed");
    assert.equal(job.conclusion, "success", `Quality Gate job ${name} did not pass`);
    for (const step of steps) {
      const matchingSteps = (job.steps || []).filter((item) => item.name === step);
      assert.equal(matchingSteps.length, 1, `Quality Gate step ${step} is missing or duplicated`);
      assert.equal(matchingSteps[0].conclusion, "success", `Quality Gate step ${step} did not pass`);
    }
  }
  return { sourceSha, workflowRunId: String(run.id), workflowRunAttempt: String(run.run_attempt) };
}

async function main(env = process.env) {
  assert.equal(env.GITHUB_ACTIONS, "true");
  assert.ok(env.GITHUB_TOKEN, "GitHub read token is required");
  const getJson = async (path) => {
    const response = await fetch(`https://api.github.com/repos/${REPOSITORY}${path}`, {
      redirect: "error",
      headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        "X-GitHub-Api-Version": "2022-11-28" },
    });
    assert.equal(response.ok, true, `GitHub certification read failed (${response.status})`);
    return response.json();
  };
  const result = await assertBackendRecoveryCiCertification({ sourceSha: env.TARGET_SHA,
    repository: env.GITHUB_REPOSITORY, getJson });
  process.stdout.write(`Exact-head PostgreSQL 18.4 and RLS certification passed in Quality Gate run ${result.workflowRunId}, attempt ${result.workflowRunAttempt}.\n`);
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
