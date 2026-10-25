import assert from "node:assert/strict";
import test from "node:test";
import { assertBackendRecoveryCiCertification } from "../github/assert-backend-recovery-ci-certification.mjs";

const sourceSha = "a".repeat(40);
const repository = "T-ej2003/genuine-scan-main";
const run = { id: 123, run_attempt: 2, head_sha: sourceSha, event: "push", head_branch: "main",
  path: ".github/workflows/quality-gate.yml", workflow_id: 7, repository: { full_name: repository },
  head_repository: { full_name: repository }, status: "completed", conclusion: "success",
  created_at: "2026-10-25T12:00:00Z" };
const job = (name, steps) => ({ name, run_id: 123, head_sha: sourceSha, status: "completed",
  conclusion: "success", steps: steps.map((step) => ({ name: step, conclusion: "success" })) });
const jobs = [
  job("backend", ["Backend quality contract"]),
  job("frontend", ["Frontend quality contract", "Playwright smoke suite"]),
  job("integration", ["Disposable system integration suite"]),
  job("Backend recovery Release Gate certification", ["Certify exact-source graph without production credentials",
    "Certify full RLS on disposable PostgreSQL 18.4"]),
  job("Full RLS package verification", ["Full RLS verification"]),
];
const payloads = () => [
  { path: ".github/workflows/quality-gate.yml", id: 7 },
  { total_count: 1, workflow_runs: [structuredClone(run)] },
  { total_count: jobs.length, jobs: structuredClone(jobs) },
];
async function verify(payload = payloads(), overrides = {}) {
  const paths = [];
  const result = await assertBackendRecoveryCiCertification({ sourceSha, repository, ...overrides,
    getJson: async (path) => { paths.push(path); return payload[paths.length - 1]; } });
  assert.deepEqual(paths, ["/actions/workflows/quality-gate.yml",
    `/actions/workflows/quality-gate.yml/runs?head_sha=${sourceSha}&per_page=100`,
    "/actions/runs/123/attempts/2/jobs?per_page=100"]);
  return result;
}

test("accepts only a successful exact-main run with completed RLS and source certification steps", async () => {
  assert.deepEqual(await verify(), { sourceSha, workflowRunId: "123", workflowRunAttempt: "2" });
});

for (const [name, change] of [
  ["wrong repository", (p) => { p[1].workflow_runs[0].repository.full_name = "attacker/repo"; }],
  ["wrong source", (p) => { p[1].workflow_runs[0].head_sha = "b".repeat(40); }],
  ["wrong workflow", (p) => { p[1].workflow_runs[0].path = ".github/workflows/other.yml"; }],
  ["non-main run", (p) => { p[1].workflow_runs[0].head_branch = "codex/branch"; }],
  ["failed run", (p) => { p[1].workflow_runs[0].conclusion = "failure"; }],
  ["missing certification", (p) => { p[2].jobs.splice(3, 1); p[2].total_count--; }],
  ["skipped certification", (p) => { p[2].jobs[3].conclusion = "skipped"; }],
  ["failed PostgreSQL step", (p) => { p[2].jobs[3].steps[1].conclusion = "failure"; }],
  ["failed package verification", (p) => { p[2].jobs[4].steps[0].conclusion = "failure"; }],
  ["failed backend build", (p) => { p[2].jobs[0].steps[0].conclusion = "failure"; }],
  ["failed frontend E2E", (p) => { p[2].jobs[1].steps[1].conclusion = "failure"; }],
  ["failed integration", (p) => { p[2].jobs[2].steps[0].conclusion = "failure"; }],
  ["incomplete jobs", (p) => { p[2].total_count++; }],
]) test(`rejects ${name}`, async () => {
  const payload = payloads(); change(payload);
  await assert.rejects(verify(payload));
});

test("rejects a newer failed exact-main run instead of reusing an older success", async () => {
  const payload = payloads();
  payload[1].workflow_runs.push({ ...structuredClone(run), id: 124, conclusion: "failure",
    created_at: "2026-10-25T12:01:00Z" });
  payload[1].total_count = 2;
  await assert.rejects(verify(payload));
});
