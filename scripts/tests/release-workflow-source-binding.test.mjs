import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { assertWorkflowDispatchRef, dispatchProtectedMainReleaseGate, dispatchSourceBoundWorkflow, selectSourceBoundRun } from "../github/dispatch-source-bound-workflow.mjs";

const repository = "T-ej2003/genuine-scan-main";
const workflow = "deployment-audit.yml";
const workflowPath = `.github/workflows/${workflow}`;
const workflowId = 42;
const current = "a".repeat(40);
const older = "b".repeat(40);

function response(status, body = undefined) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: body === undefined ? {} : { "Content-Type": "application/json" } });
}

function apiFor({ workflowFile = workflow, targetSha = current, observedSha = targetSha, headBranch = "main", freshRuns = 1, returnRunDetails = false, runAttempt = 1 } = {}) {
  const expectedPath = `.github/workflows/${workflowFile}`;
  let runsReads = 0;
  const requests = [];
  return {
    requests,
    fetch: async (url, options = {}) => {
      requests.push({ url, options });
      if (url.endsWith(`/actions/workflows/${workflowFile}`)) return response(200, { id: workflowId, path: expectedPath });
      if (url.endsWith(`/actions/workflows/${workflowFile}/dispatches`)) return returnRunDetails ? response(200, { workflow_run_id: 99 }) : response(204);
      if (url.endsWith("/actions/runs/99")) return response(200, { id: 99, workflow_id: workflowId, repository: { full_name: repository }, head_repository: { full_name: repository }, event: "workflow_dispatch", run_attempt: runAttempt, head_sha: observedSha, head_branch: headBranch, path: expectedPath, html_url: "https://example.test/runs/99" });
      if (url.includes(`/actions/workflows/${workflowFile}/runs?`)) {
        runsReads += 1;
        return response(200, { workflow_runs: runsReads === 1 ? [] : Array.from({ length: freshRuns }, (_, index) => ({ id: index + 1, workflow_id: workflowId, repository: { full_name: repository }, head_repository: { full_name: repository }, event: "workflow_dispatch", run_attempt: runAttempt, head_sha: observedSha, head_branch: headBranch, path: expectedPath, html_url: `https://example.test/runs/${index + 1}` })) });
      }
      throw new Error(`Unexpected URL: ${url}`);
    },
  };
}

test("only main or an explicit tag is a legal workflow_dispatch ref", () => {
  assert.equal(assertWorkflowDispatchRef("main"), "main");
  assert.equal(assertWorkflowDispatchRef("refs/tags/release-2026-09-10"), "refs/tags/release-2026-09-10");
  assert.equal(assertWorkflowDispatchRef("refs/tags/v1.2.3"), "refs/tags/v1.2.3");
  for (const ref of [current, "feature/release", "refs/heads/main", "", "refs/tags/", "refs/tags/rollback-foo"]) assert.throws(() => assertWorkflowDispatchRef(ref), /main or an explicit/);
});

test("Release Gate always dispatches from protected main while preserving a distinct deployment target", async () => {
  for (const targetRef of ["main", "refs/tags/release-older", "refs/tags/v1.2.3"]) {
    const api = apiFor({ workflowFile: "release-gate.yml", observedSha: "c".repeat(40), returnRunDetails: true });
    const run = await dispatchProtectedMainReleaseGate({ repository, token: "token", targetRef, targetSha: older, inputs: { git_ref: targetRef, target_sha: older }, fetchImpl: api.fetch, attempts: 1 });
    assert.equal(run.head_branch, "main");
    assert.equal(run.head_sha, "c".repeat(40));
    assert.match(api.requests.find(({ url }) => url.endsWith("/dispatches")).options.body, /"ref":"main"/);
  }
  const wrongSource = apiFor({ workflowFile: "release-gate.yml", observedSha: "c".repeat(40), headBranch: "release-older", returnRunDetails: true });
  await assert.rejects(() => dispatchProtectedMainReleaseGate({ repository, token: "token", targetRef: "refs/tags/release-older", targetSha: older, inputs: { git_ref: "refs/tags/release-older", target_sha: older }, fetchImpl: wrongSource.fetch, attempts: 1 }), /protected main/);
  await assert.rejects(() => dispatchProtectedMainReleaseGate({ repository, token: "token", targetRef: "main", targetSha: older, inputs: { git_ref: "main", target_sha: current }, attempts: 1 }), /not bound/);
});

test("current main and an older tag target dispatch only a run bound to the selected SHA", async () => {
  for (const [ref, targetSha] of [["main", current], ["refs/tags/release-older", older]]) {
    const api = apiFor({ targetSha, returnRunDetails: true });
    const run = await dispatchSourceBoundWorkflow({ repository, token: "token", workflow, ref, targetSha, inputs: { target_sha: targetSha }, fetchImpl: api.fetch, attempts: 1 });
    assert.equal(run.head_sha, targetSha);
    assert.match(api.requests.find(({ url }) => url.endsWith("/dispatches")).options.body, new RegExp(`"ref":"${ref}"`));
    assert.match(api.requests.find(({ url }) => url.endsWith("/dispatches")).options.body, /"return_run_details":true/);
  }
});

test("a main advance, wrong source, mutable ref movement, and ambiguous correlation fail closed", async () => {
  for (const options of [
    { observedSha: older },
    { observedSha: older },
    { observedSha: current, freshRuns: 2 },
    { observedSha: current, runAttempt: 2 },
  ]) {
    const api = apiFor(options);
    await assert.rejects(
      dispatchSourceBoundWorkflow({ repository, token: "token", workflow, ref: "main", targetSha: current, inputs: {}, fetchImpl: api.fetch, attempts: 1 }),
      /not the selected target SHA|ambiguous/,
    );
  }
  assert.throws(() => selectSourceBoundRun({ beforeRunIds: new Set(), runs: [], targetSha: "not-a-sha", workflowPath, workflowId, repository }), /full commit SHA/);
  assert.throws(() => selectSourceBoundRun({ beforeRunIds: new Set(), runs: [{ id: 1, workflow_id: workflowId, repository: { full_name: "other/repository" }, head_repository: { full_name: "other/repository" }, event: "workflow_dispatch", run_attempt: 1, head_sha: current, path: workflowPath }], targetSha: current, workflowPath, workflowId, repository }), /not the selected target SHA/);
});

test("Release Train resolves an exact dispatch ref and uses source-bound dispatch for every gate", () => {
  const train = readFileSync(".github/workflows/release-train.yml", "utf8");
  const gate = readFileSync(".github/workflows/release-gate.yml", "utf8");
  assert.match(train, /git_ref must be main or an explicit refs\/tags/);
  assert.match(train, /refs\/tags\/\(release-\|v\)/);
  assert.match(train, /dispatch ref must resolve exactly to target_sha/);
  assert.match(train, /--workflow "\$workflow_file" --ref "\$DISPATCH_REF" --target-sha "\$TARGET_SHA"/);
  assert.match(train, /dispatch-protected-main-release-gate\.mjs[\s\S]*--target-ref "\$TARGET_REF" --target-sha "\$TARGET_SHA"/);
  assert.doesNotMatch(train, /gh workflow run/);
  assert.match(gate, /Release Gate itself always runs from protected main/);
  assert.match(gate, /Historical production deploy targets require a release-\* or v\* tag ref/);
  assert.match(gate, /Historical deployment target SHA must equal its exact release tag/);
  assert.match(gate, /Release Train does not authenticate the retained main deployment target/);
});
