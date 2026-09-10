#!/usr/bin/env node

import fs from "node:fs";
import { pathToFileURL } from "node:url";

const SHA = /^[a-f0-9]{40}$/;
const WORKFLOW = /^[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml$/;
const TAG_REF = /^refs\/tags\/(release-|v)[A-Za-z0-9][A-Za-z0-9._/-]*$/;
const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;

export function assertWorkflowDispatchRef(ref) {
  if (ref === "main" || TAG_REF.test(ref || "")) return ref;
  throw new Error("Workflow dispatch ref must be main or an explicit refs/tags/<name> ref; commit-valued and mutable branch refs are not accepted.");
}

export function selectSourceBoundRun({ beforeRunIds, runs, targetSha, workflowPath, workflowId, repository }) {
  if (!SHA.test(targetSha || "")) throw new Error("Workflow target SHA must be a full commit SHA.");
  const fresh = (runs || []).filter((run) => !beforeRunIds.has(String(run.id)) && run?.event === "workflow_dispatch");
  if (fresh.length === 0) return null;
  const exact = fresh.filter((run) => run?.head_sha === targetSha && run?.path === workflowPath && String(run?.workflow_id) === String(workflowId) && run?.repository?.full_name === repository && run?.head_repository?.full_name === repository && String(run?.run_attempt) === "1");
  if (exact.length === 1 && fresh.length === 1) return exact[0];
  if (exact.length > 1) throw new Error("Workflow dispatch correlation is ambiguous for the selected target SHA.");
  const observed = fresh.map((run) => `${run.id}:${run.head_sha || "missing"}:${run.path || "missing"}`).join(", ");
  throw new Error(`Dispatched workflow source is not the selected target SHA (${targetSha}); observed ${observed}.`);
}

export async function dispatchSourceBoundWorkflow({ repository, token, workflow, ref, targetSha, inputs = {}, fetchImpl = fetch, sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)), attempts = 20, pollMilliseconds = 1500 } = {}) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository || "")) throw new Error("GitHub repository must be owner/name.");
  if (!token) throw new Error("GitHub token is required for source-bound workflow dispatch.");
  if (!WORKFLOW.test(workflow || "")) throw new Error("Workflow filename is invalid.");
  assertWorkflowDispatchRef(ref);
  if (!SHA.test(targetSha || "")) throw new Error("Workflow target SHA must be a full commit SHA.");
  if (Object.getPrototypeOf(inputs) !== Object.prototype || Object.values(inputs).some((value) => typeof value !== "string")) throw new Error("Workflow dispatch inputs must be a plain object of strings.");

  const repositoryBase = `https://api.github.com/repos/${repository}`;
  const workflowBase = `${repositoryBase}/actions/workflows/${encodeURIComponent(workflow)}`;
  const request = async (url, options = {}) => {
    const response = await fetchImpl(url, {
      ...options,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        ...(options.headers || {}),
      },
    });
    if (!response.ok) throw new Error(`GitHub workflow dispatch API ${response.status}: ${(await response.text()).slice(0, 500)}`);
    return response.status === 204 ? null : response.json();
  };
  const workflowMetadata = await request(workflowBase);
  const workflowPath = workflowMetadata.path;
  if (workflowPath !== `.github/workflows/${workflow}` || !Number.isSafeInteger(workflowMetadata.id) || workflowMetadata.id < 1) throw new Error("Workflow dispatch identity is not exact.");
  const before = await request(`${workflowBase}/runs?event=workflow_dispatch&per_page=100`);
  const beforeRunIds = new Set((before.workflow_runs || []).map((run) => String(run.id)));
  const dispatched = await request(`${workflowBase}/dispatches`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ref, inputs, return_run_details: true }) });
  if (dispatched?.workflow_run_id) {
    const run = await request(`${repositoryBase}/actions/runs/${dispatched.workflow_run_id}`);
    return selectSourceBoundRun({ beforeRunIds, runs: [run], targetSha, workflowPath, workflowId: workflowMetadata.id, repository }) || (() => { throw new Error("Returned workflow run is not a fresh workflow_dispatch candidate."); })();
  }

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const runs = await request(`${workflowBase}/runs?event=workflow_dispatch&per_page=100`);
    const selected = selectSourceBoundRun({ beforeRunIds, runs: runs.workflow_runs, targetSha, workflowPath, workflowId: workflowMetadata.id, repository });
    if (selected) return selected;
    if (attempt + 1 < attempts) await sleep(pollMilliseconds);
  }
  throw new Error(`No source-bound workflow run became visible for ${workflow} at ${targetSha}.`);
}

function parseArgs(args) {
  const values = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!key?.startsWith("--") || args[index + 1] === undefined || values[key]) throw new Error("Expected each dispatch option exactly once.");
    values[key] = args[index + 1];
  }
  if (Object.keys(values).length !== 4 || !values["--workflow"] || !values["--ref"] || !values["--target-sha"] || !values["--inputs-file"]) throw new Error("Usage: dispatch-source-bound-workflow.mjs --workflow <file> --ref <main|refs/tags/name> --target-sha <sha> --inputs-file <private-json-file>");
  return values;
}

if (isMain) {
  try {
    const values = parseArgs(process.argv.slice(2));
    const stat = fs.lstatSync(values["--inputs-file"]);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) throw new Error("Workflow dispatch inputs file must be a private regular file.");
    const inputs = JSON.parse(fs.readFileSync(values["--inputs-file"], "utf8"));
    const run = await dispatchSourceBoundWorkflow({
      repository: process.env.GITHUB_REPOSITORY,
      token: process.env.GH_TOKEN || process.env.GITHUB_TOKEN,
      workflow: values["--workflow"],
      ref: values["--ref"],
      targetSha: values["--target-sha"],
      inputs,
    });
    process.stdout.write(`SOURCE_BOUND_WORKFLOW_RUN_ID=${run.id}\nSOURCE_BOUND_WORKFLOW_RUN_URL=${run.html_url || ""}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exit(1);
  }
}
