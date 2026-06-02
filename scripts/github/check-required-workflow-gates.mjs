#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const isMain = import.meta.url === pathToFileURL(process.argv[1] || "").href;

export function parseList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export function runMatchesTarget(run, { targetSha, targetEvents }) {
  return run?.head_sha === targetSha && targetEvents.includes(run?.event);
}

export function selectMatchingRun(runs, options) {
  return [...(runs || [])]
    .filter((run) => runMatchesTarget(run, options))
    .sort((left, right) => Date.parse(right.created_at || 0) - Date.parse(left.created_at || 0))[0] || null;
}

export function summarizeRun(run) {
  if (!run) return "not-found";
  const conclusion = run.conclusion ? `/${run.conclusion}` : "";
  return `${run.status}${conclusion} run_id=${run.id} event=${run.event} sha=${run.head_sha}`;
}

export function buildGateEntries({ requiredWorkflowFiles, workflowPayloads, targetSha, targetEvents }) {
  return requiredWorkflowFiles.map((workflowFile) => {
    const payload = workflowPayloads[workflowFile] || {};
    const workflow = payload.workflow || null;
    const runs = payload.runs || [];
    const run = selectMatchingRun(runs, { targetSha, targetEvents });
    const latestRuns = runs.slice(0, 5).map((item) => ({
      id: item.id,
      event: item.event,
      head_sha: item.head_sha,
      head_branch: item.head_branch,
      status: item.status,
      conclusion: item.conclusion,
      html_url: item.html_url,
      created_at: item.created_at,
    }));

    return {
      workflowFile,
      workflow,
      workflowFound: Boolean(workflow),
      run,
      latestRuns,
    };
  });
}

export function evaluateGateState(entries) {
  const workflowMissing = entries.filter((entry) => !entry.workflowFound);
  const failed = entries.filter(
    ({ workflowFound, run }) =>
      workflowFound && run?.status === "completed" && run.conclusion !== "success",
  );
  const passed = entries.filter(
    ({ workflowFound, run }) => workflowFound && run?.status === "completed" && run.conclusion === "success",
  );
  const pending = entries.filter(
    ({ workflowFound, run }) => workflowFound && (!run || run.status !== "completed"),
  );

  return {
    entries,
    workflowMissing,
    failed,
    passed,
    pending,
    ok: workflowMissing.length === 0 && failed.length === 0 && pending.length === 0,
  };
}

function requireEnv(env) {
  const requiredWorkflowFiles = parseList(env.REQUIRED_WORKFLOW_FILES);
  const targetEvents = parseList(env.TARGET_EVENTS || env.TARGET_EVENT || "push,workflow_dispatch");
  const maxAttempts = Number.parseInt(env.MAX_ATTEMPTS || "1", 10);
  const pollSeconds = Number.parseInt(env.POLL_SECONDS || "30", 10);

  if (!env.GITHUB_REPOSITORY || !env.GITHUB_TOKEN || !env.TARGET_SHA || requiredWorkflowFiles.length === 0) {
    throw new Error("Missing required environment: GITHUB_REPOSITORY, GITHUB_TOKEN, TARGET_SHA, REQUIRED_WORKFLOW_FILES.");
  }
  if (targetEvents.length === 0 || !Number.isFinite(maxAttempts) || maxAttempts < 1 || !Number.isFinite(pollSeconds) || pollSeconds < 0) {
    throw new Error("Invalid polling configuration. TARGET_EVENTS must be non-empty, MAX_ATTEMPTS >= 1, POLL_SECONDS >= 0.");
  }

  const [owner, repo] = env.GITHUB_REPOSITORY.split("/");
  if (!owner || !repo) throw new Error("Invalid GITHUB_REPOSITORY. Expected owner/repo.");

  return {
    owner,
    repo,
    token: env.GITHUB_TOKEN,
    targetSha: env.TARGET_SHA,
    targetEvents,
    requiredWorkflowFiles,
    maxAttempts,
    pollSeconds,
  };
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function githubClient({ owner, repo, token }) {
  return async function githubJson(path, { allow404 = false } = {}) {
    const url = new URL(`https://api.github.com/repos/${owner}/${repo}${path}`);
    const response = await fetch(url, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });

    if (allow404 && response.status === 404) return null;
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`GitHub API ${response.status} for ${path}: ${body.slice(0, 500)}`);
    }

    return response.json();
  };
}

async function readWorkflowPayload(githubJson, workflowFile, targetSha) {
  const encodedFile = encodeURIComponent(workflowFile);
  const workflow = await githubJson(`/actions/workflows/${encodedFile}`, { allow404: true });
  if (!workflow) return { workflow: null, runs: [] };

  const params = new URLSearchParams({
    head_sha: targetSha,
    per_page: "100",
  });
  const runsPayload = await githubJson(`/actions/workflows/${encodedFile}/runs?${params}`);
  const targetRuns = runsPayload.workflow_runs || [];
  if (targetRuns.length > 0) return { workflow, runs: targetRuns };

  const latestParams = new URLSearchParams({ per_page: "5" });
  const latestRunsPayload = await githubJson(`/actions/workflows/${encodedFile}/runs?${latestParams}`);
  return { workflow, runs: latestRunsPayload.workflow_runs || [] };
}

async function readGateState(config) {
  const githubJson = githubClient(config);
  const workflowPayloadPairs = await Promise.all(
    config.requiredWorkflowFiles.map(async (workflowFile) => [
      workflowFile,
      await readWorkflowPayload(githubJson, workflowFile, config.targetSha),
    ]),
  );
  const workflowPayloads = Object.fromEntries(workflowPayloadPairs);
  return evaluateGateState(
    buildGateEntries({
      requiredWorkflowFiles: config.requiredWorkflowFiles,
      workflowPayloads,
      targetSha: config.targetSha,
      targetEvents: config.targetEvents,
    }),
  );
}

function printState(state, config, { stream = process.stdout } = {}) {
  stream.write(`Required workflow gate state for ${config.targetSha} (events: ${config.targetEvents.join(",")}):\n`);
  for (const entry of state.entries) {
    if (!entry.workflowFound) {
      stream.write(`- ${entry.workflowFile}: workflow-file-not-found\n`);
      continue;
    }
    stream.write(`- ${entry.workflowFile}: ${summarizeRun(entry.run)}${entry.run?.html_url ? ` ${entry.run.html_url}` : ""}\n`);
    if (!entry.run && entry.latestRuns.length > 0) {
      stream.write(`  latest runs for diagnostics:\n`);
      for (const latest of entry.latestRuns) {
        stream.write(
          `  - run_id=${latest.id} event=${latest.event} sha=${latest.head_sha} branch=${latest.head_branch || ""} status=${latest.status}/${latest.conclusion || ""} ${latest.html_url || ""}\n`,
        );
      }
    }
  }
}

export async function main(env = process.env) {
  const config = requireEnv(env);

  for (let attempt = 1; attempt <= config.maxAttempts; attempt += 1) {
    const state = await readGateState(config);
    printState(state, config);

    if (state.workflowMissing.length > 0) {
      for (const entry of state.workflowMissing) {
        console.error(`${entry.workflowFile} was not found in GitHub Actions. Check the workflow filename on the default branch.`);
      }
      process.exit(1);
    }

    if (state.failed.length > 0) {
      for (const { workflowFile, run } of state.failed) {
        console.error(`${workflowFile} did not pass for ${config.targetSha}: ${summarizeRun(run)} ${run.html_url || ""}`);
      }
      process.exit(1);
    }

    if (state.pending.length === 0) {
      console.log(`All required workflow gates passed for ${config.targetSha}.`);
      process.exit(0);
    }

    console.log(
      `Waiting for required gates on ${config.targetSha} (${attempt}/${config.maxAttempts}): ` +
        state.pending.map(({ workflowFile, run }) => `${workflowFile}=${summarizeRun(run)}`).join(", "),
    );

    if (attempt < config.maxAttempts) await sleep(config.pollSeconds * 1000);
  }

  console.error(`Timed out waiting for required workflow gates for ${config.targetSha}.`);
  console.error("If this is a production release, run the Release Train workflow so missing gates are dispatched and tracked for the target SHA.");
  process.exit(1);
}

if (isMain) {
  try {
    await main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(2);
  }
}
