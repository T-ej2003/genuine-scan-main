#!/usr/bin/env node

const {
  GITHUB_REPOSITORY,
  GITHUB_TOKEN,
  TARGET_BRANCH = "main",
  TARGET_EVENT = "push",
  TARGET_SHA,
  REQUIRED_WORKFLOW_FILES = "",
  MAX_ATTEMPTS = "60",
  POLL_SECONDS = "30",
} = process.env;

const requiredWorkflowFiles = REQUIRED_WORKFLOW_FILES.split(",")
  .map((value) => value.trim())
  .filter(Boolean);

if (!GITHUB_REPOSITORY || !GITHUB_TOKEN || !TARGET_SHA || requiredWorkflowFiles.length === 0) {
  console.error(
    "Missing required environment: GITHUB_REPOSITORY, GITHUB_TOKEN, TARGET_SHA, REQUIRED_WORKFLOW_FILES.",
  );
  process.exit(2);
}

const [owner, repo] = GITHUB_REPOSITORY.split("/");
const maxAttempts = Number.parseInt(MAX_ATTEMPTS, 10);
const pollSeconds = Number.parseInt(POLL_SECONDS, 10);

if (!owner || !repo || !Number.isFinite(maxAttempts) || !Number.isFinite(pollSeconds)) {
  console.error("Invalid GitHub repository or polling configuration.");
  process.exit(2);
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function githubJson(path) {
  const url = new URL(`https://api.github.com/repos/${owner}/${repo}${path}`);
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GitHub API ${response.status} for ${path}: ${body.slice(0, 500)}`);
  }

  return response.json();
}

async function getWorkflowRun(workflowFile) {
  const params = new URLSearchParams({
    branch: TARGET_BRANCH,
    event: TARGET_EVENT,
    head_sha: TARGET_SHA,
    per_page: "25",
  });
  const payload = await githubJson(`/actions/workflows/${encodeURIComponent(workflowFile)}/runs?${params}`);

  return (payload.workflow_runs || []).find((run) => run.head_sha === TARGET_SHA) || null;
}

async function readGateState() {
  const entries = await Promise.all(
    requiredWorkflowFiles.map(async (workflowFile) => {
      const run = await getWorkflowRun(workflowFile);
      return { workflowFile, run };
    }),
  );

  const failed = entries.filter(
    ({ run }) => run?.status === "completed" && run.conclusion !== "success",
  );
  const passed = entries.filter(({ run }) => run?.status === "completed" && run.conclusion === "success");
  const pending = entries.filter(({ run }) => !run || run.status !== "completed");

  return { entries, failed, passed, pending };
}

for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
  const { failed, passed, pending } = await readGateState();

  if (failed.length > 0) {
    for (const { workflowFile, run } of failed) {
      console.error(
        `${workflowFile} did not pass for ${TARGET_SHA}: conclusion=${run.conclusion}, run=${run.html_url}`,
      );
    }
    process.exit(1);
  }

  if (pending.length === 0) {
    console.log(`All required workflow gates passed for ${TARGET_SHA}:`);
    for (const { workflowFile, run } of passed) {
      console.log(`- ${workflowFile}: ${run.html_url}`);
    }
    process.exit(0);
  }

  console.log(
    `Waiting for required gates on ${TARGET_SHA} (${attempt}/${maxAttempts}): ` +
      pending
        .map(({ workflowFile, run }) => `${workflowFile}=${run ? run.status : "not-found"}`)
        .join(", "),
  );

  if (attempt < maxAttempts) {
    await sleep(pollSeconds * 1000);
  }
}

console.error(`Timed out waiting for required workflow gates for ${TARGET_SHA}.`);
process.exit(1);
