import { execFileSync } from "node:child_process";

const WORKFLOW = "production-green-stage-b-images.yml";
const APPROVED_WORKFLOW_REF = "main";
const SHA_PATTERN = /^[a-f0-9]{40}$/;

const runGh = (args, run = execFileSync) => run("gh", args, { encoding: "utf8", stdio: "pipe" });

export const dispatchProductionGreenStageBImages = ({
  releaseSha,
  workflowRef = APPROVED_WORKFLOW_REF,
  repository,
  run = execFileSync,
} = {}) => {
  if (!SHA_PATTERN.test(releaseSha || "")) throw new Error("Stage B release SHA must be a full 40-character commit SHA.");
  if (workflowRef !== APPROVED_WORKFLOW_REF || SHA_PATTERN.test(workflowRef)) {
    throw new Error(`Stage B image workflow must be dispatched from ${APPROVED_WORKFLOW_REF}, not a release SHA.`);
  }

  const repo = repository || String(runGh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"], run)).trim();
  if (!repo) throw new Error("Unable to resolve the Stage B image repository.");
  runGh(["api", `repos/${repo}/commits/${releaseSha}`], run);
  runGh(["workflow", "run", WORKFLOW, "--repo", repo, "--ref", workflowRef, "-f", `release_sha=${releaseSha}`], run);
  return { repository: repo, workflow: WORKFLOW, workflowRef, releaseSha };
};

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [releaseSha] = process.argv.slice(2);
  dispatchProductionGreenStageBImages({ releaseSha });
}
