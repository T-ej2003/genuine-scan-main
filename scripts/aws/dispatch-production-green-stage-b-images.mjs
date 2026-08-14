import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { assertObservedStageBImagePublicationMetadata, STAGE_B_IMAGE_ARTIFACT_NAME, STAGE_B_IMAGE_CANONICAL_FILENAME, STAGE_B_IMAGE_WORKFLOW_FILE, STAGE_B_IMAGE_WORKFLOW_NAME, writeStageBImagePublicationIdentity } from "./stage-b-image-publication-identity.mjs";

export const STAGE_B_IMAGE_WORKFLOW = "production-green-stage-b-images.yml";
export { STAGE_B_IMAGE_ARTIFACT_NAME, STAGE_B_IMAGE_CANONICAL_FILENAME as STAGE_B_IMAGE_ARTIFACT_FILE, STAGE_B_IMAGE_WORKFLOW_FILE, STAGE_B_IMAGE_WORKFLOW_NAME };
export { assertObservedStageBImagePublicationMetadata };
const APPROVED_WORKFLOW_REF = "main";
const SHA_PATTERN = /^[a-f0-9]{40}$/;

const runGh = (args, run = execFileSync) => run("gh", args, { encoding: "utf8", stdio: "pipe" });

export function observeStageBImagePublication({ repository, workflowRunId, toolingSha, releaseSha, run = execFileSync } = {}) {
  if (!/^[a-f0-9]{40}$/.test(String(toolingSha || ""))) throw new Error("Stage B tooling SHA must be a full 40-character commit SHA.");
  if (!/^\d+$/.test(String(workflowRunId || ""))) throw new Error("Observed Stage B workflow run ID is required.");
  if (!/^[a-f0-9]{40}$/.test(String(releaseSha || ""))) throw new Error("Stage B release SHA must be a full 40-character commit SHA.");
  const runRecord = JSON.parse(runGh(["api", `repos/${repository}/actions/runs/${workflowRunId}`], run));
  const artifacts = JSON.parse(runGh(["api", `repos/${repository}/actions/runs/${workflowRunId}/artifacts`], run)).artifacts || [];
  const matching = artifacts.filter((artifact) => artifact.name === STAGE_B_IMAGE_ARTIFACT_NAME);
  if (matching.length !== 1) throw new Error("Stage B publication must have exactly one matching four-image artifact.");
  const artifact = matching[0];
  const observed = {
    workflowRunId: String(runRecord.id),
    workflowDatabaseId: String(runRecord.workflow_id),
    workflowFile: runRecord.path,
    workflowName: runRecord.name,
    event: runRecord.event,
    workflowDefinitionSha: runRecord.head_sha,
    imageReleaseSha: releaseSha,
    headBranch: runRecord.head_branch,
    conclusion: runRecord.conclusion,
    artifactId: String(artifact.id),
    artifactName: artifact.name,
    artifactExpired: Boolean(artifact.expired),
    artifactArchiveFilename: null,
  };
  assertObservedStageBImagePublicationMetadata(observed, { expectedToolingSha: toolingSha, expectedReleaseSha: releaseSha });
  return Object.freeze(observed);
}

export function writeObservedStageBImagePublicationIdentity({ repository, workflowRunId, toolingSha, releaseSha, canonicalArtifactPath, outputPath, repositoryRoot = process.cwd(), run = execFileSync } = {}) {
  const artifactStat = fs.lstatSync(canonicalArtifactPath);
  if (!artifactStat.isFile() || artifactStat.isSymbolicLink() || (artifactStat.mode & 0o777) !== 0o600) throw new Error("Stage B canonical image artifact must be a private regular file.");
  const observed = observeStageBImagePublication({ repository, workflowRunId, toolingSha, releaseSha, run });
  return writeStageBImagePublicationIdentity({ observed, artifactBytes: fs.readFileSync(canonicalArtifactPath), expectedToolingSha: toolingSha, expectedReleaseSha: releaseSha, outputPath, repositoryRoot });
}

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
  runGh(["workflow", "run", STAGE_B_IMAGE_WORKFLOW, "--repo", repo, "--ref", workflowRef, "-f", `release_sha=${releaseSha}`], run);
  return { repository: repo, workflow: STAGE_B_IMAGE_WORKFLOW, workflowFile: STAGE_B_IMAGE_WORKFLOW_FILE, workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, workflowRef, artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactFile: STAGE_B_IMAGE_CANONICAL_FILENAME, releaseSha };
};

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [releaseSha] = process.argv.slice(2);
  dispatchProductionGreenStageBImages({ releaseSha });
}
