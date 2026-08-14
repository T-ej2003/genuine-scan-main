import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  observeStageBImagePublication,
  STAGE_B_IMAGE_ARTIFACT_NAME,
  STAGE_B_IMAGE_ARTIFACT_FILE,
} from "../aws/dispatch-production-green-stage-b-images.mjs";
import { parseStageBImagePublicationRecords } from "../aws/stage-b-image-publication-identity.mjs";
import { writeStageBPrivateFileAtomic } from "../aws/stage-b-artifact-contract.mjs";

const REPOSITORY = "T-ej2003/genuine-scan-main";
const SHA = /^[a-f0-9]{40}$/;
const RUN_ID = /^\d+$/;

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function runGh(args, run = execFileSync) {
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (!token) throw new Error("A GitHub token is required to consume the canonical image publication artifact.");
  return run("gh", args, {
    encoding: "utf8",
    stdio: "pipe",
    env: { ...process.env, GH_TOKEN: token, GITHUB_TOKEN: token },
  });
}

function findCanonicalArtifactFiles(directory) {
  const found = [];
  const walk = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const candidate = path.join(current, entry.name);
      if (entry.isDirectory()) walk(candidate);
      else if (entry.name === STAGE_B_IMAGE_ARTIFACT_FILE) found.push(candidate);
    }
  };
  walk(directory);
  return found;
}

export function consumeStageBImagePublication({
  repository = REPOSITORY,
  workflowRunId,
  releaseSha,
  downloadDirectory,
  outputPath,
  githubOutputPath,
  run = execFileSync,
} = {}) {
  if (repository !== REPOSITORY) throw new Error("Stage B image publication repository is not the protected MSCQR repository.");
  if (!RUN_ID.test(String(workflowRunId || ""))) throw new Error("A successful Stage B image publication workflow run ID is required.");
  if (!SHA.test(String(releaseSha || ""))) throw new Error("Stage B image publication release SHA must be a full commit SHA.");
  if (!downloadDirectory || !outputPath || !githubOutputPath) throw new Error("Stage B image publication output paths are required.");
  if (fs.existsSync(outputPath)) throw new Error("Stage B image publication evidence cannot overwrite an existing file.");
  fs.mkdirSync(downloadDirectory, { recursive: true, mode: 0o700 });
  if (fs.readdirSync(downloadDirectory).length !== 0) throw new Error("Stage B image publication download directory must be empty.");

  runGh(["run", "download", String(workflowRunId), "--repo", repository, "--name", STAGE_B_IMAGE_ARTIFACT_NAME, "--dir", downloadDirectory], run);
  const artifactFiles = findCanonicalArtifactFiles(downloadDirectory);
  if (artifactFiles.length !== 1) throw new Error("Stage B image publication download must contain exactly one canonical artifact file.");
  const artifactPath = artifactFiles[0];
  const stat = fs.lstatSync(artifactPath);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Stage B image publication artifact must be a regular file.");
  fs.chmodSync(artifactPath, 0o600);
  const artifactBytes = fs.readFileSync(artifactPath);
  const observed = observeStageBImagePublication({ repository, workflowRunId, releaseSha, run });
  if (observed.workflowRunId !== String(workflowRunId)) throw new Error("Stage B image publication metadata does not match the requested workflow run.");
  const images = parseStageBImagePublicationRecords(artifactBytes, { expectedReleaseSha: releaseSha });
  const manifest = {
    schemaVersion: 1,
    repository,
    workflowRunId: String(workflowRunId),
    workflowFile: observed.workflowFile,
    workflowName: observed.workflowName,
    artifactName: observed.artifactName,
    artifactSha256: sha256(artifactBytes),
    sourceSha: releaseSha,
    toolingSha: observed.headSha,
    imageReleaseSha: releaseSha,
    publication: "canonical-stage-b-workflow-success-with-cosign-verification",
    images,
  };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest)}\n`);
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: manifestBytes, repositoryRoot: process.cwd(), label: "Preauthorized Stage B image evidence" });
  const byService = Object.fromEntries(images.map((record) => [record.service, record]));
  const outputLines = [
    ["backend", byService.backend],
    ["worker", byService.worker],
    ["rls_executor", byService["rls-executor"]],
    ["rls_canary", byService["rls-canary"]],
  ].flatMap(([name, record]) => [`${name}_image_ref=${record.image_ref}`, `${name}_image_uri=${record.image_uri}`, `${name}_image_digest=${record.image_digest}`]);
  outputLines.push(`artifact_sha256=${manifest.artifactSha256}`, `image_release_sha=${releaseSha}`, `workflow_run_id=${workflowRunId}`, `manifest_path=${outputPath}`);
  fs.appendFileSync(githubOutputPath, `${outputLines.join("\n")}\n`);
  return Object.freeze({ manifest, manifestPath: outputPath, artifactPath, images });
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const [workflowRunId, releaseSha, downloadDirectory, outputPath, githubOutputPath] = process.argv.slice(2);
  consumeStageBImagePublication({ workflowRunId, releaseSha, downloadDirectory, outputPath, githubOutputPath });
}
