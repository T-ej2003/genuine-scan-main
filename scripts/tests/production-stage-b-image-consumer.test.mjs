import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseStageBImagePublicationRecords } from "../aws/stage-b-image-publication-identity.mjs";
import { consumeStageBImagePublication } from "../ci/consume-stage-b-image-publication.mjs";

const sha = "a".repeat(40);
const digest = (letter) => `sha256:${letter.repeat(64)}`;
const record = (service, releaseSha = sha, imageDigest = digest(service === "backend" ? "a" : service === "worker" ? "b" : service === "rls-executor" ? "c" : "d")) => {
  const repository = service === "worker" ? "mscqr-worker" : "mscqr-backend";
  const tag = service === "backend" || service === "worker" ? releaseSha : `${releaseSha}-${service}`;
  const imageUri = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${repository}:${tag}`;
  return { service, repository, image_uri: imageUri, image_tag: tag, image_digest: imageDigest, image_ref: imageUri.replace(/:[^:@]+$/, `@${imageDigest}`) };
};
const artifact = (records = ["backend", "worker", "rls-executor", "rls-canary"].map((service) => record(service))) => Buffer.from(`${records.map((value) => JSON.stringify(value)).join("\n")}\n`);
const metadata = (overrides = {}) => ({ id: 71, workflow_id: 72, path: ".github/workflows/production-green-stage-b-images.yml", name: "Production Green Stage B Images", event: "workflow_dispatch", head_sha: sha, head_branch: "main", conclusion: "success", ...overrides });

function harness({ artifactBytes = artifact(), metadataOverrides, runId = "71" } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-image-consumer-"));
  const downloadDirectory = path.join(root, "download");
  const outputPath = path.join(root, "evidence.json");
  const githubOutputPath = path.join(root, "github-output");
  const run = (_file, args) => {
    if (args[0] === "run" && args[1] === "download") {
      fs.mkdirSync(path.join(downloadDirectory, "production-green-stage-b-images"), { recursive: true, mode: 0o700 });
      fs.writeFileSync(path.join(downloadDirectory, "production-green-stage-b-images", "stage-b-images.jsonl"), artifactBytes, { mode: 0o600 });
      return "";
    }
    if (args[0] === "api" && args[1].endsWith("/artifacts")) return JSON.stringify({ artifacts: [{ id: 91, name: "production-green-stage-b-images", expired: false }] });
    if (args[0] === "api") return JSON.stringify(metadata(metadataOverrides));
    throw new Error(`Unexpected gh call: ${args.join(" ")}`);
  };
  return { root, downloadDirectory, outputPath, githubOutputPath, run, runId };
}

test("consumes only the exact successful protected-main publication and emits private evidence", () => {
  const originalToken = process.env.GH_TOKEN;
  process.env.GH_TOKEN = "test-token";
  const h = harness();
  try {
    const result = consumeStageBImagePublication({ workflowRunId: h.runId, releaseSha: sha, downloadDirectory: h.downloadDirectory, outputPath: h.outputPath, githubOutputPath: h.githubOutputPath, run: h.run });
    assert.equal(result.manifest.sourceSha, sha);
    assert.equal(result.manifest.toolingSha, sha);
    assert.equal(result.manifest.imageReleaseSha, sha);
    assert.equal(result.images.length, 4);
    assert.equal(fs.statSync(h.outputPath).mode & 0o777, 0o600);
    assert.match(fs.readFileSync(h.githubOutputPath, "utf8"), /backend_image_ref=.*@sha256:/);
  } finally {
    if (originalToken === undefined) delete process.env.GH_TOKEN; else process.env.GH_TOKEN = originalToken;
    fs.rmSync(h.root, { recursive: true, force: true });
  }
});

test("strictly rejects source, workflow, artifact, and digest drift before evidence output", () => {
  for (const metadataOverrides of [
    { head_sha: "b".repeat(40) },
    { head_branch: "feature" },
    { event: "push" },
    { conclusion: "failure" },
    { path: ".github/workflows/release-gate.yml" },
    { name: "Other workflow" },
  ]) {
    const h = harness({ metadataOverrides });
    process.env.GH_TOKEN = "test-token";
    assert.throws(() => consumeStageBImagePublication({ workflowRunId: h.runId, releaseSha: sha, downloadDirectory: h.downloadDirectory, outputPath: h.outputPath, githubOutputPath: h.githubOutputPath, run: h.run }));
    assert.equal(fs.existsSync(h.outputPath), false);
    fs.rmSync(h.root, { recursive: true, force: true });
  }
  const malformed = JSON.parse(artifact().toString("utf8").split("\n")[0]);
  malformed.image_digest = digest("e");
  malformed.image_ref = `${malformed.image_uri}@${digest("a")}`;
  assert.throws(() => parseStageBImagePublicationRecords(artifact([malformed, record("worker"), record("rls-executor"), record("rls-canary")]), { expectedReleaseSha: sha }), /binding/);
});

test("rejects wrong repository, missing run, occupied destination, and non-exact records", () => {
  const h = harness({ artifactBytes: artifact([record("backend"), record("worker"), record("rls-executor"), { ...record("rls-canary"), extra: true }]) });
  process.env.GH_TOKEN = "test-token";
  assert.throws(() => consumeStageBImagePublication({ repository: "other/repo", workflowRunId: h.runId, releaseSha: sha, downloadDirectory: h.downloadDirectory, outputPath: h.outputPath, githubOutputPath: h.githubOutputPath, run: h.run }), /repository/);
  assert.throws(() => consumeStageBImagePublication({ workflowRunId: "", releaseSha: sha, downloadDirectory: h.downloadDirectory, outputPath: h.outputPath, githubOutputPath: h.githubOutputPath, run: h.run }), /run ID/);
  fs.mkdirSync(path.dirname(h.outputPath), { recursive: true });
  fs.writeFileSync(h.outputPath, "occupied", { mode: 0o600 });
  assert.throws(() => consumeStageBImagePublication({ workflowRunId: h.runId, releaseSha: sha, downloadDirectory: h.downloadDirectory, outputPath: h.outputPath, githubOutputPath: h.githubOutputPath, run: h.run }), /overwrite/);
  fs.rmSync(h.root, { recursive: true, force: true });
});

test("release gate consumes publication and cannot publish ECR images", () => {
  const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  assert.match(workflow, /stage_b_image_workflow_run_id/);
  assert.match(workflow, /consume-stage-b-image-publication\.mjs/);
  assert.doesNotMatch(workflow, /amazon-ecr-login|apply-ecr-repository-controls|publish-ecs-images\.sh/);
  const identity = fs.readFileSync("infra/aws/terraform/production-github-actions-identity/main.tf", "utf8");
  assert.doesNotMatch(identity, /ecr:/i);
});
