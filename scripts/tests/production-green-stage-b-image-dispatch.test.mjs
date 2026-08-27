import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import os from "node:os";
import path from "node:path";
import { assertObservedStageBImagePublicationMetadata, dispatchProductionGreenStageBImages, observeStageBImagePublication, writeObservedStageBImagePublicationIdentity, STAGE_B_IMAGE_ARTIFACT_FILE, STAGE_B_IMAGE_ARTIFACT_NAME, STAGE_B_IMAGE_WORKFLOW, STAGE_B_IMAGE_WORKFLOW_NAME } from "../aws/dispatch-production-green-stage-b-images.mjs";

const sha = "a".repeat(40);
const dispatcher = yaml.load(fs.readFileSync(".github/workflows/production-green-stage-b-images.yml", "utf8"));
const reusable = yaml.load(fs.readFileSync(".github/workflows/production-green-stage-b-image-build.yml", "utf8"));
const mockGh = (calls, { commitExists = true } = {}) => (file, args) => {
  calls.push(args);
  if (args[0] === "api" && !commitExists) throw new Error("release commit not found");
  return args[0] === "repo" ? "T-ej2003/genuine-scan-main\n" : "";
};

test("dispatcher uses protected main as workflow source and passes release SHA separately", () => {
  const calls = [];
  const result = dispatchProductionGreenStageBImages({ releaseSha: sha, run: mockGh(calls) });
  assert.deepEqual(result, { repository: "T-ej2003/genuine-scan-main", workflow: STAGE_B_IMAGE_WORKFLOW, workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, workflowRef: "main", artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactFile: STAGE_B_IMAGE_ARTIFACT_FILE, releaseSha: sha });
  assert.deepEqual(calls, [
    ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
    ["api", "repos/T-ej2003/genuine-scan-main/commits/" + sha],
    ["workflow", "run", "production-green-stage-b-images.yml", "--repo", "T-ej2003/genuine-scan-main", "--ref", "main", "-f", `release_sha=${sha}`],
  ]);
});

test("Stage B selection validates observed workflow and artifact identity", () => {
  const observed = { workflowRunId: "7", workflowDatabaseId: "8", workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, event: "workflow_dispatch", workflowDefinitionSha: sha, imageReleaseSha: sha, headBranch: "main", conclusion: "success", artifactId: "9", artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactExpired: false, artifactArchiveFilename: null };
  assert.doesNotThrow(() => assertObservedStageBImagePublicationMetadata(observed, { expectedPublicationSourceSha: sha, expectedReleaseSha: sha }));
  for (const change of [{ workflowFile: ".github/workflows/production-green-backend-image-publish.yml" }, { workflowName: "Production Green Backend Image Publish" }, { event: "push" }, { workflowDefinitionSha: "b".repeat(40) }, { imageReleaseSha: "b".repeat(40) }, { conclusion: "failure" }, { artifactName: "production-green-backend-image-evidence" }, { artifactExpired: true }]) assert.throws(() => assertObservedStageBImagePublicationMetadata({ ...observed, ...change }, { expectedPublicationSourceSha: sha, expectedReleaseSha: sha }));
  assert.throws(() => assertObservedStageBImagePublicationMetadata(undefined, { expectedPublicationSourceSha: sha, expectedReleaseSha: sha }), /required/);
  assert.throws(() => assertObservedStageBImagePublicationMetadata({ ...observed, workflowDefinitionSha: "b".repeat(40) }, { expectedPublicationSourceSha: sha, expectedReleaseSha: sha }), /publication source/);
});

test("two-SHA publication binds workflow definition to tooling and image artifact to release", () => {
  const releaseSha = "b".repeat(40);
  const observed = { workflowRunId: "7", workflowDatabaseId: "8", workflowFile: ".github/workflows/production-green-stage-b-images.yml", workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, event: "workflow_dispatch", workflowDefinitionSha: sha, imageReleaseSha: releaseSha, headBranch: "main", conclusion: "success", artifactId: "9", artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactExpired: false, artifactArchiveFilename: null };
  assert.doesNotThrow(() => assertObservedStageBImagePublicationMetadata(observed, { expectedPublicationSourceSha: sha, expectedReleaseSha: releaseSha }));
  assert.throws(() => assertObservedStageBImagePublicationMetadata(observed, { expectedPublicationSourceSha: "c".repeat(40), expectedReleaseSha: releaseSha }), /publication source/);
  assert.throws(() => assertObservedStageBImagePublicationMetadata(observed, { expectedPublicationSourceSha: sha, expectedReleaseSha: "c".repeat(40) }), /release/);
});

test("dispatcher observes the exact successful run and single artifact from GitHub metadata", () => {
  const artifact = { id: 9, name: STAGE_B_IMAGE_ARTIFACT_NAME, expired: false };
  const calls = [];
  const run = (file, args) => { calls.push(args); return args[1].endsWith("/artifacts") ? JSON.stringify({ artifacts: [artifact] }) : JSON.stringify({ id: 7, workflow_id: 8, path: ".github/workflows/production-green-stage-b-images.yml", name: STAGE_B_IMAGE_WORKFLOW_NAME, event: "workflow_dispatch", head_sha: sha, head_branch: "main", conclusion: "success" }); };
  const observed = observeStageBImagePublication({ repository: "T-ej2003/genuine-scan-main", workflowRunId: "7", publicationSourceSha: sha, releaseSha: sha, run });
  assert.equal(observed.artifactId, "9");
  assert.deepEqual(calls, [["api", "repos/T-ej2003/genuine-scan-main/actions/runs/7"], ["api", "repos/T-ej2003/genuine-scan-main/actions/runs/7/artifacts"]]);
  assert.throws(() => observeStageBImagePublication({ repository: "repo", workflowRunId: "7", publicationSourceSha: sha, releaseSha: sha, run: () => JSON.stringify({ id: 7, workflow_id: 8, path: ".github/workflows/production-green-stage-b-images.yml", name: STAGE_B_IMAGE_WORKFLOW_NAME, event: "workflow_dispatch", head_sha: sha, head_branch: "main", conclusion: "success" }) }), /exactly one matching/);
});

test("dispatcher writes private identity bound to the observed artifact bytes", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-publication-identity-"));
  const artifactPath = path.join(root, "stage-b-images.jsonl");
  const identityPath = path.join(root, "stage-b-image-publication-identity.json");
  const records = ["backend", "worker", "rls-executor", "rls-canary"].map((service) => JSON.stringify({ service }));
  fs.writeFileSync(artifactPath, `${records.join("\n")}\n`, { mode: 0o600 });
  const run = (file, args) => args[1].endsWith("/artifacts") ? JSON.stringify({ artifacts: [{ id: 9, name: STAGE_B_IMAGE_ARTIFACT_NAME, expired: false }] }) : JSON.stringify({ id: 7, workflow_id: 8, path: ".github/workflows/production-green-stage-b-images.yml", name: STAGE_B_IMAGE_WORKFLOW_NAME, event: "workflow_dispatch", head_sha: sha, head_branch: "main", conclusion: "success" });
  const result = writeObservedStageBImagePublicationIdentity({ repository: "T-ej2003/genuine-scan-main", workflowRunId: "7", publicationSourceSha: sha, releaseSha: sha, canonicalArtifactPath: artifactPath, outputPath: identityPath, repositoryRoot: process.cwd(), run });
  assert.equal(result.identity.recordCount, 4);
  assert.equal(fs.statSync(identityPath).mode & 0o777, 0o600);
  fs.rmSync(root, { recursive: true, force: true });
});

test("dispatcher rejects malformed and commit-valued workflow refs", () => {
  assert.throws(() => dispatchProductionGreenStageBImages({ releaseSha: sha.slice(0, 12), run: mockGh([]) }), /40-character/);
  assert.throws(() => dispatchProductionGreenStageBImages({ releaseSha: sha, workflowRef: sha, run: mockGh([]) }), /dispatched from main/);
  assert.throws(() => dispatchProductionGreenStageBImages({ releaseSha: sha, workflowRef: "release-candidate", run: mockGh([]) }), /dispatched from main/);
});

test("dispatcher rejects a nonexistent release commit before dispatch", () => {
  const calls = [];
  assert.throws(() => dispatchProductionGreenStageBImages({ releaseSha: sha, run: mockGh(calls, { commitExists: false }) }), /not found/);
  assert.deepEqual(calls.map((args) => args[0]), ["repo", "api"]);
});

test("workflow source and release source stay separate even if main advances after dispatch", () => {
  assert.equal(dispatcher.jobs["verify-release"].steps[0].env.EXPECTED_WORKFLOW_REF, "refs/heads/main");
  const dispatcherTooling = dispatcher.jobs["verify-release"].steps.find((step) => step.name === "Checkout trusted workflow tooling");
  const dispatcherRelease = dispatcher.jobs["verify-release"].steps.find((step) => step.uses === "actions/checkout@v6" && step.with?.path === "release-source");
  assert.equal(dispatcherTooling.with.ref, "${{ github.sha }}");
  assert.equal(dispatcherRelease.with.ref, "${{ inputs.release_sha }}");
  assert.equal(dispatcherRelease.with.path, "release-source");
  assert.match(dispatcher.jobs["verify-release"].steps.find((step) => step.name === "Bind the trusted workflow tooling revision").run, /rev-parse FETCH_HEAD/);
  assert.doesNotMatch(`${JSON.stringify(dispatcher)}${JSON.stringify(reusable)}`, /inputs\.tooling|inputs\.workflow/);
  assert.equal(reusable.jobs["build-and-attest"].steps[0].env.EXPECTED_WORKFLOW_REF, "refs/heads/main");
  const reusableTooling = reusable.jobs["build-and-attest"].steps.find((step) => step.name === "Checkout trusted workflow tooling");
  const reusableRelease = reusable.jobs["build-and-attest"].steps.find((step) => step.uses === "actions/checkout@v6" && step.with?.path === "release-source");
  assert.equal(reusableTooling.with.ref, "${{ github.sha }}");
  assert.equal(reusableRelease.with.ref, "${{ inputs.release_sha }}");
  assert.equal(reusableRelease.with.path, "release-source");
  assert.match(JSON.stringify(reusable), /checkoutSha/);
  assert.match(JSON.stringify(reusable), /workflowDefinitionRef/);
  assert.match(JSON.stringify(reusable), /workflowDefinitionSha/);
  assert.match(JSON.stringify(reusable), /workflowRunId/);
  const calls = [];
  dispatchProductionGreenStageBImages({ releaseSha: sha, run: mockGh(calls) });
  assert.equal(calls.at(-1).at(-1), `release_sha=${sha}`);
  assert.equal(calls.at(-1)[6], "main");
});

test("an older merged release may predate tooling while the trusted helper remains available", () => {
  const dispatcherTooling = dispatcher.jobs["verify-release"].steps.find((step) => step.name === "Checkout trusted workflow tooling");
  const dispatcherRelease = dispatcher.jobs["verify-release"].steps.find((step) => step.uses === "actions/checkout@v6" && step.with?.path === "release-source");
  const toolingCheckout = reusable.jobs["build-and-attest"].steps.find((step) => step.name === "Checkout trusted workflow tooling");
  const releaseCheckout = reusable.jobs["build-and-attest"].steps.find((step) => step.uses === "actions/checkout@v6" && step.with?.path === "release-source");
  const signRun = reusable.jobs["build-and-attest"].steps.find((step) => step.name === "Generate SBOMs, sign, and attest provenance").run;
  assert.equal(toolingCheckout.with.ref, "${{ github.sha }}");
  assert.equal(releaseCheckout.with.ref, "${{ inputs.release_sha }}");
  assert.equal(dispatcherTooling.with.ref, "${{ github.sha }}");
  assert.equal(dispatcherRelease.with.ref, "${{ inputs.release_sha }}");
  assert.match(signRun, /\$GITHUB_WORKSPACE\/scripts\/aws\/cosign-idempotent-sign-and-attest\.sh/);
  assert.doesNotMatch(signRun, /release-source\/scripts\/aws\/cosign-idempotent-sign-and-attest\.sh/);
});
