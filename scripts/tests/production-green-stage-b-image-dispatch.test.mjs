import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { assertStageBImagePublicationIdentity, dispatchProductionGreenStageBImages, STAGE_B_IMAGE_ARTIFACT_FILE, STAGE_B_IMAGE_ARTIFACT_NAME, STAGE_B_IMAGE_WORKFLOW, STAGE_B_IMAGE_WORKFLOW_NAME } from "../aws/dispatch-production-green-stage-b-images.mjs";

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
  assert.deepEqual(result, { repository: "T-ej2003/genuine-scan-main", workflow: STAGE_B_IMAGE_WORKFLOW, workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, workflowRef: "main", artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactFile: STAGE_B_IMAGE_ARTIFACT_FILE, releaseSha: sha });
  assert.deepEqual(calls, [
    ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
    ["api", "repos/T-ej2003/genuine-scan-main/commits/" + sha],
    ["workflow", "run", "production-green-stage-b-images.yml", "--repo", "T-ej2003/genuine-scan-main", "--ref", "main", "-f", `release_sha=${sha}`],
  ]);
});

test("Stage B selection records and rejects publisher identity mismatches", () => {
  assert.doesNotThrow(() => assertStageBImagePublicationIdentity({ workflow: STAGE_B_IMAGE_WORKFLOW, workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactFile: STAGE_B_IMAGE_ARTIFACT_FILE }));
  assert.throws(() => assertStageBImagePublicationIdentity({ workflow: "production-green-backend-image-publish.yml", workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, artifactName: STAGE_B_IMAGE_ARTIFACT_NAME, artifactFile: STAGE_B_IMAGE_ARTIFACT_FILE }), /four-image workflow/);
  assert.throws(() => assertStageBImagePublicationIdentity({ workflow: STAGE_B_IMAGE_WORKFLOW, workflowName: STAGE_B_IMAGE_WORKFLOW_NAME, artifactName: "production-green-backend-image-evidence", artifactFile: STAGE_B_IMAGE_ARTIFACT_FILE }), /four-image workflow/);
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
  assert.equal(dispatcher.jobs["verify-release"].steps[1].with.ref, "${{ inputs.release_sha }}");
  assert.equal(reusable.jobs["build-and-attest"].steps[0].env.EXPECTED_WORKFLOW_REF, "refs/heads/main");
  assert.equal(reusable.jobs["build-and-attest"].steps[1].with.ref, "${{ inputs.release_sha }}");
  assert.match(JSON.stringify(reusable), /checkoutSha/);
  assert.match(JSON.stringify(reusable), /workflowDefinitionRef/);
  assert.match(JSON.stringify(reusable), /workflowDefinitionSha/);
  assert.match(JSON.stringify(reusable), /workflowRunId/);
  const calls = [];
  dispatchProductionGreenStageBImages({ releaseSha: sha, run: mockGh(calls) });
  assert.equal(calls.at(-1).at(-1), `release_sha=${sha}`);
  assert.equal(calls.at(-1)[6], "main");
});
