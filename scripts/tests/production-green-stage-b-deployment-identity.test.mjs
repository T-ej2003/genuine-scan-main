import assert from "node:assert/strict";
import test from "node:test";
import {
  assertStageBDeploymentIdentity,
  assertStageBProtectedMainCheckout,
  assertStageBToolingCheckout,
} from "../aws/stage-b-deployment-identity.mjs";
import { classifyStageBImageReusePath, imageReuseCompatibility, STAGE_B_IMAGE_REUSE_RULES_VERSION } from "../aws/validate-stage-b-image-reuse.mjs";

const toolingSha = "c".repeat(40);
const imageReleaseSha = "a".repeat(40);
const evidenceSha = "b".repeat(64);

const plan = (overrides = {}) => ({
  variables: {
    tooling_sha: { value: toolingSha },
    image_release_sha: { value: imageReleaseSha },
    canonical_image_evidence_sha256: { value: evidenceSha },
    ...overrides,
  },
});

test("two-SHA plan identity joins tooling, image release, and canonical evidence", () => {
  assert.deepEqual(assertStageBDeploymentIdentity({
    plan: plan(),
    expectedToolingSha: toolingSha,
    expectedImageReleaseSha: imageReleaseSha,
    expectedCanonicalImageEvidenceSha256: evidenceSha,
    imageEvidence: { imageReleaseSha },
  }), { toolingSha, imageReleaseSha, canonicalImageEvidenceSha256: evidenceSha });
});

test("image evidence does not require toolingSha", () => {
  assert.doesNotThrow(() => assertStageBDeploymentIdentity({ plan: plan(), imageEvidence: { imageReleaseSha } }));
});

test("legacy single release identity and missing joins fail closed", () => {
  assert.throws(() => assertStageBDeploymentIdentity({ plan: { variables: { release_sha: { value: imageReleaseSha } } } }), /tooling_sha/);
  assert.throws(() => assertStageBDeploymentIdentity({ plan: plan({ image_release_sha: { value: toolingSha } }), imageEvidence: { imageReleaseSha } }), /image_release_sha/);
  assert.throws(() => assertStageBDeploymentIdentity({ plan: plan({ canonical_image_evidence_sha256: { value: "d".repeat(64) } }), expectedCanonicalImageEvidenceSha256: evidenceSha }), /canonical image-evidence/);
});

test("tooling checkout must equal the plan tooling identity", () => {
  const cleanMain = { originMainHead: toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false } };
  assert.doesNotThrow(() => assertStageBToolingCheckout(toolingSha, toolingSha, cleanMain));
  assert.throws(() => assertStageBToolingCheckout(toolingSha, imageReleaseSha), /tooling HEAD/);
});

test("protected-main checkout is exact, complete, and clean", () => {
  const valid = { toolingSha, currentHead: toolingSha, originMainHead: toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false } };
  assert.doesNotThrow(() => assertStageBProtectedMainCheckout(valid));
  for (const [field, value, error] of [
    ["originMainHead", imageReleaseSha, /origin\/main/],
    ["isAncestor", false, /ancestry/],
    ["porcelainStatus", " M tracked", /tracked modifications/],
    ["porcelainStatus", "?? untracked", /untracked/],
  ]) assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, [field]: value }), error);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, shallow: true } }), /shallow/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, mergeInProgress: true } }), /merge/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, rebaseInProgress: true } }), /rebase/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, cherryPickInProgress: true } }), /cherry-pick/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, repositoryState: { ...valid.repositoryState, remoteDefaultBranch: "develop" } }), /default branch/);
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, originMainHead: undefined }), /unavailable/);
  assert.doesNotThrow(() => assertStageBProtectedMainCheckout({ ...valid, originMainHead: imageReleaseSha, mode: "review" }));
  assert.throws(() => assertStageBProtectedMainCheckout({ ...valid, mode: "unsupported" }), /mode/);
});

test("image reuse compatibility binds the reviewed tooling input tree and exact classification", () => {
  assert.equal(classifyStageBImageReusePath("scripts/aws/production-green-stage-b-image-evidence.mjs").imageAffecting, false);
  assert.equal(classifyStageBImageReusePath("backend/src/index.ts").imageAffecting, true);
  for (const file of ["Dockerfile", "backend/package-lock.json", "package-lock.json", "scripts/rls/sql/generated/policy.sql", "unknown/runtime-input.bin"]) assert.equal(classifyStageBImageReusePath(file).imageAffecting, true);
  assert.equal(classifyStageBImageReusePath("documents/security/rls-program/notes.md").imageAffecting, false);
  const changedFiles = ["scripts/plan-production-green-stage-b.mjs"];
  const classifiedChangedFiles = [{ file: changedFiles[0], category: "toolingOnly", imageAffecting: false }];
  const report = { schemaVersion: 2, imageReleaseSha, comparisonBaseSha: imageReleaseSha, comparisonHeadIdentity: "tooling-input-tree-sha256", toolingInputTreeSha256: "d".repeat(64), comparisonHeadSha256: "d".repeat(64), classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION, classifiedChangedFiles, imageReuseCompatible: true };
  assert.equal(imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: report }).imageReuseCompatible, true);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, imageReleaseSha: toolingSha } }), /different image release/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "e".repeat(64), reviewedReport: report }), /different tooling input tree/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, comparisonBaseSha: toolingSha } }), /comparison base/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, classificationRulesVersion: "old" } }), /classification rules/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: { ...report, classifiedChangedFiles: [] } }), /classification/);
  assert.throws(() => imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles: ["backend/src/index.ts"], currentHead: toolingSha, toolingInputTreeSha256: "d".repeat(64), reviewedReport: report }), /classification/);
});
