import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  assertStageBDeploymentIdentity,
  assertStageBToolingCheckout,
} from "../aws/stage-b-deployment-identity.mjs";
import { classifyStageBImageReusePath, imageReuseCompatibility } from "../aws/validate-stage-b-image-reuse.mjs";

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
  assert.doesNotThrow(() => assertStageBToolingCheckout(toolingSha, toolingSha));
  assert.throws(() => assertStageBToolingCheckout(toolingSha, imageReleaseSha), /checked-out tooling HEAD/);
});

test("image reuse compatibility fails closed for image inputs and permits tooling-only changes", () => {
  const report = JSON.parse(fs.readFileSync(path.resolve("documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json"), "utf8"));
  assert.equal(classifyStageBImageReusePath("scripts/aws/production-green-stage-b-image-evidence.mjs").imageAffecting, false);
  assert.equal(classifyStageBImageReusePath("backend/src/index.ts").imageAffecting, true);
  for (const file of ["Dockerfile", "backend/package-lock.json", "package-lock.json", "scripts/rls/sql/generated/policy.sql", "unknown/runtime-input.bin"]) assert.equal(classifyStageBImageReusePath(file).imageAffecting, true);
  assert.equal(classifyStageBImageReusePath("documents/security/rls-program/notes.md").imageAffecting, false);
  assert.equal(imageReuseCompatibility({ imageReleaseSha: report.imageReleaseSha, toolingSha: report.toolingSha, changedFiles: ["scripts/plan-production-green-stage-b.mjs"], currentHead: report.toolingSha, reviewedReport: report }).imageReuseCompatible, true);
  assert.equal(imageReuseCompatibility({ imageReleaseSha: report.imageReleaseSha, toolingSha: report.toolingSha, changedFiles: ["backend/src/index.ts"], currentHead: report.toolingSha, reviewedReport: report }).imageReuseCompatible, false);
});
