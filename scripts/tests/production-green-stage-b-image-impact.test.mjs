import assert from "node:assert/strict";
import test from "node:test";
import {
  assertImageImpactReport,
  assertProductionImageReuseResult,
  computeStageBToolingInputTreeSha256,
  imageImpactReportFor,
  imageReuseCompatibility,
  classifyStageBImageReusePath,
  parseStageBImageReuseCliArgs,
  parseStageBClosureMode,
  STAGE_B_IMAGE_REUSE_RULES_VERSION,
} from "../aws/validate-stage-b-image-reuse.mjs";

const imageReleaseSha = "a".repeat(40);
const toolingSha = "b".repeat(40);
const toolingInputTreeSha256 = "c".repeat(64);
const compatibilityReport = (classifiedChangedFiles) => ({
  schemaVersion: 2,
  imageReleaseSha,
  comparisonBaseSha: imageReleaseSha,
  comparisonHeadIdentity: "tooling-input-tree-sha256",
  toolingInputTreeSha256,
  comparisonHeadSha256: toolingInputTreeSha256,
  classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION,
  classifiedChangedFiles,
  imageReuseCompatible: true,
});

test("non-image-affecting pull-request impact is merge-ready for reviewed reuse", () => {
  const report = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["scripts/plan-production-green-stage-b.mjs"] });
  assert.equal(report.status, "merge-ready-reuse-compatible");
  assert.equal(report.imageReuseCompatible, true);
  assert.equal(report.newImagesRequired, false);
  assert.equal(report.deploymentAuthorized, false);
});

test("package-lock image impact is merge-ready but requires fresh protected-main images", () => {
  const report = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["package-lock.json"] });
  assert.deepEqual(report.imageAffectingFiles, ["package-lock.json"]);
  assert.equal(report.status, "merge-ready-new-images-required");
  assert.equal(report.imageReuseCompatible, false);
  assert.equal(report.newImagesRequired, true);
  assert.equal(report.deploymentAuthorized, false);
});

test("Stage A Terraform changes are classified as infrastructure-only without image rebuild", () => {
  const file = "infra/aws/terraform/production-green-stage-a/main.tf";
  assert.deepEqual(classifyStageBImageReusePath(file), { file, category: "terraformOnly", imageAffecting: false });
  const report = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: [file] });
  assert.deepEqual(report.imageAffectingFiles, []);
  assert.equal(report.imageReuseCompatible, true);
  assert.equal(report.newImagesRequired, false);
});

test("Terraform classification stays bounded and runtime image behavior remains fail-closed", () => {
  const stageB = "infra/aws/terraform/production-green-stage-b/main.tf";
  assert.equal(classifyStageBImageReusePath(stageB).category, "terraformOnly");
  assert.equal(classifyStageBImageReusePath("infra/aws/terraform/unrelated/main.tf").category, "unknown");

  const backend = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["backend/src/app.ts"] });
  assert.deepEqual(backend.imageAffectingFiles, ["backend/src/app.ts"]);
  assert.equal(backend.newImagesRequired, true);
  assert.throws(() => imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["frontend/src/App.tsx"] }), /unclassified/);
});

test("rotation evidence schema is canonical tooling-only input", () => {
  const file = ".security/rotation-evidence.schema.json";
  assert.deepEqual(classifyStageBImageReusePath(file), { file, category: "toolingOnly", imageAffecting: false });
  const report = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: [file] });
  assert.deepEqual(report.imageAffectingFiles, []);
  assert.equal(report.imageReuseCompatible, true);
});

test("the Gitleaks baseline is tooling-only while unknown paths remain fail-closed", () => {
  const files = [".gitleaks-baseline.json", ".gitleaksignore"];
  for (const file of files) assert.deepEqual(classifyStageBImageReusePath(file), { file, category: "toolingOnly", imageAffecting: false });
  const report = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: files });
  assert.deepEqual(report.imageAffectingFiles, []);
  assert.equal(report.imageReuseCompatible, true);
  assert.throws(() => imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["unknown/security-scan-output.bin"] }), /unclassified/);
});

test("false compatibility and unknown classification fail closed", () => {
  const report = imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["package-lock.json"] });
  assert.throws(() => assertImageImpactReport({ report: { ...report, imageReuseCompatible: true }, imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["package-lock.json"] }), /stale, incomplete, or falsely compatible/);
  assert.throws(() => imageImpactReportFor({ imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["unknown/runtime.bin"] }), /unclassified/);
});

test("production image reuse accepts only an exact compatible reviewed result", () => {
  const files = [{ file: "scripts/plan-production-green-stage-b.mjs", category: "toolingOnly", imageAffecting: false }];
  const result = imageReuseCompatibility({ imageReleaseSha, toolingSha, toolingInputTreeSha256, currentHead: toolingSha, changedFiles: files, reviewedReport: compatibilityReport(files) });
  assert.equal(assertProductionImageReuseResult(result), result);
  assert.throws(() => assertProductionImageReuseResult({ imageReuseCompatible: false, imageBuildInputsChanged: true, imageAffectingFiles: ["package-lock.json"] }), /unsafe/);
});

test("closure mode is mandatory and explicit", () => {
  assert.equal(parseStageBClosureMode(["--mode", "pull-request"]), "pull-request");
  assert.equal(parseStageBClosureMode(["--mode", "production"]), "production");
  assert.throws(() => parseStageBClosureMode([]), /requires --mode/);
  assert.throws(() => parseStageBClosureMode(["--mode", "unknown"]), /Unsupported/);
});

test("image-reuse CLI keeps boolean options out of SHA positionals", () => {
  const imageReleaseSha = "a".repeat(40);
  const toolingSha = "b".repeat(40);
  assert.deepEqual(parseStageBImageReuseCliArgs(["--mode", "production", "--write-reviewed-report"]), {
    mode: "production",
    positionals: [],
    writeReviewedReport: true,
    writeImageImpactReport: false,
  });
  assert.deepEqual(parseStageBImageReuseCliArgs(["--write-reviewed-report", "--mode", "production"]), {
    mode: "production",
    positionals: [],
    writeReviewedReport: true,
    writeImageImpactReport: false,
  });
  assert.deepEqual(parseStageBImageReuseCliArgs(["--mode", "production", imageReleaseSha, "--write-reviewed-report", toolingSha]), {
    mode: "production",
    positionals: [imageReleaseSha, toolingSha],
    writeReviewedReport: true,
    writeImageImpactReport: false,
  });
  assert.deepEqual(parseStageBImageReuseCliArgs(["--mode", "production"]), {
    mode: "production",
    positionals: [],
    writeReviewedReport: false,
    writeImageImpactReport: false,
  });
  assert.throws(() => parseStageBImageReuseCliArgs(["--mode", "production", "--write-reviewd-report"]), /Unknown option/);
  assert.throws(() => parseStageBImageReuseCliArgs(["--mode", "production", "--totally-unknown"]), /Unknown option/);
  assert.throws(() => parseStageBImageReuseCliArgs(["--mode", "production", imageReleaseSha, toolingSha, "garbage"]), /at most/);
  assert.throws(() => parseStageBImageReuseCliArgs(["--mode", "production", "not-a-sha"]), /SHA positional is invalid/);
  assert.throws(() => parseStageBImageReuseCliArgs(["--mode", "production", "g".repeat(40)]), /SHA positional is invalid/);
});

test("image-impact report generation is deterministic and exact", () => {
  const args = { imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles: ["package-lock.json", "scripts/a.mjs"] };
  const first = imageImpactReportFor(args);
  const second = imageImpactReportFor(args);
  assert.deepEqual(first, second);
  assert.doesNotThrow(() => assertImageImpactReport({ report: first, ...args }));
});

test("tooling input digest excludes both compatibility evidence artifacts but detects real tooling changes", () => {
  const evidenceJson = "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json";
  const evidenceMarkdown = "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.md";
  const toolingInput = "scripts/plan-production-green-stage-b.mjs";
  const files = [evidenceJson, evidenceMarkdown, toolingInput];
  const digest = (contents) => computeStageBToolingInputTreeSha256({
    files,
    readFile: (file) => contents[file],
  });
  const baseline = digest({ [evidenceJson]: "json-a", [evidenceMarkdown]: "markdown-a", [toolingInput]: "tooling-a" });
  assert.equal(digest({ [evidenceJson]: "json-b", [evidenceMarkdown]: "markdown-a", [toolingInput]: "tooling-a" }), baseline);
  assert.equal(digest({ [evidenceJson]: "json-a", [evidenceMarkdown]: "markdown-b", [toolingInput]: "tooling-a" }), baseline);
  assert.equal(digest({ [evidenceJson]: "json-b", [evidenceMarkdown]: "markdown-b", [toolingInput]: "tooling-a" }), baseline);
  assert.notEqual(digest({ [evidenceJson]: "json-a", [evidenceMarkdown]: "markdown-a", [toolingInput]: "tooling-b" }), baseline);
});
