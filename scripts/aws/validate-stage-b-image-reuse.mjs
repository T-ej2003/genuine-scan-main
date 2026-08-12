import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBProtectedMainCheckout, buildStageBProtectedMainCheckoutEvidence, readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const STAGE_B_IMAGE_REUSE_SCHEMA_VERSION = 2;
export const STAGE_B_IMAGE_REUSE_RULES_VERSION = "stage-b-image-reuse-v2";
export const COMPATIBILITY_REPORT_REPO_PATH = "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json";
export const STAGE_B_IMAGE_IMPACT_SCHEMA_VERSION = 1;
export const IMAGE_IMPACT_REPORT_REPO_PATH = "documents/ops/iam/MSCQRProductionGreenStageBImageImpact-v1.json";
export const STAGE_B_CLOSURE_MODES = ["pull-request", "production"];
const TOOLING_TREE_EVIDENCE_PATHS = new Set([COMPATIBILITY_REPORT_REPO_PATH, "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.md", IMAGE_IMPACT_REPORT_REPO_PATH]);
const SHA = /^[a-f0-9]{40}$/;

const IMAGE_INPUTS = [
  /^\.github\/workflows\/production-green-stage-b-image-build\.yml$/,
  /(^|\/)Dockerfile(?:\.|$)/,
  /(^|\/)(?:\.dockerignore|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/,
  /^backend\//,
  /^shared\//,
  /^scripts\/aws\/(?:production-green-stage-b-contract|publish-ecs-images|verify-image-manifest|stage-b-image-bindings)\./,
  /^scripts\/(?:smoke-release|lib\/staging-smoke-totp)\./,
  /^scripts\/rls\/sql\/generated\//,
  /^documents\/security\/rls-program\/generated\//,
  /^documents\/security\/mscqr_.*\.sql$/,
];
const DOCUMENTATION = /(?:^|\/)(?:documents|README|CHANGELOG|.*\.md)(?:\/|$)/;
const CI = /^\.github\/workflows\//;
const TERRAFORM = /^infra\/aws\/terraform\/production-green-stage-(?:a|b)\//;
const CONTROL_PLANE = /^infra\/aws\/terraform\/lambda\/production-rls-approval-broker\/(?:index\.mjs|package\.json|package-lock\.json)$/;
const TEST = /(?:^|\/)(?:tests?|fixtures)(?:\/|\.)|\.test\.[^.]+$/;
const TOOLING_ONLY = new Set([".gitleaks-baseline.json", ".gitleaksignore", ".security/rotation-evidence.schema.json"]);

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export function classifyStageBImageReusePath(file) {
  if (CONTROL_PLANE.test(file)) return { file, category: "controlPlaneOnly", imageAffecting: false };
  if (IMAGE_INPUTS.some((pattern) => pattern.test(file))) {
    const category = /package-lock|lock$/.test(file) ? "dependencyLockfile" : /Dockerfile|dockerignore|workflow.*image-build/.test(file) ? "dockerBuildConfiguration" : /^backend\//.test(file) || /^shared\//.test(file) ? "runtimeApplicationSource" : /generated/.test(file) ? "generatedRuntimePackage" : "imageBuildInput";
    return { file, category, imageAffecting: true };
  }
  if (TERRAFORM.test(file)) return { file, category: "terraformOnly", imageAffecting: false };
  if (CI.test(file)) return { file, category: "ciOnly", imageAffecting: false };
  if (DOCUMENTATION.test(file)) return { file, category: "documentationOnly", imageAffecting: false };
  if (TEST.test(file)) return { file, category: "testOnly", imageAffecting: false };
  if (/^scripts\//.test(file) || /^documents\/ops\//.test(file) || /^documents\/security\/rls-program\//.test(file) || /^package\.json$/.test(file) || TOOLING_ONLY.has(file)) {
    return { file, category: "toolingOnly", imageAffecting: false };
  }
  return { file, category: "unknown", imageAffecting: true };
}

function normalizeClassifiedFiles(files) {
  return files.map((entry) => typeof entry === "string" ? classifyStageBImageReusePath(entry) : entry)
    .map(({ file, category, imageAffecting }) => ({ file, category, imageAffecting: Boolean(imageAffecting) }))
    .sort((left, right) => left.file.localeCompare(right.file));
}

export function computeStageBToolingInputTreeSha256({ files, readFile, blobSha256 }) {
  const entries = files.filter((file) => !TOOLING_TREE_EVIDENCE_PATHS.has(file)).sort().map((file) => ({ file, sha256: blobSha256 ? blobSha256(file) : sha256(readFile(file)) }));
  return sha256(Buffer.from(canonicalJson(entries)));
}

function assertReviewedReport({ reviewedReport, imageReleaseSha, toolingInputTreeSha256, changedFiles }) {
  assert.equal(reviewedReport?.schemaVersion, STAGE_B_IMAGE_REUSE_SCHEMA_VERSION, "Compatibility report schema is unsupported.");
  assert.equal(reviewedReport.imageReleaseSha, imageReleaseSha, "Compatibility report is for a different image release SHA.");
  assert.equal(reviewedReport.comparisonBaseSha, imageReleaseSha, "Compatibility report comparison base does not match the image release SHA.");
  assert.equal(reviewedReport.comparisonHeadIdentity, "tooling-input-tree-sha256", "Compatibility report comparison head identity is unsupported.");
  assert.equal(reviewedReport.toolingInputTreeSha256, toolingInputTreeSha256, "Compatibility report is for a different tooling input tree.");
  assert.equal(reviewedReport.comparisonHeadSha256, toolingInputTreeSha256, "Compatibility report comparison head does not match the tooling input tree.");
  assert.equal(reviewedReport.classificationRulesVersion, STAGE_B_IMAGE_REUSE_RULES_VERSION, "Compatibility report classification rules are stale.");
  assert.deepEqual(reviewedReport.classifiedChangedFiles, normalizeClassifiedFiles(changedFiles), "Compatibility report changed-file classification is stale or incomplete.");
  assert.equal(reviewedReport.imageReuseCompatible, !reviewedReport.classifiedChangedFiles.some(({ imageAffecting }) => imageAffecting), "Compatibility report compatibility result is inconsistent.");
}

export function imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead, reviewedReport, toolingInputTreeSha256 }) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  if (currentHead !== undefined) assert.equal(currentHead, toolingSha, "Tooling SHA must equal the checked-out tooling HEAD.");
  const classifiedChangedFiles = normalizeClassifiedFiles(changedFiles);
  const unclassifiedFiles = classifiedChangedFiles.filter(({ category }) => category === "unknown").map(({ file }) => file);
  assert.equal(unclassifiedFiles.length, 0, `Stage B image-impact report contains unclassified files: ${unclassifiedFiles.join(", ")}`);
  const imageAffectingFiles = classifiedChangedFiles.filter(({ imageAffecting }) => imageAffecting).map(({ file }) => file);
  assertReviewedReport({ reviewedReport, imageReleaseSha, toolingInputTreeSha256, changedFiles: classifiedChangedFiles });
  return {
    schemaVersion: STAGE_B_IMAGE_REUSE_SCHEMA_VERSION,
    imageReleaseSha,
    toolingSha,
    toolingInputTreeSha256,
    comparisonBaseSha: imageReleaseSha,
    comparisonHeadSha256: toolingInputTreeSha256,
    classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION,
    imageReuseCompatible: imageAffectingFiles.length === 0,
    imageBuildInputsChanged: imageAffectingFiles.length > 0,
    classifiedChangedFiles,
    imageAffectingFiles,
    reportMatchesRecomputedDiff: true,
  };
}

export function imageImpactReportFor({ imageReleaseSha, toolingSha, changedFiles, toolingInputTreeSha256 }) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  const classifiedChangedFiles = normalizeClassifiedFiles(changedFiles);
  const unclassifiedFiles = classifiedChangedFiles.filter(({ category }) => category === "unknown").map(({ file }) => file);
  assert.equal(unclassifiedFiles.length, 0, `Stage B image-impact report contains unclassified files: ${unclassifiedFiles.join(", ")}`);
  const imageAffectingFiles = classifiedChangedFiles.filter(({ imageAffecting }) => imageAffecting).map(({ file }) => file);
  const newImagesRequired = imageAffectingFiles.length > 0;
  return {
    schemaVersion: STAGE_B_IMAGE_IMPACT_SCHEMA_VERSION,
    identityModel: "tooling-input-tree-sha256",
    imageReleaseSha,
    comparisonBaseSha: imageReleaseSha,
    toolingSha,
    toolingInputTreeSha256,
    comparisonHeadIdentity: "tooling-input-tree-sha256",
    comparisonHeadSha256: toolingInputTreeSha256,
    classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION,
    classifiedChangedFiles,
    imageAffectingFiles,
    imageReuseCompatible: !newImagesRequired,
    newImagesRequired,
    deploymentAuthorized: false,
    status: newImagesRequired ? "merge-ready-new-images-required" : "merge-ready-reuse-compatible",
    reason: newImagesRequired ? "Image-affecting changes require fresh protected-main images after merge." : "No image-affecting changes were found; reviewed image reuse remains possible after production evidence validation.",
  };
}

export function assertImageImpactReport({ report, imageReleaseSha, toolingSha, toolingInputTreeSha256, changedFiles }) {
  const expected = imageImpactReportFor({ imageReleaseSha, toolingSha, changedFiles, toolingInputTreeSha256 });
  assert.deepEqual(report, expected, "Stage B image-impact report is stale, incomplete, or falsely compatible.");
  return report;
}

export function assertProductionImageReuseResult(result) {
  assert.equal(result?.imageReuseCompatible, true, `Stage B production image reuse is unsafe; rebuild required for: ${(result?.imageAffectingFiles || []).join(", ")}`);
  assert.equal(result?.imageBuildInputsChanged, false, "Stage B production closure cannot accept new-images-required evidence.");
  return result;
}

export function parseStageBClosureMode(argv) {
  const index = argv.indexOf("--mode");
  if (index === -1 || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error("Stage B closure requires --mode pull-request or --mode production.");
  const mode = argv[index + 1];
  assert(STAGE_B_CLOSURE_MODES.includes(mode), `Unsupported Stage B closure mode: ${mode}.`);
  return mode;
}

export function parseStageBImageReuseCliArgs(argv) {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        mode: { type: "string" },
        "write-reviewed-report": { type: "boolean" },
        "write-image-impact-report": { type: "boolean" },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (error) {
    throw new Error(`Invalid Stage B image-reuse arguments: ${error.message}`);
  }

  const mode = parsed.values.mode;
  if (!mode) throw new Error("Stage B closure requires --mode pull-request or --mode production.");
  assert(STAGE_B_CLOSURE_MODES.includes(mode), `Unsupported Stage B closure mode: ${mode}.`);
  if (parsed.positionals.length > 2) throw new Error("Stage B image-reuse accepts at most image-release and tooling SHA positionals.");
  for (const value of parsed.positionals) assert(SHA.test(value), `Stage B image-reuse SHA positional is invalid: ${value}.`);

  const writeReviewedReport = parsed.values["write-reviewed-report"] === true;
  const writeImageImpactReport = parsed.values["write-image-impact-report"] === true;
  if (writeReviewedReport && mode !== "production") throw new Error("--write-reviewed-report requires --mode production.");
  if (writeImageImpactReport && mode !== "pull-request") throw new Error("--write-image-impact-report requires --mode pull-request.");
  return { mode, positionals: parsed.positionals, writeReviewedReport, writeImageImpactReport };
}

export function writeJsonAtomically(targetPath, value) {
  const bytes = `${JSON.stringify(value, null, 2)}\n`;
  JSON.parse(bytes);
  const temporaryPath = `${targetPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let published = false;
  try {
    fs.writeFileSync(temporaryPath, bytes, { encoding: "utf8", mode: 0o600 });
    fs.renameSync(temporaryPath, targetPath);
    published = true;
  } finally {
    if (!published) try { fs.unlinkSync(temporaryPath); } catch {}
  }
}

function git(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
}

function reportFor({ imageReleaseSha, toolingSha, changedFiles, toolingInputTreeSha256 }) {
  const classifiedChangedFiles = normalizeClassifiedFiles(changedFiles);
  return {
    schemaVersion: STAGE_B_IMAGE_REUSE_SCHEMA_VERSION,
    identityModel: "tooling-input-tree-sha256",
    imageReleaseSha,
    comparisonBaseSha: imageReleaseSha,
    comparisonHeadIdentity: "tooling-input-tree-sha256",
    comparisonHeadSha256: toolingInputTreeSha256,
    toolingInputTreeSha256,
    imageReuseCompatible: classifiedChangedFiles.every(({ imageAffecting }) => !imageAffecting),
    imageBuildInputsChanged: classifiedChangedFiles.some(({ imageAffecting }) => imageAffecting),
    classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION,
    generatedAt: git(["show", "-s", "--format=%cI", toolingSha]),
    generatorVersion: "validate-stage-b-image-reuse@2",
    classifiedChangedFiles,
    imageAffectingFiles: classifiedChangedFiles.filter(({ imageAffecting }) => imageAffecting).map(({ file }) => file),
    reason: "The reviewed tooling input tree contains no image-affecting changes relative to the image release.",
  };
}

function trackedFiles(toolingSha) {
  return git(["ls-tree", "-r", "--format=%(objectname) %(path)", toolingSha]).split("\n").filter(Boolean).map((line) => {
    const separator = line.indexOf(" ");
    return { blobSha: line.slice(0, separator), file: line.slice(separator + 1) };
  });
}

function changedFiles(imageReleaseSha, toolingSha) {
  const files = git(["diff", "--name-only", `${imageReleaseSha}..${toolingSha}`]).split("\n").filter(Boolean);
  if (!files.includes(COMPATIBILITY_REPORT_REPO_PATH)) files.push(COMPATIBILITY_REPORT_REPO_PATH);
  return [...new Set(files)];
}

function toolingInputTreeSha256(toolingSha) {
  const entries = trackedFiles(toolingSha);
  const blobByFile = new Map(entries.map(({ file, blobSha }) => [file, blobSha]));
  return computeStageBToolingInputTreeSha256({ files: entries.map(({ file }) => file), blobSha256: (file) => blobByFile.get(file) });
}

function imageImpactReportPath() {
  return process.env.STAGE_B_IMAGE_IMPACT_REPORT_PATH || path.join(root, IMAGE_IMPACT_REPORT_REPO_PATH);
}

function compatibilityReportPath() {
  return process.env.STAGE_B_COMPATIBILITY_REPORT_PATH || path.join(root, COMPATIBILITY_REPORT_REPO_PATH);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { mode, positionals, writeReviewedReport, writeImageImpactReport } = parseStageBImageReuseCliArgs(process.argv.slice(2));
  const reviewedReport = JSON.parse(fs.readFileSync(compatibilityReportPath(), "utf8"));
  const imageReleaseSha = positionals[0] || reviewedReport.imageReleaseSha;
  const toolingSha = positionals[1] || git(["rev-parse", "HEAD"]);
  const checkoutMode = process.env.STAGE_B_TOOLING_CHECKOUT_MODE || "review";
  if (mode === "production" && checkoutMode !== "production") throw new Error("Production image-reuse validation requires a protected-main checkout mode.");
  if (checkoutMode === "production") readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  else assertStageBProtectedMainCheckout(buildStageBProtectedMainCheckoutEvidence({ toolingSha, currentHead: git(["rev-parse", "HEAD"]), originMainHead: undefined, isAncestor: false, porcelainStatus: git(["status", "--porcelain=v1", "--untracked-files=all"]), repositoryState: { remoteDefaultBranch: undefined, shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "review" }));
  const files = changedFiles(imageReleaseSha, toolingSha);
  const inputTreeSha256 = toolingInputTreeSha256(toolingSha);
  if (mode === "pull-request") {
    const impactReport = imageImpactReportFor({ imageReleaseSha, toolingSha, changedFiles: files, toolingInputTreeSha256: inputTreeSha256 });
    const reportPath = imageImpactReportPath();
    if (writeImageImpactReport) writeJsonAtomically(reportPath, impactReport);
    else assertImageImpactReport({ report: JSON.parse(fs.readFileSync(reportPath, "utf8")), imageReleaseSha, toolingSha, toolingInputTreeSha256: inputTreeSha256, changedFiles: files });
    process.stdout.write(`${JSON.stringify({ ...impactReport, reportPath, summary: impactReport.newImagesRequired ? "Merge permitted; fresh protected-main images required before production deployment." : "Merge permitted; reviewed image reuse remains compatible." }, null, 2)}\n`);
  } else if (writeReviewedReport) {
    writeJsonAtomically(compatibilityReportPath(), reportFor({ imageReleaseSha, toolingSha, changedFiles: files, toolingInputTreeSha256: inputTreeSha256 }));
  } else {
    const result = imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles: files, currentHead: git(["rev-parse", "HEAD"]), toolingInputTreeSha256: inputTreeSha256, reviewedReport });
    assertProductionImageReuseResult(result);
    process.stdout.write(`${JSON.stringify({ status: "valid", reviewedReport: { imageReleaseSha: reviewedReport.imageReleaseSha, comparisonBaseSha: reviewedReport.comparisonBaseSha, toolingInputTreeSha256: reviewedReport.toolingInputTreeSha256 }, recomputed: { imageReleaseSha, toolingSha, toolingInputTreeSha256: inputTreeSha256 }, ...result }, null, 2)}\n`);
  }
}
