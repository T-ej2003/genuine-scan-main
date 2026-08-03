import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBProtectedMainCheckout, buildStageBProtectedMainCheckoutEvidence, readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const STAGE_B_IMAGE_REUSE_SCHEMA_VERSION = 2;
export const STAGE_B_IMAGE_REUSE_RULES_VERSION = "stage-b-image-reuse-v2";
export const COMPATIBILITY_REPORT_REPO_PATH = "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json";
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
const TERRAFORM = /^infra\/aws\/terraform\/production-green-stage-b\//;
const TEST = /(?:^|\/)(?:tests?|fixtures)(?:\/|\.)|\.test\.[^.]+$/;

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export function classifyStageBImageReusePath(file) {
  if (IMAGE_INPUTS.some((pattern) => pattern.test(file))) {
    const category = /package-lock|lock$/.test(file) ? "dependencyLockfile" : /Dockerfile|dockerignore|workflow.*image-build/.test(file) ? "dockerBuildConfiguration" : /^backend\//.test(file) || /^shared\//.test(file) ? "runtimeApplicationSource" : /generated/.test(file) ? "generatedRuntimePackage" : "imageBuildInput";
    return { file, category, imageAffecting: true };
  }
  if (TERRAFORM.test(file)) return { file, category: "terraformOnly", imageAffecting: false };
  if (CI.test(file)) return { file, category: "ciOnly", imageAffecting: false };
  if (DOCUMENTATION.test(file)) return { file, category: "documentationOnly", imageAffecting: false };
  if (TEST.test(file)) return { file, category: "testOnly", imageAffecting: false };
  if (/^scripts\//.test(file) || /^documents\/ops\//.test(file) || /^documents\/security\/rls-program\//.test(file) || /^package\.json$/.test(file)) {
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
  const entries = files.filter((file) => file !== COMPATIBILITY_REPORT_REPO_PATH).sort().map((file) => ({ file, sha256: blobSha256 ? blobSha256(file) : sha256(readFile(file)) }));
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

if (import.meta.url === `file://${process.argv[1]}`) {
  const reviewedReport = JSON.parse(fs.readFileSync(path.join(root, COMPATIBILITY_REPORT_REPO_PATH), "utf8"));
  const imageReleaseSha = process.argv[2] || reviewedReport.imageReleaseSha;
  const toolingSha = process.argv[3] || git(["rev-parse", "HEAD"]);
  const checkoutMode = process.env.STAGE_B_TOOLING_CHECKOUT_MODE || "review";
  if (checkoutMode === "production") readStageBProtectedMainCheckout({ cwd: root, fetchOriginMain: true });
  else assertStageBProtectedMainCheckout(buildStageBProtectedMainCheckoutEvidence({ toolingSha, currentHead: git(["rev-parse", "HEAD"]), originMainHead: undefined, isAncestor: false, porcelainStatus: git(["status", "--porcelain=v1", "--untracked-files=all"]), repositoryState: { remoteDefaultBranch: undefined, shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false }, mode: "review" }));
  const files = changedFiles(imageReleaseSha, toolingSha);
  const inputTreeSha256 = toolingInputTreeSha256(toolingSha);
  if (process.argv.includes("--write-reviewed-report")) {
    fs.writeFileSync(path.join(root, COMPATIBILITY_REPORT_REPO_PATH), `${JSON.stringify(reportFor({ imageReleaseSha, toolingSha, changedFiles: files, toolingInputTreeSha256: inputTreeSha256 }), null, 2)}\n`);
  } else {
    const result = imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles: files, currentHead: git(["rev-parse", "HEAD"]), toolingInputTreeSha256: inputTreeSha256, reviewedReport });
    assert.equal(result.imageReuseCompatible, true, `Stage B image reuse is unsafe; rebuild required for: ${result.imageAffectingFiles.join(", ")}`);
    process.stdout.write(`${JSON.stringify({ status: "valid", reviewedReport: { imageReleaseSha: reviewedReport.imageReleaseSha, comparisonBaseSha: reviewedReport.comparisonBaseSha, toolingInputTreeSha256: reviewedReport.toolingInputTreeSha256 }, recomputed: { imageReleaseSha, toolingSha, toolingInputTreeSha256: inputTreeSha256 }, ...result }, null, 2)}\n`);
  }
}
