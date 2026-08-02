import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const compatibilityPath = path.join(root, "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json");
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

export function imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead, reviewedReport }) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  if (currentHead !== undefined) assert.equal(currentHead, toolingSha, "Tooling SHA must equal the checked-out tooling HEAD.");
  assert.equal(reviewedReport.imageReleaseSha, imageReleaseSha, "Compatibility report is for a different image release SHA.");
  const classified = changedFiles.map(classifyStageBImageReusePath);
  const imageAffectingFiles = classified.filter(({ imageAffecting }) => imageAffecting).map(({ file }) => file);
  return {
    schemaVersion: 1,
    toolingSha,
    imageReleaseSha,
    comparison: `${imageReleaseSha}..${toolingSha}`,
    imageReuseCompatible: imageAffectingFiles.length === 0,
    imageBuildInputsChanged: imageAffectingFiles.length > 0,
    classifiedChangedFiles: Object.groupBy(classified, ({ category }) => category),
    imageAffectingFiles,
  };
}

function git(args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const reviewedReport = JSON.parse(fs.readFileSync(compatibilityPath, "utf8"));
  const imageReleaseSha = process.argv[2] || reviewedReport.imageReleaseSha;
  const toolingSha = process.argv[3] || git(["rev-parse", "HEAD"]);
  const changedFiles = git(["diff", "--name-only", `${imageReleaseSha}..${toolingSha}`]).split("\n").filter(Boolean);
  const result = imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead: git(["rev-parse", "HEAD"]), reviewedReport });
  assert.equal(result.imageReuseCompatible, true, `Stage B image reuse is unsafe; rebuild required for: ${result.imageAffectingFiles.join(", ")}`);
  process.stdout.write(`${JSON.stringify({ status: "valid", ...result }, null, 2)}\n`);
}
