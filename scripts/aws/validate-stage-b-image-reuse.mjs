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
export const STAGE_B_IMAGE_REUSE_RULES_VERSION = "stage-b-image-reuse-v4";
export const COMPATIBILITY_REPORT_REPO_PATH = "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.json";
export const STAGE_B_IMAGE_IMPACT_SCHEMA_VERSION = 1;
export const IMAGE_IMPACT_REPORT_REPO_PATH = "documents/ops/iam/MSCQRProductionGreenStageBImageImpact-v1.json";
export const STAGE_B_CLOSURE_MODES = ["pull-request", "production"];
export const STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH = ".github/workflows/production-green-stage-b-image-build.yml";
const TOOLING_TREE_EVIDENCE_PATHS = new Set([COMPATIBILITY_REPORT_REPO_PATH, "documents/ops/iam/MSCQRProductionGreenStageBImageReuseCompatibility-v1.md", IMAGE_IMPACT_REPORT_REPO_PATH]);
const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const PUBLICATION_ENV_KEYS = new Set([
  "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCOUNT_ID", "ECR_REGISTRY", "IMAGE_TAG", "SOURCE_RELEASE_SHA",
  "PLATFORMS", "BACKEND_ECR_REPO", "FRONTEND_ECR_REPO", "WORKER_ECR_REPO", "BACKEND_DOCKERFILE",
  "FRONTEND_DOCKERFILE", "WORKER_DOCKERFILE", "BACKEND_BUILD_CONTEXT", "FRONTEND_BUILD_CONTEXT",
  "WORKER_BUILD_CONTEXT", "BUILDER_NAME", "SOURCE_CONTRACT_SHA256", "MIGRATION_SET_DIGEST", "BUILD_TIMESTAMP",
]);
const PUBLICATION_ENV_SUSPECT = /(?:IMAGE|ECR|DOCKER|BUILD|PLATFORM|SOURCE|RELEASE|PUBLISH|CONTEXT|TARGET)/i;
const TRUSTED_TOOLING_STEP_NAMES = new Set(["Checkout trusted workflow tooling", "Bind the trusted workflow tooling revision"]);

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
const TERRAFORM = /^infra\/aws\/terraform\/production-green-stage-(?:a|b(?:-image-publisher|-publisher-bootstrap)?)\//;
const CONTROL_PLANE = /^infra\/aws\/terraform\/lambda\/production-rls-approval-broker\/(?:index\.mjs|package\.json|package-lock\.json)$/;
const TEST = /(?:^|\/)(?:e2e|tests?|fixtures)(?:\/|\.)|\.test\.[^.]+$/;
const TOOLING_ONLY = new Set([".gitleaks-baseline.json", ".gitleaksignore", ".security/rotation-evidence.schema.json"]);

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

function workflowStep(source, name, nextName) {
  const start = source.indexOf(`      - name: ${name}`);
  const end = source.indexOf(`      - name: ${nextName}`, start);
  assert(start >= 0 && end > start, `Trusted Stage B workflow is missing the ${name} step.`);
  return source.slice(start, end);
}

function withoutReleaseWorkingDirectory(source) {
  return source.replace(/\n        working-directory: release-source/g, "");
}

function workflowStepBlocks(source) {
  const blocks = [];
  let block = [];
  const stepsStart = source.lastIndexOf("\n    steps:\n");
  assert(stepsStart >= 0, "Trusted Stage B build job steps are missing.");
  for (const line of source.slice(stepsStart).split("\n")) {
    if (/^      - /.test(line)) {
      if (block.length) blocks.push(block.join("\n"));
      block = [line];
    } else if (block.length) block.push(line);
  }
  if (block.length) blocks.push(block.join("\n"));
  return blocks;
}

function workflowStepBy(source, predicate, label) {
  const step = workflowStepBlocks(source).find(predicate);
  assert(step, `Trusted Stage B workflow is missing the ${label} step.`);
  return step;
}

function workflowPublicationSteps(source) {
  const steps = workflowStepBlocks(source);
  const publishIndex = steps.findIndex((step) => step.startsWith("      - name: Publish immutable backend, worker, executor, and canary images"));
  assert(publishIndex >= 0, "Trusted Stage B workflow is missing the image publication step.");
  return steps.slice(0, publishIndex + 1).filter((step) => !TRUSTED_TOOLING_STEP_NAMES.has(step.match(/^      - name: (.+)$/m)?.[1]));
}

function indentedBlock(source, marker, indent) {
  const lines = source.split("\n");
  const index = lines.indexOf(marker);
  if (index < 0) return "";
  const block = [];
  for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
    const line = lines[cursor];
    if (line && new RegExp(`^ {0,${indent}}\\S`).test(line)) break;
    block.push(line);
  }
  return block.join("\n").trimEnd();
}

function parseEnvBlock(block, label) {
  if (!block) return {};
  const values = {};
  for (const line of block.split("\n").filter(Boolean)) {
    const match = line.match(/^\s{6,10}([A-Z][A-Z0-9_]*)\s*:\s*(.*)$/);
    assert(match, `Trusted Stage B ${label} environment structure is unsupported.`);
    values[match[1]] = match[2];
  }
  return Object.fromEntries(Object.entries(values).sort(([left], [right]) => left.localeCompare(right)));
}

function normalizeWorkflowText(value) {
  return value.replaceAll("release-source/", "").replaceAll("\n      TRUSTED_TOOLING_SHA: ${{ github.sha }}", "").replaceAll("\n          path: release-source", "").replaceAll("\n        working-directory: release-source", "").replaceAll("$GITHUB_WORKSPACE/scripts/aws/", "./scripts/aws/").replaceAll('node "./scripts/aws/', "node scripts/aws/").replaceAll('stage-b-release-gate.mjs" ', "stage-b-release-gate.mjs ").replace("run: MSCQR_AWS_CREDENTIAL_SOURCE=github-oidc-release-deployer ./scripts/aws/publish-ecs-images.sh production-green-stage-b", "run: ./scripts/aws/publish-ecs-images.sh production-green-stage-b");
}

function effectivePublicationEnv(source, publishStep) {
  const values = { ...parseEnvBlock(indentedBlock(source, "  env:", 2), "workflow"), ...parseEnvBlock(indentedBlock(source, "    env:", 4), "job"), ...parseEnvBlock(indentedBlock(publishStep, "        env:", 8), "publication step") };
  const unknown = Object.keys(values).filter((key) => !PUBLICATION_ENV_KEYS.has(key) && PUBLICATION_ENV_SUSPECT.test(key)).sort();
  assert.equal(unknown.length, 0, `Trusted workflow has unknown publication-affecting environment inputs: ${unknown.join(", ")}`);
  return Object.fromEntries(Object.entries(values).filter(([key]) => PUBLICATION_ENV_KEYS.has(key)).sort(([left], [right]) => left.localeCompare(right)));
}

export function stageBPublicationInputs(source) {
  const publishStep = workflowStepBy(source, (step) => step.startsWith("      - name: Publish immutable backend, worker, executor, and canary images"), "image publication");
  const releaseCheckout = workflowStepBy(source, (step) => step.startsWith("      - uses: actions/checkout@v6") && (/ref: \$\{\{ inputs\.release_sha \}\}/.test(step) || /path: release-source/.test(step)), "release checkout");
  const installStep = workflowStepBy(source, (step) => /npm ci && npm --prefix backend ci/.test(step), "release dependency installation");
  const setupNode = workflowStepBy(source, (step) => step.startsWith("      - uses: actions/setup-node@v6"), "Node setup");
  const credentials = workflowStepBy(source, (step) => step.startsWith("      - uses: aws-actions/configure-aws-credentials@v6"), "AWS credentials");
  const releaseGate = workflowStepBy(source, (step) => step.startsWith("      - name: Require the approved release to be merged into protected main"), "release gate");
  const inputBlock = indentedBlock(source, "      release_sha:", 6);
  assert(/required:\s*true/.test(inputBlock) && /type:\s*string/.test(inputBlock), "Trusted workflow release_sha input contract is invalid.");
  const setupNodeInputs = indentedBlock(setupNode, "        with:", 8).replaceAll("release-source/", "");
  return {
    workflowInput: inputBlock,
    workflowDefaults: indentedBlock(source, "  defaults:", 2),
    jobDefaults: indentedBlock(source, "    defaults:", 4),
    jobStrategy: indentedBlock(source, "    strategy:", 4),
    publicationSteps: workflowPublicationSteps(source).map(normalizeWorkflowText),
    effectiveEnv: effectivePublicationEnv(source, publishStep),
    publicationStep: normalizeWorkflowText(publishStep),
    releaseCheckout: normalizeWorkflowText(releaseCheckout),
    installStep: normalizeWorkflowText(installStep),
    setupNode: setupNode.replace(indentedBlock(setupNode, "        with:", 8), setupNodeInputs),
    credentials,
    releaseGate: normalizeWorkflowText(releaseGate),
  };
}

function trustedWorkflowProof(releaseWorkflowSource, toolingWorkflowSource) {
  const releaseInputs = stageBPublicationInputs(releaseWorkflowSource);
  const toolingInputs = stageBPublicationInputs(toolingWorkflowSource);
  const releaseFingerprint = sha256(Buffer.from(canonicalJson(releaseInputs)));
  const toolingFingerprint = sha256(Buffer.from(canonicalJson(toolingInputs)));
  assert.equal(toolingFingerprint, releaseFingerprint, "Trusted workflow changes altered the effective image publication inputs.");
  return Object.freeze({
    schemaVersion: 1,
    assertion: "STAGE_B_TRUSTED_WORKFLOW_PUBLICATION_INPUTS_V1",
    workflowPath: STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH,
    releaseFingerprint,
    toolingFingerprint,
    releaseCheckout: "release-source",
    publisherSource: "release-source",
    trustedSigningSource: "$GITHUB_WORKSPACE",
  });
}

function reusableTrustedWorkflowProof(boundary) {
  return boundary && Object.freeze({
    schemaVersion: boundary.schemaVersion,
    assertion: boundary.assertion,
    workflowPath: boundary.workflowPath,
    releaseFingerprint: boundary.releaseFingerprint,
    toolingFingerprint: boundary.toolingFingerprint,
    releaseCheckout: boundary.releaseCheckout,
    publisherSource: boundary.publisherSource,
    trustedSigningSource: boundary.trustedSigningSource,
  });
}

export function assertStageBTrustedWorkflowSeparation({ imageReleaseSha, toolingSha, readFile } = {}) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Trusted tooling SHA must be a full commit SHA.");
  const read = readFile || ((sha) => git(["show", `${sha}:${STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH}`]));
  const releaseWorkflow = read(imageReleaseSha);
  const toolingWorkflow = read(toolingSha);
  assert.notEqual(releaseWorkflow, toolingWorkflow, "Trusted workflow separation requires a changed workflow boundary.");
  const proof = trustedWorkflowProof(releaseWorkflow, toolingWorkflow);

  const releasePublishStep = workflowStep(releaseWorkflow, "Publish immutable backend, worker, executor, and canary images", "Bind image digest outputs");
  const toolingPublishStep = workflowStep(toolingWorkflow, "Publish immutable backend, worker, executor, and canary images", "Bind image digest outputs");
  assert.equal(normalizeWorkflowText(withoutReleaseWorkingDirectory(toolingPublishStep)), normalizeWorkflowText(releasePublishStep), "Trusted workflow changes altered the release image publication inputs.");
  assert.match(toolingWorkflow, /IMAGE_TAG: \$\{\{ inputs\.release_sha \}\}/, "Trusted workflow must bind the image tag to release_sha.");
  assert.match(toolingWorkflow, /ref: \$\{\{ inputs\.release_sha \}\}\s+path: release-source\s+fetch-depth: 0/, "Trusted workflow must isolate the release checkout.");
  assert.match(toolingWorkflow, /working-directory: release-source\s+run: (?:MSCQR_AWS_CREDENTIAL_SOURCE=github-oidc-release-deployer )?\.\/scripts\/aws\/publish-ecs-images\.sh production-green-stage-b/, "Trusted workflow must build from the release checkout.");
  assert.match(toolingWorkflow, /run: npm ci && npm --prefix backend ci\s+working-directory: release-source/, "Trusted workflow must install release-source dependencies.");
  assert.match(toolingWorkflow, /\$GITHUB_WORKSPACE\/scripts\/aws\/cosign-idempotent-sign-and-attest\.sh/, "Trusted signing tooling must come from the protected tooling checkout.");
  assert.match(toolingWorkflow, /\$GITHUB_WORKSPACE\/scripts\/aws\/verify-release-artifacts\.sh/, "Trusted verification tooling must come from the protected tooling checkout.");
  return Object.freeze({ file: STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH, category: "trustedToolingOnly", imageAffecting: false, ...proof, publicationInputFingerprint: proof.toolingFingerprint });
}

function classifyChangedFiles({ imageReleaseSha, toolingSha, changedFiles }) {
  const hasTrustedWorkflow = changedFiles.some((entry) => (typeof entry === "string" ? entry : entry?.file) === STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH);
  const trustedWorkflow = hasTrustedWorkflow ? assertStageBTrustedWorkflowSeparation({ imageReleaseSha, toolingSha }) : undefined;
  return { classifiedChangedFiles: normalizeClassifiedFiles(changedFiles, { trustedWorkflow }), trustedWorkflow };
}

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

function normalizeClassifiedFiles(files, { trustedWorkflow } = {}) {
  return files.map((entry) => typeof entry === "string" ? classifyStageBImageReusePath(entry) : entry)
    .map((entry) => trustedWorkflow && entry.file === trustedWorkflow.file ? trustedWorkflow : entry)
    .map(({ file, category, imageAffecting }) => ({ file, category, imageAffecting: Boolean(imageAffecting) }))
    .sort((left, right) => left.file.localeCompare(right.file));
}

export function computeStageBToolingInputTreeSha256({ files, readFile, blobSha256 }) {
  const entries = files.filter((file) => !TOOLING_TREE_EVIDENCE_PATHS.has(file)).sort().map((file) => ({ file, sha256: blobSha256 ? blobSha256(file) : sha256(readFile(file)) }));
  return sha256(Buffer.from(canonicalJson(entries)));
}

function assertReviewedReport({ reviewedReport, imageReleaseSha, toolingInputTreeSha256, changedFiles, trustedWorkflow }) {
  assert.equal(reviewedReport?.schemaVersion, STAGE_B_IMAGE_REUSE_SCHEMA_VERSION, "Compatibility report schema is unsupported.");
  assert.equal(reviewedReport.imageReleaseSha, imageReleaseSha, "Compatibility report is for a different image release SHA.");
  assert.equal(reviewedReport.comparisonBaseSha, imageReleaseSha, "Compatibility report comparison base does not match the image release SHA.");
  assert.equal(reviewedReport.comparisonHeadIdentity, "tooling-input-tree-sha256", "Compatibility report comparison head identity is unsupported.");
  assert.equal(reviewedReport.toolingInputTreeSha256, toolingInputTreeSha256, "Compatibility report is for a different tooling input tree.");
  assert.equal(reviewedReport.comparisonHeadSha256, toolingInputTreeSha256, "Compatibility report comparison head does not match the tooling input tree.");
  assert.equal(reviewedReport.classificationRulesVersion, STAGE_B_IMAGE_REUSE_RULES_VERSION, "Compatibility report classification rules are stale.");
  assert.deepEqual(reviewedReport.classifiedChangedFiles, normalizeClassifiedFiles(changedFiles), "Compatibility report changed-file classification is stale or incomplete.");
  assert.deepEqual(reviewedReport.trustedToolingOnlyPaths, changedFiles.filter(({ category }) => category === "trustedToolingOnly").map(({ file }) => file), "Compatibility report trusted-tooling boundary is stale or incomplete.");
  assert.equal(reviewedReport.publicationInputFingerprint, trustedWorkflow?.publicationInputFingerprint, "Compatibility report publication-input binding is stale or incomplete.");
  assert.deepEqual(reviewedReport.trustedWorkflowProof, reusableTrustedWorkflowProof(trustedWorkflow), "Compatibility report trusted-workflow proof is stale or incomplete.");
  assert.equal(reviewedReport.imageReuseCompatible, !reviewedReport.classifiedChangedFiles.some(({ imageAffecting }) => imageAffecting), "Compatibility report compatibility result is inconsistent.");
}

export function imageReuseCompatibility({ imageReleaseSha, toolingSha, changedFiles, currentHead, reviewedReport, toolingInputTreeSha256 }) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  if (currentHead !== undefined) assert.equal(currentHead, toolingSha, "Tooling SHA must equal the checked-out tooling HEAD.");
  const { classifiedChangedFiles, trustedWorkflow } = classifyChangedFiles({ imageReleaseSha, toolingSha, changedFiles });
  const unclassifiedFiles = classifiedChangedFiles.filter(({ category }) => category === "unknown").map(({ file }) => file);
  assert.equal(unclassifiedFiles.length, 0, `Stage B image-impact report contains unclassified files: ${unclassifiedFiles.join(", ")}`);
  const imageAffectingFiles = classifiedChangedFiles.filter(({ imageAffecting }) => imageAffecting).map(({ file }) => file);
  assertReviewedReport({ reviewedReport, imageReleaseSha, toolingInputTreeSha256, changedFiles: classifiedChangedFiles, trustedWorkflow });
  return {
    schemaVersion: STAGE_B_IMAGE_REUSE_SCHEMA_VERSION,
    imageReleaseSha,
    toolingInputTreeSha256,
    comparisonBaseSha: imageReleaseSha,
    comparisonHeadSha256: toolingInputTreeSha256,
    classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION,
    imageReuseCompatible: imageAffectingFiles.length === 0,
    imageBuildInputsChanged: imageAffectingFiles.length > 0,
    classifiedChangedFiles,
    trustedToolingOnlyPaths: classifiedChangedFiles.filter(({ category }) => category === "trustedToolingOnly").map(({ file }) => file),
    imageAffectingFiles,
    reportMatchesRecomputedDiff: true,
    ...(trustedWorkflow ? { publicationInputFingerprint: trustedWorkflow.publicationInputFingerprint, trustedWorkflowProof: reusableTrustedWorkflowProof(trustedWorkflow) } : {}),
  };
}

export function imageImpactReportFor({ imageReleaseSha, toolingSha, changedFiles, toolingInputTreeSha256 }) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  const { classifiedChangedFiles, trustedWorkflow } = classifyChangedFiles({ imageReleaseSha, toolingSha, changedFiles });
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
    trustedToolingOnlyPaths: classifiedChangedFiles.filter(({ category }) => category === "trustedToolingOnly").map(({ file }) => file),
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
    ...(trustedWorkflow ? { publicationInputFingerprint: trustedWorkflow.publicationInputFingerprint, trustedWorkflowProof: reusableTrustedWorkflowProof(trustedWorkflow) } : {}),
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

export function assertStageBTrustedToolingReuseResult(result) {
  assert.equal(result?.imageReuseCompatible, true, "Trusted workflow reuse is not compatible.");
  assert(result?.imageBuildInputsChanged === false || result?.newImagesRequired === false, "Trusted workflow reuse contains image-build changes.");
  assert.equal(result?.classificationRulesVersion, STAGE_B_IMAGE_REUSE_RULES_VERSION, "Trusted workflow reuse rules are stale.");
  assert.deepEqual(result?.trustedToolingOnlyPaths, [STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH], "Trusted workflow reuse must identify exactly the reviewed workflow boundary.");
  assert(SHA256.test(result?.publicationInputFingerprint || ""), "Trusted workflow publication-input fingerprint is required.");
  const proof = result?.trustedWorkflowProof;
  assert(proof && proof.schemaVersion === 1 && proof.assertion === "STAGE_B_TRUSTED_WORKFLOW_PUBLICATION_INPUTS_V1", "Trusted workflow publication proof is missing or unsupported.");
  assert.equal(proof.workflowPath, STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH, "Trusted workflow publication proof is for an unexpected workflow.");
  assert.equal(proof.releaseFingerprint, proof.toolingFingerprint, "Trusted workflow publication inputs are not equivalent.");
  assert.equal(proof.toolingFingerprint, result.publicationInputFingerprint, "Trusted workflow publication fingerprint is not bound to the reuse result.");
  assert.equal(proof.releaseCheckout, "release-source", "Trusted workflow does not isolate the release source.");
  assert.equal(proof.publisherSource, "release-source", "Trusted workflow publisher is not bound to the release source.");
  assert.equal(proof.trustedSigningSource, "$GITHUB_WORKSPACE", "Trusted signing source is not the protected tooling checkout.");
  const trustedEntries = (result.classifiedChangedFiles || []).filter(({ category }) => category === "trustedToolingOnly");
  assert.equal(trustedEntries.length, 1, "Trusted workflow reuse must contain exactly one trusted-tooling classification.");
  assert.deepEqual(trustedEntries[0], { file: STAGE_B_TRUSTED_IMAGE_WORKFLOW_PATH, category: "trustedToolingOnly", imageAffecting: false }, "Trusted workflow classification is not canonical.");
  assert(!(result.classifiedChangedFiles || []).some(({ category }) => category === "unknown"), "Trusted workflow reuse contains an unknown classification.");
  assert(!(result.classifiedChangedFiles || []).some(({ imageAffecting }) => imageAffecting), "Trusted workflow reuse contains an image-affecting classification.");
  assert.deepEqual(result.imageAffectingFiles, [], "Trusted workflow reuse contains image-affecting files.");
  return result;
}

export function assertStageBImageReuseResult(result) {
  assertProductionImageReuseResult(result);
  if ((result?.classifiedChangedFiles || []).some(({ category }) => category === "trustedToolingOnly")) assertStageBTrustedToolingReuseResult(result);
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

export function reportFor({ imageReleaseSha, toolingSha, changedFiles, toolingInputTreeSha256 }) {
  const { classifiedChangedFiles, trustedWorkflow } = classifyChangedFiles({ imageReleaseSha, toolingSha, changedFiles });
  return {
    schemaVersion: STAGE_B_IMAGE_REUSE_SCHEMA_VERSION,
    identityModel: "tooling-input-tree-sha256",
    imageReleaseSha,
    comparisonBaseSha: imageReleaseSha,
    toolingSha,
    comparisonHeadIdentity: "tooling-input-tree-sha256",
    comparisonHeadSha256: toolingInputTreeSha256,
    toolingInputTreeSha256,
    imageReuseCompatible: classifiedChangedFiles.every(({ imageAffecting }) => !imageAffecting),
    imageBuildInputsChanged: classifiedChangedFiles.some(({ imageAffecting }) => imageAffecting),
    classificationRulesVersion: STAGE_B_IMAGE_REUSE_RULES_VERSION,
    generatedAt: git(["show", "-s", "--format=%cI", toolingSha]),
    generatorVersion: "validate-stage-b-image-reuse@3",
    classifiedChangedFiles,
    trustedToolingOnlyPaths: classifiedChangedFiles.filter(({ category }) => category === "trustedToolingOnly").map(({ file }) => file),
    imageAffectingFiles: classifiedChangedFiles.filter(({ imageAffecting }) => imageAffecting).map(({ file }) => file),
    reason: "The reviewed tooling input tree contains no image-affecting changes relative to the image release.",
    ...(trustedWorkflow ? { publicationInputFingerprint: trustedWorkflow.publicationInputFingerprint, trustedWorkflowProof: reusableTrustedWorkflowProof(trustedWorkflow) } : {}),
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

export function deriveStageBToolingInputTreeSha256(toolingSha) {
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  return toolingInputTreeSha256(toolingSha);
}

export function deriveStageBImageImpactReport({ imageReleaseSha, toolingSha } = {}) {
  assert(SHA.test(imageReleaseSha || ""), "Image release SHA must be a full commit SHA.");
  assert(SHA.test(toolingSha || ""), "Tooling SHA must be a full commit SHA.");
  git(["rev-parse", "--verify", `${imageReleaseSha}^{commit}`]);
  git(["rev-parse", "--verify", `${toolingSha}^{commit}`]);
  const files = changedFiles(imageReleaseSha, toolingSha);
  return imageImpactReportFor({
    imageReleaseSha,
    toolingSha,
    changedFiles: files,
    toolingInputTreeSha256: toolingInputTreeSha256(toolingSha),
  });
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
    assertStageBImageReuseResult(result);
    process.stdout.write(`${JSON.stringify({ status: "valid", reviewedReport: { imageReleaseSha: reviewedReport.imageReleaseSha, comparisonBaseSha: reviewedReport.comparisonBaseSha, toolingInputTreeSha256: reviewedReport.toolingInputTreeSha256 }, recomputed: { imageReleaseSha, toolingSha, toolingInputTreeSha256: inputTreeSha256 }, ...result }, null, 2)}\n`);
  }
}
