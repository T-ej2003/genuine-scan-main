import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertImageEvidence, imageEvidenceSha256 } from "./production-green-stage-b-image-evidence.mjs";
import {
  assertImageImpactReport,
  assertProductionImageReuseResult,
} from "./validate-stage-b-image-reuse.mjs";
import {
  assertStageBArtifactPath,
  ensureStageBPrivateFile,
  writeStageBPrivateFileAtomic,
} from "./stage-b-artifact-contract.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const WORKFLOW_RUN = /^\d+$/;
const SERVICES = new Set(["backend", "worker", "rls-executor", "rls-canary"]);

export const IMAGE_AUTHORIZATION_SCHEMA_VERSION = 2;

const authorizationPayload = (value) => {
  const { evidenceSha256, filePath, authorizationSha256, ...payload } = value || {};
  return payload;
};

export const imageAuthorizationSha256 = (value) => canonicalSha256(authorizationPayload(value));

function requireSha(value, label, pattern = SHA40) {
  if (!pattern.test(String(value || ""))) throw new Error(`${label} must be a full SHA.`);
}

function readJsonPrivate(filePath, label) {
  const metadata = ensureStageBPrivateFile({ filePath, repositoryRoot, label });
  try {
    return { value: JSON.parse(fs.readFileSync(metadata.path, "utf8")), metadata };
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function assertImageRecords(images) {
  if (!Array.isArray(images) || images.length !== SERVICES.size || new Set(images.map(({ service }) => service)).size !== SERVICES.size) {
    throw new Error("Canonical image evidence must contain exactly four distinct services.");
  }
  for (const image of images) {
    if (!SERVICES.has(image?.service) || !DIGEST.test(image?.digest || "")) throw new Error(`Canonical image evidence contains an invalid ${image?.service || "unknown"} digest.`);
  }
}

function assertReuseEvidence(imageEvidence, reuseEvidence, sourceSha) {
  if (!reuseEvidence || typeof reuseEvidence !== "object" || Array.isArray(reuseEvidence)) throw new Error("Canonical image-reuse evidence is required.");
  if (reuseEvidence.imageReleaseSha !== imageEvidence.imageReleaseSha || reuseEvidence.toolingSha !== sourceSha) throw new Error("Image-reuse evidence is not bound to the image release and protected-main SHA.");
  assertImageImpactReport({
    report: reuseEvidence,
    imageReleaseSha: imageEvidence.imageReleaseSha,
    toolingSha: sourceSha,
    toolingInputTreeSha256: reuseEvidence.toolingInputTreeSha256,
    changedFiles: reuseEvidence.classifiedChangedFiles,
  });
  assertProductionImageReuseResult({
    ...reuseEvidence,
    imageBuildInputsChanged: reuseEvidence.newImagesRequired === true,
  });
  if (reuseEvidence.imageReuseCompatible !== true || reuseEvidence.newImagesRequired !== false) throw new Error("Image-reuse evidence is not compatible with immutable image reuse.");
}

export function createImageAuthorization({
  sourceSha,
  currentHead = sourceSha,
  originMainHead = sourceSha,
  imageEvidence,
  imageEvidenceSignature,
  imageReuseEvidence,
  now,
  verifyImageEvidence,
} = {}) {
  requireSha(sourceSha, "Protected-main source SHA");
  if (currentHead !== sourceSha || originMainHead !== sourceSha) throw new Error("Image authorization source SHA does not match protected main.");
  if (!imageEvidence || typeof imageEvidence !== "object" || Array.isArray(imageEvidence)) throw new Error("Canonical image evidence is required.");
  requireSha(imageEvidence.imageReleaseSha, "Image evidence release SHA");
  if (!WORKFLOW_RUN.test(String(imageEvidence.workflowRunId || ""))) throw new Error("Image evidence workflow run is missing or malformed.");

  assertImageEvidence(imageEvidence, {
    signatureArtifact: imageEvidenceSignature,
    imageReleaseSha: imageEvidence.imageReleaseSha,
    workflowRunId: imageEvidence.workflowRunId,
    artifactSha256: imageEvidence.canonicalArtifactSha256,
    now,
    ...(verifyImageEvidence ? { verifySignature: verifyImageEvidence } : {}),
  });
  assertImageRecords(imageEvidence.images);
  assertReuseEvidence(imageEvidence, imageReuseEvidence, sourceSha);

  const images = imageEvidence.images.map(({ service, digest }) => ({ service, digest }));
  const authorization = {
    schemaVersion: IMAGE_AUTHORIZATION_SCHEMA_VERSION,
    valid: true,
    sourceSha,
    imageReleaseSha: imageEvidence.imageReleaseSha,
    workflowRunId: String(imageEvidence.workflowRunId),
    evidenceSha256: null,
    imageEvidenceSha256: imageEvidenceSha256(imageEvidence),
    imageReuseEvidenceSha256: canonicalSha256(imageReuseEvidence),
    imageReuseCompatible: true,
    imageBuildInputsChanged: false,
    signatureVerified: true,
    attestationVerified: true,
    provenanceVerified: true,
    images,
    backendDigest: images.find(({ service }) => service === "backend").digest,
    imageEvidence,
    imageEvidenceSignature,
    imageReuseEvidence,
  };
  authorization.evidenceSha256 = imageAuthorizationSha256(authorization);
  authorization.authorizationSha256 = authorization.evidenceSha256;
  return Object.freeze(authorization);
}

export function writeImageAuthorization({ outputPath, authorization } = {}) {
  const target = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot, label: "Image authorization evidence", allowExisting: false });
  const bytes = Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`);
  const metadata = writeStageBPrivateFileAtomic({ filePath: target, bytes, repositoryRoot, label: "Image authorization evidence" });
  return { ...metadata, value: authorization };
}

function requiredOption(argv, option) {
  const index = argv.indexOf(option);
  const value = index === -1 ? undefined : argv[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${option} is required.`);
  return value;
}

function git(args) {
  return execFileSync("git", args, { cwd: repositoryRoot, encoding: "utf8" }).trim();
}

export function runCli(argv = process.argv.slice(2), deps = {}) {
  const allowedOptions = new Set(["--source-sha", "--image-evidence", "--image-signature", "--image-reuse-evidence", "--output"]);
  const seenOptions = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith("--")) throw new Error("Image authorization accepts options only.");
    if (!allowedOptions.has(value)) throw new Error(`Unknown image-authorization option: ${value}`);
    if (seenOptions.has(value)) throw new Error(`Duplicate image-authorization option: ${value}`);
    seenOptions.add(value);
    index += 1;
  }
  const sourceSha = requiredOption(argv, "--source-sha");
  const imageEvidencePath = requiredOption(argv, "--image-evidence");
  const imageSignaturePath = requiredOption(argv, "--image-signature");
  const imageReuseEvidencePath = requiredOption(argv, "--image-reuse-evidence");
  const outputPath = requiredOption(argv, "--output");
  const currentHead = deps.currentHead || git(["rev-parse", "HEAD"]);
  const originMainHead = deps.originMainHead || git(["rev-parse", "origin/main"]);
  const { value: imageEvidence } = readJsonPrivate(imageEvidencePath, "Image evidence");
  const { value: imageEvidenceSignature } = readJsonPrivate(imageSignaturePath, "Image evidence signature");
  const { value: imageReuseEvidence } = readJsonPrivate(imageReuseEvidencePath, "Image-reuse evidence");
  const authorization = createImageAuthorization({
    sourceSha,
    currentHead,
    originMainHead,
    imageEvidence,
    imageEvidenceSignature,
    imageReuseEvidence,
    now: deps.now,
    verifyImageEvidence: deps.verifyImageEvidence,
  });
  const result = writeImageAuthorization({ outputPath, authorization });
  process.stdout.write(`${JSON.stringify({ outputPath: result.path, evidenceSha256: authorization.evidenceSha256, sourceSha, imageReleaseSha: authorization.imageReleaseSha, workflowRunId: authorization.workflowRunId, imageReuseCompatible: authorization.imageReuseCompatible }, null, 2)}\n`);
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli();
