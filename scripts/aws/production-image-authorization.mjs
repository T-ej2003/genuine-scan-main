import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertImageEvidence, assertImageEvidenceReuseBridge, imageEvidenceSha256, verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import {
  deriveStageBImageImpactReport,
  assertStageBImageReuseResult,
} from "./validate-stage-b-image-reuse.mjs";
import {
  assertStageBArtifactPath,
  ensureStageBPrivateFile,
  writeStageBPrivateFileAtomic,
} from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-cutover-production-adapters.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const WORKFLOW_RUN = /^\d+$/;
const SERVICES = new Set(["backend", "worker", "rls-executor", "rls-canary"]);

export const IMAGE_AUTHORIZATION_SCHEMA_VERSION = 3;
export const IMAGE_AUTHORIZATION_PATHS = Object.freeze({
  REUSE: "IMAGE_REUSE",
  FRESH_PUBLICATION: "FRESH_IMAGE_PUBLICATION",
});

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

function assertExactImageImpactEvidence(imageEvidence, impactEvidence, sourceSha) {
  if (!impactEvidence || typeof impactEvidence !== "object" || Array.isArray(impactEvidence)) throw new Error("Canonical image-impact evidence is required.");
  requireSha(sourceSha, "Protected-main source SHA");
  requireSha(impactEvidence.imageReleaseSha, "Image-impact release SHA");
  if (impactEvidence.toolingSha !== sourceSha) throw new Error("Image-impact evidence is not bound to the protected-main SHA.");
  const derived = deriveStageBImageImpactReport({ imageReleaseSha: impactEvidence.imageReleaseSha, toolingSha: sourceSha });
  if (canonicalSha256(impactEvidence) !== canonicalSha256(derived)) throw new Error("Image-impact evidence does not match the independently derived git impact report.");
  return derived;
}

function assertFreshPublicationEvidence(imageEvidence, sourceSha) {
  const identity = imageEvidence?.publicationIdentity;
  if (imageEvidence?.publicationSourceSha !== undefined
    || imageEvidence?.currentSourceSha !== undefined
    || imageEvidence?.imageReuseEvidenceSha256 !== undefined
    || imageEvidence?.imageReleaseSha !== sourceSha
    || identity?.workflowDefinitionSha !== sourceSha
    || identity?.imageReleaseSha !== imageEvidence.imageReleaseSha
    || String(identity?.workflowRunId) !== String(imageEvidence.workflowRunId)
    || identity?.event !== "workflow_dispatch"
    || identity?.headBranch !== "main"
    || identity?.conclusion !== "success"
    || identity?.artifactExpired !== false) {
    throw new Error("Fresh image authorization requires a successful publication from the exact protected-main workflow revision.");
  }
}

export function assertCanonicalImageReuseEvidence(imageEvidence, reuseEvidence, sourceSha) {
  const derived = assertExactImageImpactEvidence(imageEvidence, reuseEvidence, sourceSha);
  if (derived.imageReleaseSha !== imageEvidence.imageReleaseSha) throw new Error("Image-reuse evidence is not bound to the reused image release.");
  assertStageBImageReuseResult({ ...derived, imageBuildInputsChanged: derived.newImagesRequired });
  return derived;
}

export function assertCanonicalImageImpactEvidence(imageEvidence, impactEvidence, sourceSha) {
  const derived = assertExactImageImpactEvidence(imageEvidence, impactEvidence, sourceSha);
  if (derived.newImagesRequired) {
    assertFreshPublicationEvidence(imageEvidence, sourceSha);
    return Object.freeze({ derived, authorizationPath: IMAGE_AUTHORIZATION_PATHS.FRESH_PUBLICATION });
  }
  if (derived.imageReleaseSha !== imageEvidence.imageReleaseSha) throw new Error("Image-reuse evidence is not bound to the image publication.");
  assertImageEvidenceReuseBridge(imageEvidence, { imageReuseEvidence: impactEvidence, currentSourceSha: sourceSha });
  assertStageBImageReuseResult({ ...derived, imageBuildInputsChanged: false });
  return Object.freeze({ derived, authorizationPath: IMAGE_AUTHORIZATION_PATHS.REUSE });
}

export function createImageAuthorization({
  sourceSha,
  freshProtectedMain,
  imageEvidence,
  imageEvidenceSignature,
  imageReuseEvidence,
  now,
  verifyImageEvidence,
} = {}) {
  requireSha(sourceSha, "Protected-main source SHA");
  if (freshProtectedMain?.fetchSucceeded !== true || freshProtectedMain.headSha !== sourceSha || freshProtectedMain.freshRemoteMainSha !== sourceSha) {
    throw new Error("Image authorization source SHA does not match freshly fetched protected main.");
  }
  if (!imageEvidence || typeof imageEvidence !== "object" || Array.isArray(imageEvidence)) throw new Error("Canonical image evidence is required.");
  requireSha(imageEvidence.imageReleaseSha, "Image evidence release SHA");
  if (!WORKFLOW_RUN.test(String(imageEvidence.workflowRunId || ""))) throw new Error("Image evidence workflow run is missing or malformed.");

  assertImageEvidence(imageEvidence, {
    signatureArtifact: imageEvidenceSignature,
    publicationSourceSha: imageEvidence.publicationSourceSha || imageEvidence.imageReleaseSha,
    currentSourceSha: sourceSha,
    imageReleaseSha: imageEvidence.imageReleaseSha,
    workflowRunId: imageEvidence.workflowRunId,
    artifactSha256: imageEvidence.canonicalArtifactSha256,
    now,
    ...(verifyImageEvidence ? { verifySignature: verifyImageEvidence } : {}),
  });
  assertImageRecords(imageEvidence.images);
  const { derived: impactEvidence, authorizationPath } = assertCanonicalImageImpactEvidence(imageEvidence, imageReuseEvidence, sourceSha);

  const images = imageEvidence.images.map(({ service, digest }) => ({ service, digest }));
  const authorization = {
    schemaVersion: IMAGE_AUTHORIZATION_SCHEMA_VERSION,
    valid: true,
    evidenceRef: `image-evidence:${imageEvidence.workflowRunId}`,
    sourceSha,
    imageReleaseSha: imageEvidence.imageReleaseSha,
    workflowRunId: String(imageEvidence.workflowRunId),
    evidenceSha256: null,
    imageEvidenceSha256: imageEvidenceSha256(imageEvidence),
    imageReuseEvidenceSha256: canonicalSha256(imageReuseEvidence),
    authorizationPath,
    imageReuseCompatible: impactEvidence.imageReuseCompatible,
    imageBuildInputsChanged: impactEvidence.newImagesRequired,
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
  const freshProtectedMain = deps.freshProtectedMain || readFreshProtectedMainIdentity({
    cwd: repositoryRoot,
    expectedSourceSha: sourceSha,
    run: deps.git || git,
  });
  const { value: imageEvidence } = readJsonPrivate(imageEvidencePath, "Image evidence");
  const { value: imageEvidenceSignature } = readJsonPrivate(imageSignaturePath, "Image evidence signature");
  const { value: reviewedImageReuseEvidence } = readJsonPrivate(imageReuseEvidencePath, "Image-reuse compatibility report");
  const imageReuseEvidence = deriveStageBImageImpactReport({
    imageReleaseSha: imageEvidence.imageReleaseSha,
    toolingSha: sourceSha,
    reviewedReport: reviewedImageReuseEvidence,
  });
  const releaseRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer" });
  const authorization = createImageAuthorization({
    sourceSha,
    freshProtectedMain,
    imageEvidence,
    imageEvidenceSignature,
    imageReuseEvidence,
    now: deps.now,
    verifyImageEvidence: deps.verifyImageEvidence || ((options) => verifyImageEvidenceSignature({ ...options, run: releaseRun })),
  });
  const result = writeImageAuthorization({ outputPath, authorization });
  process.stdout.write(`${JSON.stringify({ outputPath: result.path, evidenceSha256: authorization.evidenceSha256, sourceSha, imageReleaseSha: authorization.imageReleaseSha, workflowRunId: authorization.workflowRunId, authorizationPath: authorization.authorizationPath, imageReuseCompatible: authorization.imageReuseCompatible }, null, 2)}\n`);
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli();
