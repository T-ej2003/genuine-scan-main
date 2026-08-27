import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

export const STAGE_B_IMAGE_PUBLICATION_IDENTITY_SCHEMA_VERSION = 2;
export const STAGE_B_IMAGE_WORKFLOW_FILE = ".github/workflows/production-green-stage-b-images.yml";
export const STAGE_B_IMAGE_WORKFLOW_NAME = "Production Green Stage B Images";
export const STAGE_B_IMAGE_ARTIFACT_NAME = "production-green-stage-b-images";
export const STAGE_B_IMAGE_CANONICAL_FILENAME = "stage-b-images.jsonl";
export const STAGE_B_IMAGE_SERVICES = Object.freeze(["backend", "worker", "rls-executor", "rls-canary"]);

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const INTEGER = /^\d+$/;

const requireExact = (actual, expected, label) => {
  if (actual !== expected) throw new Error(`Stage B publication identity ${label} is invalid.`);
};

function assertObservedMetadata(observed, { expectedPublicationSourceSha, expectedReleaseSha } = {}) {
  if (!observed || typeof observed !== "object" || Array.isArray(observed)) throw new Error("Observed Stage B publication identity is required.");
  if (!SHA.test(String(expectedPublicationSourceSha || "")) || !SHA.test(String(expectedReleaseSha || ""))) throw new Error("Stage B publication identity requires exact publication-source and image-release SHAs.");
  if (!INTEGER.test(String(observed.workflowRunId || "")) || !INTEGER.test(String(observed.workflowDatabaseId || ""))) throw new Error("Observed Stage B publication identity requires workflow run and database IDs.");
  requireExact(observed.workflowFile, STAGE_B_IMAGE_WORKFLOW_FILE, "workflow file");
  requireExact(observed.workflowName, STAGE_B_IMAGE_WORKFLOW_NAME, "workflow name");
  requireExact(observed.event, "workflow_dispatch", "event");
  if (!SHA.test(String(observed.workflowDefinitionSha || "")) || observed.workflowDefinitionSha !== expectedPublicationSourceSha) throw new Error("Observed Stage B workflow definition SHA is not the authenticated publication source.");
  if (!SHA.test(String(observed.imageReleaseSha || "")) || observed.imageReleaseSha !== expectedReleaseSha) throw new Error("Observed Stage B image release SHA is not the requested image release.");
  requireExact(observed.headBranch, "main", "head branch");
  requireExact(observed.conclusion, "success", "conclusion");
  if (!INTEGER.test(String(observed.artifactId || ""))) throw new Error("Observed Stage B publication artifact ID is invalid.");
  requireExact(observed.artifactName, STAGE_B_IMAGE_ARTIFACT_NAME, "artifact name");
  if (observed.artifactExpired !== false) throw new Error("Observed Stage B publication artifact is expired or missing expiry evidence.");
  if (observed.artifactArchiveFilename !== null && typeof observed.artifactArchiveFilename !== "string") throw new Error("Observed Stage B publication archive filename is malformed.");
}

export function assertObservedStageBImagePublicationMetadata(observed, expected) {
  assertObservedMetadata(observed, expected);
  return true;
}

function parseServices(artifactBytes) {
  let records;
  try { records = artifactBytes.toString("utf8").trim().split(/\n/).filter(Boolean).map(JSON.parse); } catch { throw new Error("Stage B publication artifact JSONL is malformed."); }
  const services = records.map((record) => record?.service);
  if (records.length !== STAGE_B_IMAGE_SERVICES.length || new Set(services).size !== records.length || [...services].sort().join("\n") !== [...STAGE_B_IMAGE_SERVICES].sort().join("\n")) throw new Error("Stage B publication artifact must contain exactly the four reviewed services.");
  return Object.freeze([...services].sort());
}

export function buildStageBImagePublicationIdentity({ observed, artifactBytes, expectedPublicationSourceSha, expectedReleaseSha, observedAt = new Date().toISOString() } = {}) {
  assertObservedMetadata(observed, { expectedPublicationSourceSha, expectedReleaseSha });
  if (!Buffer.isBuffer(artifactBytes)) throw new Error("Stage B publication artifact bytes are required.");
  if (!ISO.test(observedAt) || !Number.isFinite(Date.parse(observedAt))) throw new Error("Stage B publication observation timestamp is malformed.");
  const canonicalArtifactSha256 = sha256(artifactBytes);
  const report = {
    schemaVersion: STAGE_B_IMAGE_PUBLICATION_IDENTITY_SCHEMA_VERSION,
    workflowRunId: String(observed.workflowRunId),
    workflowDatabaseId: String(observed.workflowDatabaseId),
    workflowFile: observed.workflowFile,
    workflowName: observed.workflowName,
    event: observed.event,
    workflowDefinitionSha: observed.workflowDefinitionSha,
    imageReleaseSha: observed.imageReleaseSha,
    headBranch: observed.headBranch,
    conclusion: observed.conclusion,
    artifactId: String(observed.artifactId),
    artifactName: observed.artifactName,
    artifactExpired: observed.artifactExpired,
    artifactArchiveFilename: observed.artifactArchiveFilename ?? null,
    canonicalFilename: STAGE_B_IMAGE_CANONICAL_FILENAME,
    canonicalArtifactSha256,
    recordCount: STAGE_B_IMAGE_SERVICES.length,
    services: parseServices(artifactBytes),
    observedAt,
  };
  assertStageBImagePublicationIdentity(report, { expectedPublicationSourceSha, expectedReleaseSha });
  return Object.freeze(report);
}

export function assertStageBImagePublicationIdentity(identity, { expectedPublicationSourceSha, expectedReleaseSha, canonicalArtifactSha256 } = {}) {
  if (!identity || identity.schemaVersion !== STAGE_B_IMAGE_PUBLICATION_IDENTITY_SCHEMA_VERSION) throw new Error("Stage B publication identity report is missing or versioned incorrectly.");
  assertObservedMetadata(identity, { expectedPublicationSourceSha, expectedReleaseSha });
  requireExact(identity.canonicalFilename, STAGE_B_IMAGE_CANONICAL_FILENAME, "canonical filename");
  if (identity.canonicalArtifactSha256 !== canonicalArtifactSha256 && canonicalArtifactSha256 !== undefined) throw new Error("Stage B publication identity canonical artifact SHA256 does not match the observed artifact.");
  if (!DIGEST.test(String(identity.canonicalArtifactSha256 || "")) || identity.recordCount !== STAGE_B_IMAGE_SERVICES.length || JSON.stringify(identity.services) !== JSON.stringify([...STAGE_B_IMAGE_SERVICES].sort()) || !ISO.test(identity.observedAt) || !Number.isFinite(Date.parse(identity.observedAt))) throw new Error("Stage B publication identity report is malformed.");
  return true;
}

export function publicationIdentitySha256(identity) {
  return sha256(Buffer.from(`${JSON.stringify(identity)}\n`));
}

export function readStageBImagePublicationIdentity(identityPath, { identitySha256, expectedPublicationSourceSha, expectedReleaseSha, canonicalArtifactBytes } = {}) {
  const stat = fs.lstatSync(identityPath);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600) throw new Error("Stage B publication identity must be a private regular file.");
  const bytes = fs.readFileSync(identityPath);
  const identity = JSON.parse(bytes.toString("utf8"));
  if (publicationIdentitySha256(identity) !== identitySha256) throw new Error("Stage B publication identity report SHA256 does not match.");
  if (!Buffer.isBuffer(canonicalArtifactBytes)) throw new Error("Canonical artifact bytes are required for publication identity binding.");
  assertStageBImagePublicationIdentity(identity, { expectedPublicationSourceSha, expectedReleaseSha, canonicalArtifactSha256: sha256(canonicalArtifactBytes) });
  if (sha256(canonicalArtifactBytes) !== identity.canonicalArtifactSha256) throw new Error("Stage B publication identity is not bound to the canonical artifact bytes.");
  return identity;
}

export function writeStageBImagePublicationIdentity({ observed, artifactBytes, expectedPublicationSourceSha, expectedReleaseSha, outputPath, repositoryRoot } = {}) {
  const identityPath = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot, label: "Stage B publication identity", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(identityPath), repositoryRoot, create: true });
  const identity = buildStageBImagePublicationIdentity({ observed, artifactBytes, expectedPublicationSourceSha, expectedReleaseSha });
  writeStageBPrivateFilesAtomic({ repositoryRoot, files: [{ filePath: identityPath, bytes: Buffer.from(`${JSON.stringify(identity)}\n`), label: "Stage B publication identity" }] });
  return { identityPath, identitySha256: publicationIdentitySha256(identity), identity };
}
