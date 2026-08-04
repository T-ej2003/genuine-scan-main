#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from "./production-green-stage-b-contract.mjs";
import { APPROVED_PREFLIGHT_GENERATOR_ARNS } from "./validate-production-green-stage-b-permissions.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "./stage-b-reference-audit-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

export const IMAGE_EVIDENCE_SCHEMA_VERSION = 3;
export const IMAGE_EVIDENCE_SIGNATURE_SCHEMA_VERSION = 3;
export const IMAGE_EVIDENCE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
export const IMAGE_EVIDENCE_CLOCK_SKEW_MS = 60 * 1000;
export const IMAGE_EVIDENCE_VALIDITY_MODEL = "immutable-image-provenance-24h";
export const IMAGE_EVIDENCE_REPOSITORY_MUTABILITY = "IMMUTABLE";
export const IMAGE_EVIDENCE_REVOCATION_MODEL = "time-bounded-no-supersession-registry";
export const IMAGE_EVIDENCE_SIGNING_KEY_ARN = STAGE_B.approvalKmsKeyArn;
export const IMAGE_EVIDENCE_SIGNING_ALGORITHM = STAGE_B_APPROVAL_ALGORITHM;
export const APPROVED_IMAGE_EVIDENCE_VERIFIER_ARNS = APPROVED_PREFLIGHT_GENERATOR_ARNS;
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const SERVICES = Object.freeze({
  backend: { repository: "mscqr-backend", tag: (sha) => sha },
  worker: { repository: "mscqr-worker", tag: (sha) => sha },
  "rls-executor": { repository: "mscqr-backend", tag: (sha) => `${sha}-rls-executor` },
  "rls-canary": { repository: "mscqr-backend", tag: (sha) => `${sha}-rls-canary` },
});

export const STAGE_B_PLAN_IMAGE_BINDINGS = Object.freeze({
  backend_image: { service: "backend", repository: "mscqr-backend" },
  worker_image: { service: "worker", repository: "mscqr-worker" },
  executor_image: { service: "rls-executor", repository: "mscqr-backend" },
  canary_image: { service: "rls-canary", repository: "mscqr-backend" },
  read_only_canary_image: { service: "rls-canary", repository: "mscqr-backend" },
});

const currentTaskImageService = (address) => {
  if (address.startsWith("aws_ecs_task_definition.executor[")) return "rls-executor";
  const key = /\["([^"]+)"\]$/.exec(address)?.[1];
  return key === "backend" ? "backend" : key === "worker" ? "worker" : key === "canary" || key === "read_only_canary" ? "rls-canary" : undefined;
};

const currentTaskImageVariable = (address) => {
  if (address.startsWith("aws_ecs_task_definition.executor[")) return "executor_image";
  const key = /\["([^"]+)"\]$/.exec(address)?.[1];
  return key === "backend" ? "backend_image" : key === "worker" ? "worker_image" : key === "canary" ? "canary_image" : key === "read_only_canary" ? "read_only_canary_image" : undefined;
};

const taskDefinitionsFromPlan = (value, address) => {
  let definitions = value;
  if (typeof definitions === "string") {
    try { definitions = JSON.parse(definitions); } catch { throw new Error(`Stage B planned task-definition container definitions are malformed: ${address}`); }
  }
  if (!Array.isArray(definitions) || definitions.length !== 1 || typeof definitions[0]?.image !== "string") throw new Error(`Stage B planned task-definition image contract is malformed: ${address}`);
  return definitions;
};

export function assertStageBPlanImageEvidenceBinding({ plan, imageEvidence } = {}) {
  if (!plan || !imageEvidence) throw new Error("Stage B signed image evidence and Terraform plan are required for image binding.");
  const reportImages = new Map();
  if (!Array.isArray(imageEvidence.images) || imageEvidence.images.length !== Object.keys(SERVICES).length) throw new Error("Stage B signed image evidence must contain exactly four image records.");
  for (const image of imageEvidence.images) {
    if (reportImages.has(image.service)) throw new Error(`Stage B signed image evidence contains duplicate service records: ${image.service}`);
    if (!Object.values(SERVICES).some((contract) => contract.repository === image.repository) || !/^sha256:[a-f0-9]{64}$/.test(image.digest || "")) throw new Error(`Stage B signed image evidence contains an invalid image record: ${image.service}`);
    reportImages.set(image.service, image);
  }
  const bindings = {};
  for (const [variable, contract] of Object.entries(STAGE_B_PLAN_IMAGE_BINDINGS)) {
    const record = reportImages.get(contract.service);
    if (!record || record.repository !== contract.repository) throw new Error(`Stage B signed image evidence is missing the required ${contract.service} binding.`);
    const expectedReference = `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/${contract.repository}@${record.digest}`;
    const actual = plan.variables?.[variable]?.value;
    if (typeof actual !== "string") throw new Error(`Stage B Terraform image variable is missing: ${variable}`);
    if (actual !== expectedReference) throw new Error(`Stage B Terraform image variable ${variable} does not match authenticated ${contract.service} digest.`);
    bindings[variable] = Object.freeze({ repository: contract.repository, digest: record.digest, imageReference: expectedReference });
  }

  const currentChanges = (plan.resource_changes || []).filter((change) => Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, change.address));
  const currentAddresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
  if (currentChanges.length !== currentAddresses.length || new Set(currentChanges.map((change) => change.address)).size !== currentAddresses.length) throw new Error("Stage B plan image binding requires exactly the twelve current task-definition addresses.");
  for (const change of currentChanges) {
    if (change.type !== "aws_ecs_task_definition") throw new Error(`Stage B current task-definition resource type is invalid: ${change.address}`);
    const actions = change.change?.actions || [];
    if (!actions.length || !actions.every((action) => action === "create" || action === "no-op")) throw new Error(`Stage B current task-definition actions are invalid: ${change.address}`);
    const service = currentTaskImageService(change.address);
    const variable = currentTaskImageVariable(change.address);
    const expected = bindings[variable];
    if (!expected) throw new Error(`Stage B task-definition image mapping is unsupported: ${change.address}`);
    const definitions = taskDefinitionsFromPlan(change.change?.after?.container_definitions, change.address);
    if (definitions[0].image !== expected.imageReference) throw new Error(`Stage B task-definition image does not match authenticated ${service} digest: ${change.address}`);
  }
  return Object.freeze({
    backend: bindings.backend_image,
    worker: bindings.worker_image,
    executor: bindings.executor_image,
    applicationCanary: bindings.canary_image,
    readOnlyCanary: bindings.read_only_canary_image,
  });
}

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
export const canonicalizeImageEvidence = (value) => canonicalJson(value);
export const imageEvidenceSha256 = (value) => sha256(Buffer.from(canonicalizeImageEvidence(value)));

const withTempBytes = (prefix, files, callback) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    const paths = Object.fromEntries(Object.entries(files).map(([name, bytes]) => {
      const filePath = path.join(directory, name);
      fs.writeFileSync(filePath, bytes, { mode: 0o600, flag: "wx" });
      return [name, filePath];
    }));
    return callback(paths);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
};

function requireImageReleaseSha(value) {
  if (!/^[a-f0-9]{40}$/.test(String(value || ""))) throw new Error("Image evidence image-release SHA must be a full 40-character SHA.");
  return value;
}

function requireDigest(value, label) {
  if (!/^sha256:[a-f0-9]{64}$/.test(String(value || ""))) throw new Error(`${label} must be an immutable SHA256 digest.`);
  return value;
}

function requireVerifier(callerArn) {
  if (!APPROVED_IMAGE_EVIDENCE_VERIFIER_ARNS.includes(callerArn)) throw new Error("Image evidence verifier is not an approved administrator identity.");
  return callerArn;
}

function parseArtifact(artifactBytes, { imageReleaseSha, artifactSha256 }) {
  if (sha256(artifactBytes) !== artifactSha256) throw new Error("Canonical image artifact SHA256 does not match the approved digest.");
  const records = artifactBytes.toString("utf8").trim().split(/\n/).filter(Boolean).map((line) => JSON.parse(line));
  if (records.length !== Object.keys(SERVICES).length || new Set(records.map((record) => record.service)).size !== records.length) {
    throw new Error("Canonical image artifact must contain exactly one record for each Stage B image.");
  }
  return Object.entries(SERVICES).map(([service, contract]) => {
    const record = records.find((candidate) => candidate.service === service);
    const tag = contract.tag(imageReleaseSha);
    const expectedImageUri = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${contract.repository}:${tag}`;
    const expectedImageRef = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${contract.repository}@${record?.image_digest || ""}`;
    if (!record || record.repository !== contract.repository || record.image_tag !== tag || record.image_uri !== expectedImageUri || record.image_ref !== expectedImageRef) {
      throw new Error(`Canonical image artifact binding is invalid for ${service}.`);
    }
    if (!record.image_uri.endsWith(`:${tag}`) || !record.image_ref.endsWith(`@${record.image_digest}`)) throw new Error(`Canonical image artifact digest binding is invalid for ${service}.`);
    return { service, repository: record.repository, tag, digest: requireDigest(record.image_digest, `${service} digest`) };
  }).sort((a, b) => a.service.localeCompare(b.service));
}

function describeImages(repository, tag) {
  return JSON.parse(execFileSync("aws", [
    "ecr", "describe-images", "--region", STAGE_B.region, "--repository-name", repository, "--image-ids", `imageTag=${tag}`, "--output", "json", "--no-cli-pager",
  ], { encoding: "utf8" }));
}

export function readImageEvidence(repository, tag, { describe = describeImages } = {}) {
  const response = describe(repository, tag);
  if (!response || !Array.isArray(response.imageDetails) || response.imageDetails.length !== 1) throw new Error(`ECR evidence must resolve exactly one image for ${repository}:${tag}.`);
  const image = response.imageDetails[0];
  if (!image.imageDigest || !image.imagePushedAt) throw new Error(`ECR evidence is incomplete for ${repository}:${tag}.`);
  return { digest: requireDigest(image.imageDigest, `${repository}:${tag} digest`), imagePushedAt: image.imagePushedAt };
}

function describeImage(repository, tag, describe = describeImages) {
  return readImageEvidence(repository, tag, { describe });
}

function describeRepositories(repository) {
  return JSON.parse(execFileSync("aws", [
    "ecr", "describe-repositories", "--registry-id", STAGE_B.account, "--region", STAGE_B.region, "--repository-names", repository, "--output", "json", "--no-cli-pager",
  ], { encoding: "utf8" }));
}

const IMAGE_REPOSITORY_EVIDENCE_KEYS = new Set(["repositoryName", "repositoryArn", "registryId", "repositoryUri", "imageTagMutability", "imageTagMutabilityExclusionFilters", "encryptionConfiguration", "createdAt", "observedAt"]);

function normalizeRepositoryEvidence(evidence, requiredRepository, observedAt) {
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) throw new Error(`Image repository evidence is malformed: ${requiredRepository}.`);
  const repository = String(evidence.repositoryName || "");
  const expectedArn = `arn:aws:ecr:${STAGE_B.region}:${STAGE_B.account}:repository/${requiredRepository}`;
  const expectedUri = `${STAGE_B.account}.dkr.ecr.${STAGE_B.region}.amazonaws.com/${requiredRepository}`;
  const observedAtMs = Date.parse(observedAt);
  const evidenceObservedAt = evidence.observedAt || observedAt;
  if (repository !== requiredRepository || evidence.repositoryArn !== expectedArn || String(evidence.registryId) !== STAGE_B.account) throw new Error(`Image repository evidence identity is wrong: ${requiredRepository}.`);
  if (evidence.repositoryUri !== expectedUri) throw new Error(`Image repository URI is wrong: ${requiredRepository}.`);
  if (evidence.imageTagMutability !== IMAGE_EVIDENCE_REPOSITORY_MUTABILITY) throw new Error(`Image repository ${requiredRepository} is not authoritatively immutable.`);
  if (evidence.imageTagMutabilityExclusionFilters?.length) throw new Error(`Image repository ${requiredRepository} uses unsupported mutability exclusions.`);
  if (evidence.imageTagMutabilityExclusionFilters !== undefined && !Array.isArray(evidence.imageTagMutabilityExclusionFilters)) throw new Error(`Image repository exclusion evidence is malformed: ${requiredRepository}.`);
  if (!evidence.encryptionConfiguration || typeof evidence.encryptionConfiguration !== "object" || Array.isArray(evidence.encryptionConfiguration)) throw new Error(`Image repository encryption evidence is malformed: ${requiredRepository}.`);
  if (!Number.isFinite(Date.parse(evidence.createdAt))) throw new Error(`Image repository creation evidence is malformed: ${requiredRepository}.`);
  if (!Number.isFinite(observedAtMs) || Date.parse(evidenceObservedAt) !== observedAtMs) throw new Error(`Image repository evidence timestamp is malformed: ${requiredRepository}.`);
  const unsupported = Object.keys(evidence).find((key) => !IMAGE_REPOSITORY_EVIDENCE_KEYS.has(key));
  if (unsupported) throw new Error(`Image repository evidence has unsupported field ${unsupported}: ${requiredRepository}.`);
  return Object.freeze({
    repositoryName: requiredRepository,
    repositoryArn: expectedArn,
    registryId: STAGE_B.account,
    repositoryUri: expectedUri,
    imageTagMutability: IMAGE_EVIDENCE_REPOSITORY_MUTABILITY,
    ...(evidence.imageTagMutabilityExclusionFilters === undefined ? {} : { imageTagMutabilityExclusionFilters: Object.freeze([...evidence.imageTagMutabilityExclusionFilters]) }),
    encryptionConfiguration: Object.freeze({ ...evidence.encryptionConfiguration }),
    createdAt: evidence.createdAt,
    observedAt: evidenceObservedAt,
  });
}

function rejectLegacyProvenanceClaims(report) {
  if (Object.hasOwn(report || {}, "immutableTagProof") || Object.hasOwn(report || {}, "superseded")) throw new Error("Image evidence schema contains unsupported legacy provenance claims.");
}

function requireRepositoryEvidence(repositories, requiredRepositories, observedAt) {
  if (!Array.isArray(repositories) || repositories.length !== requiredRepositories.length) throw new Error("Image evidence must include exactly one authoritative repository record per image repository.");
  const expected = new Set(requiredRepositories);
  const seen = new Set();
  return repositories.map((evidence) => {
    const repository = String(evidence?.repositoryName || "");
    if (!expected.has(repository) || seen.has(repository)) throw new Error(`Image repository evidence is missing, duplicated, or unexpected: ${repository}.`);
    const normalized = normalizeRepositoryEvidence(evidence, repository, observedAt);
    seen.add(repository);
    return normalized;
  }).sort((a, b) => a.repositoryName.localeCompare(b.repositoryName));
}

export function readImageRepositoryEvidence(repository, { observedAt = new Date().toISOString(), describe = describeRepositories } = {}) {
  const response = describe(repository);
  if (!response || typeof response !== "object" || Array.isArray(response) || !Array.isArray(response.repositories) || response.repositories.length !== 1) throw new Error(`ECR repository evidence must resolve exactly one repository for ${repository}.`);
  const source = response.repositories[0];
  return normalizeRepositoryEvidence({
    repositoryName: source.repositoryName,
    repositoryArn: source.repositoryArn,
    registryId: String(source.registryId || ""),
    repositoryUri: source.repositoryUri,
    imageTagMutability: source.imageTagMutability,
    ...(source.imageTagMutabilityExclusionFilters === undefined ? {} : { imageTagMutabilityExclusionFilters: source.imageTagMutabilityExclusionFilters }),
    encryptionConfiguration: source.encryptionConfiguration,
    createdAt: source.createdAt,
    observedAt,
  }, repository, observedAt);
}

export function generateImageEvidence({ artifactBytes, imageReleaseSha, workflowRunId, artifactSha256, verifierCallerArn, observedAt = new Date().toISOString(), describe = describeImage, repositories }) {
  requireImageReleaseSha(imageReleaseSha);
  if (!/^\d+$/.test(String(workflowRunId || ""))) throw new Error("Canonical workflow run ID is required.");
  requireVerifier(verifierCallerArn);
  const observedAtMs = Date.parse(observedAt);
  if (!Number.isFinite(observedAtMs)) throw new Error("Image evidence observation timestamp is malformed.");
  const artifactImages = parseArtifact(artifactBytes, { imageReleaseSha, artifactSha256 });
  const repositoryEvidence = requireRepositoryEvidence(repositories, [...new Set(artifactImages.map(({ repository }) => repository))], observedAt);
  const images = artifactImages.map((image) => {
    const live = describe(image.repository, image.tag);
    if (live.digest !== image.digest) throw new Error(`ECR digest does not match canonical artifact for ${image.service}.`);
    return { ...image, ...live };
  }).sort((a, b) => a.service.localeCompare(b.service));
  return {
    schemaVersion: IMAGE_EVIDENCE_SCHEMA_VERSION,
    imageReleaseSha,
    workflowRunId: String(workflowRunId),
    canonicalArtifactSha256: artifactSha256,
    verifierCallerArn,
    account: STAGE_B.account,
    region: STAGE_B.region,
    observedAt,
    revocationModel: IMAGE_EVIDENCE_REVOCATION_MODEL,
    repositories: repositoryEvidence,
    images,
  };
}

export function signImageEvidence(report, { now = new Date().toISOString(), keyArn = IMAGE_EVIDENCE_SIGNING_KEY_ARN, signingAlgorithm = IMAGE_EVIDENCE_SIGNING_ALGORITHM, sign = ({ digest }) => withTempBytes("stage-b-image-evidence-sign-", { digest }, ({ digest: digestPath }) => JSON.parse(execFileSync("aws", ["kms", "sign", "--key-id", keyArn, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm, "--output", "json"], { encoding: "utf8" })).Signature) } = {}) {
  if (report?.schemaVersion !== IMAGE_EVIDENCE_SCHEMA_VERSION) throw new Error("Only a valid image-evidence report may be signed.");
  rejectLegacyProvenanceClaims(report);
  requireRepositoryEvidence(report.repositories, [...new Set((report.images || []).map(({ repository }) => repository))], report.observedAt);
  if (report.revocationModel !== IMAGE_EVIDENCE_REVOCATION_MODEL) throw new Error("Image evidence revocation model is unsupported.");
  if (keyArn !== IMAGE_EVIDENCE_SIGNING_KEY_ARN || signingAlgorithm !== IMAGE_EVIDENCE_SIGNING_ALGORITHM) throw new Error("Image evidence signing contract is wrong.");
  const reportSha256 = imageEvidenceSha256(report);
  const signatureBase64 = String(sign({ keyArn, signingAlgorithm, digest: Buffer.from(reportSha256, "hex"), reportSha256 }) || "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureBase64)) throw new Error("Image evidence signing returned an invalid signature.");
  return { schemaVersion: IMAGE_EVIDENCE_SIGNATURE_SCHEMA_VERSION, keyId: keyArn, keyArn, signingAlgorithm, reportSha256, imageReleaseSha: report.imageReleaseSha, workflowRunId: report.workflowRunId, canonicalArtifactSha256: report.canonicalArtifactSha256, signatureBase64, signedAt: now };
}

export function verifyImageEvidenceSignature({ report, signatureArtifact, now = new Date().toISOString(), keyArn = IMAGE_EVIDENCE_SIGNING_KEY_ARN, signingAlgorithm = IMAGE_EVIDENCE_SIGNING_ALGORITHM, verify = ({ digest, signature }) => withTempBytes("stage-b-image-evidence-verify-", { digest, signature }, ({ digest: digestPath, signature: signaturePath }) => JSON.parse(execFileSync("aws", ["kms", "verify", "--key-id", keyArn, "--message", `fileb://${digestPath}`, "--message-type", "DIGEST", "--signature", `fileb://${signaturePath}`, "--signing-algorithm", signingAlgorithm, "--output", "json"], { encoding: "utf8" })).SignatureValid === true) }) {
  rejectLegacyProvenanceClaims(report);
  if (report?.schemaVersion !== IMAGE_EVIDENCE_SCHEMA_VERSION || report.revocationModel !== IMAGE_EVIDENCE_REVOCATION_MODEL) throw new Error("Image evidence revocation model or schema is unsupported.");
  requireRepositoryEvidence(report.repositories, [...new Set((report.images || []).map(({ repository }) => repository))], report.observedAt);
  if (!signatureArtifact || signatureArtifact.schemaVersion !== IMAGE_EVIDENCE_SIGNATURE_SCHEMA_VERSION || signatureArtifact.keyId !== keyArn || signatureArtifact.keyArn !== keyArn || signatureArtifact.signingAlgorithm !== signingAlgorithm || signatureArtifact.imageReleaseSha !== report?.imageReleaseSha || String(signatureArtifact.workflowRunId) !== String(report?.workflowRunId) || signatureArtifact.canonicalArtifactSha256 !== report?.canonicalArtifactSha256) throw new Error("Image evidence signature identity or algorithm is wrong.");
  const reportSha256 = imageEvidenceSha256(report);
  if (signatureArtifact.reportSha256 !== reportSha256) throw new Error("Image evidence signature is bound to a different report.");
  const signedAtMs = Date.parse(signatureArtifact.signedAt); const nowMs = Date.parse(now);
  if (!Number.isFinite(signedAtMs) || signedAtMs > nowMs + IMAGE_EVIDENCE_CLOCK_SKEW_MS || nowMs - signedAtMs > IMAGE_EVIDENCE_MAX_AGE_MS) throw new Error("Image evidence signature is stale or malformed.");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(signatureArtifact.signatureBase64 || "")) throw new Error("Image evidence signature is malformed.");
  if (!verify({ keyArn, signingAlgorithm, digest: Buffer.from(reportSha256, "hex"), signature: Buffer.from(signatureArtifact.signatureBase64, "base64"), reportSha256 })) throw new Error("Image evidence signature verification failed.");
  return true;
}

export function assertImageEvidence(report, { signatureArtifact, verifySignature = verifyImageEvidenceSignature, imageReleaseSha, workflowRunId, artifactSha256, now = new Date().toISOString() } = {}) {
  rejectLegacyProvenanceClaims(report);
  if (!verifySignature({ report, signatureArtifact, now })) throw new Error("Authenticated image evidence signature verification failed.");
  if (report?.schemaVersion !== IMAGE_EVIDENCE_SCHEMA_VERSION || report.imageReleaseSha !== imageReleaseSha || String(report.workflowRunId) !== String(workflowRunId) || report.canonicalArtifactSha256 !== artifactSha256) throw new Error("Image evidence is bound to a different image release, workflow, or canonical artifact.");
  if (report.revocationModel !== IMAGE_EVIDENCE_REVOCATION_MODEL) throw new Error("Image evidence revocation model is unsupported.");
  requireVerifier(report.verifierCallerArn);
  if (report.account !== STAGE_B.account || report.region !== STAGE_B.region) throw new Error("Image evidence account or region is wrong.");
  const observedAtMs = Date.parse(report.observedAt); const nowMs = Date.parse(now);
  if (!Number.isFinite(observedAtMs) || !Number.isFinite(nowMs) || observedAtMs > nowMs + IMAGE_EVIDENCE_CLOCK_SKEW_MS || nowMs - observedAtMs > IMAGE_EVIDENCE_MAX_AGE_MS) throw new Error("Image evidence observation is stale or malformed.");
  if (!Array.isArray(report.images) || report.images.length !== Object.keys(SERVICES).length || new Set(report.images.map((image) => image.service)).size !== report.images.length) throw new Error("Image evidence does not contain all four Stage B images.");
  requireRepositoryEvidence(report.repositories, [...new Set(Object.values(SERVICES).map(({ repository }) => repository))], report.observedAt);
  for (const [service, contract] of Object.entries(SERVICES)) {
    const image = report.images.find((candidate) => candidate.service === service);
    if (!image || image.repository !== contract.repository || image.tag !== contract.tag(imageReleaseSha) || !/^sha256:[a-f0-9]{64}$/.test(image.digest) || !image.imagePushedAt) throw new Error(`Image evidence is incomplete for ${service}.`);
  }
  return true;
}

function requiredOption(argv, option) { const index = argv.indexOf(option); const value = index === -1 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${option} is required.`); return value; }

export function runCli(argv = process.argv.slice(2), deps = {}) {
  const artifactPath = requiredOption(argv, "--artifact"); const imageReleaseSha = requiredOption(argv, "--image-release-sha"); const workflowRunId = requiredOption(argv, "--workflow-run-id"); const artifactSha256 = requiredOption(argv, "--artifact-sha256"); const outputPath = assertStageBArtifactPath({ artifactPath: requiredOption(argv, "--output"), repositoryRoot, label: "Stage B image evidence", allowExisting: false }); const signaturePath = assertStageBArtifactPath({ artifactPath: requiredOption(argv, "--signature-output"), repositoryRoot, label: "Stage B image-evidence signature", allowExisting: false });
  if (path.dirname(outputPath) !== path.dirname(signaturePath)) throw new Error("Stage B image evidence and signature must use one private directory.");
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot, create: true });
  const verifierCallerArn = deps.getCaller ? deps.getCaller() : JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], { encoding: "utf8" })).Arn;
  const observedAt = deps.observedAt || new Date().toISOString();
  const repositories = [...new Set(Object.values(SERVICES).map(({ repository }) => repository))].map((repository) => readImageRepositoryEvidence(repository, { observedAt, describe: deps.describeRepository || describeRepositories }));
  const report = generateImageEvidence({ artifactBytes: fs.readFileSync(artifactPath), imageReleaseSha, workflowRunId, artifactSha256, verifierCallerArn, describe: deps.describe || describeImage, observedAt, repositories });
  const signature = (deps.sign || signImageEvidence)(report, deps.sign ? { sign: deps.sign, now: deps.now } : {});
  writeStageBPrivateFilesAtomic({ repositoryRoot, files: [
    { filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(report, null, 2)}\n`), label: "Stage B image evidence" },
    { filePath: signaturePath, bytes: Buffer.from(`${JSON.stringify(signature, null, 2)}\n`), label: "Stage B image-evidence signature" },
  ] });
  return { outputPath, signaturePath, reportSha256: imageEvidenceSha256(report) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(runCli(), null, 2)); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
