#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { assertSecurityRebaselineInventory, SECURITY_REBASELINE_COLLECTOR_VERSION } from "./production-security-rebaseline-inventory.mjs";
import { buildSecurityRebaselineImageAuthorization, createProductionSecurityRebaselinePreparationManifest, productionSubscriptionProjectionContractSha256, SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW, SECURITY_REBASELINE_SIGNING_ALGORITHM, SECURITY_REBASELINE_SIGNING_KEY_ALIAS } from "./production-security-rebaseline-preparation.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const files = Object.freeze({
  requirements: "app-only-requirements.json",
  canonical: "security-rebaseline-canonical.json",
  publication: "stage-b-images.jsonl",
  manifest: "preparation-manifest.json",
});

function readReference(name, env, publication = false) {
  const value = JSON.parse(env[name] || "null");
  const fields = ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256", ...(publication ? ["workflowFile"] : [])];
  assert.deepEqual(Object.keys(value || {}).sort(), fields.sort());
  return value;
}

function kmsSign({ keyArn, signingAlgorithm, messageType, digest }) {
  assert.equal(keyArn, SECURITY_REBASELINE_SIGNING_KEY_ALIAS); assert.equal(signingAlgorithm, SECURITY_REBASELINE_SIGNING_ALGORITHM);
  assert.equal(messageType, "DIGEST"); assert.ok(Buffer.isBuffer(digest) && digest.length === 32);
  const identity = JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--region", "eu-west-2", "--output", "json", "--no-cli-pager"], { encoding: "utf8", timeout: 10000, maxBuffer: 4096, stdio: ["ignore", "pipe", "pipe"] }));
  assert.equal(identity.Account, "368992683803");
  assert.match(identity.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-security-rebaseline-image-signer\/[A-Za-z0-9+=,.@_-]+$/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-security-rebaseline-sign-"));
  try {
    fs.chmodSync(dir, 0o700); const file = path.join(dir, "digest"); fs.writeFileSync(file, digest, { flag: "wx", mode: 0o600 });
    const result = JSON.parse(execFileSync("aws", ["kms", "sign", "--region", "eu-west-2", "--key-id", keyArn, "--message", `fileb://${file}`,
      "--message-type", messageType, "--signing-algorithm", signingAlgorithm, "--output", "json", "--no-cli-pager"], { encoding: "utf8", timeout: 15000, maxBuffer: 16384, stdio: ["ignore", "pipe", "pipe"] }));
    assert.match(result.Signature || "", /^[A-Za-z0-9+/]+={0,2}$/); return result.Signature;
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

export function produceSecurityRebaselinePreparation({ sourceSha, repositoryRoot = root, env = process.env, sign = kmsSign } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(env.GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main"); assert.equal(env.GITHUB_REPOSITORY_ID, "1145608538"); assert.equal(env.GITHUB_REPOSITORY_OWNER_ID, "183396573");
  assert.equal(env.GITHUB_REF, "refs/heads/main"); assert.equal(env.GITHUB_SHA, sourceSha); assert.equal(env.GITHUB_RUN_ATTEMPT, "1");
  assert.equal(env.GITHUB_WORKFLOW_REF, "T-ej2003/genuine-scan-main/.github/workflows/prepare-production-security-rebaseline.yml@refs/heads/main");
  assert.equal(env.GITHUB_ACTOR, "T-ej2003"); assert.match(env.GITHUB_RUN_ID || "", /^[1-9][0-9]*$/);
  const requirementsBytes = fs.readFileSync(path.resolve(env.REQUIREMENTS_FILE || files.requirements));
  const canonicalBytes = fs.readFileSync(path.resolve(env.CANONICAL_FILE || files.canonical));
  const publicationBytes = fs.readFileSync(path.resolve(env.PUBLICATION_FILE || files.publication));
  const requirements = JSON.parse(requirementsBytes); const canonical = JSON.parse(canonicalBytes);
  assertAppOnlyRequirements(requirements, { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  assertSecurityRebaselineInventory(canonical, { protectedMainSha: sourceSha, candidateSourceSha: sourceSha });
  assert.equal(canonical.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY"); assert.equal(canonical.appOnlyRequirementsSha256, requirements.requirementsSha256);
  assert.equal(canonical.collectorVersion, SECURITY_REBASELINE_COLLECTOR_VERSION);
  const references = {
    requirements: readReference("REQUIREMENTS_REFERENCE_JSON", env),
    canonical: readReference("CANONICAL_REFERENCE_JSON", env),
    publication: readReference("PUBLICATION_REFERENCE_JSON", env, true),
  };
  for (const reference of Object.values(references)) {
    assert.equal(reference.sourceSha, sourceSha); assert.equal(String(reference.runId), env.GITHUB_RUN_ID); assert.equal(String(reference.runAttempt), env.GITHUB_RUN_ATTEMPT);
  }
  assert.equal(sha256(requirementsBytes), references.requirements.fileSha256); assert.equal(sha256(canonicalBytes), references.canonical.fileSha256);
  assert.equal(sha256(publicationBytes), references.publication.fileSha256);
  const rows = publicationBytes.toString("utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(rows.length, 1);
  const [backend] = rows;
  assert.equal(backend.service, "backend"); assert.equal(backend.repository, "mscqr-backend");
  assert.equal(backend.image_tag, `${sourceSha}-backend-only`);
  assert.equal(backend.image_uri, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend:${sourceSha}-backend-only`);
  assert.match(backend.image_digest || "", /^[a-f0-9]{64}$/);
  assert.equal(backend.image_ref, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${backend.image_digest}`);
  assert.equal(backend.image_ref, env.EXPECTED_IMAGE_REF);
  const publication = { workflowFile: SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW, ...references.publication };
  const authorization = buildSecurityRebaselineImageAuthorization({
    protectedMainSha: sourceSha, candidateSourceSha: sourceSha, imageRepository: backend.repository, imageDigest: `sha256:${backend.image_digest}`,
    publication, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT,
    workflowRef: env.GITHUB_WORKFLOW_REF, repositoryId: env.GITHUB_REPOSITORY_ID, ownerId: env.GITHUB_REPOSITORY_OWNER_ID,
    actor: env.GITHUB_ACTOR, sign,
  });
  const projectionContractSha256 = productionSubscriptionProjectionContractSha256(repositoryRoot);
  const manifest = createProductionSecurityRebaselinePreparationManifest({
    protectedMainSha: sourceSha, candidateSourceSha: sourceSha, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT,
    requirements, requirementsBytes, requirementsReference: references.requirements,
    canonicalInventory: canonical, canonicalInventoryBytes: canonicalBytes, canonicalReference: references.canonical,
    imageAuthorization: authorization,
    publicationReference: references.publication, probeImageDigest: authorization.image.digest,
    sourceContractSha256: requirements.sourceContractSha256, migrationSetDigest: requirements.migrationSetDigest,
    packageChecksumsSha256: requirements.canonicalPackageChecksumsSha256, subscriptionProjectionSha256: projectionContractSha256,
  });
  const output = path.resolve(env.MANIFEST_OUTPUT || files.manifest);
  fs.writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  return Object.freeze({ output, manifestSha256: manifest.manifestSha256, sourceSha, candidateSourceSha: sourceSha,
    requirementsSha256: requirements.requirementsSha256, canonicalInventorySha256: canonical.catalogueSha256,
    candidateImageDigest: backend.image_digest, probeImageDigest: authorization.image.digest });
}

function parseArgs(argv) {
  assert.equal(argv.length, 2, "Expected exactly --source-sha <40-character SHA>"); assert.equal(argv[0], "--source-sha"); assert.match(argv[1] || "", /^[a-f0-9]{40}$/); return argv[1];
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { process.stdout.write(`${JSON.stringify(produceSecurityRebaselinePreparation({ sourceSha: parseArgs(process.argv.slice(2)) }))}\n`); }
  catch { process.stderr.write("Security rebaseline preparation failed closed; no production probe was dispatched.\n"); process.exitCode = 1; }
}
