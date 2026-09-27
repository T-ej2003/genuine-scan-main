import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertAppOnlyRequirements } from "./production-app-only-requirements.mjs";
import { cleanRoomRepoRoot } from "../rls/lib/clean-room-source-contract.mjs";
import { assertSecurityRebaselineInventory, SECURITY_REBASELINE_COLLECTOR_VERSION } from "./production-security-rebaseline-inventory.mjs";
import { SUBSCRIPTION_PROJECTION_STATUS_CONTRACT } from "./production-app-only-database-verifier.mjs";

export const SECURITY_REBASELINE_IMAGE_AUTHORIZATION_PURPOSE = "READ_ONLY_PRODUCTION_SECURITY_REBASELINE";
export const SECURITY_REBASELINE_SIGNING_KEY_ALIAS = "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-security-rebaseline-image-evidence";
export const SECURITY_REBASELINE_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256";
export const SECURITY_REBASELINE_SIGNER_WORKFLOW = ".github/workflows/prepare-production-security-rebaseline.yml";
export const SECURITY_REBASELINE_SIGNER_JOB_WORKFLOW = ".github/workflows/sign-production-security-rebaseline.yml";
export const SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW = ".github/workflows/production-green-backend-image-publish.yml";
export const SECURITY_REBASELINE_SIGNER_ENVIRONMENT = "production-security-rebaseline-signing";
export const SECURITY_REBASELINE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const SOURCE = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const REPOSITORY_ID = "1145608538";
const OWNER_ID = "183396573";
const REPOSITORY = "T-ej2003/genuine-scan-main";
const exactKeys = (value, keys, label) => assert.deepEqual(Object.keys(value || {}).sort(), [...keys].sort(), `${label} fields are invalid`);
const hashBytes = (value) => crypto.createHash("sha256").update(value).digest("hex");

export function productionSubscriptionProjectionContractSha256(repositoryRoot = cleanRoomRepoRoot) {
  const provisioningSqlSha256 = hashBytes(fs.readFileSync(path.join(repositoryRoot, "documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql")));
  const verifierSourceSha256 = hashBytes(fs.readFileSync(path.join(repositoryRoot, "scripts/aws/production-app-only-database-verifier.mjs")));
  return canonicalSha256({ provisioningSqlSha256, verifierSourceSha256, statusContract: SUBSCRIPTION_PROJECTION_STATUS_CONTRACT });
}

export function assertSecurityRebaselineSigningEnvironment(value, { variables, secrets } = {}) {
  assert.equal(value?.name, SECURITY_REBASELINE_SIGNER_ENVIRONMENT);
  const reviewers = (value.protection_rules || []).find((rule) => rule.type === "required_reviewers");
  assert.ok(reviewers?.prevent_self_review === true && reviewers.reviewers?.length > 0, "Signing environment lacks independent required approval");
  assert.deepEqual(value.deployment_branch_policy, { protected_branches: true, custom_branch_policies: false }, "Signing environment must permit protected branches only");
  assert.deepEqual((variables?.variables || []).map(({ name }) => name).sort(), ["PRODUCTION_SECURITY_REBASELINE_SIGNER_ROLE_ARN"], "Signing environment must contain only the dedicated signer role ARN variable");
  assert.equal(variables.total_count, 1);
  assert.deepEqual(secrets?.secrets || [], [], "Signing environment must not contain long-lived credentials or unused secrets");
  assert.equal(secrets.total_count, 0);
  return true;
}

export function assertPreparationWorkflowArtifacts({ run, artifacts, sourceSha, runId, runAttempt, requirementsReference, canonicalReference, publicationReference } = {}) {
  assert.equal(String(run?.id), String(runId)); assert.equal(String(run?.run_attempt), String(runAttempt));
  assert.equal(run?.head_sha, sourceSha); assert.equal(run?.head_branch, "main"); assert.equal(run?.event, "workflow_dispatch");
  assert.equal(run?.path, SECURITY_REBASELINE_SIGNER_WORKFLOW); assert.equal(run?.repository?.full_name, "T-ej2003/genuine-scan-main");
  assert.equal(run?.repository?.private, true); assert.equal(run?.repository?.id, 1145608538);
  assert.equal(run?.head_repository?.full_name, "T-ej2003/genuine-scan-main"); assert.equal(run?.head_repository?.private, true);
  assert.equal(run?.head_repository?.id, 1145608538); assert.ok(Array.isArray(artifacts));
  const expected = [
    [requirementsReference, "production-security-rebaseline-requirements"],
    [canonicalReference, "production-security-rebaseline-canonical"],
    [publicationReference, "production-security-rebaseline-image-publication"],
  ];
  for (const [reference, name] of expected) {
    assert.equal(reference.sourceSha, sourceSha); assert.equal(String(reference.runId), String(runId)); assert.equal(String(reference.runAttempt), String(runAttempt));
    const matches = artifacts.filter((artifact) => artifact.name === name);
    assert.equal(matches.length, 1); const artifact = matches[0];
    assert.equal(String(artifact.id), String(reference.artifactId)); assert.equal(artifact.digest, reference.artifactDigest); assert.equal(artifact.expired, false);
    assert.equal(String(artifact.workflow_run?.id), String(runId)); assert.equal(artifact.workflow_run?.head_sha, sourceSha);
    assert.equal(artifact.workflow_run?.repository_id, 1145608538); assert.equal(artifact.workflow_run?.head_repository_id, 1145608538);
  }
  return true;
}

export function buildSecurityRebaselineImageAuthorization({
  protectedMainSha, candidateSourceSha, imageRepository, imageDigest, publication,
  workflowRunId, workflowRunAttempt, workflowRef, repositoryId, ownerId, actor,
  invocationNonce = crypto.randomBytes(32).toString("base64url"), now = new Date().toISOString(), sign,
} = {}) {
  assert.match(protectedMainSha || "", SOURCE); assert.match(candidateSourceSha || "", SOURCE);
  assert.equal(candidateSourceSha, protectedMainSha, "This exact-source preparation signs only the protected-main candidate image");
  assert.equal(imageRepository, "mscqr-backend"); assert.match(imageDigest || "", DIGEST);
  exactKeys(publication, ["workflowFile", "sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"], "Image publication identity");
  assert.equal(publication.workflowFile, SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW);
  assert.equal(publication.sourceSha, protectedMainSha);
  for (const value of [publication.runId, publication.runAttempt, publication.artifactId, workflowRunId, workflowRunAttempt]) assert.match(String(value), /^[1-9][0-9]*$/);
  assert.equal(String(publication.runId), String(workflowRunId)); assert.equal(String(publication.runAttempt), String(workflowRunAttempt));
  assert.match(publication.artifactDigest || "", /^sha256:[a-f0-9]{64}$/); assert.match(publication.fileSha256 || "", SHA256);
  assert.equal(workflowRef, `T-ej2003/genuine-scan-main/${SECURITY_REBASELINE_SIGNER_WORKFLOW}@refs/heads/main`);
  assert.equal(repositoryId, REPOSITORY_ID); assert.equal(ownerId, OWNER_ID); assert.equal(actor, "T-ej2003");
  assert.match(invocationNonce || "", /^[A-Za-z0-9_-]{43}$/);
  assert.ok(Number.isFinite(Date.parse(now)) && new Date(now).toISOString() === now);
  assert.equal(typeof sign, "function", "The protected workflow KMS signer is required");
  const body = {
    schemaVersion: 1, kind: "PRODUCTION_SECURITY_REBASELINE_CANDIDATE_IMAGE_AUTHORIZATION",
    purpose: SECURITY_REBASELINE_IMAGE_AUTHORIZATION_PURPOSE,
    protectedMainSha, candidateSourceSha,
    image: { account: "368992683803", region: "eu-west-2", repository: imageRepository, digest: imageDigest },
    publication: structuredClone(publication),
    invocation: { workflow: SECURITY_REBASELINE_SIGNER_WORKFLOW, workflowRef, environment: SECURITY_REBASELINE_SIGNER_ENVIRONMENT,
      repository: REPOSITORY, repositoryId, ownerId, actor, runId: String(workflowRunId), runAttempt: String(workflowRunAttempt), nonce: invocationNonce },
    issuedAt: now, expiresAt: new Date(Date.parse(now) + SECURITY_REBASELINE_MAX_AGE_MS).toISOString(),
    signingKeyAliasArn: SECURITY_REBASELINE_SIGNING_KEY_ALIAS, signingAlgorithm: SECURITY_REBASELINE_SIGNING_ALGORITHM,
  };
  const authorizationSha256 = canonicalSha256(body);
  const signature = sign({ keyArn: SECURITY_REBASELINE_SIGNING_KEY_ALIAS, signingAlgorithm: SECURITY_REBASELINE_SIGNING_ALGORITHM,
    messageType: "DIGEST", digest: Buffer.from(authorizationSha256, "hex") });
  assert.match(signature || "", /^[A-Za-z0-9+/]+={0,2}$/);
  return Object.freeze({ ...body, authorizationSha256, signatureBase64: signature });
}

export function assertSecurityRebaselineImageAuthorization(value, expected = {}, { now = Date.now(), verify } = {}) {
  const { authorizationSha256, signatureBase64, ...body } = value || {};
  exactKeys(value, ["schemaVersion", "kind", "purpose", "protectedMainSha", "candidateSourceSha", "image", "publication", "invocation", "issuedAt", "expiresAt", "signingKeyAliasArn", "signingAlgorithm", "authorizationSha256", "signatureBase64"], "Image authorization");
  assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "PRODUCTION_SECURITY_REBASELINE_CANDIDATE_IMAGE_AUTHORIZATION");
  assert.equal(value.purpose, SECURITY_REBASELINE_IMAGE_AUTHORIZATION_PURPOSE);
  assert.match(value.protectedMainSha || "", SOURCE); assert.equal(value.candidateSourceSha, value.protectedMainSha);
  exactKeys(value.image, ["account", "region", "repository", "digest"], "Authorized image");
  assert.equal(value.image.account, "368992683803"); assert.equal(value.image.region, "eu-west-2"); assert.equal(value.image.repository, "mscqr-backend"); assert.match(value.image.digest || "", DIGEST);
  exactKeys(value.publication, ["workflowFile", "sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"], "Publication");
  assert.equal(value.publication.workflowFile, SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW);
  assert.equal(value.publication.sourceSha, value.protectedMainSha);
  assert.equal(String(value.publication.runId), String(value.invocation?.runId)); assert.equal(String(value.publication.runAttempt), String(value.invocation?.runAttempt));
  exactKeys(value.invocation, ["workflow", "workflowRef", "environment", "repository", "repositoryId", "ownerId", "actor", "runId", "runAttempt", "nonce"], "Signer invocation");
  assert.equal(value.invocation.workflow, SECURITY_REBASELINE_SIGNER_WORKFLOW); assert.equal(value.invocation.environment, SECURITY_REBASELINE_SIGNER_ENVIRONMENT);
  assert.equal(value.invocation.workflowRef, `T-ej2003/genuine-scan-main/${SECURITY_REBASELINE_SIGNER_WORKFLOW}@refs/heads/main`);
  assert.equal(value.invocation.repository, REPOSITORY); assert.equal(value.invocation.repositoryId, REPOSITORY_ID); assert.equal(value.invocation.ownerId, OWNER_ID); assert.equal(value.invocation.actor, "T-ej2003");
  assert.match(value.invocation.runId || "", /^[1-9][0-9]*$/); assert.equal(value.invocation.runAttempt, "1"); assert.match(value.invocation.nonce || "", /^[A-Za-z0-9_-]{43}$/);
  assert.equal(value.signingKeyAliasArn, SECURITY_REBASELINE_SIGNING_KEY_ALIAS); assert.equal(value.signingAlgorithm, SECURITY_REBASELINE_SIGNING_ALGORITHM);
  assert.match(authorizationSha256 || "", SHA256); assert.equal(authorizationSha256, canonicalSha256(body)); assert.match(signatureBase64 || "", /^[A-Za-z0-9+/]+={0,2}$/);
  const issued = Date.parse(value.issuedAt), expires = Date.parse(value.expiresAt), current = typeof now === "number" ? now : Date.parse(now);
  assert.ok(Number.isFinite(issued) && Number.isFinite(expires) && Number.isFinite(current)); assert.equal(expires - issued, SECURITY_REBASELINE_MAX_AGE_MS);
  assert.ok(issued <= current && expires > current && current - issued <= SECURITY_REBASELINE_MAX_AGE_MS, "Image authorization is stale or expired");
  for (const field of ["protectedMainSha", "candidateSourceSha"]) if (expected[field] !== undefined) assert.equal(value[field], expected[field]);
  if (expected.imageDigest !== undefined) assert.equal(value.image.digest, expected.imageDigest);
  if (expected.workflowRunId !== undefined) assert.equal(value.invocation.runId, String(expected.workflowRunId));
  if (expected.workflowRunAttempt !== undefined) assert.equal(value.invocation.runAttempt, String(expected.workflowRunAttempt));
  if (verify !== undefined) {
    assert.equal(typeof verify, "function", "KMS signature verification must be callable");
    assert.equal(verify({ keyArn: value.signingKeyAliasArn, signingAlgorithm: value.signingAlgorithm, messageType: "DIGEST",
      digest: Buffer.from(authorizationSha256, "hex"), signature: Buffer.from(signatureBase64, "base64") }), true, "Image authorization signature is invalid");
  }
  return Object.freeze(value);
}

function assertArtifactReference(value, label) {
  exactKeys(value, ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"], label);
  assert.match(value.sourceSha || "", SOURCE); for (const field of ["runId", "runAttempt", "artifactId"]) assert.match(String(value[field]), /^[1-9][0-9]*$/);
  assert.match(value.artifactDigest || "", /^sha256:[a-f0-9]{64}$/); assert.match(value.fileSha256 || "", SHA256);
}

function assertPublicationReference(value) {
  exactKeys(value, ["workflowFile", "sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"], "Publication reference");
  assert.equal(value.workflowFile, SECURITY_REBASELINE_IMAGE_PUBLISHER_WORKFLOW);
  const { workflowFile, ...reference } = value;
  assertArtifactReference(reference, "Publication reference");
  return reference;
}

export function createProductionSecurityRebaselinePreparationManifest({
  protectedMainSha, candidateSourceSha, workflowRunId, workflowRunAttempt,
  requirements, requirementsBytes, requirementsReference,
  canonicalInventory, canonicalInventoryBytes, canonicalReference,
  imageAuthorization,
  publicationReference, probeImageDigest, sourceContractSha256, migrationSetDigest,
  packageChecksumsSha256, subscriptionProjectionSha256,
} = {}) {
  assert.match(protectedMainSha || "", SOURCE); assert.match(candidateSourceSha || "", SOURCE);
  assert.equal(candidateSourceSha, protectedMainSha, "Preparation candidate must match the exact protected-main image build");
  assert.match(String(workflowRunId || ""), /^[1-9][0-9]*$/); assert.equal(String(workflowRunAttempt), "1", "Workflow reruns must regenerate evidence with a new run");
  assert.ok(Buffer.isBuffer(requirementsBytes)); assert.ok(Buffer.isBuffer(canonicalInventoryBytes));
  assertAppOnlyRequirements(requirements, { sourceSha: protectedMainSha, candidateSourceSha, repositoryRoot: cleanRoomRepoRoot });
  assert.deepEqual(JSON.parse(requirementsBytes.toString("utf8")), requirements, "Requirements bytes differ from authenticated object");
  const canonical = assertSecurityRebaselineInventory(canonicalInventory, { protectedMainSha, candidateSourceSha });
  assert.deepEqual(JSON.parse(canonicalInventoryBytes.toString("utf8")), canonicalInventory, "Canonical inventory bytes differ from authenticated object");
  assert.equal(canonical.kind, "PRODUCTION_SECURITY_REBASELINE_CANONICAL_INVENTORY");
  assert.equal(canonical.appOnlyRequirementsSha256, requirements.requirementsSha256);
  assert.ok(Buffer.isBuffer(requirementsBytes) && hashBytes(requirementsBytes) === requirementsReference.fileSha256);
  assert.ok(Buffer.isBuffer(canonicalInventoryBytes) && hashBytes(canonicalInventoryBytes) === canonicalReference.fileSha256);
  for (const [reference, label] of [[requirementsReference, "Requirements reference"], [canonicalReference, "Canonical reference"]]) {
    assertArtifactReference(reference, label); assert.equal(reference.sourceSha, protectedMainSha); assert.equal(String(reference.runId), String(workflowRunId)); assert.equal(String(reference.runAttempt), String(workflowRunAttempt));
  }
  assertPublicationReference(publicationReference);
  assert.equal(publicationReference.sourceSha, protectedMainSha);
  assert.equal(String(publicationReference.runId), String(workflowRunId));
  assert.equal(String(publicationReference.runAttempt), String(workflowRunAttempt));
  assert.equal(canonical.collectorVersion, SECURITY_REBASELINE_COLLECTOR_VERSION);
  assert.equal(canonical.sourceContractSha256, sourceContractSha256); assert.equal(canonical.migrationSetDigest, migrationSetDigest); assert.equal(canonical.packageChecksumsSha256, packageChecksumsSha256);
  assert.match(subscriptionProjectionSha256 || "", SHA256); assert.match(probeImageDigest || "", DIGEST);
  assertSecurityRebaselineImageAuthorization(imageAuthorization, { protectedMainSha, candidateSourceSha, imageDigest: probeImageDigest, workflowRunId, workflowRunAttempt });
  assert.deepEqual(imageAuthorization.publication, publicationReference);
  const body = {
    schemaVersion: 1, kind: "PRODUCTION_SECURITY_REBASELINE_PREPARATION",
    protectedMainSha, candidateSourceSha, generatedBy: { repository: REPOSITORY, repositoryId: REPOSITORY_ID, ownerId: OWNER_ID,
      workflow: SECURITY_REBASELINE_SIGNER_WORKFLOW, runId: String(workflowRunId), runAttempt: String(workflowRunAttempt), ref: "refs/heads/main" },
    requirements: { reference: requirementsReference, requirementsSha256: requirements.requirementsSha256,
      sourceContractSha256, migrationSetDigest, packageChecksumsSha256 },
    canonicalInventory: { reference: canonicalReference, requirementsSha256: canonical.appOnlyRequirementsSha256, artifactSha256: canonical.artifactSha256,
      catalogueSha256: canonical.catalogueSha256, collectorVersion: canonical.collectorVersion, postgresqlMajor: 18,
      sourceContractSha256: canonical.sourceContractSha256, migrationSetDigest: canonical.migrationSetDigest,
      packageChecksumsSha256: canonical.packageChecksumsSha256 },
    candidateImage: { authorization: imageAuthorization, authorizationSha256: imageAuthorization.authorizationSha256,
      repository: imageAuthorization.image.repository, digest: imageAuthorization.image.digest, sourceSha: candidateSourceSha },
    probeRuntime: { sourceSha: protectedMainSha, imageDigest: probeImageDigest },
    publicationReference,
    subscriptionProjection: { expectedDefinitionSha256: subscriptionProjectionSha256, presence: "VERIFY_IN_SINGLE_READ_ONLY_PROBE_BEFORE_INVENTORY" },
    execution: { productionProbeDispatched: false, databaseMutation: false, deployment: false },
  };
  const manifestSha256 = canonicalSha256(body);
  const manifest = Object.freeze({ ...body, manifestSha256 });
  assertProductionSecurityRebaselinePreparationManifest(manifest, { protectedMainSha, candidateSourceSha, workflowRunId, workflowRunAttempt });
  return manifest;
}

export function assertProductionSecurityRebaselinePreparationManifest(value, expected = {}) {
  const { manifestSha256, ...body } = value || {};
  exactKeys(value, ["schemaVersion", "kind", "protectedMainSha", "candidateSourceSha", "generatedBy", "requirements", "canonicalInventory", "candidateImage", "probeRuntime", "publicationReference", "subscriptionProjection", "execution", "manifestSha256"], "Preparation manifest");
  exactKeys(value.generatedBy, ["repository", "repositoryId", "ownerId", "workflow", "runId", "runAttempt", "ref"], "Manifest producer");
  exactKeys(value.requirements, ["reference", "requirementsSha256", "sourceContractSha256", "migrationSetDigest", "packageChecksumsSha256"], "Manifest requirements");
  exactKeys(value.canonicalInventory, ["reference", "requirementsSha256", "artifactSha256", "catalogueSha256", "collectorVersion", "postgresqlMajor", "sourceContractSha256", "migrationSetDigest", "packageChecksumsSha256"], "Manifest canonical inventory");
  exactKeys(value.candidateImage, ["authorization", "authorizationSha256", "repository", "digest", "sourceSha"], "Manifest candidate image");
  exactKeys(value.probeRuntime, ["sourceSha", "imageDigest"], "Manifest probe runtime");
  exactKeys(value.subscriptionProjection, ["expectedDefinitionSha256", "presence"], "Manifest subscription projection");
  exactKeys(value.execution, ["productionProbeDispatched", "databaseMutation", "deployment"], "Manifest execution state");
  assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "PRODUCTION_SECURITY_REBASELINE_PREPARATION");
  assert.match(value.protectedMainSha || "", SOURCE); assert.equal(value.candidateSourceSha, value.protectedMainSha);
  assert.equal(value.generatedBy.repository, REPOSITORY); assert.equal(value.generatedBy.repositoryId, REPOSITORY_ID); assert.equal(value.generatedBy.ownerId, OWNER_ID);
  assert.equal(value.generatedBy.workflow, SECURITY_REBASELINE_SIGNER_WORKFLOW); assert.equal(value.generatedBy.ref, "refs/heads/main"); assert.equal(value.generatedBy.runAttempt, "1");
  assert.match(value.generatedBy.runId || "", /^[1-9][0-9]*$/); assert.match(value.requirements.requirementsSha256 || "", SHA256);
  assert.match(value.requirements.sourceContractSha256 || "", SHA256); assert.match(value.requirements.migrationSetDigest || "", SHA256); assert.match(value.requirements.packageChecksumsSha256 || "", SHA256);
  assertArtifactReference(value.requirements.reference, "Requirements reference"); assertArtifactReference(value.canonicalInventory.reference, "Canonical inventory reference"); assertPublicationReference(value.publicationReference);
  for (const ref of [value.requirements.reference, value.canonicalInventory.reference]) { assert.equal(ref.sourceSha, value.protectedMainSha); assert.equal(String(ref.runId), value.generatedBy.runId); assert.equal(ref.runAttempt, value.generatedBy.runAttempt); }
  assertPublicationReference(value.publicationReference);
  assert.equal(value.publicationReference.sourceSha, value.protectedMainSha);
  assert.equal(String(value.publicationReference.runId), value.generatedBy.runId);
  assert.equal(value.publicationReference.runAttempt, value.generatedBy.runAttempt);
  assert.equal(value.canonicalInventory.postgresqlMajor, 18); assert.equal(value.canonicalInventory.collectorVersion, SECURITY_REBASELINE_COLLECTOR_VERSION);
  assert.match(value.canonicalInventory.artifactSha256 || "", SHA256); assert.match(value.canonicalInventory.catalogueSha256 || "", SHA256);
  assert.match(value.canonicalInventory.sourceContractSha256 || "", SHA256); assert.match(value.canonicalInventory.migrationSetDigest || "", SHA256); assert.match(value.canonicalInventory.packageChecksumsSha256 || "", SHA256);
  assert.equal(value.canonicalInventory.requirementsSha256, value.requirements.requirementsSha256);
  assert.equal(value.canonicalInventory.sourceContractSha256, value.requirements.sourceContractSha256);
  assert.equal(value.canonicalInventory.migrationSetDigest, value.requirements.migrationSetDigest);
  assert.equal(value.canonicalInventory.packageChecksumsSha256, value.requirements.packageChecksumsSha256);
  assert.equal(value.candidateImage.sourceSha, value.candidateSourceSha);
  assert.equal(value.candidateImage.authorizationSha256, value.candidateImage.authorization.authorizationSha256);
  assert.equal(value.candidateImage.repository, value.candidateImage.authorization.image.repository);
  assert.equal(value.candidateImage.digest, value.candidateImage.authorization.image.digest);
  assert.deepEqual(value.candidateImage.authorization.publication, value.publicationReference);
  assert.equal(value.probeRuntime.sourceSha, value.protectedMainSha); assert.equal(value.probeRuntime.imageDigest, value.candidateImage.digest); assert.match(value.probeRuntime.imageDigest || "", DIGEST);
  assertSecurityRebaselineImageAuthorization(value.candidateImage.authorization, { protectedMainSha: value.protectedMainSha,
    candidateSourceSha: value.candidateSourceSha, imageDigest: value.candidateImage.digest,
    workflowRunId: value.generatedBy.runId, workflowRunAttempt: value.generatedBy.runAttempt }, { now: expected.now ?? Date.now() });
  assert.deepEqual(value.subscriptionProjection.presence, "VERIFY_IN_SINGLE_READ_ONLY_PROBE_BEFORE_INVENTORY"); assert.match(value.subscriptionProjection.expectedDefinitionSha256 || "", SHA256);
  assert.deepEqual(value.execution, { productionProbeDispatched: false, databaseMutation: false, deployment: false });
  assert.match(manifestSha256 || "", SHA256); assert.equal(manifestSha256, canonicalSha256(body));
  for (const field of ["protectedMainSha", "candidateSourceSha"]) if (expected[field] !== undefined) assert.equal(value[field], expected[field]);
  if (expected.workflowRunId !== undefined) assert.equal(value.generatedBy.runId, String(expected.workflowRunId));
  if (expected.workflowRunAttempt !== undefined) assert.equal(value.generatedBy.runAttempt, String(expected.workflowRunAttempt));
  return Object.freeze(value);
}

export const preparationManifestSha256 = (value) => assertProductionSecurityRebaselinePreparationManifest(value).manifestSha256;

export function verifyProductionSecurityRebaselinePreparationManifest(value, expected = {}, { verifyImageAuthorization } = {}) {
  const manifest = assertProductionSecurityRebaselinePreparationManifest(value, expected);
  assert.equal(typeof verifyImageAuthorization, "function", "KMS image-authorization verification is required");
  assertSecurityRebaselineImageAuthorization(manifest.candidateImage.authorization, {
    protectedMainSha: manifest.protectedMainSha, candidateSourceSha: manifest.candidateSourceSha,
    imageDigest: manifest.candidateImage.digest, workflowRunId: manifest.generatedBy.runId,
    workflowRunAttempt: manifest.generatedBy.runAttempt,
  }, { verify: verifyImageAuthorization });
  return manifest;
}

export function authenticateProductionSecurityRebaselinePreparation({
  manifestBytes, manifestReference, requirementsBytes, requirementsReference,
  canonicalInventoryBytes, canonicalReference, publicationBytes, publicationReference,
  sourceSha, verifyImageAuthorization, repositoryRoot = cleanRoomRepoRoot, now = Date.now(),
} = {}) {
  for (const [bytes, label] of [[manifestBytes, "Manifest"], [requirementsBytes, "Requirements"], [canonicalInventoryBytes, "Canonical inventory"], [publicationBytes, "Image publication"]])
    assert.ok(Buffer.isBuffer(bytes) && bytes.length > 0, `${label} artifact bytes are required`);
  const manifest = verifyProductionSecurityRebaselinePreparationManifest(JSON.parse(manifestBytes), { protectedMainSha: sourceSha, candidateSourceSha: sourceSha,
    workflowRunId: manifestReference?.runId, workflowRunAttempt: manifestReference?.runAttempt, now }, { verifyImageAuthorization });
  assert.equal(manifest.subscriptionProjection.expectedDefinitionSha256, productionSubscriptionProjectionContractSha256(repositoryRoot),
    "Preparation projection identity differs from the protected source contract");
  const referenceFields = ["sourceSha", "runId", "runAttempt", "artifactId", "artifactDigest", "fileSha256"];
  const exactReference = (actual, expected, label) => {
    assert.deepEqual(Object.keys(actual || {}).sort(), [...referenceFields].sort(), `${label} reference fields are invalid`);
    assert.deepEqual(actual, expected, `${label} artifact reference differs from the signed manifest`);
    assert.equal(actual.sourceSha, sourceSha); assert.equal(String(actual.runId), manifest.generatedBy.runId); assert.equal(actual.runAttempt, manifest.generatedBy.runAttempt);
  };
  assert.match(crypto.createHash("sha256").update(manifestBytes).digest("hex"), SHA256);
  assert.equal(crypto.createHash("sha256").update(requirementsBytes).digest("hex"), manifest.requirements.reference.fileSha256);
  assert.equal(crypto.createHash("sha256").update(canonicalInventoryBytes).digest("hex"), manifest.canonicalInventory.reference.fileSha256);
  const publicationRef = { ...publicationReference };
  delete publicationRef.workflowFile;
  exactReference(manifestReference, { sourceSha, runId: manifest.generatedBy.runId, runAttempt: manifest.generatedBy.runAttempt,
    artifactId: String(manifestReference.artifactId), artifactDigest: manifestReference.artifactDigest, fileSha256: crypto.createHash("sha256").update(manifestBytes).digest("hex") }, "Preparation manifest");
  exactReference(requirementsReference, manifest.requirements.reference, "Requirements");
  exactReference(canonicalReference, manifest.canonicalInventory.reference, "Canonical inventory");
  assert.deepEqual(publicationReference, manifest.publicationReference);
  exactReference(publicationRef, { sourceSha, runId: manifest.generatedBy.runId, runAttempt: manifest.generatedBy.runAttempt,
    artifactId: publicationRef.artifactId, artifactDigest: publicationRef.artifactDigest, fileSha256: crypto.createHash("sha256").update(publicationBytes).digest("hex") }, "Image publication");
  const requirements = assertAppOnlyRequirements(JSON.parse(requirementsBytes), { sourceSha, candidateSourceSha: sourceSha, repositoryRoot });
  const canonical = assertSecurityRebaselineInventory(JSON.parse(canonicalInventoryBytes), { protectedMainSha: sourceSha, candidateSourceSha: sourceSha });
  assert.equal(requirements.requirementsSha256, manifest.requirements.requirementsSha256);
  assert.equal(canonical.artifactSha256, manifest.canonicalInventory.artifactSha256);
  assert.equal(canonical.catalogueSha256, manifest.canonicalInventory.catalogueSha256);
  const publicationRows = publicationBytes.toString("utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(publicationRows.length, 1);
  const [image] = publicationRows;
  assert.equal(image.service, "backend"); assert.equal(image.repository, manifest.candidateImage.repository);
  assert.equal(image.image_tag, `${sourceSha}-backend-only`); assert.equal(image.image_digest, manifest.candidateImage.digest.slice("sha256:".length));
  assert.equal(image.image_ref, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/${image.repository}@${manifest.candidateImage.digest}`);
  return Object.freeze({ manifest, requirements, canonicalInventory: canonical, publicationImage: Object.freeze(image) });
}
