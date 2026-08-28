import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstatSync, rmSync } from "node:fs";
import path from "node:path";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { loadApprovedArtifactSigningBindings } from "./production-artifact-signing-secrets-adapter.mjs";
import { buildOverlapTaskDefinition } from "./production-overlap-task-definition.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { RELEASE_ROLE_ARN } from "./production-identity-adapters.mjs";
import { assertImageAuthorization, authorizedBackendDigest, buildRotationTerraformInputs, renderRotationTerraformInput } from "./production-cutover-control-plane.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { assertOnboardingPaths, PRODUCTION_ONBOARDING_PATHS } from "../security/production-onboarding-contract.mjs";
import { assertAuthenticatedCurrentStageBState, assertPostApplyStageAPlanRecovery, readAuthenticatedStageARecoverySources } from "./production-stage-a-recovery-evidence.mjs";
import { assertRootDropEvidence } from "./production-root-drop-evidence.mjs";
import { assertPreCutoverTemporaryCapabilityAbsent } from "./production-stage-a-temporary-kms-capability.mjs";
import { parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { assertProductionRotationGraceSeconds } from "../../backend/scripts/security/production-rotation-grace-contract.mjs";
import {
  assertProductionInitialMigrationSourceAdvance,
  assertProductionSupersessionEvidence,
  PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE_KIND,
} from "../security/production-initial-migration-source-advance.mjs";
import { assertBindingsMatchLegacyBaseline, deriveLegacyRotationBaseline } from "./production-legacy-rotation-baseline.mjs";
import { authenticateReleasePreflightCheckerTrustEvidence } from "./production-release-preflight-checker-attestation.mjs";
import { assertRebaselineRotationBindings, BASELINE_COMPLETE, PRODUCTION_DUAL_SLOT_REBASELINE, REBASELINE_ROTATION_BINDINGS_KIND, REBASELINE_ROTATION_BINDINGS_PRODUCER } from "./production-dual-slot-rebaseline-contract.mjs";

const ACCOUNT = STAGE_B.account;
const REGION = STAGE_B.region;
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const BASE_ARN = new RegExp(`^arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:[A-Za-z0-9/_+=.@-]+$`);
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const REQUIRED_SECRET_BINDINGS = Object.freeze([
  "jwt.currentSecretId", "jwt.previousSecretId", "jwt.pendingSecretId",
  "qr.privateCurrentSecretId", "qr.privatePendingSecretId", "qr.publicCurrentSecretId",
  "qr.publicPreviousSecretId", "qr.publicPendingSecretId", "qr.currentKeyVersionSecretId", "qr.previousKeyVersionSecretId", "qr.previousKeyVersion",
]);
const INITIAL_DUAL_SLOT_ROTATION_BINDINGS_KIND = "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS";
const INITIAL_DUAL_SLOT_ROTATION_BINDINGS_PRODUCER = "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const canonicalHash = (value) => hash(canonical(value));
const nonEmpty = (value, name) => {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required.`);
  return value.trim();
};

function assertRebaselineAuthorizationCoordinates(value) {
  if (!value || canonical(Object.keys(value).sort()) !== canonical(["workflowRunAttempt", "workflowRunId"]) || !/^[1-9][0-9]*$/.test(String(value.workflowRunId || "")) || !/^[1-9][0-9]*$/.test(String(value.workflowRunAttempt || ""))) throw new Error("Rebaseline authorization workflow coordinates are required.");
  return Object.freeze({ workflowRunId: String(value.workflowRunId), workflowRunAttempt: String(value.workflowRunAttempt) });
}

function assertNoSecretMaterial(value, label) {
  const serialized = JSON.stringify(value);
  if (/(BEGIN [A-Z ]+PRIVATE KEY|SecretString|AccessKeyId|SecretAccessKey|SessionToken|DATABASE_URL=|password|token)/i.test(serialized)) throw new Error(`${label} contains prohibited secret material.`);
}

function assertApproval(approval = {}) {
  for (const name of ["ticket", "approvedBy", "approverRole", "reason", "verificationRef"]) nonEmpty(approval[name], `approval.${name}`);
  assertProductionRotationGraceSeconds(approval.minimumGraceSeconds, "approval.minimumGraceSeconds");
  assertNoSecretMaterial(approval, "Approval metadata");
  return Object.freeze({ ...approval });
}

function assertLiveRebaselinePostWrite(value, { bindings, authorization } = {}) {
  const resources = {
    jwtPending: bindings.jwt.pendingSecretId, qrPrivatePending: bindings.qr.privatePendingSecretId, qrPublicPending: bindings.qr.publicPendingSecretId,
    jwtPrevious: bindings.jwt.previousSecretId, qrPublicPrevious: bindings.qr.publicPreviousSecretId, qrCurrentVersion: bindings.qr.currentKeyVersionSecretId, qrPreviousVersion: bindings.qr.previousKeyVersionSecretId,
  };
  const body = { kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, authorizationSha256: authorization.authorizationSha256, resources, versionIds: authorization.writeIdentities, payloadIdentities: authorization.writePayloadIdentities };
  if (!value || canonicalHash({ kind: value.kind, sourceSha: value.sourceSha, rotationId: value.rotationId, authorizationSha256: value.authorizationSha256, resources: value.resources, versionIds: value.versionIds, payloadIdentities: value.payloadIdentities }) !== value.livePostWriteSha256 || canonicalHash(body) !== value.livePostWriteSha256) throw new Error("Live post-write rebaseline verification is not independently authenticated.");
  return value;
}

function assertBindings(bindings = {}, { rebaselineAuthorization, verifyRebaselineLivePostWrite } = {}) {
  const missing = REQUIRED_SECRET_BINDINGS.filter((key) => {
    const [group, field] = key.split(".");
    return typeof bindings[group]?.[field] !== "string" || !bindings[group][field].trim();
  });
  if (missing.length) throw new Error(`Rotation secret binding manifest is incomplete: ${missing.join(", ")}.`);
  const refs = REQUIRED_SECRET_BINDINGS.filter((key) => !key.endsWith("previousKeyVersion")).map((key) => {
    const [group, field] = key.split(".");
    return bindings[group][field];
  });
  if (refs.some((value) => !BASE_ARN.test(value))) throw new Error("Rotation SDK bindings must be base eu-west-2 production Secrets Manager identifiers.");
  if (new Set(refs).size !== refs.length) throw new Error("Rotation secret bindings must be distinct.");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(bindings.qr.previousKeyVersion)) throw new Error("qr.previousKeyVersion is invalid.");
  assertNoSecretMaterial(bindings, "Rotation secret binding manifest");
  const checked = { jwt: Object.freeze({ ...bindings.jwt }), qr: Object.freeze({ ...bindings.qr }) };
  let livePostWrite;
  if (bindings.kind === REBASELINE_ROTATION_BINDINGS_KIND) {
    if (bindings.producer !== REBASELINE_ROTATION_BINDINGS_PRODUCER || bindings.operation !== PRODUCTION_DUAL_SLOT_REBASELINE.kind || bindings.baselineCompletion?.kind !== BASELINE_COMPLETE) throw new Error("Completed dual-slot baseline evidence is required for rebaseline runtime consumption.");
    assertRebaselineRotationBindings(bindings, { authorization: rebaselineAuthorization });
    if (verifyRebaselineLivePostWrite !== undefined) {
      if (typeof verifyRebaselineLivePostWrite !== "function") throw new Error("Live post-write rebaseline verifier is invalid.");
      livePostWrite = assertLiveRebaselinePostWrite(verifyRebaselineLivePostWrite({ bindings, authorization: rebaselineAuthorization }), { bindings, authorization: rebaselineAuthorization });
    }
  } else if (bindings.kind !== INITIAL_DUAL_SLOT_ROTATION_BINDINGS_KIND || bindings.producer !== INITIAL_DUAL_SLOT_ROTATION_BINDINGS_PRODUCER) {
    throw new Error("Rotation secret binding producer identity is required; ambiguous binding manifests are rejected.");
  }
  const ecs = rotationBindingsToTaskBindings(checked);
  if (bindings.ecs && JSON.stringify(bindings.ecs) !== JSON.stringify(ecs)) throw new Error("ECS rotation bindings do not match the canonical base-ARN bindings.");
  return Object.freeze({ ...checked, kind: bindings.kind, producer: bindings.producer, schemaVersion: bindings.schemaVersion, ...(bindings.kind === REBASELINE_ROTATION_BINDINGS_KIND ? { operation: bindings.operation, sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, historicalRotationId: bindings.historicalRotationId, abandonmentEvidenceSha256: bindings.abandonmentEvidenceSha256, abandonmentEvidence: bindings.abandonmentEvidence, baselineCompletionSha256: bindings.baselineCompletionSha256, baselineCompletion: bindings.baselineCompletion, authorizationSha256: bindings.authorizationSha256, ...(livePostWrite ? { livePostWrite } : {}) } : { sourceSha: bindings.sourceSha, rotationId: bindings.rotationId, legacy: bindings.legacy }), ecs: Object.freeze(ecs) });
}

function readInputFile(filePath, repositoryRoot, label, parse = (bytes) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes))) {
  const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot, label });
  const value = parse(captured.bytes);
  assertNoSecretMaterial(value, label);
  return { path: captured.path, value, sha256: captured.sha256 };
}

export function deriveRuntimeMetadata(taskDefinition) {
  const environment = taskDefinition?.containerDefinitions?.find(({ name }) => name === "backend")?.environment || [];
  const baseUrl = environment.find(({ name }) => ["PUBLIC_APP_URL", "APP_URL", "WEB_APP_BASE_URL"].includes(name))?.value;
  const currentKeyVersion = environment.find(({ name }) => name === "QR_SIGN_ACTIVE_KEY_VERSION")?.value;
  if (!/^https:\/\//.test(baseUrl || "")) throw new Error("Production onboarding base URL is not deterministically available from the live task definition.");
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(currentKeyVersion || "")) throw new Error("Current QR key version is not deterministically available from the live task definition.");
  return { baseUrl: baseUrl.replace(/\/+$/, ""), currentKeyVersion };
}

function discoverGit({ run = execFileSync } = {}) {
  const status = String(run("git", ["status", "--porcelain=v1"], { encoding: "utf8" }));
  if (status.trim()) throw new Error("Protected-main execution tree is not clean.");
  const fresh = readFreshProtectedMainIdentity({ run: (args) => run("git", args, { encoding: "utf8" }) });
  if (!SHA40.test(fresh.headSha) || fresh.headSha !== fresh.freshRemoteMainSha) throw new Error("HEAD is not the exact freshly fetched protected main.");
  return fresh.headSha;
}

function phasePaths(directory) {
  return {
    rotationConfigFile: path.join(directory, "rotation-config.json"),
    rotationTerraformInputFile: path.join(directory, "rotation-infrastructure.tfvars"),
    rotationTerraformPlanFile: path.join(directory, "rotation-infrastructure.tfplan"),
    rotationStateFile: path.join(directory, "rotation-state.json"),
    rotationFixtureFile: path.join(directory, "rotation-fixture.json"),
    runtimeProofFixtureFile: path.join(directory, "rotation-fixture.json"),
    readinessEvidenceFile: path.join(directory, "readiness-evidence.json"),
  };
}

function assertFutureArtifactsAbsent(paths, repositoryRoot) {
  for (const [name, filePath] of Object.entries(paths)) {
    if (!["rotationConfigFile", "rotationTerraformInputFile", "rotationTerraformPlanFile", "rotationStateFile", "rotationFixtureFile", "runtimeProofFixtureFile", "readinessEvidenceFile"].includes(name)) continue;
    ensureStageBPrivateDirectory({ directory: path.dirname(filePath), repositoryRoot, create: false });
    const stat = lstatSync(filePath, { throwIfNoEntry: false });
    if (!stat) continue;
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${name} must be an absent regular file before its producer phase.`);
    ensureStageBPrivateFile({ filePath, repositoryRoot, label: name });
    throw new Error(`${name} must not exist before its producer phase.`);
  }
}

export function buildProductionRotationConfig({ sourceSha, rotationId, approval, bindings, rebaselineAuthorization, rebaselineAuthorizationCoordinates, verifyRebaselineLivePostWrite, liveCurrentKeyVersion, overlapDeploymentSha = sourceSha } = {}) {
  if (!SHA40.test(sourceSha || "") || !ROTATION_ID.test(rotationId || "")) throw new Error("Production rotation identity is invalid.");
  const checkedApproval = assertApproval(approval);
  if (bindings?.kind === REBASELINE_ROTATION_BINDINGS_KIND && typeof verifyRebaselineLivePostWrite !== "function") throw new Error("Live post-write rebaseline verification is required before runtime preparation.");
  const checkedBindings = assertBindings(bindings, { rebaselineAuthorization, verifyRebaselineLivePostWrite });
  if (liveCurrentKeyVersion !== undefined) {
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(liveCurrentKeyVersion) || checkedBindings.qr.previousKeyVersion !== liveCurrentKeyVersion) throw new Error("qr.previousKeyVersion must equal the live QR_SIGN_ACTIVE_KEY_VERSION.");
  }
  if (!SHA40.test(overlapDeploymentSha || "")) throw new Error("overlapDeploymentSha must be a full protected-main SHA.");
  const checkedRebaselineCoordinates = checkedBindings.operation ? assertRebaselineAuthorizationCoordinates(rebaselineAuthorizationCoordinates) : undefined;
  return {
    region: REGION,
    expectedRoleArn: RELEASE_ROLE_ARN,
    rotationId,
    sourceSha,
    ticket: checkedApproval.ticket,
    approvedBy: checkedApproval.approvedBy,
    approverRole: checkedApproval.approverRole,
    reason: checkedApproval.reason,
    minimumGraceSeconds: checkedApproval.minimumGraceSeconds,
    overlapDeploymentSha,
    verificationRef: checkedApproval.verificationRef,
    jwt: checkedBindings.jwt,
    qr: checkedBindings.qr,
    ...(checkedBindings.operation ? { operation: checkedBindings.operation, baselineCompletionSha256: checkedBindings.baselineCompletionSha256, baselineCompletion: checkedBindings.baselineCompletion, rebaselineRuntime: { bindings, authorizationCoordinates: checkedRebaselineCoordinates }, ...(checkedBindings.livePostWrite ? { livePostWriteSha256: checkedBindings.livePostWrite.livePostWriteSha256 } : {}) } : {}),
  };
}

export function buildInitialMigrationSourceAdvance({ currentSourceSha, rotationBindings, rebaselineAuthorization, supersessionEvidence, liveLegacyBaseline, proveDescendant } = {}) {
  const originalSourceSha = rotationBindings?.sourceSha;
  if (!SHA40.test(currentSourceSha || "") || !SHA40.test(originalSourceSha || "") || !liveLegacyBaseline) throw new Error("Initial-migration source-advance inputs are incomplete.");
  assertBindings(rotationBindings, { rebaselineAuthorization });
  assertBindingsMatchLegacyBaseline(rotationBindings, liveLegacyBaseline);
  if (originalSourceSha === currentSourceSha) return undefined;
  if (rotationBindings.rotationId !== supersessionEvidence?.rotationId) throw new Error("Initial-migration source-advance inputs are incomplete.");
  const evidence = assertProductionSupersessionEvidence(supersessionEvidence);
  if (evidence.sourceSha !== originalSourceSha || proveDescendant?.({ ancestorSha: originalSourceSha, descendantSha: currentSourceSha }) !== true) throw new Error("Initial-migration source advancement is not an authenticated protected-main descendant transition.");
  const expectedArns = {
    jwtPending: rotationBindings.jwt?.pendingSecretId,
    qrPrivatePending: rotationBindings.qr?.privatePendingSecretId,
    qrPublicPending: rotationBindings.qr?.publicPendingSecretId,
    jwtPrevious: rotationBindings.jwt?.previousSecretId,
    qrPublicPrevious: rotationBindings.qr?.publicPreviousSecretId,
    qrCurrentVersion: rotationBindings.qr?.currentKeyVersionSecretId,
    qrPreviousVersion: rotationBindings.qr?.previousKeyVersionSecretId,
  };
  if (Object.entries(expectedArns).some(([slot, arn]) => evidence.resources[slot].arn !== arn)) throw new Error("Initial-migration source-advance resources do not match rotation bindings.");
  return assertProductionInitialMigrationSourceAdvance({
    schemaVersion: 1,
    kind: PRODUCTION_INITIAL_MIGRATION_SOURCE_ADVANCE_KIND,
    currentSourceSha,
    supersessionEvidence: evidence,
  });
}

export function prepareProductionCutoverRuntime({
  repositoryRoot = process.cwd(),
  outputDirectory,
  approval,
  rotationBindings,
  rebaselineAuthorization,
  rebaselineAuthorizationCoordinates,
  verifyRebaselineLivePostWrite,
  rotationSupersessionEvidence,
  sourceSha,
  git,
  imageAuthorization,
  iamEvidence,
  releasePreflightEvidenceFile,
  releasePreflightAttestationFile,
  releasePreflightAttestationSignatureFile,
  artifactBindingFile,
  rootDropEvidenceFile,
  temporaryKmsCapabilityFile,
  stageAPlanPath,
  stageARecoveryEvidenceFile,
  stageAStatePath,
  stageAHandoffPath,
  stageBStatePath,
  currentStageBStatePath,
  currentTaskDefinition,
  loadCurrentTaskDefinition,
  inventoryApprovalId,
  onboardingPaths,
  stageBTfvarsPath,
  stageBTfvarsBindingReportPath,
  stageBTfvarsBindingReportSha256,
  stageBTerraformDataDir,
  rotationId: requestedRotationId,
  constructAdapters,
  imageAuthorizationValidation,
  verifyRootDropSignature,
  verifyReleasePreflightAttestationSignature,
  proveSourceAdvance,
} = {}) {
  const directory = ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot, create: true, normalize: true, label: "Production cutover runtime directory" });
  const paths = phasePaths(directory);
  assertFutureArtifactsAbsent(paths, repositoryRoot);
  const blockers = [];
  let protectedSha;
  try {
    const discoveredSha = discoverGit({ run: git });
    if (sourceSha && sourceSha !== discoveredSha) throw new Error("Caller-supplied source SHA does not match protected main.");
    protectedSha = discoveredSha;
  } catch (error) { blockers.push(error.message); }
  let config;
  let staticBindings;
  let configBytes;
  let runtimeConfigSha256;
  let onboardingPathsBytes;
  let onboardingPathsFile;
  let rotationTerraformInputBytes;
  let rotationTerraformInputFile;
  try {
    if (!protectedSha || !SHA40.test(protectedSha)) throw new Error("protected-main source SHA is unresolved.");
    if (typeof verifyReleasePreflightAttestationSignature !== "function") throw new Error("Release-preflight checker-trust verification requires the canonical release-profile verifier.");
    if (!rotationBindings) throw new Error("rotation secret binding manifest is required; current/previous/pending JWT/QR bindings are not derivable from the legacy live task.");
    const rotationId = requestedRotationId || `rotation-${new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14)}-${randomUUID().slice(0, 8)}`;
    if (!ROTATION_ID.test(rotationId)) throw new Error("Requested rotation ID is invalid.");
    if (!imageAuthorization?.filePath) throw new Error("image authorization evidence file is required.");
    const preparedImageAuthorization = readInputFile(imageAuthorization.filePath, repositoryRoot, "Image authorization evidence");
    const suppliedImageAuthorization = { ...imageAuthorization }; delete suppliedImageAuthorization.filePath;
    if (canonicalHash(suppliedImageAuthorization) !== canonicalHash(preparedImageAuthorization.value)) throw new Error("Image authorization input differs from its authenticated file.");
    assertImageAuthorization(preparedImageAuthorization.value, protectedSha, imageAuthorizationValidation);
    const backendImageDigest = authorizedBackendDigest(preparedImageAuthorization.value);
    if (!backendImageDigest) throw new Error("Authorized backend image digest is missing.");
    if (!iamEvidence?.filePath) throw new Error("IAM evidence file is required.");
    const preparedIamEvidence = readInputFile(iamEvidence.filePath, repositoryRoot, "IAM evidence");
    const suppliedIamEvidence = { ...iamEvidence }; delete suppliedIamEvidence.filePath;
    if (canonicalHash(suppliedIamEvidence) !== canonicalHash(preparedIamEvidence.value)) throw new Error("IAM evidence input differs from its authenticated file.");
    if (preparedIamEvidence.value.status !== "valid" || preparedIamEvidence.value.iamEvaluationCensus?.executed !== preparedIamEvidence.value.iamEvaluationCensus?.total || preparedIamEvidence.value.iamEvaluationCensus?.invalid !== 0) throw new Error("IAM evidence is incomplete.");
    assertPreCutoverTemporaryCapabilityAbsent(preparedIamEvidence.value.temporaryKmsCapability, { sourceSha: protectedSha });
    if (!releasePreflightEvidenceFile) throw new Error("Release-preflight checker-trust evidence file is required.");
    const releasePreflightEvidence = readInputFile(releasePreflightEvidenceFile, repositoryRoot, "Release-preflight checker-trust evidence");
    if (!releasePreflightAttestationFile || !releasePreflightAttestationSignatureFile) throw new Error("Release-preflight checker-trust attestation and signature files are required.");
    const releasePreflightAttestation = readInputFile(releasePreflightAttestationFile, repositoryRoot, "Release-preflight checker-trust attestation");
    const releasePreflightAttestationSignature = readInputFile(releasePreflightAttestationSignatureFile, repositoryRoot, "Release-preflight checker-trust attestation signature");
    authenticateReleasePreflightCheckerTrustEvidence({
      report: releasePreflightEvidence.value,
      reportBytes: readStageBPrivateFileBytes({ filePath: releasePreflightEvidence.path, repositoryRoot, label: "Release-preflight checker-trust evidence" }).bytes,
      attestation: releasePreflightAttestation.value,
      attestationBytes: readStageBPrivateFileBytes({ filePath: releasePreflightAttestation.path, repositoryRoot, label: "Release-preflight checker-trust attestation" }).bytes,
      signatureArtifact: releasePreflightAttestationSignature.value,
      signatureBytes: readStageBPrivateFileBytes({ filePath: releasePreflightAttestationSignature.path, repositoryRoot, label: "Release-preflight checker-trust attestation signature" }).bytes,
      sourceSha: protectedSha,
      administratorReportSha256: preparedIamEvidence.sha256,
      expectedAttestationFileSha256: releasePreflightAttestation.sha256,
      expectedSignatureFileSha256: releasePreflightAttestationSignature.sha256,
      verifySignature: verifyReleasePreflightAttestationSignature,
    });
    const temporaryKmsCapability = temporaryKmsCapabilityFile ? readInputFile(temporaryKmsCapabilityFile, repositoryRoot, "Temporary Stage-A KMS capability evidence") : null;
    if (temporaryKmsCapability) {
      assertPreCutoverTemporaryCapabilityAbsent(temporaryKmsCapability.value, { sourceSha: protectedSha });
      if (canonicalHash(temporaryKmsCapability.value) !== canonicalHash(preparedIamEvidence.value.temporaryKmsCapability)) throw new Error("Standalone temporary capability evidence diverges from canonical IAM evidence.");
    }
    if (!artifactBindingFile) throw new Error("Existing artifact-signing runtime binding file is required.");
    const artifactBinding = readStageBPrivateFileBytes({ filePath: artifactBindingFile, repositoryRoot, label: "Artifact-signing runtime binding" });
    const artifactBindings = loadApprovedArtifactSigningBindings(artifactBinding.path, { expectedSourceSha: protectedSha, expectedSha256: artifactBinding.sha256, repositoryRoot });
    if (!rootDropEvidenceFile) throw new Error("Root-drop evidence file is required.");
    const rootDrop = readInputFile(rootDropEvidenceFile, repositoryRoot, "Root-drop evidence");
    assertRootDropEvidence(rootDrop.value, { sourceSha: protectedSha, ...(verifyRootDropSignature ? { verifySignature: verifyRootDropSignature } : {}) });
    if ((stageAPlanPath && stageARecoveryEvidenceFile) || (!stageAPlanPath && !stageARecoveryEvidenceFile)) throw new Error("Exactly one of preserved Stage-A saved plan or post-apply Stage-A recovery evidence is required.");
    const stageARecovery = stageARecoveryEvidenceFile ? readInputFile(stageARecoveryEvidenceFile, repositoryRoot, "Stage-A recovery evidence") : null;
    if (stageARecovery && (!stageAStatePath || !stageAHandoffPath || !stageBStatePath || !currentStageBStatePath)) throw new Error("Stage-A recovery requires historical provenance and the authenticated current Stage-B state.");
    for (const [filePath, label] of [[stageAStatePath, "Stage-A state"], [stageAHandoffPath, "Stage-A handoff"], [stageBStatePath, "Historical Stage-B state"], [currentStageBStatePath, "Current Stage-B state"]]) if (stageARecovery) ensureStageBPrivateFile({ filePath, repositoryRoot, label });
    if (stageARecovery) assertPostApplyStageAPlanRecovery(stageARecovery.value, { sourceSha: protectedSha, expectedStageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", expectedStageBSerial: 98, authenticated: { ...readAuthenticatedStageARecoverySources({ stageAStatePath, stageAHandoffPath, stageBStatePath, repositoryRoot }), ingress: stageARecovery.value.ingress } });
    const stageAPlan = stageAPlanPath ? readStageBPrivateFileBytes({ filePath: stageAPlanPath, repositoryRoot, label: "Preserved Stage-A saved plan" }) : null;
    const reviewedOnboardingPaths = assertOnboardingPaths(onboardingPaths || PRODUCTION_ONBOARDING_PATHS);
    onboardingPathsFile = path.join(directory, "onboarding-paths.json");
    onboardingPathsBytes = Buffer.from(`${JSON.stringify(reviewedOnboardingPaths, null, 2)}\n`);
    if (!inventoryApprovalId || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(inventoryApprovalId)) throw new Error("Inventory approval ID is required.");
    if (!stageBTfvarsPath || !stageBTfvarsBindingReportPath || !SHA256.test(stageBTfvarsBindingReportSha256 || "") || !stageBTerraformDataDir) throw new Error("Canonical Stage B tfvars and Terraform data directory are required for rotation infrastructure convergence.");
    ensureStageBPrivateFile({ filePath: stageBTfvarsPath, repositoryRoot, label: "Canonical Stage B tfvars" });
    const stageBTfvarsBinding = readInputFile(stageBTfvarsBindingReportPath, repositoryRoot, "Canonical Stage B tfvars binding report");
    if (stageBTfvarsBinding.sha256 !== stageBTfvarsBindingReportSha256) throw new Error("Canonical Stage B tfvars binding report hash does not match its authenticated input.");
    ensureStageBPrivateDirectory({ directory: stageBTerraformDataDir, repositoryRoot, create: false, normalize: true, label: "Canonical Stage B Terraform data directory" });
    let currentStageBStateSha256 = null;
    if (stageARecovery) {
      const checkedCurrentStageB = readStageBPrivateFileBytes({ filePath: currentStageBStatePath, repositoryRoot, label: "Current Stage-B state" });
      const currentStageB = { path: checkedCurrentStageB.path, value: parseAuthenticatedStateBytes(checkedCurrentStageB.bytes), sha256: checkedCurrentStageB.sha256 };
      if (currentStageB.sha256 !== stageBTfvarsBinding.value.stateBackupSha256 || currentStageB.value.lineage !== stageBTfvarsBinding.value.stateLineage || currentStageB.value.serial !== stageBTfvarsBinding.value.stateSerial) throw new Error("Current Stage-B state is not bound to canonical Stage-B tfvars evidence.");
      assertAuthenticatedCurrentStageBState(currentStageB.value, currentStageB.value, { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a" });
      currentStageBStateSha256 = currentStageB.sha256;
    }
    const loadedTaskDefinition = typeof loadCurrentTaskDefinition === "function" ? loadCurrentTaskDefinition() : currentTaskDefinition;
    const taskDefinition = loadedTaskDefinition?.taskDefinition || loadedTaskDefinition;
    const { baseUrl, currentKeyVersion } = deriveRuntimeMetadata(taskDefinition);
    const liveLegacyBaseline = deriveLegacyRotationBaseline(taskDefinition);
    const initialMigrationSourceAdvance = buildInitialMigrationSourceAdvance({
      currentSourceSha: protectedSha,
      rotationBindings,
      rebaselineAuthorization,
      supersessionEvidence: rotationSupersessionEvidence,
      liveLegacyBaseline,
      proveDescendant: proveSourceAdvance || (({ ancestorSha, descendantSha }) => {
        try { (git || execFileSync)("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { stdio: "ignore" }); return true; } catch { return false; }
      }),
    });
    const approvalConfig = { ...buildProductionRotationConfig({ sourceSha: protectedSha, rotationId, approval, bindings: rotationBindings, rebaselineAuthorization, rebaselineAuthorizationCoordinates, verifyRebaselineLivePostWrite, liveCurrentKeyVersion: currentKeyVersion }), ...(initialMigrationSourceAdvance ? { initialMigrationSourceAdvance } : {}) };
    const overlapTaskInput = buildOverlapTaskDefinition({
      backendImage: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${backendImageDigest}`,
      releaseSha: protectedSha,
      backendLogGroup: STAGE_B.inventoryLogGroupName,
      secretBindings: {
        ...rotationBindingsToTaskBindings(rotationBindings),
        ...artifactBindings,
        ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read",
      },
    }).taskDefinition;
    const rotationTerraformInputs = buildRotationTerraformInputs({
      sourceSha: protectedSha,
      rotationId: approvalConfig.rotationId,
      secretBindings: { ...rotationBindingsToPostPrepareTaskBindings(rotationBindings), ...artifactBindings },
    });
    rotationTerraformInputFile = path.join(directory, "rotation-infrastructure.tfvars");
    const existingRotationInput = lstatSync(rotationTerraformInputFile, { throwIfNoEntry: false });
    if (existingRotationInput) throw new Error("rotationTerraformInputFile must not already exist.");
    rotationTerraformInputBytes = Buffer.from(renderRotationTerraformInput(rotationTerraformInputs));
    staticBindings = {
      ...approvalConfig,
      artifactBindingFile: path.resolve(artifactBindingFile),
      imageAuthorizationFile: preparedImageAuthorization.path,
      iamEvidenceFile: preparedIamEvidence.path,
      iamEvidenceSha256: preparedIamEvidence.value.evidence?.evidenceSha256 || preparedIamEvidence.value.evidenceSha256 || null,
      releasePreflightEvidenceFile: releasePreflightEvidence.path,
      releasePreflightEvidenceFileSha256: releasePreflightEvidence.sha256,
      releasePreflightAttestationFile: releasePreflightAttestation.path,
      releasePreflightAttestationFileSha256: releasePreflightAttestation.sha256,
      releasePreflightAttestationSignatureFile: releasePreflightAttestationSignature.path,
      releasePreflightAttestationSignatureFileSha256: releasePreflightAttestationSignature.sha256,
      rootDropEvidenceFile: rootDrop.path,
      rootDropEvidenceSha256: rootDrop.sha256,
      temporaryKmsCapabilityFile: temporaryKmsCapability?.path || null,
      temporaryKmsCapabilitySha256: temporaryKmsCapability?.sha256 || null,
      stageARoot: path.resolve("infra/aws/terraform/production-green-stage-a"),
      stageAPlanPath: stageAPlanPath ? path.resolve(stageAPlanPath) : null,
      stageAPlanSha256: stageAPlan?.sha256 || null,
      stageARecoveryEvidenceFile: stageARecovery?.path || null,
      stageARecoveryEvidenceSha256: stageARecovery?.sha256 || null,
      stageARecoveryMode: stageARecovery?.value?.mode || null,
      stageAStatePath: stageARecovery ? path.resolve(stageAStatePath) : null,
      stageAHandoffPath: stageARecovery ? path.resolve(stageAHandoffPath) : null,
      stageBStatePath: stageARecovery ? path.resolve(stageBStatePath) : null,
      currentStageBStatePath: stageARecovery ? path.resolve(currentStageBStatePath) : null,
      currentStageBStateSha256,
      artifactBindingSha256: artifactBinding.sha256,
      imageAuthorizationSha256: preparedImageAuthorization.sha256,
      iamEvidenceFileSha256: preparedIamEvidence.sha256,
      backendImageDigest,
      expectedCurrentTaskDefinitionArn: taskDefinition?.taskDefinitionArn,
      inventoryApprovalId,
      inventoryDatabaseSecretArn: overlapTaskInput.containerDefinitions.find(({ name }) => name === "backend")?.secrets?.find(({ name }) => name === "DATABASE_URL")?.valueFrom,
      inventoryTaskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
      inventoryExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
      rotationInventoryRlsRole: "mscqr_prod_rls_read",
      inventoryLogGroupName: STAGE_B.inventoryLogGroupName,
      overlapTaskInput: { backendImage: overlapTaskInput.containerDefinitions.find(({ name }) => name === "backend")?.image, releaseSha: protectedSha, backendLogGroup: STAGE_B.inventoryLogGroupName, secretBindings: { ...rotationBindingsToTaskBindings(rotationBindings), ...artifactBindings, ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } },
      ...paths,
      stageBTfvarsPath: path.resolve(stageBTfvarsPath),
      stageBTfvarsBindingReportPath: path.resolve(stageBTfvarsBindingReportPath),
      stageBTfvarsBindingReportSha256,
      stageBTerraformDataDir: path.resolve(stageBTerraformDataDir),
      rotationTerraformInputFile,
      rotationTerraformInputSha256: hash(rotationTerraformInputBytes),
      onboardingBaseUrl: baseUrl,
      onboardingPaths: reviewedOnboardingPaths,
      onboardingPathsFile,
      onboardingPathsSha256: hash(onboardingPathsBytes),
      rotationHealthUrl: `${baseUrl}/api/health`,
      rotationDeploymentSha: protectedSha,
      runtimeInvocationRef: approvalConfig.verificationRef,
      releaseProfile: "mscqr-production-release-deployer",
      verifierProfile: "mscqr-production-ecs-exec-verifier",
    };
    assertNoSecretMaterial(staticBindings, "Generated cutover runtime config");
    configBytes = Buffer.from(`${JSON.stringify(staticBindings, null, 2)}\n`);
    runtimeConfigSha256 = hash(configBytes);
  } catch (error) { blockers.push(error.message); }
  const manifest = {
    schemaVersion: 1,
    generatedBy: "scripts/aws/prepare-production-cutover-runtime.mjs",
    protectedMainSha: protectedSha || null,
    staticBindingSha256: staticBindings ? canonicalHash(staticBindings) : null,
    runtimeConfigSha256,
    phaseArtifacts: { rotationState: paths.rotationStateFile, rotationFixture: paths.rotationFixtureFile, readinessEvidence: paths.readinessEvidenceFile, rotationTerraformInput: paths.rotationTerraformInputFile },
    blockers: [...new Set(blockers)],
    readyToConsumeMfa: blockers.length === 0,
  };
  const manifestPath = path.join(directory, "cutover-runtime-manifest.json");
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  if (blockers.length) {
    writeStageBPrivateFileAtomic({ filePath: manifestPath, bytes: manifestBytes, repositoryRoot, label: "Cutover runtime manifest" });
    return { readyToConsumeMfa: false, blockers: manifest.blockers, runtimeDirectory: directory, manifestPath, phasePaths: paths, protectedMainSha: protectedSha || null };
  }
  const configPath = paths.rotationConfigFile;
  writeStageBPrivateFilesAtomic({ files: [
    { filePath: onboardingPathsFile, bytes: onboardingPathsBytes, label: "Canonical onboarding path manifest" },
    { filePath: rotationTerraformInputFile, bytes: rotationTerraformInputBytes, label: "Rotation Terraform input" },
    { filePath: manifestPath, bytes: manifestBytes, label: "Cutover runtime manifest" },
    { filePath: configPath, bytes: configBytes, label: "Generated rotation config" },
  ], repositoryRoot });
  if (typeof constructAdapters === "function") {
    try {
      constructAdapters({ config: staticBindings, sourceSha: protectedSha, rotationId: staticBindings.rotationId, runtimeConfigSha256 });
    } catch (error) {
      for (const filePath of [onboardingPathsFile, rotationTerraformInputFile, manifestPath, configPath]) rmSync(filePath, { force: true });
      const failedManifest = { ...manifest, blockers: [error.message], readyToConsumeMfa: false };
      writeStageBPrivateFileAtomic({ filePath: manifestPath, bytes: Buffer.from(`${JSON.stringify(failedManifest, null, 2)}\n`), repositoryRoot, label: "Cutover runtime manifest" });
      return { readyToConsumeMfa: false, blockers: failedManifest.blockers, runtimeDirectory: directory, manifestPath, phasePaths: paths, protectedMainSha: protectedSha };
    }
  }
  const command = `npm run stage-b:run-cutover-operator -- --config ${shellQuote(configPath)} --config-sha256 ${runtimeConfigSha256} --source-sha ${staticBindings.sourceSha} --rotation-id ${staticBindings.rotationId}`;
  return { readyToConsumeMfa: true, runtimeDirectory: directory, configPath, runtimeConfigSha256, manifestPath, staticBindingSha256: manifest.staticBindingSha256, protectedMainSha: protectedSha, nextCommand: command, config: staticBindings, phasePaths: paths };
}

function envelopeEcsValueFrom(secretId, name) {
  if (!BASE_ARN.test(secretId || "")) throw new Error(`${name} must be a base Secrets Manager identifier before ECS JSON-key binding.`);
  return `${secretId}:value::`;
}

function rotationBindingsToTaskBindings(bindings) {
  if (!bindings?.jwt || !bindings?.qr) throw new Error("Rotation SDK bindings are required before ECS binding derivation.");
  return {
    JWT_SECRET_CURRENT: bindings.jwt.currentSecretId,
    JWT_SECRET_PREVIOUS: envelopeEcsValueFrom(bindings.jwt.previousSecretId, "JWT previous"),
    QR_SIGN_PRIVATE_KEY_CURRENT: bindings.qr.privateCurrentSecretId,
    QR_SIGN_PUBLIC_KEY_CURRENT: bindings.qr.publicCurrentSecretId,
    QR_SIGN_ACTIVE_KEY_VERSION: envelopeEcsValueFrom(bindings.qr.currentKeyVersionSecretId, "QR current key version"),
    QR_SIGN_PUBLIC_KEY_PREVIOUS: envelopeEcsValueFrom(bindings.qr.publicPreviousSecretId, "QR previous public key"),
    QR_SIGN_PREVIOUS_KEY_VERSION: envelopeEcsValueFrom(bindings.qr.previousKeyVersionSecretId, "QR previous key version"),
  };
}

export function rotationBindingsToPostPrepareTaskBindings(bindings) {
  const ecs = rotationBindingsToTaskBindings(bindings);
  return {
    ...ecs,
    JWT_SECRET_CURRENT: envelopeEcsValueFrom(bindings.jwt.currentSecretId, "JWT current"),
    QR_SIGN_PRIVATE_KEY_CURRENT: envelopeEcsValueFrom(bindings.qr.privateCurrentSecretId, "QR private current"),
    QR_SIGN_PUBLIC_KEY_CURRENT: envelopeEcsValueFrom(bindings.qr.publicCurrentSecretId, "QR public current"),
  };
}

const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

export function parseBootstrapArgs(argv) {
  const supported = new Set([
    "output-directory", "ticket", "approved-by", "approver-role", "reason", "verification-ref",
    "minimum-grace-seconds", "rotation-bindings", "rotation-supersession-evidence", "rebaseline-authorization-run-id", "rebaseline-authorization-run-attempt", "image-authorization", "iam-evidence", "release-preflight-evidence", "release-preflight-attestation", "release-preflight-attestation-signature",
    "artifact-binding", "root-drop-evidence", "temporary-kms-capability", "stage-a-plan", "stage-a-recovery-evidence", "stage-a-state", "stage-a-handoff", "stage-b-state", "current-stage-b-state", "inventory-approval-id", "onboarding-paths",
    "stage-b-tfvars", "stage-b-tfvars-binding-report", "stage-b-tfvars-binding-report-sha256", "stage-b-terraform-data-dir",
  ]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (!name.startsWith("--") || !supported.has(name.slice(2)) || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`Invalid or unsupported bootstrap argument: ${name}`);
    const key = name.slice(2);
    if (values.has(key)) throw new Error(`Duplicate bootstrap argument: ${name}`);
    values.set(key, argv[++index]);
  }
  return values;
}

export { discoverGit, phasePaths, assertBindings, rotationBindingsToTaskBindings };
