import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync, chmodSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createHash } from "node:crypto";
import { createProductionCutoverAdapters, createProductionRotationInfrastructureAdapter } from "../aws/production-cutover-production-adapters.mjs";
import { assertImageAuthorization } from "../aws/production-cutover-control-plane.mjs";
import { createProductionRotationPrepareAdapter } from "../aws/production-rotation-prepare-adapter.mjs";
import { buildInitialMigrationSourceAdvance, parseBootstrapArgs, prepareProductionCutoverRuntime, rotationBindingsToPostPrepareTaskBindings, rotationBindingsToTaskBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";
import { productionSupersessionEvidenceIdentity, productionSupersessionVersionId } from "../security/production-initial-migration-source-advance.mjs";
import { assertUniqueSecretBindingNames, buildOverlapTaskDefinition } from "../aws/production-overlap-task-definition.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { PRODUCTION_ONBOARDING_PATHS } from "../security/production-onboarding-contract.mjs";
import { stageBApprovalIdForReleaseSha } from "../aws/production-green-stage-b-contract.mjs";
import { buildRootDropEvidence, buildRootDropPayload } from "../aws/production-root-drop-evidence.mjs";
import { buildTemporaryCapabilityEvidence } from "../aws/production-stage-a-temporary-kms-capability.mjs";
import {
  assertProductionRotationGraceSeconds,
  deriveProductionRotationCleanupEligibleAt,
  PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS,
  PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS,
} from "../../backend/scripts/security/production-rotation-grace-contract.mjs";
import { artifactSigningRuntimeBindingPath, loadArtifactSigningBootstrapContract } from "../aws/production-artifact-signing-bootstrap.mjs";
import { runCli as runArtifactSigningBootstrap } from "../aws/bootstrap-production-artifact-signing.mjs";
import { producePostApplyStageAPlanRecovery } from "../aws/production-stage-a-recovery-evidence.mjs";
import { STAGE_A_STATE_IDENTITY_VERSION, stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";
import { productionStageAIngress, productionStageAState, STAGE_A_STATE_OBJECT } from "./fixtures/production-stage-a-state.mjs";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { buildReleasePreflightCheckerTrustAttestation } from "../aws/production-release-preflight-checker-attestation.mjs";
import { signPermissionReport } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { assertInitialDualSlotBindings } from "../aws/production-initial-dual-slot-bootstrap.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { buildPartialRebaselineRecoveryCompletion, buildPartialRebaselineRecoveryRotationBindings, createPartialRebaselineRecoveryAuthorization, PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA, assertPartialRebaselineRecoveryAuthorization } from "../aws/production-dual-slot-rebaseline-contract.mjs";
import { partialRecoveryEnvelopeFixture, partialRecoveryOriginalPreparationFixture } from "./fixtures/partial-rebaseline-runtime.mjs";

const sourceSha = "96a4be6f0edcd626285c6a1bd8062a4008175d25";
const digest = "sha256:5c03df843e46dd0853762108c7ae780a4d06b7e11cac585d9d2b2cd3d196f6ad";
const image = "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@" + digest;
const paths = PRODUCTION_ONBOARDING_PATHS;
const secretArn = (name) => ["arn", "aws", "secretsmanager", "eu-west-2", "368992683803", `secret:${name}`].join(":");
const bindings = {
  schemaVersion: 2,
  kind: "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS",
  producer: "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation",
  sourceSha,
  rotationId: "rotation-initial-fixture",
  jwt: {
    currentSecretId: secretArn("mscqr/prod/jwt-current-a"),
    previousSecretId: secretArn("mscqr/prod/jwt-previous-b"),
    pendingSecretId: secretArn("mscqr/prod/jwt-pending-c"),
  },
  qr: {
    privateCurrentSecretId: secretArn("mscqr/prod/qr-private-current-d"),
    privatePendingSecretId: secretArn("mscqr/prod/qr-private-pending-e"),
    publicCurrentSecretId: secretArn("mscqr/prod/qr-public-current-f"),
    publicPreviousSecretId: secretArn("mscqr/prod/qr-public-previous-g"),
    currentKeyVersionSecretId: secretArn("mscqr/prod/qr-current-version-i"),
    previousKeyVersionSecretId: secretArn("mscqr/prod/qr-previous-version-j"),
    publicPendingSecretId: secretArn("mscqr/prod/qr-public-pending-h"),
    previousKeyVersion: "qr-v1",
  },
};

function sourceAdvanceEvidence(originalSourceSha, rotationId, sourceBindings = bindings) {
  const arns = {
    jwtPending: sourceBindings.jwt.pendingSecretId,
    qrPrivatePending: sourceBindings.qr.privatePendingSecretId,
    qrPublicPending: sourceBindings.qr.publicPendingSecretId,
    jwtPrevious: sourceBindings.jwt.previousSecretId,
    qrPublicPrevious: sourceBindings.qr.publicPreviousSecretId,
    qrCurrentVersion: sourceBindings.qr.currentKeyVersionSecretId,
    qrPreviousVersion: sourceBindings.qr.previousKeyVersionSecretId,
  };
  const resources = Object.fromEntries(Object.entries(arns).map(([slot, arn]) => [slot, { arn, versionId: productionSupersessionVersionId(originalSourceSha, rotationId, slot), stages: ["AWSCURRENT"] }]));
  const evidence = { schemaVersion: 1, transition: "SUPERSEDE_STALE_PENDING", sourceSha: originalSourceSha, staleSourceSha: "7".repeat(40), rotationId, staleRotationId: "rotation-stale-source", generatedAt: "2026-08-26T06:06:32.000Z", resources };
  evidence.evidenceIdentitySha256 = productionSupersessionEvidenceIdentity(evidence);
  return evidence;
}

function gitFixture(expectedSha = sourceSha) {
  return (file, args) => {
    if (file === "git" && args[0] === "status") return "";
    if (file === "git" && args[0] === "fetch") return "";
    if (file === "git" && args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return expectedSha + "\n";
    if (file === "git" && args[0] === "rev-parse") return expectedSha + "\n";
    throw new Error("unexpected git call: " + file + " " + args.join(" "));
  };
}

function approval() {
  return { ticket: "CHG-ROTATION-0001", approvedBy: "security@example.invalid", approverRole: "Security Lead", reason: "Scheduled production security rotation", verificationRef: "https://example.invalid/approval/1", minimumGraceSeconds: PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS };
}

const verifyInitialBindingOrigin = ({ bindings: candidate }) => ({ kind: "PRODUCTION_INITIAL_DUAL_SLOT_ROTATION_BINDINGS", producer: "scripts/aws/production-initial-dual-slot-bootstrap.mjs:bootstrapInitialDualSlotRotation", sourceSha: candidate.sourceSha, rotationId: candidate.rotationId, bindingSha256: canonicalSha256(candidate) });
const strictInitialBindingOrigin = ({ bindings: candidate }) => {
  if (JSON.stringify(Object.keys(candidate).sort()) !== JSON.stringify(["ecs", "jwt", "kind", "legacy", "producer", "qr", "rotationId", "schemaVersion", "sourceSha"])) throw new Error("Live initial binding origin schema is not exact.");
  assertInitialDualSlotBindings(candidate);
  return verifyInitialBindingOrigin({ bindings: candidate });
};

function taskDefinition(taskBindings = bindings) {
  return { taskDefinition: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47", containerDefinitions: [{ name: "backend", environment: [{ name: "PUBLIC_APP_URL", value: "https://www.mscqr.com" }, { name: "QR_SIGN_ACTIVE_KEY_VERSION", value: taskBindings.qr.previousKeyVersion }], secrets: [{ name: "JWT_SECRET", valueFrom: taskBindings.jwt.currentSecretId }, { name: "QR_SIGN_PRIVATE_KEY", valueFrom: taskBindings.qr.privateCurrentSecretId }, { name: "QR_SIGN_PUBLIC_KEY", valueFrom: taskBindings.qr.publicCurrentSecretId }] }] } };
}

function evidenceFiles(directory, repositoryRoot, expectedSha = sourceSha, imageReleaseSha) {
  const file = (name, value) => { const target = path.join(directory, name); writeFileSync(target, JSON.stringify(value) + "\n", { mode: 0o600 }); chmodSync(target, 0o600); return target; };
  const imageAuthorizationFixture = makeCanonicalImageAuthorization({ sourceSha: expectedSha, ...(imageReleaseSha ? { imageReleaseSha } : {}) });
  const imageAuthorization = file("image-authorization.json", imageAuthorizationFixture.authorization);
  const iamEvidence = file("iam-evidence.json", { status: "valid", iamEvaluationCensus: { total: 158, executed: 158, invalid: 0, failures: [] }, evidenceSha256: "d".repeat(64) });
  const temporaryKmsCapability = file("temporary-kms-capability.json", buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha: expectedSha, transitionId: "rehearsal-transition", defaultVersionId: "v1", observedAt: "2026-08-18T12:00:00.000Z" }));
  const iamDocument = JSON.parse(readFileSync(iamEvidence, "utf8"));
  iamDocument.temporaryKmsCapability = JSON.parse(readFileSync(temporaryKmsCapability, "utf8"));
  writeFileSync(iamEvidence, JSON.stringify(iamDocument) + "\n", { mode: 0o600 });
  chmodSync(iamEvidence, 0o600);
  const releasePreflightEvidence = file("release-preflight.json", {
    status: "ready-for-plan",
    sourceSha: expectedSha,
    administratorReportSha256: createHash("sha256").update(readFileSync(iamEvidence)).digest("hex"),
    checkerTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN },
  });
  const releasePreflightReportBytes = readFileSync(releasePreflightEvidence);
  const releasePreflightAttestation = file("release-preflight.attestation.json", buildReleasePreflightCheckerTrustAttestation({
    report: JSON.parse(releasePreflightReportBytes),
    reportBytes: releasePreflightReportBytes,
    sourceSha: expectedSha,
    administratorReportSha256: createHash("sha256").update(readFileSync(iamEvidence)).digest("hex"),
  }));
  const releasePreflightAttestationSignature = file("release-preflight.attestation.signature.json", signPermissionReport(JSON.parse(readFileSync(releasePreflightAttestation)), {
    now: new Date().toISOString(),
    reportBytes: readFileSync(releasePreflightAttestation),
    sign: () => "AQ==",
  }));
  const rootDrop = file("root-drop.json", buildRootDropEvidence({ payload: buildRootDropPayload({ sourceSha: expectedSha, callerArn: "arn:aws:iam::368992683803:root", now: new Date().toISOString(), nonce: "runtime-bootstrap-root-with-entropy" }), signatureBase64: "c2lnbmF0dXJl" }));
  const stageAPlan = file("stage-a.tfplan", "binary-fixture");
  const tfvarsBytes = Buffer.from("production_rotation_enabled = false\n");
  const stageBTfvarsPath = path.join(directory, "stage-b.tfvars");
  writeFileSync(stageBTfvarsPath, tfvarsBytes, { mode: 0o600 }); chmodSync(stageBTfvarsPath, 0o600);
  const stageBTfvarsBindingReportPath = file("stage-b.tfvars.binding.json", { schemaVersion: 2, tfvarsSchemaVersion: 1, tfvarsFormat: "hcl", tfvarsFileName: "stage-b.tfvars", tfvarsExtension: ".tfvars", generator: "scripts/aws/generate-production-green-stage-b-tfvars.mjs", tfvarsSha256: createHash("sha256").update(tfvarsBytes).digest("hex") });
  const stageBTerraformDataDir = path.join(directory, "terraform-data");
  mkdirSync(stageBTerraformDataDir, { mode: 0o700 }); chmodSync(stageBTerraformDataDir, 0o700);
  const artifactBinding = artifactSigningRuntimeBindingPath(expectedSha);
  mkdirSync(path.dirname(artifactBinding), { recursive: true, mode: 0o700 }); chmodSync(path.dirname(artifactBinding), 0o700);
  writeFileSync(artifactBinding, JSON.stringify({ schemaVersion: 2, generatedBy: "scripts/aws/production-artifact-signing-bootstrap.mjs", sourceSha: expectedSha, bindings: {
    ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: secretArn("mscqr/production/rls-green/artifact-signing/private-key-current-a"),
    ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: secretArn("mscqr/production/rls-green/artifact-signing/public-key-current-b"),
    ARTIFACT_SIGN_ACTIVE_KEY_VERSION: secretArn("mscqr/production/rls-green/artifact-signing/active-key-version-c"),
    ARTIFACT_SIGN_PUBLIC_KEYS_JSON: secretArn("mscqr/production/rls-green/artifact-signing/public-keys-json-d"),
  } }, null, 2));
  chmodSync(artifactBinding, 0o600);
  return { imageAuthorization, imageAuthorizationFixture, iamEvidence, releasePreflightEvidence, releasePreflightAttestation, releasePreflightAttestationSignature, temporaryKmsCapability, rootDrop, stageAPlan, artifactBinding, stageBTfvarsPath, stageBTfvarsBindingReportPath, stageBTfvarsBindingReportSha256: createHash("sha256").update(readFileSync(stageBTfvarsBindingReportPath)).digest("hex"), stageBTerraformDataDir };
}

function fullInput(directory, repositoryRoot, expectedSha = sourceSha, imageReleaseSha) {
  const evidence = evidenceFiles(directory, repositoryRoot, expectedSha, imageReleaseSha);
  return {
    outputDirectory: path.join(directory, "runtime"),
    repositoryRoot,
    approval: approval(),
    rotationBindings: bindings,
    git: gitFixture(expectedSha),
    imageAuthorization: { ...JSON.parse(readFileSync(evidence.imageAuthorization, "utf8")), filePath: evidence.imageAuthorization },
    iamEvidence: { ...JSON.parse(readFileSync(evidence.iamEvidence, "utf8")), filePath: evidence.iamEvidence },
    releasePreflightEvidenceFile: evidence.releasePreflightEvidence,
    releasePreflightAttestationFile: evidence.releasePreflightAttestation,
    releasePreflightAttestationSignatureFile: evidence.releasePreflightAttestationSignature,
    temporaryKmsCapabilityFile: evidence.temporaryKmsCapability,
    artifactBindingFile: evidence.artifactBinding,
    rootDropEvidenceFile: evidence.rootDrop,
    stageAPlanPath: evidence.stageAPlan,
    stageBTfvarsPath: evidence.stageBTfvarsPath,
    stageBTfvarsBindingReportPath: evidence.stageBTfvarsBindingReportPath,
    stageBTfvarsBindingReportSha256: evidence.stageBTfvarsBindingReportSha256,
    stageBTerraformDataDir: evidence.stageBTerraformDataDir,
    currentTaskDefinition: taskDefinition(),
    inventoryApprovalId: stageBApprovalIdForReleaseSha(expectedSha),
    onboardingPaths: paths,
    constructAdapters: ({ config, sourceSha: actualSha, rotationId, runtimeConfigSha256 }) => createProductionCutoverAdapters({ config, sourceSha: actualSha, rotationId, runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }),
    imageAuthorizationValidation: { now: evidence.imageAuthorizationFixture.now, verifyImageEvidence: evidence.imageAuthorizationFixture.verifyImageEvidence },
    verifyRootDropSignature: () => true,
    verifyReleasePreflightAttestationSignature: () => true,
    verifyInitialBindingOrigin,
  };
}

test("REAL_BOOTSTRAP_TO_CONSTRUCTOR generates config without future state or fixture", () => {
  const repositoryRoot = process.cwd();
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, repositoryRoot));
    assert.equal(result.readyToConsumeMfa, true);
    assert.equal(result.protectedMainSha, sourceSha);
    assert.equal(existsSync(result.configPath), true);
    assert.equal(existsSync(result.phasePaths.rotationStateFile), false);
    assert.equal(existsSync(result.phasePaths.rotationFixtureFile), false);
    assert.equal(existsSync(result.config.onboardingPathsFile), true);
    assert.equal(statSync(result.config.onboardingPathsFile).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(readFileSync(result.config.onboardingPathsFile, "utf8")), paths);
    assert.equal(result.config.onboardingBaseUrl, "https://www.mscqr.com");
    assert.equal(result.config.qr.previousKeyVersion, "qr-v1");
    assert.match(result.config.stageARoot, /production-green-stage-a$/);
    assert.match(result.config.stageAPlanSha256, /^[a-f0-9]{64}$/);
    assert.equal(result.config.expectedRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-release-deployer");
    assert.equal(result.config.overlapTaskInput.secretBindings.ARTIFACT_SIGN_ACTIVE_KEY_VERSION.includes("artifact-signing"), true);
    assert.doesNotMatch(readFileSync(result.configPath, "utf8"), /PRIVATE KEY|SecretString|fixture-password|123456/);
  } finally {
    rmSync(path.join(repositoryRoot, "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rebaseline revalidation never performs a late GitHub lookup inside the sanitized AWS environment", async () => {
  const directory = fsTemp();
  try {
    const prepared = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    let ghLookupAttempted = false;
    const config = {
      ...prepared.config,
      rebaselineRuntime: { bindings, authorizationCoordinates: { workflowRunId: "123", workflowRunAttempt: "1" } },
      livePostWriteSha256: "a".repeat(64),
    };
    assert.throws(() => createProductionCutoverAdapters({
      config,
      sourceSha,
      rotationId: config.rotationId,
      runtimeConfigSha256: prepared.runtimeConfigSha256,
      verifyReleasePreflightAttestationSignature: () => true,
      createCommandRunner: () => (args) => {
        if (args[0] === "gh") {
          ghLookupAttempted = true;
          throw new Error("GitHub token missing after AWS environment sanitization");
        }
        return "{}";
      },
    }), /pre-mutation authenticated rebaseline authorization/i);
    assert.equal(ghLookupAttempted, false);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("outer runtime preparation rejects a rebaseline manifest relabeled as initial", () => {
  const directory = fsTemp();
  try {
    const relabeled = { ...bindings, operation: "PRODUCTION_DUAL_SLOT_REBASELINE", historicalRotationId: "rotation-abandoned", abandonmentEvidenceSha256: "a".repeat(64), baselineCompletionSha256: "b".repeat(64), authorizationSha256: "c".repeat(64) };
    const result = prepareProductionCutoverRuntime({ ...fullInput(directory, process.cwd()), rotationBindings: relabeled, verifyInitialBindingOrigin: strictInitialBindingOrigin });
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join(" "), /origin|schema|binding/i);
    assert.equal(result.configPath, undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("outer runtime preparation rejects an initial manifest relabeled as rebaseline", () => {
  const directory = fsTemp();
  try {
    const relabeled = { ...bindings, kind: "PRODUCTION_DUAL_SLOT_REBASELINE_ROTATION_BINDINGS", producer: "scripts/aws/rebaseline-production-dual-slot.mjs:execute", operation: "PRODUCTION_DUAL_SLOT_REBASELINE" };
    const result = prepareProductionCutoverRuntime({ ...fullInput(directory, process.cwd()), rotationBindings: relabeled, verifyInitialBindingOrigin: strictInitialBindingOrigin });
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join(" "), /origin|schema|binding/i);
    assert.equal(result.configPath, undefined);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test("source-advance bridge anchors legacy-current bindings to the live task definition", () => {
  const originalSourceSha = "5".repeat(40);
  const rotationId = "rotation-source-advance";
  const rotationBindings = { ...bindings, sourceSha: originalSourceSha, rotationId, legacy: { jwtCurrent: bindings.jwt.currentSecretId, qrPrivateCurrent: bindings.qr.privateCurrentSecretId, qrPublicCurrent: bindings.qr.publicCurrentSecretId, qrCurrentVersion: bindings.qr.previousKeyVersion } };
  const evidence = sourceAdvanceEvidence(originalSourceSha, rotationId, rotationBindings);
  const liveLegacyBaseline = { jwtCurrent: bindings.jwt.currentSecretId, qrPrivateCurrent: bindings.qr.privateCurrentSecretId, qrPublicCurrent: bindings.qr.publicCurrentSecretId, qrCurrentVersion: bindings.qr.previousKeyVersion };
  const input = { currentSourceSha: sourceSha, rotationBindings, supersessionEvidence: evidence, liveLegacyBaseline, proveDescendant: ({ ancestorSha, descendantSha }) => ancestorSha === originalSourceSha && descendantSha === sourceSha, verifyInitialBindingOrigin };
  const bridge = buildInitialMigrationSourceAdvance(input);
  assert.equal(bridge.supersessionEvidence.sourceSha, originalSourceSha);
  assert.equal(bridge.currentSourceSha, sourceSha);
  for (const changed of [
    { rotationBindings: { ...rotationBindings, rotationId: "rotation-foreign" } },
    { proveDescendant: () => false },
    { supersessionEvidence: { ...evidence, resources: { ...evidence.resources, jwtPending: { ...evidence.resources.jwtPending, arn: bindings.jwt.currentSecretId } } } },
  ]) assert.throws(() => buildInitialMigrationSourceAdvance({ ...input, ...changed }));

  for (const field of ["jwt.currentSecretId", "qr.privateCurrentSecretId", "qr.publicCurrentSecretId"]) {
    const [group, name] = field.split(".");
    const changedBindings = { ...rotationBindings, [group]: { ...rotationBindings[group], [name]: `${rotationBindings[group][name]}-changed` } };
    assert.throws(() => buildInitialMigrationSourceAdvance({ ...input, rotationBindings: changedBindings }), /authenticated live legacy/);
  }
  const changedSeven = { ...rotationBindings, jwt: { ...rotationBindings.jwt, pendingSecretId: `${rotationBindings.jwt.pendingSecretId}-changed` } };
  assert.throws(() => buildInitialMigrationSourceAdvance({ ...input, rotationBindings: changedSeven }), /resources do not match/);
});

test("same-source runtime binding still authenticates the live legacy baseline", () => {
  const liveLegacyBaseline = { jwtCurrent: bindings.jwt.currentSecretId, qrPrivateCurrent: bindings.qr.privateCurrentSecretId, qrPublicCurrent: bindings.qr.publicCurrentSecretId, qrCurrentVersion: bindings.qr.previousKeyVersion };
  assert.equal(buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: bindings, liveLegacyBaseline, verifyInitialBindingOrigin }), undefined);
  const changed = { ...bindings, jwt: { ...bindings.jwt, currentSecretId: `${bindings.jwt.currentSecretId}-changed` } };
  assert.throws(() => buildInitialMigrationSourceAdvance({ currentSourceSha: sourceSha, rotationBindings: changed, liveLegacyBaseline, verifyInitialBindingOrigin }), /authenticated live legacy/);
});

test("runtime config carries the authenticated source-advance bridge into coordinator approval bytes", () => {
  const directory = fsTemp();
  try {
    const originalSourceSha = "5".repeat(40);
    const rotationId = "rotation-source-advance";
    const rotationBindings = { ...bindings, sourceSha: originalSourceSha, rotationId, legacy: { jwtCurrent: bindings.jwt.currentSecretId, qrPrivateCurrent: bindings.qr.privateCurrentSecretId, qrPublicCurrent: bindings.qr.publicCurrentSecretId, qrCurrentVersion: bindings.qr.previousKeyVersion } };
    const evidence = sourceAdvanceEvidence(originalSourceSha, rotationId, rotationBindings);
    const input = {
      ...fullInput(directory, process.cwd()),
      rotationBindings,
      rotationSupersessionEvidence: evidence,
      proveSourceAdvance: () => true,
    };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, true);
    assert.equal(result.config.initialMigrationSourceAdvance.supersessionEvidence.sourceSha, originalSourceSha);
    assert.equal(result.config.sourceSha, sourceSha);
    assert.deepEqual(JSON.parse(readFileSync(result.configPath, "utf8")).initialMigrationSourceAdvance, result.config.initialMigrationSourceAdvance);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("artifact bootstrap keeps a clean checkout executable through runtime preparation", async () => {
  const directory = fsTemp();
  const remote = path.join(directory, "origin.git");
  const checkout = path.join(directory, "checkout");
  const actualSourceSha = sourceSha;
  execFileSync("git", ["init", "--bare", remote]);
  execFileSync("git", ["clone", "--shared", "--no-checkout", process.cwd(), checkout]);
  execFileSync("git", ["sparse-checkout", "set", "README.md"], { cwd: checkout });
  execFileSync("git", ["checkout", "-B", "main", actualSourceSha], { cwd: checkout });
  execFileSync("git", ["remote", "set-url", "origin", remote], { cwd: checkout });
  execFileSync("git", ["push", "-u", "origin", "main"], { cwd: checkout });
  const gitArgs = (args) => execFileSync("git", args, { cwd: checkout, encoding: "utf8" });
  const gitExec = (file, args) => execFileSync(file, args, { cwd: checkout, encoding: "utf8" });
  const contract = loadArtifactSigningBootstrapContract();
  const run = async (args) => {
    const name = args[args.indexOf("--secret-id") + 1];
    return JSON.stringify({ Name: name, ARN: secretArn(`${name}-AbCd12`), VersionIdsToStages: { current: ["AWSCURRENT"] } });
  };
  const evidenceDirectory = path.join(directory, "evidence");
  mkdirSync(evidenceDirectory, { mode: 0o700 });
  const input = fullInput(evidenceDirectory, checkout, actualSourceSha);
  try {
    assert.equal(Object.values(contract.names).length, 4);
    const bootstrapResult = await runArtifactSigningBootstrap(["--source-sha", actualSourceSha], { git: gitArgs, run, repositoryRoot: checkout, write: () => {} });
    assert.equal(bootstrapResult.bindingFile, artifactSigningRuntimeBindingPath(actualSourceSha));
    assert.equal(gitArgs(["status", "--porcelain=v1", "--untracked-files=all"]).trim(), "");
    input.git = gitExec;
    const prepared = prepareProductionCutoverRuntime(input);
    assert.equal(prepared.readyToConsumeMfa, true);

    writeFileSync(path.join(checkout, "dirty.txt"), "dirty\n");
    const dirtyInput = { ...input, outputDirectory: path.join(directory, "dirty-runtime") };
    const rejected = prepareProductionCutoverRuntime(dirtyInput);
    assert.equal(rejected.readyToConsumeMfa, false);
    assert.match(rejected.blockers.join("\n"), /execution tree is not clean/);
  } finally {
    rmSync(artifactSigningRuntimeBindingPath(actualSourceSha), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime adapter rejects artifact binding tamper after preparation", () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    writeFileSync(result.config.artifactBindingFile, `${readFileSync(result.config.artifactBindingFile, "utf8")} `, { mode: 0o600 });
    assert.throws(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId, runtimeConfigSha256: result.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }), /changed after runtime preparation/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime adapter authenticates every prepared eligibility artifact before AWS work", () => {
  for (const [field, message] of [
    ["iamEvidenceFile", /IAM evidence changed after runtime preparation/],
    ["releasePreflightEvidenceFile", /Release-preflight checker-trust evidence changed after runtime preparation/],
    ["rootDropEvidenceFile", /Root-drop evidence changed after runtime preparation/],
    ["onboardingPathsFile", /Onboarding path manifest changed after runtime preparation/],
  ]) {
    const directory = fsTemp();
    try {
      const input = fullInput(directory, process.cwd());
      if (field === "iamEvidenceFile") delete input.temporaryKmsCapabilityFile;
      const result = prepareProductionCutoverRuntime(input);
      writeFileSync(result.config[field], `${readFileSync(result.config[field], "utf8")} `, { mode: 0o600 });
      assert.throws(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId, runtimeConfigSha256: result.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }), message);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("runtime preparation binds release-preflight checker trust separately from administrator evidence", () => {
  const cases = [
    ["missing", (input) => { delete input.releasePreflightEvidenceFile; }, /Release-preflight checker-trust evidence file is required/],
    ["missing attestation", (input) => { delete input.releasePreflightAttestationFile; }, /attestation and signature files are required/],
    ["missing attestation signature", (input) => { delete input.releasePreflightAttestationSignatureFile; }, /attestation and signature files are required/],
    ["modified authenticated report", (input) => { writeFileSync(input.releasePreflightEvidenceFile, `${readFileSync(input.releasePreflightEvidenceFile, "utf8").trim()} \n`, { mode: 0o600 }); }, /releasePreflightReportSha256/],
    ["exact false", (input) => { const report = JSON.parse(readFileSync(input.releasePreflightEvidenceFile, "utf8")); report.checkerTrust.exact = false; writeFileSync(input.releasePreflightEvidenceFile, `${JSON.stringify(report)}\n`, { mode: 0o600 }); }, /checker Role-A MFA trust evidence is invalid/],
    ["MFA false", (input) => { const report = JSON.parse(readFileSync(input.releasePreflightEvidenceFile, "utf8")); report.checkerTrust.mfaRequired = false; writeFileSync(input.releasePreflightEvidenceFile, `${JSON.stringify(report)}\n`, { mode: 0o600 }); }, /checker Role-A MFA trust evidence is invalid/],
    ["source mismatch", (input) => { const report = JSON.parse(readFileSync(input.releasePreflightEvidenceFile, "utf8")); report.sourceSha = "a".repeat(40); writeFileSync(input.releasePreflightEvidenceFile, `${JSON.stringify(report)}\n`, { mode: 0o600 }); }, /not bound to the authenticated source/],
    ["administrator hash mismatch", (input) => { const report = JSON.parse(readFileSync(input.releasePreflightEvidenceFile, "utf8")); report.administratorReportSha256 = "0".repeat(64); writeFileSync(input.releasePreflightEvidenceFile, `${JSON.stringify(report)}\n`, { mode: 0o600 }); }, /not bound to the authenticated source/],
  ];
  for (const [name, mutate, expected] of cases) {
    const directory = fsTemp();
    try {
      const input = fullInput(directory, process.cwd());
      mutate(input);
      const result = prepareProductionCutoverRuntime(input);
      assert.equal(result.readyToConsumeMfa, false, name);
      assert.match(result.blockers.join("\n"), expected, name);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  }
});

test("rotation infrastructure revalidates the classified saved plan before apply", async () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    let applyCalls = 0;
    const run = (command, args, options) => {
      assert.equal(command, "terraform");
      assert.equal(options.env.AWS_PROFILE, "fixture");
      for (const name of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_PROFILE"]) assert.equal(options.env[name], undefined);
      if (args.includes("plan")) { writeFileSync(result.config.rotationTerraformPlanFile, "classified-plan\n", { mode: 0o600 }); return ""; }
      if (args.includes("show")) {
        writeFileSync(result.config.rotationTerraformPlanFile, "replaced-plan\n", { mode: 0o600 });
        return JSON.stringify({ resource_changes: [{ address: 'aws_iam_role_policy.execution["backend"]', change: { actions: ["update"] } }] });
      }
      if (args.includes("apply")) applyCalls += 1;
      return "";
    };
    const artifactBindings = Object.fromEntries(Object.entries(result.config.overlapTaskInput.secretBindings).filter(([name]) => name.startsWith("ARTIFACT_SIGN_")));
    const adapter = createProductionRotationInfrastructureAdapter({ run, releaseProfile: "fixture", config: result.config });
    await assert.rejects(() => adapter.run({ sourceSha, rotationId: result.config.rotationId, secretBindings: { ...rotationBindingsToPostPrepareTaskBindings(bindings), ...artifactBindings } }), /changed after classification/);
    assert.equal(applyCalls, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rotation infrastructure rejects a substituted plan destination before Terraform", async () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    symlinkSync(path.join(directory, "plan-target"), result.config.rotationTerraformPlanFile);
    let terraformCalls = 0;
    const artifactBindings = Object.fromEntries(Object.entries(result.config.overlapTaskInput.secretBindings).filter(([name]) => name.startsWith("ARTIFACT_SIGN_")));
    const adapter = createProductionRotationInfrastructureAdapter({ run: () => { terraformCalls += 1; }, releaseProfile: "fixture", config: result.config });
    await assert.rejects(() => adapter.run({ sourceSha, rotationId: result.config.rotationId, secretBindings: { ...rotationBindingsToPostPrepareTaskBindings(bindings), ...artifactBindings } }), /must not be a symlink/);
    assert.equal(terraformCalls, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("generated cutover command binds runtime config and image authorization bytes", () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    assert.throws(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId }), /Hash-authenticated/);
    assert.match(result.nextCommand, /^npm run stage-b:run-cutover-operator -- --config /);
    assert.match(result.nextCommand, new RegExp(`--config-sha256 ${result.runtimeConfigSha256}`));
    assert.equal(result.nextCommand.includes("MSCQR_VERIFIER_MFA_CODE"), false);
    assert.equal(JSON.stringify(result.config).includes("MSCQR_VERIFIER_MFA_CODE"), false);
    const run = () => execFileSync(process.execPath, ["scripts/aws/run-production-cutover.mjs", "--mode", "production", "--config", result.configPath, "--config-sha256", result.runtimeConfigSha256, "--source-sha", sourceSha, "--rotation-id", result.config.rotationId], { cwd: process.cwd(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    writeFileSync(result.configPath, `${readFileSync(result.configPath, "utf8")} `, { mode: 0o600 });
    assert.throws(run, /Production cutover runtime config changed after runtime preparation/);

  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("canonical IAM evidence is sufficient without a duplicate temporary-capability file", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    delete input.temporaryKmsCapabilityFile;
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, true);
    assert.equal(result.config.temporaryKmsCapabilityFile, null);
    assert.doesNotThrow(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId, runtimeConfigSha256: result.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime preparation validates canonical IAM evidence before live AWS discovery", () => {
  const directory = fsTemp();
  let awsReads = 0;
  try {
    const input = fullInput(directory, process.cwd());
    input.iamEvidence.iamEvaluationCensus.executed -= 1;
    const { filePath, ...report } = input.iamEvidence;
    writeFileSync(filePath, `${JSON.stringify(report)}\n`, { mode: 0o600 });
    input.loadCurrentTaskDefinition = () => { awsReads += 1; return input.currentTaskDefinition; };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /IAM evidence is incomplete/);
    assert.equal(awsReads, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime preparation requires the release-profile checker verifier before live AWS discovery", () => {
  const directory = fsTemp();
  let awsReads = 0;
  try {
    const input = fullInput(directory, process.cwd());
    delete input.verifyReleasePreflightAttestationSignature;
    input.loadCurrentTaskDefinition = () => { awsReads += 1; return input.currentTaskDefinition; };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /canonical release-profile verifier/);
    assert.equal(awsReads, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime preparation rejects fixture-bound nested KMS absence evidence before a standalone proof", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    const { filePath, ...report } = input.iamEvidence;
    report.temporaryKmsCapability = buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha: "e".repeat(40), transitionId: "preflight-eeeeeeeeeeee", defaultVersionId: "v1", observedAt: "2026-08-18T12:00:00.000Z" });
    writeFileSync(filePath, `${JSON.stringify(report)}\n`, { mode: 0o600 });
    input.iamEvidence = { ...report, filePath };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /Temporary Stage-A KMS capability: evidence identity or state is wrong/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("canonical IAM outer hash fails closed for nested, census, SHA, path, and symlink tamper", () => {
  const cases = [
    ["self-consistent nested absence", (result) => {
      const report = JSON.parse(readFileSync(result.config.iamEvidenceFile, "utf8"));
      report.temporaryKmsCapability = buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha, transitionId: "different-transition", defaultVersionId: "v1", observedAt: "2026-08-18T12:01:00.000Z" });
      writeFileSync(result.config.iamEvidenceFile, `${JSON.stringify(report)}\n`, { mode: 0o600 });
    }, /IAM evidence changed/],
    ["changed census", (result) => {
      const report = JSON.parse(readFileSync(result.config.iamEvidenceFile, "utf8"));
      report.iamEvaluationCensus.executed -= 1;
      writeFileSync(result.config.iamEvidenceFile, `${JSON.stringify(report)}\n`, { mode: 0o600 });
    }, /IAM evidence changed/],
    ["missing SHA", (result) => { delete result.config.iamEvidenceFileSha256; }, /expected SHA-256 is invalid/],
    ["malformed SHA", (result) => { result.config.iamEvidenceFileSha256 = "not-a-sha"; }, /expected SHA-256 is invalid/],
    ["wrong SHA", (result) => { result.config.iamEvidenceFileSha256 = "0".repeat(64); }, /IAM evidence changed/],
    ["repository path escape", (result) => { result.config.iamEvidenceFile = path.join(process.cwd(), "package.json"); }, /must be outside the repository|must have mode 0600/],
    ["parent symlink into repository", (result, directory) => {
      const linkedRepository = path.join(directory, "linked-repository");
      symlinkSync(process.cwd(), linkedRepository, "dir");
      result.config.iamEvidenceFile = path.join(linkedRepository, "package.json");
    }, /must be outside the repository/],
    ["symlink replacement", (result, directory) => {
      const original = result.config.iamEvidenceFile;
      const replacement = path.join(directory, "replacement-iam.json");
      writeFileSync(replacement, readFileSync(original), { mode: 0o600 });
      rmSync(original);
      symlinkSync(replacement, original);
    }, /must be a regular non-symlink file/],
  ];
  for (const [name, mutate, expected] of cases) {
    const directory = fsTemp();
    try {
      const input = fullInput(directory, process.cwd());
      delete input.temporaryKmsCapabilityFile;
      const result = prepareProductionCutoverRuntime(input);
      mutate(result, directory);
      assert.throws(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId, runtimeConfigSha256: result.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }), expected, name);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("standalone temporary-capability evidence remains independently authenticated and consistent", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    const result = prepareProductionCutoverRuntime(input);
    writeFileSync(result.config.temporaryKmsCapabilityFile, `${readFileSync(result.config.temporaryKmsCapabilityFile, "utf8")} `, { mode: 0o600 });
    assert.throws(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId, runtimeConfigSha256: result.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }), /Temporary Stage-A KMS capability evidence changed/);

    const disagreementDirectory = path.join(directory, "disagreement");
    mkdirSync(disagreementDirectory, { mode: 0o700 });
    const disagreement = fullInput(disagreementDirectory, process.cwd());
    writeFileSync(disagreement.temporaryKmsCapabilityFile, `${JSON.stringify(buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha, transitionId: "different-transition", defaultVersionId: "v1", observedAt: "2026-08-18T12:01:00.000Z" }))}\n`, { mode: 0o600 });
    const rejected = prepareProductionCutoverRuntime(disagreement);
    assert.equal(rejected.readyToConsumeMfa, false);
    assert.match(rejected.blockers.join("\n"), /diverges from canonical IAM evidence/);

    const runtimeDirectory = path.join(directory, "runtime-disagreement");
    mkdirSync(runtimeDirectory, { mode: 0o700 });
    const runtime = prepareProductionCutoverRuntime(fullInput(runtimeDirectory, process.cwd()));
    const canonicalIam = JSON.parse(readFileSync(runtime.config.iamEvidenceFile, "utf8"));
    canonicalIam.temporaryKmsCapability = buildTemporaryCapabilityEvidence({ state: "ABSENCE_VERIFIED", sourceSha, transitionId: "runtime-different-transition", defaultVersionId: "v1", observedAt: "2026-08-18T12:02:00.000Z" });
    const canonicalIamBytes = Buffer.from(`${JSON.stringify(canonicalIam)}\n`);
    writeFileSync(runtime.config.iamEvidenceFile, canonicalIamBytes, { mode: 0o600 });
    runtime.config.iamEvidenceFileSha256 = createHash("sha256").update(canonicalIamBytes).digest("hex");
    assert.throws(() => createProductionCutoverAdapters({ config: runtime.config, sourceSha, rotationId: runtime.config.rotationId, runtimeConfigSha256: runtime.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }), /diverges from canonical IAM evidence/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime preparation authenticates the tfvars binding report before consuming state identity", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    input.stageBTfvarsBindingReportSha256 = "0".repeat(64);
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /binding report hash/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("post-apply recovery binds historical provenance separately from current Stage-B state", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    const stageAState = productionStageAState();
    const historicalStageB = { version: 4, serial: 98, lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", outputs: {}, resources: [{ mode: "managed", type: "aws_ecs_service", name: "backend", instances: [{ schema_version: 0, attributes: { id: "mscqr-backend-servi-euw2" } }] }] };
    const currentStageB = { ...historicalStageB, serial: 100, outputs: { bound_images: { value: { backend: digest }, type: ["object", { backend: "string" }] } } };
    const stageAStatePath = path.join(directory, "stage-a-state.json");
    const stageAHandoffPath = path.join(directory, "stage-a-handoff.json");
    const stageBStatePath = path.join(directory, "stage-b-historical.json");
    const currentStageBStatePath = path.join(directory, "stage-b-current.json");
    const stageARecoveryEvidenceFile = path.join(directory, "stage-a-recovery.json");
    writeFileSync(stageAStatePath, JSON.stringify(stageAState), { mode: 0o600 });
    writeFileSync(stageAHandoffPath, JSON.stringify({ toolingSha: sourceSha, stageAStateIdentityVersion: STAGE_A_STATE_IDENTITY_VERSION, stageAStateObject: STAGE_A_STATE_OBJECT, stageAStateLineage: stageAState.lineage, stageAStateSerial: stageAState.serial, stageAStateSha256: stageAStateSemanticSha256(stageAState) }), { mode: 0o600 });
    writeFileSync(stageBStatePath, JSON.stringify(historicalStageB), { mode: 0o600 });
    const currentBytes = Buffer.from(JSON.stringify(currentStageB));
    writeFileSync(currentStageBStatePath, currentBytes, { mode: 0o600 });
    producePostApplyStageAPlanRecovery({ sourceSha, stageAStatePath, stageAHandoffPath, stageBStatePath, ingress: productionStageAIngress(), outputPath: stageARecoveryEvidenceFile, repositoryRoot: process.cwd() });
    const binding = JSON.parse(readFileSync(input.stageBTfvarsBindingReportPath, "utf8"));
    Object.assign(binding, { stateBackupSha256: createHash("sha256").update(currentBytes).digest("hex"), stateLineage: currentStageB.lineage, stateSerial: currentStageB.serial });
    writeFileSync(input.stageBTfvarsBindingReportPath, `${JSON.stringify(binding)}\n`, { mode: 0o600 });
    delete input.stageAPlanPath;
    Object.assign(input, { stageARecoveryEvidenceFile, stageAStatePath, stageAHandoffPath, stageBStatePath, currentStageBStatePath, stageBTfvarsBindingReportSha256: createHash("sha256").update(readFileSync(input.stageBTfvarsBindingReportPath)).digest("hex") });
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, true);
    assert.equal(result.config.stageBStatePath, stageBStatePath);
    assert.equal(result.config.currentStageBStatePath, currentStageBStatePath);
    assert.equal(result.config.currentStageBStateSha256, binding.stateBackupSha256);
    writeFileSync(result.config.stageARecoveryEvidenceFile, `${readFileSync(result.config.stageARecoveryEvidenceFile, "utf8")} `, { mode: 0o600 });
    assert.throws(() => createProductionCutoverAdapters({ config: result.config, sourceSha, rotationId: result.config.rotationId, runtimeConfigSha256: result.runtimeConfigSha256, verifyReleasePreflightAttestationSignature: () => true }), /Stage-A recovery evidence changed after runtime preparation/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("LIVE_QR_VERSION_BINDING rejects an operator value that differs from live production", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    input.rotationBindings = { ...bindings, qr: { ...bindings.qr, previousKeyVersion: "qr-v0" } };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /must equal the live QR_SIGN_ACTIVE_KEY_VERSION|authenticated live legacy/);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("QR secret identifiers remain bindings and are never logical key versions", () => {
  const result = rotationBindingsToTaskBindings(bindings);
  assert.match(result.QR_SIGN_ACTIVE_KEY_VERSION, /:value::$/);
  assert.match(result.QR_SIGN_PREVIOUS_KEY_VERSION, /:value::$/);
  assert.notEqual(result.QR_SIGN_PREVIOUS_KEY_VERSION, bindings.qr.previousKeyVersion);
});

test("rotation task bindings preserve SDK base ARNs and derive ECS JSON-key references", () => {
  const result = rotationBindingsToTaskBindings(bindings);
  assert.equal(result.JWT_SECRET_CURRENT, bindings.jwt.currentSecretId);
  assert.equal(result.QR_SIGN_PRIVATE_KEY_CURRENT, bindings.qr.privateCurrentSecretId);
  assert.equal(result.QR_SIGN_PUBLIC_KEY_CURRENT, bindings.qr.publicCurrentSecretId);
  for (const name of ["JWT_SECRET_PREVIOUS", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"]) {
    assert.equal(result[name].endsWith(":value::"), true);
    assert.doesNotMatch(result[name], /:value::.*:value::/);
  }
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE KEY|SecretString/);
});

test("post-prepare current bindings use ECS JSON-key references while SDK bindings stay base ARNs", async () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    const result = prepareProductionCutoverRuntime(input);
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
      configSha256: result.runtimeConfigSha256,
      stateFile: result.phasePaths.rotationStateFile,
      fixtureFile: result.phasePaths.rotationFixtureFile,
      run: async (args) => {
        assert.deepEqual(args.slice(args.indexOf("--config-sha256"), args.indexOf("--config-sha256") + 2), ["--config-sha256", result.runtimeConfigSha256]);
        writeFileSync(result.phasePaths.rotationStateFile, JSON.stringify({ rotationId: result.config.rotationId, phase: "overlap-deploy-required", sourceSha }), { mode: 0o600 });
        writeFileSync(result.phasePaths.rotationFixtureFile, JSON.stringify({ payload: null, signature: null, token: null }), { mode: 0o600 });
        return JSON.stringify({ rotationId: result.config.rotationId, phase: "overlap-deploy-required" });
      },
    });
    const prepared = await prepare.run({ rotationId: result.config.rotationId, inventory: { evidenceSha256: "f".repeat(64) } });
    for (const name of ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT"]) {
      assert.match(prepared.overlapSecretBindings[name], /:value::$/);
      assert.doesNotMatch(result.config.jwt.currentSecretId + result.config.qr.privateCurrentSecretId + result.config.qr.publicCurrentSecretId, /:value::/);
    }
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("overlap task rejects duplicate secret names instead of ambiguous bindings", () => {
  const definition = { containerDefinitions: [{ secrets: [{ name: "JWT_SECRET_CURRENT" }, { name: "JWT_SECRET_CURRENT" }] }] };
  assert.throws(() => assertUniqueSecretBindingNames(definition), /duplicate secret binding names/);
});

test("overlap task rejects legacy/ECS reference confusion and double JSON-key suffixes", () => {
  const secretBindings = {
    ...rotationBindingsToTaskBindings(bindings),
    ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: secretArn("artifact-private"),
    ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: secretArn("artifact-public"),
    ARTIFACT_SIGN_ACTIVE_KEY_VERSION: secretArn("artifact-version"),
    ARTIFACT_SIGN_PUBLIC_KEYS_JSON: secretArn("artifact-registry"),
    ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read",
  };
  const input = {
    backendImage: image,
    releaseSha: sourceSha,
    backendLogGroup: "/ecs/mscqr-production/rls-green-backend",
    secretBindings,
  };
  assert.doesNotThrow(() => buildOverlapTaskDefinition(input));
  for (const name of ["JWT_SECRET_CURRENT", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT"]) {
    assert.throws(() => buildOverlapTaskDefinition({ ...input, secretBindings: { ...secretBindings, [name]: `${secretBindings[name]}:value::` } }), /wrong SDK\/ECS reference shape/);
  }
  for (const name of ["JWT_SECRET_PREVIOUS", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PUBLIC_KEY_PREVIOUS", "QR_SIGN_PREVIOUS_KEY_VERSION"]) {
    assert.throws(() => buildOverlapTaskDefinition({ ...input, secretBindings: { ...secretBindings, [name]: secretBindings[name].replace(/:value::$/, "") } }), /wrong SDK\/ECS reference shape/);
    assert.throws(() => buildOverlapTaskDefinition({ ...input, secretBindings: { ...secretBindings, [name]: `${secretBindings[name]}:value::` } }), /exact production reference|wrong SDK\/ECS reference shape/);
  }
});

test("BOOTSTRAP_DOWNSTREAM_IMAGE_AUTHORIZATION uses the canonical validator", () => {
  const directory = fsTemp();
  const malformedFields = [
    "evidenceSha256", "signatureVerified", "attestationVerified", "provenanceVerified",
    "imageReleaseSha", "workflowRunId",
  ];
  try {
    const input = fullInput(directory, process.cwd());
    const valid = JSON.parse(readFileSync(input.imageAuthorization.filePath, "utf8"));
    assert.doesNotThrow(() => assertImageAuthorization(valid, sourceSha, input.imageAuthorizationValidation));
    for (const field of malformedFields) {
      const malformed = { ...valid };
      delete malformed[field];
      assert.throws(() => assertImageAuthorization(malformed, sourceSha));
      input.imageAuthorization = { ...malformed, filePath: input.imageAuthorization.filePath };
      rmSync(path.join(input.outputDirectory, "cutover-runtime-manifest.json"), { force: true });
      const result = prepareProductionCutoverRuntime(input);
      assert.equal(result.readyToConsumeMfa, false, `${field} must block bootstrap`);
      input.imageAuthorization = { ...valid, filePath: input.imageAuthorization.filePath };
    }
    const variants = [
      { images: valid.images.slice(0, 3) },
      { images: [...valid.images, { service: "unexpected", digest }] },
      { sourceSha: "a".repeat(40) },
    ];
    for (const variant of variants) {
      const malformed = { ...valid, ...variant };
      assert.throws(() => assertImageAuthorization(malformed, sourceSha));
      input.imageAuthorization = { ...malformed, filePath: input.imageAuthorization.filePath };
      rmSync(path.join(input.outputDirectory, "cutover-runtime-manifest.json"), { force: true });
      assert.equal(prepareProductionCutoverRuntime(input).readyToConsumeMfa, false);
    }
    const wrongDigest = { ...valid, images: valid.images.map((image) => image.service === "backend" ? { ...image, digest: "not-a-digest" } : image) };
    assert.throws(() => assertImageAuthorization(wrongDigest, sourceSha), /record/);
    input.imageAuthorization = { ...wrongDigest, filePath: input.imageAuthorization.filePath };
    rmSync(path.join(input.outputDirectory, "cutover-runtime-manifest.json"), { force: true });
    assert.equal(prepareProductionCutoverRuntime(input).readyToConsumeMfa, false);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("DERIVABLE_FIELDS_NOT_OPERATOR_REQUIRED rejects source SHA override", () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime({ ...fullInput(directory, process.cwd()), sourceSha: "a".repeat(40) });
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /does not match protected main/);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("BOOTSTRAP_FRESH_MAIN rejects stale remote identity before MFA or config generation", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    input.git = (file, args) => {
      if (args[0] === "status") return "";
      if (args[0] === "fetch") return "";
      if (args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return "b".repeat(40);
      if (args[0] === "rev-parse" && args[1] === "HEAD") return sourceSha;
      if (args[0] === "rev-parse") return sourceSha;
      throw new Error(`unexpected git call: ${file} ${args.join(" ")}`);
    };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /freshly fetched protected main/);
    assert.equal(existsSync(path.join(result.runtimeDirectory, "rotation-config.json")), false);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("BOOTSTRAP_FRESH_MAIN rejects fetch failure without falling back to origin/main", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    input.git = (file, args) => {
      if (args[0] === "status") return "";
      if (args[0] === "fetch") throw new Error("network unavailable");
      if (args[0] === "rev-parse" && args[1] === "origin/main") return sourceSha;
      throw new Error(`unexpected git call: ${file} ${args.join(" ")}`);
    };
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /Fresh protected-main fetch failed/);
    assert.equal(existsSync(path.join(result.runtimeDirectory, "rotation-config.json")), false);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("HUMAN_FIELDS_REQUIRED fails before generating a rotation config", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    delete input.approval.minimumGraceSeconds;
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, false);
    assert.match(result.blockers.join("\n"), /minimumGraceSeconds/);
    assert.equal(existsSync(path.join(result.runtimeDirectory, "rotation-config.json")), false);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("reviewed rotation grace accepts the minimum or longer and rejects shorter or unsafe values", () => {
  for (const minimumGraceSeconds of [PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS, PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS + 1, 3_000_000]) {
    const directory = fsTemp();
    try {
      const input = fullInput(directory, process.cwd()); input.approval.minimumGraceSeconds = minimumGraceSeconds;
      const result = prepareProductionCutoverRuntime(input);
      assert.equal(result.readyToConsumeMfa, true);
      assert.equal(result.config.minimumGraceSeconds, minimumGraceSeconds);
    } finally {
      rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
      rmSync(directory, { recursive: true, force: true });
    }
  }
  for (const minimumGraceSeconds of [PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS - 1, 0, -1, PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS + 1, 9_000_000_000_000, Number.MAX_SAFE_INTEGER + 1]) {
    const directory = fsTemp();
    try {
      const input = fullInput(directory, process.cwd()); input.approval.minimumGraceSeconds = minimumGraceSeconds;
      const result = prepareProductionCutoverRuntime(input);
      assert.equal(result.readyToConsumeMfa, false);
      assert.match(result.blockers.join("\n"), /minimumGraceSeconds|timestamp range/);
    } finally {
      rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("rotation grace uses the JavaScript timestamp boundary and derives deadlines centrally", () => {
  assert.equal(assertProductionRotationGraceSeconds(PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS), PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS);
  assert.equal(assertProductionRotationGraceSeconds(3_000_000), 3_000_000);
  assert.equal(assertProductionRotationGraceSeconds(PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS), PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS);
  assert.throws(() => assertProductionRotationGraceSeconds(PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS + 1), /at most/);
  assert.equal(deriveProductionRotationCleanupEligibleAt("1970-01-01T00:00:00.000Z", PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS), "+275760-09-13T00:00:00.000Z");
  assert.throws(() => deriveProductionRotationCleanupEligibleAt("2026-08-26T00:00:00.000Z", PRODUCTION_ROTATION_MAXIMUM_GRACE_SECONDS), /timestamp range/);
});

test("PREPARE_ARTIFACT_LIFECYCLE leaves future files absent until coordinator prepare", async () => {
  const directory = fsTemp();
  const repositoryRoot = process.cwd();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, repositoryRoot));
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
      configSha256: result.runtimeConfigSha256,
      stateFile: result.phasePaths.rotationStateFile,
      fixtureFile: result.phasePaths.rotationFixtureFile,
      run: async () => {
        writeFileSync(result.phasePaths.rotationStateFile, JSON.stringify({ rotationId: result.config.rotationId, phase: "overlap-deploy-required", sourceSha }), { mode: 0o600 });
        writeFileSync(result.phasePaths.rotationFixtureFile, JSON.stringify({ payload: null, signature: null, token: null }), { mode: 0o600 });
        return JSON.stringify({ rotationId: result.config.rotationId, phase: "overlap-deploy-required" });
      },
    });
    assert.equal(existsSync(result.phasePaths.rotationStateFile), false);
    assert.equal(existsSync(result.phasePaths.rotationFixtureFile), false);
    const prepared = await prepare.run({ rotationId: result.config.rotationId, inventory: { evidenceSha256: "f".repeat(64) } });
    assert.equal(prepared.prepared, true);
    assert.match(prepared.rotationFixtureSha256, /^[a-f0-9]{64}$/);
    assert.equal(existsSync(result.phasePaths.rotationStateFile), true);
    assert.equal(existsSync(result.phasePaths.rotationFixtureFile), true);
  } finally {
    rmSync(path.join(repositoryRoot, "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rotation prepare reauthenticates runtime config before invoking the mutating coordinator", async () => {
  const directory = fsTemp();
  let coordinatorCalls = 0;
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
      configSha256: result.runtimeConfigSha256,
      stateFile: result.phasePaths.rotationStateFile,
      fixtureFile: result.phasePaths.rotationFixtureFile,
      run: async () => { coordinatorCalls += 1; return ""; },
    });
    writeFileSync(result.configPath, `${readFileSync(result.configPath, "utf8")} `, { mode: 0o600 });
    await assert.rejects(() => prepare.run({ rotationId: result.config.rotationId, inventory: { evidenceSha256: "f".repeat(64) } }), /Production cutover runtime config changed after runtime preparation/);
    assert.equal(coordinatorCalls, 0);
    assert.equal(existsSync(result.phasePaths.rotationStateFile), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rotation prepare rejects unsafe output paths before invoking the mutating coordinator", async () => {
  const directory = fsTemp();
  let coordinatorCalls = 0;
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    symlinkSync(result.configPath, result.phasePaths.rotationFixtureFile);
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
      configSha256: result.runtimeConfigSha256,
      stateFile: result.phasePaths.rotationStateFile,
      fixtureFile: result.phasePaths.rotationFixtureFile,
      run: async () => { coordinatorCalls += 1; return ""; },
    });
    await assert.rejects(() => prepare.run({ rotationId: result.config.rotationId, inventory: { evidenceSha256: "f".repeat(64) } }), /Persisted rotation fixture must not be a symlink/);
    assert.equal(coordinatorCalls, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rotation prepare authenticates persisted state before authorizing the next boundary", async () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
      configSha256: result.runtimeConfigSha256,
      stateFile: result.phasePaths.rotationStateFile,
      fixtureFile: result.phasePaths.rotationFixtureFile,
      run: async () => {
        writeFileSync(result.phasePaths.rotationStateFile, JSON.stringify({ rotationId: "different-rotation", phase: "overlap-deploy-required" }), { mode: 0o600 });
        writeFileSync(result.phasePaths.rotationFixtureFile, JSON.stringify({ payload: null, signature: null, token: null }), { mode: 0o600 });
        return JSON.stringify({ rotationId: result.config.rotationId, phase: "overlap-deploy-required" });
      },
    });
    await assert.rejects(() => prepare.run({ rotationId: result.config.rotationId, inventory: { evidenceSha256: "f".repeat(64) } }), /does not match coordinator readback/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rebaseline registration requires a fresh read-only prepared-rotation status", async () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    writeFileSync(result.phasePaths.rotationStateFile, JSON.stringify({ rotationId: result.config.rotationId, phase: "overlap-deploy-required", sourceSha }), { mode: 0o600 });
    chmodSync(result.phasePaths.rotationStateFile, 0o600);
    writeFileSync(result.phasePaths.rotationFixtureFile, JSON.stringify({ payload: null, signature: null, token: null }), { mode: 0o600 });
    chmodSync(result.phasePaths.rotationFixtureFile, 0o600);
    const stateSha256 = createHash("sha256").update(readFileSync(result.phasePaths.rotationStateFile)).digest("hex");
    const calls = [];
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
      configSha256: result.runtimeConfigSha256,
      stateFile: result.phasePaths.rotationStateFile,
      fixtureFile: result.phasePaths.rotationFixtureFile,
      run: async (args) => { calls.push(args); return JSON.stringify({ mode: "status", phase: "overlap-deploy-required", records: { jwtCurrent: { versionId: "fixture" } } }); },
    });
    assert.equal((await prepare.revalidate({ rotationId: result.config.rotationId, rotationStateSha256: stateSha256 })).valid, true);
    assert.deepEqual(calls[0].slice(1, 3), ["backend/scripts/security/rotate-production-signing-material.mjs", "--status"]);
    await assert.rejects(() => prepare.revalidate({ rotationId: result.config.rotationId, rotationStateSha256: "0".repeat(64) }), /state changed/i);
    assert.equal(calls.length, 1);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rotation task bindings never include secret values or pending-only fields", () => {
  const result = rotationBindingsToTaskBindings(bindings);
  assert.equal(Object.keys(result).sort().join(","), ["JWT_SECRET_CURRENT", "JWT_SECRET_PREVIOUS", "QR_SIGN_ACTIVE_KEY_VERSION", "QR_SIGN_PREVIOUS_KEY_VERSION", "QR_SIGN_PRIVATE_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_CURRENT", "QR_SIGN_PUBLIC_KEY_PREVIOUS"].sort().join(","));
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE KEY|SecretString/);
});

test("FUTURE_ARTIFACTS_PRESEEDED fail closed before config generation", () => {
  const directory = fsTemp();
  try {
    const input = fullInput(directory, process.cwd());
    mkdirSync(path.join(directory, "runtime"), { recursive: true, mode: 0o700 });
    writeFileSync(path.join(directory, "runtime", "rotation-state.json"), "{}\n", { mode: 0o600 });
    assert.throws(() => prepareProductionCutoverRuntime(input), /rotationStateFile must not exist/);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("PRIVATE_RUNTIME_FILES are owner-only and bootstrap output contains no credentials", () => {
  const directory = fsTemp();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, process.cwd()));
    assert.equal(statSync(result.runtimeDirectory).mode & 0o777, 0o700);
    for (const filePath of [result.configPath, result.manifestPath]) assert.equal(statSync(filePath).mode & 0o777, 0o600);
    assert.doesNotMatch(readFileSync(result.manifestPath, "utf8"), /AccessKeyId|SecretAccessKey|SessionToken|123456|fixture-password/);
    assert.equal(lstatSync(result.configPath).isSymbolicLink(), false);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

test("BOOTSTRAP_ARGUMENTS reject unknown, positional, and duplicate options", () => {
  assert.throws(() => parseBootstrapArgs(["--unknown", "x"]), /unsupported/);
  assert.throws(() => parseBootstrapArgs(["positional"]), /Invalid/);
  assert.throws(() => parseBootstrapArgs(["--ticket", "A", "--ticket", "B"]), /Duplicate/);
});

test("BOOTSTRAP_ARGUMENTS accept the exact successor-recovery evidence options", () => {
  const parsed = parseBootstrapArgs(["--recovery-envelope", "/private/tmp/recovery-envelope.json", "--original-rebaseline-preparation", "/private/tmp/original-preparation.json"]);
  assert.equal(parsed.get("recovery-envelope"), "/private/tmp/recovery-envelope.json");
  assert.equal(parsed.get("original-rebaseline-preparation"), "/private/tmp/original-preparation.json");
  for (const argv of [["--recovery-envelope"], ["--original-rebaseline-preparation"], ["--recovery-envelope", "x", "--recovery-envelope", "y"], ["--recovery-envelope", "x", "--recovery-unknown", "y"]]) assert.throws(() => parseBootstrapArgs(argv), /Invalid|Duplicate|unsupported/);
});

test("REAL successor-recovery runtime path preserves recovery context through adapter construction", () => {
  const directory = fsTemp();
  const recoverySource = PARTIAL_REBASELINE_RECOVERY_BASE_SOURCE_SHA;
  const envelope = partialRecoveryEnvelopeFixture();
  const originalPreparation = partialRecoveryOriginalPreparationFixture();
  const imageFixture = makeCanonicalImageAuthorization({ sourceSha: recoverySource, imageReleaseSha: recoverySource });
  const approvalEvidence = createProductionEnvironmentApprovalEvidence({
    environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "checker" } }] }] },
    repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha: recoverySource,
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.dualSlotRebaselineRecoveryWorkflowRef, eventName: "workflow_dispatch",
    workflowRunId: "987655", workflowRunAttempt: "1", executionActor: "operator", observedAt: imageFixture.now,
    actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "checker" },
  });
  const liveCas = { liveReferenceAuditSha256: createHash("sha256").update("recovery-audit").digest("hex"), liveLegacyBaselineIdentitySha256: createHash("sha256").update("recovery-legacy").digest("hex"), observedSlotIdentitiesSha256: createHash("sha256").update("recovery-slots").digest("hex") };
  const proveDescendant = ({ ancestorSha, descendantSha }) => ancestorSha === recoverySource && descendantSha === recoverySource;
  const authorization = createPartialRebaselineRecoveryAuthorization({ protectedEnvironmentApprovalEvidence: approvalEvidence, sourceSha: recoverySource, recoveryEnvelope: envelope, imageAuthorization: imageFixture.authorization, imageAuthorizationValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence }, ...liveCas, reason: "resume fixture", approverRole: "production-independent-checker", verificationRef: "recovery-runtime-fixture", proveDescendant });
  const finalSnapshots = originalPreparation.writePlan.map(({ slot, secretArn, clientRequestToken, payloadSha256 }) => ({ slot, arn: secretArn, currentVersionId: clientRequestToken, currentStages: ["AWSCURRENT"], currentPayloadSha256: payloadSha256, versions: [{ versionId: clientRequestToken, stages: ["AWSCURRENT"], payloadSha256 }] }));
  const originalWritePlan = originalPreparation.writePlan.map((entry) => ({ ...entry, payload: { keyVersion: entry.payloadIdentity.keyVersion } }));
  const completion = buildPartialRebaselineRecoveryCompletion({ originalPreparation, sourceSha: recoverySource, recoveryEnvelope: envelope, recoveryAuthorization: authorization, finalSnapshots, writePlan: originalWritePlan });
  const recoveryBindings = buildPartialRebaselineRecoveryRotationBindings({ sourceSha: recoverySource, originalPreparation, recoveryEnvelope: envelope, recoveryAuthorization: authorization, completion });
  const livePostWriteBody = { kind: "PRODUCTION_DUAL_SLOT_REBASELINE_LIVE_POST_WRITE", sourceSha: recoverySource, rotationId: envelope.rotationId, authorizationSha256: authorization.authorizationSha256, resources: envelope.resources, versionIds: authorization.writeIdentities, payloadIdentities: authorization.writePayloadIdentities };
  const input = {
    ...fullInput(directory, process.cwd(), recoverySource, recoverySource),
    rotationId: envelope.rotationId,
    rotationBindings: recoveryBindings,
    recoveryEnvelope: envelope,
    originalPreparation,
    rebaselineAuthorization: authorization,
    rebaselineAuthorizationCoordinates: { workflowRunId: "987655", workflowRunAttempt: "1" },
    imageAuthorizationValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence },
    verifyRebaselineLivePostWrite: () => ({ ...livePostWriteBody, livePostWriteSha256: canonicalSha256(livePostWriteBody) }),
    proveRecoveryDescendant: proveDescendant,
    currentTaskDefinition: taskDefinition({ jwt: { currentSecretId: recoveryBindings.legacy.jwtCurrent, previousSecretId: recoveryBindings.jwt.previousSecretId, pendingSecretId: recoveryBindings.jwt.pendingSecretId }, qr: { ...recoveryBindings.qr } }),
  };
  writeFileSync(input.imageAuthorization.filePath, `${JSON.stringify(imageFixture.authorization)}\n`, { mode: 0o600 });
  input.imageAuthorization = { ...imageFixture.authorization, filePath: input.imageAuthorization.filePath };
  try {
    const result = prepareProductionCutoverRuntime(input);
    assert.equal(result.readyToConsumeMfa, true, result.blockers?.join(" | "));
    assert.equal(result.config.rebaselineRuntime.runtimeVariant, "SUCCESSOR_RECOVERY_REBASELINE_RUNTIME");
    assert.equal(result.config.rebaselineRuntime.recoveryEnvelope.recoverySha256, envelope.recoverySha256);
    assert.equal(result.config.rebaselineRuntime.originalPreparation.preparationSha256, originalPreparation.preparationSha256);
    assert.doesNotThrow(() => assertPartialRebaselineRecoveryAuthorization(result.config.rebaselineRuntime.authorization, { sourceSha: recoverySource, recoveryEnvelope: envelope, imageAuthorization: imageFixture.authorization, imageAuthorizationValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence }, proveDescendant }));
    assert.equal(JSON.parse(readFileSync(result.configPath, "utf8")).rebaselineRuntime.runtimeVariant, "SUCCESSOR_RECOVERY_REBASELINE_RUNTIME");
    const runtimeConfigSha = (config) => createHash("sha256").update(`${JSON.stringify(config, null, 2)}\n`).digest("hex");
    const adapterArgs = (mutate) => {
      const config = structuredClone(result.config);
      mutate(config);
      return { config, sourceSha: recoverySource, rotationId: config.rotationId, runtimeConfigSha256: runtimeConfigSha(config), verifyReleasePreflightAttestationSignature: () => true, createCommandRunner: () => () => "" };
    };
    assert.throws(() => createProductionCutoverAdapters(adapterArgs((config) => { config.rebaselineRuntime.runtimeVariant = "ORDINARY_REBASELINE_RUNTIME"; })), /contains successor-recovery authority/);
    assert.throws(() => createProductionCutoverAdapters(adapterArgs((config) => { delete config.rebaselineRuntime.recoveryEnvelope; })), /Complete successor-recovery runtime authority/);
    assert.throws(() => createProductionCutoverAdapters(adapterArgs((config) => { config.rebaselineRuntime.runtimeVariant = "UNKNOWN_REBASELINE_RUNTIME"; })), /missing or unsupported/);
  } finally {
    rmSync(path.join(process.cwd(), "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
    rmSync(directory, { recursive: true, force: true });
  }
});

function fsTemp() {
  const directory = path.join(os.tmpdir(), "mscqr-runtime-bootstrap-" + Date.now() + "-" + Math.random().toString(16).slice(2));
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  return directory;
}

test.after(() => rmSync(artifactSigningRuntimeBindingPath(sourceSha), { force: true }));
