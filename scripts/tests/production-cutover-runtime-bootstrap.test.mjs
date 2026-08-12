import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createProductionCutoverAdapters } from "../aws/production-cutover-production-adapters.mjs";
import { createProductionRotationPrepareAdapter } from "../aws/production-rotation-prepare-adapter.mjs";
import { parseBootstrapArgs, prepareProductionCutoverRuntime, rotationBindingsToTaskBindings } from "../aws/production-cutover-runtime-bootstrap.mjs";

const sourceSha = "b".repeat(40);
const digest = "sha256:" + "c".repeat(64);
const image = "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@" + digest;
const paths = Object.fromEntries(["tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "artifactSigning", "publicQrVerification"].map((name) => [name, "/api/" + name]));
const bindings = {
  jwt: {
    currentSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-current-a",
    previousSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-previous-b",
    pendingSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/jwt-pending-c",
  },
  qr: {
    privateCurrentSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-private-current-d",
    privatePendingSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-private-pending-e",
    publicCurrentSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-public-current-f",
    publicPreviousSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-public-previous-g",
    currentKeyVersionSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-current-version-i",
    previousKeyVersionSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-previous-version-j",
    publicPendingSecretId: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/qr-public-pending-h",
    previousKeyVersion: "qr-v0",
  },
};

function gitFixture() {
  return (file, args) => {
    if (file === "git" && args[0] === "status") return "";
    if (file === "git" && args[0] === "rev-parse") return sourceSha + "\n";
    throw new Error("unexpected git call: " + file + " " + args.join(" "));
  };
}

function approval() {
  return { ticket: "CHG-ROTATION-0001", approvedBy: "security@example.invalid", approverRole: "Security Lead", reason: "Scheduled production security rotation", verificationRef: "https://example.invalid/approval/1", minimumGraceSeconds: 2592000 };
}

function taskDefinition() {
  return { taskDefinition: { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47", containerDefinitions: [{ name: "backend", environment: [{ name: "PUBLIC_APP_URL", value: "https://www.mscqr.com" }, { name: "QR_SIGN_ACTIVE_KEY_VERSION", value: "qr-v1" }] }] } };
}

function evidenceFiles(directory, repositoryRoot) {
  const file = (name, value) => { const target = path.join(directory, name); writeFileSync(target, JSON.stringify(value) + "\n", { mode: 0o600 }); chmodSync(target, 0o600); return target; };
  const imageAuthorization = file("image-authorization.json", { valid: true, sourceSha, imageReuseCompatible: true, imageBuildInputsChanged: false, images: [{ service: "backend", digest }, { service: "worker", digest }, { service: "rls-executor", digest }, { service: "rls-canary", digest }] });
  const iamEvidence = file("iam-evidence.json", { status: "valid", iamEvaluationCensus: { total: 158, executed: 158, invalid: 0, failures: [] }, evidenceSha256: "d".repeat(64) });
  const rootDrop = file("root-drop.json", { valid: true, callerArn: "arn:aws:iam::368992683803:root", evidenceSha256: "e".repeat(64) });
  const stageAPlan = file("stage-a.tfplan", "binary-fixture");
  const artifactBinding = path.join(repositoryRoot, "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json");
  writeFileSync(artifactBinding, JSON.stringify({ bindings: {
    ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/private-key-current-a",
    ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-key-current-b",
    ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/active-key-version-c",
    ARTIFACT_SIGN_PUBLIC_KEYS_JSON: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-keys-json-d",
  } }, null, 2));
  chmodSync(artifactBinding, 0o600);
  return { imageAuthorization, iamEvidence, rootDrop, stageAPlan, artifactBinding };
}

function fullInput(directory, repositoryRoot) {
  const evidence = evidenceFiles(directory, repositoryRoot);
  return {
    outputDirectory: path.join(directory, "runtime"),
    repositoryRoot,
    approval: approval(),
    rotationBindings: bindings,
    git: gitFixture(),
    imageAuthorization: { ...JSON.parse(readFileSync(evidence.imageAuthorization, "utf8")), filePath: evidence.imageAuthorization },
    iamEvidence: { ...JSON.parse(readFileSync(evidence.iamEvidence, "utf8")), filePath: evidence.iamEvidence },
    artifactBindingFile: evidence.artifactBinding,
    rootDropEvidenceFile: evidence.rootDrop,
    stageAPlanPath: evidence.stageAPlan,
    currentTaskDefinition: taskDefinition(),
    inventoryApprovalId: "APR-STAGE-B-0001",
    onboardingPaths: paths,
    onboardingCredentials: { email: "admin@example.invalid", password: "fixture-password", mfaCode: "123456" },
    constructAdapters: ({ config, sourceSha: actualSha, rotationId }) => createProductionCutoverAdapters({ config, sourceSha: actualSha, rotationId }),
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
    assert.equal(result.config.onboardingBaseUrl, "https://www.mscqr.com");
    assert.equal(result.config.expectedRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-release-deployer");
    assert.equal(result.config.overlapTaskInput.secretBindings.ARTIFACT_SIGN_ACTIVE_KEY_VERSION.includes("artifact-signing"), true);
    assert.doesNotMatch(readFileSync(result.configPath, "utf8"), /PRIVATE KEY|SecretString|fixture-password|123456/);
  } finally {
    rmSync(path.join(repositoryRoot, "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
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

test("PREPARE_ARTIFACT_LIFECYCLE leaves future files absent until coordinator prepare", async () => {
  const directory = fsTemp();
  const repositoryRoot = process.cwd();
  try {
    const result = prepareProductionCutoverRuntime(fullInput(directory, repositoryRoot));
    const prepare = createProductionRotationPrepareAdapter({
      coordinator: "backend/scripts/security/rotate-production-signing-material.mjs",
      configFile: result.configPath,
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
    assert.equal(existsSync(result.phasePaths.rotationStateFile), true);
    assert.equal(existsSync(result.phasePaths.rotationFixtureFile), true);
  } finally {
    rmSync(path.join(repositoryRoot, "documents/ops/iam/MSCQRProductionGreenStageBArtifactSigningBindings.runtime.json"), { force: true });
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

function fsTemp() {
  const directory = path.join(os.tmpdir(), "mscqr-runtime-bootstrap-" + Date.now() + "-" + Math.random().toString(16).slice(2));
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  chmodSync(directory, 0o700);
  return directory;
}
