#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { canonicalJson, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { authenticateRotationSuccessor, signRotationSuccessor } from "./production-rotation-successor.mjs";
import { readBoundStageBPrivateJson, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { preflightProductionCutoverRotation } from "./run-production-cutover-operator.mjs";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const arg = (argv, name) => {
  const index = argv.indexOf(`--${name}`);
  if (index < 0 || !argv[index + 1] || argv[index + 1].startsWith("--")) throw new Error(`--${name} is required.`);
  return argv[index + 1];
};

export async function prepareProductionRotationSuccessor({ argv, root = process.cwd(), readAws, signAws, statusRun = execFileSync, preflight = preflightProductionCutoverRotation } = {}) {
  const configPath = path.resolve(arg(argv, "config"));
  const configSha256 = arg(argv, "config-sha256");
  const config = readBoundStageBPrivateJson({ filePath: configPath, expectedSha256: configSha256, repositoryRoot: root, label: "Successor rotation config" });
  readStageBProtectedMainCheckout({ cwd: root, expectedSourceSha: config.recoveryTooling?.sourceSha || config.sourceSha, requireCanonicalRepository: true });
  const predecessor = config.rotationSuccessor;
  if (!predecessor || config.rotationConfigFile !== configPath || config.completedInventoryAdoptionRequired !== true
      || path.dirname(config.rotationStateFile || "") !== path.dirname(configPath)) throw new Error("Rotation successor runtime is incomplete.");
  const originalConfig = readBoundStageBPrivateJson({ filePath: predecessor.predecessorConfigFile, expectedSha256: predecessor.predecessorConfigSha256, repositoryRoot: root, label: "Original rotation config" });
  const originalState = readBoundStageBPrivateJson({ filePath: predecessor.predecessorStateFile, expectedSha256: predecessor.predecessorStateSha256, repositoryRoot: root, label: "Original rotation state" });
  const originalFixture = readStageBPrivateFileBytes({ filePath: predecessor.predecessorFixtureFile, repositoryRoot: root, label: "Original rotation fixture" });
  if (originalFixture.sha256 !== predecessor.predecessorFixtureSha256 || originalConfig.sourceSha !== predecessor.predecessorSourceSha
      || originalConfig.rotationId !== config.rotationId || originalConfig.rotationStateFile !== predecessor.predecessorStateFile
      || originalConfig.rotationFixtureFile !== predecessor.predecessorFixtureFile || originalState.sourceSha !== originalConfig.sourceSha) throw new Error("Historical rotation material is not bound to the original config.");
  const proveDescendant = ({ ancestorSha, descendantSha }) => {
    try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
  };
  if (!proveDescendant({ ancestorSha: originalConfig.sourceSha, descendantSha: config.sourceSha })) throw new Error("Rotation successor is not protected-main ancestry.");
  const runtime = { "--config": configPath, "--config-sha256": configSha256, "--source-sha": config.sourceSha, "--rotation-id": config.rotationId };
  preflight({ config, runtime, cwd: root });
  const releaseRun = readAws || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: config.releaseProfile });
  const checkerRun = signAws || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-checker-mfa" });
  const releaseIdentity = json(releaseRun, ["sts", "get-caller-identity"]);
  const checkerIdentity = json(checkerRun, ["sts", "get-caller-identity"]);
  if (!new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-release-deployer/`).test(releaseIdentity.Arn || "")
      || !new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/`).test(checkerIdentity.Arn || "")) throw new Error("Rotation successor requires separate release and checker identities.");
  const statusEnvironment = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: config.releaseProfile });
  const status = String(statusRun(process.execPath, ["backend/scripts/security/rotate-production-signing-material.mjs", "--status", "--config", predecessor.predecessorConfigFile, "--config-sha256", predecessor.predecessorConfigSha256, "--state-file", predecessor.predecessorStateFile], { cwd: root, env: statusEnvironment, encoding: "utf8" })).trim().split("\n").at(-1);
  const result = JSON.parse(status);
  if (result.mode !== "status" || result.phase !== "overlap-deploy-required" || !result.records || typeof result.records !== "object") throw new Error("Historical rotation is not live and prepared for overlap.");
  const adoptionFile = path.join(path.dirname(configPath), "inventory-completed-adoption-evidence.json");
  const inventoryEvidence = JSON.parse(readStageBPrivateFileBytes({ filePath: adoptionFile, repositoryRoot: root, label: "Current inventory adoption" }).bytes);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-rotation-successor-"));
  fs.chmodSync(temporary, 0o700);
  const messageFile = path.join(temporary, "message");
  const message = bytes => { fs.writeFileSync(messageFile, bytes, { mode: 0o600 }); return `fileb://${messageFile}`; };
  try {
    const verifySignature = ({ keyId, message: bytes, signature }) => json(releaseRun, ["kms", "verify", "--key-id", keyId, "--message", message(bytes), "--message-type", "RAW", "--signature", Buffer.from(signature).toString("base64"), "--signing-algorithm", "RSASSA_PSS_SHA_256"]).SignatureValid === true;
    const sign = ({ keyId, message: bytes }) => json(checkerRun, ["kms", "sign", "--key-id", keyId, "--message", message(bytes), "--message-type", "RAW", "--signing-algorithm", "RSASSA_PSS_SHA_256"]).Signature;
    const evidenceFile = path.join(path.dirname(configPath), "rotation-successor-evidence.json");
    let evidence;
    let state;
    if (fs.existsSync(evidenceFile)) {
      evidence = JSON.parse(readStageBPrivateFileBytes({ filePath: evidenceFile, repositoryRoot: root, label: "Rotation successor evidence" }).bytes);
      state = { ...originalState, sourceSha: config.sourceSha, overlapDeploymentSha: config.sourceSha, successorProvenance: evidence };
    } else {
      ({ evidence, state } = await signRotationSuccessor({ config, configSha256, predecessorState: originalState, predecessorStateSha256: predecessor.predecessorStateSha256, predecessorFixtureSha256: originalFixture.sha256, inventoryEvidence, proveDescendant, verifySignature, sign }));
      try { writeStageBPrivateFileExclusive({ filePath: evidenceFile, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), repositoryRoot: root, label: "Rotation successor evidence" }); }
      catch (error) {
        if (!fs.existsSync(evidenceFile)) throw error;
        evidence = JSON.parse(readStageBPrivateFileBytes({ filePath: evidenceFile, repositoryRoot: root, label: "Rotation successor evidence" }).bytes);
        state = { ...originalState, sourceSha: config.sourceSha, overlapDeploymentSha: config.sourceSha, successorProvenance: evidence };
      }
    }
    await authenticateRotationSuccessor({ config, configSha256, predecessorState: originalState, predecessorStateSha256: predecessor.predecessorStateSha256, predecessorFixtureSha256: originalFixture.sha256, state, fixtureSha256: originalFixture.sha256, inventoryEvidence, evidence, proveDescendant, verifySignature });
    for (const [filePath, bytes, label] of [
      [config.rotationStateFile, Buffer.from(`${JSON.stringify(state, null, 2)}\n`), "Successor rotation state"],
      [config.rotationFixtureFile, originalFixture.bytes, "Successor rotation fixture"],
    ]) {
      if (fs.existsSync(filePath)) {
        if (!readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label }).bytes.equals(bytes)) throw new Error(`${label} conflicts with signed successor.`);
      } else writeStageBPrivateFileExclusive({ filePath, bytes, repositoryRoot: root, label });
    }
    return { sourceSha: config.sourceSha, rotationId: config.rotationId, predecessorStateSha256: predecessor.predecessorStateSha256, successorStateSha256: hash(Buffer.from(`${JSON.stringify(state, null, 2)}\n`)), evidenceSha256: hash(canonicalJson(evidence)), adopted: true };
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  prepareProductionRotationSuccessor({ argv: process.argv.slice(2) }).then(result => process.stdout.write(`${JSON.stringify(result)}\n`), error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
