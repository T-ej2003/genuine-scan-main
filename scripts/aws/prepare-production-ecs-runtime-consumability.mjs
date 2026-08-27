#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  assertSignedRuntimeDependencyInventory,
  buildRuntimeDependencyInventory,
  collectRuntimeConsumabilityEvidence,
  collectRuntimeResourceMetadata,
  signRuntimeConsumabilityEvidence,
  signRuntimeDependencyInventory,
} from "./production-ecs-runtime-consumability.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const decode = (captured) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
const candidateArtifact = (candidateFile, candidateFileSha256) => {
  const captured = readStageBPrivateFileBytes({ filePath: candidateFile, repositoryRoot: root, label: "Production ECS runtime candidate" });
  if (captured.sha256 !== candidateFileSha256) throw new Error("Production ECS runtime candidate file bytes changed before closure.");
  return { candidate: decode(captured), candidateFileSha256: captured.sha256 };
};
const privateJson = (filePath, expectedSha256, label) => {
  const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label });
  if (captured.sha256 !== expectedSha256) throw new Error(`${label} bytes changed before closure.`);
  return decode(captured);
};
async function administratorContext({ sourceSha, candidateFile, candidateFileSha256, run, protectedMain }) {
  if (typeof run !== "function") throw new Error("Runtime closure requires an explicit administrator AWS command runner.");
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const artifact = candidateArtifact(candidateFile, candidateFileSha256);
  const aws = async (args) => JSON.parse(run(args));
  const caller = await aws(["sts", "get-caller-identity"]);
  if (caller?.Account !== "368992683803" || !/^arn:aws:iam::368992683803:root$|^arn:aws:sts::368992683803:assumed-role\/mscqr-production-bootstrap-mfa\//.test(caller?.Arn || "")) throw new Error("Runtime closure must be produced by the governed production administrator boundary.");
  const readKmsKey = async (keyArn) => ({ metadata: (await aws(["kms", "describe-key", "--key-id", keyArn]))?.KeyMetadata, policy: (await aws(["kms", "get-key-policy", "--key-id", keyArn, "--policy-name", "default"]))?.Policy });
  return { ...artifact, aws, readKmsKey };
}

function withSignatureFiles(callback) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-runtime-closure-sign-"));
  try { return callback(directory); }
  finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

const signer = (run, directory) => ({ digest, keyArn, signingAlgorithm }) => {
  const digestFile = path.join(directory, "digest");
  fs.writeFileSync(digestFile, digest, { mode: 0o600, flag: "wx" });
  return JSON.parse(run(["kms", "sign", "--key-id", keyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm])).Signature;
};
const verifier = (run, directory) => ({ digest, signature, keyArn, signingAlgorithm }) => {
  const digestFile = path.join(directory, "verify-digest"); const signatureFile = path.join(directory, "verify-signature");
  fs.writeFileSync(digestFile, digest, { mode: 0o600, flag: "wx" }); fs.writeFileSync(signatureFile, signature, { mode: 0o600, flag: "wx" });
  return JSON.parse(run(["kms", "verify", "--key-id", keyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signature", `fileb://${signatureFile}`, "--signing-algorithm", signingAlgorithm])).SignatureValid === true;
};
const persist = (outputFile, value, label) => {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: outputFile, bytes, label }] });
  return readStageBPrivateFileBytes({ filePath: outputFile, repositoryRoot: root, label }).sha256;
};

export async function prepareProductionEcsRuntimeInventory({ sourceSha, candidateFile, candidateFileSha256, outputFile, run, protectedMain = readFreshProtectedMainIdentity, now = new Date().toISOString() } = {}) {
  const context = await administratorContext({ sourceSha, candidateFile, candidateFileSha256, run, protectedMain });
  const resourceMetadata = await collectRuntimeResourceMetadata(context.candidate, context.aws, { readKmsKey: context.readKmsKey });
  const inventory = buildRuntimeDependencyInventory({ sourceSha, candidate: context.candidate, candidateFileSha256: context.candidateFileSha256, resourceMetadata, generatedAt: now });
  const envelope = withSignatureFiles((directory) => signRuntimeDependencyInventory(inventory, { signedAt: now, sign: signer(run, directory) }));
  const outputSha256 = persist(outputFile, envelope, "Production ECS runtime dependency inventory");
  return { outputFile, outputSha256, inventorySha256: inventory.inventorySha256, candidateFileSha256: inventory.candidateFileSha256, candidateCanonicalSha256: inventory.candidateCanonicalSha256, candidateFingerprint: inventory.candidateFingerprint, dependencyCount: inventory.dependencies.length };
}

export async function prepareProductionEcsRuntimeConsumability({ sourceSha, candidateFile, candidateFileSha256, inventoryFile, inventoryFileSha256, outputFile, run, protectedMain = readFreshProtectedMainIdentity, now = new Date().toISOString() } = {}) {
  const context = await administratorContext({ sourceSha, candidateFile, candidateFileSha256, run, protectedMain });
  const envelope = privateJson(inventoryFile, inventoryFileSha256, "Production ECS runtime dependency inventory");
  const inventory = withSignatureFiles((directory) => assertSignedRuntimeDependencyInventory(envelope, { sourceSha, candidate: context.candidate, candidateFileSha256: context.candidateFileSha256, now: Date.parse(now), verify: verifier(run, directory) }));
  const evidence = await collectRuntimeConsumabilityEvidence({ sourceSha, candidate: context.candidate, aws: context.aws, readKmsKey: context.readKmsKey, generatedAt: now });
  if (evidence.dependencySha256 !== inventory.dependencySha256 || canonicalSha256(evidence.resourceMetadata) !== canonicalSha256(inventory.resourceMetadata)) throw new Error("Runtime dependency inventory changed before post-convergence consumability authorization.");
  const signedEvidence = withSignatureFiles((directory) => signRuntimeConsumabilityEvidence(evidence, { signedAt: now, sign: signer(run, directory) }));
  const outputSha256 = persist(outputFile, signedEvidence, "Production ECS runtime consumability evidence");
  return { outputFile, outputSha256, evidenceSha256: evidence.evidenceSha256, envelopeSha256: signedEvidence.envelopeSha256, inventorySha256: inventory.inventorySha256, dependencyCount: evidence.dependencies.length };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = required(process.argv, "--mode");
  const common = { sourceSha: required(process.argv, "--source-sha"), candidateFile: required(process.argv, "--candidate"), candidateFileSha256: required(process.argv, "--candidate-file-sha256"), outputFile: path.resolve(required(process.argv, "--output")) };
  const rootRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default" });
  const operation = mode === "inventory" ? prepareProductionEcsRuntimeInventory({ ...common, run: rootRun })
    : mode === "consumability" ? prepareProductionEcsRuntimeConsumability({ ...common, inventoryFile: required(process.argv, "--runtime-inventory"), inventoryFileSha256: required(process.argv, "--runtime-inventory-sha256"), run: rootRun })
      : Promise.reject(new Error("--mode must be inventory or consumability."));
  operation.then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
