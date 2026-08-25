#!/usr/bin/env node
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { buildLegacyBackendRecoveryCandidate } from "./production-backend-health-recovery-contract.mjs";
import { canonicalSha256, taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { loadApprovedArtifactSigningBindings } from "./production-artifact-signing-secrets-adapter.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const read = (filePath, sha256, label) => {
  const value = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot: root, label });
  if (value.sha256 !== sha256) throw new Error(`${label} bytes changed before candidate preparation.`);
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(value.bytes));
};

export function prepareProductionBackendRecoveryCandidate({ sourceSha, taskDefinition, imageAuthorization, imageValidation, artifactSigningBindings, artifactSigningBindingSha256 } = {}) {
  assertImageAuthorization(imageAuthorization, sourceSha, imageValidation);
  if (!/^[a-f0-9]{64}$/.test(artifactSigningBindingSha256 || "")) throw new Error("Artifact-signing binding SHA-256 is invalid.");
  const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: taskDefinition, recoveryImageDigest: authorizedBackendDigest(imageAuthorization), imageReleaseSha: imageAuthorization.imageReleaseSha, artifactSigningBindings });
  return Object.freeze({ candidate, candidateCanonicalSha256: canonicalSha256(candidate), candidateFingerprint: taskDefinitionFingerprint(candidate, candidate?.tags || []), artifactSigningBindingSha256 });
}

export function persistProductionBackendRecoveryCandidate(result, output) {
  const bytes = Buffer.from(`${JSON.stringify(result.candidate, null, 2)}\n`);
  const candidateCanonicalSha256 = canonicalSha256(result.candidate);
  const candidateFingerprint = taskDefinitionFingerprint(result.candidate, result.candidate?.tags || []);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes, label: "Production backend recovery candidate" }] });
  return Object.freeze({ output, candidateFileSha256: crypto.createHash("sha256").update(bytes).digest("hex"), candidateCanonicalSha256, candidateFingerprint, artifactSigningBindingSha256: result.artifactSigningBindingSha256 });
}

export function runCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  const taskDefinition = read(required(argv, "--task-definition"), required(argv, "--task-definition-sha256"), "Legacy backend task definition");
  const imageAuthorization = read(required(argv, "--image-authorization"), required(argv, "--image-authorization-sha256"), "Recovery image authorization");
  const artifactSigningFile = required(argv, "--artifact-signing-bindings");
  const artifactSigningBindingSha256 = required(argv, "--artifact-signing-bindings-sha256");
  const artifactSigningBindings = loadApprovedArtifactSigningBindings(artifactSigningFile, { expectedSourceSha: sourceSha, expectedSha256: artifactSigningBindingSha256, repositoryRoot: root });
  const result = prepareProductionBackendRecoveryCandidate({ sourceSha, taskDefinition, imageAuthorization, imageValidation: deps.imageValidation || { verifyImageEvidence: (input) => verifyImageEvidenceSignature(input) }, artifactSigningBindings, artifactSigningBindingSha256 });
  const output = path.resolve(required(argv, "--output"));
  return persistProductionBackendRecoveryCandidate(result, output);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
