#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createAuthenticatedFailedRecoveryEvidence } from "./production-backend-failed-recovery-evidence.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const sha = /^[a-f0-9]{64}$/;

export function prepareProductionBackendFailedRecoveryEvidence({ sourceSha, manifestFile, manifestSha256, outputFile, run, protectedMain = readFreshProtectedMainIdentity, now } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const manifestArtifact = readStageBPrivateFileBytes({ filePath: path.resolve(manifestFile), repositoryRoot: root, label: "Historical failed recovery manifest" });
  if (manifestArtifact.sha256 !== manifestSha256) throw new Error("Historical failed recovery manifest bytes changed.");
  const manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestArtifact.bytes));
  if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.records) || !manifest.records.length) throw new Error("Historical failed recovery manifest is malformed.");
  const records = manifest.records.map((record) => Object.fromEntries([
    ["recoveryEvidenceBytes", "recoveryEvidence"], ["environmentApprovalBytes", "environmentApproval"], ["runtimeConsumabilityBytes", "runtimeConsumability"],
  ].map(([name, field]) => {
    const value = record?.[field];
    if (!value || Object.keys(value).sort().join(",") !== "file,sha256" || !sha.test(value.sha256 || "")) throw new Error(`Historical ${field} manifest binding is malformed.`);
    const artifact = readStageBPrivateFileBytes({ filePath: path.resolve(value.file), repositoryRoot: root, label: `Historical ${field}` });
    if (artifact.sha256 !== value.sha256) throw new Error(`Historical ${field} bytes changed.`);
    return [name, artifact.bytes];
  })));
  const kms = ({ digest, signature, keyArn, signingAlgorithm }, operation) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-failed-recovery-sign-"));
    try {
      const digestFile = path.join(directory, "digest"); fs.writeFileSync(digestFile, digest, { mode: 0o600, flag: "wx" });
      const args = ["kms", operation, "--key-id", keyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm];
      if (signature) { const signatureFile = path.join(directory, "signature"); fs.writeFileSync(signatureFile, signature, { mode: 0o600, flag: "wx" }); args.push("--signature", `fileb://${signatureFile}`); }
      return JSON.parse(run("aws", [...args, "--region", "eu-west-2", "--output", "json", "--no-cli-pager"]));
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  const envelope = createAuthenticatedFailedRecoveryEvidence({ records, signedAt: new Date(now ?? Date.now()).toISOString(), verifyRuntime: (input) => kms(input, "verify").SignatureValid === true, sign: (input) => kms(input, "sign").Signature });
  const output = path.resolve(outputFile);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`), label: "Authenticated failed recovery evidence" }] });
  return { outputFile: output, envelopeSha256: envelope.envelopeSha256 };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try {
    const profile = process.env.AWS_PROFILE;
    const env = { ...process.env, AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2", ...(profile ? { AWS_PROFILE: profile } : {}) };
    const result = prepareProductionBackendFailedRecoveryEvidence({ sourceSha: required(process.argv, "--source-sha"), manifestFile: required(process.argv, "--manifest"), manifestSha256: required(process.argv, "--manifest-sha256"), outputFile: required(process.argv, "--output"), run: (command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
