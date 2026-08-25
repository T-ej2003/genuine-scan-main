#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertFailedRecoveryEvidenceReference, assertFailedRecoveryEvidenceReleaseReadback } from "./production-backend-failed-recovery-evidence-reference.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function resolveProductionBackendFailedRecoveryEvidence({ sourceSha, referenceFile, referenceFileSha256, outputFile, run } = {}) {
  const captured = readStageBPrivateFileBytes({ filePath: path.resolve(referenceFile), repositoryRoot: root, label: "Immutable failed recovery evidence reference" });
  if (captured.sha256 !== referenceFileSha256) throw new Error("Failed-recovery evidence reference bytes changed before resolution.");
  const reference = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes));
  if (reference === null) {
    const bytes = Buffer.from("null"); assertFailedRecoveryEvidenceReference(null, { sourceSha, evidenceBytes: bytes });
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: path.resolve(outputFile), bytes, label: "Resolved failed recovery evidence" }] });
    return Object.freeze({ outputFile: path.resolve(outputFile), evidenceSha256: crypto.createHash("sha256").update(bytes).digest("hex"), referenceSha256: null });
  }
  assertFailedRecoveryEvidenceReference(reference, { sourceSha });
  const release = JSON.parse(run("gh", ["api", `repos/${reference.repository}/releases/${reference.releaseId}`]));
  const asset = JSON.parse(run("gh", ["api", `repos/${reference.repository}/releases/assets/${reference.assetId}`]));
  const evidenceBytes = Buffer.from(run("gh", ["api", `repos/${reference.repository}/releases/assets/${reference.assetId}`, "-H", "Accept: application/octet-stream"], { encoding: null }));
  assertFailedRecoveryEvidenceReleaseReadback(reference, { release, asset, evidenceBytes });
  const output = path.resolve(outputFile);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes: evidenceBytes, label: "Resolved failed recovery evidence" }] });
  return Object.freeze({ outputFile: output, evidenceSha256: reference.evidenceByteSha256, referenceSha256: reference.referenceSha256 });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = resolveProductionBackendFailedRecoveryEvidence({ sourceSha: required(process.argv, "--source-sha"), referenceFile: required(process.argv, "--reference"), referenceFileSha256: required(process.argv, "--reference-sha256"), outputFile: required(process.argv, "--output"), run: (command, args, options = {}) => execFileSync(command, args, { cwd: root, encoding: options.encoding === null ? null : "utf8", stdio: ["ignore", "pipe", "pipe"] }) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
