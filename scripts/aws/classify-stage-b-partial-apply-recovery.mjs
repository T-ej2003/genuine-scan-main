#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertStageBArtifactPath, assertStageBPrivateFile, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertRecoveryClassification, classifyRecoveryResidue, createStageBRecoveryKmsVerifier, parseCanonicalTerraformSerialCliText } from "./stage-b-partial-apply-recovery-contract.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const option = (argv, name) => { const i = argv.indexOf(name); return i < 0 ? undefined : argv[i + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
export function classifyStageBPartialApplyRecovery({ refreshReport, refreshReportSha256, attestation, attestationSignature, attestationBytes, attestationSignatureBytes, expected, verify, now } = {}) {
  const result = classifyRecoveryResidue({ refreshReport, refreshReportSha256, attestation, attestationSignature, attestationBytes, attestationSignatureBytes, expected, verify, now });
  return { ...result, sourceSha: attestation.currentObservedEvidence.protectedSourceSha };
}

export function runCli(argv = process.argv.slice(2), { verifySignature } = {}) {
  if (typeof verifySignature !== "function") throw new Error("Recovery classification requires an explicit release signature verifier.");
  const refreshPath = required(argv, "--refresh-report");
  const refreshSha = required(argv, "--refresh-report-sha256");
  const attestationPath = required(argv, "--attestation");
  const attestationSha = required(argv, "--attestation-sha256");
  const signaturePath = required(argv, "--signature");
  const signatureSha = required(argv, "--signature-sha256");
  const outputPath = assertStageBArtifactPath({ artifactPath: required(argv, "--output"), repositoryRoot: root, label: "Stage B recovery classification", allowExisting: false });
  for (const [filePath, label] of [[refreshPath, "refresh report"], [attestationPath, "recovery attestation"], [signaturePath, "recovery signature"]]) assertStageBPrivateFile({ filePath, repositoryRoot: root, label });
  const refreshBytes = fs.readFileSync(refreshPath); const attestationBytes = fs.readFileSync(attestationPath); const signatureBytes = fs.readFileSync(signaturePath);
  if (sha256(refreshBytes) !== refreshSha || sha256(attestationBytes) !== attestationSha || sha256(signatureBytes) !== signatureSha) throw new Error("Recovery classification input SHA256 mismatch.");
  const sourceSha = required(argv, "--source-sha"); const lineage = required(argv, "--lineage"); const serial = parseCanonicalTerraformSerialCliText(required(argv, "--serial"), "--serial");
  const result = classifyStageBPartialApplyRecovery({ refreshReport: JSON.parse(refreshBytes), refreshReportSha256: refreshSha, attestation: JSON.parse(attestationBytes), attestationSignature: JSON.parse(signatureBytes), attestationBytes, attestationSignatureBytes: signatureBytes, expected: { protectedSourceSha: sourceSha, terraformLineage: lineage, terraformSerial: serial }, verify: verifySignature, now: new Date() });
  assertRecoveryClassification(result, { refreshReportSha256: refreshSha, recoveryAttestationSha256: attestationSha, expectedSourceSha: sourceSha, expectedLineage: lineage, expectedSerial: serial });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true });
  const bytes = Buffer.from(`${JSON.stringify(result, null, 2)}\n`);
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes, repositoryRoot: root, label: "Stage B recovery classification" });
  return { outputPath, sha256: sha256(bytes), status: result.status };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer" });
    process.stdout.write(`${JSON.stringify(runCli(process.argv.slice(2), { verifySignature: createStageBRecoveryKmsVerifier({ run: releaseRun }) }))}\n`);
  }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
