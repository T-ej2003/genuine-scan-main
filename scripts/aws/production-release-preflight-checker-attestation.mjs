#!/usr/bin/env node
import crypto from "node:crypto";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { CHECKER_TARGET_ROLE_ARN, assertReleasePreflightCheckerTrustEvidence } from "./production-checker-chain-contract.mjs";
import { assertPermissionReportHashDomains, canonicalizeJson, PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_SIGNING_KEY_ARN, signPermissionReport, verifyPermissionReportSignature } from "./validate-production-green-stage-b-permissions.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const CHECKER_SESSION = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[^/]+$/;
export const RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_KIND = "PRODUCTION_RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION";
export const RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_PHASE = "release-preflight";
export const RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_PURPOSE = "checker-trust-attestation";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const parse = (bytes, label) => {
  try { return JSON.parse(bytes); } catch { throw new Error(`${label} is malformed.`); }
};
const required = (argv, name) => {
  const index = argv.indexOf(name);
  const value = index < 0 ? "" : String(argv[index + 1] || "");
  if (!value || value.startsWith("--")) throw new Error(`${name} is required.`);
  return value;
};

export function buildReleasePreflightCheckerTrustAttestation({ report, reportBytes, sourceSha, administratorReportSha256 } = {}) {
  if (!Buffer.isBuffer(reportBytes) || !SHA40.test(sourceSha || "") || !SHA256.test(administratorReportSha256 || "")) throw new Error("Release-preflight checker-trust attestation inputs are invalid.");
  const checked = assertReleasePreflightCheckerTrustEvidence(report, { sourceSha, administratorReportSha256 });
  return {
    schemaVersion: 1,
    evidenceKind: RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_KIND,
    phase: RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_PHASE,
    purpose: RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_PURPOSE,
    status: "valid",
    sourceSha,
    administratorReportSha256,
    releasePreflightReportSha256: sha256(reportBytes),
    signerRoleArn: CHECKER_TARGET_ROLE_ARN,
    checkerTrust: checked.checkerTrust,
  };
}

export function assertReleasePreflightCheckerTrustAttestation(attestation, { reportBytes, sourceSha, administratorReportSha256 } = {}) {
  if (!Buffer.isBuffer(reportBytes) || !SHA40.test(sourceSha || "") || !SHA256.test(administratorReportSha256 || "")) throw new Error("Release-preflight checker-trust attestation expectations are invalid.");
  const expected = {
    schemaVersion: 1,
    evidenceKind: RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_KIND,
    phase: RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_PHASE,
    purpose: RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_PURPOSE,
    status: "valid",
    sourceSha,
    administratorReportSha256,
    releasePreflightReportSha256: sha256(reportBytes),
    signerRoleArn: CHECKER_TARGET_ROLE_ARN,
  };
  for (const [field, value] of Object.entries(expected)) if (attestation?.[field] !== value) throw new Error(`Release-preflight checker-trust attestation ${field} is invalid.`);
  const checkerTrust = attestation?.checkerTrust;
  if (!checkerTrust || canonicalizeJson(checkerTrust) !== canonicalizeJson(assertReleasePreflightCheckerTrustEvidence({ status: "ready-for-plan", sourceSha, administratorReportSha256, checkerTrust }, { sourceSha, administratorReportSha256 }).checkerTrust)) throw new Error("Release-preflight checker-trust attestation checker trust is invalid.");
  return Object.freeze({ ...expected, checkerTrust: Object.freeze({ ...checkerTrust }) });
}

export function authenticateReleasePreflightCheckerTrustEvidence({ report, reportBytes, attestation, attestationBytes, signatureArtifact, signatureBytes, sourceSha, administratorReportSha256, expectedAttestationFileSha256, expectedSignatureFileSha256, now, verifySignature } = {}) {
  const checked = assertReleasePreflightCheckerTrustEvidence(report, { sourceSha, administratorReportSha256 });
  const verifiedAttestation = assertReleasePreflightCheckerTrustAttestation(attestation, { reportBytes, sourceSha, administratorReportSha256 });
  verifyPermissionReportSignature({
    report: attestation,
    signatureArtifact,
    reportBytes: attestationBytes,
    signatureBytes,
    expectedReportFileSha256: expectedAttestationFileSha256,
    expectedSignatureFileSha256,
    ...(now ? { now } : {}),
    ...(verifySignature ? { verify: verifySignature } : {}),
  });
  return Object.freeze({ sourceSha, administratorReportSha256, reportSha256: sha256(reportBytes), attestation: verifiedAttestation, checkerTrust: Object.freeze({ ...checked.checkerTrust }) });
}

export function runReleasePreflightCheckerTrustAttestationCli(argv = process.argv.slice(2), {
  caller = () => JSON.parse(execFileSync("aws", ["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"], { encoding: "utf8" })).Arn,
  sign = signPermissionReport,
  readProtectedMainCheckout = () => readStageBProtectedMainCheckout({ cwd: root }),
} = {}) {
  const sourceSha = required(argv, "--source-sha");
  const administratorReportSha256 = required(argv, "--administrator-report-sha256");
  if (!SHA40.test(sourceSha) || !SHA256.test(administratorReportSha256)) throw new Error("Release-preflight checker-trust attestation source bindings are invalid.");
  const protectedMain = readProtectedMainCheckout();
  if (!protectedMain || protectedMain.toolingSha !== sourceSha || protectedMain.currentHead !== sourceSha || protectedMain.originMainHead !== sourceSha || protectedMain.porcelainStatus) throw new Error("Release-preflight checker-trust attestation requires the exact clean protected-main source.");
  if (!CHECKER_SESSION.test(String(caller() || ""))) throw new Error("Only the exact independent checker session may attest release-preflight checker trust.");
  const reportPath = required(argv, "--release-preflight-report");
  const outputPath = assertStageBArtifactPath({ artifactPath: required(argv, "--output"), repositoryRoot: root, label: "Release-preflight checker-trust attestation", allowExisting: false });
  const signaturePath = assertStageBArtifactPath({ artifactPath: required(argv, "--signature-output"), repositoryRoot: root, label: "Release-preflight checker-trust attestation signature", allowExisting: false });
  if (path.dirname(outputPath) !== path.dirname(signaturePath) || outputPath === signaturePath) throw new Error("Release-preflight checker-trust attestation outputs must be distinct files in one private directory.");
  const reportBytes = readStageBPrivateFileBytes({ filePath: reportPath, repositoryRoot: root, label: "Release-preflight checker-trust evidence" }).bytes;
  const report = parse(reportBytes, "Release-preflight report");
  const attestation = buildReleasePreflightCheckerTrustAttestation({ report, reportBytes, sourceSha, administratorReportSha256 });
  const attestationBytes = Buffer.from(`${JSON.stringify(attestation, null, 2)}\n`);
  const signature = sign(attestation, { reportBytes: attestationBytes });
  const signatureBytes = Buffer.from(`${JSON.stringify(signature, null, 2)}\n`);
  assertPermissionReportHashDomains({ report: attestation, signatureArtifact: signature, reportBytes: attestationBytes, signatureBytes });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, create: true });
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [
    { filePath: outputPath, bytes: attestationBytes, label: "Release-preflight checker-trust attestation" },
    { filePath: signaturePath, bytes: signatureBytes, label: "Release-preflight checker-trust attestation signature" },
  ] });
  return { status: "attested", attestationPath: outputPath, attestationSha256: sha256(attestationBytes), signaturePath, signatureSha256: sha256(signatureBytes), signerRoleArn: CHECKER_TARGET_ROLE_ARN, keyArn: PERMISSION_REPORT_SIGNING_KEY_ARN, signingAlgorithm: PERMISSION_REPORT_SIGNING_ALGORITHM };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.stdout.write(`${JSON.stringify(runReleasePreflightCheckerTrustAttestationCli())}\n`);
