import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { CHECKER_TARGET_ROLE_ARN } from "../aws/production-checker-chain-contract.mjs";
import { RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_KIND, authenticateReleasePreflightCheckerTrustEvidence, buildReleasePreflightCheckerTrustAttestation, runReleasePreflightCheckerTrustAttestationCli } from "../aws/production-release-preflight-checker-attestation.mjs";
import { PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_SIGNING_KEY_ARN, signPermissionReport } from "../aws/validate-production-green-stage-b-permissions.mjs";

const sourceSha = "a".repeat(40);
const administratorReportSha256 = "b".repeat(64);
const now = new Date("2026-08-27T12:00:00.000Z");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const report = () => ({ status: "ready-for-plan", sourceSha, administratorReportSha256, checkerTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN } });

function signedEvidence({ reportValue = report(), source = sourceSha, administratorHash = administratorReportSha256 } = {}) {
  const reportBytes = Buffer.from(`${JSON.stringify(reportValue)}\n`);
  const attestation = buildReleasePreflightCheckerTrustAttestation({ report: reportValue, reportBytes, sourceSha: source, administratorReportSha256: administratorHash });
  const attestationBytes = Buffer.from(`${JSON.stringify(attestation)}\n`);
  const signatureArtifact = signPermissionReport(attestation, { now: now.toISOString(), reportBytes: attestationBytes, sign: () => "AQ==" });
  const signatureBytes = Buffer.from(`${JSON.stringify(signatureArtifact)}\n`);
  return { report: reportValue, reportBytes, attestation, attestationBytes, signatureArtifact, signatureBytes };
}

function authenticate(input, overrides = {}) {
  return authenticateReleasePreflightCheckerTrustEvidence({
    ...input,
    sourceSha,
    administratorReportSha256,
    expectedAttestationFileSha256: sha256(input.attestationBytes),
    expectedSignatureFileSha256: sha256(input.signatureBytes),
    now,
    verifySignature: () => true,
    ...overrides,
  });
}

test("authenticated checker attestation accepts only the exact canonical report binding", () => {
  const evidence = signedEvidence();
  const authenticated = authenticate(evidence);
  assert.equal(authenticated.checkerTrust.exact, true);
  assert.equal(authenticated.checkerTrust.mfaRequired, true);
  assert.equal(authenticated.attestation.releasePreflightReportSha256, sha256(evidence.reportBytes));
  assert.equal(authenticated.attestation.signerRoleArn, CHECKER_TARGET_ROLE_ARN);
});

test("semantic or self-hashed local release reports cannot become checker evidence without an independent signature", () => {
  const forged = report();
  const reportBytes = Buffer.from(`${JSON.stringify(forged)}\n`);
  const attestation = buildReleasePreflightCheckerTrustAttestation({ report: forged, reportBytes, sourceSha, administratorReportSha256 });
  const attestationBytes = Buffer.from(`${JSON.stringify(attestation)}\n`);
  const signatureBytes = Buffer.from(JSON.stringify({ ...attestation, reportFileSha256: sha256(attestationBytes) }));
  assert.throws(() => authenticateReleasePreflightCheckerTrustEvidence({ report: forged, reportBytes, attestation, attestationBytes, signatureArtifact: JSON.parse(signatureBytes), signatureBytes, sourceSha, administratorReportSha256, now, verifySignature: () => true }), /signature identity or algorithm is wrong/);
});

test("attestation rejects report tamper, substitutions, malformed signatures, and failed KMS verification", () => {
  const evidence = signedEvidence();
  const cases = [
    ["modified report", { reportBytes: Buffer.from(`${JSON.stringify({ ...evidence.report, status: "blocked" })}\n`) }, /not bound to the authenticated source|attestation releasePreflightReportSha256/],
    ["source substitution", { sourceSha: "c".repeat(40) }, /not bound to the authenticated source|attestation sourceSha/],
    ["administrator substitution", { administratorReportSha256: "d".repeat(64) }, /not bound to the authenticated source|attestation administratorReportSha256/],
    ["wrong verifier", { verifySignature: () => false }, /signature verification failed/],
    ["wrong signature bytes", { signatureBytes: Buffer.from(`${JSON.stringify({ ...evidence.signatureArtifact, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/other" })}\n`) }, /signature bytes do not match|signature identity or algorithm is wrong/],
  ];
  for (const [name, overrides, expected] of cases) assert.throws(() => authenticate(evidence, overrides), expected, name);
});

test("attestation rejects semantically valid substitutions before runtime configuration", () => {
  const evidence = signedEvidence();
  const copiedReport = Buffer.from(`${JSON.stringify({ ...evidence.report, copied: true })}\n`);
  const wrongDomain = { ...evidence.attestation, evidenceKind: "OTHER_DOMAIN" };
  const wrongDomainBytes = Buffer.from(`${JSON.stringify(wrongDomain)}\n`);
  const wrongDomainSignature = signPermissionReport(wrongDomain, { now: now.toISOString(), reportBytes: wrongDomainBytes, sign: () => "AQ==" });
  const wrongDomainSignatureBytes = Buffer.from(`${JSON.stringify(wrongDomainSignature)}\n`);
  const wrongKey = { ...evidence.signatureArtifact, keyArn: "arn:aws:kms:eu-west-2:368992683803:key/other" };
  const wrongKeyBytes = Buffer.from(`${JSON.stringify(wrongKey)}\n`);
  const cases = [
    ["copied checker trust", { reportBytes: copiedReport }, /releasePreflightReportSha256/],
    ["missing signature", { signatureArtifact: undefined }, /signature identity or algorithm is wrong/],
    ["wrong signing key", { signatureArtifact: wrongKey, signatureBytes: wrongKeyBytes }, /signature identity or algorithm is wrong/],
    ["wrong evidence domain", { attestation: wrongDomain, attestationBytes: wrongDomainBytes, signatureArtifact: wrongDomainSignature, signatureBytes: wrongDomainSignatureBytes }, /evidenceKind is invalid/],
  ];
  for (const [name, overrides, expected] of cases) assert.throws(() => authenticate(evidence, overrides), expected, name);
  assert.equal(evidence.attestation.evidenceKind, RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_KIND);
});

test("attestation producer requires the exact independent checker session and writes a private detached pair", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-preflight-attestation-"));
  try {
    const reportPath = path.join(directory, "release.json");
    const outputPath = path.join(directory, "attestation.json");
    const signaturePath = path.join(directory, "attestation.signature.json");
    fs.writeFileSync(reportPath, `${JSON.stringify(report())}\n`, { mode: 0o600 });
    const argv = ["--source-sha", sourceSha, "--administrator-report-sha256", administratorReportSha256, "--release-preflight-report", reportPath, "--output", outputPath, "--signature-output", signaturePath];
    const protectedMain = { toolingSha: sourceSha, currentHead: sourceSha, originMainHead: sourceSha, porcelainStatus: "" };
    const result = runReleasePreflightCheckerTrustAttestationCli(argv, {
      caller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test",
      readProtectedMainCheckout: () => protectedMain,
      sign: (value, { reportBytes }) => signPermissionReport(value, { now: now.toISOString(), reportBytes, sign: () => "AQ==" }),
    });
    assert.equal(result.status, "attested");
    assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(signaturePath).mode & 0o777, 0o600);
    assert.equal(result.keyArn, PERMISSION_REPORT_SIGNING_KEY_ARN);
    assert.equal(result.signingAlgorithm, PERMISSION_REPORT_SIGNING_ALGORITHM);
    assert.equal(result.signerRoleArn, CHECKER_TARGET_ROLE_ARN);
    assert.throws(() => runReleasePreflightCheckerTrustAttestationCli(argv, { caller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", readProtectedMainCheckout: () => protectedMain }), /exact independent checker session/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
