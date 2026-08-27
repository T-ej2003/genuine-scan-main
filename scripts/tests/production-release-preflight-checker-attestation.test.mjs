import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CHECKER_SOURCE_ROLE_ARN, CHECKER_USER_ARN } from "../aws/production-checker-chain-contract.mjs";
import { RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_KIND, RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_SIGNER_ARN, authenticateReleasePreflightCheckerTrustEvidence, buildReleasePreflightCheckerTrustAttestation, runReleasePreflightCheckerTrustAttestationCli } from "../aws/production-release-preflight-checker-attestation.mjs";
import { PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_SIGNING_KEY_ARN, signPermissionReport } from "../aws/validate-production-green-stage-b-permissions.mjs";
import { createProductionCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "../aws/production-cutover-production-adapters.mjs";
import { createProductionCutoverRuntimeComposition } from "../aws/production-cutover-runtime-composition.mjs";
import { buildRootAttestationKeyPolicy, ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_KEY_DESCRIPTION, ROOT_ATTESTATION_TAGS } from "../aws/production-root-attestation-key.mjs";

const sourceSha = "a".repeat(40);
const administratorReportSha256 = "b".repeat(64);
const now = new Date("2026-08-27T12:00:00.000Z");
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const report = () => ({ status: "ready-for-plan", sourceSha, administratorReportSha256, checkerTrust: { exact: true, mfaRequired: true, principal: CHECKER_USER_ARN, roleArn: CHECKER_SOURCE_ROLE_ARN } });
const rootKeyArn = "arn:aws:kms:eu-west-2:368992683803:key/11111111-1111-1111-1111-111111111111";
const sharedCheckerApprovalKeyArn = "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478";
const rootKeyResponse = (args) => {
  if (args[0] !== "kms") throw new Error("unexpected command");
  if (args[1] === "describe-key") return { KeyMetadata: { Arn: rootKeyArn, KeyId: rootKeyArn.split("/").at(-1), Description: ROOT_ATTESTATION_KEY_DESCRIPTION, KeyUsage: "SIGN_VERIFY", KeySpec: "RSA_3072", KeyState: "Enabled", Enabled: true, KeyManager: "CUSTOMER", Origin: "AWS_KMS", MultiRegion: false } };
  if (args[1] === "get-key-policy") return { Policy: JSON.stringify(buildRootAttestationKeyPolicy()) };
  if (args[1] === "list-resource-tags") return { Tags: Object.entries(ROOT_ATTESTATION_TAGS).map(([TagKey, TagValue]) => ({ TagKey, TagValue })) };
  if (args[1] === "verify") return { SignatureValid: true };
  if (args[1] === "sign") return { Signature: "AQ==" };
  throw new Error("unexpected command");
};

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
  assert.equal(authenticated.attestation.signerArn, RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_SIGNER_ARN);
});

test("runtime-preparation production composition verifies checker attestation through the explicit release profile", () => {
  const calls = [];
  const originalProfile = process.env.AWS_PROFILE;
  process.env.AWS_PROFILE = "hostile-default-profile";
  try {
    const releaseRun = createProductionCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,
      profile: "mscqr-production-release-deployer",
      exec: (file, args, options) => {
        calls.push({ file, args, options });
        return JSON.stringify(rootKeyResponse(args));
      },
    });
    const composition = createProductionCutoverRuntimeComposition({ releaseRun });
    const evidence = signedEvidence();
    authenticate(evidence, { verifySignature: composition.verifyReleasePreflightAttestationSignature });
    assert.deepEqual(calls.map(({ args }) => args.slice(0, 2)), [["kms", "describe-key"], ["kms", "get-key-policy"], ["kms", "list-resource-tags"], ["kms", "verify"]]);
    assert.equal(calls.every(({ file }) => file === "aws"), true);
    assert.equal(calls.some(({ args }) => args[1] === "verify" && args.includes(rootKeyArn)), true);
    assert.equal(calls.every(({ options }) => options.env.AWS_PROFILE === "mscqr-production-release-deployer"), true);
    assert.equal(calls.every(({ options }) => options.env.AWS_PROFILE !== "hostile-default-profile" && options.env.AWS_DEFAULT_PROFILE === undefined), true);
  } finally {
    originalProfile === undefined ? delete process.env.AWS_PROFILE : process.env.AWS_PROFILE = originalProfile;
  }
});

test("checker attestation rejects a missing production verifier before any KMS command", () => {
  const evidence = signedEvidence();
  assert.throws(() => authenticateReleasePreflightCheckerTrustEvidence({
    ...evidence,
    sourceSha,
    administratorReportSha256,
    expectedAttestationFileSha256: sha256(evidence.attestationBytes),
    expectedSignatureFileSha256: sha256(evidence.signatureBytes),
    now,
  }), /explicit trusted verifier/);
});

test("semantic or self-hashed local release reports cannot become checker evidence without an independent signature", () => {
  const forged = report();
  const reportBytes = Buffer.from(`${JSON.stringify(forged)}\n`);
  const attestation = buildReleasePreflightCheckerTrustAttestation({ report: forged, reportBytes, sourceSha, administratorReportSha256 });
  const attestationBytes = Buffer.from(`${JSON.stringify(attestation)}\n`);
  const signatureBytes = Buffer.from(JSON.stringify({ ...attestation, reportFileSha256: sha256(attestationBytes) }));
  assert.throws(() => authenticateReleasePreflightCheckerTrustEvidence({ report: forged, reportBytes, attestation, attestationBytes, signatureArtifact: JSON.parse(signatureBytes), signatureBytes, sourceSha, administratorReportSha256, now, verifySignature: () => true }), /signature identity or algorithm is wrong/);
});

test("a checker-valid shared approval-key signature cannot impersonate the root attestation authority", () => {
  const evidence = signedEvidence();
  const checkerSignature = { ...evidence.signatureArtifact, keyArn: sharedCheckerApprovalKeyArn };
  const checkerSignatureBytes = Buffer.from(`${JSON.stringify(checkerSignature)}\n`);
  let cryptographicVerificationReached = false;
  assert.throws(() => authenticate(evidence, {
    signatureArtifact: checkerSignature,
    signatureBytes: checkerSignatureBytes,
    verifySignature: () => { cryptographicVerificationReached = true; return true; },
  }), /signature identity or algorithm is wrong/);
  assert.equal(cryptographicVerificationReached, false);
  assert.equal(PERMISSION_REPORT_SIGNING_KEY_ARN, ROOT_ATTESTATION_KEY_ALIAS_ARN);
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

test("root-attested checker trust is reachable before Stage A checker-role convergence and writes a private detached pair", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "release-preflight-attestation-"));
  try {
    const reportPath = path.join(directory, "release.json");
    const outputPath = path.join(directory, "attestation.json");
    const signaturePath = path.join(directory, "attestation.signature.json");
    fs.writeFileSync(reportPath, `${JSON.stringify(report())}\n`, { mode: 0o600 });
    const argv = ["--source-sha", sourceSha, "--administrator-report-sha256", administratorReportSha256, "--release-preflight-report", reportPath, "--output", outputPath, "--signature-output", signaturePath];
    const protectedMain = { toolingSha: sourceSha, currentHead: sourceSha, originMainHead: sourceSha, porcelainStatus: "" };
    const result = runReleasePreflightCheckerTrustAttestationCli(argv, {
      caller: () => RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_SIGNER_ARN,
      readProtectedMainCheckout: () => protectedMain,
      sign: (value, { reportBytes }) => signPermissionReport(value, { now: now.toISOString(), reportBytes, sign: () => "AQ==" }),
    });
    assert.equal(result.status, "attested");
    assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(signaturePath).mode & 0o777, 0o600);
    assert.equal(result.keyArn, PERMISSION_REPORT_SIGNING_KEY_ARN);
    assert.equal(result.signingAlgorithm, PERMISSION_REPORT_SIGNING_ALGORITHM);
    assert.equal(result.signerArn, RELEASE_PREFLIGHT_CHECKER_TRUST_ATTESTATION_SIGNER_ARN);
    assert.throws(() => runReleasePreflightCheckerTrustAttestationCli(argv, { caller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test", readProtectedMainCheckout: () => protectedMain }), /exact root administrator preflight signer/);
    assert.throws(() => runReleasePreflightCheckerTrustAttestationCli(argv, { caller: () => "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test", readProtectedMainCheckout: () => protectedMain }), /exact root administrator preflight signer/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
