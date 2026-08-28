#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { createProductionDualSlotRebaselineAuthorization } from "./production-dual-slot-rebaseline-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const i = argv.indexOf(name); return i < 0 ? undefined : argv[i + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const readJson = (filePath, label) => { const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label }); return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)), sha256: captured.sha256 }; };

export function runProductionDualSlotRebaselineAuthorizationCli(argv = process.argv.slice(2), env = process.env) {
  if (!argv.includes("--authorize")) throw new Error("--authorize is required.");
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Dual-slot rebaseline authorization", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Dual-slot rebaseline authorization directory" });
  const evidencePath = required(argv, "--environment-approval");
  const capturedEvidence = readJson(evidencePath, "Dual-slot rebaseline environment approval");
  if (capturedEvidence.sha256 !== required(argv, "--environment-approval-sha256")) throw new Error("Dual-slot rebaseline environment approval changed after authentication.");
  const evidence = capturedEvidence.value;
  const resources = JSON.parse(required(argv, "--resources-json"));
  const writeIdentities = JSON.parse(required(argv, "--write-identities-json"));
  const writePayloadIdentities = JSON.parse(required(argv, "--write-payload-identities-json"));
  const authorization = createProductionDualSlotRebaselineAuthorization({
    protectedEnvironmentApprovalEvidence: evidence,
    sourceSha: required(argv, "--source-sha"),
    historicalRotationId: required(argv, "--historical-rotation-id"),
    rotationId: required(argv, "--rotation-id"),
    abandonmentEvidenceSha256: required(argv, "--abandonment-evidence-sha256"),
    baselineIdentitySha256: required(argv, "--baseline-identity-sha256"),
    resources,
    writeIdentities,
    writePayloadIdentities,
    expectedSecretValueWrites: Number(required(argv, "--expected-secret-value-writes")),
    expectedSecretDeletes: Number(required(argv, "--expected-secret-deletes")),
    liveReferenceAudit: required(argv, "--live-reference-audit"),
    liveReferenceAuditSha256: required(argv, "--live-reference-audit-sha256"),
    observedSlotIdentitiesSha256: required(argv, "--observed-slot-identities-sha256"),
    reason: required(argv, "--reason"),
    approvedBy: required(argv, "--approved-by"),
    approverRole: required(argv, "--approver-role"),
    verificationRef: required(argv, "--verification-ref"),
  });
  writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Dual-slot rebaseline authorization" });
  return { ...authorization, authorizationPath: output, authorizationSha256: authorization.authorizationSha256, actor: env.GITHUB_ACTOR || null };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runProductionDualSlotRebaselineAuthorizationCli(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
