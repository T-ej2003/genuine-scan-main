#!/usr/bin/env node
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { createPartialRebaselineRecoveryAuthorization } from "./production-dual-slot-rebaseline-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const i = argv.indexOf(name); return i < 0 ? undefined : argv[i + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const readJson = (filePath, label) => { const captured = readStageBPrivateFileBytes({ filePath, repositoryRoot: root, label }); return { value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)), sha256: captured.sha256 }; };

export function runPartialRebaselineRecoveryAuthorizationCli(argv = process.argv.slice(2), env = process.env, { proveDescendant = ({ ancestorSha, descendantSha }) => {
  try { execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
} } = {}) {
  if (!argv.includes("--authorize-recovery")) throw new Error("--authorize-recovery is required.");
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Partial rebaseline recovery authorization", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, label: "Partial rebaseline recovery authorization directory" });
  const evidence = readJson(required(argv, "--environment-approval"), "Partial recovery environment approval");
  if (evidence.sha256 !== required(argv, "--environment-approval-sha256")) throw new Error("Partial recovery environment approval changed after authentication.");
  const envelope = readJson(required(argv, "--recovery-envelope"), "Partial recovery envelope");
  if (envelope.sha256 !== required(argv, "--recovery-envelope-file-sha256")) throw new Error("Partial recovery envelope file changed after authentication.");
  const image = readJson(required(argv, "--image-authorization"), "Partial recovery image authorization");
  if (image.sha256 !== required(argv, "--image-authorization-file-sha256")) throw new Error("Partial recovery image authorization file changed after authentication.");
  const authorization = createPartialRebaselineRecoveryAuthorization({
    protectedEnvironmentApprovalEvidence: evidence.value,
    sourceSha: required(argv, "--source-sha"), recoveryEnvelope: envelope.value, imageAuthorization: image.value,
    liveReferenceAuditSha256: required(argv, "--live-reference-audit-sha256"), liveLegacyBaselineIdentitySha256: required(argv, "--live-legacy-baseline-identity-sha256"), observedSlotIdentitiesSha256: required(argv, "--observed-slot-identities-sha256"),
    reason: required(argv, "--reason"), approverRole: required(argv, "--approver-role"), verificationRef: required(argv, "--verification-ref"), proveDescendant,
  });
  writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Partial rebaseline recovery authorization" });
  return { ...authorization, authorizationPath: output, actor: env.GITHUB_ACTOR || null };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(runPartialRebaselineRecoveryAuthorizationCli(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
