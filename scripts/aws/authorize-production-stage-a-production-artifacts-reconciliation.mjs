#!/usr/bin/env node
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageAProductionArtifactsRecoverySourceCompatibility, createStageAProductionArtifactsReconciliationAuthorization, resolveStageAProductionArtifactsAuthorizationArtifact, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { createStageAProductionArtifactsJournal } from "./production-stage-a-production-artifacts-journal.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const proveDescendant = ({ ancestorSha, descendantSha }) => {
  try { execFileSync("git", ["cat-file", "-e", `${ancestorSha}^{commit}`], { cwd: root, stdio: "ignore" }); execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
};

export function authorizeStageAProductionArtifactsReconciliation(argv = process.argv.slice(2), { verifyRecoveryCompletionEvidence, resolveRecoveryAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, proveSourceDescendant = proveDescendant } = {}) {
  const read = (name) => JSON.parse(fs.readFileSync(path.resolve(required(argv, name)), "utf8")); const outputPath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Stage A production-artifacts reconciliation authorization", allowExisting: false });
  const prepareEvidence = read("--prepare-evidence");
  const preState = { lineage: required(argv, "--state-lineage"), serial: Number(required(argv, "--state-serial")), stateSha256: required(argv, "--state-sha256") };
  const sourceSha = required(argv, "--source-sha"); const recoverySourceSha = required(argv, "--recovery-source-sha");
  assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha, recoverySourceSha, proveDescendant: proveSourceDescendant });
  const recovery = resolveRecoveryAuthorization({ workflowRunId: required(argv, "--recovery-authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--recovery-authorization-workflow-run-attempt"), sourceSha: recoverySourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION });
  if (!journal || typeof journal.readRecoveryCompletion !== "function") throw new Error("Stage A production-artifacts reconciliation authorization requires the durable recovery completion journal.");
  const persistedCompletion = journal.readRecoveryCompletion(recovery.authorization.authorizationSha256);
  if (!persistedCompletion) throw new Error("Stage A production-artifacts reconciliation authorization requires the durable recovery completion record.");
  let recoveryCompletion; try { recoveryCompletion = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(persistedCompletion.bytes)); } catch { throw new Error("Stage A production-artifacts durable recovery completion is malformed."); }
  if (typeof verifyRecoveryCompletionEvidence !== "function") throw new Error("Stage A production-artifacts reconciliation authorization requires an independent recovery completion verifier.");
  const authorization = createStageAProductionArtifactsReconciliationAuthorization({ sourceSha, recoverySourceSha, preState, recoveryAuthorization: recovery.authorization, recoveryCompletion, prepareEvidence, savedPlanSha256: required(argv, "--saved-plan-sha256"), protectedEnvironmentApprovalEvidence: read("--environment-approval"), verificationRef: required(argv, "--verification-ref"), verifyRecoveryCompletionEvidence, proveDescendant: proveSourceDescendant });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, label: "Stage A production-artifacts reconciliation authorization directory" });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Stage A production-artifacts reconciliation authorization" });
  return Object.freeze({ outputPath, authorizationSha256: authorization.authorizationSha256 });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const aws = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: "eu-west-2" });
  const caller = JSON.parse(aws(["sts", "get-caller-identity", "--output", "json", "--no-cli-pager"]));
  if (caller.Account !== "368992683803" || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(caller.Arn || "")) throw new Error("Stage A production-artifacts reconciliation authorization requires the exact OIDC release-deployer identity.");
  process.stdout.write(`${JSON.stringify(authorizeStageAProductionArtifactsReconciliation(process.argv.slice(2), { verifyRecoveryCompletionEvidence: createRootAttestationKmsVerifier({ run: aws }), journal: createStageAProductionArtifactsJournal({ run: aws }) }), null, 2)}\n`);
}
