#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { assertStageAProductionArtifactsRecoveryCompletionEvidence, createStageAProductionArtifactsContinuationRebindAuthorization, resolveStageAProductionArtifactsAuthorizationArtifact, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { createStageAProductionArtifactsJournal } from "./production-stage-a-production-artifacts-journal.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function authorizeStageAProductionArtifactsContinuationRebind(argv = process.argv.slice(2), { resolveRecoveryAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, verifyRecoveryCompletionEvidence } = {}) {
  const sourceSha = required(argv, "--source-sha"); const recoverySourceSha = required(argv, "--recovery-source-sha");
  const outputPath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Stage A continuation rebind authorization", allowExisting: false });
  const recovery = resolveRecoveryAuthorization({ workflowRunId: required(argv, "--recovery-authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--recovery-authorization-workflow-run-attempt"), sourceSha: recoverySourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION });
  const persisted = journal?.readRecoveryCompletion(recovery.authorization.authorizationSha256);
  if (!persisted || typeof verifyRecoveryCompletionEvidence !== "function") throw new Error("Stage A continuation rebind requires an authenticated historical recovery completion.");
  const completion = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(persisted.bytes));
  assertStageAProductionArtifactsRecoveryCompletionEvidence(completion, { authorization: recovery.authorization, verify: verifyRecoveryCompletionEvidence });
  const approval = JSON.parse(fs.readFileSync(path.resolve(required(argv, "--environment-approval")), "utf8"));
  const authorization = createStageAProductionArtifactsContinuationRebindAuthorization({ historicalRecoveryAuthorization: recovery.authorization, recoveryCompletion: completion, reviewedContinuationSourceSha: sourceSha, reviewedGovernedExecutableManifestSha256: required(argv, "--reviewed-governed-executable-manifest-sha256"), protectedEnvironmentApprovalEvidence: approval, verificationRef: required(argv, "--verification-ref") });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, label: "Stage A continuation rebind authorization directory" });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Stage A continuation rebind authorization" });
  return Object.freeze({ outputPath, authorizationSha256: authorization.authorizationSha256 });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const aws = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, region: "eu-west-2" });
  process.stdout.write(`${JSON.stringify(authorizeStageAProductionArtifactsContinuationRebind(process.argv.slice(2), { journal: createStageAProductionArtifactsJournal({ run: aws }), verifyRecoveryCompletionEvidence: createRootAttestationKmsVerifier({ run: aws }) }), null, 2)}\n`);
}
