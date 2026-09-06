#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { createStageAProductionArtifactsRecoveryAuthorization } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { stageAProductionArtifactsInitialActivationReservationRetirementTransition } from "./production-stage-a-control-plane.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
export const STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_TRANSITION = stageAProductionArtifactsInitialActivationReservationRetirementTransition();

export function authorizeStageAProductionArtifactsRecovery(argv = process.argv.slice(2)) {
  const approvalPath = path.resolve(required(argv, "--environment-approval")); const outputPath = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Stage A production-artifacts recovery authorization", allowExisting: false });
  const authorization = createStageAProductionArtifactsRecoveryAuthorization({ sourceSha: required(argv, "--source-sha"), preState: { lineage: required(argv, "--state-lineage"), serial: Number(required(argv, "--state-serial")), stateSha256: required(argv, "--state-sha256") }, protectedEnvironmentApprovalEvidence: JSON.parse(fs.readFileSync(approvalPath, "utf8")), verificationRef: required(argv, "--verification-ref"), transition: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_TRANSITION });
  ensureStageBPrivateDirectory({ directory: path.dirname(outputPath), repositoryRoot: root, label: "Stage A production-artifacts recovery authorization directory" });
  writeStageBPrivateFileAtomic({ filePath: outputPath, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Stage A production-artifacts recovery authorization" });
  return Object.freeze({ outputPath, authorizationSha256: authorization.authorizationSha256 });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(authorizeStageAProductionArtifactsRecovery(), null, 2)}\n`);
