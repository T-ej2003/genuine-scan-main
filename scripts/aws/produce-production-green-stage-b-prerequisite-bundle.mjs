#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { generateStageAPrerequisites, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { generateStageBTfvars } from "./generate-production-green-stage-b-tfvars.mjs";
import { packageStageBBroker } from "./package-production-green-stage-b-broker.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { verifyProductionReleaseImageAuthorization } from "./verify-production-release-image-authorization.mjs";
import { deriveStageBToolingInputTreeSha256 } from "./validate-stage-b-image-reuse.mjs";
import { createStageBPrerequisiteBundle, STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW } from "./stage-b-prerequisite-bundle.mjs";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile, readBoundStageBPrivateJson } from "./stage-b-artifact-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND, writeStageBTerraformStateBackup } from "./stage-b-terraform-backend-contract.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactArgs = (argv) => { const names = argv.filter((_, index) => index % 2 === 0); if (argv.length !== 8 || new Set(names).size !== 4 || names.some((name) => !["--source-sha", "--ticket-id", "--image-authorization", "--image-authorization-sha256"].includes(name))) throw new Error("Stage B prerequisite producer arguments are not exact."); };

export async function produceStageBPrerequisiteBundle({ sourceSha, ticketId, imageAuthorizationPath, imageAuthorizationSha256, outputDirectory, repository = "T-ej2003/genuine-scan-main", workflowRunId, workflowRunAttempt = "1", headSha = sourceSha, run, packageBroker = packageStageBBroker, deriveToolingTree = deriveStageBToolingInputTreeSha256, verifyAuthorization = verifyProductionReleaseImageAuthorization, verifyImageEvidence = verifyImageEvidenceSignature, generateTfvars = generateStageBTfvars } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(ticketId || "") || repository !== "T-ej2003/genuine-scan-main" || !/^\d+$/.test(String(workflowRunId)) || String(workflowRunAttempt) !== "1" || headSha !== sourceSha || typeof run !== "function") throw new Error("Stage B prerequisite producer identity is invalid.");
  if (!path.isAbsolute(outputDirectory || "") || outputDirectory.startsWith(`${root}${path.sep}`)) throw new Error("Stage B prerequisite producer output must be an absolute private runner path.");
  ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot: root, create: true, normalize: true });
  const stageAStateBackupPath = path.join(outputDirectory, "stage-a-state-backup.json"); const stageAInputPath = path.join(outputDirectory, "stage-a-input.json"); const stageBStateBackupPath = path.join(outputDirectory, "stage-b-state-backup.json"); const brokerPackagePath = path.join(outputDirectory, "broker-package.zip"); const brokerManifestPath = path.join(outputDirectory, "broker-package.manifest.json"); const tfvarsPath = path.join(outputDirectory, "stage-b.tfvars"); const bindingReportPath = path.join(outputDirectory, "stage-b-tfvars-binding.json"); const bundlePath = path.join(outputDirectory, "prerequisite-bundle.zip");
  const authorization = readBoundStageBPrivateJson({ filePath: imageAuthorizationPath, expectedSha256: imageAuthorizationSha256, repositoryRoot: root, label: "Stage B reconciliation image authorization" });
  verifyAuthorization({ authorization, sourceSha, verifyImageEvidence: (options) => verifyImageEvidence({ ...options, run }) });
  run(["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", STAGE_A_STATE_OBJECT, "--expected-bucket-owner", STAGE_B.account, stageAStateBackupPath, "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager"]);
  writeStageBTerraformStateBackup({ run, output: stageBStateBackupPath });
  ensureStageBPrivateFile({ filePath: stageAStateBackupPath, repositoryRoot: root, normalize: true, label: "Stage-A state backup" });
  ensureStageBPrivateFile({ filePath: stageBStateBackupPath, repositoryRoot: root, normalize: true, label: "Stage B state backup" });
  const toolingTreeSha256 = deriveToolingTree(sourceSha);
  generateStageAPrerequisites({ stateBackup: stageAStateBackupPath, stateObject: STAGE_A_STATE_OBJECT, toolingSha: sourceSha, toolingTreeSha256, outputPath: stageAInputPath, phase: "POST_APPLY", run });
  await packageBroker({ outputPath: brokerPackagePath, manifestPath: brokerManifestPath, toolingSha: sourceSha, toolingTreeSha256, repositoryRoot: root });
  const imageEvidencePath = path.join(outputDirectory, "image-evidence.json"); const imageEvidenceSignaturePath = path.join(outputDirectory, "image-evidence-signature.json");
  fs.writeFileSync(imageEvidencePath, `${JSON.stringify(authorization.imageEvidence)}\n`, { mode: 0o600, flag: "wx" }); fs.writeFileSync(imageEvidenceSignaturePath, `${JSON.stringify(authorization.imageEvidenceSignature)}\n`, { mode: 0o600, flag: "wx" });
  generateTfvars({ imageEvidence: imageEvidencePath, imageEvidenceSignature: imageEvidenceSignaturePath, stateBackup: stageBStateBackupPath, stageAInput: stageAInputPath, stageAStateBackup: stageAStateBackupPath, brokerPackagePath, toolingSha: sourceSha, toolingTreeSha256, imageReleaseSha: authorization.imageEvidence.publicationIdentity.imageReleaseSha, workflowRunId: authorization.imageEvidence.workflowRunId, canonicalArtifactSha256: authorization.imageEvidence.canonicalArtifactSha256, outputPath: tfvarsPath, bindingReportPath, verifySignature: (options) => verifyImageEvidence({ ...options, run }) });
  return createStageBPrerequisiteBundle({ outputPath: bundlePath, sourceSha, ticketId, repository, workflowRunId, workflowRunAttempt, headSha, brokerPackagePath, brokerManifestPath, stageAInputPath, stageAStateBackupPath, tfvarsPath, bindingReportPath });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    exactArgs(process.argv.slice(2));
    const sourceSha = option(process.argv, "--source-sha"); const ticketId = option(process.argv, "--ticket-id"); const imageAuthorizationPath = option(process.argv, "--image-authorization"); const imageAuthorizationSha256 = option(process.argv, "--image-authorization-sha256");
    if (process.env.GITHUB_ACTIONS !== "true" || process.env.GITHUB_REPOSITORY !== "T-ej2003/genuine-scan-main" || process.env.GITHUB_WORKFLOW_REF !== `${process.env.GITHUB_REPOSITORY}/${STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW}@refs/heads/main` || process.env.GITHUB_EVENT_NAME !== "workflow_dispatch" || process.env.GITHUB_RUN_ATTEMPT !== "1" || process.env.GITHUB_SHA !== sourceSha) throw new Error("Stage B prerequisite producer is workflow-only and source-bound.");
    const outputDirectory = path.join(process.env.RUNNER_TEMP || os.tmpdir(), "stage-b-prerequisite-bundle");
    const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env: process.env });
    const result = await produceStageBPrerequisiteBundle({ sourceSha, ticketId, imageAuthorizationPath, imageAuthorizationSha256, outputDirectory, workflowRunId: process.env.GITHUB_RUN_ID, workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT, run });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
