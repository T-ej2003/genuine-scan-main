#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { generateStageAPrerequisites, STAGE_A_STATE_OBJECT } from "./generate-production-green-stage-a-prerequisites.mjs";
import { packageStageBBroker } from "./package-production-green-stage-b-broker.mjs";
import { deriveStageBToolingInputTreeSha256 } from "./validate-stage-b-image-reuse.mjs";
import { createStageBPrerequisiteBundle, STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW } from "./stage-b-prerequisite-bundle.mjs";
import { ensureStageBPrivateDirectory, ensureStageBPrivateFile } from "./stage-b-artifact-contract.mjs";
import { STAGE_B_TERRAFORM_BACKEND } from "./stage-b-terraform-backend-contract.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const exactArgs = (argv) => { if (argv.length !== 4 || !["--source-sha", "--ticket-id"].includes(argv[0]) || !["--source-sha", "--ticket-id"].includes(argv[2]) || argv[0] === argv[2]) throw new Error("Stage B prerequisite producer arguments are not exact."); };

export async function produceStageBPrerequisiteBundle({ sourceSha, ticketId, outputDirectory, repository = "T-ej2003/genuine-scan-main", workflowRunId, workflowRunAttempt = "1", headSha = sourceSha, run, packageBroker = packageStageBBroker } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(ticketId || "") || repository !== "T-ej2003/genuine-scan-main" || !/^\d+$/.test(String(workflowRunId)) || String(workflowRunAttempt) !== "1" || headSha !== sourceSha || typeof run !== "function") throw new Error("Stage B prerequisite producer identity is invalid.");
  if (!path.isAbsolute(outputDirectory || "") || outputDirectory.startsWith(`${root}${path.sep}`)) throw new Error("Stage B prerequisite producer output must be an absolute private runner path.");
  ensureStageBPrivateDirectory({ directory: outputDirectory, repositoryRoot: root, create: true, normalize: true });
  const stageAStateBackupPath = path.join(outputDirectory, "stage-a-state-backup.json"); const stageAInputPath = path.join(outputDirectory, "stage-a-input.json"); const brokerPackagePath = path.join(outputDirectory, "broker-package.zip"); const brokerManifestPath = path.join(outputDirectory, "broker-package.manifest.json"); const bundlePath = path.join(outputDirectory, "prerequisite-bundle.zip");
  run(["s3api", "get-object", "--bucket", STAGE_B_TERRAFORM_BACKEND.bucketName, "--key", STAGE_A_STATE_OBJECT, "--expected-bucket-owner", STAGE_B.account, stageAStateBackupPath, "--region", STAGE_B_TERRAFORM_BACKEND.region, "--no-cli-pager"]);
  ensureStageBPrivateFile({ filePath: stageAStateBackupPath, repositoryRoot: root, normalize: true, label: "Stage-A state backup" });
  const toolingTreeSha256 = deriveStageBToolingInputTreeSha256(sourceSha);
  generateStageAPrerequisites({ stateBackup: stageAStateBackupPath, stateObject: STAGE_A_STATE_OBJECT, toolingSha: sourceSha, toolingTreeSha256, outputPath: stageAInputPath, phase: "POST_APPLY", run });
  await packageBroker({ outputPath: brokerPackagePath, manifestPath: brokerManifestPath, toolingSha: sourceSha, toolingTreeSha256, repositoryRoot: root });
  return createStageBPrerequisiteBundle({ outputPath: bundlePath, sourceSha, ticketId, repository, workflowRunId, workflowRunAttempt, headSha, brokerPackagePath, brokerManifestPath, stageAInputPath, stageAStateBackupPath });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    exactArgs(process.argv.slice(2));
    const sourceSha = option(process.argv, "--source-sha"); const ticketId = option(process.argv, "--ticket-id");
    if (process.env.GITHUB_ACTIONS !== "true" || process.env.GITHUB_REPOSITORY !== "T-ej2003/genuine-scan-main" || process.env.GITHUB_WORKFLOW_REF !== `${process.env.GITHUB_REPOSITORY}/${STAGE_B_PREREQUISITE_BUNDLE_WORKFLOW}@refs/heads/main` || process.env.GITHUB_EVENT_NAME !== "workflow_dispatch" || process.env.GITHUB_RUN_ATTEMPT !== "1" || process.env.GITHUB_SHA !== sourceSha) throw new Error("Stage B prerequisite producer is workflow-only and source-bound.");
    const outputDirectory = path.join(process.env.RUNNER_TEMP || os.tmpdir(), "stage-b-prerequisite-bundle");
    const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env: process.env });
    const result = await produceStageBPrerequisiteBundle({ sourceSha, ticketId, outputDirectory, workflowRunId: process.env.GITHUB_RUN_ID, workflowRunAttempt: process.env.GITHUB_RUN_ATTEMPT, run });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
