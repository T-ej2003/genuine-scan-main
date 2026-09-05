#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { INSTALLATION, createInstallationAuthorization } from "./production-initial-activation-reconciler-installation-contract.mjs";
import { assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function runAuthorizeCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--authorize")) throw new Error("Installation authorization requires --authorize.");
  const sourceSha = required(argv, "--source-sha");
  const preparationPath = path.resolve(required(argv, "--preparation"));
  const preparationSha256 = required(argv, "--preparation-sha256");
  const approvalPath = path.resolve(required(argv, "--environment-approval"));
  const approvalSha256 = required(argv, "--environment-approval-sha256");
  const outputPath = path.resolve(required(argv, "--output"));
  const preparation = readBoundStageBPrivateJson({ filePath: preparationPath, expectedSha256: preparationSha256, repositoryRoot: root, label: "Installation preparation artifact" });
  const approval = readBoundStageBPrivateJson({ filePath: approvalPath, expectedSha256: approvalSha256, repositoryRoot: root, label: "Installation environment approval" });
  const env = deps.env || process.env;
  assertProductionEnvironmentApprovalEvidence(approval, { sourceSha, repository: INSTALLATION.repository, environment: INSTALLATION.environment, workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS });
  const authorization = createInstallationAuthorization({ preparation, preparationSha256, protectedEnvironmentApprovalEvidence: approval, sourceSha });
  const output = assertStageBArtifactPath({ artifactPath: outputPath, repositoryRoot: root, label: "Installation authorization artifact", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Installation authorization directory" });
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Installation authorization artifact" }] });
  return authorization;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runAuthorizeCli().then((value) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`));
