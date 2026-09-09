#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { RECONCILER_STATE_RECONCILIATION as CONTRACT, createReconcilerStateReconciliationRecoveryAuthorization } from "./production-initial-activation-reconciler-state-reconciliation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
export function runAuthorizeReconcilerStateReconciliationRecovery(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--authorize-recovery")) throw new Error("State reconciliation recovery authorization requires --authorize-recovery.");
  const sourceSha = required(argv, "--source-sha"); const preparation = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--recovery-preparation")), expectedSha256: required(argv, "--recovery-preparation-file-sha256"), repositoryRoot: root, label: "State reconciliation recovery preparation" });
  const approval = readBoundStageBPrivateJson({ filePath: path.resolve(required(argv, "--environment-approval")), expectedSha256: required(argv, "--environment-approval-file-sha256"), repositoryRoot: root, label: "State reconciliation recovery approval" });
  const env = deps.env || process.env;
  assertProductionEnvironmentApprovalEvidence(approval, { sourceSha, repository: CONTRACT.repository, environment: CONTRACT.environment, workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS });
  const authorization = createReconcilerStateReconciliationRecoveryAuthorization({ recoveryPreparation: preparation, approval, now: deps.now || new Date() });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "State reconciliation recovery authorization", allowExisting: false }); ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "State reconciliation recovery authorization directory" }); writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "State reconciliation recovery authorization" }); return authorization;
}
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runAuthorizeReconcilerStateReconciliationRecovery(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }
