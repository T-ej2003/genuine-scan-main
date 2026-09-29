#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, readBoundStageBPrivateJson, writeStageBPrivateFileExclusive } from "./stage-b-artifact-contract.mjs";
import { assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { SIGNER_STATE_RECONCILIATION as CONTRACT, createSignerStateAuthorization, createSignerStateRecoveryAuthorization } from "./production-initial-activation-signer-state-reconciliation.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, key) => { const i = argv.indexOf(key); if (i < 0 || !argv[i + 1] || argv[i + 1].startsWith("--")) throw new Error(`${key} is required.`); return argv[i + 1]; };
export function runAuthorizeSignerState(argv = process.argv.slice(2), deps = {}) {
  const recovery = argv.includes("--authorize-recovery");
  if (!recovery && !argv.includes("--authorize")) throw new Error("Signer state authorization mode is required.");
  const allowed = new Set([recovery ? "--authorize-recovery" : "--authorize", "--source-sha", recovery ? "--recovery-preparation" : "--preparation", recovery ? "--recovery-preparation-file-sha256" : "--preparation-file-sha256", "--environment-approval", "--environment-approval-file-sha256", "--output"]);
  const seen = new Set(); for (let i = 0; i < argv.length; i++) { const key = argv[i]; if (!allowed.has(key) || seen.has(key)) throw new Error("Signer state authorization arguments are not exact."); seen.add(key); if (!key.startsWith("--authorize")) i++; }
  const sourceSha = required(argv, "--source-sha");
  const read = (file, digest, label) => readBoundStageBPrivateJson({ filePath: path.resolve(file), expectedSha256: digest, repositoryRoot: root, label });
  const preparation = read(required(argv, recovery ? "--recovery-preparation" : "--preparation"), required(argv, recovery ? "--recovery-preparation-file-sha256" : "--preparation-file-sha256"), "Signer state preparation");
  const approval = read(required(argv, "--environment-approval"), required(argv, "--environment-approval-file-sha256"), "Signer state approval");
  const env = deps.env || process.env;
  assertProductionEnvironmentApprovalEvidence(approval, { sourceSha, repository: CONTRACT.repository, environment: CONTRACT.environment, workflowRef: env.GITHUB_WORKFLOW_REF, eventName: env.GITHUB_EVENT_NAME, workflowRunId: env.GITHUB_RUN_ID, workflowRunAttempt: env.GITHUB_RUN_ATTEMPT, executionActor: env.GITHUB_ACTOR, githubActions: env.GITHUB_ACTIONS });
  const authorization = recovery ? createSignerStateRecoveryAuthorization({ recoveryPreparation: preparation, approval, now: deps.now || new Date() }) : createSignerStateAuthorization({ preparation, approval, now: deps.now || new Date() });
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required(argv, "--output")), repositoryRoot: root, label: "Signer state authorization", allowExisting: false });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot: root, create: true, label: "Signer state authorization directory" });
  writeStageBPrivateFileExclusive({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot: root, label: "Signer state authorization" }); return authorization;
}
if (import.meta.url === pathToFileURL(process.argv[1] || "").href) { try { process.stdout.write(`${JSON.stringify(runAuthorizeSignerState(), null, 2)}\n`); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; } }
