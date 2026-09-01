#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runPostOverlapVerification } from "./production-cutover-control-plane.mjs";
import { createProductionCutoverRuntimeComposition } from "./production-cutover-runtime-composition.mjs";
import { resolveProductionOverlapDeploymentReceipt } from "./production-overlap-deployment-receipt.mjs";
import { readAndAssertReadyForOverlapDeployment } from "./production-overlap-readiness-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { readBoundStageBPrivateJson, readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export async function verifyProductionCutoverOverlap({ configFile, configSha256, sourceSha, rotationId, workflowRunId, workflowRunAttempt, githubRun = (command, args) => execFileSync(command, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), protectedMain = readFreshProtectedMainIdentity, constructAdapters = createProductionCutoverRuntimeComposition().constructAdapters } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const config = readBoundStageBPrivateJson({ filePath: configFile, expectedSha256: configSha256, repositoryRoot: root, label: "Production cutover runtime config" });
  if (config.sourceSha !== sourceSha || config.rotationId !== rotationId) throw new Error("Verifier continuation config identity is wrong.");
  const state = readStageBPrivateFileBytes({ filePath: config.rotationStateFile, repositoryRoot: root, label: "Persisted rotation state" });
  const fixture = readStageBPrivateFileBytes({ filePath: config.rotationFixtureFile, repositoryRoot: root, label: "Persisted rotation fixture" });
  const readiness = readStageBPrivateFileBytes({ filePath: config.readinessEvidenceFile, repositoryRoot: root, label: "Persisted overlap readiness" });
  readAndAssertReadyForOverlapDeployment({ filePath: config.readinessEvidenceFile, evidenceSha256: readiness.sha256, sourceSha, rotationId, rotationStateSha256: state.sha256 });
  const resolved = resolveProductionOverlapDeploymentReceipt({ workflowRunId, workflowRunAttempt, sourceSha, run: githubRun });
  const receipt = resolved.receipt;
  for (const [field, expected] of Object.entries({ rotationId, rotationStateSha256: state.sha256, readinessSha256: readiness.sha256, rotationFixtureSha256: fixture.sha256, expectedCurrentTaskDefinitionArn: config.expectedCurrentTaskDefinitionArn, taskDefinitionArn: receipt.taskDefinitionArn, imageDigest: config.backendImageDigest, deploymentSha: config.rotationDeploymentSha })) if (receipt[field] !== expected) throw new Error(`Verifier continuation ${field} binding is wrong.`);
  const adapters = constructAdapters({ config, sourceSha, rotationId, runtimeConfigSha256: configSha256 });
  const identities = await adapters.identities.establish();
  if (!/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-ecs-exec-verifier\//.test(identities.verifier?.callerArn || "") || /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\//.test(identities.verifier?.callerArn || "")) throw new Error("Independent MFA verifier identity is required.");
  const result = await runPostOverlapVerification({ deployment: { updateServiceCount: 1, propagateTags: "TASK_DEFINITION", taskDefinitionArn: receipt.taskDefinitionArn, receipt }, sourceSha, rotationId, rotationStateSha256: state.sha256, rotationFixtureSha256: fixture.sha256, taskDefinitionArn: receipt.taskDefinitionArn, expectedImageDigest: receipt.imageDigest, verifierSession: identities.verifier.session, postDeploy: adapters.postDeploy, ecsExec: adapters.ecsExec, rotationVerify: adapters.rotationPrepare.verifyOverlap });
  return { terminalState: result.terminalState, workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt), receiptArtifactId: resolved.artifact.id, receiptArtifactDigest: resolved.artifact.digest, receiptSha256: receipt.receiptSha256, reviewer: resolved.reviewer, rotationId, overlapReadyAt: result.verified.overlapReadyAt, cleanupEligibleAt: result.verified.cleanupEligibleAt, updateServiceCount: 0 };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  verifyProductionCutoverOverlap({ configFile: required(process.argv, "--config"), configSha256: required(process.argv, "--config-sha256"), sourceSha: required(process.argv, "--source-sha"), rotationId: required(process.argv, "--rotation-id"), workflowRunId: required(process.argv, "--workflow-run-id"), workflowRunAttempt: required(process.argv, "--workflow-run-attempt") })
    .then((result) => process.stdout.write(`${JSON.stringify(result)}\n`))
    .catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
