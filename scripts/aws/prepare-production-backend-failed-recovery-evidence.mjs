#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import yaml from "js-yaml";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createAuthenticatedFailedRecoveryEvidence, PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE } from "./production-backend-failed-recovery-evidence.mjs";
import { taskDefinitionFingerprint } from "./stage-b-task-definition-recovery-contract.mjs";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? null : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const sha = /^[a-f0-9]{64}$/;
const repository = "T-ej2003/genuine-scan-main";

export function resolveLegacyWorkflowEvidence({ workflowRunId, run }) {
  const workflow = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}`]));
  if (String(workflow.id) !== workflowRunId || workflow.repository?.full_name !== repository || workflow.head_repository?.full_name !== repository
    || !/^[a-f0-9]{40}$/.test(workflow.head_sha || "") || workflow.event !== "workflow_dispatch"
    || workflow.path !== ".github/workflows/release-gate.yml" || workflow.status !== "completed" || workflow.conclusion !== "failure") throw new Error("Legacy recovery workflow identity is not authentic.");
  const workflowBytes = Buffer.from(run("git", ["show", `${workflow.head_sha}:${workflow.path}`]));
  const definition = yaml.load(workflowBytes.toString("utf8"));
  const productionJob = definition?.jobs?.["deploy-production-ecs"];
  if ((typeof productionJob?.environment === "string" ? productionJob.environment : productionJob?.environment?.name) !== "production"
    || productionJob?.steps?.some?.((step) => step?.uses === "actions/upload-artifact@v7" && step?.with?.name === "backend-health-recovery-evidence"
      && step?.if === "${{ always() && inputs.release_mode == 'backend-health-recovery' }}") !== true) throw new Error("Legacy recovery workflow did not bind production approval and durable recovery evidence.");
  const listed = JSON.parse(run("gh", ["api", `repos/${repository}/actions/runs/${workflowRunId}/artifacts`, "--paginate", "--slurp"]));
  const artifacts = listed.flatMap((page) => page.artifacts || []);
  const matches = artifacts?.filter((item) => item.name === "backend-health-recovery-evidence" && item.expired === false
    && String(item.workflow_run?.id) === workflowRunId && item.workflow_run?.head_sha === workflow.head_sha);
  if (matches?.length !== 1) throw new Error("Legacy recovery workflow does not expose one immutable evidence artifact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-legacy-recovery-evidence-"));
  try {
    run("gh", ["run", "download", workflowRunId, "--repo", repository, "--name", "backend-health-recovery-evidence", "--dir", directory]);
    const evidenceBytes = fs.readFileSync(path.join(directory, "evidence.json"));
    if (!/^sha256:[a-f0-9]{64}$/.test(matches[0].digest || "")) throw new Error("Legacy recovery artifact lacks its GitHub digest.");
    return { workflow, workflowDefinitionSha256: crypto.createHash("sha256").update(workflowBytes).digest("hex"), artifact: matches[0], evidenceBytes };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function prepareProductionBackendFailedRecoveryEvidence({ sourceSha, manifestFile, manifestSha256, outputFile, run, protectedMain = readFreshProtectedMainIdentity, resolveLegacy = resolveLegacyWorkflowEvidence, now } = {}) {
  protectedMain({ cwd: root, expectedSourceSha: sourceSha });
  const manifestArtifact = readStageBPrivateFileBytes({ filePath: path.resolve(manifestFile), repositoryRoot: root, label: "Historical failed recovery manifest" });
  if (manifestArtifact.sha256 !== manifestSha256) throw new Error("Historical failed recovery manifest bytes changed.");
  const manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestArtifact.bytes));
  if (manifest?.schemaVersion !== 1 || !Array.isArray(manifest.records) || !manifest.records.length) throw new Error("Historical failed recovery manifest is malformed.");
  const records = manifest.records.map((record) => {
    if (record?.evidenceContract === PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE) {
      if (Object.keys(record).sort().join(",") !== "evidenceContract,taskDefinition,workflowRunId" || !/^[1-9][0-9]*$/.test(record.workflowRunId || "")) throw new Error("Legacy historical recovery manifest binding is malformed.");
      const task = record.taskDefinition;
      if (!task || Object.keys(task).sort().join(",") !== "file,sha256" || !sha.test(task.sha256 || "")) throw new Error("Legacy task-definition manifest binding is malformed.");
      const taskArtifact = readStageBPrivateFileBytes({ filePath: path.resolve(task.file), repositoryRoot: root, label: "Legacy task definition" });
      if (taskArtifact.sha256 !== task.sha256) throw new Error("Legacy task-definition bytes changed.");
      const taskDefinition = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(taskArtifact.bytes));
      const resolved = resolveLegacy({ workflowRunId: record.workflowRunId, run });
      const evidence = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(resolved.evidenceBytes));
      const definition = taskDefinition.taskDefinition || taskDefinition;
      const fingerprint = taskDefinitionFingerprint(definition, taskDefinition.tags || []);
      if (definition.taskDefinitionArn !== evidence.targetArn || definition.containerDefinitions?.find(({ name }) => name === "backend")?.image?.split("@")[1] !== evidence.recoveryImageDigest) throw new Error("Legacy task definition differs from its recovery evidence.");
      return { recoveryEvidenceBytes: resolved.evidenceBytes, legacyIdentity: {
        schemaVersion: 1, kind: "BACKEND_FAILED_RECOVERY_LEGACY_IDENTITY", evidenceContract: PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE,
        repository, workflowRunId: String(resolved.workflow.id), workflowRunAttempt: String(resolved.workflow.run_attempt), workflowPath: resolved.workflow.path,
        workflowEvent: resolved.workflow.event, workflowHeadSha: resolved.workflow.head_sha, workflowConclusion: resolved.workflow.conclusion,
        workflowCreatedAt: resolved.workflow.created_at, workflowDefinitionSha256: resolved.workflowDefinitionSha256, artifactId: resolved.artifact.id, artifactName: resolved.artifact.name,
        artifactArchiveSizeInBytes: resolved.artifact.size_in_bytes, artifactArchiveDigest: resolved.artifact.digest, evidenceByteSize: resolved.evidenceBytes.length, evidenceByteSha256: crypto.createHash("sha256").update(resolved.evidenceBytes).digest("hex"),
        environmentApprovalEvidence: "PRODUCTION_ENVIRONMENT_BOUND_BY_SCHEMA3_WORKFLOW_NO_PERSISTED_APPROVAL_ARTIFACT", runtimeConsumabilityEvidence: "NOT_PART_OF_SCHEMA", candidateFingerprintEvidence: "NOT_PART_OF_SCHEMA",
        sourceSha: evidence.sourceSha, service: "mscqr-backend-servi-euw2", releaseMode: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME",
        taskDefinitionArn: evidence.targetArn, taskDefinitionFingerprint: fingerprint, recoveryImageDigest: evidence.recoveryImageDigest, imageReleaseSha: evidence.imageReleaseSha,
      } };
    }
    return Object.fromEntries([
    ["recoveryEvidenceBytes", "recoveryEvidence"], ["environmentApprovalBytes", "environmentApproval"], ["runtimeConsumabilityBytes", "runtimeConsumability"],
  ].map(([name, field]) => {
    const value = record?.[field];
    if (!value || Object.keys(value).sort().join(",") !== "file,sha256" || !sha.test(value.sha256 || "")) throw new Error(`Historical ${field} manifest binding is malformed.`);
    const artifact = readStageBPrivateFileBytes({ filePath: path.resolve(value.file), repositoryRoot: root, label: `Historical ${field}` });
    if (artifact.sha256 !== value.sha256) throw new Error(`Historical ${field} bytes changed.`);
    return [name, artifact.bytes];
  }));
  });
  const kms = ({ digest, signature, keyArn, signingAlgorithm }, operation) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-failed-recovery-sign-"));
    try {
      const digestFile = path.join(directory, "digest"); fs.writeFileSync(digestFile, digest, { mode: 0o600, flag: "wx" });
      const args = ["kms", operation, "--key-id", keyArn, "--message", `fileb://${digestFile}`, "--message-type", "DIGEST", "--signing-algorithm", signingAlgorithm];
      if (signature) { const signatureFile = path.join(directory, "signature"); fs.writeFileSync(signatureFile, signature, { mode: 0o600, flag: "wx" }); args.push("--signature", `fileb://${signatureFile}`); }
      return JSON.parse(run("aws", [...args, "--region", "eu-west-2", "--output", "json", "--no-cli-pager"]));
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  const envelope = createAuthenticatedFailedRecoveryEvidence({ records, signedAt: new Date(now ?? Date.now()).toISOString(), verifyRuntime: (input) => kms(input, "verify").SignatureValid === true, sign: (input) => kms(input, "sign").Signature });
  const output = path.resolve(outputFile);
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`), label: "Authenticated failed recovery evidence" }] });
  return { outputFile: output, envelopeSha256: envelope.envelopeSha256 };
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try {
    const profile = process.env.AWS_PROFILE;
    const env = { ...process.env, AWS_REGION: "eu-west-2", AWS_DEFAULT_REGION: "eu-west-2", ...(profile ? { AWS_PROFILE: profile } : {}) };
    const result = prepareProductionBackendFailedRecoveryEvidence({ sourceSha: required(process.argv, "--source-sha"), manifestFile: required(process.argv, "--manifest"), manifestSha256: required(process.argv, "--manifest-sha256"), outputFile: required(process.argv, "--output"), run: (command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
