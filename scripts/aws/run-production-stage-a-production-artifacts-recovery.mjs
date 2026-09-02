#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createTerraformStageAAdapter, buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, stageAProductionArtifactsPolicySha256 } from "./production-stage-a-control-plane.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { STAGE_A_TERRAFORM_BACKEND } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { createRootAttestationKmsSigner } from "./production-root-attestation-signer.mjs";
import { createStageAProductionArtifactsJournal } from "./production-stage-a-production-artifacts-journal.mjs";
import { createStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsRecoveryAuthorization, resolveStageAProductionArtifactsAuthorizationArtifact, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactRoot = (value) => value?.Account === "368992683803" && value?.Arn === "arn:aws:iam::368992683803:root";
const exactRelease = (value) => value?.Account === "368992683803" && /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(value?.Arn || "");

function readPolicy(run) {
  const encoded = awsJson(run, ["s3api", "get-bucket-policy", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket]);
  return JSON.parse(encoded.Policy);
}

function assertJournalRetention(run) {
  const versioning = awsJson(run, ["s3api", "get-bucket-versioning", "--bucket", "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"]);
  if (versioning.Status !== "Enabled") throw new Error("Stage A recovery journal requires production-artifacts bucket versioning.");
  try {
    const lifecycle = awsJson(run, ["s3api", "get-bucket-lifecycle-configuration", "--bucket", "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"]);
    for (const rule of lifecycle.Rules || []) {
      const prefix = rule?.Filter?.Prefix ?? rule?.Prefix ?? "";
      if (rule?.Status === "Enabled" && (prefix === "" || "production-stage-a-production-artifacts-reconciliation/".startsWith(prefix)) && (rule.Expiration || rule.NoncurrentVersionExpiration)) throw new Error("Stage A recovery journal lifecycle would expire its immutable records.");
    }
  } catch (error) { if (!/NoSuchLifecycleConfiguration/i.test(`${error.message || ""}\n${error.stderr || ""}`)) throw error; }
}

export async function runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId, workflowRunAttempt, rootRun, releaseRun, readStateIdentity, resolveAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, sign, readProtectedSource = readFreshProtectedMainIdentity } = {}) {
  if (typeof rootRun !== "function" || typeof releaseRun !== "function" || typeof readStateIdentity !== "function" || typeof resolveAuthorization !== "function" || !journal || typeof journal.writeRecoveryCompletion !== "function" || typeof sign !== "function") throw new Error("Stage A production-artifacts recovery composition is incomplete.");
  const fresh = readProtectedSource({ run: (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), expectedSourceSha: sourceSha });
  const authenticated = resolveAuthorization({ workflowRunId, workflowRunAttempt, sourceSha: fresh.headSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION }); const authorization = authenticated.authorization;
  const preState = await readStateIdentity(); assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: fresh.headSha, preState });
  if (!exactRoot(awsJson(rootRun, ["sts", "get-caller-identity"])) || !exactRelease(awsJson(releaseRun, ["sts", "get-caller-identity"]))) throw new Error("Stage A production-artifacts recovery caller identity is outside the exact root/release split.");
  assertJournalRetention(rootRun);
  const before = readPolicy(releaseRun); if (stageAProductionArtifactsPolicySha256(before) !== authorization.expectedLivePolicySha256 || stageAProductionArtifactsPolicySha256(before) !== stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor())) throw new Error("Stage A production-artifacts live predecessor policy is not exact.");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-production-artifacts-recovery-")); const policyPath = path.join(directory, "policy.json");
  try {
    fs.writeFileSync(policyPath, JSON.stringify(buildStageAProductionArtifactsBucketPolicy()), { mode: 0o600, flag: "wx" });
    rootRun(["s3api", "put-bucket-policy", "--bucket", authorization.bucket, "--policy", `file://${policyPath}`]);
    const after = readPolicy(releaseRun); if (stageAProductionArtifactsPolicySha256(after) !== authorization.desiredPolicySha256) throw new Error("Stage A production-artifacts recovery readback is not the exact desired policy.");
    const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization, preRecoveryLivePolicy: before, postRecoveryLivePolicy: after, sign }); const bytes = Buffer.from(`${JSON.stringify(completion)}\n`);
    const persisted = journal.writeRecoveryCompletion({ recoveryAuthorizationSha256: authorization.authorizationSha256, bytes });
    return Object.freeze({ recovered: true, putBucketPolicyCount: 1, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: completion.completionEvidenceSha256, completionObjectSha256: persisted.sha256, completionKey: persisted.key });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export async function runStageAProductionArtifactsRecoveryCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--production")) throw new Error("Stage A production-artifacts recovery requires --production.");
  const sourceSha = required(argv, "--source-sha"); const rootProfile = required(argv, "--root-profile"); const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir"));
  if (!path.isAbsolute(terraformDataDir) || terraformDataDir.startsWith(`${root}${path.sep}`)) throw new Error("Stage A recovery Terraform data directory must be external and absolute.");
  fs.mkdirSync(terraformDataDir, { recursive: true, mode: 0o700 }); fs.chmodSync(terraformDataDir, 0o700);
  const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" }); const rootRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: rootProfile, region: "eu-west-2" });
  const terraformRun = async (args) => execFileSync(args[0], args.slice(1), { cwd: root, env: { ...process.env, AWS_PROFILE: "mscqr-production-release-deployer", AWS_REGION: "eu-west-2", TF_DATA_DIR: terraformDataDir }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const adapter = createTerraformStageAAdapter({ root: "infra/aws/terraform/production-green-stage-a", planPath: path.join(terraformDataDir, "unused.tfplan"), backendArgs: Object.entries(STAGE_A_TERRAFORM_BACKEND).filter(([key]) => key !== "type").map(([key, value]) => `-backend-config=${key}=${value}`), run: terraformRun, describeIngress: async () => ({ present: false }), readProductionArtifactsPolicy: async () => readPolicy(releaseRun), sourceSha });
  const result = await runStageAProductionArtifactsRecovery({ sourceSha, workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), rootRun, releaseRun, readStateIdentity: () => adapter.readStateIdentity(), journal: createStageAProductionArtifactsJournal({ run: releaseRun }), sign: createRootAttestationKmsSigner({ run: rootRun }), ...deps });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runStageAProductionArtifactsRecoveryCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
