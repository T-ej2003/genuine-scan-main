#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createTerraformStageAAdapter, buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, stageAProductionArtifactsPolicySha256 } from "./production-stage-a-control-plane.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { createStageATerraformBackendLock, STAGE_A_TERRAFORM_BACKEND } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { createRootAttestationKmsSigner } from "./production-root-attestation-signer.mjs";
import { createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { createStageAProductionArtifactsJournal } from "./production-stage-a-production-artifacts-journal.mjs";
import { createStageAProductionArtifactsRecoveryAttemptEvidence, assertStageAProductionArtifactsRecoveryAttemptEvidence, createStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsRecoveryAuthorization, assertStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsRecoverySourceCompatibility, resolveStageAProductionArtifactsAuthorizationArtifact, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactRoot = (value) => value?.Account === "368992683803" && value?.Arn === "arn:aws:iam::368992683803:root";
const exactRelease = (value) => value?.Account === "368992683803" && /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(value?.Arn || "");

function readPolicy(run) {
  const encoded = awsJson(run, ["s3api", "get-bucket-policy", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket]);
  return JSON.parse(encoded.Policy);
}

const proveProtectedMainDescendant = ({ ancestorSha, descendantSha }) => {
  try { execFileSync("git", ["cat-file", "-e", `${ancestorSha}^{commit}`], { cwd: root, stdio: "ignore" }); execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
};

export function assertStageAProductionArtifactsJournalRetention(lifecycle, journalPrefix = "production-stage-a-production-artifacts-reconciliation/") {
  if (!lifecycle || !Array.isArray(lifecycle.Rules)) throw new Error("Stage A recovery journal lifecycle response is malformed.");
  const prefixFor = (rule) => {
    if (typeof rule?.Prefix === "string") return rule.Prefix;
    if (typeof rule?.Filter?.Prefix === "string") return rule.Filter.Prefix;
    if (typeof rule?.Filter?.And?.Prefix === "string") return rule.Filter.And.Prefix;
    return null;
  };
  const canProveDisjoint = (rule) => {
    const prefix = prefixFor(rule);
    return prefix !== null && !journalPrefix.startsWith(prefix) && !prefix.startsWith(journalPrefix);
  };
  const deletesEvidence = (rule) => Boolean(rule?.Expiration || rule?.NoncurrentVersionExpiration);
  for (const rule of lifecycle.Rules) {
    if (rule?.Status === "Enabled" && deletesEvidence(rule) && !canProveDisjoint(rule)) throw new Error("Stage A recovery journal lifecycle would expire its immutable records.");
  }
  return true;
}

function assertJournalRetention(run) {
  const versioning = awsJson(run, ["s3api", "get-bucket-versioning", "--bucket", "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"]);
  if (versioning.Status !== "Enabled") throw new Error("Stage A recovery journal requires production-artifacts bucket versioning.");
  try {
    const lifecycle = awsJson(run, ["s3api", "get-bucket-lifecycle-configuration", "--bucket", "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an"]);
    assertStageAProductionArtifactsJournalRetention(lifecycle);
  } catch (error) { if (!/NoSuchLifecycleConfiguration/i.test(`${error.message || ""}\n${error.stderr || ""}`)) throw error; }
}

export async function runStageAProductionArtifactsRecovery({ sourceSha, recoverySourceSha = sourceSha, workflowRunId, workflowRunAttempt, rootRun, releaseRun, readStateIdentity, terraformStateLock, resolveAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, recoveryJournal = journal, sign, verify, readProtectedSource = readStageBProtectedMainCheckout, proveDescendant = proveProtectedMainDescendant } = {}) {
  if (typeof rootRun !== "function" || typeof releaseRun !== "function" || typeof readStateIdentity !== "function" || !terraformStateLock || typeof terraformStateLock.acquire !== "function" || typeof terraformStateLock.release !== "function" || typeof resolveAuthorization !== "function" || !journal || typeof journal.writeRecoveryCompletion !== "function" || typeof journal.readRecoveryCompletion !== "function" || !recoveryJournal || typeof recoveryJournal.writeRecoveryAttempt !== "function" || typeof recoveryJournal.readRecoveryAttempt !== "function" || typeof sign !== "function" || typeof verify !== "function") throw new Error("Stage A production-artifacts recovery composition is incomplete.");
  const fresh = readProtectedSource({ cwd: root, requireCanonicalRepository: true, run: (args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), expectedSourceSha: sourceSha }); const authenticatedSourceSha = fresh.toolingSha || fresh.headSha;
  assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: authenticatedSourceSha, recoverySourceSha, proveDescendant });
  const historicalResume = authenticatedSourceSha !== recoverySourceSha;
  const authenticated = resolveAuthorization({ workflowRunId, workflowRunAttempt, sourceSha: recoverySourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION }); const authorization = authenticated.authorization;
  if (!exactRoot(awsJson(rootRun, ["sts", "get-caller-identity"])) || !exactRelease(awsJson(releaseRun, ["sts", "get-caller-identity"]))) throw new Error("Stage A production-artifacts recovery caller identity is outside the exact root/release split.");
  assertJournalRetention(rootRun);
  const before = readPolicy(releaseRun); const beforeSha256 = stageAProductionArtifactsPolicySha256(before); const predecessorSha256 = stageAProductionArtifactsPolicySha256(buildStageAProductionArtifactsBucketPolicyPredecessor());
  if (![predecessorSha256, authorization.desiredPolicySha256].includes(beforeSha256)) throw new Error("Stage A production-artifacts live policy is neither the exact predecessor nor desired policy.");
  const decode = (record, label) => { if (!record) return null; try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(record.bytes)); } catch { throw new Error(`${label} is malformed.`); } };
  const existingCompletion = decode(journal.readRecoveryCompletion(authorization.authorizationSha256), "Stage A recovery completion");
  if (existingCompletion) {
    assertStageAProductionArtifactsRecoveryCompletionEvidence(existingCompletion, { authorization, verify });
    if (beforeSha256 !== authorization.desiredPolicySha256) throw new Error("Stage A recovery completion exists but live policy is not exact desired policy.");
    return Object.freeze({ recovered: true, resumed: true, alreadyComplete: true, putBucketPolicyCount: 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: existingCompletion.completionEvidenceSha256 });
  }
  if (historicalResume && beforeSha256 === predecessorSha256) throw new Error("Stage A descendant recovery continuation cannot start a new P0 policy execution under the descendant source.");
  let attempt = decode(recoveryJournal.readRecoveryAttempt(authorization.authorizationSha256), "Stage A recovery attempt");
  if (!attempt) {
    if (beforeSha256 !== predecessorSha256) throw new Error("Stage A recovery desired-policy resume lacks the immutable signed pre-write attempt.");
    attempt = createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization, sign });
    recoveryJournal.writeRecoveryAttempt({ recoveryAuthorizationSha256: authorization.authorizationSha256, bytes: Buffer.from(`${JSON.stringify(attempt)}\n`) });
  }
  assertStageAProductionArtifactsRecoveryAttemptEvidence(attempt, { authorization, verify });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-production-artifacts-recovery-")); const policyPath = path.join(directory, "policy.json");
  let lockHeld = false;
  try {
    fs.writeFileSync(policyPath, JSON.stringify(buildStageAProductionArtifactsBucketPolicy()), { mode: 0o600, flag: "wx" });
    await terraformStateLock.acquire(); lockHeld = true;
    const finalState = await readStateIdentity();
    assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: recoverySourceSha, preState: finalState });
    const finalPolicy = readPolicy(releaseRun); const finalPolicySha256 = stageAProductionArtifactsPolicySha256(finalPolicy);
    if (finalPolicySha256 !== beforeSha256) throw new Error("Stage A recovery live policy changed before the policy write.");
    if (beforeSha256 === predecessorSha256) await rootRun(["s3api", "put-bucket-policy", "--bucket", authorization.bucket, "--policy", `file://${policyPath}`]);
    const after = readPolicy(releaseRun); if (stageAProductionArtifactsPolicySha256(after) !== authorization.desiredPolicySha256) throw new Error("Stage A production-artifacts recovery readback is not the exact desired policy.");
    const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization, preRecoveryLivePolicy: buildStageAProductionArtifactsBucketPolicyPredecessor(), postRecoveryLivePolicy: after, sign }); const bytes = Buffer.from(`${JSON.stringify(completion)}\n`);
    let persisted;
    try { persisted = journal.writeRecoveryCompletion({ recoveryAuthorizationSha256: authorization.authorizationSha256, bytes }); }
    catch (error) { const existing = decode(journal.readRecoveryCompletion(authorization.authorizationSha256), "Stage A recovery completion"); if (!existing) throw error; assertStageAProductionArtifactsRecoveryCompletionEvidence(existing, { authorization, verify }); return Object.freeze({ recovered: true, resumed: true, alreadyComplete: true, putBucketPolicyCount: beforeSha256 === predecessorSha256 ? 1 : 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: existing.completionEvidenceSha256 }); }
    return Object.freeze({ recovered: true, resumed: beforeSha256 === authorization.desiredPolicySha256, putBucketPolicyCount: beforeSha256 === predecessorSha256 ? 1 : 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: completion.completionEvidenceSha256, completionObjectSha256: persisted.sha256, completionKey: persisted.key });
  } finally { try { if (lockHeld) await terraformStateLock.release(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } }
}

export async function runStageAProductionArtifactsRecoveryCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--production")) throw new Error("Stage A production-artifacts recovery requires --production.");
  const sourceSha = required(argv, "--source-sha"); const recoverySourceSha = argv.includes("--recovery-source-sha") ? required(argv, "--recovery-source-sha") : sourceSha; const rootProfile = required(argv, "--root-profile"); const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir"));
  if (!path.isAbsolute(terraformDataDir) || terraformDataDir.startsWith(`${root}${path.sep}`)) throw new Error("Stage A recovery Terraform data directory must be external and absolute.");
  fs.mkdirSync(terraformDataDir, { recursive: true, mode: 0o700 }); fs.chmodSync(terraformDataDir, 0o700);
  const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" }); const rootRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: rootProfile, region: "eu-west-2" });
  const terraformEnvironment = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" }), TF_DATA_DIR: terraformDataDir };
  const terraformRun = async (args) => execFileSync(args[0], args.slice(1), { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const adapter = createTerraformStageAAdapter({ root: "infra/aws/terraform/production-green-stage-a", planPath: path.join(terraformDataDir, "unused.tfplan"), backendArgs: Object.entries(STAGE_A_TERRAFORM_BACKEND).filter(([key]) => key !== "type").map(([key, value]) => `-backend-config=${key}=${value}`), run: terraformRun, describeIngress: async () => ({ present: false }), readProductionArtifactsPolicy: async () => readPolicy(releaseRun), sourceSha });
  const result = await runStageAProductionArtifactsRecovery({ sourceSha, recoverySourceSha, workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), rootRun, releaseRun, readStateIdentity: () => adapter.readStateIdentity(), terraformStateLock: createStageATerraformBackendLock({ run: releaseRun, lockFilePath: path.join(terraformDataDir, `stage-a-recovery-${crypto.randomUUID()}.tflock`) }), journal: createStageAProductionArtifactsJournal({ run: releaseRun }), recoveryJournal: createStageAProductionArtifactsJournal({ run: rootRun }), sign: createRootAttestationKmsSigner({ run: rootRun }), verify: createRootAttestationKmsVerifier({ run: releaseRun }), proveDescendant: proveProtectedMainDescendant, ...deps });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runStageAProductionArtifactsRecoveryCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
