#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createProductionAwsCommandRunner, createProductionAwsCredentialEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { createTerraformStageAAdapter, buildStageAProductionArtifactsBucketPolicy, buildStageAProductionArtifactsBucketPolicyPredecessor, buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation, resolveStageAProductionArtifactsBucketPolicyTransition, stageAProductionArtifactsPolicySemanticallyEqual } from "./production-stage-a-control-plane.mjs";
import { PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";
import { createStageATerraformBackendLock, STAGE_A_TERRAFORM_BACKEND } from "./production-stage-a-root-drop-orphan-recovery.mjs";
import { parseAuthenticatedStateBytes } from "./generate-production-green-stage-a-prerequisites.mjs";
import { createRootAttestationKmsSigner } from "./production-root-attestation-signer.mjs";
import { createRootAttestationKmsVerifier } from "./production-root-attestation-key.mjs";
import { createStageAProductionArtifactsJournal } from "./production-stage-a-production-artifacts-journal.mjs";
import { createStageAProductionArtifactsRecoveryAttemptEvidence, assertStageAProductionArtifactsRecoveryAttemptEvidence, createStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsRecoveryAuthorization, assertStageAProductionArtifactsRecoveryCompletionEvidence, assertStageAProductionArtifactsRecoverySourceCompatibility, resolveStageAProductionArtifactsAuthorizationArtifact, stageAProductionArtifactsGovernedExecutableManifest, STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION } from "./production-stage-a-production-artifacts-recovery-governance.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";
import { assertProductionEnvironmentApprovalFreshness } from "./production-github-environment-approval.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const required = (argv, name) => { const i = argv.indexOf(name); const value = i < 0 ? undefined : argv[i + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const awsJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
const exactRoot = (value) => value?.Account === "368992683803" && value?.Arn === "arn:aws:iam::368992683803:root";
const exactRelease = (value) => value?.Account === "368992683803" && /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/.test(value?.Arn || "");
const readContinuationChangedFiles = ({ ancestorSha, descendantSha }) => {
  const changed = (sourceSha) => new Map(stageAProductionArtifactsGovernedExecutableManifest(sourceSha).files.map(({ path, sha256 }) => [path, sha256]));
  const ancestor = changed(ancestorSha); const descendant = changed(descendantSha);
  return [...new Set([...ancestor.keys(), ...descendant.keys()])].filter((file) => ancestor.get(file) !== descendant.get(file)).sort();
};

function readPolicy(run) {
  const encoded = awsJson(run, ["s3api", "get-bucket-policy", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket]);
  return JSON.parse(encoded.Policy);
}

export function readRawTerraformStateIdentity(run) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-raw-state-"));
  const output = path.join(directory, "terraform.tfstate");
  try {
    run(["s3api", "get-object", "--bucket", STAGE_A_TERRAFORM_BACKEND.bucket, "--key", STAGE_A_TERRAFORM_BACKEND.key, "--expected-bucket-owner", "368992683803", output]);
    const bytes = fs.readFileSync(output);
    const state = parseAuthenticatedStateBytes(bytes);
    return { lineage: state.lineage, serial: state.serial, stateSha256: crypto.createHash("sha256").update(bytes).digest("hex") };
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export const STAGE_A_RECOVERY_CLASSIFICATION = Object.freeze({
  READY_FOR_WRITE: "READY_FOR_WRITE",
  MUTATION_ATTEMPT_STARTED: "MUTATION_ATTEMPT_STARTED",
  POST_WRITE_COMPLETION_PENDING: "POST_WRITE_COMPLETION_PENDING",
  LIVE_POLICY_CONFLICT: "LIVE_POLICY_CONFLICT",
  P2_WITHOUT_ATTEMPT: "P2_WITHOUT_ATTEMPT",
  COMPLETED: "COMPLETED",
});
export function classifyStageAProductionArtifactsRecovery({ livePolicy, attempt, completion, transition = { predecessor: buildStageAProductionArtifactsBucketPolicyPredecessor(), desired: buildStageAProductionArtifactsBucketPolicy() } } = {}) {
  if (completion) return STAGE_A_RECOVERY_CLASSIFICATION.COMPLETED;
  const equal = (left, right) => { try { return stageAProductionArtifactsPolicySemanticallyEqual(left, right); } catch { return false; } };
  if (equal(livePolicy, transition.desired)) return attempt ? STAGE_A_RECOVERY_CLASSIFICATION.POST_WRITE_COMPLETION_PENDING : STAGE_A_RECOVERY_CLASSIFICATION.P2_WITHOUT_ATTEMPT;
  if (equal(livePolicy, transition.predecessor)) return attempt ? STAGE_A_RECOVERY_CLASSIFICATION.MUTATION_ATTEMPT_STARTED : STAGE_A_RECOVERY_CLASSIFICATION.READY_FOR_WRITE;
  return STAGE_A_RECOVERY_CLASSIFICATION.LIVE_POLICY_CONFLICT;
}

const proveProtectedMainDescendant = ({ ancestorSha, descendantSha }) => {
  try { execFileSync("git", ["cat-file", "-e", `${ancestorSha}^{commit}`], { cwd: root, stdio: "ignore" }); execFileSync("git", ["merge-base", "--is-ancestor", ancestorSha, descendantSha], { cwd: root, stdio: "ignore" }); return true; } catch { return false; }
};

export function assertStageAProductionArtifactsJournalRetention(lifecycle, journalPrefixes = ["production-stage-a-production-artifacts-reconciliation/", PRODUCTION_ACTIVATION_LIFECYCLE.initialActivationPolicyReconciliationReservationPrefix]) {
  if (!lifecycle || !Array.isArray(lifecycle.Rules)) throw new Error("Stage A recovery journal lifecycle response is malformed.");
  const protectedPrefixes = (Array.isArray(journalPrefixes) ? journalPrefixes : [journalPrefixes]).filter((prefix) => typeof prefix === "string" && prefix.length > 0);
  if (!protectedPrefixes.length) throw new Error("Stage A recovery journal protected prefixes are invalid.");
  const prefixFor = (rule) => {
    if (typeof rule?.Prefix === "string") return rule.Prefix;
    if (typeof rule?.Filter?.Prefix === "string") return rule.Filter.Prefix;
    if (typeof rule?.Filter?.And?.Prefix === "string") return rule.Filter.And.Prefix;
    return null;
  };
  const canProveDisjoint = (rule) => {
    const prefix = prefixFor(rule);
    return prefix !== null && protectedPrefixes.every((protectedPrefix) => !protectedPrefix.startsWith(prefix) && !prefix.startsWith(protectedPrefix));
  };
  const hasCurrentVersionExpiration = (expiration) => Boolean(expiration && (Number.isInteger(expiration.Days) || typeof expiration.Date === "string"));
  const makesEvidenceUnavailable = (rule) => Boolean(hasCurrentVersionExpiration(rule?.Expiration) || rule?.Transition || rule?.Transitions?.length);
  for (const [index, rule] of lifecycle.Rules.entries()) {
    if (rule?.Status === "Enabled" && makesEvidenceUnavailable(rule) && !canProveDisjoint(rule)) throw new Error(`Stage A recovery journal lifecycle rule ${rule?.ID || index} would make a protected immutable record unavailable (current records unavailable).`);
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

export async function runStageAProductionArtifactsRecovery({ sourceSha, recoverySourceSha = sourceSha, workflowRunId, workflowRunAttempt, rootRun, releaseRun, readStateIdentity, terraformStateLock, resolveAuthorization = resolveStageAProductionArtifactsAuthorizationArtifact, journal, recoveryJournal = journal, rootRecoveryJournal = recoveryJournal, sign, verify, readProtectedSource = readStageBProtectedMainCheckout, proveDescendant = proveProtectedMainDescendant, readGovernedExecutableManifestSha256 } = {}) {
  if (typeof rootRun !== "function" || typeof releaseRun !== "function" || typeof readStateIdentity !== "function" || !terraformStateLock || typeof terraformStateLock.acquire !== "function" || typeof terraformStateLock.release !== "function" || typeof resolveAuthorization !== "function" || !journal || typeof journal.writeRecoveryCompletion !== "function" || typeof journal.readRecoveryCompletion !== "function" || !recoveryJournal || typeof recoveryJournal.writeRecoveryAttempt !== "function" || typeof recoveryJournal.readRecoveryAttempt !== "function" || !rootRecoveryJournal || typeof rootRecoveryJournal.readRecoveryCompletion !== "function" || typeof sign !== "function" || typeof verify !== "function") throw new Error("Stage A production-artifacts recovery composition is incomplete.");
  const fresh = readProtectedSource({ cwd: root, requireCanonicalRepository: true, run: (args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), expectedSourceSha: sourceSha }); const authenticatedSourceSha = fresh.toolingSha || fresh.headSha;
  assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: authenticatedSourceSha, recoverySourceSha, proveDescendant, readGovernedExecutableManifestSha256, ...(readProtectedSource === readStageBProtectedMainCheckout ? { readContinuationChangedFiles } : {}) });
  const historicalResume = authenticatedSourceSha !== recoverySourceSha;
  const authenticated = resolveAuthorization({ workflowRunId, workflowRunAttempt, sourceSha: recoverySourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, readGovernedExecutableManifestSha256 }); const authorization = authenticated.authorization;
  const transition = resolveStageAProductionArtifactsBucketPolicyTransition(authorization);
  assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: authenticatedSourceSha, recoverySourceSha, proveDescendant, historicalGovernedExecutableManifestSha256: authorization?.governedExecutableManifestSha256, readGovernedExecutableManifestSha256, ...(readProtectedSource === readStageBProtectedMainCheckout ? { readContinuationChangedFiles } : {}) });
  const historicalTransition = (() => { try { return stageAProductionArtifactsPolicySemanticallyEqual(transition.predecessor, buildStageAProductionArtifactsBucketPolicyPredecessor()) && stageAProductionArtifactsPolicySemanticallyEqual(transition.desired, buildStageAProductionArtifactsBucketPolicy()); } catch { return false; } })();
  if (historicalResume && historicalTransition) throw new Error("Stage A historical A-to-B recovery is not supported from a descendant source; use the authenticated completion path.");
  if (!exactRoot(awsJson(rootRun, ["sts", "get-caller-identity"])) || !exactRelease(awsJson(releaseRun, ["sts", "get-caller-identity"]))) throw new Error("Stage A production-artifacts recovery caller identity is outside the exact root/release split.");
  assertJournalRetention(rootRun);
  const samePolicy = (left, right) => { try { return stageAProductionArtifactsPolicySemanticallyEqual(left, right); } catch { return false; } };
  const before = readPolicy(releaseRun); const predecessorLive = samePolicy(before, transition.predecessor); const desiredLive = samePolicy(before, transition.desired);
  if (!predecessorLive && !desiredLive) throw new Error("Stage A production-artifacts live policy is neither the exact predecessor nor desired policy.");
  const reservationTransition = samePolicy(transition.predecessor, buildStageAProductionArtifactsBucketPolicy()) && samePolicy(transition.desired, buildStageAProductionArtifactsBucketPolicyWithInitialActivationReservation());
  if (!historicalTransition && !reservationTransition) throw new Error("Stage A production-artifacts recovery transition is unsupported.");
  const attemptJournal = historicalTransition ? rootRecoveryJournal : recoveryJournal;
  const completionJournal = journal;
  const decode = (record, label) => { if (!record) return null; try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(record.bytes)); } catch { throw new Error(`${label} is malformed.`); } };
  const readCompletion = (reader) => { try { return reader.readRecoveryCompletion(authorization.authorizationSha256); } catch (error) {
    if (!desiredLive || reader !== journal || !/AccessDenied|403/i.test(`${error.message || ""}\n${error.stderr || ""}`)) throw error;
    return rootRecoveryJournal.readRecoveryCompletion(authorization.authorizationSha256);
  } };
  const existingCompletionReader = predecessorLive ? rootRecoveryJournal : completionJournal;
  const existingCompletionRecord = readCompletion(existingCompletionReader);
  const existingCompletion = decode(existingCompletionRecord, "Stage A recovery completion");
  if (existingCompletion) {
    assertStageAProductionArtifactsRecoveryCompletionEvidence(existingCompletion, { authorization, verify });
    if (!desiredLive) throw new Error("Stage A recovery completion exists but live policy is not exact desired policy.");
    return Object.freeze({ recovered: true, resumed: true, alreadyComplete: true, classification: STAGE_A_RECOVERY_CLASSIFICATION.COMPLETED, putBucketPolicyCount: 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: existingCompletion.completionEvidenceSha256 });
  }
  if (historicalResume && predecessorLive) throw new Error("Stage A descendant recovery continuation cannot start a new P0 policy execution under the descendant source.");
  const readAttempt = () => {
    try { return attemptJournal.readRecoveryAttempt(authorization.authorizationSha256); }
    catch (error) {
      if (!reservationTransition || attemptJournal !== recoveryJournal || !/AccessDenied|403/i.test(`${error.message || ""}\n${error.stderr || ""}`)) throw error;
      try { return rootRecoveryJournal.readRecoveryAttempt(authorization.authorizationSha256); }
      catch (rootError) {
        if (/NoSuchKey|NotFound|404/i.test(`${rootError.message || ""}\n${rootError.stderr || ""}`)) return null;
        throw rootError;
      }
    }
  };
  let attempt = decode(readAttempt(), "Stage A recovery attempt");
  let createdAttempt = false;
  if (!attempt) {
    if (!predecessorLive) throw new Error("Stage A recovery desired-policy resume lacks the immutable signed pre-write attempt.");
    assertProductionEnvironmentApprovalFreshness(authorization.protectedEnvironmentApprovalEvidence);
    attempt = createStageAProductionArtifactsRecoveryAttemptEvidence({ authorization, sign });
    attemptJournal.writeRecoveryAttempt({ recoveryAuthorizationSha256: authorization.authorizationSha256, bytes: Buffer.from(`${JSON.stringify(attempt)}\n`) });
    createdAttempt = true;
  }
  assertStageAProductionArtifactsRecoveryAttemptEvidence(attempt, { authorization, verify });
  if (!createdAttempt && predecessorLive) throw new Error("Stage A recovery MUTATION_ATTEMPT_STARTED: PREDECESSOR_LIVE_EXACT does not permit another PutBucketPolicy; governed recovery decision required.");
  const classification = classifyStageAProductionArtifactsRecovery({ livePolicy: before, attempt, transition });
  if ([STAGE_A_RECOVERY_CLASSIFICATION.LIVE_POLICY_CONFLICT, STAGE_A_RECOVERY_CLASSIFICATION.P2_WITHOUT_ATTEMPT].includes(classification)) throw new Error(`Stage A recovery classification is not executable: ${classification}.`);
  const postWriteContinuation = classification === STAGE_A_RECOVERY_CLASSIFICATION.POST_WRITE_COMPLETION_PENDING;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-production-artifacts-recovery-")); const policyPath = path.join(directory, "policy.json");
  let lockHeld = false;
  try {
    fs.writeFileSync(policyPath, JSON.stringify(transition.desired), { mode: 0o600, flag: "wx" });
    let after;
    await terraformStateLock.acquire(); lockHeld = true;
    const finalSource = readProtectedSource({ cwd: root, requireCanonicalRepository: true, run: (args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }), expectedSourceSha: sourceSha }); const finalSourceSha = finalSource.toolingSha || finalSource.headSha;
    assertStageAProductionArtifactsRecoverySourceCompatibility({ sourceSha: finalSourceSha, recoverySourceSha, proveDescendant, historicalGovernedExecutableManifestSha256: authorization.governedExecutableManifestSha256, readGovernedExecutableManifestSha256, ...(readProtectedSource === readStageBProtectedMainCheckout ? { readContinuationChangedFiles } : {}) });
    const finalAuthenticated = resolveAuthorization({ workflowRunId, workflowRunAttempt, sourceSha: recoverySourceSha, operation: STAGE_A_PRODUCTION_ARTIFACTS_RECOVERY_OPERATION, readGovernedExecutableManifestSha256 });
    if (finalAuthenticated?.authorization?.authorizationSha256 !== authorization.authorizationSha256) throw new Error("Stage A recovery authorization changed at the locked execution boundary.");
    if (postWriteContinuation) {
      const finalAttempt = decode(attemptJournal.readRecoveryAttempt(authorization.authorizationSha256), "Stage A recovery attempt");
      assertStageAProductionArtifactsRecoveryAttemptEvidence(finalAttempt, { authorization, verify });
      const finalState = await readStateIdentity();
      assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: recoverySourceSha, preState: finalState });
      after = readPolicy(releaseRun);
      if (!samePolicy(after, before) || !stageAProductionArtifactsPolicySemanticallyEqual(after, transition.desired)) throw new Error("Stage A recovery live policy changed before completion continuation.");
      const concurrentCompletion = decode(readCompletion(completionJournal), "Stage A recovery completion");
      if (concurrentCompletion) {
        assertStageAProductionArtifactsRecoveryCompletionEvidence(concurrentCompletion, { authorization, verify });
        return Object.freeze({ recovered: true, resumed: true, alreadyComplete: true, classification: STAGE_A_RECOVERY_CLASSIFICATION.COMPLETED, putBucketPolicyCount: 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: concurrentCompletion.completionEvidenceSha256 });
      }
    } else {
      const finalState = await readStateIdentity();
      assertStageAProductionArtifactsRecoveryAuthorization(authorization, { sourceSha: recoverySourceSha, preState: finalState });
      const finalPolicy = readPolicy(releaseRun);
      if (!samePolicy(finalPolicy, before)) throw new Error("Stage A recovery live policy changed before the policy write.");
      assertProductionEnvironmentApprovalFreshness(authorization.protectedEnvironmentApprovalEvidence);
      try { if (predecessorLive) await rootRun(["s3api", "put-bucket-policy", "--bucket", authorization.bucket, "--policy", `file://${policyPath}`]); }
      catch (error) {
        // The durable attempt is consumed even if the request never reached AWS.
        const observed = readPolicy(releaseRun);
        if (samePolicy(observed, transition.predecessor)) throw new Error("Stage A recovery ambiguous mutation: PREDECESSOR_LIVE_EXACT; no automatic PutBucketPolicy retry.", { cause: error });
        if (!samePolicy(observed, transition.desired)) throw new Error("Stage A recovery ambiguous mutation: UNEXPECTED live policy; no automatic PutBucketPolicy retry.", { cause: error });
      }
      after = readPolicy(releaseRun); if (!stageAProductionArtifactsPolicySemanticallyEqual(after, transition.desired)) throw new Error("Stage A production-artifacts recovery readback is not the exact desired policy.");
    }
    const completion = createStageAProductionArtifactsRecoveryCompletionEvidence({ authorization, preRecoveryLivePolicy: transition.predecessor, postRecoveryLivePolicy: after, sign }); const bytes = Buffer.from(`${JSON.stringify(completion)}\n`);
    let persisted;
    try { persisted = completionJournal.writeRecoveryCompletion({ recoveryAuthorizationSha256: authorization.authorizationSha256, bytes }); }
    catch (error) { const existing = decode(readCompletion(completionJournal), "Stage A recovery completion"); if (!existing) throw error; assertStageAProductionArtifactsRecoveryCompletionEvidence(existing, { authorization, verify }); return Object.freeze({ recovered: true, resumed: true, alreadyComplete: true, classification: STAGE_A_RECOVERY_CLASSIFICATION.COMPLETED, putBucketPolicyCount: predecessorLive ? 1 : 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: existing.completionEvidenceSha256 }); }
    return Object.freeze({ recovered: true, resumed: desiredLive, classification, putBucketPolicyCount: predecessorLive ? 1 : 0, deleteBucketPolicyCount: 0, authorizationSha256: authorization.authorizationSha256, completionEvidenceSha256: completion.completionEvidenceSha256, completionObjectSha256: persisted.sha256, completionKey: persisted.key });
  } finally { try { if (lockHeld) await terraformStateLock.release(); } finally { fs.rmSync(directory, { recursive: true, force: true }); } }
}

export function createStageARecoveryRootCommandRunner({ exec = execFileSync, ...options } = {}) {
  return createProductionAwsCommandRunner({ ...options, exec: (file, args, execution) => exec(file, args, { ...execution, env: args[0] === "s3api" && args[1] === "put-bucket-policy" ? { ...execution.env, AWS_MAX_ATTEMPTS: "1" } : execution.env }) });
}

export async function runStageAProductionArtifactsRecoveryCli(argv = process.argv.slice(2), deps = {}) {
  if (!argv.includes("--production")) throw new Error("Stage A production-artifacts recovery requires --production.");
  const sourceSha = required(argv, "--source-sha"); const recoverySourceSha = argv.includes("--recovery-source-sha") ? required(argv, "--recovery-source-sha") : sourceSha; const rootProfile = required(argv, "--root-profile"); const terraformDataDir = path.resolve(required(argv, "--terraform-data-dir"));
  if (!path.isAbsolute(terraformDataDir) || terraformDataDir.startsWith(`${root}${path.sep}`)) throw new Error("Stage A recovery Terraform data directory must be external and absolute.");
  fs.mkdirSync(terraformDataDir, { recursive: true, mode: 0o700 }); fs.chmodSync(terraformDataDir, 0o700);
  const releaseRun = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" }); const rootRun = createStageARecoveryRootCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: rootProfile, region: "eu-west-2" });
  const terraformEnvironment = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: "eu-west-2" }), TF_DATA_DIR: terraformDataDir };
  const terraformRun = async (args) => execFileSync(args[0], args.slice(1), { cwd: root, env: terraformEnvironment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  const adapter = createTerraformStageAAdapter({ root: "infra/aws/terraform/production-green-stage-a", planPath: path.join(terraformDataDir, "unused.tfplan"), backendArgs: Object.entries(STAGE_A_TERRAFORM_BACKEND).filter(([key]) => key !== "type").map(([key, value]) => `-backend-config=${key}=${value}`), run: terraformRun, describeIngress: async () => ({ present: false }), readProductionArtifactsPolicy: async () => readPolicy(releaseRun), sourceSha });
  const result = await runStageAProductionArtifactsRecovery({ sourceSha, recoverySourceSha, workflowRunId: required(argv, "--authorization-workflow-run-id"), workflowRunAttempt: required(argv, "--authorization-workflow-run-attempt"), rootRun, releaseRun, readStateIdentity: () => readRawTerraformStateIdentity(releaseRun), terraformStateLock: createStageATerraformBackendLock({ run: releaseRun, lockFilePath: path.join(terraformDataDir, `stage-a-recovery-${crypto.randomUUID()}.tflock`) }), journal: createStageAProductionArtifactsJournal({ run: releaseRun }), recoveryJournal: createStageAProductionArtifactsJournal({ run: releaseRun }), rootRecoveryJournal: createStageAProductionArtifactsJournal({ run: rootRun }), sign: createRootAttestationKmsSigner({ run: rootRun }), verify: createRootAttestationKmsVerifier({ run: releaseRun }), proveDescendant: proveProtectedMainDescendant, ...deps });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`); return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runStageAProductionArtifactsRecoveryCli().catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
