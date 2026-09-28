#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { SIGNER_TEMPORARY_CAPABILITY as C, assertSignerCapabilityEvidence, assertSignerCreationPlan, assertSignerInitializedBackendMetadata, assertSignerPolicySoleConsumer, assertSignerRevocation, assertSignerTemporaryPolicy, buildSignerCapabilityEvidence, buildSignerTemporaryPolicy, resolveSignerTemporaryVersionId } from "./production-signer-temporary-capability.mjs";
import { verifyProductionSecurityRebaselineSigner } from "./verify-production-security-rebaseline-signer.mjs";
import { buildRecoveryAwsEnvironment } from "./recover-stage-b-backend-task-definition.mjs";
import { createAssumedRoleSessionEnvironment, productionAwsExecutable } from "./production-credential-source-contract.mjs";
import { AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES } from "./production-release-policy-history.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonical = (value) => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
const fail = (message) => { throw new Error(`Signer temporary capability: ${message}`); };
const opt = (argv, name, required = true) => { const i = argv.indexOf(name), value = i < 0 ? undefined : argv[i + 1]; if (required && (!value || value.startsWith("--"))) fail(`${name} is required`); return value; };
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const steadyPolicy = readJson(path.join(root, "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json"));
const trustPolicy = readJson(path.join(root, `${C.root}/trust-policy.json`));
const aws = (profile, args, sessionEnv, singleAttempt = false) => JSON.parse(execFileSync(productionAwsExecutable(), [...args, "--region", C.region, ...(profile ? ["--profile", profile] : []), "--output", "json", "--no-cli-pager"], { cwd: root, env: { ...(sessionEnv || (profile ? buildRecoveryAwsEnvironment(profile) : process.env)), ...(singleAttempt ? { AWS_RETRY_MODE: "standard", AWS_MAX_ATTEMPTS: "1" } : {}) }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
const protect = (file, value) => {
  const parent = path.dirname(file); fs.mkdirSync(parent, { recursive: true, mode: 0o700 }); fs.chmodSync(parent, 0o700);
  const stat = fs.lstatSync(parent); if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail("evidence directory must be a private non-symlink directory");
  const tmp = `${file}.${process.pid}.tmp`; fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx", mode: 0o600 }); fs.renameSync(tmp, file); fs.chmodSync(file, 0o600);
};
const readEvidence = (file, identity) => {
  const stat = fs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail("evidence must be a private regular file");
  const value = readJson(file); assertSignerCapabilityEvidence(value, identity); return value;
};
const readBrokerLedger = (file, identity) => {
  const stat = fs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail("broker lifecycle evidence must be a private regular file");
  const value = readJson(file), authorization = value?.authorization;
  if (value?.kind !== "MSCQR_SIGNER_POLICY_BROKER_LEDGER" || authorization?.sourceSha !== identity.sourceSha || authorization?.transitionId !== identity.transitionId || !/^[a-f0-9]{64}$/.test(authorization?.authorizationSha256 || "")) fail("broker lifecycle evidence differs from the requested source or transition");
  return value;
};
const BOOTSTRAP_PROFILE = "mscqr-production-bootstrap-mfa";
export function assertSignerBootstrapIdentity(profile, caller) {
  if (profile !== BOOTSTRAP_PROFILE) fail(`only ${BOOTSTRAP_PROFILE} may install or revoke the signer capability`);
  if (caller.Account !== C.accountId || caller.Arn !== `arn:aws:iam::${C.accountId}:user/mscqr-production-bootstrap-operator`) fail(`${profile} is not the exact non-root production bootstrap operator`);
  return caller.Arn;
}
const profileIdentity = (profile) => assertSignerBootstrapIdentity(profile, aws(profile, ["sts", "get-caller-identity"]));
const installerEnvironment = () => Object.fromEntries(["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"].filter((key) => process.env[key]).map((key) => [key, process.env[key]]));
export function assertSignerCliArguments(argv, phase) {
  const common = ["--phase", "--source-sha", "--transition-id", "--state-file", "--broker-state-file", "--bootstrap-profile"];
  const extra = ({ plan: ["--plan-output"], "verify-plan": ["--saved-plan", "--approval-reference"], apply: ["--saved-plan", "--approval-reference"], "recover-plan": ["--plan-output"], "recover-verify-plan": ["--saved-plan", "--approval-reference"], "recover-apply": ["--saved-plan", "--approval-reference"], "verify-convergence": ["--saved-plan", "--terraform-state"], revoke: [] })[phase] || [];
  const switches = phase === "revoke" ? ["--abort-before-apply-confirmed"] : [];
  if (!["recover-install", "init", "plan", "verify-plan", "apply", "recover-plan", "recover-verify-plan", "recover-apply", "verify-convergence", "revoke", "verify-absent"].includes(phase)) fail(`unsupported phase ${phase}`);
  const allowed = new Set([...common, ...extra, ...switches]);
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i];
    if (!allowed.has(name) || seen.has(name)) fail(`unsupported or duplicate option ${name}`);
    seen.add(name);
    if (!switches.includes(name) && (!argv[i + 1] || argv[i + 1].startsWith("--"))) fail(`${name} requires one value`);
    if (!switches.includes(name)) i += 1;
  }
  const required = new Set([...common, ...extra]);
  for (const name of required) if (!seen.has(name)) fail(`${name} is required for ${phase}`);
}
function brokerTransition(brokerStateFile, phase, values = {}) {
  const args = [path.join(root, "scripts/aws/production-signer-broker-transition-cli.mjs"), "--phase", phase, "--state-file", brokerStateFile];
  for (const [name, value] of Object.entries(values)) if (value != null) {
    args.push(`--${name.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`)}`); if (value !== true) args.push(value);
  }
  execFileSync(process.execPath, args, { cwd: root, stdio: "inherit" });
}
function assertSource(sourceSha, { cleanupReadback = false } = {}) {
  if (!/^[a-f0-9]{40}$/.test(sourceSha || "") || execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim() !== sourceSha) fail("checkout HEAD differs from authorized source SHA");
  if (execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim()) fail("source checkout is not clean");
  let mainSha;
  if (process.env.GITHUB_ACTIONS === "true" && process.env.GH_TOKEN) {
    mainSha = execFileSync("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main", "--jq", ".commit.sha"], { cwd: root, env: { ...process.env, GH_TOKEN: process.env.GH_TOKEN }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } else {
    execFileSync("git", ["fetch", "origin", "main"], { cwd: root, stdio: "ignore" });
    mainSha = execFileSync("git", ["rev-parse", "refs/remotes/origin/main"], { cwd: root, encoding: "utf8" }).trim();
  }
  if (mainSha !== sourceSha) {
    if (!cleanupReadback) fail("authorized source SHA is no longer current protected main; plan/apply is blocked");
    try { execFileSync("git", ["merge-base", "--is-ancestor", sourceSha, mainSha], { cwd: root, stdio: "ignore" }); } catch { fail("authorized source is not protected-main history"); }
    const stablePaths = [
      "documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", `${C.root}/`,
      "infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-trust-policy.json",
      "infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-permissions-policy.json",
      ".github/workflows/production-signer-policy-transition.yml", ".github/workflows/production-signer-policy-transition-operation.yml",
      "scripts/aws/production-github-environment-approval.mjs", "scripts/aws/reconcile-production-signer-temporary-capability.mjs",
      "scripts/aws/verify-production-security-rebaseline-signer.mjs", "scripts/aws/production-signer-temporary-capability.mjs",
    ];
    try { execFileSync("git", ["diff", "--quiet", `${sourceSha}..${mainSha}`, "--", ...stablePaths], { cwd: root, stdio: "ignore" }); } catch { fail("protected main changed the signer or steady-policy contract; cleanup requires fresh review"); }
  }
}
export function assertSignerSource(sourceSha, options) { assertSource(sourceSha, options); }
function signerSession(bootstrapProfile, transitionId) {
  const assumed = aws(bootstrapProfile, ["sts", "assume-role", "--role-arn", `arn:aws:iam::${C.accountId}:role/mscqr-production-release-deployer`, "--role-session-name", `signer-${sha(transitionId).slice(0, 16)}`, "--duration-seconds", "3600", "--policy-arns", `arn=${C.sourcePolicyArn}`]);
  const credentials = assumed.Credentials;
  const expiresAt = Date.parse(credentials?.Expiration);
  if (!credentials?.AccessKeyId || !credentials.SecretAccessKey || !credentials.SessionToken || !Number.isFinite(expiresAt) || expiresAt < Date.now() + 60000 || expiresAt > Date.now() + 3601000) fail("MFA release session with the exact temporary managed session policy was not issued");
  const env = createAssumedRoleSessionEnvironment({ credentials });
  const caller = aws(undefined, ["sts", "get-caller-identity"], env);
  if (caller.Account !== C.accountId || caller.Arn !== assumed.AssumedRoleUser?.Arn || !new RegExp(`^arn:aws:sts::${C.accountId}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(caller.Arn || "")) fail("temporary signer session identity differs from the exact release-deployer role");
  return env;
}
function terraformSessionEnvironment(sessionEnv) {
  const env = { ...sessionEnv };
  const unexpected = Object.keys(process.env).filter((key) => key.startsWith("TF_VAR_"));
  if (unexpected.length) fail(`Terraform variable environment contains unreviewed keys: ${unexpected.sort().join(", ")}`);
  for (const key of Object.keys(env)) if (key.startsWith("TF_")) delete env[key];
  return env;
}
function policyState(profile, sessionEnv) {
  const policy = aws(profile, ["iam", "get-policy", "--policy-arn", C.sourcePolicyArn], sessionEnv).Policy;
  const versions = aws(profile, ["iam", "list-policy-versions", "--policy-arn", C.sourcePolicyArn], sessionEnv).Versions;
  if (!Array.isArray(versions) || !versions.length || versions.length > 5 || new Set(versions.map(({ VersionId }) => VersionId)).size !== versions.length) fail("policy version topology is invalid");
  const docs = versions.map((version) => {
    const raw = aws(profile, ["iam", "get-policy-version", "--policy-arn", C.sourcePolicyArn, "--version-id", version.VersionId], sessionEnv).PolicyVersion.Document;
    let document = raw; if (typeof raw === "string") { try { document = JSON.parse(raw); } catch { document = JSON.parse(decodeURIComponent(raw)); } }
    return { ...version, document };
  });
  if (docs.filter((version) => version.IsDefaultVersion).length !== 1 || docs.find((version) => version.IsDefaultVersion)?.VersionId !== policy.DefaultVersionId) fail("policy default version readback is ambiguous");
  return { policy, versions: docs, active: docs.find((version) => version.IsDefaultVersion) };
}
function assertCapabilityPolicyAttached(profile, sessionEnv) {
  const attached = aws(profile, ["iam", "list-attached-role-policies", "--role-name", "mscqr-production-release-deployer"], sessionEnv).AttachedPolicies || [];
  if (attached.filter(({ PolicyArn }) => PolicyArn === C.sourcePolicyArn).length !== 1) fail("temporary capability policy is not attached exactly once to the governed release-deployer");
}
function exactSignerTemporaryVersion(doc, identity) {
  try { assertSignerTemporaryPolicy(doc, { steadyPolicy, ...identity }); return true; } catch { return false; }
}
export function assertCanonicalPolicyHistory(state, identity, allowTemporary) {
  const temporary = buildSignerTemporaryPolicy(steadyPolicy, identity);
  const historical = new Set(AUTHENTICATED_HISTORICAL_STEADY_STATE_POLICY_SOURCES.map(({ policySha256 }) => policySha256));
  for (const version of state.versions) {
    const steady = canonical(version.document) === canonical(steadyPolicy);
    const recognizedHistoricalSteady = !version.IsDefaultVersion && historical.has(sha(canonical(version.document)));
    const signer = allowTemporary && canonical(version.document) === canonical(temporary);
    if (!steady && !recognizedHistoricalSteady && !signer) fail("managed policy contains an unexpected version document");
  }
  if (allowTemporary && state.versions.filter(({ document }) => canonical(document) === canonical(temporary)).length !== 1) fail("exactly one signer transition marker is required");
  return true;
}
function verifySignerResourceCensus(profile, sessionEnv, { allowExisting = false } = {}) {
  let rolePresent = false;
  try { aws(profile, ["iam", "get-role", "--role-name", C.roleName], sessionEnv); rolePresent = true; } catch (error) { if (!String(error.stderr || "").includes("NoSuchEntity")) fail("cannot prove the signer role is absent"); }
  if (rolePresent && !allowExisting) fail("signer role already exists; initial convergence refuses adoption");
  let aliasMarker, aliasPages = 0; const seenAliases = new Set();
  do {
    if (++aliasPages > 100 || (aliasMarker && seenAliases.has(aliasMarker))) fail("KMS alias census pagination is invalid");
    if (aliasMarker) seenAliases.add(aliasMarker);
    const page = aws(profile, ["kms", "list-aliases", "--no-paginate", ...(aliasMarker ? ["--marker", aliasMarker] : [])], sessionEnv);
    if (!allowExisting && (page.Aliases || []).some(({ AliasName }) => AliasName === C.alias)) fail("signer alias already exists; initial convergence refuses adoption");
    if (typeof page.Truncated !== "boolean" || (page.Truncated && (typeof page.NextMarker !== "string" || !page.NextMarker))) fail("KMS alias census pagination is incomplete");
    aliasMarker = page.Truncated ? page.NextMarker : undefined;
  } while (aliasMarker);
  let marker, pages = 0; const seen = new Set();
  do {
    if (++pages > 100 || (marker && seen.has(marker))) fail("KMS key census pagination is invalid");
    if (marker) seen.add(marker);
    const page = aws(profile, ["kms", "list-keys", "--no-paginate", ...(marker ? ["--marker", marker] : [])], sessionEnv);
    for (const { KeyId } of page.Keys || []) {
      const tags = aws(profile, ["kms", "list-resource-tags", "--key-id", KeyId], sessionEnv).Tags || [];
      const actual = Object.fromEntries(tags.map(({ TagKey, TagValue }) => [TagKey, TagValue]));
      if (!allowExisting && Object.entries(C.tags).every(([key, value]) => actual[key] === value)) fail("a key already carries the exact signer tags; refusing ambiguous ownership");
    }
    if (typeof page.Truncated !== "boolean" || (page.Truncated && (typeof page.NextMarker !== "string" || !page.NextMarker))) fail("KMS key census pagination is incomplete");
    marker = page.Truncated ? page.NextMarker : undefined;
  } while (marker);
  return true;
}
function assertTerraformState(file) {
  const stat = fs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail("Terraform state export must be a private regular file");
  const state = readJson(file); if (!Array.isArray(state.resources) || state.resources.length !== 4) fail("Terraform state resources are missing or contain unexpected resources");
  const expected = new Set(["aws_iam_role.signer", "aws_kms_key.image_authorization", "aws_kms_alias.image_authorization", "aws_iam_role_policy.sign_only"]);
  const actual = state.resources.map((r) => `${r.type}.${r.name}`);
  if (state.resources.some((r) => r.mode !== "managed" || r.module !== undefined || !Array.isArray(r.instances) || r.instances.length !== 1) || new Set(actual).size !== 4 || actual.some((address) => !expected.has(address)) || [...expected].some((address) => !actual.includes(address))) fail("Terraform state does not own exactly the four signer resources");
  return sha(canonical(state.resources));
}
function assertInitializedSignerBackend(sessionEnv) {
  const directory = path.join(root, C.root, ".terraform"), file = path.join(directory, "terraform.tfstate");
  const dirStat = fs.lstatSync(directory), fileStat = fs.lstatSync(file);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink() || (dirStat.mode & 0o077) || !fileStat.isFile() || fileStat.isSymbolicLink() || (fileStat.mode & 0o077)) fail("Terraform backend metadata must be private (directory 0700, file 0600)");
  assertSignerInitializedBackendMetadata(readJson(file).backend);
  const workspace = execFileSync("terraform", [`-chdir=${path.join(root, C.root)}`, "workspace", "show"], { cwd: root, env: sessionEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  if (workspace !== "default") fail("signer Terraform root must use the default workspace");
}

export function runSignerTemporaryCapability(argv = process.argv.slice(2), { write = (s) => process.stdout.write(s), now = () => new Date().toISOString() } = {}) {
  const phase = opt(argv, "--phase"), sourceSha = opt(argv, "--source-sha"), transitionId = opt(argv, "--transition-id"), stateFile = path.resolve(opt(argv, "--state-file")), brokerStateFile = path.resolve(opt(argv, "--broker-state-file"));
  assertSignerCliArguments(argv, phase);
  const identity = { sourceSha, transitionId }, bootstrap = opt(argv, "--bootstrap-profile");
  assertSource(sourceSha, { cleanupReadback: ["recover-plan", "recover-verify-plan", "recover-apply", "verify-convergence", "revoke", "verify-absent"].includes(phase) });
  profileIdentity(bootstrap);
  let current = policyState(bootstrap);
  assertCapabilityPolicyAttached(bootstrap);
  const evidence = fs.existsSync(stateFile) ? readEvidence(stateFile, identity) : null;
  const brokerLedger = readBrokerLedger(brokerStateFile, identity);
  if (phase === "recover-install" && (!evidence || evidence.state === "INSTALLING")) {
    if (brokerLedger.state === "INSTALLING") { brokerTransition(brokerStateFile, "install"); current = policyState(bootstrap); }
    else if (brokerLedger.state !== "INSTALLED") fail("authoritative broker lifecycle is not ready for install recovery");
    assertCanonicalPolicyHistory(current, identity, true);
    const active = current.active;
    if (!exactSignerTemporaryVersion(active.document, identity)) fail("there is no exact active signer capability to recover");
    const base = current.versions.filter(({ document }) => canonical(document) === canonical(steadyPolicy));
    const steadyVersionId = evidence?.steadyVersionId || (base.length === 1 ? base[0].VersionId : null);
    if (!base.some(({ VersionId }) => VersionId === steadyVersionId)) fail("canonical pre-install policy version cannot be identified uniquely");
    const session = signerSession(bootstrap, transitionId);
    verifySignerResourceCensus(undefined, session);
    const result = buildSignerCapabilityEvidence({ state: "INSTALLED", ...identity, steadyVersionId, temporaryVersionId: active.VersionId, observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, evidenceSha256: result.evidenceSha256, recovered: true })}\n`); return result;
  }
  if (!evidence) fail("private authorization evidence is required");
  if (phase === "verify-absent" && evidence.state === "REVOKED" && evidence.temporaryVersionId === null) {
    assertCanonicalPolicyHistory(current, identity, false);
    if (current.active.VersionId !== evidence.steadyVersionId || canonical(current.active.document) !== canonical(steadyPolicy)) fail("canonical steady policy readback differs after no-mutation recovery");
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "ABSENCE_VERIFIED", observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, restoredPolicy: "VALID", temporaryVersion: "NEVER_INSTALLED" })}\n`); return result;
  }
  assertCanonicalPolicyHistory(current, identity, true);
  const temporaryVersionId = resolveSignerTemporaryVersionId({ versions: current.versions, activeVersionId: current.active.VersionId, evidence, steadyPolicy, identity });
  const temp = current.versions.find(({ VersionId }) => VersionId === temporaryVersionId);
  if (!temp || !exactSignerTemporaryVersion(temp.document, identity)) fail("exact temporary policy version is not present");
  if (["plan", "verify-plan", "apply", "recover-plan", "recover-verify-plan", "recover-apply", "verify-convergence"].includes(phase) && current.active.VersionId !== temporaryVersionId) fail("temporary capability is not the active policy version");
  const session = ["init", "plan", "apply", "recover-plan", "recover-apply", "verify-convergence"].includes(phase) ? signerSession(bootstrap, transitionId) : null;
  if (phase === "init") {
    const terraformRoot = path.join(root, C.root);
    const previousUmask = process.umask(0o077);
    try { execFileSync("terraform", [`-chdir=${terraformRoot}`, "init", "-input=false", "-lockfile=readonly", `-backend-config=bucket=${C.bucket}`, `-backend-config=key=${C.stateKey}`, `-backend-config=region=${C.region}`, "-backend-config=encrypt=true", "-backend-config=use_lockfile=true"], { cwd: root, env: terraformSessionEnvironment(session), stdio: "ignore" }); }
    finally { process.umask(previousUmask); }
    assertInitializedSignerBackend(session);
    write(`${JSON.stringify({ state: "BACKEND_INITIALIZED", accountId: C.accountId, region: C.region, stateKey: C.stateKey })}\n`); return evidence;
  }
  if (phase === "plan") {
    if (evidence.state !== "INSTALLED") fail("a fresh installed capability is required before planning");
    assertInitializedSignerBackend(session);
    const output = path.resolve(opt(argv, "--plan-output"));
    fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 }); fs.chmodSync(path.dirname(output), 0o700);
    const outputDirectory = fs.lstatSync(path.dirname(output)); if (!outputDirectory.isDirectory() || outputDirectory.isSymbolicLink() || (outputDirectory.mode & 0o077)) fail("saved-plan directory must be private and must not be a symlink");
    if (!fs.existsSync(output)) {
      const previousUmask = process.umask(0o077);
      try { execFileSync("terraform", [`-chdir=${path.join(root, C.root)}`, "plan", "-input=false", `-out=${output}`], { cwd: root, env: terraformSessionEnvironment(session), stdio: "ignore" }); }
      catch (error) { fail(`Terraform plan failed with exit status ${error.status ?? "unknown"}; no plan was authorized`); }
      finally { process.umask(previousUmask); }
    }
    const stat = fs.lstatSync(output); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail("Terraform did not create a private regular saved plan");
    const planSha256 = sha(fs.readFileSync(output));
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "PLAN_GENERATED", planSha256, observedAt: now() });
    brokerTransition(brokerStateFile, "advance", { state: "PLAN_GENERATED", planSha256 }); protect(stateFile, result); write(`${JSON.stringify({ state: result.state, planSha256, planFile: output })}\n`); return result;
  }
  if (phase === "verify-plan") {
    if (evidence.state !== "PLAN_GENERATED") fail("source-bound saved plan generation is required before review");
    const savedPlanFile = path.resolve(opt(argv, "--saved-plan"));
    const planStat = fs.lstatSync(savedPlanFile); if (!planStat.isFile() || planStat.isSymbolicLink() || (planStat.mode & 0o077)) fail("saved plan must be a private regular file");
    const savedPlanSha256 = sha(fs.readFileSync(savedPlanFile)); if (savedPlanSha256 !== evidence.planSha256) fail("saved plan differs from the exact source-bound plan");
    const planJson = execFileSync("terraform", ["show", "-json", savedPlanFile], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assertSignerCreationPlan(JSON.parse(planJson), { trustPolicy });
    const approvalReference = opt(argv, "--approval-reference");
    if (!/^[A-Za-z0-9._:/-]{6,160}$/.test(approvalReference)) fail("separate human plan-approval reference is malformed");
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "PLAN_REVIEWED", planSha256: savedPlanSha256, approvalReference, observedAt: now() });
    brokerTransition(brokerStateFile, "advance", { state: "PLAN_REVIEWED", planSha256: savedPlanSha256, approvalReference }); protect(stateFile, result); write(`${JSON.stringify({ state: result.state, planSha256: savedPlanSha256, approvalReference })}\n`); return result;
  }
  if (phase === "apply") {
    if (evidence.state !== "PLAN_REVIEWED") fail("reviewed exact-source plan and approval reference are required before apply");
    assertInitializedSignerBackend(session);
    const savedPlanFile = path.resolve(opt(argv, "--saved-plan")), approvalReference = opt(argv, "--approval-reference");
    if (approvalReference !== evidence.approvalReference) fail("apply approval reference differs from the reviewed plan");
    const stat = fs.lstatSync(savedPlanFile); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || sha(fs.readFileSync(savedPlanFile)) !== evidence.planSha256) fail("saved plan changed or is not private");
    const planJson = execFileSync("terraform", ["show", "-json", savedPlanFile], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assertSignerCreationPlan(JSON.parse(planJson), { trustPolicy });
    if (brokerLedger.state === "PLAN_REVIEWED") brokerTransition(brokerStateFile, "advance", { state: "APPLY_AUTHORIZED", planSha256: evidence.planSha256, approvalReference });
    if (!["PLAN_REVIEWED", "APPLY_AUTHORIZED", "APPLY_STARTED"].includes(brokerLedger.state)) fail("authoritative lifecycle cannot start or resume Terraform apply");
    brokerTransition(brokerStateFile, "advance", { state: "APPLY_STARTED", planSha256: evidence.planSha256, approvalReference });
    const started = buildSignerCapabilityEvidence({ ...evidence, state: "APPLY_STARTED", observedAt: now() });
    protect(stateFile, started);
    try { execFileSync("terraform", [`-chdir=${path.join(root, C.root)}`, "apply", "-input=false", savedPlanFile], { cwd: root, env: terraformSessionEnvironment(session), stdio: "ignore" }); }
    catch (error) { fail(`separately authorized Terraform apply failed with exit status ${error.status ?? "unknown"}; reconcile exact state and AWS readback before retrying`); }
    brokerTransition(brokerStateFile, "advance", { state: "APPLIED", planSha256: evidence.planSha256, approvalReference });
    const result = buildSignerCapabilityEvidence({ ...started, state: "APPLY_COMPLETED", observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, planSha256: result.planSha256, approvalReference })}\n`); return result;
  }
  if (phase === "recover-plan") {
    if (!["APPLY_STARTED", "RECOVERY_APPLY_STARTED"].includes(evidence.state) || brokerLedger.state !== "APPLY_STARTED") fail("authoritative partial-apply recovery is not available");
    assertInitializedSignerBackend(session);
    const output = path.resolve(opt(argv, "--plan-output")); fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 }); fs.chmodSync(path.dirname(output), 0o700);
    if (!fs.existsSync(output)) {
      const previousUmask = process.umask(0o077);
      try { execFileSync("terraform", [`-chdir=${path.join(root, C.root)}`, "plan", "-input=false", `-out=${output}`], { cwd: root, env: terraformSessionEnvironment(session), stdio: "ignore" }); }
      finally { process.umask(previousUmask); }
    }
    const stat = fs.lstatSync(output); if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail("Terraform did not create a private recovery plan");
    const planSha256 = sha(fs.readFileSync(output)), planJson = JSON.parse(execFileSync("terraform", ["show", "-json", output], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
    assertSignerCreationPlan(planJson, { trustPolicy, allowPartial: true });
    brokerTransition(brokerStateFile, "recovery", { state: "PLAN_GENERATED", planSha256 });
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "RECOVERY_PLAN_GENERATED", planSha256, approvalReference: null, observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, planSha256, planFile: output })}\n`); return result;
  }
  if (phase === "recover-verify-plan") {
    if (evidence.state !== "RECOVERY_PLAN_GENERATED") fail("a fresh partial-apply recovery plan is required");
    const savedPlanFile = path.resolve(opt(argv, "--saved-plan")), stat = fs.lstatSync(savedPlanFile);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || sha(fs.readFileSync(savedPlanFile)) !== evidence.planSha256) fail("recovery plan changed or is not private");
    assertSignerCreationPlan(JSON.parse(execFileSync("terraform", ["show", "-json", savedPlanFile], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })), { trustPolicy, allowPartial: true });
    const approvalReference = opt(argv, "--approval-reference"); if (!/^[A-Za-z0-9._:/-]{6,160}$/.test(approvalReference)) fail("recovery approval reference is malformed");
    brokerTransition(brokerStateFile, "recovery", { state: "PLAN_REVIEWED", planSha256: evidence.planSha256, approvalReference });
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "RECOVERY_PLAN_REVIEWED", approvalReference, observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, planSha256: result.planSha256, approvalReference })}\n`); return result;
  }
  if (phase === "recover-apply") {
    if (evidence.state !== "RECOVERY_PLAN_REVIEWED") fail("a separately reviewed partial-apply recovery plan is required");
    assertInitializedSignerBackend(session);
    const savedPlanFile = path.resolve(opt(argv, "--saved-plan")), approvalReference = opt(argv, "--approval-reference"), stat = fs.lstatSync(savedPlanFile);
    if (approvalReference !== evidence.approvalReference || !stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) || sha(fs.readFileSync(savedPlanFile)) !== evidence.planSha256) fail("recovery apply binding differs");
    assertSignerCreationPlan(JSON.parse(execFileSync("terraform", ["show", "-json", savedPlanFile], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })), { trustPolicy, allowPartial: true });
    brokerTransition(brokerStateFile, "recovery", { state: "APPLY_STARTED", planSha256: evidence.planSha256, approvalReference });
    const started = buildSignerCapabilityEvidence({ ...evidence, state: "RECOVERY_APPLY_STARTED", observedAt: now() }); protect(stateFile, started);
    try { execFileSync("terraform", [`-chdir=${path.join(root, C.root)}`, "apply", "-input=false", savedPlanFile], { cwd: root, env: terraformSessionEnvironment(session), stdio: "ignore" }); }
    catch (error) { fail(`partial-apply recovery failed with exit status ${error.status ?? "unknown"}; produce and review a new recovery plan before retrying`); }
    brokerTransition(brokerStateFile, "advance", { state: "APPLIED", planSha256: evidence.planSha256, approvalReference });
    const result = buildSignerCapabilityEvidence({ ...started, state: "APPLY_COMPLETED", observedAt: now() }); protect(stateFile, result);
    write(`${JSON.stringify({ state: result.state, planSha256: result.planSha256, approvalReference })}\n`); return result;
  }
  if (phase === "verify-convergence") {
    if (!["PLAN_REVIEWED", "APPLY_STARTED", "RECOVERY_APPLY_STARTED", "APPLY_COMPLETED"].includes(evidence.state)) fail("separately reviewed saved plan is required before convergence readback");
    if (sha(fs.readFileSync(opt(argv, "--saved-plan"))) !== evidence.planSha256) fail("saved plan bytes changed after review");
    const statePath = path.resolve(opt(argv, "--terraform-state"));
    if (fs.existsSync(statePath)) fail("Terraform state evidence output already exists");
    fs.mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 }); fs.chmodSync(path.dirname(statePath), 0o700);
    const stateDirectory = fs.lstatSync(path.dirname(statePath)); if (!stateDirectory.isDirectory() || stateDirectory.isSymbolicLink() || (stateDirectory.mode & 0o077)) fail("Terraform state evidence directory must be private and must not be a symlink");
    const stateFd = fs.openSync(statePath, "wx", 0o600);
    try { fs.writeFileSync(stateFd, execFileSync("terraform", [`-chdir=${path.join(root, C.root)}`, "state", "pull"], { cwd: root, env: terraformSessionEnvironment(session), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })); }
    catch (error) { fs.rmSync(statePath, { force: true }); throw error; }
    finally { fs.closeSync(stateFd); }
    const stateSha256 = assertTerraformState(statePath);
    const readback = verifyProductionSecurityRebaselineSigner({ env: session });
    const signerReadbackSha256 = sha(canonical({ stateSha256, readback }));
    if (brokerLedger.state === "APPLY_STARTED") brokerTransition(brokerStateFile, "advance", { state: "APPLIED", planSha256: evidence.planSha256, approvalReference: evidence.approvalReference });
    if (!["APPLY_STARTED", "APPLIED", "CONVERGED"].includes(brokerLedger.state)) fail("authoritative lifecycle has not reached Terraform apply");
    brokerTransition(brokerStateFile, "advance", { state: "CONVERGED", planSha256: evidence.planSha256, approvalReference: evidence.approvalReference, signerReadbackSha256 });
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "CONVERGED", signerReadbackSha256, observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, evidenceSha256: result.evidenceSha256, signerReadback: "VALID" })}\n`); return result;
  }
  if (phase === "revoke") {
    const abort = argv.includes("--abort-before-apply-confirmed");
    brokerTransition(brokerStateFile, "revoke", abort ? { abortBeforeApplyConfirmed: true } : {});
    current = policyState(bootstrap); assertCanonicalPolicyHistory(current, identity, true);
    if (canonical(current.active.document) !== canonical(steadyPolicy)) fail("broker revocation did not restore canonical steady policy");
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "REVOKED", steadyVersionId: current.active.VersionId, temporaryVersionId, observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, steadyVersionId: current.active.VersionId })}\n`); return result;
  }
  if (phase === "verify-absent") {
    if (evidence.state !== "REVOKED" || current.active.VersionId !== evidence.steadyVersionId || !temp) fail("normal release-deployer policy was not restored");
    assertSignerRevocation({ activePolicy: current.active.document, temporaryPolicy: temp.document, activeVersionId: current.active.VersionId, temporaryVersionId: evidence.temporaryVersionId, steadyPolicy, identity });
    const result = buildSignerCapabilityEvidence({ ...evidence, state: "ABSENCE_VERIFIED", observedAt: now() });
    protect(stateFile, result); write(`${JSON.stringify({ state: result.state, restoredPolicy: "VALID", temporaryVersion: "NON_DEFAULT" })}\n`); return result;
  }
  fail(`unsupported phase ${phase}`);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { runSignerTemporaryCapability(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
