import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";
import { componentBrokerPackageManifest } from "./component-broker-package.mjs";
import { brokerEntryPointCandidates } from "./component-broker-configuration.mjs";
import { assertArchivedInstallationAuthorization } from "./component-broker-authorization.mjs";
import { assertIdentityBootstrapAuthorization, bootstrapAuthorizationContract } from "./component-identity-bootstrap-authorization.mjs";
import { assertBootstrapRecoveryAuthorization } from "./component-bootstrap-partial-recovery-authorization.mjs";
import { bootstrapRecovery } from "./component-bootstrap-partial-recovery-contract.mjs";
import { assertBrokerChangeAuthorization } from "./component-broker-change-authorization.mjs";
import { brokerChange } from "./component-broker-change-contract.mjs";
import { assertBrokerPolicySuccessorAuthorization } from "./component-broker-policy-successor-authorization.mjs";
import { brokerPolicySuccessor } from "./component-broker-policy-successor-contract.mjs";
import { assertPartialActivationRecoveryAuthorization } from "./component-infrastructure-partial-activation-recovery-authorization.mjs";
import { partialActivationRecovery } from "./component-infrastructure-partial-activation-recovery-contract.mjs";

// Authorization only: no AWS, dispatch, consumption, or installation. The caller
// must run trusted protected-main code and consume the transition once before writes.
// authenticatePublishedComponentAuthorization({runId, sourceSha, transitionId}) always
// reads GitHub; there is deliberately no local authorization-file or CLI override.
export const componentIamAuthorization = Object.freeze({
  repository: "T-ej2003/genuine-scan-main", account: "368992683803", region: "eu-west-2",
  environment: "production-component-infrastructure-install-permission",
  workflow: ".github/workflows/authorize-component-iam-installation.yml",
  maxAgeMs: 30 * 60 * 1000,
});
const { repository, environment, workflow } = componentIamAuthorization;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function coordinates({ sourceSha, transitionId }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/, "Invalid source SHA");
  assert.match(transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i, "Invalid transition UUID");
}
function timestamp(value) {
  assert(typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)), "Invalid timestamp");
  assert.equal(new Date(Date.parse(value)).toISOString(), value.includes(".") ? value : value.replace("Z", ".000Z"));
  return Date.parse(value);
}
function user(value) {
  assert.equal(value?.type, "User", "Required User identity");
  assert.equal(value?.login, "T-ej2003", "Wrong operator login");
  assert.equal(value?.id, 183396573, "Wrong operator ID");
}
function protectedMain(branch, sourceSha) {
  assert.equal(branch.name, "main");
  assert.equal(branch.protected, true, "Main is not protected");
  assert.equal(branch.commit?.sha, sourceSha, "Source is not current main");
}

export function assertComponentIamEnvironment(config, branches, approvals) {
  return assertSoloEnvironment(config, branches, approvals, environment);
}

export function assertComponentIdentityBootstrapEnvironment(config, branches, approvals) {
  return assertSoloEnvironment(config, branches, approvals, "production-component-installation-identity-bootstrap");
}

export function assertSoloEnvironment(config, branches, approvals, expectedEnvironment) {
  assert.equal(config.name, expectedEnvironment);
  assert(Number.isSafeInteger(config.id) && config.id > 0, "Invalid environment ID");
  assert.equal(config.can_admins_bypass, false);
  assert.deepEqual(config.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.equal(branches.total_count, 1);
  assert.deepEqual(branches.branch_policies.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]);
  const rules = config.protection_rules.filter((rule) => rule.type === "required_reviewers");
  assert.equal(rules.length, 1);
  assert.equal(rules[0].prevent_self_review, false);
  assert.equal(rules[0].reviewers.length, 1);
  assert.equal(rules[0].reviewers[0].type, "User");
  user(rules[0].reviewers[0].reviewer);
  // This workflow has one environment and one approval; reject ambiguous history,
  // rejections, bypasses, teams, and approvals for an environment recreated by name.
  assert(Array.isArray(approvals) && approvals.length === 1, "Exactly one approval required");
  assert.equal(approvals[0].state, "approved");
  user(approvals[0].user);
  assert.deepEqual(approvals[0].environments.map(({ id, name }) => ({ id, name })), [{ id: config.id, name: expectedEnvironment }]);
  return config.id;
}

// Fixed executable candidates: never resolve gh through caller-controlled PATH.
// Resolve installed symlinks once, then execute the canonical absolute path.
function githubExecutable() {
  for (const candidate of ["/usr/bin/gh", "/opt/homebrew/bin/gh", "/usr/local/bin/gh", "/Users/abhiramteja/.local/bin/gh"]) {
    if (!fs.existsSync(candidate)) continue;
    const resolved = fs.realpathSync(candidate);
    assert(/^(?:\/usr\/bin\/gh|\/usr\/local\/bin\/gh|\/(?:opt\/homebrew|usr\/local)\/Cellar\/gh\/[^/]+\/bin\/gh|\/Users\/abhiramteja\/\.local\/gh-[0-9.]+\/bin\/gh)$/.test(resolved), "GitHub executable is outside canonical safelist");
    assert(fs.statSync(resolved).isFile() && !(fs.statSync(resolved).mode & 0o022), "Unsafe GitHub executable");
    return resolved;
  }
  throw new Error("No safelisted GitHub CLI installation found");
}

function githubReader(execute, env, targetEnvironment = environment) {
  const childEnv = { ...createProductionGithubCredentialEnvironment({ env }), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" };
  const executable = execute ? "gh" : githubExecutable();
  const runner = execute || execFileSync;
  return (endpoint, { binary = false, paginate = false } = {}) => {
    const prefix = `repos/${repository}/`;
    const suffix = endpoint.slice(prefix.length);
    assert(endpoint.startsWith(prefix) && (suffix === "branches/main" || suffix === `environments/${targetEnvironment}` || suffix === `environments/${targetEnvironment}/deployment-branch-policies` || /^actions\/(?:runs\/[1-9][0-9]*(?:\/(?:approvals|artifacts))?|artifacts\/[1-9][0-9]*\/zip)$/.test(suffix)), "Endpoint outside read-only authorization safelist");
    let bytes;
    try {
      bytes = runner(executable, ["api", "--hostname", "github.com", endpoint, ...(paginate ? ["--paginate", "--slurp"] : [])], { env: childEnv, encoding: binary ? null : "utf8", maxBuffer: 1024 * 1024, timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] });
    } catch { throw new Error("GitHub authorization read failed"); }
    return binary ? bytes : JSON.parse(bytes);
  };
}

// Normal installation authenticates the publisher's completed run before MFA
// issuance. The broker independently authenticates the durable AWS archive;
// these audit bytes can never replace it. Cleanup does not use this function.
export function authenticatePublishedComponentAuthorization(input, dependencies = {}) {
  return authenticatePublication(input, dependencies);
}

export function authenticateIdentityBootstrapPublication(input, packageEvidence, dependencies = {}) {
  assert(packageEvidence, "Clean-source bootstrap package required");
  return authenticatePublication(input, dependencies, packageEvidence);
}

export function authenticateBootstrapRecoveryPublication(input, packageEvidence, dependencies = {}) {
  assert(packageEvidence, "Clean-source recovery package required");
  return authenticatePublication(input, dependencies, undefined, undefined, packageEvidence);
}

export function authenticateBrokerChangePublication(input, packageEvidence, dependencies = {}) {
  assert(packageEvidence, "Clean-source broker successor package required");
  return authenticatePublication(input, dependencies, undefined, undefined, undefined, packageEvidence);
}

export function authenticateBrokerPolicySuccessorPublication(input, packageEvidence, dependencies = {}) {
  assert(packageEvidence, "Clean-source broker-policy successor package required");
  return authenticatePublication(input, dependencies, undefined, undefined, undefined, undefined, undefined, undefined, packageEvidence);
}

export function authenticateTerraformActivationAuthorization(input, dependencies = {}) {
  assert.deepEqual(Object.keys(input).sort(), ["planSha256", "preparationSha256", "runId", "sourceSha", "transitionId"]);
  const { planSha256, preparationSha256, ...coordinates } = input;
  for (const value of [planSha256, preparationSha256]) assert.match(value || "", /^[a-f0-9]{64}$/);
  return authenticatePublication(coordinates, dependencies, undefined, { sourceSha: input.sourceSha, planSha256, preparationSha256 });
}

export function authenticatePartialActivationRecoveryAuthorization(input, dependencies = {}) {
  assert.deepEqual(Object.keys(input || {}).sort(), ["preparation", "preparationSha256", "runId"]);
  const { preparation, preparationSha256, runId } = input;
  assert.match(preparationSha256 || "", /^[a-f0-9]{64}$/);
  return authenticatePublication({ runId, sourceSha: preparation.sourceSha, transitionId: preparation.recoveryTransitionId }, dependencies, undefined, undefined, undefined, undefined, { preparation, preparationSha256 });
}

// Historical approval evidence is deliberately non-executable: it authenticates
// the incident only and never bypasses the normal current-main/freshness guard.
export function authenticateHistoricalTerraformActivationAuthorization(input, dependencies = {}) {
  assert.deepEqual(Object.keys(input || {}).sort(), ["authorizationArtifactSha256", "planSha256", "preparationSha256", "runId", "sourceSha", "transitionId"]);
  for (const field of ["planSha256", "preparationSha256"]) assert.match(input[field] || "", /^[a-f0-9]{64}$/);
  assert.match(input.authorizationArtifactSha256 || "", /^sha256:[a-f0-9]{64}$/);
  const authorization = authenticatePublication({ runId: input.runId, sourceSha: input.sourceSha, transitionId: input.transitionId }, dependencies, undefined, undefined, undefined, undefined, undefined, { planSha256: input.planSha256, preparationSha256: input.preparationSha256, authorizationArtifactSha256: input.authorizationArtifactSha256 });
  return Object.freeze({ ...authorization, historical: true, executable: false });
}

export function readComponentActivationEnvironments(sourceSha, { execute, env = process.env } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  return ["production-normal-deploy", "production-component-state-bootstrap", "production-component-infrastructure-activation"].map(name => {
    const read = githubReader(execute, env, name);
    protectedMain(read(`repos/${repository}/branches/main`), sourceSha);
    const config = read(`repos/${repository}/environments/${name}`);
    const branches = read(`repos/${repository}/environments/${name}/deployment-branch-policies`);
    assert.equal(config.name, name);
    assert.equal(branches.total_count, 1);
    return { config, branches };
  });
}

export function readPartialActivationRecoveryEnvironment(sourceSha, { execute, env = process.env } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  const read = githubReader(execute, env, partialActivationRecovery.environment);
  protectedMain(read(`repos/${repository}/branches/main`), sourceSha);
  const config = read(`repos/${repository}/environments/${partialActivationRecovery.environment}`);
  const branches = read(`repos/${repository}/environments/${partialActivationRecovery.environment}/deployment-branch-policies`);
  assert.equal(branches.total_count, 1);
  return { config, branches };
}

function authenticatePublication(input, { execute, env = process.env, now = Date.now }, bootstrapPackage, terraformBinding, recoveryPackage, brokerChangePackage, partialActivationPackage, historicalTerraformPackage, brokerPolicySuccessorPackage) {
  const targetEnvironment = brokerPolicySuccessorPackage ? brokerPolicySuccessor.environment : partialActivationPackage ? partialActivationRecovery.environment : brokerChangePackage ? brokerChange.environment : recoveryPackage ? bootstrapRecovery.environment : terraformBinding || historicalTerraformPackage ? "production-component-infrastructure-activation" : bootstrapPackage ? "production-component-installation-identity-bootstrap" : environment;
  const targetWorkflow = brokerPolicySuccessorPackage ? brokerPolicySuccessor.workflow : partialActivationPackage ? partialActivationRecovery.workflow : brokerChangePackage ? brokerChange.workflow : recoveryPackage ? bootstrapRecovery.workflow : terraformBinding || historicalTerraformPackage ? ".github/workflows/authorize-component-infrastructure-activation.yml" : bootstrapPackage ? bootstrapAuthorizationContract.workflow : workflow;
  assert.deepEqual(Object.keys(input).sort(), ["runId", "sourceSha", "transitionId"]);
  coordinates(input);
  const { runId, sourceSha, transitionId } = input;
  assert.match(runId || "", /^[1-9][0-9]*$/);
  const gh = githubReader(execute, env, targetEnvironment);
  const api = (suffix, options) => gh(`repos/${repository}/${suffix}`, options);
  const verifyRun = (run) => {
    assert.equal(String(run.id), runId);
    for (const value of [run.repository, run.head_repository]) {
      assert.equal(value?.full_name, repository);
      assert.equal(value?.id, 1145608538);
    }
    assert.equal(run.path, targetWorkflow);
    assert.equal(run.event, "workflow_dispatch");
    assert.equal(run.head_branch, "main");
    assert.equal(run.head_sha, sourceSha);
    assert.equal(run.run_attempt, 1);
    assert.equal(run.status, "completed");
    assert.equal(run.conclusion, "success");
    user(run.actor); user(run.triggering_actor);
    assert(timestamp(run.created_at) <= now());
    assert(timestamp(run.updated_at) <= now());
    assert(timestamp(run.created_at) <= timestamp(run.updated_at));
  };
  if (!historicalTerraformPackage) protectedMain(api("branches/main"), sourceSha);
  const run = api(`actions/runs/${runId}`);
  verifyRun(run);
  assertSoloEnvironment(api(`environments/${targetEnvironment}`), api(`environments/${targetEnvironment}/deployment-branch-policies`), api(`actions/runs/${runId}/approvals`), targetEnvironment);
  const pages = api(`actions/runs/${runId}/artifacts`, { paginate: true });
  assert(Array.isArray(pages) && pages.length && pages.every(page => Array.isArray(page.artifacts)));
  const artifacts = pages.flatMap(page => page.artifacts);
  assert.equal(artifacts.length, 1);
  const artifact = artifacts[0];
  assert.equal(artifact.name, brokerPolicySuccessorPackage ? brokerPolicySuccessor.artifact : partialActivationPackage ? partialActivationRecovery.artifact : brokerChangePackage ? brokerChange.artifact : recoveryPackage ? bootstrapRecovery.artifact : terraformBinding || historicalTerraformPackage ? "component-infrastructure-authorization" : bootstrapPackage ? bootstrapAuthorizationContract.artifact : "component-installation-authorization-audit");
  assert.equal(artifact.expired, false);
  assert(Number.isSafeInteger(artifact.id) && artifact.id > 0);
  assert(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= 1024 * 1024);
  assert.equal(String(artifact.workflow_run?.id), runId);
  assert.equal(artifact.workflow_run.head_sha, sourceSha);
  assert.equal(artifact.workflow_run.repository_id, 1145608538);
  assert.match(artifact.digest || "", /^sha256:[a-f0-9]{64}$/);
  const bytes = api(`actions/artifacts/${artifact.id}/zip`, { binary: true });
  assert(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 1024 * 1024);
  assert.equal(`sha256:${sha256(bytes)}`, artifact.digest);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "component-publisher-audit-"));
  let audit;
  try {
    const zip = path.join(directory, "audit.zip");
    fs.writeFileSync(zip, bytes, { mode: 0o600, flag: "wx" });
    const unzip = (...args) => execFileSync("/usr/bin/unzip", args, { env: { PATH: "/usr/bin:/bin", LANG: "C" }, encoding: "utf8", timeout: 10000, maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
    const names = brokerPolicySuccessorPackage ? [brokerPolicySuccessor.file] : partialActivationPackage ? [partialActivationRecovery.file] : brokerChangePackage ? [brokerChange.file] : recoveryPackage ? [bootstrapRecovery.file] : terraformBinding || historicalTerraformPackage ? ["authorization.json"] : bootstrapPackage ? [bootstrapAuthorizationContract.file] : ["invocation", "request", "result"].map(name => `component-installation-${name}.json`);
    assert.deepEqual(unzip("-Z1", zip).trim().split("\n").sort(), names);
    const listing = unzip("-Z", "-l", zip).split("\n");
    for (const name of names) {
      const lines = listing.filter(line => line.trim().endsWith(` ${name}`));
      assert.equal(lines.length, 1);
      assert(lines[0].trim().startsWith("-"), "Audit member must be a regular file");
    }
    audit = Object.fromEntries(names.map(name => [name, JSON.parse(unzip("-p", zip, name))]));
  } finally { fs.rmSync(directory, { recursive: true }); }
  let authorization;
  if (brokerPolicySuccessorPackage) authorization = audit[brokerPolicySuccessor.file];
  else if (partialActivationPackage) authorization = audit[partialActivationRecovery.file];
  else if (brokerChangePackage) authorization = audit[brokerChange.file];
  else if (recoveryPackage) authorization = audit[bootstrapRecovery.file];
  else if (terraformBinding || historicalTerraformPackage) authorization = audit["authorization.json"];
  else if (bootstrapPackage) authorization = audit[bootstrapAuthorizationContract.file];
  else {
    const request = audit["component-installation-request.json"];
    assert.deepEqual(Object.keys(request).sort(), ["authorization", "operation"]);
    assert.equal(request.operation, "AUTHORIZE");
    authorization = request.authorization;
  }
  if (brokerPolicySuccessorPackage) {
    const authorizationSha256 = assertBrokerPolicySuccessorAuthorization(authorization, brokerPolicySuccessorPackage, now());
    protectedMain(api("branches/main"), sourceSha);
    const finalRun = api(`actions/runs/${runId}`); verifyRun(finalRun); assert.equal(finalRun.created_at, run.created_at); assert.equal(finalRun.updated_at, run.updated_at);
    return Object.freeze({ ...authorization, authorizationSha256 });
  }
  if (partialActivationPackage) {
    assertPartialActivationRecoveryAuthorization(authorization, partialActivationPackage.preparation, partialActivationPackage.preparationSha256, now());
    protectedMain(api("branches/main"), sourceSha);
    const finalRun = api(`actions/runs/${runId}`); verifyRun(finalRun);
    assert.equal(finalRun.created_at, run.created_at); assert.equal(finalRun.updated_at, run.updated_at);
    return Object.freeze(authorization);
  }
  if (historicalTerraformPackage) {
    assert.equal(artifact.digest, historicalTerraformPackage.authorizationArtifactSha256, "Historical authorization artifact changed");
    assert.deepEqual(authorization, { sourceSha, planSha256: historicalTerraformPackage.planSha256, preparationSha256: historicalTerraformPackage.preparationSha256 }, "Historical saved-plan bindings differ");
    return Object.freeze(authorization);
  }
  if (terraformBinding) {
    assert.deepEqual(authorization, terraformBinding, "Saved-plan approval bindings differ");
    // A successful environment-gated run can complete only after approval.
    // GitHub's authenticated completion timestamp is the effective freshness
    // origin; workflow dispatch time is not approval time.
    assert(now() - timestamp(run.updated_at) < componentIamAuthorization.maxAgeMs, "Saved-plan approval expired");
    protectedMain(api("branches/main"), sourceSha);
    const finalRun = api(`actions/runs/${runId}`); verifyRun(finalRun);
    assert.equal(finalRun.created_at, run.created_at); assert.equal(finalRun.updated_at, run.updated_at);
    return Object.freeze(authorization);
  }
  assert.equal(authorization.runId, runId);
  assert.equal(authorization.transitionId, transitionId);
  assert(timestamp(run.created_at) <= timestamp(authorization.approvalObservedAt));
  assert(timestamp(authorization.approvalObservedAt) <= timestamp(run.updated_at));
  const authorizationSha256 = brokerChangePackage
    ? assertBrokerChangeAuthorization(authorization, brokerChangePackage, now())
    : recoveryPackage
    ? assertBootstrapRecoveryAuthorization(authorization, recoveryPackage, now())
    : bootstrapPackage
    ? assertIdentityBootstrapAuthorization(authorization, bootstrapPackage, now())
    : assertArchivedInstallationAuthorization(authorization, componentBrokerPackageManifest(sourceSha), authorization.brokerPackageSha256, { now: now() });
  if (!bootstrapPackage && !recoveryPackage && !brokerChangePackage) {
    const invocation = audit["component-installation-invocation.json"];
    assert.equal(invocation.StatusCode, 200);
    assert(brokerEntryPointCandidates("AUTHORIZE").includes(invocation.ExecutedVersion), "Unexpected broker authorizer version");
    assert.equal(invocation.FunctionError, undefined);
    assert.deepEqual(audit["component-installation-result.json"], { authorizationSha256 });
  }
  if (!historicalTerraformPackage) protectedMain(api("branches/main"), sourceSha);
  const finalRun = api(`actions/runs/${runId}`);
  verifyRun(finalRun);
  assert.equal(finalRun.created_at, run.created_at);
  assert.equal(finalRun.updated_at, run.updated_at);
  assert(now() < Date.parse(authorization.expiresAt));
  return Object.freeze({ ...authorization, authorizationSha256 });
}
