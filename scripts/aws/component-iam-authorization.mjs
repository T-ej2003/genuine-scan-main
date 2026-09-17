import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";
import { documentBindings, digest, installationCapabilitySet } from "./component-iam-installation-contract.mjs";

// Authorization only: no AWS, dispatch, consumption, or installation. The caller
// must run trusted protected-main code and consume the transition once before writes.
// authenticateComponentIamAuthorization({runId, sourceSha, transitionId}) always
// reads GitHub; there is deliberately no local authorization-file or CLI override.
export const componentIamAuthorization = Object.freeze({
  repository: "T-ej2003/genuine-scan-main", account: "368992683803", region: "eu-west-2",
  environment: "production-component-infrastructure-install-permission",
  workflow: ".github/workflows/authorize-component-iam-installation.yml",
  artifact: "component-iam-installation-authorization", maxAgeMs: 30 * 60 * 1000,
});
const { repository, environment, workflow, artifact: artifactName, maxAgeMs } = componentIamAuthorization;
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const fields = ["runId", "sourceSha", "transitionId", "documentBindingsSha256", "capabilitySetSha256", "expiresAt"];
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

// Pure artifact builder, not proof of permission. createdAt must come from the
// authenticated GitHub run, never workflow input. Both hashes are source-owned.
export function createComponentIamAuthorization({ runId, sourceSha, transitionId, createdAt }, now = Date.now()) {
  assert.match(String(runId || ""), /^[1-9][0-9]*$/, "Invalid run ID");
  coordinates({ sourceSha, transitionId });
  const created = timestamp(createdAt);
  assert(Number.isFinite(now) && created <= now && now < created + maxAgeMs, "Authorization expired or future-dated");
  return Object.freeze({ runId: String(runId), sourceSha, transitionId, documentBindingsSha256: digest(documentBindings()), capabilitySetSha256: digest(installationCapabilitySet()), expiresAt: new Date(created + maxAgeMs).toISOString() });
}

export function assertComponentIamEnvironment(config, branches, approvals) {
  assert.equal(config.name, environment);
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
  assert.deepEqual(approvals[0].environments.map(({ id, name }) => ({ id, name })), [{ id: config.id, name: environment }]);
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

function githubReader(execute, env) {
  const childEnv = { ...createProductionGithubCredentialEnvironment({ env }), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" };
  const executable = execute ? "gh" : githubExecutable();
  const runner = execute || execFileSync;
  return (endpoint, { binary = false, paginate = false } = {}) => {
    const prefix = `repos/${repository}/`;
    const suffix = endpoint.slice(prefix.length);
    assert(endpoint.startsWith(prefix) && (suffix === "branches/main" || /^compare\/[a-f0-9]{40}\.\.\.[a-f0-9]{40}$/.test(suffix) || suffix === `environments/${environment}` || suffix === `environments/${environment}/deployment-branch-policies` || /^actions\/(?:runs\/[1-9][0-9]*(?:\/(?:approvals|artifacts))?|artifacts\/[1-9][0-9]*\/zip)$/.test(suffix)), "Endpoint outside read-only authorization safelist");
    let bytes;
    try {
      bytes = runner(executable, ["api", "--hostname", "github.com", endpoint, ...(paginate ? ["--paginate", "--slurp"] : [])], { env: childEnv, encoding: binary ? null : "utf8", maxBuffer: 1024 * 1024, timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] });
    } catch { throw new Error("GitHub authorization read failed"); }
    return binary ? bytes : JSON.parse(bytes);
  };
}

/** Authenticate a successful first-attempt run and download its bound artifact.
 * Second argument is for in-process tests only; there is no generic public CLI.
 * Returns runId, actor, environmentId, expiry and canonical authorizationSha256.
 * The caller must independently reserve transitionId exactly once before AWS.
 */
export function authenticateComponentIamAuthorization(input, deps = {}) {
  return authenticate(input, deps, "INSTALL");
}

/** Cleanup-only evidence. expectedAuthorizationSha256 MUST come from the immutable
 * trusted AWS ledger, never an operator file or CLI argument. This helper performs
 * no AWS reads; the root closer must validate that ledger and its exact resource
 * identities/policy hashes. It must never use this result to install or grant IAM.
 * Original capabilities are ledger-bound, not recomputed from newer source.
 */
export function authenticateComponentIamClosureAuthorization(input, deps = {}) {
  assert.match(input.expectedAuthorizationSha256 || "", /^[a-f0-9]{64}$/, "Trusted ledger authorization hash required");
  return authenticate(input, deps, "CLEANUP");
}

function authenticate({ runId, sourceSha, transitionId, expectedAuthorizationSha256 }, { execute, now = Date.now, env = process.env }, purpose) {
  coordinates({ sourceSha, transitionId });
  assert.match(String(runId || ""), /^[1-9][0-9]*$/, "Invalid run ID");
  const gh = githubReader(execute, env);
  const api = (suffix, options) => gh(`repos/${repository}/${suffix}`, options);
  const verifySource = () => {
    const branch = api("branches/main");
    protectedMain(branch, purpose === "INSTALL" ? sourceSha : branch.commit?.sha);
    if (purpose === "CLEANUP") {
      assert.match(branch.commit.sha, /^[a-f0-9]{40}$/);
      const comparison = api(`compare/${sourceSha}...${branch.commit.sha}`);
      assert(["ahead", "identical"].includes(comparison.status), "Original source is not a main ancestor");
      assert.equal(comparison.base_commit?.sha, sourceSha);
      assert.equal(comparison.merge_base_commit?.sha, sourceSha, "Original source diverged from main");
    }
  };
  verifySource();
  const run = api(`actions/runs/${runId}`);
  const verifyRun = (value) => {
    assert.equal(String(value.id), String(runId));
    assert.equal(value.repository?.full_name, repository);
    assert.equal(value.head_repository?.full_name, repository);
    assert(Number.isSafeInteger(value.repository.id) && value.repository.id > 0);
    assert.equal(value.head_repository.id, value.repository.id);
    assert.equal(value.path, workflow);
    assert.equal(value.event, "workflow_dispatch");
    assert.equal(value.head_branch, "main");
    assert.equal(value.head_sha, sourceSha);
    assert.equal(value.status, "completed");
    assert.equal(value.conclusion, "success");
    assert.equal(value.run_attempt, 1, "Rerun authorization forbidden");
    user(value.actor);
    user(value.triggering_actor);
    const created = timestamp(value.created_at);
    const time = now();
    assert(Number.isFinite(time) && created <= time, "Future-dated run");
    if (purpose === "INSTALL") assert(time < created + maxAgeMs, "Authorization expired");
  };
  verifyRun(run);
  const config = api(`environments/${environment}`);
  const environmentId = assertComponentIamEnvironment(config, api(`environments/${environment}/deployment-branch-policies`), api(`actions/runs/${runId}/approvals`));
  const pages = api(`actions/runs/${runId}/artifacts`, { paginate: true });
  assert(Array.isArray(pages) && pages.length > 0 && pages.every((page) => Array.isArray(page.artifacts)), "Malformed artifact listing");
  const artifacts = pages.flatMap((page) => page.artifacts);
  assert.equal(artifacts.length, 1, "Exactly one artifact required");
  const artifact = artifacts[0];
  assert.equal(artifact.name, artifactName);
  assert.equal(artifact.expired, false);
  assert(Number.isSafeInteger(artifact.id) && artifact.id > 0);
  assert(Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0 && artifact.size_in_bytes <= 1024 * 1024);
  assert.equal(String(artifact.workflow_run?.id), String(runId));
  assert.equal(artifact.workflow_run?.head_sha, sourceSha);
  assert.equal(artifact.workflow_run?.repository_id, run.repository.id);
  assert.match(artifact.digest || "", /^sha256:[a-f0-9]{64}$/);
  const archive = api(`actions/artifacts/${artifact.id}/zip`, { binary: true });
  assert(Buffer.isBuffer(archive) && archive.length > 0 && archive.length <= 1024 * 1024, "Invalid authorization archive");
  assert.equal(`sha256:${sha256(archive)}`, artifact.digest, "Artifact digest mismatch");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "component-iam-authorization-"));
  let authorization;
  try {
    const file = path.join(directory, "authorization.zip");
    fs.writeFileSync(file, archive, { flag: "wx", mode: 0o600 });
    const unzip = (...args) => execFileSync("/usr/bin/unzip", args, { encoding: "utf8", maxBuffer: 64 * 1024, timeout: 10_000, env: { PATH: "/usr/bin:/bin", LANG: "C" }, stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(unzip("-Z1", file).trim(), "authorization.json", "Unexpected archive entries");
    const listing = unzip("-Z", "-l", file).split("\n").filter((line) => line.trim().endsWith(" authorization.json"));
    assert.equal(listing.length, 1);
    assert(listing[0].trim().startsWith("-"), "Authorization must be a regular file");
    authorization = JSON.parse(unzip("-p", file, "authorization.json"));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  assert(authorization && typeof authorization === "object" && !Array.isArray(authorization));
  assert.deepEqual(Object.keys(authorization).sort(), [...fields].sort(), "Unexpected authorization fields");
  if (purpose === "INSTALL") {
    const expected = createComponentIamAuthorization({ runId, sourceSha, transitionId, createdAt: run.created_at }, now());
    assert.deepEqual(authorization, expected, "Authorization bindings mismatch");
  } else {
    assert.equal(authorization.runId, String(runId));
    assert.equal(authorization.sourceSha, sourceSha);
    assert.equal(authorization.transitionId, transitionId);
    assert.match(authorization.documentBindingsSha256 || "", /^[a-f0-9]{64}$/);
    assert.match(authorization.capabilitySetSha256 || "", /^[a-f0-9]{64}$/);
    assert.equal(authorization.expiresAt, new Date(timestamp(run.created_at) + maxAgeMs).toISOString());
    assert.equal(digest(authorization), expectedAuthorizationSha256, "Trusted ledger authorization hash mismatch");
  }
  // Recheck source and run after transport: installation requires current main;
  // closure requires ancestry. No cached/local bytes substitute for this read.
  verifySource();
  const finalRun = api(`actions/runs/${runId}`);
  verifyRun(finalRun);
  assert.equal(finalRun.created_at, run.created_at);
  return Object.freeze({ ...authorization, purpose, runId: String(runId), actor: Object.freeze({ login: run.actor.login, id: run.actor.id }), environmentId, authorizationSha256: digest(authorization) });
}
