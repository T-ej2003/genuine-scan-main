import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildComponentBrokerPackage, componentBrokerPackageManifest } from "./component-broker-package.mjs";
import { brokerPolicySuccessor, brokerPolicySuccessorBindings, brokerPolicySuccessorCapabilitySet } from "./component-broker-policy-successor-contract.mjs";
import { digest } from "./component-iam-installation-contract.mjs";
import { createProductionGithubCredentialEnvironment } from "./production-credential-source-contract.mjs";

const actor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function environment(config, branches, approvals) {
  assert.equal(config.name, brokerPolicySuccessor.environment); assert(Number.isSafeInteger(config.id) && config.id > 0); assert.equal(config.can_admins_bypass, false);
  assert.deepEqual(config.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.equal(branches.total_count, 1); assert.deepEqual(branches.branch_policies.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]);
  const rules = config.protection_rules.filter(({ type }) => type === "required_reviewers");
  assert.equal(rules.length, 1); assert.equal(rules[0].prevent_self_review, false);
  assert.deepEqual(rules[0].reviewers.map(({ type, reviewer }) => ({ type, reviewer: { type: reviewer?.type, login: reviewer?.login, id: reviewer?.id } })), [{ type: "User", reviewer: actor }]);
  assert.deepEqual(approvals.map(({ state, user, environments }) => ({ state, user: { type: user?.type, login: user?.login, id: user?.id }, environments: environments.map(({ id, name }) => ({ id, name })) })),
    [{ state: "approved", user: actor, environments: [{ id: config.id, name: brokerPolicySuccessor.environment }] }]);
}

export function brokerPolicySuccessorSourceBindings(packageEvidence) {
  assert.equal(packageEvidence.manifestSha256, digest(packageEvidence.manifest));
  assert.equal(packageEvidence.manifestSha256, digest(componentBrokerPackageManifest(packageEvidence.manifest.sourceSha)));
  return { ...brokerPolicySuccessorBindings(packageEvidence), capabilitySetSha256: digest(brokerPolicySuccessorCapabilitySet()) };
}

export function approveBrokerPolicySuccessor({ sourceSha, transitionId, runId, main, run, environment: config, branches, approvals, packageEvidence, now }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(transitionId || "", uuid); assert.match(runId || "", /^[1-9][0-9]*$/); assert(Number.isFinite(now));
  assert.deepEqual({ name: main.name, protected: main.protected, sha: main.commit?.sha }, { name: "main", protected: true, sha: sourceSha });
  assert.equal(run.head_sha, sourceSha); assert.equal(run.head_branch, "main"); assert.equal(run.path, brokerPolicySuccessor.workflow); assert.equal(run.event, "workflow_dispatch"); assert.equal(run.status, "in_progress"); assert.equal(run.run_attempt, 1); assert.equal(String(run.id), runId);
  for (const repo of [run.repository, run.head_repository]) assert.deepEqual({ id: repo?.id, full_name: repo?.full_name }, { id: 1145608538, full_name: "T-ej2003/genuine-scan-main" });
  for (const value of [run.actor, run.triggering_actor]) assert.deepEqual({ type: value?.type, login: value?.login, id: value?.id }, actor);
  environment(config, branches, approvals);
  const bindings = brokerPolicySuccessorSourceBindings(packageEvidence); assert.equal(bindings.successor.sourceSha, sourceSha);
  return { schemaVersion: 1, transitionType: brokerPolicySuccessor.transitionType, account: "368992683803", region: "eu-west-2", ...bindings,
    transitionId, runId, environment: brokerPolicySuccessor.environment, operator: actor, reviewer: actor,
    approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + brokerPolicySuccessor.maxAgeMs).toISOString() };
}

export function assertBrokerPolicySuccessorAuthorization(value, packageEvidence, now) {
  const expected = { schemaVersion: 1, transitionType: brokerPolicySuccessor.transitionType, account: "368992683803", region: "eu-west-2", ...brokerPolicySuccessorSourceBindings(packageEvidence),
    transitionId: value.transitionId, runId: value.runId, environment: brokerPolicySuccessor.environment, operator: actor, reviewer: actor,
    approvalObservedAt: value.approvalObservedAt, expiresAt: value.expiresAt };
  assert.deepEqual(value, expected, "Broker-policy successor authorization bindings differ"); assert.match(value.transitionId || "", uuid); assert.match(value.runId || "", /^[1-9][0-9]*$/);
  const approved = Date.parse(value.approvalObservedAt), expires = Date.parse(value.expiresAt);
  assert.equal(new Date(approved).toISOString(), value.approvalObservedAt); assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(Number.isFinite(now) && approved <= now && now < expires && expires - approved === brokerPolicySuccessor.maxAgeMs, "Broker-policy successor authorization expired or invalid");
  return digest(value);
}

async function prepare() {
  assert.deepEqual(process.argv.slice(2), ["prepare"]);
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, SOURCE_SHA, TRANSITION_ID, RUNNER_TEMP } = process.env;
  assert.equal(GITHUB_REPOSITORY, "T-ej2003/genuine-scan-main"); assert.equal(GITHUB_REF, "refs/heads/main"); assert.equal(GITHUB_RUN_ATTEMPT, "1"); assert.equal(SOURCE_SHA, GITHUB_SHA); assert(path.isAbsolute(RUNNER_TEMP || ""));
  const gh = suffix => JSON.parse(execFileSync("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/T-ej2003/genuine-scan-main/${suffix}`], { env: { ...createProductionGithubCredentialEnvironment(), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }));
  const packageEvidence = await buildComponentBrokerPackage(), environmentPath = `environments/${brokerPolicySuccessor.environment}`;
  const approval = approveBrokerPolicySuccessor({ sourceSha: SOURCE_SHA, transitionId: TRANSITION_ID, runId: GITHUB_RUN_ID, main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`),
    environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`), approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`), packageEvidence, now: Date.now() });
  assert.equal(gh("branches/main").commit.sha, SOURCE_SHA); fs.writeFileSync(path.join(RUNNER_TEMP, brokerPolicySuccessor.file), JSON.stringify(approval), { flag: "wx", mode: 0o600 });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) prepare().catch(() => { process.stderr.write("Component broker-policy successor approval rejected.\n"); process.exitCode = 1; });
