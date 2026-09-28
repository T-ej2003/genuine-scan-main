import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildComponentBrokerPackage } from "./component-broker-package.mjs";
import { digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { brokerSignerSuccessor, brokerSignerSuccessorBindings, brokerSignerSuccessorCapabilitySet } from "./component-broker-signer-successor-contract.mjs";
import { assertBrokerRecoverySuccessorClosureMetadata, authenticateSecondSuccessorReservation, brokerRecoverySuccessor } from "./component-broker-recovery-successor-contract.mjs";
import { identityBootstrap } from "./component-installation-identity-contract.mjs";
import { createProductionAwsCredentialEnvironment, createProductionGithubCredentialEnvironment, productionAwsExecutable, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const actor = Object.freeze({ type: "User", login: "T-ej2003", id: 183396573 });
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function assertEnvironment(config, branches, approvals) {
  assert.equal(config.name, brokerSignerSuccessor.environment); assert(Number.isSafeInteger(config.id) && config.id > 0); assert.equal(config.can_admins_bypass, false);
  assert.deepEqual(config.deployment_branch_policy, { protected_branches: false, custom_branch_policies: true });
  assert.deepEqual(branches.branch_policies?.map(({ name, type }) => ({ name, type })), [{ name: "main", type: "branch" }]); assert.equal(branches.total_count, 1);
  const rules = config.protection_rules.filter(({ type }) => type === "required_reviewers"); assert.equal(rules.length, 1); assert.equal(rules[0].prevent_self_review, false);
  assert.deepEqual(rules[0].reviewers.map(({ type, reviewer }) => ({ type, reviewer: { type: reviewer?.type, login: reviewer?.login, id: reviewer?.id } })), [{ type: "User", reviewer: actor }]);
  assert.deepEqual(approvals.map(({ state, user, environments }) => ({ state, user: { type: user?.type, login: user?.login, id: user?.id }, environments: environments.map(({ id, name }) => ({ id, name })) })), [{ state: "approved", user: actor, environments: [{ id: config.id, name: brokerSignerSuccessor.environment }] }]);
}

export function authenticateSecondSuccessorLineage({ reservation, reservationEtag, metadata, bootstrap }) {
  const encoded = metadata?.[brokerRecoverySuccessor.metadataKey];
  assert(typeof encoded === "string" && encoded, "Second successor closure missing");
  const closure = bootstrap?.brokerRecoverySuccessorClosure;
  assert.equal(encoded, digest(closure), "Second successor body and metadata differ");
  const bindings = authenticateSecondSuccessorReservation(reservation, closure, reservationEtag);
  assert.deepEqual(Object.keys(metadata).sort(), ["broker-policy-successor", brokerRecoverySuccessor.metadataKey, ...(Object.hasOwn(metadata, "broker-signer-successor") ? ["broker-signer-successor"] : [])].sort());
  assertBrokerRecoverySuccessorClosureMetadata({ "broker-policy-successor": metadata["broker-policy-successor"], [brokerRecoverySuccessor.metadataKey]: encoded }, bindings, reservation, reservationEtag, bootstrap);
  assert.deepEqual(Object.keys(closure.runtimeVersions || {}).sort(), ["10", "11", "12"]);
  return Object.freeze({ reservation: Object.freeze(structuredClone(reservation)), closure: Object.freeze(structuredClone(closure)), bindings });
}

export function brokerSignerSuccessorSourceBindings(packageEvidence, secondClosure) {
  const bindings = brokerSignerSuccessorBindings(packageEvidence, secondClosure);
  return Object.freeze({ ...bindings, capabilitySetSha256: digest(brokerSignerSuccessorCapabilitySet()) });
}

export function approveBrokerSignerSuccessor({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, packageEvidence, secondClosure, now }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(transitionId || "", uuid); assert.match(runId || "", /^[1-9][0-9]*$/); assert(Number.isFinite(now));
  assert.deepEqual({ name: main?.name, protected: main?.protected, sha: main?.commit?.sha }, { name: "main", protected: true, sha: sourceSha });
  assert.equal(run?.head_sha, sourceSha); assert.equal(run?.head_branch, "main"); assert.equal(run?.path, brokerSignerSuccessor.workflow); assert.equal(run?.event, "workflow_dispatch"); assert.equal(run?.status, "in_progress"); assert.equal(run?.run_attempt, 1); assert.equal(String(run?.id), runId);
  for (const repository of [run?.repository, run?.head_repository]) assert.deepEqual({ id: repository?.id, full_name: repository?.full_name }, { id: 1145608538, full_name: installationIdentity.repository });
  for (const value of [run?.actor, run?.triggering_actor]) assert.deepEqual({ type: value?.type, login: value?.login, id: value?.id }, actor);
  assertEnvironment(environment, branches, approvals);
  const bindings = brokerSignerSuccessorSourceBindings(packageEvidence, secondClosure);
  assert.equal(bindings.successor.sourceSha, sourceSha);
  return Object.freeze({ schemaVersion: 1, transitionType: brokerSignerSuccessor.transitionType, account: "368992683803", region: "eu-west-2", ...bindings, transitionId, runId, environment: brokerSignerSuccessor.environment, operator: actor, reviewer: actor, approvalObservedAt: new Date(now).toISOString(), expiresAt: new Date(now + brokerSignerSuccessor.maxAgeMs).toISOString() });
}

export function assertBrokerSignerSuccessorAuthorization(value, packageEvidence, secondClosure, now) {
  const bindings = brokerSignerSuccessorSourceBindings(packageEvidence, secondClosure);
  const expected = { schemaVersion: 1, transitionType: brokerSignerSuccessor.transitionType, account: "368992683803", region: "eu-west-2", ...bindings,
    transitionId: value?.transitionId, runId: value?.runId, environment: brokerSignerSuccessor.environment, operator: actor, reviewer: actor,
    approvalObservedAt: value?.approvalObservedAt, expiresAt: value?.expiresAt };
  assert.deepEqual(value, expected, "Second successor authorization bindings differ");
  assert.match(value.transitionId || "", uuid); assert.match(value.runId || "", /^[1-9][0-9]*$/);
  const approved = Date.parse(value.approvalObservedAt), expires = Date.parse(value.expiresAt); assert.equal(new Date(approved).toISOString(), value.approvalObservedAt); assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(Number.isFinite(now) && approved <= now && now < expires && expires - approved === brokerSignerSuccessor.maxAgeMs, "Second successor authorization expired");
  return digest(value);
}

export async function prepareBrokerSignerSuccessorAuthorization({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, readEvidence, packageEvidence, now }) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(transitionId || "", uuid); assert.match(runId || "", /^[1-9][0-9]*$/);
  const candidate = packageEvidence || await buildComponentBrokerPackage(); assert.equal(candidate.manifest.sourceSha, sourceSha, "Candidate package source differs");
  const [reservation, bootstrap] = await Promise.all([readEvidence(brokerRecoverySuccessor.reservationKey), readEvidence(`${identityBootstrap.prefix}identity-bootstrap.json`)]);
  const lineage = authenticateSecondSuccessorLineage({ reservation: reservation.value, reservationEtag: reservation.etag, metadata: bootstrap.metadata, bootstrap: bootstrap.value });
  const approval = approveBrokerSignerSuccessor({ sourceSha, transitionId, runId, main, run, environment, branches, approvals, packageEvidence: candidate, secondClosure: lineage.closure, now });
  assertBrokerSignerSuccessorAuthorization(approval, candidate, lineage.closure, now);
  return Object.freeze({ approval, lineage });
}

function githubApi(suffix, exec = execFileSync, env = process.env) {
  return JSON.parse(exec("/usr/bin/gh", ["api", "--hostname", "github.com", `repos/${installationIdentity.repository}/${suffix}`], { env: { ...createProductionGithubCredentialEnvironment({ env }), GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }));
}

function createEvidenceReader({ exec = execFileSync, env = process.env } = {}) {
  const allowed = new Set([brokerRecoverySuccessor.reservationKey, `${identityBootstrap.prefix}identity-bootstrap.json`]);
  const commandEnv = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_BROKER_SIGNER_SUCCESSOR_EVIDENCE, env });
  const aws = productionAwsExecutable();
  return async key => {
    assert(allowed.has(key), "Historical evidence key is outside the exact read contract");
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-broker-signer-successor-evidence-"));
    fs.chmodSync(directory, 0o700);
    const bodyPath = path.join(directory, "body.json");
    try {
      const response = JSON.parse(exec(aws, ["s3api", "get-object", "--bucket", identityBootstrap.bucket, "--key", key, "--region", "eu-west-2", "--output", "json", "--no-cli-pager", bodyPath], { env: commandEnv, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 30000 }));
      const bytes = fs.readFileSync(bodyPath);
      assert(bytes.length > 0 && bytes.length <= 1024 * 1024, "Historical evidence body size is invalid");
      return Object.freeze({ value: JSON.parse(bytes), metadata: Object.freeze({ ...(response.Metadata || {}) }), etag: response.ETag, versionId: response.VersionId });
    } finally {
      fs.rmSync(directory, { recursive: true });
    }
  };
}

export async function runBrokerSignerSuccessorAuthorizationPrepare({ env = process.env, exec = execFileSync, readEvidence, packageEvidence, now = Date.now() } = {}) {
  assert.deepEqual(process.argv.slice(2), ["prepare"]);
  const { GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT, SOURCE_SHA, TRANSITION_ID, RUNNER_TEMP } = env;
  assert.equal(GITHUB_REPOSITORY, installationIdentity.repository); assert.equal(GITHUB_REF, "refs/heads/main"); assert.equal(GITHUB_RUN_ATTEMPT, "1"); assert.equal(SOURCE_SHA, GITHUB_SHA); assert(path.isAbsolute(RUNNER_TEMP || ""));
  const gh = suffix => githubApi(suffix, exec, env), environmentPath = `environments/${brokerSignerSuccessor.environment}`;
  const result = await prepareBrokerSignerSuccessorAuthorization({ sourceSha: SOURCE_SHA, transitionId: TRANSITION_ID, runId: GITHUB_RUN_ID,
    main: gh("branches/main"), run: gh(`actions/runs/${GITHUB_RUN_ID}`), environment: gh(environmentPath), branches: gh(`${environmentPath}/deployment-branch-policies`), approvals: gh(`actions/runs/${GITHUB_RUN_ID}/approvals`),
    readEvidence: readEvidence || createEvidenceReader({ exec, env }), packageEvidence, now });
  assert.equal(gh("branches/main").commit.sha, SOURCE_SHA);
  const output = path.join(RUNNER_TEMP, brokerSignerSuccessor.file);
  fs.writeFileSync(output, JSON.stringify(result.approval), { flag: "wx", mode: 0o600 });
  return Object.freeze({ output, authorizationSha256: digest(result.approval) });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) runBrokerSignerSuccessorAuthorizationPrepare().catch(() => { process.stderr.write("Component broker signer successor approval rejected.\n"); process.exitCode = 1; });
