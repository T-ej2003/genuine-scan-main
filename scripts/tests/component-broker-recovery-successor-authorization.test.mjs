import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import yaml from "js-yaml";
import { approveBrokerRecoverySuccessor, assertBrokerRecoverySuccessorAuthorization, prepareBrokerRecoverySuccessorAuthorization } from "../aws/component-broker-recovery-successor-authorization.mjs";
import { brokerRecoverySuccessor } from "../aws/component-broker-recovery-successor-contract.mjs";
import { assertBrokerRecoverySuccessorEvidenceReaderSource, brokerRecoverySuccessorEvidenceReader } from "../aws/component-broker-recovery-successor-evidence-reader-contract.mjs";
import { brokerPolicySuccessor, brokerPolicySuccessorBindings, brokerPolicySuccessorClosureMetadata } from "../aws/component-broker-policy-successor-contract.mjs";
import { componentBrokerPackageManifest } from "../aws/component-broker-package.mjs";
import { brokerPolicySuccessorEntryPoints, brokerRecoverySuccessorEntryPoints } from "../aws/component-broker-configuration.mjs";
import { digest } from "../aws/component-iam-installation-contract.mjs";
import { identityBootstrap } from "../aws/component-installation-identity-contract.mjs";

function fixture() {
  const sourceSha = "b".repeat(40), historicalSource = "a".repeat(40), now = Date.parse("2026-09-20T12:00:00Z");
  const manifest = componentBrokerPackageManifest(sourceSha), packageEvidence = { bytes: Buffer.from("candidate"), manifest, manifestSha256: digest(manifest), packageSha256: "c".repeat(64) };
  const historicalManifest = componentBrokerPackageManifest(historicalSource), historicalPackage = { manifest: historicalManifest, manifestSha256: digest(historicalManifest), packageSha256: "d".repeat(64) };
  const bindings = brokerPolicySuccessorBindings(historicalPackage), reservation = { schemaVersion: 1, state: "VERIFIED", transitionId: "11111111-1111-4111-8111-111111111111", owner: "22222222-2222-4222-8222-222222222222", authorizationSha256: "e".repeat(64), authorizationExpiresAt: new Date(now + 1000).toISOString(), sessionExpiresAt: new Date(now + 2000).toISOString(), authorizationHistory: [], bindings };
  const runtime = `arn:aws:lambda:eu-west-2::runtime:${"f".repeat(64)}`, metadata = brokerPolicySuccessorClosureMetadata(reservation, bindings, Object.fromEntries(Object.values(brokerPolicySuccessorEntryPoints).map(version => [version, runtime])), '"etag"', new Date(now - 1000).toISOString());
  const actor = { type: "User", login: "T-ej2003", id: 183396573 }, repository = { full_name: "T-ej2003/genuine-scan-main", id: 1145608538 };
  const governance = { sourceSha, transitionId: "33333333-3333-4333-8333-333333333333", runId: "456", now, main: { name: "main", protected: true, commit: { sha: sourceSha } }, run: { id: 456, head_sha: sourceSha, head_branch: "main", path: brokerRecoverySuccessor.workflow, event: "workflow_dispatch", status: "in_progress", run_attempt: 1, repository, head_repository: repository, actor, triggering_actor: actor }, environment: { id: 97, name: brokerRecoverySuccessor.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] }, branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] }, approvals: [{ state: "approved", user: actor, environments: [{ id: 97, name: brokerRecoverySuccessor.environment }] }] };
  const f = { ...governance, packageEvidence, reservation, reservationEtag: '"etag"', metadata, reads: [] };
  f.readEvidence = async key => { f.reads.push(key); if (key === brokerPolicySuccessor.reservationKey) return { value: f.reservation, etag: f.reservationEtag }; if (key === `${identityBootstrap.prefix}identity-bootstrap.json`) return { value: { state: "BOOTSTRAP_CLOSED" }, metadata: f.metadata }; throw new Error("unexpected key"); };
  return f;
}

test("prepare reads only immutable lineage and deterministically authorizes exact 7/8/9 to 10/11/12", async () => {
  const f = fixture(), one = await prepareBrokerRecoverySuccessorAuthorization(f), two = await prepareBrokerRecoverySuccessorAuthorization({ ...f, reads: [] });
  assert.deepEqual(one.approval, two.approval); assert.equal(assertBrokerRecoverySuccessorAuthorization(one.approval, f.packageEvidence, one.lineage.closure, f.now), digest(one.approval));
  assert.deepEqual(one.approval.predecessor.entryPoints, brokerPolicySuccessorEntryPoints); assert.deepEqual(one.approval.successor.entryPoints, brokerRecoverySuccessorEntryPoints);
  assert.deepEqual(f.reads, [brokerPolicySuccessor.reservationKey, `${identityBootstrap.prefix}identity-bootstrap.json`, brokerPolicySuccessor.reservationKey, `${identityBootstrap.prefix}identity-bootstrap.json`]);
});

test("prepare fails closed for substituted historical, candidate, governance, and transition evidence", async () => {
  const mutations = [
    f => { f.reservation = null; },
    f => { f.reservation.schemaVersion = 2; },
    f => { f.reservation.state = "EXECUTING"; },
    f => { f.reservation.transitionId = "44444444-4444-4444-8444-444444444444"; },
    f => { f.reservation.authorizationSha256 = "0".repeat(64); },
    f => { f.reservationEtag = '"substituted"'; },
    f => { f.reservation.bindings.successor.sourceSha = "0".repeat(40); },
    f => { f.metadata = {}; },
    f => { f.metadata = { "broker-policy-successor": Buffer.from("{}").toString("base64url") }; },
    f => { const closure = JSON.parse(Buffer.from(f.metadata["broker-policy-successor"], "base64url")); closure.runtimeVersions = { 7: closure.runtimeVersions[7], 8: closure.runtimeVersions[8], 10: closure.runtimeVersions[9] }; f.metadata = { "broker-policy-successor": Buffer.from(JSON.stringify(closure)).toString("base64url") }; },
    f => { f.packageEvidence.manifest = { ...f.packageEvidence.manifest, sourceSha: "0".repeat(40) }; f.packageEvidence.manifestSha256 = digest(f.packageEvidence.manifest); },
    f => { f.run.actor.id = 1; },
    f => { f.environment.protection_rules[0].reviewers[0].reviewer.id = 1; },
    f => { f.approvals = []; },
    f => { f.transitionId = "not-a-uuid"; },
  ];
  for (const mutate of mutations) { const f = fixture(); mutate(f); await assert.rejects(prepareBrokerRecoverySuccessorAuthorization(f)); }
});

test("authorization rejects stale, future-generation and first-closure substitutions", async () => {
  const f = fixture(), { approval, lineage } = await prepareBrokerRecoverySuccessorAuthorization(f);
  assert.throws(() => assertBrokerRecoverySuccessorAuthorization(approval, f.packageEvidence, lineage.closure, Date.parse(approval.expiresAt)), /expired/);
  for (const mutate of [
    value => { value.successor.entryPoints = { INSTALL: "13", CLEANUP: "14", AUTHORIZE: "15" }; },
    value => { value.firstClosure.transitionId = "44444444-4444-4444-8444-444444444444"; },
  ]) { const changed = structuredClone(approval); mutate(changed); assert.throws(() => assertBrokerRecoverySuccessorAuthorization(changed, f.packageEvidence, lineage.closure, f.now)); }
});

test("evidence reader and workflow are exact, read-only, OIDC-bound contracts", () => {
  const { trust, permissions } = assertBrokerRecoverySuccessorEvidenceReaderSource();
  assert.deepEqual(permissions.Statement[0].Action, "s3:GetObject"); assert.deepEqual(permissions.Statement[0].Resource, brokerRecoverySuccessorEvidenceReader.resources);
  assert(!JSON.stringify(permissions).match(/PutObject|DeleteObject|ListBucket|lambda:|dynamodb:|iam:|sts:AssumeRole"/));
  const conditions = trust.Statement[0].Condition.StringEquals; assert.equal(conditions["token.actions.githubusercontent.com:repository_id"], "1145608538"); assert.equal(conditions["token.actions.githubusercontent.com:ref"], "refs/heads/main");
  const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/authorize-component-broker-recovery-successor.yml", import.meta.url), "utf8"));
  assert.deepEqual(workflow.permissions, { contents: "read", actions: "read", "id-token": "write" }); assert.equal(workflow.jobs.authorize.environment, brokerRecoverySuccessorEvidenceReader.environment);
  assert.equal(workflow.jobs.authorize.steps.filter(step => step.uses === "aws-actions/configure-aws-credentials@v6")[0].with["role-to-assume"], brokerRecoverySuccessorEvidenceReader.roleArn);
  assert(!JSON.stringify(workflow).includes("PutObject"));
});
