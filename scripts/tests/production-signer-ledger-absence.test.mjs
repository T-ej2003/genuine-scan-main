import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PRODUCTION_ENVIRONMENT_APPROVAL, createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { createSignerLedgerAbsenceAuthorization, assertSignerLedgerAbsenceAuthorization, resolveSignerLedgerAbsenceAuthorization } from "../aws/production-signer-ledger-absence-authorization.mjs";
import { classifySignerLedgerBucketPolicy, signerLedgerAbsence, signerLedgerBucketPolicyPredecessor, signerLedgerBucketPolicySuccessor } from "../aws/production-signer-ledger-absence-policy.mjs";
import { reconcileSignerLedgerAbsence, runSignerLedgerAbsenceCli } from "../aws/production-signer-ledger-absence-reconciliation.mjs";
import { brokerSignerSuccessorManagedIdentities } from "../aws/component-installation-identity-contract.mjs";

const sourceSha = "a".repeat(40);
const approval = () => createProductionEnvironmentApprovalEvidence({ repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository, environment: "production", sourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.signerLedgerAbsenceWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "42", workflowRunAttempt: "1", executionActor: "operator",
  observedAt: new Date().toISOString(), environmentConfig: { id: 17, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "operator" } }] }] },
  actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "operator" } });

test("exact state-bucket successor adds only a signer-ledger-key ListBucket grant", () => {
  const before = signerLedgerBucketPolicyPredecessor(), after = signerLedgerBucketPolicySuccessor();
  assert.equal(classifySignerLedgerBucketPolicy(before), "EXACT_PREDECESSOR");
  assert.equal(classifySignerLedgerBucketPolicy(after), "EXACT_SUCCESSOR");
  assert.deepEqual(after.Statement.slice(0, -1), before.Statement);
  const added = after.Statement.at(-1);
  assert.deepEqual(added, { Sid: "AllowComponentBrokerListExactSignerLedger", Effect: "Allow", Principal: { AWS: signerLedgerAbsence.principal }, Action: "s3:ListBucket",
    Resource: `arn:aws:s3:::${signerLedgerAbsence.bucket}`, Condition: { StringEquals: { "s3:prefix": signerLedgerAbsence.key } } });
  const permits = ({ principal, action, resource, prefix }) => principal === added.Principal.AWS && action === added.Action && resource === added.Resource && prefix === added.Condition.StringEquals["s3:prefix"];
  assert(permits({ principal: signerLedgerAbsence.principal, action: "s3:ListBucket", resource: added.Resource, prefix: signerLedgerAbsence.key }));
  for (const value of [
    { prefix: "mscqr/production/component-deployment-state/ordinary.json" },
    { prefix: "mscqr/production/component-deployment-state/" },
    { prefix: `${signerLedgerAbsence.key}/extra` },
    { principal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer" },
    { action: "s3:ListBucketVersions" },
    { resource: "arn:aws:s3:::unrelated-bucket" },
  ]) assert.equal(permits({ principal: signerLedgerAbsence.principal, action: "s3:ListBucket", resource: added.Resource, prefix: signerLedgerAbsence.key, ...value }), false);
  for (const altered of [
    { ...after, Statement: [...after.Statement, { Effect: "Allow", Action: "s3:*", Resource: "*" }] },
    { ...after, Statement: [...after.Statement.slice(0, -1), { ...added, Condition: { StringLike: { "s3:prefix": "mscqr/production/*" } } }] },
    { ...before, Statement: before.Statement.slice(1) },
  ]) assert.throws(() => classifySignerLedgerBucketPolicy(altered), /differs/);
  const broker = brokerSignerSuccessorManagedIdentities().find(({ role }) => role === "mscqr-production-component-iam-provisioner");
  assert(broker);
  assert(!broker.policy.Statement.find(({ Action }) => Action === "s3:ListBucket").Condition.StringEquals["s3:prefix"].includes(signerLedgerAbsence.key), "Closed 13/14/15 identity policy must remain unchanged");
});

test("protected approval and exact policy hashes bind the fixed successor", () => {
  const valid = createSignerLedgerAbsenceAuthorization({ sourceSha, approval: approval() });
  assert.equal(assertSignerLedgerAbsenceAuthorization(valid, { sourceSha }), valid);
  for (const changed of [{ sourceSha: "b".repeat(40) }, { key: "other" }, { principal: "other" }, { successorSha256: "0".repeat(64) }, { approvalSha256: "0".repeat(64) }])
    assert.throws(() => assertSignerLedgerAbsenceAuthorization({ ...valid, ...changed }, { sourceSha }));
  assert.throws(() => assertSignerLedgerAbsenceAuthorization(valid, { sourceSha, now: new Date(Date.now() + 31 * 60 * 1000) }), /stale/);
});

test("authorization resolver binds immutable archive, protected run, source and attempt", () => {
  const authorization = createSignerLedgerAbsenceAuthorization({ sourceSha, approval: approval() });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-signer-absence-auth-"));
  try {
    const json = path.join(directory, "authorization.json"), archive = path.join(directory, "authorization.zip");
    fs.writeFileSync(json, `${JSON.stringify(authorization)}\n`); execFileSync("zip", ["-q", "-j", archive, json]);
    const bytes = fs.readFileSync(archive), digest = `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;
    const workflow = { id: 42, run_attempt: 1, repository: { id: 1, full_name: PRODUCTION_ENVIRONMENT_APPROVAL.repository }, head_repository: { full_name: PRODUCTION_ENVIRONMENT_APPROVAL.repository }, path: ".github/workflows/authorize-production-signer-ledger-absence.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", actor: { login: "operator" } };
    const artifact = { id: 7, name: "production-signer-ledger-absence-authorization", expired: false, digest, workflow_run: { id: 42, head_sha: sourceSha, repository_id: 1 } };
    const githubRun = (command, args, options = {}) => {
      if (command === "gh" && args[1].endsWith("/artifacts")) return JSON.stringify({ artifacts: [artifact] });
      if (command === "gh" && args[1].endsWith("/zip")) return bytes;
      if (command === "gh") return JSON.stringify(workflow);
      return execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8" });
    };
    assert.equal(resolveSignerLedgerAbsenceAuthorization({ workflowRunId: "42", workflowRunAttempt: "1", sourceSha, githubRun }).authorizationSha256, authorization.authorizationSha256);
    assert.throws(() => resolveSignerLedgerAbsenceAuthorization({ workflowRunId: "42", workflowRunAttempt: "2", sourceSha, githubRun }), /provenance/);
    assert.throws(() => resolveSignerLedgerAbsenceAuthorization({ workflowRunId: "42", workflowRunAttempt: "1", sourceSha: "b".repeat(40), githubRun }), /provenance/);
    const wrongActorRun = (command, args, options) => args?.[1] === `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/42` ? JSON.stringify({ ...workflow, actor: { login: "someone-else" } }) : githubRun(command, args, options);
    assert.throws(() => resolveSignerLedgerAbsenceAuthorization({ workflowRunId: "42", workflowRunAttempt: "1", sourceSha, githubRun: wrongActorRun }), /actor differs/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test("reconciliation writes the exact policy once and existing successor is a no-op", async () => {
  let live = signerLedgerBucketPolicyPredecessor(); const calls = [];
  const s3 = async (operation, input) => {
    calls.push({ operation, input }); assert.equal(input.Bucket, signerLedgerAbsence.bucket); assert.equal(input.ExpectedBucketOwner, "368992683803");
    if (operation === "GetBucketPolicy") return { Policy: JSON.stringify(live) };
    assert.equal(operation, "PutBucketPolicy"); live = JSON.parse(input.Policy); return {};
  };
  const authorization = createSignerLedgerAbsenceAuthorization({ sourceSha, approval: approval() });
  const options = { sourceSha, authorization, s3, currentSource: async () => sourceSha };
  assert.equal((await reconcileSignerLedgerAbsence(options)).putBucketPolicyCount, 1);
  assert.equal(classifySignerLedgerBucketPolicy(live), "EXACT_SUCCESSOR");
  assert.equal((await reconcileSignerLedgerAbsence(options)).putBucketPolicyCount, 0);
  assert.equal(calls.filter(({ operation }) => operation === "PutBucketPolicy").length, 1);
});

test("ambiguous policy-write response resumes by exact readback without a second mutation", async () => {
  let live = signerLedgerBucketPolicyPredecessor(), writes = 0;
  const s3 = async (operation, input) => {
    if (operation === "GetBucketPolicy") return { Policy: JSON.stringify(live) };
    assert.equal(operation, "PutBucketPolicy"); writes++; live = JSON.parse(input.Policy);
    throw new Error("response lost after S3 accepted the write");
  };
  const authorization = createSignerLedgerAbsenceAuthorization({ sourceSha, approval: approval() });
  const input = { sourceSha, authorization, s3, currentSource: async () => sourceSha };
  const result = await reconcileSignerLedgerAbsence(input);
  assert.deepEqual({ state: result.state, writes, ambiguous: result.writeResponseAmbiguous }, { state: "CONVERGED", writes: 1, ambiguous: true });
  assert.equal((await reconcileSignerLedgerAbsence(input)).putBucketPolicyCount, 0);
  assert.equal(writes, 1);
});

test("canonical prepare and execute entrypoints reach only the exact root-MFA bucket-policy transition", async () => {
  const authorization = createSignerLedgerAbsenceAuthorization({ sourceSha, approval: approval() });
  let live = signerLedgerBucketPolicyPredecessor(), writes = 0, rootCalls = 0, closed = 0;
  const deps = { source: () => sourceSha, readPolicy: () => classifySignerLedgerBucketPolicy(live), resolve: ({ workflowRunId, workflowRunAttempt, sourceSha: requested }) => {
    assert.deepEqual([workflowRunId, workflowRunAttempt, requested], ["42", "1", sourceSha]); return authorization;
  }, root: async () => { rootCalls++; return { credentials: { accessKeyId: "fixture", secretAccessKey: "fixture", sessionToken: "fixture" }, close: () => { closed++; } }; }, transport: credentials => {
    assert.equal(credentials.accessKeyId, "fixture");
    return { send: async (operation, input) => {
      if (operation === "GetBucketPolicy") return { Policy: JSON.stringify(live) };
      assert.equal(operation, "PutBucketPolicy"); writes++; live = JSON.parse(input.Policy); return {};
    }, close: () => { closed++; } };
  } };
  assert.equal((await runSignerLedgerAbsenceCli(["prepare"], deps)).live, "EXACT_PREDECESSOR");
  assert.equal(rootCalls, 0);
  assert.equal((await runSignerLedgerAbsenceCli(["execute", "42", "1"], deps)).state, "CONVERGED");
  assert.deepEqual({ writes, rootCalls, closed }, { writes: 1, rootCalls: 1, closed: 2 });
  assert.equal((await runSignerLedgerAbsenceCli(["execute", "42", "1"], deps)).state, "ALREADY_CONVERGED");
  assert.deepEqual({ writes, rootCalls, closed }, { writes: 1, rootCalls: 1, closed: 2 });
});

test("drift, source advance, stale approval, and ambiguous readback fail before a write or closed confirmation", async () => {
  const authorization = createSignerLedgerAbsenceAuthorization({ sourceSha, approval: approval() });
  let writes = 0; const drift = { ...signerLedgerBucketPolicyPredecessor(), Statement: [] };
  const s3 = async operation => { if (operation === "GetBucketPolicy") return { Policy: JSON.stringify(drift) }; writes++; return {}; };
  await assert.rejects(reconcileSignerLedgerAbsence({ sourceSha, authorization, s3, currentSource: async () => sourceSha }), /differs/);
  await assert.rejects(reconcileSignerLedgerAbsence({ sourceSha, authorization, s3, currentSource: async () => "b".repeat(40) }), /Protected main changed/);
  assert.equal(writes, 0);
  const predecessor = signerLedgerBucketPolicyPredecessor();
  await assert.rejects(reconcileSignerLedgerAbsence({ sourceSha, authorization, s3: async operation => { if (operation === "GetBucketPolicy") return { Policy: JSON.stringify(predecessor) }; writes++; return {}; }, currentSource: async () => sourceSha, now: () => Date.now() + 31 * 60 * 1000 }), /stale/);
  assert.equal(writes, 0);
});
