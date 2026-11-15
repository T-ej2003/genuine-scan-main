import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { assertStaleSignerSuccessorIamRequest, assertStaleSignerSuccessorS3Request, run } from "../aws/component-broker-stale-signer-successor-cli.mjs";
import { staleSignerPublisherPolicy, staleSignerSuccessor, staleSignerSuccessorCapabilitySet } from "../aws/component-broker-stale-signer-successor-contract.mjs";
import { brokerStaleSignerSuccessorManagedIdentities, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { canonical } from "../aws/component-iam-installation-contract.mjs";

test("stale signer successor confines IAM writes to five broker policies and exact v18 publisher", () => {
  const identities = brokerStaleSignerSuccessorManagedIdentities();
  for (const identity of identities) assert.doesNotThrow(() => assertStaleSignerSuccessorIamRequest("PutRolePolicy", { RoleName: identity.role, PolicyName: identity.policyName, PolicyDocument: canonical(identity.policy) }));
  assert.doesNotThrow(() => assertStaleSignerSuccessorIamRequest("PutRolePolicy", { RoleName: "mscqr-production-signer-policy-installer", PolicyName: "ProductionSignerPolicyInstaller", PolicyDocument: canonical(staleSignerPublisherPolicy) }));
  for (const request of [
    { RoleName: "other", PolicyName: "ProductionSignerPolicyInstaller", PolicyDocument: canonical(staleSignerPublisherPolicy) },
    { RoleName: "mscqr-production-signer-policy-installer", PolicyName: "ProductionSignerPolicyInstaller", PolicyDocument: canonical({ ...staleSignerPublisherPolicy, Statement: [] }) },
    { RoleName: "mscqr-production-signer-policy-installer", PolicyName: "Other", PolicyDocument: canonical(staleSignerPublisherPolicy) },
  ]) assert.throws(() => assertStaleSignerSuccessorIamRequest("PutRolePolicy", request));
  assert.doesNotThrow(() => assertStaleSignerSuccessorIamRequest("GetPolicyVersion", { PolicyArn: `arn:aws:iam::${identityBootstrap.account}:policy/MSCQRProductionGreenStageARelease`, VersionId: "v24" }));
  assert.throws(() => assertStaleSignerSuccessorIamRequest("GetPolicyVersion", { PolicyArn: `arn:aws:iam::${identityBootstrap.account}:policy/MSCQRProductionGreenStageARelease`, VersionId: "v25" }));
  assert.deepEqual(JSON.parse(fs.readFileSync("infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-permissions-policy.json", "utf8")), staleSignerPublisherPolicy);
});

test("stale signer successor reads predecessor and retired ledger but writes only its checkpoint and bootstrap", () => {
  const policy = staleSignerSuccessorCapabilitySet();
  const reads = policy.Statement.find(({ Action }) => Action === "s3:GetObject").Resource;
  const writes = policy.Statement.find(({ Action }) => Action === "s3:PutObject").Resource;
  const request = (Key, write = false) => ({ Bucket: identityBootstrap.bucket, Key, ...(write ? { ServerSideEncryption: "AES256" } : {}) });
  for (const name of ["broker-policy-successor.json", "broker-recovery-successor.json", "broker-signer-successor.json", "signer-policy-transition.json"]) {
    const key = `${identityBootstrap.prefix}${name}`, arn = `arn:aws:s3:::${identityBootstrap.bucket}/${key}`;
    assert(reads.includes(arn)); assert(!writes.includes(arn));
    assert.doesNotThrow(() => assertStaleSignerSuccessorS3Request("GetObject", request(key)));
    assert.throws(() => assertStaleSignerSuccessorS3Request("PutObject", request(key, true)));
  }
  for (const key of [staleSignerSuccessor.reservationKey, `${identityBootstrap.prefix}identity-bootstrap.json`]) assert.doesNotThrow(() => assertStaleSignerSuccessorS3Request("PutObject", request(key, true)));
});

test("stale signer successor authenticates source approval before root MFA and closes its session", async () => {
  const calls = [], sourceSha = "a".repeat(40), transitionId = "12345678-1234-4234-8234-123456789abc";
  const deps = { source: () => sourceSha, build: async () => ({ manifest: { sourceSha } }),
    authorize: () => { calls.push("authorize"); return { authorizationSha256: "b".repeat(64), transitionId }; },
    admin: async () => { calls.push("admin"); return { issuanceEvents: async () => [], authenticate: async () => {}, close: () => calls.push("close") }; },
    human: async binding => { calls.push("human"); assert.equal(binding.purpose, "BROKER_STALE_SIGNER_SUCCESSOR"); return {}; },
    execute: async () => { calls.push("execute"); return { brokerStaleSignerSuccessor: { state: "BROKER_STALE_SIGNER_SUCCESSOR_CLOSED" } }; } };
  assert.equal((await run(["execute", "456", transitionId], deps)).state, "BROKER_STALE_SIGNER_SUCCESSOR_CLOSED");
  assert.deepEqual(calls, ["authorize", "admin", "human", "execute", "close"]);
  calls.length = 0; deps.authorize = () => { calls.push("authorize"); throw new Error("approval denied"); };
  await assert.rejects(run(["execute", "456", transitionId], deps), /approval denied/); assert.deepEqual(calls, ["authorize"]);
});

test("current runbook exposes the exact stale-signer generation route", () => {
  const scripts = JSON.parse(fs.readFileSync("package.json", "utf8")).scripts;
  assert.equal(scripts["production:component-broker-stale-signer-successor"], "node scripts/aws/component-broker-stale-signer-successor-cli.mjs");
  const guide = fs.readFileSync("documents/ops/iam/MSCQR_PRODUCTION_SECURITY_REBASELINE_SIGNER_TEMPORARY_CAPABILITY-v1.md", "utf8");
  assert.match(guide, /successor=stale-signer/);
  assert.match(guide, /npm run production:component-broker-stale-signer-successor -- execute RUN_ID TRANSITION_ID/);
});
