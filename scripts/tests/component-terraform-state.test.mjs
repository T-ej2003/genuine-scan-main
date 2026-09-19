import test from "node:test";
import assert from "node:assert/strict";
import { createTerraformStateBoundary } from "../aws/component-terraform-state.mjs";
import { installationDocuments, documentBindings, digest } from "../aws/component-iam-installation-contract.mjs";

const binding = { sourceSha: "a".repeat(40), transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "b".repeat(64), purpose: "TERRAFORM" };
const key = "mscqr/production/component-deployment-state/terraform.tfstate";
function liveReceiptBody(f, client) {
  return { transformToString: async () => {
    await Promise.resolve();
    if (client?.destroyed) throw Object.assign(new Error("aborted"), { code: "ECONNRESET" });
    f.streamRead = true;
    if (f.streamFailure) throw new Error("receipt stream failed");
    return JSON.stringify(f.receipt);
  } };
}
function fixture({ liveStream = false } = {}) {
  const targets = installationDocuments();
  const f = { objects: [], versions: [], deleted: [], table: null, versioning: "Enabled", truncated: false, mutate: () => {}, calls: [], puts: [], denied: false, clients: [] };
  f.receipt = { schemaVersion: 1, sourceSha: binding.sourceSha, transitionId: binding.transitionId, authorizationSha256: binding.authorizationSha256,
    documentBindingsSha256: digest(documentBindings()), state: "IAM_VERIFIED", live: targets.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })) };
  const send = async (service, operation, input, client) => {
      f.calls.push({ service, operation, input });
      if (service === "s3") {
        assert.equal(input.Bucket, "mscqr-production-terraform-state-368992683803-eu-west-2");
        if (operation === "GetBucketVersioning") return { Status: f.versioning };
        if (operation === "ListObjectsV2") { assert.equal(input.Prefix, key); return { IsTruncated: f.truncated, Contents: f.objects }; }
        if (operation === "ListObjectVersions") { assert.equal(input.Prefix, key); return { IsTruncated: f.truncated, Versions: f.versions, DeleteMarkers: f.deleted }; }
        if (operation === "GetObject") {
          assert.equal(input.Key, "mscqr/production/component-deployment-state/iam-installation.json"); if (f.denied) throw new Error("AccessDenied");
          return { Body: liveReceiptBody(f, client) };
        }
        assert.equal(operation, "PutObject"); assert.equal(input.Key, key + ".initial-activation-attempt");
        assert.equal(input.IfNoneMatch, "*"); assert.equal(input.ServerSideEncryption, "AES256");
        f.puts.push(input); if (f.ambiguous) throw new Error("ambiguous acceptance"); return { ETag: "authenticated-service-response" };
      }
      assert.equal(service, "iam");
      const target = targets.find(value => value.role === input.RoleName); assert(target);
      const response = {
        GetRole: { Role: { RoleName: target.role, Arn: target.arn, Path: "/", MaxSessionDuration: 3600, AssumeRolePolicyDocument: target.trust,
          Tags: [{ Key: "ManagedBy", Value: "GuardedComponentInstaller" }, { Key: "Environment", Value: "production" }, { Key: "Transition", Value: binding.transitionId }] } },
        GetRolePolicy: { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: target.policy },
        ListRolePolicies: { IsTruncated: false, PolicyNames: [target.policyName] },
        ListAttachedRolePolicies: { IsTruncated: false, AttachedPolicies: [] },
      }[operation]; assert(response);
      f.mutate(operation, response, target); return response;
    };
  const dependencies = { describe: async () => f.table };
  if (liveStream) {
    dependencies.createClient = service => {
      const client = {
        destroyed: false, destroyCalls: 0,
        async send(command) { client.operation = command.constructor.name.replace("Command", ""); return send(service, client.operation, command.input, client); },
        destroy() { client.destroyed = true; client.destroyCalls++; },
      };
      f.clients.push(client); return client;
    };
  } else dependencies.send = send;
  f.boundary = createTerraformStateBoundary({ AccessKeyId: "fixture", SecretAccessKey: "placeholder", SessionToken: "fixture-token" }, binding, dependencies);
  return f;
}
test("state preflight authenticates exact absent state/history/table and all guarded IAM readbacks", async () => {
  const f = fixture(), result = await f.boundary.inspect();
  assert.equal(result.stateIdentity, "ABSENT"); assert.match(result.iamInstallation.receiptSha256, /^[a-f0-9]{64}$/);
  assert.equal(result.iamInstallation.authorizationSha256, binding.authorizationSha256);
  assert.equal(f.puts.length, 0);
  assert(f.calls.every(value => !/Create|Put|Delete|Update/.test(value.operation)));
});
test("receipt stream stays live until fully consumed and every client is cleaned up once", async () => {
  const f = fixture({ liveStream: true }), result = await f.boundary.inspect();
  assert.equal(result.stateIdentity, "ABSENT"); assert.equal(f.streamRead, true);
  assert(f.clients.length > 1);
  assert(f.clients.every(client => client.destroyed && client.destroyCalls === 1));
  assert(f.clients.filter(client => client.operation !== "GetObject").every(client => client.destroyed && client.destroyCalls === 1));
});
test("a live receipt stream aborts when its client closes before consumption", async () => {
  const client = { destroyed: true };
  await assert.rejects(liveReceiptBody({ receipt: {} }, client).transformToString(), error => error.code === "ECONNRESET" && error.message === "aborted");
});
test("receipt stream failure still closes its client exactly once", async () => {
  const f = fixture({ liveStream: true }); f.streamFailure = true;
  await assert.rejects(f.boundary.inspect(), /receipt stream failed/);
  assert.equal(f.streamRead, true);
  assert(f.clients.every(client => client.destroyed && client.destroyCalls === 1));
});
for (const mutate of [
  f => { f.objects = [{ Key: key }]; }, f => { f.objects = [{ Key: key + ".tflock" }]; }, f => { f.objects = [{ Key: key + ".initial-activation-attempt" }]; },
  f => { f.versions = [{ Key: key }]; }, f => { f.deleted = [{ Key: key }]; }, f => { f.deleted = [{ Key: key + ".initial-activation-attempt" }]; },
  f => { f.table = { TableName: "mscqr-production-component-deployment-state" }; }, f => { f.truncated = true; }, f => { f.versioning = "Suspended"; },
  f => { f.denied = true; }, f => { f.receipt.sourceSha = "c".repeat(40); }, f => { f.receipt.authorizationSha256 = "c".repeat(64); },
  f => { f.receipt.state = "IAM_INSTALLING"; }, f => { f.receipt.documentBindingsSha256 = "c".repeat(64); },
]) test("unexpected, consumed, incomplete or unauthenticated baseline fails before writes", async () => {
  const f = fixture(); mutate(f); await assert.rejects(f.boundary.inspect()); assert.equal(f.puts.length, 0);
});
for (const [operation, mutate] of [
  ["GetRole", value => { value.Role.Arn += "other"; }], ["GetRole", value => { value.Role.AssumeRolePolicyDocument = {}; }],
  ["GetRole", value => { value.Role.PermissionsBoundary = {}; }], ["GetRole", value => { value.Role.Tags.push({ Key: "extra", Value: "drift" }); }],
  ["GetRole", value => { value.Role.Path = "/alternate/"; }], ["GetRole", value => { value.Role.MaxSessionDuration = 7200; }],
  ["GetRolePolicy", value => { value.PolicyDocument = {}; }], ["GetRolePolicy", value => { value.PolicyName += "other"; }],
  ["ListRolePolicies", value => { value.IsTruncated = true; }], ["ListRolePolicies", value => { value.PolicyNames.push("unexpected"); }],
  ["ListAttachedRolePolicies", value => { value.AttachedPolicies.push({ PolicyArn: "unexpected" }); }],
]) test("live IAM drift is not hidden by a valid receipt: " + operation, async () => {
  const f = fixture(); f.mutate = (observed, value, target) => { if (operation === observed && target.trust) mutate(value); };
  await assert.rejects(f.boundary.inspect()); assert.equal(f.puts.length, 0);
});
test("write-once attempt reservation has only the fixed key and never retries ambiguous acceptance", async () => {
  const f = fixture(), now = Date.now();
  const session = { ...binding, account: "368992683803", region: "eu-west-2", principal: "arn:aws:sts::368992683803:assumed-role/mscqr-production-component-table-installer/component-" + binding.transitionId,
    issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 900000).toISOString(), issuanceEventTime: new Date(now).toISOString(), issuanceEventId: "12345678-1234-4234-8234-123456789def",
    operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true };
  const record = { sourceSha: binding.sourceSha, transitionId: binding.transitionId, authorizationRunId: "123", planSha256: "c".repeat(64), preparationSha256: "d".repeat(64), iamReceiptSha256: "e".repeat(64), session };
  await assert.rejects(f.boundary.reserve({ ...record, key: "arbitrary" })); assert.equal(f.puts.length, 0);
  f.ambiguous = true; await assert.rejects(f.boundary.reserve(record), /ambiguous acceptance/); assert.equal(f.puts.length, 1);
});
