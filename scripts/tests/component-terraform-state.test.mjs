import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createTerraformStateBoundary } from "../aws/component-terraform-state.mjs";
import { installationDocuments, documentBindings, digest, terraformExecutorPolicyGeneration } from "../aws/component-iam-installation-contract.mjs";
import { contract } from "../aws/component-infrastructure-activation.mjs";
import { partialActivationRecoveryTarget, assertPartialActivationRecoveryPreparation } from "../aws/component-infrastructure-partial-activation-recovery-contract.mjs";

const binding = { sourceSha: "a".repeat(40), transitionId: "12345678-1234-4234-8234-123456789abc", authorizationSha256: "b".repeat(64), purpose: "TERRAFORM" };
const key = "mscqr/production/component-deployment-state/terraform.tfstate";
const historical = { sourceSha: "c".repeat(40), authorizationRunId: "456", authorizationArtifactSha256: `sha256:${"d".repeat(64)}`, planSha256: "e".repeat(64), preparationSha256: "f".repeat(64), transitionId: binding.transitionId };
function liveReceiptBody(f, client) {
  return { transformToString: async () => {
    await Promise.resolve();
    if (client?.destroyed) throw Object.assign(new Error("aborted"), { code: "ECONNRESET" });
    f.streamRead = true;
    if (f.streamFailure) throw new Error("receipt stream failed");
    return JSON.stringify(f.receipt);
  } };
}
function activationAttempt(f) {
  return { authorizationRunId: historical.authorizationRunId, sourceSha: historical.sourceSha, planSha256: historical.planSha256, preparationSha256: historical.preparationSha256, transitionId: historical.transitionId, iamReceiptSha256: crypto.createHash("sha256").update(JSON.stringify(f.receipt)).digest("hex"), session: { ...binding, account: "368992683803", region: "eu-west-2", principal: `arn:aws:sts::368992683803:assumed-role/mscqr-production-component-table-installer/component-${binding.transitionId}`, issuedAt: "2026-09-19T00:00:00.000Z", expiresAt: "2026-09-19T00:15:00.000Z", issuanceEventId: "12345678-1234-4234-8234-123456789abc", issuanceEventTime: "2026-09-19T00:00:00.000Z", operatorArn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", mfaAuthenticated: true } };
}
function fixture({ liveStream = false, recovery = false, now = Date.now } = {}) {
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
          if (recovery && input.Key === key + ".tflock") return { Body: { transformToString: async () => JSON.stringify(f.lockBodies?.[input.VersionId] || { ID: "incident-lock", Operation: "OperationTypeApply", Info: "", Who: "operator", Version: "1.15.8", Created: "2026-09-19T00:00:00Z", Path: "mscqr-production-terraform-state-368992683803-eu-west-2/" + key }) } };
          if (recovery && input.Key === key + ".initial-activation-attempt") return { Body: { transformToString: async () => JSON.stringify(f.attempt || activationAttempt(f)) } };
          if (recovery && input.Key === key) return { Body: { transformToString: async () => JSON.stringify({ lineage: "lineage", serial: 1, resources: [{ mode: "managed", type: "aws_dynamodb_table", name: "component_deployment_state", instances: [{ attributes: { id: "mscqr-production-component-deployment-state" } }] }] }) } };
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
  const dependencies = { describe: async () => f.table, now };
  if (recovery) dependencies.recoveryDescribe = async operation => f.recoveryMetadata?.[operation];
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

function recoveryFixture(now) {
  const f = fixture({ recovery: true, ...(now ? { now } : {}) });
  f.objects = [{ Key: key + ".initial-activation-attempt" }, { Key: key + ".tflock" }];
  f.versions = [{ Key: key + ".initial-activation-attempt", IsLatest: true, VersionId: "attempt-version", ETag: '"attempt"' },
    { Key: key + ".tflock", IsLatest: true, VersionId: "lock-version", ETag: '"lock"', LastModified: "2026-09-19T00:10:00.000Z" },
    { Key: key + ".tflock", IsLatest: false, VersionId: "plan-lock-version", ETag: '"plan-lock"', LastModified: "2026-09-19T00:00:00.000Z" }];
  f.deleted = [{ Key: key + ".tflock", IsLatest: false, VersionId: "plan-delete-version", LastModified: "2026-09-19T00:01:00.000Z" }];
  f.lockBodies = { "lock-version": { ID: "12345678-1234-4234-8234-123456789abc", Operation: "OperationTypeApply", Info: "", Who: "terraform@isolated", Version: "1.15.8", Created: "2026-09-19T00:10:00.000Z", Path: "mscqr-production-terraform-state-368992683803-eu-west-2/" + key },
    "plan-lock-version": { ID: "22345678-1234-4234-8234-123456789abc", Operation: "OperationTypePlan", Info: "", Who: "terraform@isolated", Version: "1.15.8", Created: "2026-09-19T00:00:00.000Z", Path: "mscqr-production-terraform-state-368992683803-eu-west-2/" + key } };
  f.table = { TableName: "mscqr-production-component-deployment-state", TableArn: "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-component-deployment-state", TableStatus: "ACTIVE", BillingModeSummary: { BillingMode: "PAY_PER_REQUEST" }, KeySchema: [{ AttributeName: "stateKey", KeyType: "HASH" }], AttributeDefinitions: [{ AttributeName: "stateKey", AttributeType: "S" }], SSEDescription: { Status: "ENABLED" }, DeletionProtectionEnabled: false, StreamSpecification: { StreamEnabled: false }, Replicas: [] };
  f.recoveryMetadata = { DescribeContinuousBackups: { ContinuousBackupsDescription: { PointInTimeRecoveryDescription: { PointInTimeRecoveryStatus: "ENABLED" } } }, DescribeTimeToLive: { TimeToLiveDescription: { TimeToLiveStatus: "DISABLED" } }, ListTagsOfResource: { Tags: [{ Key: "ManagedBy", Value: "Terraform" }, { Key: "Environment", Value: "production" }, { Key: "Stack", Value: "production-component-deployment-state" }] } };
  return f;
}

test("partial activation recovery authenticates the exact immutable reservation, retained lock, empty state history and expected live table", async () => {
  const f = recoveryFixture(), result = await f.boundary.inspectPartialActivationRecovery(historical);
  assert.equal(result.stateIdentity, "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE"); assert.equal(result.lock.versionId, "lock-version"); assert.equal(result.table.address, "aws_dynamodb_table.component_deployment_state");
  const statements = terraformExecutorPolicyGeneration("7", true).Statement;
  for (const { input } of f.calls.filter(({ operation, input }) => operation === "GetObject" && input.VersionId)) {
    const resource = `arn:aws:s3:::${input.Bucket}/${input.Key}`;
    assert(statements.some(statement => [].concat(statement.Action).includes("s3:GetObjectVersion") && [].concat(statement.Resource).includes(resource)), `Missing version-read authority for ${resource}`);
  }
  assert(f.calls.every(({ operation }) => !/Put|Delete|Create|Update/.test(operation)));
});
for (const [name, stream, accepted] of [
  ["accepts an absent DynamoDB stream specification as disabled", undefined, true],
  ["accepts an explicitly disabled DynamoDB stream", { StreamEnabled: false }, true],
  ["rejects an enabled DynamoDB stream", { StreamEnabled: true }, false],
]) test(`partial activation recovery ${name}`, async () => {
  const f = recoveryFixture();
  if (stream === undefined) delete f.table.StreamSpecification;
  else f.table.StreamSpecification = stream;
  if (accepted) assert.equal((await f.boundary.inspectPartialActivationRecovery(historical)).stateIdentity, "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE");
  else await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical), /DynamoDB stream must be disabled/);
});
test("partial activation recovery accepts the pinned Terraform lock ID format without inventing UUIDv4 semantics", async () => {
  const f = recoveryFixture(), id = "12345678-1234-7abc-2def-0123456789ab";
  // Terraform 1.15.8's uuid.FormatUUID formats random bytes; it does not set
  // the UUIDv4 version or variant bits this ID deliberately lacks.
  assert.doesNotMatch(id, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i);
  f.lockBodies["lock-version"].ID = id;
  assert.equal((await f.boundary.inspectPartialActivationRecovery(historical)).stateIdentity, "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE");
  for (const mutate of [value => { value.ID = "not-a-terraform-lock-id"; }, value => { value.ID = id.toUpperCase(); }, value => { value.ID = ""; }, value => { delete value.ID; }]) {
    const invalid = recoveryFixture(); mutate(invalid.lockBodies["lock-version"]);
    await assert.rejects(invalid.boundary.inspectPartialActivationRecovery(historical));
  }
});
test("partial activation recovery accepts only paired preparatory plan lock history before the current apply lock", async () => {
  for (const mutate of [
    f => { f.deleted = []; },
    f => { f.deleted[0].IsLatest = true; },
    f => { f.lockBodies["plan-lock-version"].Operation = "OperationTypeApply"; },
    f => { f.deleted[0].LastModified = "2026-09-19T00:11:00.000Z"; },
  ]) { const f = recoveryFixture(); mutate(f); await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical)); }
});
test("partial activation recovery waits through the authenticated original Terraform session expiry fence", async () => {
  const expiry = Date.parse("2026-09-19T00:15:00.000Z"), fence = expiry + 120000, clock = { value: expiry - 1 };
  const f = recoveryFixture(() => clock.value);
  await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical), /not safely expired/);
  assert(f.calls.every(({ operation }) => !/Put|Delete|Create|Update/.test(operation)));
  clock.value = fence;
  await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical), /not safely expired/);
  clock.value = fence + 1;
  assert.equal((await f.boundary.inspectPartialActivationRecovery(historical)).stateIdentity, "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE");
  for (const mutate of [value => { delete value.session.expiresAt; }, value => { value.session.expiresAt = "invalid"; }, value => { value.session.issuedAt = "2026-09-19T01:00:00.000Z"; value.session.expiresAt = "2026-09-19T01:15:00.000Z"; }]) {
    f.attempt = activationAttempt(f); mutate(f.attempt);
    await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical));
  }
});
test("continuation accepts only native import or verification locks following their exact recovery checkpoints", async () => {
  const f = recoveryFixture(), receiptSha256 = crypto.createHash("sha256").update(JSON.stringify(f.receipt)).digest("hex");
  const original = { key: partialActivationRecoveryTarget.lockKey, sha256: "4".repeat(64), etag: '"original"', versionId: "original" };
  const preparation = assertPartialActivationRecoveryPreparation({ schemaVersion: 1, sourceSha: binding.sourceSha, recoveryTransitionId: "87654321-1234-4234-8234-123456789abc", stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE", backend: contract, historicalActivation: historical,
    iamInstallation: { sourceSha: binding.sourceSha, transitionId: binding.transitionId, authorizationSha256: binding.authorizationSha256, documentBindingsSha256: digest(documentBindings()), receiptSha256 }, liveTable: partialActivationRecoveryTarget, lock: original,
    attempt: { authorizationRunId: historical.authorizationRunId, etag: '"attempt"', sha256: crypto.createHash("sha256").update(JSON.stringify(activationAttempt(f))).digest("hex"), versionId: "attempt-version" } });
  const preparationSha256 = "7".repeat(64), checkpoint = { schemaVersion: 1, state: "RECOVERY_EXECUTING", sourceSha: binding.sourceSha, recoveryTransitionId: preparation.recoveryTransitionId, preparationSha256, authorizationSha256: "8".repeat(64), expiresAt: "2026-09-19T00:15:00.000Z", owner: { principal: "recovery-owner", expiresAt: "2026-09-19T00:15:00.000Z" }, historical, lock: original };
  f.objects = [{ Key: key + ".initial-activation-attempt" }, { Key: key + ".tflock" }, { Key: key }];
  f.versions = [{ Key: key + ".initial-activation-attempt", IsLatest: true, VersionId: "attempt-version", ETag: '"attempt"' }, { Key: key, IsLatest: true, VersionId: "state-version", ETag: '"state"' }, { Key: key + ".tflock", IsLatest: true, VersionId: "native", ETag: '"native"' }, { Key: key + ".tflock", IsLatest: false, VersionId: "recovery", ETag: '"recovery"' }, { Key: key + ".tflock", IsLatest: false, VersionId: "original", ETag: '"original"' }];
  f.lockBodies = { native: { ID: "12345678-1234-4234-8234-123456789abc", Operation: "OperationTypeApply", Info: "", Who: "terraform@isolated", Version: "1.15.8", Created: "2026-09-19T00:01:00.000Z", Path: "mscqr-production-terraform-state-368992683803-eu-west-2/" + key }, recovery: { ID: preparation.recoveryTransitionId, Operation: "OperationTypeRecovery", Info: JSON.stringify(checkpoint), Who: "recovery-owner", Version: "1.15.8", Created: "2026-09-19T00:00:00.000Z", Path: "mscqr-production-terraform-state-368992683803-eu-west-2/" + key } };
  const result = await f.boundary.inspectPartialActivationRecoveryContinuation(preparation, preparationSha256);
  assert.equal(result.stateExists, true); assert.equal(result.retainedNativeLock.id, "12345678-1234-4234-8234-123456789abc");
  f.lockBodies.native.Operation = "OperationTypePlan";
  await assert.rejects(f.boundary.inspectPartialActivationRecoveryContinuation(preparation, preparationSha256));
  checkpoint.state = "RESOURCE_ADOPTED"; f.lockBodies.recovery.Info = JSON.stringify(checkpoint);
  assert.equal((await f.boundary.inspectPartialActivationRecoveryContinuation(preparation, preparationSha256)).retainedNativeLock.operation, "OperationTypePlan");
  f.lockBodies.native.Operation = "OperationTypeRefresh";
  await assert.rejects(f.boundary.inspectPartialActivationRecoveryContinuation(preparation, preparationSha256));
});
for (const mutate of [
  value => { value.authorizationRunId = "999"; }, value => { value.planSha256 = "0".repeat(64); }, value => { value.preparationSha256 = "0".repeat(64); },
  value => { value.transitionId = "87654321-1234-4234-8234-123456789abc"; }, value => { value.sourceSha = "0".repeat(40); }, value => { value.session.mfaAuthenticated = false; }, value => { delete value.session.issuanceEventId; },
]) test("partial activation recovery rejects a substituted or malformed immutable reservation", async () => {
  const f = recoveryFixture(); await f.boundary.inspectPartialActivationRecovery(historical);
  const get = f.calls.find(({ operation, input }) => operation === "GetObject" && input.Key === key + ".initial-activation-attempt");
  assert(get); // The parser is exercised again with one independently mutated immutable record.
  f.attempt = activationAttempt(f);
  mutate(f.attempt); await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical));
});

for (const mutate of [
  f => { f.objects = f.objects.filter(({ Key }) => Key !== key + ".initial-activation-attempt"); }, f => { f.objects = f.objects.filter(({ Key }) => Key !== key + ".tflock"); },
  f => { f.objects.push({ Key: key }); }, f => { f.versions.push({ Key: key, IsLatest: true, VersionId: "state", ETag: '"state"' }); }, f => { f.deleted.push({ Key: key }); },
  f => { f.table.KeySchema = []; }, f => { f.table.BillingModeSummary.BillingMode = "PROVISIONED"; }, f => { f.table.SSEDescription.Status = "DISABLED"; },
  f => { f.recoveryMetadata.DescribeContinuousBackups.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus = "DISABLED"; }, f => { f.recoveryMetadata.ListTagsOfResource.Tags.pop(); },
]) test("partial activation recovery fails closed on incident topology or table drift", async () => {
  const f = recoveryFixture(); mutate(f); await assert.rejects(f.boundary.inspectPartialActivationRecovery(historical)); assert(f.calls.every(({ operation }) => !/Put|Delete|Create|Update/.test(operation)));
});
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
test("recovery lock streams finish before cleanup and still clean up after a body failure", async () => {
  const preparation = { schemaVersion: 1, sourceSha: binding.sourceSha, recoveryTransitionId: "87654321-1234-4234-8234-123456789abc", stateIdentity: "INFRASTRUCTURE_CREATED_STATE_INCOMPLETE", backend: contract,
    historicalActivation: historical, iamInstallation: { sourceSha: binding.sourceSha, transitionId: binding.transitionId, authorizationSha256: binding.authorizationSha256, documentBindingsSha256: "1".repeat(64), receiptSha256: "2".repeat(64) }, liveTable: partialActivationRecoveryTarget,
    lock: { key: partialActivationRecoveryTarget.lockKey, sha256: "3".repeat(64), etag: '"original"', versionId: "original" }, attempt: { authorizationRunId: historical.authorizationRunId, etag: '"attempt"', sha256: "6".repeat(64), versionId: "attempt" } };
  const record = { schemaVersion: 1, state: "RECOVERY_EXECUTING", sourceSha: binding.sourceSha, recoveryTransitionId: preparation.recoveryTransitionId, preparationSha256: "4".repeat(64), authorizationSha256: "5".repeat(64), expiresAt: "2026-09-19T00:15:00.000Z", owner: { principal: "recovery-owner", expiresAt: "2026-09-19T00:15:00.000Z" }, historical, lock: preparation.lock };
  for (const failure of [false, true]) {
    const clients = [];
    const boundary = createTerraformStateBoundary({ AccessKeyId: "fixture", SecretAccessKey: "fixture", SessionToken: "fixture" }, binding, { createClient: service => {
      const client = { destroyed: false, destroyCalls: 0, async send(command) {
        const operation = command.constructor.name.replace("Command", ""), input = command.input;
        if (operation === "GetObject") return { ETag: '"claim"', Body: { transformToString: async () => { await Promise.resolve(); assert.equal(client.destroyed, false); if (failure) throw new Error("lock stream failed"); return JSON.stringify({ ID: preparation.recoveryTransitionId, Operation: "OperationTypeRecovery", Info: JSON.stringify(record), Who: "recovery-owner", Version: "1.15.8", Created: "2026-09-19T00:00:00.000Z", Path: "mscqr-production-terraform-state-368992683803-eu-west-2/" + key }); } } };
        if (operation === "DeleteObject") return { DeleteMarker: true };
        assert.equal(operation, "ListObjectsV2"); assert.equal(input.Key, undefined); return { Contents: [] };
      }, destroy() { client.destroyed = true; client.destroyCalls++; } };
      clients.push(client); return client;
    } });
    if (failure) await assert.rejects(boundary.releasePartialActivationLock(preparation.lock, '"claim"', record, preparation, record.preparationSha256), /lock stream failed/);
    else await boundary.releasePartialActivationLock(preparation.lock, '"claim"', record, preparation, record.preparationSha256);
    assert(clients.every(client => client.destroyed && client.destroyCalls === 1));
  }
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
