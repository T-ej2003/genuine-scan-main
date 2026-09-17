import test from "node:test";
import assert from "node:assert/strict";
import { executeFixedBroker } from "../aws/component-iam-broker.mjs";
import { installationDocuments, documentBindings, digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, componentBrokerArn, identityBootstrap } from "../aws/component-installation-identity-contract.mjs";
import { sessionProofBinding } from "../aws/component-session-proof.mjs";
import { brokerConfiguration } from "../aws/component-broker-configuration.mjs";

const start = Date.parse("2026-09-17T12:00:00.000Z");
const sourceSha = "a".repeat(40);
const packageSha256 = "b".repeat(64);
const runtimeArn = `arn:aws:lambda:eu-west-2::runtime:${"c".repeat(64)}`;
const transitionId = "12345678-1234-4234-8234-123456789abc";
const actor = { type: "User", login: "T-ej2003", id: 183396573 };
const prefix = "mscqr/production/component-deployment-state/";
const fault = (name) => Object.assign(new Error(name), { name });

function fixture() {
  const identities = bootstrapManagedIdentities();
  const manifest = { account: installationIdentity.account, sourceSha, identities, targets: installationDocuments(), documentBindingsSha256: digest(documentBindings()), capabilitySetSha256: digest(identities) };
  const bootstrap = { schemaVersion: 1, state: "BOOTSTRAP_CLOSED", sourceSha, manifestSha256: digest(manifest), identitySetSha256: digest(identities), packageSha256, runtimeVersions: { 1: runtimeArn, 2: runtimeArn, 3: runtimeArn } };
  const authorization = { schemaVersion: 1, account: installationIdentity.account, region: installationIdentity.region, sourceSha, transitionId, runId: "12345", operator: actor, reviewer: actor,
    environment: installationIdentity.authorizationEnvironment, approvalObservedAt: new Date(start).toISOString(), expiresAt: new Date(start + 1800000).toISOString(),
    documentBindingsSha256: manifest.documentBindingsSha256, capabilitySetSha256: manifest.capabilitySetSha256, brokerPackageSha256: packageSha256, brokerManifestSha256: digest(manifest) };
  const objects = new Map([[`${prefix}identity-bootstrap.json`, { value: bootstrap, etag: "bootstrap" }]]);
  const roles = new Map([[manifest.targets[2].role, { RoleName: manifest.targets[2].role, Arn: manifest.targets[2].arn }]]);
  const policies = new Map();
  const f = { clock: start + 1000, main: sourceSha, sessionIssuedAt: start, sessionEventId: "12345678-1234-4234-8234-123456789def", writes: [], objects, roles, policies, manifest, authorization, bootstrap, configure: () => {}, configureIdentity: () => {}, afterWrite: () => {} };
  let serial = 0;
  const s3 = async (operation, input) => {
    assert.equal(input.Bucket, "mscqr-production-terraform-state-368992683803-eu-west-2");
    const key = input.Key || input.Prefix;
    assert(["identity-bootstrap.json", "installation-authorization.json", "iam-installation.json", "permission-installation.json", "installation-session.json"].map((name) => `${prefix}${name}`).includes(key));
    const previous = objects.get(key);
    if (operation === "ListObjectsV2") return { IsTruncated: false, Contents: previous ? [{ Key: key }] : [] };
    if (operation === "GetObject") {
      if (!previous) throw fault("NoSuchKey");
      return { ETag: previous.etag, Body: { transformToString: async () => JSON.stringify(previous.value) } };
    }
    assert.equal(operation, "PutObject");
    assert.notEqual(key, `${prefix}identity-bootstrap.json`, "Broker cannot forge bootstrap evidence");
    assert.equal(input.ServerSideEncryption, "AES256");
    if (input.IfNoneMatch === "*" ? previous : !previous || previous.etag !== input.IfMatch) throw fault("PreconditionFailed");
    const etag = `${++serial}`;
    objects.set(key, { value: JSON.parse(input.Body), etag });
    f.afterWrite(operation, key);
    return { ETag: etag };
  };
  const iam = async (operation, input) => {
    const identity = identities.find(({ role }) => role === input.RoleName);
    if (identity) {
      const responses = {
        GetRole: { Role: { RoleName: identity.role, Arn: identity.arn, Path: identity.path, MaxSessionDuration: identity.maxSessionDuration, AssumeRolePolicyDocument: identity.trust } },
        GetRolePolicy: { RoleName: identity.role, PolicyName: identity.policyName, PolicyDocument: identity.policy },
        ListRolePolicies: { IsTruncated: false, PolicyNames: [identity.policyName] },
        ListAttachedRolePolicies: { IsTruncated: false, AttachedPolicies: [] },
        ListRoleTags: { IsTruncated: false, Tags: Object.entries(identity.tags).map(([Key, Value]) => ({ Key, Value })) },
      };
      assert(Object.hasOwn(responses, operation), "Broker cannot mutate execution identities");
      const response = structuredClone(responses[operation]);
      f.configureIdentity(operation, response);
      return response;
    }
    const target = manifest.targets.find(({ role }) => role === input.RoleName);
    assert(target, "Unexpected IAM target");
    const role = roles.get(target.role);
    if (operation === "GetRole") { if (!role) throw fault("NoSuchEntity"); return { Role: structuredClone(role) }; }
    if (operation === "GetRolePolicy") {
      assert.equal(input.PolicyName, target.policyName);
      const document = policies.get(target.role);
      if (!document) throw fault("NoSuchEntity");
      return { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: encodeURIComponent(JSON.stringify(document)) };
    }
    if (operation === "ListRolePolicies") return { IsTruncated: false, PolicyNames: policies.has(target.role) ? [target.policyName] : [] };
    if (operation === "ListAttachedRolePolicies") return { IsTruncated: false, AttachedPolicies: [] };
    if (operation === "CreateRole") {
      assert(!role);
      assert.deepEqual(JSON.parse(input.AssumeRolePolicyDocument), target.trust);
      roles.set(target.role, { RoleName: target.role, Arn: target.arn, Path: input.Path, MaxSessionDuration: input.MaxSessionDuration, AssumeRolePolicyDocument: JSON.parse(input.AssumeRolePolicyDocument), Tags: input.Tags });
    } else {
      assert.equal(operation, "PutRolePolicy"); assert(role);
      assert.equal(input.PolicyName, target.policyName);
      assert.deepEqual(JSON.parse(input.PolicyDocument), target.policy);
      policies.set(target.role, JSON.parse(input.PolicyDocument));
    }
    f.writes.push(operation);
    f.afterWrite(operation, target.role);
    return {};
  };
  const lambda = async (operation, input) => {
    assert.equal(input.FunctionName, installationIdentity.functionName);
    if (operation === "GetPolicy") {
      if (f.resourcePolicy === (input.Qualifier || "$LATEST")) return { Policy: "unexpected" };
      if (f.policyReadDenied) throw fault("AccessDeniedException");
      throw fault("ResourceNotFoundException");
    }
    if (operation === "GetFunction") {
      const expected = brokerConfiguration({ packageSha256, manifestSha256: digest(manifest), entryPoint: { 1: "INSTALL", 2: "CLEANUP", 3: "AUTHORIZE" }[input.Qualifier] });
      const response = { Configuration: { ...expected, State: "Active", LastUpdateStatus: "Successful", CodeSize: 1000, RuntimeVersionConfig: { RuntimeVersionArn: runtimeArn } } };
      f.configure(response.Configuration);
      return response;
    }
    if (operation === "GetFunctionConcurrency") return { ReservedConcurrentExecutions: 1 };
    if (operation === "GetFunctionCodeSigningConfig") return { FunctionName: installationIdentity.functionName };
    assert.equal(operation, "GetRuntimeManagementConfig");
    return { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null };
  };
  f.run = (operation, fields = {}, version = { AUTHORIZE: "3", CLOSE: "2", CLEANUP_CONTEXT: "2", PROVE_CLEANUP_SESSION: "2", INSTALL: "1", INSPECT: "1", PROVE_INSTALL_SESSION: "1" }[operation]) => {
    const purpose = ["CLOSE", "PROVE_CLEANUP_SESSION"].includes(operation) ? "CLEANUP" : "INSTALL";
    const role = purpose === "CLEANUP" ? identityBootstrap.cleanupRole : identityBootstrap.installationRole;
    const binding = { sourceSha, transitionId, authorizationSha256: digest(authorization), purpose };
    const key = ["A", "S", "I", "A"].join("") + "0".repeat(16);
    const date = new Date(f.clock).toISOString().replace(/[-:]|\.\d{3}/g, "");
    const proof = { query: { Action: "GetCallerIdentity", Version: "2011-06-15", "X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": `${key}/${date.slice(0, 8)}/eu-west-2/sts/aws4_request`,
      "X-Amz-Date": date, "X-Amz-Expires": "60", "X-Amz-Security-Token": "disposable-session-fixture", "X-Amz-Signature": "c".repeat(64), "X-Amz-SignedHeaders": "host;x-mscqr-component-binding" } };
    const principal = `arn:aws:sts::368992683803:assumed-role/${role}/component-${transitionId}`;
    const issued = purpose === "CLEANUP" ? Math.floor(f.clock / 1000) * 1000 : f.sessionIssuedAt;
    const issuance = { eventID: f.sessionEventId, eventTime: new Date(issued).toISOString(), eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: "eu-west-2", recipientAccountId: "368992683803",
      userIdentity: { type: "IAMUser", accountId: "368992683803", arn: "arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator", sessionContext: { attributes: { mfaAuthenticated: "true" } } },
      requestParameters: { roleArn: `arn:aws:iam::368992683803:role/${role}`, roleSessionName: `component-${transitionId}`, durationSeconds: 900 },
      responseElements: { credentials: { accessKeyId: key, expiration: new Date(issued + 900000).toISOString() }, assumedRoleUser: { arn: principal, assumedRoleId: "role-id:session" } } };
    const event = operation === "CLEANUP_CONTEXT" ? { operation, ...fields } : operation === "AUTHORIZE" ? { operation, authorization, ...fields } : { operation, transitionId, authorizationSha256: digest(authorization), proof, ...fields };
    return executeFixedBroker(event, { functionVersion: version, invokedFunctionArn: `${componentBrokerArn}:${version}` }, { manifest, iam, s3, lambda, currentMain: async () => f.main, now: () => f.clock,
      sts: async (request) => { assert.equal(request.headers["x-mscqr-component-binding"], sessionProofBinding(binding)); return { Account: "368992683803", Arn: principal, UserId: "role-id:session" }; }, issuanceEvents: async () => f.issuanceMissing ? [] : [issuance] });
  };
  return f;
}

test("proof readiness authenticates issuance without claiming a session or writing IAM/S3", async () => {
  const f = fixture(); await f.run("AUTHORIZE");
  const before = JSON.stringify([...f.objects]);
  for (const operation of ["PROVE_INSTALL_SESSION", "PROVE_CLEANUP_SESSION"]) {
    f.issuanceMissing = true; await assert.rejects(f.run(operation));
    f.issuanceMissing = false;
    const proof = await f.run(operation);
    assert.equal(proof.state, "SESSION_VERIFIED");
    assert.equal(proof.transitionId, transitionId);
    assert.equal(JSON.stringify([...f.objects]), before);
    assert.deepEqual(f.writes, []);
    await assert.rejects(f.run(operation, {}, operation === "PROVE_INSTALL_SESSION" ? "2" : "1"));
  }
});

test("cleanup context reads the fixed authenticated archive after expiry without mutating it", async () => {
  const f = fixture();
  await f.run("AUTHORIZE");
  const before = JSON.stringify([...f.objects]);
  f.clock += 91 * 24 * 3600000;
  f.main = "d".repeat(40);
  assert.deepEqual(await f.run("CLEANUP_CONTEXT"), { sourceSha, transitionId, authorizationSha256: digest(f.authorization), purpose: "CLEANUP" });
  assert.equal(JSON.stringify([...f.objects]), before);
  assert.deepEqual(f.writes, []);
  for (const fields of [{ key: "alternate" }, { transitionId }, { authorizationSha256: "d".repeat(64) }]) await assert.rejects(f.run("CLEANUP_CONTEXT", fields));
  for (const version of ["1", "3", "$LATEST"]) await assert.rejects(f.run("CLEANUP_CONTEXT", {}, version));
  f.resourcePolicy = "2";
  await assert.rejects(f.run("CLEANUP_CONTEXT"), /resource-based/);
});

for (const qualifier of ["$LATEST", "1", "2", "3"]) test(`broker rejects a resource policy bypass on ${qualifier}`, async () => {
  const f = fixture();
  f.resourcePolicy = qualifier;
  await assert.rejects(f.run("AUTHORIZE"), /resource-based invocation policy/);
  assert.deepEqual(f.writes, []);
});

test("broker cannot mistake denied policy readback for absence", async () => {
  const f = fixture();
  f.policyReadDenied = true;
  await assert.rejects(f.run("AUTHORIZE"), /AccessDeniedException/);
  assert.deepEqual(f.writes, []);
});

test("real broker requires session proof; no local marker or missing proof can reach IAM writes", async () => {
  const f = fixture();
  await f.run("AUTHORIZE");
  for (const fields of [{ proof: undefined }, { proof: { mfaAuthenticated: true } }, { session: { expiresAt: "2099-01-01T00:00:00Z" } }]) await assert.rejects(f.run("INSTALL", fields));
  assert.deepEqual(f.writes, []);
});

test("AWS expiry during installation stops the next IAM mutation and retains exact partial state", async () => {
  const f = fixture();
  await f.run("AUTHORIZE");
  f.afterWrite = (operation) => { if (operation === "CreateRole") f.clock = start + 900000; };
  await assert.rejects(f.run("INSTALL"), /session expired/);
  assert.deepEqual(f.writes, ["CreateRole"]);
  assert.equal(f.policies.size, 0);
  const durable = JSON.stringify([...f.objects.values()]);
  assert(!durable.includes("disposable-session-fixture"));
  assert(!durable.includes(["A", "S", "I", "A"].join("") + "0".repeat(16)));
  assert.equal(f.objects.get(`${prefix}installation-session.json`).value.session.expiresAt, new Date(start + 900000).toISOString());
});

test("expired partial installation resumes only after fresh approval, readback and a fenced new AWS session", async () => {
  const f = fixture();
  await f.run("AUTHORIZE");
  const oldHash = digest(f.authorization);
  f.afterWrite = (operation) => { if (operation === "CreateRole") f.clock = start + 900000; };
  await assert.rejects(f.run("INSTALL"), /session expired/);
  f.afterWrite = () => {};
  f.clock = start + 1020000;
  Object.assign(f.authorization, { runId: "12346", approvalObservedAt: new Date(f.clock).toISOString(), expiresAt: new Date(f.clock + 1800000).toISOString() });
  await assert.rejects(f.run("AUTHORIZE"), /not safely expired/);
  assert.equal(f.objects.get(`${prefix}installation-authorization.json`).value.authorizationSha256, oldHash);
  f.clock += 1000;
  await f.run("AUTHORIZE");
  await assert.rejects(f.run("INSTALL", { authorizationSha256: oldHash }));
  // A new approval alone cannot make an old AWS session current again.
  await assert.rejects(f.run("INSTALL"));
  f.sessionIssuedAt = f.clock;
  f.sessionEventId = "12345678-1234-4234-8234-123456789aaa";
  assert.equal((await f.run("INSTALL")).state, "IAM_VERIFIED");
  assert.deepEqual(f.writes, ["CreateRole", "PutRolePolicy", "CreateRole", "PutRolePolicy", "PutRolePolicy"]);
  assert.equal(f.objects.get(`${prefix}installation-session.json`).value.history.length, 1);
  assert.equal(f.objects.get(`${prefix}installation-authorization.json`).value.history.length, 1);
  await f.run("CLOSE");
  f.authorization.runId = "12347";
  f.authorization.approvalObservedAt = new Date(f.clock + 1).toISOString();
  f.clock++;
  await assert.rejects(f.run("AUTHORIZE"), /Closed authorization/);
});

test("fresh approval cannot replace the archive when partial live IAM has different bytes", async () => {
  const f = fixture();
  await f.run("AUTHORIZE");
  const oldHash = digest(f.authorization);
  f.afterWrite = (operation) => { if (operation === "CreateRole") throw new Error("Lost runner"); };
  await assert.rejects(f.run("INSTALL"), /Lost runner/);
  f.afterWrite = () => {};
  f.clock = start + 1021000;
  Object.assign(f.authorization, { runId: "12346", approvalObservedAt: new Date(f.clock).toISOString(), expiresAt: new Date(f.clock + 1800000).toISOString() });
  f.roles.get(f.manifest.targets[0].role).AssumeRolePolicyDocument = { Version: "2012-10-17", Statement: [] };
  await assert.rejects(f.run("AUTHORIZE"), /Unexpected trust/);
  assert.equal(f.objects.get(`${prefix}installation-authorization.json`).value.authorizationSha256, oldHash);
  assert.deepEqual(f.writes, ["CreateRole"]);
});

for (const [operation, mutate] of [
  ["GetRole", (response) => { response.Role.PermissionsBoundary = { PermissionsBoundaryArn: "unexpected" }; }],
  ["GetRolePolicy", (response) => { response.PolicyDocument.Statement.push({ Effect: "Allow", Action: "iam:*", Resource: "*" }); }],
  ["ListAttachedRolePolicies", (response) => { response.AttachedPolicies = [{ PolicyName: "unexpected" }]; }],
  ["ListRolePolicies", (response) => { response.PolicyNames.push("unexpected"); }],
  ["ListRoleTags", (response) => { response.Tags.push({ Key: "unexpected", Value: "extra" }); }],
]) test(`fixed broker rejects execution authority drift: ${operation}`, async () => {
  const f = fixture();
  f.configureIdentity = (observed, response) => { if (observed === operation) mutate(response); };
  await assert.rejects(f.run("AUTHORIZE"));
  assert.deepEqual(f.writes, []);
});

test("bootstrapped fixed broker: authorize -> install exact five writes -> idempotent readback -> durable close", async () => {
  const f = fixture();
  await assert.rejects(f.run("INSTALL"), /No durable authorization/);
  await f.run("AUTHORIZE");
  assert.equal((await f.run("INSTALL")).state, "IAM_VERIFIED");
  assert.deepEqual(f.writes, ["CreateRole", "PutRolePolicy", "CreateRole", "PutRolePolicy", "PutRolePolicy"]);
  await f.run("INSTALL"); assert.equal(f.writes.length, 5);
  f.clock += 100 * 86400000;
  assert.equal((await f.run("CLOSE")).state, "CLOSED");
  await f.run("CLOSE"); assert.equal(f.writes.length, 5);
  await assert.rejects(f.run("INSTALL"));
});

test("cleanup before any installation writes closes authorization without creating or deleting IAM", async () => {
  const f = fixture(); await f.run("AUTHORIZE");
  assert.equal((await f.run("CLOSE")).state, "CLOSED");
  await assert.rejects(f.run("INSTALL"), /consumed/);
  assert.deepEqual(f.writes, []);
});

test("installer credentials used directly cannot archive approval or select replacement documents", async () => {
  const f = fixture();
  await assert.rejects(f.run("AUTHORIZE", {}, "1"));
  await f.run("AUTHORIZE");
  for (const field of ["role", "roleArn", "policyName", "policy", "trust", "sourceSha", "s3Key", "manifest"]) await assert.rejects(f.run("INSTALL", { [field]: "override" }));
  await assert.rejects(f.run("INSTALL", {}, "2"));
  assert.deepEqual(f.writes, []);
});

for (const [field, replacement] of Object.entries({ CodeSha256: Buffer.alloc(32).toString("base64"), Role: "other", Environment: { Variables: { PRIVATE_TEST_MARKER: "do-not-include-in-error" } }, Layers: [{ Arn: "unknown" }], VpcConfig: { VpcId: "other" } })) {
  test(`real dispatch rejects bootstrapped broker drift: ${field}`, async () => {
    const f = fixture(); f.configure = (config) => { config[field] = replacement; };
    await assert.rejects(f.run("AUTHORIZE"), (error) => !String(error).includes("do-not-include-in-error"));
    assert.deepEqual(f.writes, []);
  });
}

test("ambiguous successful IAM writes are reconciled, not replayed", async () => {
  for (let failAt = 1; failAt <= 5; failAt++) {
    const f = fixture(); await f.run("AUTHORIZE");
    f.afterWrite = (operation) => { if (["CreateRole", "PutRolePolicy"].includes(operation) && f.writes.length === failAt) throw fault("ResponseLost"); };
    await assert.rejects(f.run("INSTALL"), /ResponseLost/);
    f.afterWrite = () => {};
    assert.equal((await f.run("INSTALL")).state, "IAM_VERIFIED");
    assert.equal(f.writes.length, 5);
  }
});

test("an unfinished or substituted bootstrap record cannot authorize any broker writes", async () => {
  for (const field of ["sourceSha", "state", "manifestSha256", "identitySetSha256", "packageSha256"]) {
    const f = fixture(); f.bootstrap[field] = "different";
    await assert.rejects(f.run("AUTHORIZE"));
    assert.deepEqual(f.writes, []);
  }
});
