import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createInstallationHandler } from "../aws/component-iam-broker.mjs";
import { installationDocuments, documentBindings, digest, installationIdentity } from "../aws/component-iam-installation-contract.mjs";

// Offline contract tests. Run: node --test scripts/tests/component-iam-broker.test.mjs
// Faults before a write model rejection; faults after it model a lost response.
const instant = Date.parse("2026-09-17T12:00:00Z");
const emptyPolicy = { Version: "2012-10-17", Statement: [] };
const error = (name, status) => Object.assign(new Error(name), { name, $metadata: { httpStatusCode: status } });
const mutations = new Set(["CreateRole", "PutRolePolicy"]);
const encoded = (value) => encodeURIComponent(JSON.stringify(value));

function fixture() {
  const manifest = {
    account: installationIdentity.account,
    sourceSha: "a".repeat(40),
    transitionId: "a0b1c2d3-1234-4567-89ab-0123456789ab",
    expiresAt: new Date(instant + 60_000).toISOString(),
    authorizationSha256: digest({ authorization: "offline-fixture" }),
    targets: installationDocuments(),
    documentBindingsSha256: digest(documentBindings()),
  };
  const roles = new Map();
  const policies = new Map();
  const calls = [];
  const writes = [];
  const commits = [];
  const f = { manifest, roles, policies, calls, writes, commits, clock: instant,
    source: manifest.sourceSha, object: null, version: 0,
    beforeIam: () => {}, afterIam: () => {}, beforeS3: () => {}, afterS3: () => {},
  };
  const targetFor = (input) => {
    const target = manifest.targets.find(({ role }) => role === input.RoleName);
    assert(target, `Unexpected IAM target: ${input.RoleName}`);
    return target;
  };
  const roleFor = (target) => ({
    RoleName: target.role, RoleId: "AROAEXAMPLE00000000000", Arn: target.arn,
    Path: "/", MaxSessionDuration: 3600, CreateDate: new Date(instant),
    AssumeRolePolicyDocument: encoded(target.trust || emptyPolicy),
    Tags: [{ Key: "ManagedBy", Value: "GuardedComponentInstaller" },
      { Key: "Environment", Value: "production" }, { Key: "Transition", Value: manifest.transitionId }],
  });
  f.seed = (state = "IAM_INSTALLING", complete = false) => {
    if (complete) for (const target of manifest.targets) {
      roles.set(target.role, roleFor(target));
      policies.set(target.role, new Map([[target.policyName, structuredClone(target.policy)]]));
    }
    f.object = { ETag: `"version-${++f.version}"`, Body: JSON.stringify({
      schemaVersion: 1, sourceSha: manifest.sourceSha, transitionId: manifest.transitionId,
      authorizationSha256: manifest.authorizationSha256,
      documentBindingsSha256: manifest.documentBindingsSha256, state,
      live: manifest.targets.map(({ arn, role, policyName }) => ({ arn,
        role: roles.has(role) ? "EXPECTED" : "ABSENT",
        policy: policies.get(role)?.has(policyName) ? "EXPECTED" : "ABSENT" })),
    }) };
  };
  f.ledger = () => f.object && JSON.parse(f.object.Body);
  roles.set(manifest.targets[2].role, roleFor(manifest.targets[2]));
  f.iam = async (operation, input) => {
    calls.push({ service: "iam", operation, input: structuredClone(input) });
    const target = targetFor(input);
    await f.beforeIam(operation, input);
    let result;
    const role = roles.get(input.RoleName);
    switch (operation) {
      case "GetRole":
        if (!role) throw error("NoSuchEntity", 404);
        result = { Role: structuredClone(role) };
        break;
      case "GetRolePolicy": {
        const policy = policies.get(input.RoleName)?.get(input.PolicyName);
        if (!role || !policy) throw error("NoSuchEntity", 404);
        result = { RoleName: input.RoleName, PolicyName: input.PolicyName, PolicyDocument: encoded(policy) };
        break;
      }
      case "ListAttachedRolePolicies":
        if (!role) throw error("NoSuchEntity", 404);
        result = { AttachedPolicies: [], IsTruncated: false };
        break;
      case "ListRolePolicies":
        if (!role) throw error("NoSuchEntity", 404);
        result = { PolicyNames: [...(policies.get(input.RoleName)?.keys() || [])], IsTruncated: false };
        break;
      case "CreateRole":
        assert.deepEqual(Object.keys(input).sort(), ["AssumeRolePolicyDocument", "MaxSessionDuration", "Path", "RoleName", "Tags"]);
        assert.deepEqual(JSON.parse(input.AssumeRolePolicyDocument), target.trust);
        assert.equal(input.Path, "/");
        assert.equal(input.MaxSessionDuration, 3600);
        assert.deepEqual(input.Tags, roleFor(target).Tags);
        if (role) throw error("EntityAlreadyExists", 409);
        roles.set(input.RoleName, { ...roleFor(target), AssumeRolePolicyDocument: encoded(JSON.parse(input.AssumeRolePolicyDocument)) });
        writes.push({ operation, input: structuredClone(input) });
        result = { Role: structuredClone(roles.get(input.RoleName)) };
        break;
      case "PutRolePolicy":
        assert.deepEqual(Object.keys(input).sort(), ["PolicyDocument", "PolicyName", "RoleName"]);
        assert.equal(input.PolicyName, target.policyName);
        assert.deepEqual(JSON.parse(input.PolicyDocument), target.policy);
        if (!role) throw error("NoSuchEntity", 404);
        if (!policies.has(input.RoleName)) policies.set(input.RoleName, new Map());
        // IAM overwrites an existing inline policy: do not hide duplicate writes.
        policies.get(input.RoleName).set(input.PolicyName, JSON.parse(input.PolicyDocument));
        writes.push({ operation, input: structuredClone(input) });
        result = {};
        break;
      default: assert.fail(`Unexpected IAM operation: ${operation}`);
    }
    result.$metadata = { httpStatusCode: 200 };
    await f.afterIam(operation, input, result);
    return result;
  };
  f.s3 = async (operation, input) => {
    calls.push({ service: "s3", operation, input: structuredClone(input) });
    assert.equal(input.Bucket, "mscqr-production-terraform-state-368992683803-eu-west-2");
    assert.equal(input.Key || input.Prefix, "mscqr/production/component-deployment-state/iam-installation.json");
    await f.beforeS3(operation, input);
    let result;
    if (operation === "ListObjectsV2") {
      assert.deepEqual(Object.keys(input).sort(), ["Bucket", "Prefix"]);
      result = { IsTruncated: false, Contents: f.object ? [{ Key: input.Prefix }] : [] };
    } else if (operation === "GetObject") {
      assert.deepEqual(Object.keys(input).sort(), ["Bucket", "Key"]);
      if (!f.object) throw error("NoSuchKey", 404);
      const snapshot = structuredClone(f.object);
      result = { ETag: snapshot.ETag, Body: { transformToString: async () => snapshot.Body } };
    } else {
      assert.equal(operation, "PutObject");
      assert.equal(input.ServerSideEncryption, "AES256");
      assert.equal(typeof input.Body, "string");
      assert.notEqual(Boolean(input.IfMatch), Boolean(input.IfNoneMatch), "Exactly one CAS condition required");
      if (input.IfNoneMatch) {
        assert.equal(input.IfNoneMatch, "*");
        if (f.object) throw error("PreconditionFailed", 412);
      } else if (!f.object || f.object.ETag !== input.IfMatch) throw error("PreconditionFailed", 412);
      f.object = { ETag: `"version-${++f.version}"`, Body: input.Body };
      commits.push(JSON.parse(input.Body));
      result = { ETag: f.object.ETag };
    }
    result.$metadata = { httpStatusCode: 200 };
    await f.afterS3(operation, input, result);
    return result;
  };
  f.run = (event = { operation: "INSTALL", transitionId: manifest.transitionId }) => createInstallationHandler({
    manifest, iam: f.iam, s3: f.s3, currentMain: async () => f.source, now: () => f.clock,
  })(event);
  return f;
}

function assertInstalled(f) {
  assert.equal(f.ledger().state, "IAM_VERIFIED");
  assert.deepEqual(f.ledger().live, f.manifest.targets.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })));
  assert.equal(f.writes.filter(({ operation }) => operation === "CreateRole").length, 2);
  assert.equal(f.writes.filter(({ operation }) => operation === "PutRolePolicy").length, 3);
  assert.equal(new Set(f.writes.map(({ operation, input }) => `${operation}:${input.RoleName}`)).size, 5);
}

test("INSPECT -> ABSENT; INSTALL -> IAM_INSTALLING -> IAM_VERIFIED; verified retries are read-only", async () => {
  const f = fixture();
  assert.equal((await f.run({ operation: "INSPECT", transitionId: f.manifest.transitionId })).state, "ABSENT");
  assert.equal(f.writes.length, 0);
  assert.equal(f.commits.length, 0);
  assert.equal((await f.run()).state, "IAM_VERIFIED");
  assertInstalled(f);
  assert.deepEqual(f.commits.map(({ state }) => state), ["IAM_INSTALLING", "IAM_VERIFIED"]);
  const puts = f.calls.filter(({ service, operation }) => service === "s3" && operation === "PutObject");
  assert.equal(puts[0].input.IfNoneMatch, "*");
  assert.equal(puts[1].input.IfMatch, '"version-1"');
  const firstWrite = f.calls.findIndex(({ operation }) => mutations.has(operation));
  assert(f.calls.findIndex(({ operation }) => operation === "PutObject") < firstWrite);
  await f.run();
  assert.equal((await f.run({ operation: "INSPECT", transitionId: f.manifest.transitionId })).state, "IAM_VERIFIED");
  assertInstalled(f);
  assert.equal(f.commits.length, 2);
});

for (const [index, target] of installationDocuments().entries()) for (const operation of target.trust ? ["CreateRole", "PutRolePolicy"] : ["PutRolePolicy"]) for (const phase of ["beforeIam", "afterIam"]) {
  test(`${operation} target ${index + 1} ${phase === "beforeIam" ? "rejected" : "committed with lost response"}: abort and resume without duplicate writes`, async () => {
    const f = fixture();
    let fired = false;
    f[phase] = (name, input) => {
      if (name === operation && input.RoleName === target.role && !fired) { fired = true; throw error("ServiceFailure", 500); }
    };
    await assert.rejects(f.run(), { name: "ServiceFailure" });
    assert.equal(f.ledger().state, "IAM_INSTALLING");
    assert.equal(f.calls.filter((call) => call.operation === operation && call.input.RoleName === target.role).length, 1, "No same-invocation retry");
    const writes = f.writes.length;
    assert.equal((await f.run({ operation: "INSPECT", transitionId: f.manifest.transitionId })).state, "IAM_INSTALLING");
    assert.equal(f.writes.length, writes);
    await f.run();
    assertInstalled(f);
  });
}

for (const state of ["IAM_INSTALLING", "IAM_VERIFIED"]) for (const phase of ["beforeS3", "afterS3"]) {
  test(`${state} journal ${phase === "beforeS3" ? "commit fails" : "commits but response is lost"}: retry reconciles persisted state`, async () => {
    const f = fixture();
    let fired = false;
    f[phase] = (operation, input) => {
      if (operation === "PutObject" && JSON.parse(input.Body).state === state && !fired) {
        fired = true;
        throw error("ServiceUnavailable", 503);
      }
    };
    await assert.rejects(f.run(), { name: "ServiceUnavailable" });
    assert.equal(f.writes.length, state === "IAM_INSTALLING" ? 0 : 5);
    assert.equal(f.ledger()?.state ?? null, phase === "afterS3" ? state : state === "IAM_INSTALLING" ? null : "IAM_INSTALLING");
    await f.run();
    assertInstalled(f);
    assert.deepEqual(f.commits.map(({ state: value }) => value), ["IAM_INSTALLING", "IAM_VERIFIED"]);
  });
}

for (const state of ["IAM_INSTALLING", "IAM_VERIFIED"]) {
  test(`${state} CAS conflict rejects a competing journal version`, async () => {
    const f = fixture();
    let fired = false;
    f.beforeS3 = (operation, input) => {
      if (operation === "PutObject" && JSON.parse(input.Body).state === state && !fired) {
        fired = true;
        f.object = { Body: input.Body, ETag: '"competing-version"' };
      }
    };
    await assert.rejects(f.run(), { name: "PreconditionFailed" });
    assert.equal(f.object.ETag, '"competing-version"');
    assert.equal(f.writes.length, state === "IAM_INSTALLING" ? 0 : 5);
    await f.run();
    assertInstalled(f);
  });
}

for (const [label, alter] of [
  ["wrong trust", (f) => { f.roles.get(f.manifest.targets[0].role).AssumeRolePolicyDocument = encoded(emptyPolicy); }],
  ["wrong inline policy", (f) => { const t = f.manifest.targets[0]; f.policies.get(t.role).set(t.policyName, emptyPolicy); }],
  ["wrong release inline policy", (f) => { const t = f.manifest.targets[2]; f.policies.get(t.role).set(t.policyName, emptyPolicy); }],
  ["wrong ARN", (f) => { f.roles.get(f.manifest.targets[0].role).Arn += "-other"; }],
  ["wrong path", (f) => { f.roles.get(f.manifest.targets[0].role).Path = "/other/"; }],
  ["wrong session duration", (f) => { f.roles.get(f.manifest.targets[0].role).MaxSessionDuration = 7200; }],
  ["missing tags", (f) => { delete f.roles.get(f.manifest.targets[0].role).Tags; }],
  ["wrong transition tag", (f) => { f.roles.get(f.manifest.targets[0].role).Tags[2].Value = "other"; }],
  ["permissions boundary", (f) => { f.roles.get(f.manifest.targets[0].role).PermissionsBoundary = { PermissionsBoundaryArn: "arn:aws:iam::368992683803:policy/other", PermissionsBoundaryType: "Policy" }; }],
  ["extra inline policy", (f) => { f.policies.get(f.manifest.targets[0].role).set("Unapproved", emptyPolicy); }],
  ["missing release role", (f) => { f.roles.delete(f.manifest.targets[2].role); }],
]) test(`live ${label} fails closed before writes`, async () => {
  const f = fixture();
  f.seed("IAM_INSTALLING", true);
  alter(f);
  await assert.rejects(f.run(), { name: "AssertionError" });
  assert.equal(f.writes.length, 0);
  assert.equal(f.commits.length, 0);
});

for (const [label, operation, response] of [
  ["attached policy", "ListAttachedRolePolicies", { AttachedPolicies: [{ PolicyName: "Other", PolicyArn: "arn:aws:iam::368992683803:policy/Other" }] }],
  ["truncated attached policies", "ListAttachedRolePolicies", { IsTruncated: true, Marker: "next" }],
  ["missing attached pagination flag", "ListAttachedRolePolicies", { IsTruncated: undefined }],
  ["missing attached array", "ListAttachedRolePolicies", { AttachedPolicies: undefined }],
  ["truncated inline policies", "ListRolePolicies", { IsTruncated: true, Marker: "next" }],
  ["missing inline pagination flag", "ListRolePolicies", { IsTruncated: undefined }],
  ["missing inline array", "ListRolePolicies", { PolicyNames: undefined }],
  ["unexpected inline name", "ListRolePolicies", { PolicyNames: ["Other"] }],
]) test(`observe rejects ${label}`, async () => {
  const f = fixture();
  f.seed("IAM_INSTALLING", true);
  f.afterIam = (name, input, result) => { if (name === operation) Object.assign(result, response); };
  await assert.rejects(f.run(), { name: "AssertionError" });
  assert.equal(f.writes.length, 0);
  assert.equal(f.commits.length, 0);
});

for (const extra of [{ extra: true }, { policy: emptyPolicy }, { trust: emptyPolicy }, { targets: [] }, { manifest: {} }]) {
  test(`event rejects caller-supplied ${Object.keys(extra)[0]} before dependencies`, async () => {
    const f = fixture();
    await assert.rejects(f.run({ operation: "INSTALL", transitionId: f.manifest.transitionId, ...extra }), { name: "AssertionError" });
    assert.equal(f.calls.length, 0);
  });
}

for (const field of ["policy", "trust", "policySha256", "trustSha256", "documentBindingsSha256"]) {
  test(`manifest rejects replaced ${field} before dependencies`, async () => {
    const f = fixture();
    if (field === "documentBindingsSha256") f.manifest[field] = "0".repeat(64);
    else f.manifest.targets[0][field] = field.endsWith("Sha256") ? "0".repeat(64) : emptyPolicy;
    await assert.rejects(f.run(), { name: "AssertionError" });
    assert.equal(f.calls.length, 0);
  });
}

for (const field of ["transitionId", "sourceSha", "authorizationSha256", "state"]) {
  test(`journal rejects another ${field} before IAM observation`, async () => {
    const f = fixture();
    f.seed();
    const ledger = f.ledger();
    ledger[field] = field === "state" ? "CONSUMED" : field === "transitionId" ? "b0b1c2d3-1234-4567-89ab-0123456789ab" : "b".repeat(field === "sourceSha" ? 40 : 64);
    f.object.Body = JSON.stringify(ledger);
    await assert.rejects(f.run(), { name: "AssertionError" });
    assert.deepEqual(f.calls.map(({ operation }) => operation), ["ListObjectsV2", "GetObject"]);
  });
}

for (const guard of ["source", "expiry"]) for (const checkpoint of ["entry", "journal", "CreateRole", "PutRolePolicy"]) {
  test(`${guard} changes at ${checkpoint}: next mutation is blocked`, async () => {
    const f = fixture();
    const invalidate = () => { if (guard === "source") f.source = "b".repeat(40); else f.clock = Date.parse(f.manifest.expiresAt); };
    if (checkpoint === "entry") invalidate();
    else if (checkpoint === "journal") f.afterS3 = (operation) => { if (operation === "PutObject") invalidate(); };
    else f.afterIam = (operation) => { if (operation === checkpoint) invalidate(); };
    await assert.rejects(f.run(), guard === "source" ? /Protected source moved/ : /Authorization expired/);
    assert.equal(f.writes.length, checkpoint === "CreateRole" ? 1 : checkpoint === "PutRolePolicy" ? 2 : 0);
    assert.equal(f.commits.length, checkpoint === "entry" ? 0 : 1);
  });
}

test("IAM read access errors are not treated as absence", async () => {
  const f = fixture();
  f.beforeIam = () => { throw error("AccessDenied", 403); };
  await assert.rejects(f.run(), { name: "AccessDenied" });
  assert.equal(f.writes.length, 0);
  assert.equal(f.commits.length, 0);
});

test("S3 read access errors are not treated as an empty journal", async () => {
  const f = fixture();
  f.beforeS3 = () => { throw error("AccessDenied", 403); };
  await assert.rejects(f.run(), { name: "AccessDenied" });
  assert.equal(f.writes.length, 0);
  assert.equal(f.commits.length, 0);
});

test("a successful but not yet visible IAM write stops before subsequent mutation", async () => {
  const f = fixture();
  f.afterIam = (operation) => {
    if (operation === "CreateRole") f.beforeIam = (name, input) => {
      if (name === "GetRole" && input.RoleName === f.manifest.targets[0].role) throw error("NoSuchEntity", 404);
    };
  };
  await assert.rejects(f.run(), /Role creation not yet authenticated/);
  assert.equal(f.writes.length, 1);
  assert.equal(f.ledger().state, "IAM_INSTALLING");
  f.beforeIam = () => {};
  f.afterIam = () => {};
  await f.run();
  assertInstalled(f);
});

// Consumed receipts are read-only unless the controller pins a fresh approval.
test("VERIFIED must not rewrite a subsequently missing inline policy", async () => {
  const f = fixture();
  f.seed("IAM_VERIFIED", true);
  const target = f.manifest.targets[0];
  f.policies.get(target.role).delete(target.policyName);
  // Allow either a read-only report or rejection, but never a new IAM write.
  try { await f.run(); } catch (cause) { assert.equal(cause.name, "AssertionError"); }
  assert.equal(f.writes.length, 0, "A consumed VERIFIED installation must not regain write authority");
  assert.equal(f.commits.length, 0);
});

test("journal with mismatched document bindings must reject before IAM writes", async () => {
  const f = fixture();
  f.seed();
  f.object.Body = JSON.stringify({ ...f.ledger(), documentBindingsSha256: "0".repeat(64) });
  let rejected = false;
  try { await f.run(); } catch (cause) { assert.equal(cause.name, "AssertionError"); rejected = true; }
  assert.equal(f.writes.length, 0, "Journal document bindings must match the immutable manifest");
  assert(rejected, "Mismatched journal bindings must be rejected");
  assert.equal(f.commits.length, 0);
});

for (const state of ["IAM_INSTALLING", "IAM_VERIFIED"]) test(`fresh pinned authorization reconciles ${state} without replaying completed writes`, async () => {
  const f = fixture();
  f.seed(state, state === "IAM_VERIFIED");
  const previous = f.manifest.authorizationSha256;
  f.manifest.authorizedPredecessors = [{ authorizationSha256: previous, sourceSha: f.manifest.sourceSha, documentBindingsSha256: f.manifest.documentBindingsSha256 }];
  f.manifest.authorizationSha256 = digest({ authorization: "fresh-offline-fixture" });
  await f.run();
  assert.equal(f.ledger().state, "IAM_VERIFIED");
  assert(f.ledger().live.every(({ role, policy }) => role === "EXPECTED" && policy === "EXPECTED"));
  assert.equal(f.ledger().authorizationSha256, f.manifest.authorizationSha256);
  if (state === "IAM_VERIFIED") assert.equal(f.writes.length, 0);
  const writes = f.writes.length;
  await f.run();
  assert.equal(f.writes.length, writes);
});

test("renewal cannot consume a different authorization's journal", async () => {
  const f = fixture(); f.seed();
  f.manifest.authorizedPredecessors = [{ authorizationSha256: digest({ unrelated: true }), sourceSha: f.manifest.sourceSha, documentBindingsSha256: f.manifest.documentBindingsSha256 }];
  f.manifest.authorizationSha256 = digest({ fresh: true });
  await assert.rejects(f.run(), /Unbound prior authorization/);
  assert.equal(f.writes.length, 0);
  assert.equal(f.commits.length, 0);
});

test("renewal CAS failure prevents remaining IAM mutations", async () => {
  const f = fixture(); f.seed();
  f.manifest.authorizedPredecessors = [{ authorizationSha256: f.manifest.authorizationSha256, sourceSha: f.manifest.sourceSha, documentBindingsSha256: f.manifest.documentBindingsSha256 }];
  f.manifest.authorizationSha256 = digest({ fresh: true });
  f.beforeS3 = (operation) => { if (operation === "PutObject") throw error("PreconditionFailed", 412); };
  await assert.rejects(f.run(), /PreconditionFailed/);
  assert.equal(f.writes.length, 0);
});

test("renewal migrates only an exact predecessor-source verified ledger", async () => {
  const f = fixture(); f.seed("IAM_VERIFIED", true);
  const previous = f.manifest.authorizationSha256, sourceSha = "b".repeat(40);
  f.object.Body = JSON.stringify({ ...f.ledger(), sourceSha });
  f.manifest.authorizedPredecessors = [{ authorizationSha256: previous, sourceSha, documentBindingsSha256: f.manifest.documentBindingsSha256 }];
  f.manifest.authorizationSha256 = digest({ authorization: "fresh-predecessor-migration" });
  await f.run();
  assert.equal(f.ledger().sourceSha, f.manifest.sourceSha);
  assert.equal(f.ledger().authorizationSha256, f.manifest.authorizationSha256);
  assert.equal(f.writes.length, 0);
});

for (const [field, value] of [["sourceSha", "c".repeat(40)], ["documentBindingsSha256", "c".repeat(64)]]) test(`renewal rejects a substituted predecessor ${field}`, async () => {
  const f = fixture(); f.seed("IAM_VERIFIED", true);
  const previous = f.manifest.authorizationSha256, sourceSha = "b".repeat(40);
  f.object.Body = JSON.stringify({ ...f.ledger(), sourceSha });
  f.manifest.authorizedPredecessors = [{ authorizationSha256: previous, sourceSha, documentBindingsSha256: f.manifest.documentBindingsSha256, [field]: value }];
  f.manifest.authorizationSha256 = digest({ authorization: `substituted-${field}` });
  await assert.rejects(f.run(), /Unbound prior authorization/);
  assert.equal(f.writes.length, 0); assert.equal(f.commits.length, 0);
});

test("first-install absence is established by exact listing, never AccessDenied", async () => {
  const f = fixture();
  f.beforeS3 = (operation) => { if (operation === "GetObject") throw error("AccessDenied", 403); };
  await f.run();
  assertInstalled(f);
  const denied = fixture();
  denied.beforeS3 = () => { throw error("AccessDenied", 403); };
  await assert.rejects(denied.run(), /AccessDenied/);
  assert.equal(denied.writes.length, 0);
});

test("production SDK clients disable retries so ambiguity returns to guarded reconciliation", () => {
  const code = fs.readFileSync(new URL("../aws/component-iam-broker.mjs", import.meta.url), "utf8");
  assert.match(code, /const options = \{ region: "eu-west-2", maxAttempts: 1, credentials:/);
  for (const client of ["IAMClient", "S3Client", "LambdaClient"]) assert(code.includes(`${client}(options)`));
});
