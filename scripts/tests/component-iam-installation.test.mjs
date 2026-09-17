import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { run, runCli } from "../aws/component-iam-installation.mjs";
import { createComponentIamAuthorization, componentIamAuthorization as authContract } from "../aws/component-iam-authorization.mjs";
import { installationIdentity as identity, canonical, digest } from "../aws/component-iam-installation-contract.mjs";

// Offline root-controller proof: node --test scripts/tests/component-iam-installation.test.mjs
// Only command transport/clock are injected. Real authorization, MFA provenance,
// ZIP generation/digest, stored-document validation and CAS lifecycle execute.
const start = Date.parse("2026-09-17T12:05:00Z");
const transitionId = "01234567-89ab-4cde-8f01-23456789abcd";
const sourceSha = "a".repeat(40);
const reservationKey = "mscqr/production/component-deployment-state/permission-installation.json";
const receiptKey = "mscqr/production/component-deployment-state/iam-installation.json";
const roleArn = (role) => `arn:aws:iam::${identity.account}:role/${role}`;
const hash = (bytes, encoding = "hex") => crypto.createHash("sha256").update(bytes).digest(encoding);
const awsError = (name) => Object.assign(new Error(name), { stderr: `An error occurred (${name}) when calling the operation` });
const mutating = new Set(["create-role", "put-role-policy", "delete-role-policy", "create-function", "update-function-code", "update-function-configuration", "put-function-concurrency", "invoke"]);

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "component-root-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const original = createComponentIamAuthorization({ runId: "1234", sourceSha, transitionId, createdAt: "2026-09-17T12:00:00Z" }, start);
  fs.writeFileSync(path.join(directory, "authorization.json"), canonical(original));
  execFileSync("/usr/bin/zip", ["-q", "authorization.zip", "authorization.json"], { cwd: directory });
  const archive = fs.readFileSync(path.join(directory, "authorization.zip"));
  const authorizations = new Map([["1234", { authorization: original, archive, createdAt: "2026-09-17T12:00:00Z" }]]);
  const objects = new Map();
  const roles = new Map();
  const policies = new Map();
  const calls = [];
  const f = { clock: start, main: sourceSha, original, objects, roles, policies, calls, fn: null,
    before: () => {}, after: () => {}, mfa: true, principalRole: "mscqr-production-release-deployer" };
  const put = (key, value) => {
    const bytes = canonical(value);
    objects.set(key, { value: structuredClone(value), ETag: `"${crypto.createHash("md5").update(bytes).digest("hex")}"` });
  };
  f.put = put;
  f.record = () => objects.get(reservationKey)?.value;
  f.authorize = (runId) => {
    const createdAt = new Date(f.clock).toISOString();
    const authorization = createComponentIamAuthorization({ runId, sourceSha, transitionId, createdAt }, f.clock);
    const temp = fs.mkdtempSync(path.join(directory, "auth-"));
    fs.writeFileSync(path.join(temp, "authorization.json"), canonical(authorization));
    execFileSync("/usr/bin/zip", ["-q", "authorization.zip", "authorization.json"], { cwd: temp });
    authorizations.set(runId, { authorization, createdAt, archive: fs.readFileSync(path.join(temp, "authorization.zip")) });
  };
  const actor = { login: "T-ej2003", id: 183396573, type: "User" };
  const flag = (args, name) => { const i = args.indexOf(name); assert(i >= 0, `Missing ${name}`); return args[i + 1]; };
  const gh = (args) => {
    const endpoint = args.find((arg) => arg.startsWith(`repos/${identity.repository}/`));
    assert(endpoint);
    const suffix = endpoint.slice(`repos/${identity.repository}/`.length);
    const runId = /^actions\/runs\/(\d+)/.exec(suffix)?.[1] || /^actions\/artifacts\/(\d+)/.exec(suffix)?.[1];
    const auth = runId && authorizations.get(runId);
    if (suffix === "branches/main") return { name: "main", protected: true, commit: { sha: f.main } };
    if (suffix.startsWith("compare/")) return { status: f.main === sourceSha ? "identical" : "ahead", base_commit: { sha: sourceSha }, merge_base_commit: { sha: sourceSha } };
    if (suffix === `actions/runs/${runId}` && auth) return { id: Number(runId), repository: { id: 42, full_name: identity.repository }, head_repository: { id: 42, full_name: identity.repository },
      path: authContract.workflow, head_branch: "main", head_sha: sourceSha, event: "workflow_dispatch", status: "completed", conclusion: "success", run_attempt: 1, actor, triggering_actor: actor, created_at: auth.createdAt };
    if (suffix === `environments/${authContract.environment}`) return { id: 91, name: authContract.environment, can_admins_bypass: false,
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
      protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: actor }] }] };
    if (suffix.endsWith("/deployment-branch-policies")) return { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] };
    if (suffix === `actions/runs/${runId}/approvals` && auth) return [{ state: "approved", user: actor, environments: [{ id: 91, name: authContract.environment }] }];
    if (suffix === `actions/runs/${runId}/artifacts` && auth) return [{ artifacts: [{ id: Number(runId), name: authContract.artifact, expired: false,
      size_in_bytes: auth.archive.length, digest: `sha256:${hash(auth.archive)}`, workflow_run: { id: Number(runId), head_sha: sourceSha, repository_id: 42 } }] }];
    if (suffix === `actions/artifacts/${runId}/zip` && auth) return auth.archive;
    assert.fail(`Unexpected GitHub endpoint ${suffix}`);
  };
  const execute = (command, args, options) => {
    if (command === "/usr/bin/zip") return execFileSync(command, args, options);
    if (command === "git") {
      if (args[0] === "fetch" || args[0] === "status") return "";
      assert.equal(args[0], "rev-parse");
      return f.main;
    }
    if (command === "gh") { const result = gh(args); return Buffer.isBuffer(result) ? result : JSON.stringify(result); }
    assert.equal(command, "aws", "No real cloud/subprocess fallback allowed");
    const [service, operation] = args;
    assert.equal(flag(args, "--output"), "json");
    assert(args.includes("--no-cli-pager"));
    assert([identity.region, "us-east-1"].includes(flag(args, "--region")));
    const call = { service, operation, args: [...args] };
    calls.push(call);
    // Never capture credential values in call logs or assertion diagnostics.
    if (mutating.has(operation) || service === "s3api") assert.equal(options.env.AWS_PROFILE, "default");
    f.before(call);
    const expiration = new Date(f.clock + 3600000).toISOString();
    const caller = { Account: identity.account, Arn: `arn:aws:sts::${identity.account}:assumed-role/${f.principalRole}/operator`, UserId: "AROAEXAMPLE:operator" };
    let result;
    if (service === "sts") result = options.env.AWS_PROFILE === "default" ? { Account: identity.account, Arn: `arn:aws:iam::${identity.account}:root` } : caller;
    else if (service === "configure") {
      assert.equal(operation, "export-credentials");
      assert.equal(options.env.AWS_PROFILE, "mscqr-production-release-deployer");
      assert.equal(flag(args, "--format"), "process");
      result = { AccessKeyId: "offline-key", SecretAccessKey: "offline-secret", SessionToken: "offline-session", Expiration: expiration };
    } else if (service === "cloudtrail") {
      assert.equal(operation, "lookup-events");
      const event = { eventID: transitionId, eventTime: new Date(f.clock - 1000).toISOString(), eventSource: "sts.amazonaws.com", eventName: "AssumeRole", recipientAccountId: identity.account,
        userIdentity: { type: "IAMUser", arn: `arn:aws:iam::${identity.account}:user/mscqr-production-bootstrap-operator`, accountId: identity.account, sessionContext: { attributes: { mfaAuthenticated: String(f.mfa) } } },
        requestParameters: { roleArn: roleArn(f.principalRole) }, responseElements: { credentials: { accessKeyId: "offline-key", expiration }, assumedRoleUser: { arn: caller.Arn, assumedRoleId: caller.UserId } } };
      result = { Events: [{ CloudTrailEvent: JSON.stringify(event) }] };
    } else if (service === "s3api") {
      assert.equal(flag(args, "--bucket"), "mscqr-production-terraform-state-368992683803-eu-west-2");
      const key = flag(args, "--key");
      assert([reservationKey, receiptKey].includes(key));
      const object = objects.get(key);
      if (operation === "get-object") {
        if (!object) throw awsError("NoSuchKey");
        fs.writeFileSync(args[args.indexOf("--key") + 2], canonical(object.value));
        result = { ETag: object.ETag };
      } else {
        assert.equal(operation, "put-object");
        assert.equal(key, reservationKey, "Root never forges broker receipts");
        assert.equal(flag(args, "--server-side-encryption"), "AES256");
        assert.notEqual(args.includes("--if-match"), args.includes("--if-none-match"));
        if (args.includes("--if-none-match")) {
          assert.equal(flag(args, "--if-none-match"), "*");
          if (object) throw awsError("PreconditionFailed");
        } else if (!object || object.ETag !== flag(args, "--if-match")) throw awsError("PreconditionFailed");
        put(key, JSON.parse(fs.readFileSync(flag(args, "--body"))));
        result = { ETag: objects.get(key).ETag };
      }
    } else if (service === "iam") {
      const role = flag(args, "--role-name");
      assert([identity.provisionerRole, identity.terraformRole].includes(role), "Root must never mutate target roles");
      if (operation === "get-role") {
        if (!roles.has(role)) throw awsError("NoSuchEntity");
        result = { Role: structuredClone(roles.get(role)) };
      } else if (operation === "create-role") {
        if (roles.has(role)) throw awsError("EntityAlreadyExists");
        const tags = args.slice(args.indexOf("--tags") + 1, args.indexOf("--region")).map((tag) => {
          const match = /^Key=([^,]+),Value=(.+)$/.exec(tag); assert(match); return { Key: match[1], Value: match[2] };
        });
        roles.set(role, { RoleName: role, Arn: roleArn(role), Path: flag(args, "--path"), MaxSessionDuration: Number(flag(args, "--max-session-duration")), Tags: tags, AssumeRolePolicyDocument: encodeURIComponent(flag(args, "--assume-role-policy-document")) });
        result = { Role: roles.get(role) };
      } else if (operation === "list-attached-role-policies") result = { AttachedPolicies: [], IsTruncated: false };
      else if (operation === "list-role-policies") result = { PolicyNames: [...(policies.get(role)?.keys() || [])], IsTruncated: false };
      else {
        const name = flag(args, "--policy-name");
        assert.equal(name, role === identity.provisionerRole ? "MSCQRComponentIamInstallationTemporary" : "MSCQRComponentTableInstallationTemporary");
        if (operation === "get-role-policy") {
          if (!policies.get(role)?.has(name)) throw awsError("NoSuchEntity");
          result = { RoleName: role, PolicyName: name, PolicyDocument: encodeURIComponent(canonical(policies.get(role).get(name))) };
        } else if (operation === "put-role-policy") {
          if (!roles.has(role)) throw awsError("NoSuchEntity");
          if (!policies.has(role)) policies.set(role, new Map());
          policies.get(role).set(name, JSON.parse(flag(args, "--policy-document")));
          result = {};
        } else {
          assert.equal(operation, "delete-role-policy");
          if (!policies.get(role)?.delete(name)) throw awsError("NoSuchEntity");
          result = {};
        }
      }
    } else {
      assert.equal(service, "lambda");
      assert.equal(flag(args, "--function-name"), identity.functionName);
      if (operation === "get-function") {
        if (!f.fn) throw awsError("ResourceNotFoundException");
        result = structuredClone(f.fn);
      } else if (operation === "create-function") {
        if (f.fn) throw awsError("ResourceConflictException");
        f.fn = { Configuration: { ...structuredClone(f.record().expectedConfig),
          CodeSha256: hash(fs.readFileSync(flag(args, "--zip-file").replace(/^fileb:\/\//, "")), "base64"),
          Description: flag(args, "--description"), Role: flag(args, "--role"), Runtime: flag(args, "--runtime"), Handler: flag(args, "--handler"), Timeout: Number(flag(args, "--timeout")), MemorySize: Number(flag(args, "--memory-size")),
          Environment: { Variables: {} }, State: "Active", LastUpdateStatus: "Successful", RevisionId: "revision-1" } };
        result = f.fn.Configuration;
      } else if (operation === "wait") {
        assert(["function-active-v2", "function-updated-v2"].includes(args[2])); result = {};
      } else if (operation === "update-function-code" || operation === "update-function-configuration") {
        assert(f.fn);
        assert.equal(flag(args, "--revision-id"), f.fn.Configuration.RevisionId);
        assert.equal(f.policyCount(), 0, "No temporary authority during executable replacement");
        assert.equal(f.fn.Concurrency.ReservedConcurrentExecutions, 0);
        if (operation === "update-function-code") f.fn.Configuration.CodeSha256 = hash(fs.readFileSync(flag(args, "--zip-file").replace(/^fileb:\/\//, "")), "base64");
        else f.fn.Configuration.Description = flag(args, "--description");
        f.fn.Configuration.RevisionId += "-next";
        result = f.fn.Configuration;
      } else if (operation === "put-function-concurrency") {
        assert(f.fn);
        f.fn.Concurrency = { ReservedConcurrentExecutions: Number(flag(args, "--reserved-concurrent-executions")) };
        result = f.fn.Concurrency;
      } else {
        assert.equal(operation, "invoke");
        assert.equal(flag(args, "--cli-binary-format"), "raw-in-base64-out");
        const payload = JSON.parse(flag(args, "--payload"));
        assert.deepEqual(payload, { operation: "INSTALL", transitionId });
        // Broker implementation is tested separately. Model its authenticated
        // predecessor contract, never permit an unrelated authorization rewrite.
        const prior = objects.get(receiptKey)?.value;
        if (prior && prior.authorizationSha256 !== f.record().authorizationSha256) assert.equal(prior.authorizationSha256, f.record().manifest.previousAuthorizationSha256);
        put(receiptKey, { schemaVersion: 1, ...Object.fromEntries(["sourceSha", "transitionId", "documentBindingsSha256"].map((key) => [key, f.record().authorization[key]])),
          authorizationSha256: f.record().authorizationSha256, state: "IAM_VERIFIED", live: f.record().manifest.targets.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })) });
        fs.writeFileSync(args[args.indexOf("--payload") + 2], canonical(objects.get(receiptKey).value));
        result = { StatusCode: 200 };
      }
    }
    f.after(call, result);
    return JSON.stringify(result);
  };
  f.run = (mode, overrides = {}) => {
    const work = fs.mkdtempSync(path.join(directory, "work-"));
    return (overrides.cli ? runCli : run)([mode, work, overrides.runId || "1234", overrides.transitionId || transitionId,
      ...(mode.endsWith("-table") ? [overrides.planDirectory || directory] : []),
      ...(mode === "apply-table" ? [overrides.planApprovalRun || "9876"] : [])],
    { execute, now: () => f.clock, env: { PATH: "/usr/bin:/bin" }, ...(f.tableActivation ? { tableActivation: f.tableActivation } : {}), ...(overrides.signals ? { signals: overrides.signals } : {}) });
  };
  f.writes = () => calls.filter(({ operation }) => mutating.has(operation));
  f.policyCount = () => [...policies.values()].reduce((sum, values) => sum + values.size, 0);
  return f;
}

test("activate/install/verified retry/close: exact bytes and durable terminal state", (t) => {
  const f = fixture(t);
  assert.equal(f.run("activate").state, "CAPABILITY_VERIFIED");
  const codeHash = f.record().codeSha256;
  assert.equal(f.record().lease, null);
  assert.equal(f.policyCount(), 2);
  const firstGrant = f.calls.findIndex(({ operation }) => operation === "put-role-policy");
  assert(f.calls.slice(0, firstGrant).some(({ operation }) => operation === "get-function"));
  assert.equal(f.run("install").state, "IAM_VERIFIED");
  assert.equal(f.record().codeSha256, codeHash, "Fresh ZIP reproduces stored bytes");
  assert.equal(f.run("install").state, "IAM_VERIFIED");
  assert.equal(f.calls.filter(({ operation }) => operation === "put-role-policy").length, 2);
  assert.equal(f.run("close").state, "CLOSED");
  assert.equal(f.policyCount(), 0);
  assert.equal(f.roles.size, 2, "Temporary roles are preserved too");
  assert.equal(f.record().lease, null);
  assert.equal(f.run("close").state, "CLOSED");
  assert.throws(() => f.run("activate"), /replay/);
  assert.throws(() => f.run("recover"), /consumed/);
});

for (const kind of ["expired", "main advanced", "both"]) test(`explicit close works with ${kind} and never grants`, (t) => {
  const f = fixture(t);
  f.run("activate");
  if (kind !== "main advanced") f.clock += 3600000;
  if (kind !== "expired") f.main = "b".repeat(40);
  const before = f.writes().length;
  assert.equal(f.run("close").state, "CLOSED");
  assert.deepEqual(f.writes().slice(before).map(({ operation }) => operation), ["delete-role-policy", "delete-role-policy"]);
  assert.equal(f.policyCount(), 0);
});

for (const mode of ["recover", "install"]) test(`expired ${mode} has no AWS mutations`, (t) => {
  const f = fixture(t); f.run("activate"); f.clock += 3600000;
  const before = f.calls.length;
  assert.throws(() => f.run(mode), /expired/);
  assert(!f.calls.slice(before).some(({ operation }) => mutating.has(operation) || operation === "put-object"));
});

for (const mode of ["activate", "recover", "install", "close"]) test(`concurrent ${mode} cannot acquire the root lease`, (t) => {
  const f = fixture(t);
  let attempts = 0;
  f.before = ({ operation }) => {
    if (operation !== "put-role-policy" || attempts++) return;
    assert.throws(() => f.run(mode), /leased|replay|not verified/);
  };
  assert.equal(f.run("activate").state, "CAPABILITY_VERIFIED");
  assert.equal(f.policyCount(), 2);
});

test("recover cannot regrant while close holds the lease", (t) => {
  const f = fixture(t); f.run("activate");
  f.put(reservationKey, { ...f.record(), state: "RESERVED" });
  f.after = ({ operation }) => {
    if (operation === "delete-role-policy") assert.throws(() => f.run("recover"), /consumed/);
  };
  f.run("close");
  assert.equal(f.policyCount(), 0);
  assert.equal(f.record().state, "CLOSED");
});

test("released partial reservation resumes only the same authorization", (t) => {
  const f = fixture(t); f.run("activate");
  f.put(reservationKey, { ...f.record(), state: "RESERVED" });
  f.policies.get(identity.terraformRole).clear();
  const before = f.writes().length;
  assert.equal(f.run("recover").state, "CAPABILITY_VERIFIED");
  assert.equal(f.writes().slice(before).filter(({ operation }) => operation === "put-role-policy").length, 1);
  assert.throws(() => f.run("recover"), /partial/);
  assert.throws(() => f.run("recover", { transitionId: "11234567-89ab-4cde-8f01-23456789abcd" }), /bindings mismatch/);
});

for (const field of ["CodeSha256", "Role", "Runtime", "Handler", "Timeout", "MemorySize", "Layers", "Environment", "Architectures", "Description"]) {
  test(`install rejects changed function ${field}, cleans up, and never invokes`, (t) => {
    const f = fixture(t); f.run("activate");
    f.fn.Configuration[field] = field === "Environment" ? { Variables: { NODE_OPTIONS: "unapproved" } } : "wrong";
    assert.throws(() => f.run("install"), /Unexpected function/);
    assert(!f.calls.some(({ operation }) => operation === "invoke"));
    assert.equal(f.policyCount(), 0);
    assert.equal(f.record().state, "CLOSED");
  });
}

test("unexpected pre-existing executable never receives a policy grant", (t) => {
  const f = fixture(t);
  f.fn = { Configuration: { CodeSha256: "untrusted" } };
  assert.throws(() => f.run("activate"), /Unexpected function/);
  assert(!f.calls.some(({ operation }) => operation === "put-role-policy"));
  assert.equal(f.record().state, "CLOSED");
});

for (const field of ["authorizationSha256", "policies", "capabilities", "manifestHash"]) test(`close rejects corrupted stored ${field} before deletion`, (t) => {
  const f = fixture(t); f.run("activate");
  const record = structuredClone(f.record());
  record[field] = field === "policies" ? { provisioner: {}, terraform: {} } : field === "capabilities" ? {} : "0".repeat(64);
  f.put(reservationKey, record);
  const before = f.writes().length;
  assert.throws(() => f.run("close"));
  assert.equal(f.writes().length, before);
});

test("close preserves unknown inline bytes; resumes exact cleanup after correction", (t) => {
  const f = fixture(t); f.run("activate");
  const name = "MSCQRComponentIamInstallationTemporary";
  const expected = f.policies.get(identity.provisionerRole).get(name);
  f.policies.get(identity.provisionerRole).set(name, { Version: "2012-10-17", Statement: [] });
  assert.throws(() => f.run("close"), /Unknown temporary capability/);
  assert.equal(f.record().state, "CLOSING");
  assert.equal(f.record().lease, null);
  f.policies.get(identity.provisionerRole).set(name, expected);
  assert.equal(f.run("close").state, "CLOSED");
});

for (const phase of ["before", "after"]) test(`ambiguous policy grant (${phase}) auto-cleans exact capabilities`, (t) => {
  const f = fixture(t); let fired = false;
  f[phase] = ({ operation }) => { if (operation === "put-role-policy" && !fired) { fired = true; throw awsError("ServiceFailure"); } };
  assert.throws(() => f.run("activate"), /ServiceFailure/);
  assert.equal(f.policyCount(), 0);
  assert.equal(f.record().state, "CLOSED");
  assert.equal(f.record().lease, null);
});

test("failed automatic cleanup releases claim for explicit close after interruption", (t) => {
  const f = fixture(t); let grants = 0;
  f.before = ({ operation }) => {
    if (operation === "put-role-policy" && ++grants === 2) throw awsError("ServiceFailure");
    if (operation === "delete-role-policy") throw awsError("AccessDenied");
  };
  assert.throws(() => f.run("activate"), /automatic cleanup incomplete/);
  assert.equal(f.record().state, "CLOSING");
  assert.equal(f.record().lease, null);
  f.before = () => {};
  f.clock += 3600000; f.main = "b".repeat(40);
  assert.equal(f.run("close").state, "CLOSED");
  assert.equal(f.policyCount(), 0);
});

test("lost S3 commit response is authenticated through exact readback", (t) => {
  const f = fixture(t); let fired = false;
  f.after = ({ operation }) => { if (operation === "put-object" && !fired) { fired = true; throw awsError("ServiceUnavailable"); } };
  assert.equal(f.run("activate").state, "CAPABILITY_VERIFIED");
  assert.equal(f.record().lease, null);
});

test("competing initial CAS winner prevents every root resource mutation", (t) => {
  const f = fixture(t); let fired = false;
  f.before = ({ operation }) => {
    if (operation === "put-object" && !fired) { fired = true; f.put(reservationKey, { state: "OTHER_OWNER" }); }
  };
  assert.throws(() => f.run("activate"), /PreconditionFailed/);
  assert.equal(f.writes().length, 0);
});

test("orphan lease cannot be stolen even after expiry", (t) => {
  const f = fixture(t); f.run("activate");
  f.put(reservationKey, { ...f.record(), lease: { owner: "interrupted-process", mode: "recover", acquiredAt: new Date(start).toISOString() } });
  f.clock += 86400000;
  const before = f.writes().length;
  assert.throws(() => f.run("close"), /leased/);
  assert.equal(f.writes().length, before);
});

for (const kind of ["missing MFA", "wrong purpose role"]) test(`original release-session MFA provenance rejects ${kind}`, (t) => {
  const f = fixture(t);
  if (kind === "missing MFA") f.mfa = false; else f.principalRole = identity.terraformRole;
  assert.throws(() => f.run("activate"));
  assert.equal(f.writes().length, 0);
  assert.equal(f.record(), undefined);
});

for (const previousState of ["CLOSED", "EXPIRED"]) test(`fresh authorization renews ${previousState} capability with exact source package and journal predecessor`, (t) => {
  const f = fixture(t); f.run("activate"); f.run("install");
  const oldHash = f.record().authorizationSha256;
  const oldCode = f.record().codeSha256;
  if (previousState === "CLOSED") f.run("close");
  f.clock += previousState === "EXPIRED" ? 3600000 : 1000;
  f.authorize("1235");
  const pending = f.run("renew", { runId: "1235" });
  assert.equal(pending.state, "RESERVED");
  assert.equal(pending.next, "recover");
  assert.equal(f.policyCount(), 0);
  assert.equal(f.fn.Concurrency.ReservedConcurrentExecutions, 0);
  assert.equal(f.record().manifest.previousAuthorizationSha256, oldHash);
  assert.notEqual(f.record().codeSha256, oldCode);
  assert.equal(f.record().manifestHash, digest(f.record().manifest));
  assert.equal(f.run("recover", { runId: "1235" }).state, "RESERVED", "No grant before drain deadline");
  f.clock += 61000;
  assert.equal(f.run("recover", { runId: "1235" }).state, "CAPABILITY_VERIFIED");
  assert.equal(f.run("install", { runId: "1235" }).state, "IAM_VERIFIED");
  assert.equal(f.objects.get(receiptKey).value.authorizationSha256, f.record().authorizationSha256);
  assert.equal(f.record().authorizationHistory.length, 2);
  assert.equal(f.run("close", { runId: "1235" }).state, "CLOSED");
});

test("renewal refuses a still-active capability and every reused authorization run", (t) => {
  const f = fixture(t); f.run("activate"); f.clock += 1000; f.authorize("1235");
  const before = f.writes().length;
  assert.throws(() => f.run("renew", { runId: "1235" }), /closed or expired/);
  assert.equal(f.writes().length, before);
  f.run("close");
  assert.throws(() => f.run("renew"), /already consumed/);
  f.run("renew", { runId: "1235" });
  f.run("close", { runId: "1235" });
  assert.throws(() => f.run("renew", { runId: "1235" }), /already consumed/);
});

test("renewal refuses a journal outside the consumed authorization lineage", (t) => {
  const f = fixture(t); f.run("activate"); f.run("install"); f.run("close");
  f.put(receiptKey, { ...f.objects.get(receiptKey).value, authorizationSha256: "0".repeat(64) });
  f.clock += 1000; f.authorize("1235");
  const before = f.writes().length;
  assert.throws(() => f.run("renew", { runId: "1235" }), /outside consumed lineage/);
  assert.equal(f.writes().length, before);
});

for (const operation of ["update-function-code", "update-function-configuration"]) for (const phase of ["before", "after"]) {
  test(`renewal ${operation} failure ${phase} write remains forward recoverable with fresh run`, (t) => {
    const f = fixture(t); f.run("activate"); f.run("install"); f.run("close");
    const oldReceiptHash = f.objects.get(receiptKey).value.authorizationSha256;
    f.clock += 1000; f.authorize("1235"); let fired = false;
    f[phase] = (call) => { if (call.operation === operation && !fired) { fired = true; throw awsError("ServiceFailure"); } };
    assert.throws(() => f.run("renew", { runId: "1235" }), /ServiceFailure/);
    assert.equal(f.record().state, "CLOSED");
    assert.equal(f.policyCount(), 0);
    f[phase] = () => {};
    f.clock += 1000; f.authorize("1236");
    assert.equal(f.run("renew", { runId: "1236" }).state, "RESERVED");
    assert.equal(f.record().manifest.previousAuthorizationSha256, oldReceiptHash);
    assert.deepEqual(f.record().authorizationHistory.map(({ runId }) => runId), ["1234", "1235", "1236"]);
    assert.equal(digest(f.record().authorizationHistory[0].authorization), oldReceiptHash);
    f.clock += 61000;
    f.run("recover", { runId: "1236" });
    assert.equal(f.run("install", { runId: "1236" }).state, "IAM_VERIFIED");
  });
}

test("renewal after failed initial function creation creates only the exact new package", (t) => {
  const f = fixture(t);
  f.before = ({ operation }) => { if (operation === "create-function") throw awsError("ServiceFailure"); };
  assert.throws(() => f.run("activate"), /ServiceFailure/);
  assert.equal(f.fn, null);
  f.before = () => {};
  f.clock += 1000; f.authorize("1235");
  f.run("renew", { runId: "1235" });
  assert.equal(f.fn.Configuration.CodeSha256, f.record().codeSha256);
  assert.equal(f.policyCount(), 0);
  f.clock += 61000;
  assert.equal(f.run("recover", { runId: "1235" }).state, "CAPABILITY_VERIFIED");
});

for (const mode of ["prepare-table", "apply-table"]) for (const fail of [false, true]) {
  test(`${mode} ${fail ? "failure" : "success"} preserves separate plan approval and correct cleanup`, (t) => {
    const f = fixture(t); f.run("activate"); f.run("install");
    let called = 0;
    f.tableActivation = (args, deps) => {
      called++;
      assert.deepEqual(args, [mode === "prepare-table" ? "prepare" : "apply", "/private/plan-for-review", ...(mode === "apply-table" ? ["9876"] : [])]);
      assert.equal(deps.env.AWS_PROFILE, undefined, "Root profile never crosses into table runner");
      assert.equal(deps.env.AWS_ACCESS_KEY_ID, undefined);
      assert.equal(f.record().lease.mode, mode);
      assert.throws(() => f.run("close"), /leased/);
      if (fail) throw new Error("table phase failed");
    };
    const invoke = () => f.run(mode, { planDirectory: "/private/plan-for-review", planApprovalRun: "9876" });
    if (fail) assert.throws(invoke, /table phase failed/); else invoke();
    assert.equal(called, 1);
    const closes = fail || mode === "apply-table";
    assert.equal(f.record().state, closes ? "CLOSED" : "IAM_VERIFIED");
    assert.equal(f.policyCount(), closes ? 0 : 2);
    assert.equal(f.record().lease, null);
  });
}

test("prepare that crosses expiry cleans up instead of retaining grants for review", (t) => {
  const f = fixture(t); f.run("activate"); f.run("install");
  f.tableActivation = () => { f.clock += 3600000; };
  assert.throws(() => f.run("prepare-table"), /expired/);
  assert.equal(f.record().state, "CLOSED");
  assert.equal(f.policyCount(), 0);
});

test("source movement between function verification and policy grant blocks grant", (t) => {
  const f = fixture(t);
  f.after = ({ operation }) => { if (operation === "put-function-concurrency") f.main = "b".repeat(40); };
  assert.throws(() => f.run("activate"));
  assert(!f.calls.some(({ operation }) => operation === "put-role-policy"));
  assert.equal(f.record().state, "CLOSED");
});

test("ambiguous successful deletion is accepted only after absence readback", (t) => {
  const f = fixture(t); f.run("activate");
  f.after = ({ operation }) => { if (operation === "delete-role-policy") throw awsError("ServiceUnavailable"); };
  assert.equal(f.run("close").state, "CLOSED");
  assert.equal(f.policyCount(), 0);
});

for (const signal of ["SIGINT", "SIGTERM"]) test(`CLI ${signal} best-effort authenticated cleanup releases capabilities and handlers`, async (t) => {
  const f = fixture(t);
  const signals = new EventEmitter();
  f.after = ({ operation }) => { if (operation === "put-role-policy") signals.emit(signal); };
  await assert.rejects(f.run("activate", { cli: true, signals }), /temporary capabilities closed/);
  assert.equal(f.record().state, "CLOSED");
  assert.equal(f.record().lease, null);
  assert.equal(f.policyCount(), 0);
  assert.equal(signals.listenerCount(signal), 0);
});
