#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { installationIdentity as identity, installationCapabilitySet, installationDocuments, documentBindings, canonical, digest } from "./component-iam-installation-contract.mjs";
import { authenticateComponentIamAuthorization, authenticateComponentIamClosureAuthorization } from "./component-iam-authorization.mjs";
import { authenticateOperatorSession, run as runTableActivation } from "./component-infrastructure-activation.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { createProductionAwsCredentialEnvironment, createProductionGithubCredentialEnvironment, createAssumedRoleSessionEnvironment, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
const prefix = "mscqr/production/component-deployment-state/";
const reservationKey = `${prefix}permission-installation.json`;
const iamReceiptKey = `${prefix}iam-installation.json`;
const provisionerPolicyName = "MSCQRComponentIamInstallationTemporary";
const terraformPolicyName = "MSCQRComponentTableInstallationTemporary";
const arn = (role) => `arn:aws:iam::${identity.account}:role/${role}`;
const functionArn = `arn:aws:lambda:${identity.region}:${identity.account}:function:${identity.functionName}`;
const missing = (error) => /\((?:NoSuchEntity|NoSuchKey|404|ResourceNotFoundException)\)/.test(String(error.stderr));

export function temporaryInstallationPolicies(authorization) {
  return boundedPolicies(authorization, installationCapabilitySet());
}

function boundedPolicies(authorization, capabilities) {
  const bounded = (policy, lambda) => ({ ...policy, Statement: policy.Statement.map((statement) => ({ ...statement, Condition: {
    ...statement.Condition, DateLessThan: { "aws:CurrentTime": authorization.expiresAt },
    ...(lambda ? { ArnEquals: { "lambda:SourceFunctionArn": functionArn } } : {}),
  } })) });
  return { provisioner: bounded(capabilities.provisioner, true), terraform: bounded(capabilities.terraform, false) };
}

// Administrative bootstrap only. Its credentials never execute IAM installation
// target writes or Terraform. The isolated Lambda is the only target writer.
// Lifecycle: activate reserves once; recover completes RESERVED under the same
// live authorization; install authenticates package/config and the broker receipt;
// close removes only two exact temporary inline documents, even after expiry or
// main advancement. Failures move to CLOSING/CLOSED and cannot regain authority.
// prepare-table <work> <permissionRun> <transition> <planDirectory> retains grants
// only on success. apply-table adds <planApprovalRun> and ALWAYS cleans up. These
// wrappers retain the root lease while the existing table runner independently
// authenticates its Terraform session, saved plan and separate plan approval.
// Run offline proof: node --test scripts/tests/component-iam-installation.test.mjs
export function run(argv = process.argv.slice(2), deps = {}) {
  const [mode, directory, runId, transitionId, planDirectory, planApprovalRun] = argv;
  assert(["activate", "recover", "install", "close", "renew", "prepare-table", "apply-table"].includes(mode));
  assert.equal(argv.length, mode === "prepare-table" ? 5 : mode === "apply-table" ? 6 : 4);
  if (mode === "apply-table") assert.match(planApprovalRun || "", /^[1-9][0-9]*$/);
  assert.match(runId || "", /^[1-9][0-9]*$/);
  assert.match(transitionId || "", /^[a-f0-9-]{36}$/i);
  const work = fs.realpathSync(directory);
  assert(work !== root.replace(/\/$/, "") && !work.startsWith(root));
  assert.equal(fs.statSync(work).mode & 0o077, 0);
  const env = deps.env || process.env;
  const clock = deps.now || Date.now;
  const execute = deps.execute || execFileSync;
  const adminEnv = { ...createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "default", region: identity.region, env }), AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true" };
  const localEnv = createProductionAwsCredentialEnvironment({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile: "mscqr-production-release-deployer", region: identity.region, env });
  const githubEnv = createProductionGithubCredentialEnvironment({ env });
  const exec = (name, args, childEnv = adminEnv) => execute(name, args, { cwd: root, env: childEnv, encoding: "utf8", maxBuffer: 16 * 1024 * 1024, timeout: 120000 }).trim();
  const aws = (service, operation, parameters = [], childEnv = adminEnv, region = identity.region) => JSON.parse(exec("aws", [service, operation, ...parameters, "--region", region, "--output", "json", "--no-cli-pager"], childEnv) || "{}");
  const maybe = (service, operation, parameters) => { try { return aws(service, operation, parameters); } catch (error) { if (missing(error)) return null; throw error; } };
  const source = () => {
    exec("git", ["fetch", "origin", "main"], localEnv);
    const sha = exec("git", ["rev-parse", "HEAD"], localEnv);
    assert.equal(sha, exec("git", ["rev-parse", "origin/main"], localEnv));
    assert.equal(exec("git", ["status", "--porcelain", "--untracked-files=all"], localEnv), "");
    const main = JSON.parse(exec("gh", ["api", `repos/${identity.repository}/branches/main`], githubEnv));
    assert.equal(main.commit.sha, sha);
    assert.equal(main.protected, true);
    return sha;
  };
  const sourceSha = source();
  const administrator = aws("sts", "get-caller-identity");
  assert.equal(administrator.Account, identity.account);
  assert.equal(administrator.Arn, `arn:aws:iam::${identity.account}:root`, "Separate governed administrator required");
  const credentials = aws("configure", "export-credentials", ["--format", "process"], localEnv);
  const humanEnv = createAssumedRoleSessionEnvironment({ credentials, region: identity.region, env });
  const caller = aws("sts", "get-caller-identity", [], humanEnv);
  const now = clock();
  const events = new Map();
  for (const region of [identity.region, "us-east-1"]) {
    let token;
    for (let page = 0; page < 20; page++) {
      const response = aws("cloudtrail", "lookup-events", ["--lookup-attributes", "AttributeKey=EventName,AttributeValue=AssumeRole", "--start-time", new Date(now - 3600000).toISOString(), "--end-time", new Date(now).toISOString(), "--no-paginate", ...(token ? ["--next-token", token] : [])], adminEnv, region);
      for (const entry of response.Events || []) { const event = JSON.parse(entry.CloudTrailEvent); events.set(event.eventID, event); }
      token = response.NextToken;
      if (!token) break;
    }
    assert(!token);
  }
  authenticateOperatorSession({ caller, credentials, events: [...events.values()], now, purpose: "IAM_BOOTSTRAP" });
  const getObject = (key, label) => {
    const target = path.join(work, label);
    const result = maybe("s3api", "get-object", ["--bucket", bucket, "--key", key, target]);
    if (!result) return null;
    assert(typeof result.ETag === "string" && result.ETag.length > 0, "Missing S3 journal ETag");
    return { value: JSON.parse(fs.readFileSync(target)), etag: result.ETag };
  };
  let reservation = getObject(reservationKey, "permission-live.json");
  const authFields = ["runId", "sourceSha", "transitionId", "documentBindingsSha256", "capabilitySetSha256", "expiresAt"];
  const authDocument = (authorization) => Object.fromEntries(authFields.map((key) => [key, authorization[key]]));
  const authDeps = { execute: deps.execute, env, now: clock };
  let record;
  let renewal;
  let archive;
  if (mode === "close" || mode === "renew") {
    assert(reservation, "No trusted permission record to close");
    record = reservation.value;
    assert.equal(record.schemaVersion, 2, "Legacy record lacks authenticated cleanup documents");
    if (mode === "close") assert.equal(record.authorization.runId, runId);
    assert.equal(record.authorization.transitionId, transitionId);
    assert.equal(digest(record.authorization), record.authorizationSha256);
    const authorization = authenticateComponentIamClosureAuthorization({ runId: record.authorization.runId,
      sourceSha: record.authorization.sourceSha, transitionId,
      expectedAuthorizationSha256: record.authorizationSha256 }, authDeps);
    assert.deepEqual(authDocument(authorization), record.authorization);
    assert.equal(digest(record.capabilities), authorization.capabilitySetSha256);
    assert.deepEqual(record.policies, boundedPolicies(record.authorization, record.capabilities));
    assert.equal(digest(record.policies.provisioner), record.provisionerPolicySha256);
    assert.equal(digest(record.policies.terraform), record.terraformPolicySha256);
    assert.equal(digest(record.manifest), record.manifestHash);
    assert.deepEqual(authDocument(record.manifest), record.authorization);
    assert.equal(record.manifest.authorizationSha256, record.authorizationSha256);
  }
  if (mode !== "close") {
    if (mode === "activate") assert.equal(reservation, null, "Already consumed; activation replay forbidden");
    else assert(reservation, "No authenticated transition reservation");
    const authorization = authenticateComponentIamAuthorization({ runId, sourceSha, transitionId }, authDeps);
    const capabilities = installationCapabilitySet();
    assert.equal(authorization.capabilitySetSha256, digest(capabilities));
    const previous = mode === "renew" ? record : null;
    if (previous) {
      assert.equal(sourceSha, previous.authorization.sourceSha, "Renewal must preserve source");
      assert.equal(authorization.documentBindingsSha256, previous.authorization.documentBindingsSha256);
      assert.equal(authorization.capabilitySetSha256, previous.authorization.capabilitySetSha256);
      assert(previous.state === "CLOSED" || clock() >= Date.parse(previous.authorization.expiresAt), "Previous capability must be closed or expired");
      assert(!previous.authorizationHistory.some((entry) => entry.runId === runId), "Authorization run already consumed");
      assert(Date.parse(authorization.expiresAt) > Date.parse(previous.authorization.expiresAt), "Renewal must extend expiry");
      const receipt = getObject(iamReceiptKey, "iam-previous.json");
      if (receipt) {
        assert.equal(receipt.value.schemaVersion, 1);
        for (const key of ["sourceSha", "transitionId", "documentBindingsSha256"]) assert.equal(receipt.value[key], previous.authorization[key]);
        assert(["IAM_INSTALLING", "IAM_VERIFIED"].includes(receipt.value.state));
        assert(previous.authorizationHistory.some((entry) => entry.authorizationSha256 === receipt.value.authorizationSha256), "Journal authorization outside consumed lineage");
      }
      renewal = { previousAuthorizationSha256: receipt?.value.authorizationSha256 || previous.authorizationSha256,
        previousExpectedConfig: previous.expectedConfig, notBefore: null };
    }
    const policies = boundedPolicies(authorization, capabilities);
    const priorHash = renewal?.previousAuthorizationSha256 || reservation?.value.renewal?.previousAuthorizationSha256;
    const manifest = { ...authorization, account: identity.account, targets: installationDocuments(),
      ...(priorHash ? { previousAuthorizationSha256: priorHash } : {}) };
    const manifestHash = digest(manifest);
    const packageDirectory = fs.mkdtempSync(path.join(work, "broker-package-"));
    const files = [path.join(packageDirectory, "index.mjs"), path.join(packageDirectory, "installation-manifest.json")];
    fs.writeFileSync(files[0], fs.readFileSync(path.join(root, "scripts/aws/component-iam-broker.mjs")), { mode: 0o600 });
    fs.writeFileSync(files[1], canonical(manifest), { mode: 0o600 });
    for (const file of files) fs.utimesSync(file, 315532800, 315532800);
    archive = path.join(packageDirectory, "broker.zip");
    execute("/usr/bin/zip", ["-X", "-j", archive, ...files], { env: { PATH: "/usr/bin:/bin", TZ: "UTC" }, encoding: "utf8" });
    const codeSha256 = crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("base64");
    const expectedConfig = { FunctionArn: functionArn, CodeSha256: codeSha256,
      Description: `Component IAM installation ${manifestHash}`, Role: arn(identity.provisionerRole),
      Runtime: "nodejs22.x", Handler: "index.handler", Timeout: 60, MemorySize: 256,
      PackageType: "Zip", Architectures: ["x86_64"], Layers: [], Environment: {},
      TracingConfig: { Mode: "PassThrough" }, EphemeralStorage: { Size: 512 } };
    const evidence = { runId, authorization: authDocument(authorization), authorizationSha256: authorization.authorizationSha256,
      capabilities, policies, manifest, manifestHash, codeSha256, expectedConfig };
    const next = { schemaVersion: 2, authorization: authDocument(authorization),
      authorizationSha256: authorization.authorizationSha256, capabilities, policies,
      provisionerPolicySha256: digest(policies.provisioner), terraformPolicySha256: digest(policies.terraform),
      manifest, manifestHash, codeSha256, expectedConfig,
      authorizationHistory: previous ? [...previous.authorizationHistory, evidence]
        : reservation?.value.authorizationHistory || [evidence],
      renewal: renewal || reservation?.value.renewal || null };
    if (previous) {
      renewal = { next, previous };
      record = previous;
    } else if (reservation) {
      for (const [key, value] of Object.entries(next)) assert.deepEqual(reservation.value[key], value, `Permission binding mismatch: ${key}; use renew with a fresh authorization`);
      record = reservation.value;
    } else record = { ...next, state: "RESERVED", lease: null };
  }
  assert(Array.isArray(record.authorizationHistory) && record.authorizationHistory.length > 0, "Missing authorization evidence history");
  assert.equal(new Set(record.authorizationHistory.map(({ runId }) => runId)).size, record.authorizationHistory.length, "Reused authorization run in history");
  for (const entry of record.authorizationHistory) {
    assert.equal(entry.runId, entry.authorization.runId);
    assert.equal(digest(entry.authorization), entry.authorizationSha256);
    assert.equal(digest(entry.capabilities), entry.authorization.capabilitySetSha256);
    assert.deepEqual(entry.policies, boundedPolicies(entry.authorization, entry.capabilities));
    assert.equal(digest(entry.manifest), entry.manifestHash);
    assert.deepEqual(authDocument(entry.manifest), entry.authorization);
    assert.equal(entry.manifest.authorizationSha256, entry.authorizationSha256);
    for (const key of ["sourceSha", "transitionId", "documentBindingsSha256", "capabilitySetSha256"]) assert.equal(entry.authorization[key], record.authorization[key]);
  }
  assert.equal(record.authorizationHistory.at(-1).authorizationSha256, record.authorizationSha256);
  assert(["RESERVED", "CAPABILITY_VERIFIED", "IAM_VERIFIED", "CLOSING", "CLOSED"].includes(record.state), "Unknown permission state");
  if (!["close", "renew"].includes(mode)) assert(!["CLOSING", "CLOSED"].includes(record.state), "Transition consumed; close only");
  if (mode === "recover") assert.equal(record.state, "RESERVED", "Recovery is for partial capability installation only");
  if (mode === "install") assert(["CAPABILITY_VERIFIED", "IAM_VERIFIED"].includes(record.state), "Capability not verified");
  if (mode.endsWith("-table")) assert.equal(record.state, "IAM_VERIFIED", "Install IAM before table preparation/application");

  // Durable non-stealable lease: IAM has no S3 fencing-token parameter. A TTL
  // takeover can race a paused root writer. Handled exits release this claim;
  // SIGKILL/host loss requires external proof the writer and requests have stopped
  // before operator reconciliation. Never remove/steal a claim merely by age.
  // Evidence boundary: identify host/PID/owner, establish process termination and
  // settle outstanding IAM/Lambda requests via authoritative readback/audit. This
  // CLI intentionally offers no arbitrary S3 override or timeout unlock. Until a
  // separately reviewed owner-reconciliation path exists, an orphan stays blocked.
  // Renewal consumes a fresh run, preserves source/transition/documents and binds
  // the exact previous journal authorization. Redeployment occurs with both old
  // policies absent and concurrency zero; recover resumes after the old 60-second
  // function execution window drains. Broker CAS-rebinding is required before IAM.
  assert.equal(record.lease, null, "Root operation already leased; do not steal an orphan claim by timeout");
  const owner = crypto.randomUUID();
  const writeRecord = (value) => {
    const file = path.join(work, "permission-write.json");
    fs.writeFileSync(file, canonical(value), { mode: 0o600 });
    try {
      aws("s3api", "put-object", ["--bucket", bucket, "--key", reservationKey, "--body", file, "--server-side-encryption", "AES256", ...(reservation ? ["--if-match", reservation.etag] : ["--if-none-match", "*"])]);
    } catch (cause) {
      // A lost response is resolved only by exact authoritative readback.
      const observed = getObject(reservationKey, "permission-check.json");
      if (!observed || canonical(observed.value) !== canonical(value)) throw cause;
    }
    const observed = getObject(reservationKey, "permission-check.json");
    assert(observed && canonical(observed.value) === canonical(value), "Permission commit not authenticated");
    reservation = observed;
    record = observed.value;
  };
  writeRecord({ ...record, lease: { owner, mode, host: os.hostname(), pid: process.pid, acquiredAt: new Date(clock()).toISOString() } });
  const owned = () => {
    const live = getObject(reservationKey, "permission-check.json");
    assert.equal(live?.value.lease?.owner, owner, "Root operation lease lost");
    assert.equal(live.etag, reservation.etag, "Root operation version changed");
    assert.deepEqual(live.value, record, "Root operation record changed");
  };
  const reserve = (state) => { owned(); writeRecord({ ...record, state }); };
  const guard = () => {
    owned();
    assert.equal(source(), record.authorization.sourceSha);
    assert(clock() < Date.parse(record.authorization.expiresAt), "Authorization expired; close only");
    assert.equal(digest(documentBindings()), record.authorization.documentBindingsSha256);
    assert.equal(digest(installationCapabilitySet()), record.authorization.capabilitySetSha256);
    assert(!["CLOSING", "CLOSED"].includes(record.state), "Transition consumed");
  };
  const targets = () => [
    { role: identity.provisionerRole, trust: record.capabilities.provisionerTrust, policyName: provisionerPolicyName, policy: record.policies.provisioner },
    { role: identity.terraformRole, trust: record.capabilities.terraformTrust, policyName: terraformPolicyName, policy: record.policies.terraform },
  ];
  const inspectRole = (target) => {
    const found = maybe("iam", "get-role", ["--role-name", target.role]);
    if (!found) return null;
    assert.equal(found.Role.Arn, arn(target.role));
    assert.deepEqual(normalizeIamPolicyDocument(found.Role.AssumeRolePolicyDocument), target.trust);
    assert.equal(found.Role.Path, "/"); assert.equal(found.Role.MaxSessionDuration, 3600);
    assert.equal(found.Role.PermissionsBoundary, undefined);
    assert.deepEqual(Object.fromEntries((found.Role.Tags || []).map(({ Key, Value }) => [Key, Value])), { ManagedBy: "GuardedComponentInstaller", Environment: "production", Transition: transitionId });
    const attached = aws("iam", "list-attached-role-policies", ["--role-name", target.role]);
    assert(!attached.IsTruncated); assert.deepEqual(attached.AttachedPolicies, []);
    const inline = aws("iam", "list-role-policies", ["--role-name", target.role]);
    assert(!inline.IsTruncated); assert(inline.PolicyNames.length <= 1 && inline.PolicyNames.every((name) => name === target.policyName));
    return found;
  };
  const readPolicy = (target) => {
    const found = maybe("iam", "get-role-policy", ["--role-name", target.role, "--policy-name", target.policyName]);
    if (found) {
      assert.equal(found.RoleName, target.role);
      assert.equal(found.PolicyName, target.policyName);
      assert.equal(digest(normalizeIamPolicyDocument(found.PolicyDocument)), digest(target.policy), "Unknown temporary capability");
    }
    return found;
  };
  const inspectFunction = (requireConcurrency = true, expectedConfig = record.expectedConfig) => {
    const fn = aws("lambda", "get-function", ["--function-name", identity.functionName]);
    const config = { ...fn.Configuration, Layers: fn.Configuration.Layers || [], Environment: fn.Configuration.Environment?.Variables || {} };
    for (const [key, value] of Object.entries(expectedConfig)) assert.deepEqual(config[key], value, `Unexpected function ${key}`);
    assert.equal(config.State, "Active");
    assert.equal(config.LastUpdateStatus, "Successful");
    if (requireConcurrency) assert.equal(fn.Concurrency?.ReservedConcurrentExecutions, 1, "Function concurrency is not isolated");
    return fn;
  };
  const cleanup = () => {
    reserve("CLOSING");
    for (const target of targets()) {
      // Cleanup deliberately reads only the exact temporary inline document.
      // Unrelated trust/tags/policies cannot prevent removal of known authority.
      if (readPolicy(target)) {
        owned();
        try { aws("iam", "delete-role-policy", ["--role-name", target.role, "--policy-name", target.policyName]); }
        catch (cause) { if (readPolicy(target)) throw cause; }
        assert.equal(readPolicy(target), null, "Temporary authority removal unconfirmed");
      }
    }
    reserve("CLOSED");
    return { state: "CLOSED" };
  };
  let result;
  let failure;
  try {
    if (mode === "close") result = cleanup();
    else if (mode === "activate" || mode === "recover" || mode === "renew") {
      if (mode === "renew") {
        cleanup();
        // Authenticate the prior executable before changing it. There is no
        // arbitrary-code update: both packages/configurations are source-bound.
        const prior = maybe("lambda", "get-function", ["--function-name", identity.functionName]);
        if (prior) {
          // A previous renewal may have stopped between code and description
          // updates. Only the two persisted source-owned configurations qualify.
          const configs = [record.expectedConfig, record.renewal?.previousExpectedConfig].filter(Boolean);
          assert(configs.some((config) => config.CodeSha256 === prior.Configuration.CodeSha256), "Unknown previous executable");
          assert(configs.some((config) => config.Description === prior.Configuration.Description), "Unknown previous manifest description");
          const exact = { ...record.expectedConfig, CodeSha256: prior.Configuration.CodeSha256, Description: prior.Configuration.Description };
          inspectFunction(false, exact);
          renewal.next.renewal.previousExpectedConfig = exact;
          owned();
          aws("lambda", "put-function-concurrency", ["--function-name", identity.functionName, "--reserved-concurrent-executions", "0"]);
          assert.equal(aws("lambda", "get-function", ["--function-name", identity.functionName]).Concurrency?.ReservedConcurrentExecutions, 0);
        }
        const next = renewal.next;
        writeRecord({ ...next, renewal: { ...next.renewal, notBefore: new Date(clock() + 61_000).toISOString() }, state: "RESERVED", lease: record.lease });
      }
      guard();
      for (const target of targets()) {
        if (!inspectRole(target)) {
          guard();
          aws("iam", "create-role", ["--role-name", target.role, "--path", "/", "--max-session-duration", "3600", "--assume-role-policy-document", canonical(target.trust), "--tags", "Key=ManagedBy,Value=GuardedComponentInstaller", "Key=Environment,Value=production", `Key=Transition,Value=${transitionId}`]);
          assert(inspectRole(target));
        }
        readPolicy(target);
      }
      if (!maybe("lambda", "get-function", ["--function-name", identity.functionName])) {
        guard();
        aws("lambda", "create-function", ["--function-name", identity.functionName, "--runtime", "nodejs22.x", "--handler", "index.handler", "--role", arn(identity.provisionerRole), "--timeout", "60", "--memory-size", "256", "--zip-file", `fileb://${archive}`, "--description", record.expectedConfig.Description]);
        aws("lambda", "wait", ["function-active-v2", "--function-name", identity.functionName]);
        if (record.renewal) {
          guard();
          aws("lambda", "put-function-concurrency", ["--function-name", identity.functionName, "--reserved-concurrent-executions", "0"]);
        }
      }
      if (record.renewal) {
        // Both authority documents must remain absent throughout redeployment.
        for (const target of targets()) assert.equal(readPolicy(target), null, "Renewal redeployment requires absent capabilities");
        const current = aws("lambda", "get-function", ["--function-name", identity.functionName]);
        const oldConfig = record.renewal.previousExpectedConfig;
        const codeCurrent = current.Configuration.CodeSha256 === record.codeSha256;
        const descriptionCurrent = current.Configuration.Description === record.expectedConfig.Description;
        inspectFunction(false, { ...oldConfig,
          ...(codeCurrent ? { CodeSha256: record.codeSha256 } : {}),
          ...(descriptionCurrent ? { Description: record.expectedConfig.Description } : {}) });
        assert.equal(current.Concurrency?.ReservedConcurrentExecutions, 0, "Renewal function must remain quiesced");
        if (!codeCurrent) {
          guard();
          aws("lambda", "update-function-code", ["--function-name", identity.functionName, "--zip-file", `fileb://${archive}`, "--revision-id", current.Configuration.RevisionId]);
          aws("lambda", "wait", ["function-updated-v2", "--function-name", identity.functionName]);
        }
        if (!descriptionCurrent) {
          const updated = aws("lambda", "get-function", ["--function-name", identity.functionName]);
          guard();
          aws("lambda", "update-function-configuration", ["--function-name", identity.functionName, "--description", record.expectedConfig.Description, "--revision-id", updated.Configuration.RevisionId]);
          aws("lambda", "wait", ["function-updated-v2", "--function-name", identity.functionName]);
        }
        inspectFunction(false);
        if (clock() < Date.parse(record.renewal.notBefore)) {
          result = { state: "RESERVED", runId, resumeAfter: record.renewal.notBefore, next: "recover" };
        }
      }
      if (!result) {
        inspectFunction(false);
        guard();
        aws("lambda", "put-function-concurrency", ["--function-name", identity.functionName, "--reserved-concurrent-executions", "1"]);
        inspectFunction();
        for (const target of targets()) if (!readPolicy(target)) {
          inspectFunction();
          guard();
          aws("iam", "put-role-policy", ["--role-name", target.role, "--policy-name", target.policyName, "--policy-document", canonical(target.policy)]);
          assert(readPolicy(target));
        }
        guard();
        reserve("CAPABILITY_VERIFIED");
        result = { state: record.state, codeSha256: record.codeSha256, manifestHash: record.manifestHash };
      }
    } else if (mode.endsWith("-table")) {
      guard();
      for (const target of targets()) { assert(inspectRole(target)); assert(readPolicy(target)); }
      const tableMode = mode === "prepare-table" ? "prepare" : "apply";
      // In-process test seam only; the CLI can select neither an executable nor
      // an alternate implementation. Administrator credentials are NOT passed.
      (deps.tableActivation || runTableActivation)([tableMode, planDirectory, ...(tableMode === "apply" ? [planApprovalRun] : [])], { env, execute: deps.execute });
      if (tableMode === "apply") result = cleanup();
      else { guard(); result = { state: "TABLE_PREPARED", permissionState: record.state, expiresAt: record.authorization.expiresAt }; }
    } else {
      guard();
      for (const target of targets()) { assert(inspectRole(target)); assert(readPolicy(target)); }
      inspectFunction();
      guard();
      // INSTALL on a verified broker is read-only AND rejects live drift;
      // INSPECT merely reports drift and cannot authenticate successful replay.
      const invocation = aws("lambda", "invoke", ["--function-name", identity.functionName, "--cli-binary-format", "raw-in-base64-out", "--payload", canonical({ operation: "INSTALL", transitionId }), path.join(work, "iam-result.json")]);
      assert.equal(invocation.FunctionError, undefined, "IAM installation stopped; exact cleanup required");
      assert.equal(invocation.StatusCode, 200);
      const receipt = getObject(iamReceiptKey, "iam-live.json");
      assert.equal(receipt?.value.state, "IAM_VERIFIED");
      assert.equal(receipt.value.schemaVersion, 1);
      for (const key of ["sourceSha", "transitionId", "documentBindingsSha256"]) assert.equal(receipt.value[key], record.authorization[key]);
      assert.equal(receipt.value.authorizationSha256, record.authorizationSha256);
      assert.deepEqual(receipt.value.live, record.manifest.targets.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })));
      reserve("IAM_VERIFIED");
      result = receipt.value;
    }
  } catch (cause) {
    failure = cause;
    if (mode !== "close") {
      try { cleanup(); }
      catch (cleanupError) { failure = new AggregateError([cause, cleanupError], "Operation failed; automatic cleanup incomplete. Explicit close required; do not replay activation."); }
    }
  } finally {
    try { owned(); writeRecord({ ...record, lease: null }); }
    catch (releaseError) { failure = new AggregateError([...(failure ? [failure] : []), releaseError], "Lease release unconfirmed; fail closed and reconcile the owner before another root operation."); }
  }
  if (failure) throw failure;
  return result;
}

// execFileSync blocks JavaScript signal dispatch while a child runs. Keep CLI
// handlers installed through an event-loop turn after completion, then request
// authenticated close on SIGINT/SIGTERM. This is best effort, NOT prompt abort or
// SIGKILL recovery. A hard kill retains the non-stealable claim described above.
export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const signals = deps.signals || process;
  let interrupted;
  const onInt = () => { interrupted = "SIGINT"; };
  const onTerm = () => { interrupted = "SIGTERM"; };
  signals.on("SIGINT", onInt);
  signals.on("SIGTERM", onTerm);
  let result;
  let failure;
  try {
    try { result = run(argv, deps); } catch (cause) { failure = cause; }
    await new Promise((resolve) => setImmediate(resolve));
    if (interrupted) {
      try {
        if (argv[0] !== "close") run(["close", argv[1], argv[2], argv[3]], deps);
        failure = new AggregateError(failure ? [failure] : [], `${interrupted}: stopped; exact temporary capabilities closed`);
      } catch (cause) {
        failure = new AggregateError([...(failure ? [failure] : []), cause], `${interrupted}: cleanup unconfirmed; explicit authenticated close or orphan-owner reconciliation required`);
      }
    }
  } finally {
    signals.off("SIGINT", onInt);
    signals.off("SIGTERM", onTerm);
  }
  if (failure) throw failure;
  return result;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  try { process.stdout.write(`${JSON.stringify(await runCli())}\n`); }
  catch (cause) {
    // Avoid dumping execFileSync stdout/environment fields (credential exports).
    process.stderr.write(`${cause.message}\n`);
    process.exitCode = 1;
  }
}
