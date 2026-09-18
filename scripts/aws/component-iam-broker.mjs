import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createBrokerAuthorizationArchive } from "./component-broker-authorization.mjs";
import { assertBrokerEntryPoint, assertBrokerConfiguration, brokerConfiguration } from "./component-broker-configuration.mjs";
import { assertEffectiveBootstrapTrustAnchor } from "./component-bootstrap-trust-anchor.mjs";
import { componentBrokerArn, inspectBootstrapIdentities, inspectBrokerChangeIdentities } from "./component-installation-identity-contract.mjs";
import { authenticateComponentSession, claimComponentSession } from "./component-session-proof.mjs";

const canonical = (value) => JSON.stringify(sort(value));
function sort(value) {
  if (Array.isArray(value)) return value.map(sort);
  return value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])])) : value;
}
const hash = (value) => crypto.createHash("sha256").update(canonical(value)).digest("hex");
function policy(value) {
  if (typeof value !== "string") return value;
  try { return JSON.parse(value); } catch { return JSON.parse(decodeURIComponent(value)); }
}
const absent = (error) => ["NoSuchEntity", "NoSuchEntityException", "NoSuchKey"].includes(error.name);
const account = "368992683803";
const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
const key = "mscqr/production/component-deployment-state/iam-installation.json";

// Dependency injection is test-only; the deployed handler below loads only its
// immutable package, SDK clients and fixed public protected-main identity URL.
export function createInstallationHandler({ manifest, iam, s3, currentMain, now = Date.now, cleanup = false }) {
  const read = async (operation, parameters) => {
    try { return await iam(operation, parameters); }
    catch (error) { if (absent(error)) return null; throw error; }
  };
  const guard = async () => {
    if (!cleanup) {
      assert.equal(await currentMain(), manifest.sourceSha, "Protected source moved");
      assert(now() < Date.parse(manifest.expiresAt), "Authorization expired");
    }
    assert.equal(hash(manifest.targets.map(({ arn, policyName, policySha256, trustSha256 }) => ({ arn, policyName, policySha256, ...(trustSha256 ? { trustSha256 } : {}) }))), manifest.documentBindingsSha256);
    for (const target of manifest.targets) {
      assert.equal(hash(target.policy), target.policySha256);
      if (target.trust) assert.equal(hash(target.trust), target.trustSha256);
    }
  };
  const observe = async () => {
    const result = [];
    for (const target of manifest.targets) {
      const role = await read("GetRole", { RoleName: target.role });
      const inline = await read("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName });
      if (!target.trust) assert(role, "Existing release role is required");
      if (role) {
        assert.equal(role.Role.Arn, target.arn);
        assert.equal(role.Role.RoleName, target.role);
        if (target.trust) {
          assert.equal(hash(policy(role.Role.AssumeRolePolicyDocument)), target.trustSha256, "Unexpected trust");
          assert.equal(role.Role.Path, "/");
          assert.equal(role.Role.MaxSessionDuration, 3600);
          assert.equal(role.Role.PermissionsBoundary, undefined);
          assert.equal(role.Role.Tags?.length, 3);
          assert.deepEqual(Object.fromEntries(role.Role.Tags.map(({ Key, Value }) => [Key, Value])), { ManagedBy: "GuardedComponentInstaller", Environment: "production", Transition: manifest.transitionId });
          const attached = await iam("ListAttachedRolePolicies", { RoleName: target.role });
          assert.equal(attached.IsTruncated, false);
          assert.deepEqual(attached.AttachedPolicies, []);
          const names = await iam("ListRolePolicies", { RoleName: target.role });
          assert.equal(names.IsTruncated, false);
          assert.deepEqual(names.PolicyNames, inline ? [target.policyName] : []);
        }
      }
      if (inline) {
        assert(role);
        assert.equal(inline.RoleName, target.role);
        assert.equal(inline.PolicyName, target.policyName);
        assert.equal(hash(policy(inline.PolicyDocument)), target.policySha256, "Unexpected policy");
      }
      result.push({ arn: target.arn, role: role ? "EXPECTED" : "ABSENT", policy: inline ? "EXPECTED" : "ABSENT" });
    }
    return result;
  };
  return async (event) => {
    assert.deepEqual(Object.keys(event).sort(), ["operation", "transitionId"]);
    assert(["INSTALL", "INSPECT"].includes(event.operation));
    if (cleanup) assert.equal(event.operation, "INSPECT", "Cleanup cannot install IAM");
    assert.equal(event.transitionId, manifest.transitionId);
    await guard();
    let stored;
    // Exact-prefix listing proves first-install absence without interpreting a
    // GetObject AccessDenied as absence. A concurrent creator loses the CAS.
    const listing = await s3("ListObjectsV2", { Bucket: bucket, Prefix: key });
    assert(!listing.IsTruncated, "Incomplete receipt inventory");
    assert((listing.Contents || []).every(({ Key }) => Key === key), "Unexpected receipt namespace");
    if (listing.Contents?.length) stored = await s3("GetObject", { Bucket: bucket, Key: key });
    let ledger = stored ? JSON.parse(await stored.Body.transformToString()) : null;
    let etag = stored?.ETag;
    let renewing = false;
    if (ledger) {
      assert.equal(ledger.transitionId, manifest.transitionId, "Different or consumed transition");
      renewing = ledger.authorizationSha256 !== manifest.authorizationSha256;
      if (renewing) {
        assert(Array.isArray(manifest.authorizedPredecessors) && manifest.authorizedPredecessors.length <= 100, "Authenticated authorization lineage required");
        const predecessor = manifest.authorizedPredecessors.find((value) => value?.authorizationSha256 === ledger.authorizationSha256);
        assert(predecessor && Object.keys(predecessor).sort().join(",") === "authorizationSha256,documentBindingsSha256,sourceSha", "Unbound prior authorization");
        for (const field of ["authorizationSha256", "documentBindingsSha256"]) assert.match(predecessor[field], /^[a-f0-9]{64}$/);
        assert.match(predecessor.sourceSha, /^[a-f0-9]{40}$/);
        assert.equal(ledger.sourceSha, predecessor.sourceSha, "Unbound prior authorization");
        assert.equal(ledger.documentBindingsSha256, predecessor.documentBindingsSha256, "Unbound prior authorization");
      }
      if (!renewing) {
        assert.equal(ledger.sourceSha, manifest.sourceSha);
        assert.equal(ledger.documentBindingsSha256, manifest.documentBindingsSha256);
      }
      assert(["IAM_INSTALLING", "IAM_VERIFIED", ...(cleanup ? ["CLOSED"] : [])].includes(ledger.state));
    }
    const persist = async (state, live) => {
      await guard();
      const next = { schemaVersion: 1, sourceSha: manifest.sourceSha, transitionId: manifest.transitionId, authorizationSha256: manifest.authorizationSha256, documentBindingsSha256: manifest.documentBindingsSha256, state, live };
      const result = await s3("PutObject", { Bucket: bucket, Key: key, Body: canonical(next), ServerSideEncryption: "AES256", ...(etag ? { IfMatch: etag } : { IfNoneMatch: "*" }) });
      etag = result.ETag;
      assert(etag, "Missing journal version");
      ledger = next;
    };
    let live = await observe();
    if (event.operation === "INSPECT") return { state: ledger?.state || "ABSENT", live };
    if (ledger?.state === "IAM_VERIFIED") {
      assert(live.every(({ role, policy: status }) => role === "EXPECTED" && status === "EXPECTED"), "Verified installation drifted");
      if (renewing) await persist("IAM_VERIFIED", live);
      return ledger;
    }
    // The fixed broker derives predecessor hashes only from its durable archive.
    // Rebind by CAS after readback, before any remaining IAM write.
    if (renewing) await persist("IAM_INSTALLING", live);
    if (!ledger) {
      assert(live.every((target, index) => target.policy === "ABSENT" && (index === 2 || target.role === "ABSENT")), "First installation must start absent");
      await persist("IAM_INSTALLING", live);
    }
    // Function reserved concurrency MUST be one. A failed/ambiguous write is
    // never retried here; the next invocation reads every target before acting.
    for (const [index, target] of manifest.targets.entries()) {
      if (live[index].role === "ABSENT") {
        await guard();
        await iam("CreateRole", { RoleName: target.role, Path: "/", MaxSessionDuration: 3600, AssumeRolePolicyDocument: canonical(target.trust), Tags: [{ Key: "ManagedBy", Value: "GuardedComponentInstaller" }, { Key: "Environment", Value: "production" }, { Key: "Transition", Value: manifest.transitionId }] });
        live = await observe();
        assert.equal(live[index].role, "EXPECTED", "Role creation not yet authenticated");
      }
      if (live[index].policy === "ABSENT") {
        await guard();
        await iam("PutRolePolicy", { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: canonical(target.policy) });
        live = await observe();
        assert.equal(live[index].policy, "EXPECTED", "Policy write not yet authenticated");
      }
    }
    assert(live.every(({ role, policy: status }) => role === "EXPECTED" && status === "EXPECTED"));
    if (ledger.state !== "IAM_VERIFIED") await persist("IAM_VERIFIED", live);
    return ledger;
  };
}

export async function handler(event, context) {
  try { return await runHandler(event, context); }
  catch { throw new Error("Component installation broker request rejected."); }
}

async function runHandler(event, context) {
  const manifest = JSON.parse(fs.readFileSync(new URL("./installation-manifest.json", import.meta.url), "utf8"));
  const iamSdk = await import("@aws-sdk/client-iam");
  const s3Sdk = await import("@aws-sdk/client-s3");
  const lambdaSdk = await import("@aws-sdk/client-lambda");
  const trailSdk = await import("@aws-sdk/client-cloudtrail");
  for (const field of Object.keys(process.env)) assert(!/^AWS_(?:PROFILE|DEFAULT_PROFILE|CONFIG_FILE|SHARED_CREDENTIALS_FILE|ENDPOINT_URL(?:_|$)|WEB_IDENTITY_TOKEN_FILE|CONTAINER_CREDENTIALS)/.test(field), "Unreviewed runtime credential/endpoint source");
  for (const field of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]) assert(process.env[field], "Runtime session missing");
  const options = { region: "eu-west-2", maxAttempts: 1, credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, sessionToken: process.env.AWS_SESSION_TOKEN } };
  const iamClient = new iamSdk.IAMClient(options);
  const s3Client = new s3Sdk.S3Client(options);
  const lambdaClient = new lambdaSdk.LambdaClient(options);
  const trailClient = new trailSdk.CloudTrailClient(options);
  const iam = (name, parameters) => iamClient.send(new iamSdk[`${name}Command`](parameters));
  const s3 = (name, parameters) => s3Client.send(new s3Sdk[`${name}Command`](parameters));
  const lambda = (name, parameters) => lambdaClient.send(new lambdaSdk[`${name}Command`](parameters));
  assert.equal(process.env.AWS_REGION, "eu-west-2");
  assert.equal(manifest.account, account);
  const currentMain = async () => {
      const response = await fetch("https://api.github.com/repos/T-ej2003/genuine-scan-main/branches/main", { headers: { Accept: "application/vnd.github+json" }, signal: AbortSignal.timeout(10000), redirect: "error" });
      assert(response.ok, "Unable to authenticate current protected main");
      const main = await response.json();
      assert.equal(main.name, "main");
      assert.equal(main.protected, true, "Protected-main requirement changed");
      return main.commit.sha;
  };
  const issuanceEvents = async () => {
    const end = Date.now();
    const events = new Map();
    const tokens = new Set();
    let next;
    do {
      const page = await trailClient.send(new trailSdk.LookupEventsCommand({ LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: "AssumeRole" }], StartTime: new Date(end - 3600000), EndTime: new Date(end), MaxResults: 50, ...(next ? { NextToken: next } : {}) }));
      assert(Array.isArray(page.Events), "Incomplete issuance history");
      for (const item of page.Events) {
        const observed = JSON.parse(item.CloudTrailEvent);
        if (events.has(observed.eventID)) assert.equal(hash(events.get(observed.eventID)), hash(observed), "Inconsistent issuance history");
        events.set(observed.eventID, observed);
      }
      next = page.NextToken;
      if (next) {
        assert(typeof next === "string" && !tokens.has(next) && tokens.size < 20, "Incomplete issuance pagination");
        tokens.add(next);
      }
    } while (next);
    return [...events.values()];
  };
  return executeFixedBroker(event, context, { manifest, iam, s3, lambda, currentMain, issuanceEvents });
}

// Transport injection is for offline state-machine tests. The deployed handler
// supplies only fixed SDK clients and its immutable package, never request data.
export async function executeFixedBroker(event, context, { manifest, iam, s3, lambda, currentMain, issuanceEvents, sts, now = Date.now }) {
  assert.equal(manifest.account, account);
  const bootstrap = JSON.parse(await (await s3("GetObject", { Bucket: bucket, Key: "mscqr/production/component-deployment-state/identity-bootstrap.json" })).Body.transformToString());
  const functionName = "mscqr-production-component-iam-installer";
  assert.match(context?.functionVersion || "", /^[1-9][0-9]*$/, "Unqualified broker invocation forbidden");
  assert.equal(context?.invokedFunctionArn, `${componentBrokerArn}:${context.functionVersion}`, "Broker invocation ARN differs");
  const fn = await lambda("GetFunction", { FunctionName: functionName, Qualifier: context.functionVersion });
  const packageSha256 = Buffer.from(fn.Configuration.CodeSha256, "base64").toString("hex");
  const anchor = assertEffectiveBootstrapTrustAnchor(bootstrap, manifest, packageSha256);
  const version = assertBrokerEntryPoint(context, event?.operation, anchor.entryPoints);
  const identities = await (anchor.changed ? inspectBrokerChangeIdentities(iam) : inspectBootstrapIdentities(iam));
  assert(identities.every(({ role, policy }) => role === "EXPECTED" && policy === "EXPECTED"), "Bootstrap execution authority is incomplete");
  const [concurrency, signing, runtime] = await Promise.all([
    lambda("GetFunctionConcurrency", { FunctionName: functionName }),
    lambda("GetFunctionCodeSigningConfig", { FunctionName: functionName }),
    lambda("GetRuntimeManagementConfig", { FunctionName: functionName, Qualifier: version }),
  ]);
  assert.equal(fn.Configuration.RuntimeVersionConfig?.RuntimeVersionArn, anchor.runtimeVersions[version], "Bootstrapped runtime changed");
  const entryPoint = Object.entries(anchor.entryPoints).find(([, value]) => value === version)?.[0];
  assert(entryPoint, "Unknown immutable broker entry point");
  assertBrokerConfiguration(fn, brokerConfiguration({ packageSha256, manifestSha256: hash(manifest), entryPoint, entryPoints: anchor.entryPoints }), { concurrency, signing, runtime });
  // Identity policies are the only invocation grant. A resource policy on the
  // function or any fixed entry version could bypass the authorizer role trust.
  for (const qualifier of [null, ...anchor.allVersions]) {
    let missingPolicy = false;
    try { await lambda("GetPolicy", { FunctionName: functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); }
    catch (error) {
      if (error.name !== "ResourceNotFoundException") throw error;
      missingPolicy = true;
    }
    assert(missingPolicy, "Unexpected broker resource-based invocation policy");
  }
  const bind = (authorization) => ({ ...manifest, ...authorization.authorization, authorizationSha256: authorization.authorizationSha256,
    authorizedPredecessors: authorization.history.map(({ authorization: prior, authorizationSha256 }) => ({ authorizationSha256,
      sourceSha: prior.sourceSha, documentBindingsSha256: prior.documentBindingsSha256 })) });
  const inspect = (authorization) => createInstallationHandler({ manifest: bind(authorization), iam, s3, currentMain, cleanup: true, now })({ operation: "INSPECT", transitionId: authorization.authorization.transitionId });
  const predecessors = anchor.changed ? [{ sourceSha: anchor.predecessor.sourceSha, packageSha256: anchor.predecessor.packageSha256, manifestSha256: anchor.predecessor.manifestSha256 }] : [];
  const archive = createBrokerAuthorizationArchive({ manifest, packageSha256, s3, currentMain, now, reconcile: inspect, entryPoints: anchor.entryPoints, predecessors });
  if (event.operation === "AUTHORIZE") return archive.authorize(event, context);
  if (event.operation === "CLEANUP_CONTEXT") return archive.cleanupContext(event, context);
  if (event.operation === "TERRAFORM_CONTEXT") {
    const provenance = await archive.terraformContext(event, context);
    const authorization = await archive.authenticate({ operation: "PROVE_TERRAFORM_SESSION", transitionId: provenance.transitionId,
      authorizationSha256: provenance.authorizationSha256 }, context);
    const observed = await inspect(authorization);
    assert.equal(observed.state, "IAM_VERIFIED", "Terraform requires durable verified IAM installation");
    assert(observed.live.every(target => target.role === "EXPECTED" && target.policy === "EXPECTED"));
    return provenance;
  }
  assert.deepEqual(Object.keys(event).sort(), ["authorizationSha256", "operation", "proof", "transitionId"]);
  const { proof, ...request } = event;
  const authorization = await archive.authenticate(request, context);
  const cleanup = ["CLOSE", "PROVE_CLEANUP_SESSION"].includes(event.operation);
  const terraform = event.operation === "PROVE_TERRAFORM_SESSION";
  const session = await authenticateComponentSession(proof, { sourceSha: authorization.authorization.sourceSha, transitionId: request.transitionId, authorizationSha256: request.authorizationSha256, purpose: cleanup ? "CLEANUP" : terraform ? "TERRAFORM" : "INSTALL" }, { sts, issuanceEvents, now: now() });
  if (!cleanup) assert(Date.parse(session.issuanceEventTime) >= Date.parse(authorization.authorization.approvalObservedAt) - 999, "Session predates explicit approval");
  // CloudTrail issuance is eventually visible. This exact read-only operation
  // lets the same in-memory STS session wait for proof without retrying a write,
  // reserving controller ownership or issuing another MFA session each attempt.
  if (terraform) {
    const observed = await inspect(authorization);
    assert.equal(observed.state, "IAM_VERIFIED", "Terraform requires verified IAM installation");
    assert(observed.live.every(target => target.role === "EXPECTED" && target.policy === "EXPECTED"));
  }
  if (["PROVE_INSTALL_SESSION", "PROVE_CLEANUP_SESSION", "PROVE_TERRAFORM_SESSION"].includes(event.operation)) return {
    state: "SESSION_VERIFIED", principal: session.principal, expiresAt: session.expiresAt,
    sourceSha: authorization.authorization.sourceSha, transitionId: request.transitionId, authorizationSha256: request.authorizationSha256,
    ...(terraform ? { session } : {}),
  };
  // Inspection must not consume or replace the mutation session. A freshly
  // authenticated reader can classify an active/partial installation without
  // either stealing its lease or requiring another installation approval.
  if (event.operation === "INSPECT") return inspect(authorization);
  // Classify live IAM before claiming/replacing controller ownership. The write
  // engine repeats readback afterward and authenticates the guard at every write.
  if (!cleanup) await inspect(authorization);
  const sessionGuard = cleanup ? async () => { assert(now() < Date.parse(session.expiresAt), "Cleanup session expired"); } : await claimComponentSession({ session, s3, now });
  const bound = bind(authorization);
  const execute = createInstallationHandler({ manifest: bound, iam, s3, cleanup, now, currentMain: async () => {
    // Reauthenticate at every IAM-write guard, not merely upon invocation.
    await sessionGuard();
    await archive.authenticate(request, context);
    return currentMain();
  } });
  if (!cleanup) return execute({ operation: event.operation, transitionId: bound.transitionId });
  const observed = await execute({ operation: "INSPECT", transitionId: bound.transitionId });
  await sessionGuard();
  return archive.close(request, context, observed.live, session);
}
