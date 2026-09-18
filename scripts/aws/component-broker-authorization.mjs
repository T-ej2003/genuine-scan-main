import assert from "node:assert/strict";
import crypto from "node:crypto";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";
import { assertExpiredSession } from "./component-installation-identity-contract.mjs";
import { brokerChangeEntryPoints, brokerEntryPoints } from "./component-broker-configuration.mjs";

const canonical = (value) => JSON.stringify(sorted(value));
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  return value && typeof value === "object" ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])])) : value;
}
const digest = (value) => crypto.createHash("sha256").update(canonical(value)).digest("hex");
const bucket = "mscqr-production-terraform-state-368992683803-eu-west-2";
const key = "mscqr/production/component-deployment-state/installation-authorization.json";
const closureKey = "mscqr/production/component-deployment-state/permission-installation.json";
const functionArn = "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-component-iam-installer";
const environment = "production-component-infrastructure-install-permission";
const fields = ["schemaVersion", "account", "region", "sourceSha", "transitionId", "runId", "operator", "reviewer", "environment", "approvalObservedAt", "expiresAt", "documentBindingsSha256", "capabilitySetSha256", "brokerPackageSha256", "brokerManifestSha256"];

function assertIdentity(value) {
  assert.deepEqual(value, { login: "T-ej2003", id: 183396573, type: "User" });
}

// This validator never authenticates unsigned local JSON. It is used only after
// the AWS invocation-version boundary or a read from the fixed broker-owned key.
export function assertArchivedInstallationAuthorization(value, manifest, packageSha256, { now, allowExpired = false }) {
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort());
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.account, "368992683803");
  assert.equal(value.region, "eu-west-2");
  assert.equal(value.sourceSha, manifest.sourceSha);
  assert.match(value.sourceSha, /^[a-f0-9]{40}$/);
  assert.match(value.transitionId || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.match(value.runId || "", /^[1-9][0-9]*$/);
  assert.equal(value.environment, environment);
  assertIdentity(value.operator);
  assertIdentity(value.reviewer);
  for (const field of ["documentBindingsSha256", "capabilitySetSha256"]) {
    assert.match(value[field] || "", /^[a-f0-9]{64}$/);
    assert.equal(value[field], manifest[field]);
  }
  assert.equal(value.brokerManifestSha256, digest(manifest));
  assert.match(packageSha256 || "", /^[a-f0-9]{64}$/);
  assert.equal(value.brokerPackageSha256, packageSha256);
  // GitHub's approval-history API has no approval timestamp. Bind the trusted
  // workflow's observation timestamp; never mislabel it as the click time.
  const approved = Date.parse(value.approvalObservedAt);
  const expires = Date.parse(value.expiresAt);
  assert(Number.isFinite(now) && Number.isFinite(approved) && Number.isFinite(expires));
  assert.equal(new Date(approved).toISOString(), value.approvalObservedAt);
  assert.equal(new Date(expires).toISOString(), value.expiresAt);
  assert(approved <= now && expires > approved && expires - approved <= 1800000);
  if (!allowExpired) assert(now < expires, "Authorization expired");
  return digest(value);
}

export function createBrokerAuthorizationArchive({ manifest, packageSha256, s3, currentMain, reconcile, entryPoints = brokerEntryPoints, now = Date.now }) {
  assert(entryPoints === brokerEntryPoints || entryPoints === brokerChangeEntryPoints, "Unreviewed broker entry points");
  const closure = async (authorizationSha256) => {
    const list = await s3("ListObjectsV2", { Bucket: bucket, Prefix: closureKey });
    assert(!list.IsTruncated);
    assert((list.Contents || []).length <= 1 && (list.Contents || []).every(({ Key }) => Key === closureKey));
    if (!list.Contents?.length) return null;
    const record = JSON.parse(await (await s3("GetObject", { Bucket: bucket, Key: closureKey })).Body.transformToString());
    assert.deepEqual(Object.keys(record).sort(), ["authorizationSha256", "cleanupSession", "live", "sourceSha", "state", "transitionId"]);
    assert.equal(record.state, "CLOSED");
    assert.equal(record.sourceSha, manifest.sourceSha);
    assert.equal(record.authorizationSha256, authorizationSha256);
    assertComponentSessionRecord(record.cleanupSession);
    assert.equal(record.cleanupSession.purpose, "CLEANUP");
    assert.equal(record.cleanupSession.sourceSha, record.sourceSha);
    assert.equal(record.cleanupSession.transitionId, record.transitionId);
    assert.equal(record.cleanupSession.authorizationSha256, authorizationSha256);
    assert.deepEqual(record.live.map(({ arn }) => arn), manifest.targets.map(({ arn }) => arn));
    for (const target of record.live) {
      assert.deepEqual(Object.keys(target).sort(), ["arn", "policy", "role"]);
      assert(["ABSENT", "EXPECTED"].includes(target.role));
      assert(["ABSENT", "EXPECTED"].includes(target.policy));
    }
    return record;
  };
  const read = async () => {
    // Listing is deliberately exact-prefix and never treats AccessDenied as
    // absence. A missing object then loses races through IfNoneMatch.
    const list = await s3("ListObjectsV2", { Bucket: bucket, Prefix: key });
    assert(!list.IsTruncated);
    assert((list.Contents || []).every(({ Key }) => Key === key));
    assert((list.Contents || []).length <= 1);
    if (!list.Contents?.length) return null;
    const response = await s3("GetObject", { Bucket: bucket, Key: key });
    assert(response.ETag);
    const record = JSON.parse(await response.Body.transformToString());
    assert.deepEqual(Object.keys(record).sort(), ["authorization", "authorizationSha256", "history", "state"]);
    assert.equal(record.authorizationSha256, assertArchivedInstallationAuthorization(record.authorization, manifest, packageSha256, { now: now(), allowExpired: true }));
    assert.equal(record.state, "AUTHORIZED");
    assert(Array.isArray(record.history) && record.history.length <= 100);
    const runs = new Set([record.authorization.runId]);
    for (const previous of record.history) {
      assert.deepEqual(Object.keys(previous).sort(), ["authorization", "authorizationSha256"]);
      assert.equal(previous.authorizationSha256, assertArchivedInstallationAuthorization(previous.authorization, manifest, packageSha256, { now: now(), allowExpired: true }));
      assert.equal(previous.authorization.transitionId, record.authorization.transitionId);
      assert(!runs.has(previous.authorization.runId), "Replayed archived approval");
      runs.add(previous.authorization.runId);
    }
    Object.defineProperty(record, "etag", { value: response.ETag });
    return record;
  };
  const api = {
    async cleanupContext(event, context) {
      assert.equal(context.functionVersion, entryPoints.CLEANUP);
      assert.equal(context.invokedFunctionArn, `${functionArn}:${entryPoints.CLEANUP}`);
      assert.deepEqual(event, { operation: "CLEANUP_CONTEXT" });
      const record = await read();
      assert(record, "No durable authorization");
      // Non-secret coordinates only. Discovery grants no mutation authority:
      // CLOSE still requires the exact fresh MFA/session proof and live readback.
      return { sourceSha: record.authorization.sourceSha, transitionId: record.authorization.transitionId,
        authorizationSha256: record.authorizationSha256, purpose: "CLEANUP" };
    },
    async terraformContext(event, context) {
      assert.equal(context.functionVersion, entryPoints.INSTALL);
      assert.equal(context.invokedFunctionArn, `${functionArn}:${entryPoints.INSTALL}`);
      assert.deepEqual(Object.keys(event).sort(), ["operation", "transitionId"]);
      assert.equal(event.operation, "TERRAFORM_CONTEXT");
      const record = await read();
      assert(record, "No durable authorization");
      assert.equal(record.authorization.transitionId, event.transitionId);
      const closed = await closure(record.authorizationSha256);
      assert(closed, "Verified installation closure required");
      assert(closed.live.every(({ role, policy }) => role === "EXPECTED" && policy === "EXPECTED"), "Closed installation was not fully verified");
      return { sourceSha: record.authorization.sourceSha, transitionId: record.authorization.transitionId,
        authorizationSha256: record.authorizationSha256, purpose: "TERRAFORM" };
    },
    async authorize(event, context) {
      assert.equal(context.functionVersion, entryPoints.AUTHORIZE);
      assert.equal(context.invokedFunctionArn, `${functionArn}:${entryPoints.AUTHORIZE}`);
      assert.deepEqual(Object.keys(event).sort(), ["authorization", "operation"]);
      assert.equal(event.operation, "AUTHORIZE");
      assert.equal(await currentMain(), manifest.sourceSha);
      const authorizationSha256 = assertArchivedInstallationAuthorization(event.authorization, manifest, packageSha256, { now: now() });
      const prior = await read();
      if (prior) {
        assert.equal(event.authorization.transitionId, prior.authorization.transitionId, "Different installation transition");
        assert.equal(await closure(prior.authorizationSha256), null, "Closed authorization cannot reopen installation");
        const history = [...prior.history, prior];
        assert(history.every((item) => item.authorization.runId !== event.authorization.runId), "Approval already consumed");
        assert(Date.parse(event.authorization.approvalObservedAt) > Date.parse(prior.authorization.approvalObservedAt), "Fresh approval required");
        const sessionKey = "mscqr/production/component-deployment-state/installation-session.json";
        const listing = await s3("ListObjectsV2", { Bucket: bucket, Prefix: sessionKey });
        assert.equal(listing.IsTruncated, false);
        assert((listing.Contents || []).length <= 1 && (listing.Contents || []).every(({ Key }) => Key === sessionKey));
        if (listing.Contents?.length) {
          const journal = JSON.parse(await (await s3("GetObject", { Bucket: bucket, Key: sessionKey })).Body.transformToString());
          assert.equal(journal.schemaVersion, 1);
          assertComponentSessionRecord(journal.session);
          assert.equal(journal.session.sourceSha, manifest.sourceSha);
          assert.equal(journal.session.transitionId, event.authorization.transitionId);
          assert(history.some((item) => item.authorizationSha256 === journal.session.authorizationSha256), "Session belongs to unknown authorization");
          assertExpiredSession(journal.session, now());
        }
        assert.equal(typeof reconcile, "function", "Authenticated live reconciliation required for renewal");
      }
      if (reconcile) await reconcile(prior || { authorization: event.authorization, authorizationSha256, history: [] });
      const record = { state: "AUTHORIZED", authorization: event.authorization, authorizationSha256,
        history: prior ? [...prior.history, { authorization: prior.authorization, authorizationSha256: prior.authorizationSha256 }] : [] };
      assert(record.history.length <= 100, "Authorization history requires separate reviewed recovery");
      assert.equal(await currentMain(), manifest.sourceSha, "Protected source moved during reconciliation");
      assertArchivedInstallationAuthorization(event.authorization, manifest, packageSha256, { now: now() });
      try {
        await s3("PutObject", { Bucket: bucket, Key: key, Body: canonical(record), ServerSideEncryption: "AES256", ...(prior ? { IfMatch: prior.etag } : { IfNoneMatch: "*" }) });
      } catch (cause) {
        if (["PreconditionFailed", "ConditionalRequestConflict"].includes(cause.name)) throw cause;
        // An exact record resolves ambiguous persistence. This only archives
        // authorization, never claims IAM installation or replays an IAM write.
        const observed = await read();
        if (canonical(observed) !== canonical(record)) throw cause;
      }
      assert.deepEqual(await read(), record);
      return { authorizationSha256 };
    },
    async authenticate(event, context) {
      assert.deepEqual(Object.keys(event).sort(), ["authorizationSha256", "operation", "transitionId"]);
      const version = { INSTALL: entryPoints.INSTALL, INSPECT: entryPoints.INSTALL, PROVE_INSTALL_SESSION: entryPoints.INSTALL, PROVE_TERRAFORM_SESSION: entryPoints.INSTALL, CLOSE: entryPoints.CLEANUP, PROVE_CLEANUP_SESSION: entryPoints.CLEANUP }[event.operation];
      assert(version, "Unsupported semantic operation");
      assert.equal(context.functionVersion, version);
      assert.equal(context.invokedFunctionArn, `${functionArn}:${version}`);
      const record = await read();
      assert(record, "No durable authorization");
      assert.equal(record.authorization.transitionId, event.transitionId);
      assert.equal(record.authorizationSha256, event.authorizationSha256);
      const operationClass = ["CLOSE", "PROVE_CLEANUP_SESSION"].includes(event.operation) ? "CLEANUP"
        : event.operation === "PROVE_TERRAFORM_SESSION" ? "PROVENANCE" : "MUTATION";
      assertArchivedInstallationAuthorization(record.authorization, manifest, packageSha256, { now: now(), allowExpired: operationClass !== "MUTATION" });
      if (operationClass === "MUTATION") {
        assert.equal(await closure(record.authorizationSha256), null, "Installation authorization consumed by closure");
        assert.equal(await currentMain(), manifest.sourceSha);
      } else if (operationClass === "PROVENANCE") {
        const closed = await closure(record.authorizationSha256);
        assert(closed, "Verified installation closure required");
        assert(closed.live.every(({ role, policy }) => role === "EXPECTED" && policy === "EXPECTED"), "Closed installation was not fully verified");
      }
      // Cleanup can read archived provenance after GitHub artifact expiry. It
      // receives no authority to install and must still obey the closure ledger.
      return record;
    },
    async close(event, context, live, cleanupSession) {
      assert.equal(event.operation, "CLOSE");
      const authorized = await api.authenticate(event, context);
      assertComponentSessionRecord(cleanupSession);
      assert.equal(cleanupSession.purpose, "CLEANUP");
      assert.equal(cleanupSession.account, "368992683803");
      assert.equal(cleanupSession.region, "eu-west-2");
      assert.equal(cleanupSession.sourceSha, manifest.sourceSha);
      assert.equal(cleanupSession.transitionId, event.transitionId);
      assert.equal(cleanupSession.authorizationSha256, authorized.authorizationSha256);
      assert.equal(cleanupSession.mfaAuthenticated, true);
      assert(now() < Date.parse(cleanupSession.expiresAt), "Cleanup session expired");
      assert.deepEqual(live.map(({ arn }) => arn), manifest.targets.map(({ arn }) => arn));
      assert(live.every(({ role, policy }) => ["EXPECTED", "ABSENT"].includes(role) && ["EXPECTED", "ABSENT"].includes(policy)));
      const existing = await closure(authorized.authorizationSha256);
      if (existing) return existing;
      const record = { state: "CLOSED", sourceSha: manifest.sourceSha, transitionId: event.transitionId, authorizationSha256: authorized.authorizationSha256, cleanupSession, live };
      try {
        await s3("PutObject", { Bucket: bucket, Key: closureKey, Body: canonical(record), ServerSideEncryption: "AES256", IfNoneMatch: "*" });
      } catch (cause) {
        if (["PreconditionFailed", "ConditionalRequestConflict"].includes(cause.name)) throw cause;
        if (canonical(await closure(authorized.authorizationSha256)) !== canonical(record)) throw cause;
      }
      assert.deepEqual(await closure(authorized.authorizationSha256), record);
      return record;
    },
  };
  return api;
}
