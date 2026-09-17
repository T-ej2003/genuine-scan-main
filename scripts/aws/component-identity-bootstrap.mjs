import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { identityBootstrap, bootstrapManagedIdentities, inspectBootstrapIdentities } from "./component-installation-identity-contract.mjs";
import { assertIdentityBootstrapAuthorization } from "./component-identity-bootstrap-authorization.mjs";
import { bootstrapFixedBroker } from "./component-broker-bootstrap.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";

const bucket = identityBootstrap.bucket;
const key = `${identityBootstrap.prefix}identity-bootstrap.json`;

// Internal exceptional first-bootstrap transaction. Normal controllers do not
// import it. Authorization and MFA/admin credential issuance belong to its
// separate composition root, never caller-selected CLI documents or SDK inputs.
export async function executeIdentityBootstrap({ authorization, packageEvidence }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay }) {
  const approval = structuredClone(authorization);
  const authorizationSha256 = assertIdentityBootstrapAuthorization(approval, packageEvidence, now());
  const identities = bootstrapManagedIdentities();
  const owner = randomUUID();
  const record = { schemaVersion: 1, state: "BOOTSTRAP_EXECUTING", sourceSha: approval.sourceSha,
    transitionId: approval.transitionId, authorizationSha256, authorization: approval, owner,
    manifestSha256: approval.manifestSha256, identitySetSha256: approval.identitySetSha256, packageSha256: approval.packageSha256 };
  const read = async () => {
    const listing = await s3("ListObjectsV2", { Bucket: bucket, Prefix: key });
    assert.equal(listing.IsTruncated, false);
    assert((listing.Contents || []).length <= 1 && (listing.Contents || []).every(value => value.Key === key));
    if (!listing.Contents?.length) return null;
    const response = await s3("GetObject", { Bucket: bucket, Key: key });
    assert(typeof response.ETag === "string" && response.ETag);
    return { value: JSON.parse(await response.Body.transformToString()), etag: response.ETag };
  };
  const authorize = async () => {
    assertIdentityBootstrapAuthorization(approval, packageEvidence, now());
    await authenticate();
  };
  await authorize();
  assert.equal(await read(), null, "Bootstrap is already reserved or closed; no automatic administrative takeover");
  const baseline = await inspectBootstrapIdentities(iam);
  assert(baseline.every(target => target.role === "ABSENT" && target.policy === "ABSENT"), "First identity bootstrap must start absent");
  try {
    await lambda("GetFunction", { FunctionName: installationIdentity.functionName });
    assert.fail("First broker bootstrap must start absent");
  } catch (error) { if (error.name !== "ResourceNotFoundException") throw error; }
  await authorize();
  try {
    await s3("PutObject", { Bucket: bucket, Key: key, Body: canonical(record), ServerSideEncryption: "AES256", IfNoneMatch: "*" });
  } catch (error) {
    if (["PreconditionFailed", "ConditionalRequestConflict"].includes(error.name)) throw new Error("Concurrent bootstrap won reservation");
    const observed = await read();
    assert(observed && canonical(observed.value) === canonical(record), "Ambiguous bootstrap reservation");
  }
  const guard = async () => {
    await authorize();
    const observed = await read();
    assert(observed && canonical(observed.value) === canonical(record), "Bootstrap reservation no longer owned");
    return observed.etag;
  };
  const inspectTarget = async target => (await inspectBootstrapIdentities(iam)).find(value => value.arn === target.arn);
  const waitExpected = async (target, field) => {
    for (let attempt = 0; attempt < 12; attempt++) {
      await guard();
      const observed = await inspectTarget(target);
      if (observed[field] === "EXPECTED") return;
      assert.equal(observed[field], "ABSENT");
      await sleep(1000);
    }
    throw new Error("Identity readback did not converge; bootstrap remains reserved");
  };
  const write = async (operation, input, target, field) => {
    await guard();
    try { await iam(operation, input); }
    catch {
      // Readback, never retry, resolves ambiguous acceptance. An absent or
      // different target stops the transaction without releasing its reservation.
      await waitExpected(target, field);
      return;
    }
    await waitExpected(target, field);
  };
  for (const target of identities) {
    assert.equal((await inspectTarget(target)).role, "ABSENT");
    await write("CreateRole", { RoleName: target.role, Path: target.path, MaxSessionDuration: target.maxSessionDuration,
      AssumeRolePolicyDocument: canonical(target.trust), Tags: Object.entries(target.tags).map(([Key, Value]) => ({ Key, Value })) }, target, "role");
    assert.equal((await inspectTarget(target)).policy, "ABSENT");
    await write("PutRolePolicy", { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: canonical(target.policy) }, target, "policy");
  }
  const broker = await bootstrapFixedBroker(packageEvidence, { lambda, authorize: guard, sleep });
  const live = await inspectBootstrapIdentities(iam);
  assert(live.every(target => target.role === "EXPECTED" && target.policy === "EXPECTED"));
  const etag = await guard();
  const closed = { ...record, state: "BOOTSTRAP_CLOSED", identities: live, broker, runtimeVersions: broker.runtimeVersions, closedAt: new Date(now()).toISOString(), identityReadbackSha256: digest(live) };
  try {
    await s3("PutObject", { Bucket: bucket, Key: key, Body: canonical(closed), ServerSideEncryption: "AES256", IfMatch: etag });
  } catch (error) {
    if (["PreconditionFailed", "ConditionalRequestConflict"].includes(error.name)) throw new Error("Bootstrap closure CAS conflicted");
    assert.equal(canonical((await read())?.value), canonical(closed), "Ambiguous bootstrap closure");
  }
  assert.equal(canonical((await read())?.value), canonical(closed), "Bootstrap closure readback differs");
  return closed;
}
