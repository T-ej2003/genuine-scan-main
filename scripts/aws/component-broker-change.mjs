import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { assertBrokerConfiguration, brokerChangeEntryPoints, brokerConfiguration, brokerEntryPoints } from "./component-broker-configuration.mjs";
import { assertBrokerChangeAuthorization } from "./component-broker-change-authorization.mjs";
import { brokerChangeConfigurations, brokerChangeOperations, brokerChangePredecessor } from "./component-broker-change-contract.mjs";
import { assertCompletedRecoveryTrustAnchor, assertEffectiveBootstrapTrustAnchor, assertRecoveredBootstrapLineage } from "./component-bootstrap-trust-anchor.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { bootstrapManagedIdentities, brokerChangeManagedIdentities, componentBrokerArn, identityBootstrap, inspectBootstrapIdentities, inspectBrokerChangeIdentities } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const key = `${identityBootstrap.prefix}identity-bootstrap.json`;
const absent = error => error?.name === "ResourceNotFoundException";
const takeoverMarginMs = 60_000;
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);

export async function executeBrokerChange({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay }) {
  assert.equal(createHash("sha256").update(packageEvidence.bytes).digest("hex"), packageEvidence.packageSha256, "Successor package bytes differ");
  const approval = structuredClone(authorization), authorizationSha256 = assertBrokerChangeAuthorization(approval, packageEvidence, now());
  const human = structuredClone(operatorProof); assertComponentSessionRecord(human); assert.equal(human.purpose, "BROKER_CHANGE");
  for (const [field, value] of Object.entries({ sourceSha: approval.successorSourceSha, transitionId: approval.transitionId, authorizationSha256 })) assert.equal(human[field], value);
  assert(Date.parse(human.issuanceEventTime) >= Date.parse(approval.approvalObservedAt) - 999, "Broker change session predates approval");
  const owner = randomUUID(); let active, activeEtag;
  const authorize = async () => { assertBrokerChangeAuthorization(approval, packageEvidence, now()); assert(now() < Date.parse(human.expiresAt), "Broker change session expired"); await authenticate(); };
  const readJournal = async () => {
    const listing = await s3("ListObjectsV2", { Bucket: identityBootstrap.bucket, Prefix: key });
    assert.equal(listing.IsTruncated, false); assert.deepEqual((listing.Contents || []).map(({ Key }) => Key), [key], "Exact bootstrap journal required");
    const response = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key });
    assert(typeof response.ETag === "string" && response.ETag); return { value: JSON.parse(await response.Body.transformToString()), etag: response.ETag };
  };
  const put = async (next, etag) => {
    await authorize();
    try { await s3("PutObject", { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(next), ServerSideEncryption: "AES256", IfMatch: etag }); }
    catch {
      const observed = await readJournal(); assert.equal(canonical(observed.value), canonical(next), "Broker change CAS lost");
    }
    const observed = await readJournal(); assert.equal(canonical(observed.value), canonical(next), "Broker change journal readback differs"); return observed;
  };
  const read = async qualifier => lambda("GetFunction", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) });
  const ready = async qualifier => {
    for (let attempt = 0; attempt < 12; attempt++) {
      const fn = await read(qualifier); const { State, LastUpdateStatus } = fn.Configuration;
      if (State === "Active" && LastUpdateStatus === "Successful") return fn;
      assert(["Pending", "Active"].includes(State) && [undefined, "InProgress", "Successful"].includes(LastUpdateStatus), "Broker change cannot converge");
      await sleep(1000);
    }
    throw new Error("Broker change did not converge");
  };
  const versions = async () => {
    const result = [], seen = new Set(); let Marker;
    do { const page = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName, ...(Marker ? { Marker } : {}) });
      assert(Array.isArray(page.Versions)); result.push(...page.Versions.map(({ Version }) => Version)); Marker = page.NextMarker;
      if (Marker) { assert(typeof Marker === "string" && !seen.has(Marker) && seen.size < 20, "Incomplete broker versions"); seen.add(Marker); }
    } while (Marker);
    assert.equal(new Set(result).size, result.length); assert(result.includes("$LATEST"));
    return result.filter(version => version !== "$LATEST").sort((a, b) => Number(a) - Number(b));
  };
  const controls = async qualifier => ({ concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }), signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }), runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }) });
  const noPolicies = async () => { for (const qualifier of [null, "1", "2", "3", "4", "5", "6"]) try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); throw new Error("Unexpected broker resource policy"); } catch (error) { if (!absent(error)) throw error; } };
  const oldConfigurations = Object.fromEntries(Object.keys(brokerChangeEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: brokerChangePredecessor().recoveryPackageSha256, manifestSha256: brokerChangePredecessor().recoveryManifestSha256, entryPoint })]));
  const successor = brokerChangeConfigurations(packageEvidence);
  const assertPredecessor = async () => {
    const journal = await readJournal(); assertCompletedRecoveryTrustAnchor(journal.value);
    const fn = await ready(); assert.equal(fn.Configuration.CodeSha256, Buffer.from(brokerChangePredecessor().recoveryPackageSha256, "hex").toString("base64"));
    assert.deepEqual(await versions(), ["1", "2", "3"]); await noPolicies();
    const settings = await controls(); assertBrokerConfiguration(fn, { ...oldConfigurations.AUTHORIZE, FunctionArn: componentBrokerArn, Version: "$LATEST" }, settings);
    for (const [entryPoint, version] of Object.entries(brokerEntryPoints)) {
      const versioned = await ready(version);
      assertBrokerConfiguration(versioned, oldConfigurations[entryPoint], await controls(version));
    }
    assert((await inspectBootstrapIdentities(iam)).every(({ role, policy }) => role === "EXPECTED" && policy === "EXPECTED"), "Predecessor identities differ");
    return journal;
  };
  const claimRecord = () => ({ schemaVersion: 1, state: "EXECUTING", transitionId: approval.transitionId, authorizationSha256,
    sourceSha: approval.successorSourceSha, predecessor: brokerChangePredecessor(), successor: {
      sourceSha: approval.successorSourceSha, packageSha256: approval.successorPackageSha256, lambdaCodeSha256: approval.successorLambdaCodeSha256,
      manifestSha256: approval.successorManifestSha256, configurationSha256: approval.successorConfigurationSha256,
      identitySetSha256: approval.successorIdentitySetSha256, versions: ["4", "5", "6"] },
    configurationSha256: approval.successorConfigurationSha256, identitySetSha256: approval.successorIdentitySetSha256,
    remainingOperations: brokerChangeOperations, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt,
    authorizationHistory: [], owner, runtimeVersions: {}, policyCheckpoints: [] });
  const assertReservation = (existing) => {
    const required = ["schemaVersion", "state", "transitionId", "authorizationSha256", "sourceSha", "predecessor", "successor", "configurationSha256", "identitySetSha256", "remainingOperations", "authorizationExpiresAt", "sessionExpiresAt", "authorizationHistory", "owner", "runtimeVersions", "policyCheckpoints", ...(existing.state === "VERIFIED" ? ["identityReadbackSha256"] : [])];
    assert.deepEqual(Object.keys(existing).sort(), required.sort(), "Malformed broker change reservation");
    const states = ["EXECUTING", "CODE_UPDATED", "INSTALL_DESCRIPTION_SET", "VERSION_4", "CLEANUP_DESCRIPTION_SET", "VERSION_5", "AUTHORIZE_DESCRIPTION_SET", "VERSION_6", "IDENTITY_POLICY_1", "IDENTITY_POLICY_2", "IDENTITY_POLICY_3", "IDENTITY_POLICY_4", "IDENTITY_POLICY_5", "VERIFIED"];
    assert(states.includes(existing.state), "Unknown broker change checkpoint"); assert.deepEqual(existing.runtimeVersions, {}, "Active broker change cannot predeclare runtime versions");
    const roles = brokerChangeManagedIdentities().map(({ role }) => role), completed = existing.state === "VERIFIED" ? roles.length : existing.state.startsWith("IDENTITY_POLICY_") ? Number(existing.state.at(-1)) : 0;
    assert.deepEqual(existing.policyCheckpoints, roles.slice(0, completed), "Broker change policy checkpoint lineage differs");
    assert(Array.isArray(existing.authorizationHistory));
    const seen = new Set([existing.authorizationSha256]); assert.match(existing.authorizationSha256 || "", /^[a-f0-9]{64}$/);
    for (const prior of existing.authorizationHistory) {
      assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]);
      assert.match(prior.authorizationSha256 || "", /^[a-f0-9]{64}$/); uuid(prior.owner);
      for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(prior[field])).toISOString(), prior[field]);
      assert(!seen.has(prior.authorizationSha256), "Repeated broker change authorization"); seen.add(prior.authorizationSha256);
    }
  };
  await authorize(); let initial = await readJournal();
  let record = claimRecord();
  if (!Object.hasOwn(initial.value, "brokerChange")) {
    await assertPredecessor(); active = { ...initial.value, brokerChange: record }; ({ etag: activeEtag } = await put(active, initial.etag));
  } else {
    assertRecoveredBootstrapLineage(initial.value);
    const existing = initial.value.brokerChange;
    assert(existing && typeof existing === "object" && !Array.isArray(existing));
    if (existing.state === "BROKER_CHANGE_CLOSED") throw new Error("Broker change is already closed");
    assertReservation(existing); assert.equal(existing.transitionId, approval.transitionId); assert.equal(existing.sourceSha, approval.successorSourceSha);
    assert.deepEqual(existing.predecessor, brokerChangePredecessor()); assert.deepEqual(existing.successor, record.successor); assert.deepEqual(existing.remainingOperations, brokerChangeOperations); assert(Array.isArray(existing.policyCheckpoints) && existing.policyCheckpoints.every(role => brokerChangeManagedIdentities().some(target => target.role === role)) && new Set(existing.policyCheckpoints).size === existing.policyCheckpoints.length);
    assert.notEqual(existing.authorizationSha256, authorizationSha256, "Existing owner requires fresh authorization");
    const fenceAt = Math.max(Date.parse(existing.authorizationExpiresAt), Date.parse(existing.sessionExpiresAt)) + takeoverMarginMs;
    assert(now() >= fenceAt && Date.parse(human.issuanceEventTime) >= fenceAt, "Prior broker change owner is not safely fenced");
    record = { ...existing, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, owner,
      authorizationHistory: [...existing.authorizationHistory, { authorizationSha256: existing.authorizationSha256, authorizationExpiresAt: existing.authorizationExpiresAt, sessionExpiresAt: existing.sessionExpiresAt, owner: existing.owner }] };
    active = { ...initial.value, brokerChange: record }; ({ etag: activeEtag } = await put(active, initial.etag));
  }
  const checkpoint = async (state, patch = {}) => { record = { ...record, state, ...patch }; active = { ...active, brokerChange: record }; ({ etag: activeEtag } = await put(active, activeEtag)); };
  const guard = async () => { await authorize(); const observed = await readJournal(); assert.equal(canonical(observed.value), canonical(active), "Broker change owner is no longer current"); activeEtag = observed.etag; };
  const mutate = async (operation, input, reconcile) => { await guard(); try { await lambda(operation, input); } catch {} await reconcile(); };
  let latest = await ready(), published = await versions();
  const oldCode = Buffer.from(brokerChangePredecessor().recoveryPackageSha256, "hex").toString("base64");
  if (latest.Configuration.CodeSha256 === oldCode) {
    assert.deepEqual(published, ["1", "2", "3"]); const revision = latest.Configuration.RevisionId; assert(typeof revision === "string" && revision);
    await mutate("UpdateFunctionCode", { FunctionName: installationIdentity.functionName, ZipFile: Buffer.from(packageEvidence.bytes), Publish: false, RevisionId: revision }, async () => { latest = await ready(); assert.equal(latest.Configuration.CodeSha256, approval.successorLambdaCodeSha256, "Code update did not converge to successor"); });
    await checkpoint("CODE_UPDATED");
  } else assert.equal(latest.Configuration.CodeSha256, approval.successorLambdaCodeSha256, "Broker code is neither predecessor nor successor");
  for (const entryPoint of Object.keys(brokerChangeEntryPoints)) {
    const version = brokerChangeEntryPoints[entryPoint]; let versioned;
    try { versioned = await ready(version); } catch (error) { if (!absent(error)) throw error; }
    if (!versioned) {
      latest = await ready(); const expected = successor[entryPoint];
      if (latest.Configuration.Description !== expected.Description) {
        const revision = latest.Configuration.RevisionId; assert(typeof revision === "string" && revision);
        await mutate("UpdateFunctionConfiguration", { FunctionName: installationIdentity.functionName, Description: expected.Description, RevisionId: revision }, async () => { latest = await ready(); assert.equal(latest.Configuration.Description, expected.Description); });
        await checkpoint(`${entryPoint}_DESCRIPTION_SET`);
      }
      const revision = latest.Configuration.RevisionId; assert(typeof revision === "string" && revision);
      await mutate("PublishVersion", { FunctionName: installationIdentity.functionName, Description: expected.Description, CodeSha256: expected.CodeSha256, RevisionId: revision }, async () => { versioned = await ready(version); assertBrokerConfiguration(versioned, expected, await controls(version)); });
      await checkpoint(`VERSION_${version}`);
    }
    assertBrokerConfiguration(versioned, successor[entryPoint], await controls(version));
  }
  assert.deepEqual(await versions(), ["1", "2", "3", "4", "5", "6"]);
  for (const [index, target] of brokerChangeManagedIdentities().entries()) {
    const predecessor = bootstrapManagedIdentities().find(value => value.role === target.role); assert(predecessor);
    let observed = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName });
    const observedHash = digest(normalizeIamPolicyDocument(observed.PolicyDocument));
    assert([predecessor.policySha256, target.policySha256].includes(observedHash), "Broker identity policy is neither exact predecessor nor successor");
    if (!record.policyCheckpoints.includes(target.role) && observedHash !== target.policySha256) {
      await guard();
      try { await iam("PutRolePolicy", { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: canonical(target.policy) }); }
      catch { /* exact IAM readback decides whether an accepted response is safe */ }
    }
    observed = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName });
    assert.equal(observed.RoleName, target.role); assert.equal(observed.PolicyName, target.policyName);
    assert.equal(digest(normalizeIamPolicyDocument(observed.PolicyDocument)), target.policySha256, "Broker invocation policy rebinding did not converge");
    if (!record.policyCheckpoints.includes(target.role)) await checkpoint(`IDENTITY_POLICY_${index + 1}`, { policyCheckpoints: [...record.policyCheckpoints, target.role] });
  }
  await checkpoint("VERIFIED", { identityReadbackSha256: digest((await inspectBrokerChangeIdentities(iam))) });
  latest = await ready(); assertBrokerConfiguration(latest, { ...successor.AUTHORIZE, FunctionArn: componentBrokerArn, Version: "$LATEST" }, await controls()); await noPolicies();
  const runtimeVersions = Object.fromEntries(await Promise.all(Object.values(brokerChangeEntryPoints).map(async version => [version, (await ready(version)).Configuration.RuntimeVersionConfig.RuntimeVersionArn])));
  const closed = { ...active, brokerChange: { ...record, state: "BROKER_CHANGE_CLOSED", closedAt: new Date(now()).toISOString(), runtimeVersions } };
  await guard(); active = closed; ({ etag: activeEtag } = await put(closed, activeEtag));
  assertEffectiveBootstrapTrustAnchor((await readJournal()).value, packageEvidence.manifest, packageEvidence.packageSha256);
  return closed;
}
