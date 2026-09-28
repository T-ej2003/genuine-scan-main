import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { assertBrokerConfiguration, brokerConfiguration, brokerPolicySuccessorEntryPoints, brokerRecoverySuccessorEntryPoints, brokerSignerSuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { assertBrokerRecoverySuccessorAuthorization, authenticateFirstSuccessorLineage } from "./component-broker-recovery-successor-authorization.mjs";
import { assertBrokerRecoverySuccessorClosureMetadata, assertS3UserMetadataSize, assertVerifiedRecoveryClosurePredecessor, brokerRecoverySuccessor, brokerRecoverySuccessorBindings, brokerRecoverySuccessorClosure, brokerRecoverySuccessorConfigurations } from "./component-broker-recovery-successor-contract.mjs";
import { brokerSignerSuccessorConfigurations } from "./component-broker-signer-successor-contract.mjs";
import { assertEffectiveBootstrapTrustAnchor, assertHistoricalBrokerChangeClosure } from "./component-bootstrap-trust-anchor.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { brokerPolicySuccessorManagedIdentities, brokerRecoverySuccessorManagedIdentities, brokerSignerSuccessorManagedIdentities, identityBootstrap, inspectBrokerPolicySuccessorIdentities, inspectBrokerRecoverySuccessorIdentities, inspectBrokerSignerSuccessorIdentities } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const journalKey = `${identityBootstrap.prefix}identity-bootstrap.json`;
const absent = error => ["NoSuchKey", "NotFound", "ResourceNotFoundException"].includes(error?.name);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);

export async function executeBrokerRecoverySuccessor({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay,
  verifyEffective = assertEffectiveBootstrapTrustAnchor, inspectPredecessor = inspectBrokerPolicySuccessorIdentities, inspectSuccessor = inspectBrokerRecoverySuccessorIdentities }) {
  assert.equal(createHash("sha256").update(packageEvidence.bytes).digest("hex"), packageEvidence.packageSha256, "Successor package bytes differ");
  const readObject = async key => { const received = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key }); const text = await received.Body.transformToString(); assert(typeof received.ETag === "string" && received.ETag); return { value: JSON.parse(text), etag: received.ETag, metadata: received.Metadata || {} }; };
  const readJournal = () => readObject(journalKey);
  const readReservation = async () => { try { return await readObject(brokerRecoverySuccessor.reservationKey); } catch (error) { if (absent(error)) return null; throw error; } };
  const firstReservation = await readObject(`${identityBootstrap.prefix}broker-policy-successor.json`), initialJournal = await readJournal();
  const lineage = authenticateFirstSuccessorLineage({ reservation: firstReservation.value, reservationEtag: firstReservation.etag, metadata: initialJournal.metadata });
  const approval = structuredClone(authorization), authorizationSha256 = assertBrokerRecoverySuccessorAuthorization(approval, packageEvidence, lineage.closure, now());
  const human = structuredClone(operatorProof); assertComponentSessionRecord(human); assert.equal(human.purpose, "BROKER_RECOVERY_SUCCESSOR");
  for (const [field, value] of Object.entries({ sourceSha: approval.successor.sourceSha, transitionId: approval.transitionId, authorizationSha256 })) assert.equal(human[field], value);
  assert(Date.parse(human.issuanceEventTime) >= Date.parse(approval.approvalObservedAt) - 999);
  const bindings = brokerRecoverySuccessorBindings(packageEvidence, lineage.closure), owner = randomUUID();
  const authorize = async () => { assertBrokerRecoverySuccessorAuthorization(approval, packageEvidence, lineage.closure, now()); assert(now() < Date.parse(human.expiresAt)); await authenticate(); };
  const put = async (key, value, condition, metadata) => {
    await authorize(); assertS3UserMetadataSize(metadata || {}); const input = { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(value), ServerSideEncryption: "AES256", ...(metadata ? { Metadata: metadata } : {}), ...condition };
    try { await s3("PutObject", input); } catch (error) { const observed = await readObject(key); assert.equal(canonical(observed.value), canonical(value), `Successor checkpoint CAS lost after ${error?.name || "AWS persistence failure"}`); if (metadata) assert.deepEqual(observed.metadata, metadata, "Successor closure metadata differs"); return observed; }
    const observed = await readObject(key); assert.equal(canonical(observed.value), canonical(value), "Successor checkpoint readback differs"); if (metadata) assert.deepEqual(observed.metadata, metadata, "Successor closure metadata differs"); return observed;
  };
  const readFunction = async qualifier => lambda("GetFunction", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) });
  const ready = async qualifier => { for (let attempt = 0; attempt < 12; attempt++) { const fn = await readFunction(qualifier); if (fn.Configuration.State === "Active" && fn.Configuration.LastUpdateStatus === "Successful") return fn; await sleep(1000); } throw new Error("Broker successor did not converge"); };
  const controls = async qualifier => ({ concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }), signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }), runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }) });
  const noPolicies = async () => { for (const qualifier of [null, "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]) try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); throw new Error("Unexpected broker invocation bypass"); } catch (error) { if (!absent(error)) throw error; } };
  const versions = async () => { const response = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName }); assert.equal(response.NextMarker, undefined); return response.Versions.map(({ Version }) => Version).filter(value => value !== "$LATEST").sort((a, b) => Number(a) - Number(b)); };
  const oldConfigurations = Object.fromEntries(Object.keys(brokerPolicySuccessorEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: lineage.bindings.successor.packageSha256, manifestSha256: lineage.bindings.successor.manifestSha256, entryPoint, entryPoints: brokerPolicySuccessorEntryPoints })]));
  const successorStates = ["EXECUTING", "CODE_UPDATED", "INSTALL_DESCRIPTION_SET", "INSTALL_VERSION_PUBLISHED", "CLEANUP_DESCRIPTION_SET", "CLEANUP_VERSION_PUBLISHED", "AUTHORIZE_DESCRIPTION_SET", "AUTHORIZE_VERSION_PUBLISHED", "BROKER_POLICY_INSTALLED", "POLICY_INSTALLED", "INSTALLATION_SESSION_POLICY_INSTALLED", "CLEANUP_SESSION_POLICY_INSTALLED", "AUTHORIZATION_SESSION_POLICY_INSTALLED", "VERIFIED"];
  const authenticatePredecessor = async journal => {
    const observed = authenticateFirstSuccessorLineage({ reservation: firstReservation.value, reservationEtag: firstReservation.etag, metadata: journal.metadata });
    assert.equal(canonical(observed.closure), canonical(lineage.closure), "First successor closure changed");
    assert.deepEqual(await versions(), ["1", "2", "3", "4", "5", "6", "7", "8", "9"]);
    for (const [entryPoint, version] of Object.entries(brokerPolicySuccessorEntryPoints)) assertBrokerConfiguration(await ready(version), oldConfigurations[entryPoint], await controls(version));
    const live = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === installationIdentity.terraformRole), policy = await iam("GetRolePolicy", { RoleName: live.role, PolicyName: live.policyName });
    assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), live.policySha256, "Recovery predecessor executor policy differs");
    assert((await inspectPredecessor(iam)).every(({ role, policy: state }) => role === "EXPECTED" && state === "EXPECTED"), "Recovery predecessor identities differ");
  };
  const claim = { schemaVersion: 1, state: "EXECUTING", transitionId: approval.transitionId, owner, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [], bindings };
  const assertClaim = value => { assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "bindings", "owner", "schemaVersion", "sessionExpiresAt", "state", "transitionId"].sort()); assert.equal(value.schemaVersion, 1); uuid(value.owner); assert.match(value.authorizationSha256 || "", /^[a-f0-9]{64}$/); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(value[field])).toISOString(), value[field]); assert.equal(canonical(value.bindings), canonical(bindings)); assert(successorStates.includes(value.state)); assert(Array.isArray(value.authorizationHistory)); const seen = new Set([value.authorizationSha256]); for (const prior of value.authorizationHistory) { assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]); assert.match(prior.authorizationSha256 || "", /^[a-f0-9]{64}$/); assert(!seen.has(prior.authorizationSha256)); seen.add(prior.authorizationSha256); uuid(prior.owner); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(prior[field])).toISOString(), prior[field]); } };
  await authorize(); const journal = await readJournal(); assert.equal(journal.etag, initialJournal.etag, "First successor lineage changed before reservation");
  if (Object.hasOwn(journal.metadata, brokerRecoverySuccessor.metadataKey)) { assertBrokerRecoverySuccessorClosureMetadata(journal.metadata, bindings, undefined, undefined, journal.value); assert.fail("Broker recovery successor is already closed"); }
  let reservation = await readReservation(), reservationEtag;
  if (!reservation) { await authenticatePredecessor(journal); ({ etag: reservationEtag } = await put(brokerRecoverySuccessor.reservationKey, claim, { IfNoneMatch: "*" })); reservation = { value: claim, etag: reservationEtag }; }
  else {
    assertClaim(reservation.value); assert.equal(reservation.value.transitionId, approval.transitionId); reservationEtag = reservation.etag;
    assert.notEqual(reservation.value.authorizationSha256, authorizationSha256, "Successor authorization already consumed");
    const fence = Math.max(Date.parse(reservation.value.authorizationExpiresAt), Date.parse(reservation.value.sessionExpiresAt)) + 120000;
    assert(now() > fence && Date.parse(human.issuanceEventTime) > fence, "Prior successor owner is not safely fenced");
    const previous = { authorizationSha256: reservation.value.authorizationSha256, authorizationExpiresAt: reservation.value.authorizationExpiresAt, sessionExpiresAt: reservation.value.sessionExpiresAt, owner: reservation.value.owner };
    reservation.value = { ...reservation.value, owner, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [...reservation.value.authorizationHistory, previous] };
    ({ etag: reservationEtag } = await put(brokerRecoverySuccessor.reservationKey, reservation.value, { IfMatch: reservationEtag }));
  }
  let record = reservation.value;
  const checkpoint = async state => { record = { ...record, state }; ({ etag: reservationEtag } = await put(brokerRecoverySuccessor.reservationKey, record, { IfMatch: reservationEtag })); };
  const guard = async () => { await authorize(); const observed = await readReservation(); assert.equal(canonical(observed?.value), canonical(record), "Successor owner changed"); reservationEtag = observed.etag; };
  const mutate = async (service, operation, input, reconcile) => { await guard(); try { await service(operation, input); } catch {} await reconcile(); };
  const successorConfigurations = brokerRecoverySuccessorConfigurations(packageEvidence), successorCode = bindings.successor.lambdaCodeSha256;
  let latest = await ready();
  if (latest.Configuration.CodeSha256 !== successorCode) {
    assert.equal(latest.Configuration.CodeSha256, Buffer.from(lineage.bindings.successor.packageSha256, "hex").toString("base64"));
    await mutate(lambda, "UpdateFunctionCode", { FunctionName: installationIdentity.functionName, ZipFile: Buffer.from(packageEvidence.bytes), Publish: false, RevisionId: latest.Configuration.RevisionId }, async () => { latest = await ready(); assert.equal(latest.Configuration.CodeSha256, successorCode); });
    await checkpoint("CODE_UPDATED");
  }
  const published = {};
  for (const entryPoint of Object.keys(brokerRecoverySuccessorEntryPoints)) {
    const version = brokerRecoverySuccessorEntryPoints[entryPoint], configuration = successorConfigurations[entryPoint];
    try { published[version] = await ready(version); } catch (error) { if (!absent(error)) throw error; }
    if (!published[version]) {
      latest = await ready(); if (latest.Configuration.Description !== configuration.Description) {
        await mutate(lambda, "UpdateFunctionConfiguration", { FunctionName: installationIdentity.functionName, Description: configuration.Description, RevisionId: latest.Configuration.RevisionId }, async () => { latest = await ready(); assert.equal(latest.Configuration.Description, configuration.Description); });
        await checkpoint(`${entryPoint}_DESCRIPTION_SET`);
      }
      await mutate(lambda, "PublishVersion", { FunctionName: installationIdentity.functionName, Description: configuration.Description, CodeSha256: configuration.CodeSha256, RevisionId: latest.Configuration.RevisionId }, async () => { published[version] = await ready(version); assertBrokerConfiguration(published[version], configuration, await controls(version)); });
    }
    assertBrokerConfiguration(published[version], configuration, await controls(version));
    if (successorStates.indexOf(record.state) < successorStates.indexOf(`${entryPoint}_VERSION_PUBLISHED`)) await checkpoint(`${entryPoint}_VERSION_PUBLISHED`);
  }
  const verifiedRecovery = record.state === "VERIFIED", listed = await versions();
  assert(listed.length >= 12 && listed.length <= (verifiedRecovery ? 15 : 12));
  assert.deepEqual(listed, Array.from({ length: listed.length }, (_, index) => String(index + 1)), "Recovery generations differ");
  const predecessorIdentities = brokerPolicySuccessorManagedIdentities(), successorIdentities = brokerRecoverySuccessorManagedIdentities();
  const installPolicy = async (role, predecessorSha256, successorSha256, state, label) => {
    const target = successorIdentities.find(identity => identity.role === role), predecessorTarget = predecessorIdentities.find(identity => identity.role === role);
    assert(target && predecessorTarget && target.policyName === predecessorTarget.policyName);
    let policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }), policySha = digest(normalizeIamPolicyDocument(policy.PolicyDocument));
    const compatibleSha256 = brokerSignerSuccessorManagedIdentities().find(identity => identity.role === role)?.policySha256;
    assert([predecessorSha256, successorSha256, ...(verifiedRecovery ? [compatibleSha256] : [])].includes(policySha), `${label} policy is outside authorized generation lineage`);
    assert(!verifiedRecovery || policySha !== predecessorSha256, `${label} predecessor cannot follow VERIFIED recovery`);
    if (verifiedRecovery && policySha === compatibleSha256) return;
    if (policySha !== successorSha256) {
      await guard(); policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }); assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), predecessorSha256, `${label} policy CAS predecessor changed`);
      await authorize();
      try { await iam("PutRolePolicy", { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: canonical(target.policy) }); } catch {}
      policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }); assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), successorSha256, `${label} policy successor did not converge`);
    }
    if (successorStates.indexOf(record.state) < successorStates.indexOf(state)) await checkpoint(state);
  };
  for (const [role, state, label] of [[installationIdentity.provisionerRole, "BROKER_POLICY_INSTALLED", "Broker execution"], [installationIdentity.terraformRole, "POLICY_INSTALLED", "Executor"]]) {
    const predecessor = predecessorIdentities.find(identity => identity.role === role), successor = successorIdentities.find(identity => identity.role === role);
    await installPolicy(role, predecessor.policySha256, successor.policySha256, state, label);
  }
  for (const [role, state, label] of [
    [identityBootstrap.installationRole, "INSTALLATION_SESSION_POLICY_INSTALLED", "Installation session"],
    [identityBootstrap.cleanupRole, "CLEANUP_SESSION_POLICY_INSTALLED", "Cleanup session"],
    [identityBootstrap.authorizationRole, "AUTHORIZATION_SESSION_POLICY_INSTALLED", "Authorization session"],
  ]) {
    const predecessorSession = predecessorIdentities.find(identity => identity.role === role), successorSession = successorIdentities.find(identity => identity.role === role);
    await installPolicy(role, predecessorSession.policySha256, successorSession.policySha256, state, label);
  }
  if (!verifiedRecovery) { const identities = await inspectSuccessor(iam); assert(identities.every(({ role, policy: state }) => role === "EXPECTED" && state === "EXPECTED")); await noPolicies(); await checkpoint("VERIFIED"); }
  else await noPolicies();
  const compatible = await convergeCompatibleSignerRuntime({ iam, lambda, packageEvidence, guard, oldPackageSha256: bindings.successor.packageSha256, sleep });
  const closedAt = new Date(now()).toISOString(), runtimeVersions = Object.fromEntries(Object.entries(brokerRecoverySuccessorEntryPoints).map(([, version]) => [version, published[version].Configuration.RuntimeVersionConfig.RuntimeVersionArn]));
  const finalRecord = { ...record, state: "BROKER_RECOVERY_SUCCESSOR_CLOSED", closedAt, runtimeVersions };
  const currentJournal = await readJournal(); assert.equal(currentJournal.etag, journal.etag, "Bootstrap lineage changed during successor transition");
  assert.equal(canonical(authenticateFirstSuccessorLineage({ reservation: firstReservation.value, reservationEtag: firstReservation.etag, metadata: currentJournal.metadata }).closure), canonical(lineage.closure), "First successor closure changed during successor transition");
  assert.equal(assertEffectiveBootstrapTrustAnchor(currentJournal.value, packageEvidence.manifest, packageEvidence.packageSha256, currentJournal.metadata, firstReservation, { value: record, etag: reservationEtag }, null, true).pendingSignerClosure, true);
  const closure = brokerRecoverySuccessorClosure(record, bindings, runtimeVersions, reservationEtag, closedAt, currentJournal.metadata);
  const closedBody = { ...currentJournal.value, brokerRecoverySuccessorClosure: closure.value };
  await guard();
  assert.deepEqual(await inspectBrokerSignerSuccessorIdentities(iam), compatible.nextIdentities.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })), "Active compatible reader changed before closure");
  for (const [entryPoint, version] of Object.entries(brokerSignerSuccessorEntryPoints)) assertBrokerConfiguration(await compatible.ready(version), compatible.successorConfigurations[entryPoint], await compatible.controls(version));
  await put(journalKey, closedBody, { IfMatch: currentJournal.etag }, closure.metadata); assertBrokerRecoverySuccessorClosureMetadata(closure.metadata, bindings, record, reservationEtag, closedBody);
  const closedJournal = await readJournal(); verifyEffective(closedJournal.value, packageEvidence.manifest, packageEvidence.packageSha256, closedJournal.metadata, firstReservation, { value: record, etag: reservationEtag });
  return { ...closedJournal.value, brokerRecoverySuccessor: finalRecord };
}

async function convergeCompatibleSignerRuntime({ iam, lambda, packageEvidence, guard, oldPackageSha256, sleep }) {
  const oldIdentities = brokerRecoverySuccessorManagedIdentities(), nextIdentities = brokerSignerSuccessorManagedIdentities();
  const ready = async qualifier => { for (let attempt = 0; attempt < 12; attempt++) { const fn = await lambda("GetFunction", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); if (fn.Configuration.State === "Active" && fn.Configuration.LastUpdateStatus === "Successful") return fn; await sleep(1000); } assert.fail("Compatible broker runtime did not converge"); };
  const controls = async qualifier => ({ concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }), signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }), runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }) });
  const successorConfigurations = brokerSignerSuccessorConfigurations(packageEvidence);
  let latest = await ready();
  const candidateCode = Buffer.from(packageEvidence.packageSha256, "hex").toString("base64");
  if (latest.Configuration.CodeSha256 !== candidateCode) {
    assert.equal(latest.Configuration.CodeSha256, Buffer.from(oldPackageSha256, "hex").toString("base64"), "Unreviewed broker code predecessor");
    await guard(); try { await lambda("UpdateFunctionCode", { FunctionName: installationIdentity.functionName, ZipFile: Buffer.from(packageEvidence.bytes), Publish: false, RevisionId: latest.Configuration.RevisionId }); } catch {}
    latest = await ready(); assert.equal(latest.Configuration.CodeSha256, candidateCode, "Compatible broker code did not converge");
  }
  for (const [entryPoint, version] of Object.entries(brokerSignerSuccessorEntryPoints)) {
    const config = successorConfigurations[entryPoint]; let published;
    try { published = await ready(version); } catch (error) { if (!absent(error)) throw error; }
    if (!published) {
      latest = await ready(); if (latest.Configuration.Description !== config.Description) {
        await guard(); try { await lambda("UpdateFunctionConfiguration", { FunctionName: installationIdentity.functionName, Description: config.Description, RevisionId: latest.Configuration.RevisionId }); } catch {}
        latest = await ready(); assert.equal(latest.Configuration.Description, config.Description, "Compatible broker description did not converge");
      }
      await guard(); try { await lambda("PublishVersion", { FunctionName: installationIdentity.functionName, Description: config.Description, CodeSha256: config.CodeSha256, RevisionId: latest.Configuration.RevisionId }); } catch {}
      published = await ready(version);
    }
    assertBrokerConfiguration(published, config, await controls(version));
  }
  const afterPublication = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName }); assert.equal(afterPublication.NextMarker, undefined);
  assert.deepEqual(afterPublication.Versions.map(({ Version }) => Version).filter(value => value !== "$LATEST").sort((a, b) => Number(a) - Number(b)), Array.from({ length: 15 }, (_, i) => String(i + 1)));
  for (const qualifier of Object.values(brokerSignerSuccessorEntryPoints)) {
    try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, Qualifier: qualifier }); assert.fail("Unexpected compatible broker invocation bypass"); }
    catch (error) { if (!absent(error)) throw error; }
  }
  for (const old of oldIdentities) {
    const next = nextIdentities.find(item => item.role === old.role);
    let policy = await iam("GetRolePolicy", { RoleName: old.role, PolicyName: old.policyName }); let sha = digest(normalizeIamPolicyDocument(policy.PolicyDocument));
    assert([old.policySha256, next.policySha256].includes(sha), "Unreviewed signer identity predecessor");
    if (sha !== next.policySha256) {
      await guard(); policy = await iam("GetRolePolicy", { RoleName: old.role, PolicyName: old.policyName }); assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), old.policySha256, "Signer identity CAS predecessor changed");
      try { await iam("PutRolePolicy", { RoleName: next.role, PolicyName: next.policyName, PolicyDocument: canonical(next.policy) }); } catch {}
      policy = await iam("GetRolePolicy", { RoleName: next.role, PolicyName: next.policyName }); sha = digest(normalizeIamPolicyDocument(policy.PolicyDocument)); assert.equal(sha, next.policySha256, "Compatible signer identity did not converge");
    }
  }
  assert.deepEqual(await inspectBrokerSignerSuccessorIdentities(iam), nextIdentities.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })), "Compatible active signer identities differ");
  return { nextIdentities, successorConfigurations, ready, controls };
}

// The reviewed 10/11/12 and five recovery IAM successors are already live.
// This fenced continuation publishes only new compatible versions and moves
// invocation grants before it writes the missing compact journal closure.
export async function closeVerifiedBrokerRecoverySuccessor({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay }) {
  assert.equal(createHash("sha256").update(packageEvidence.bytes).digest("hex"), packageEvidence.packageSha256, "Closure package bytes differ");
  const approval = structuredClone(authorization);
  assert(approval.resume, "Closure-only authorization required");
  const authorizationSha256 = assertBrokerRecoverySuccessorAuthorization(approval, packageEvidence, approval.firstClosure, now());
  const human = structuredClone(operatorProof); assertComponentSessionRecord(human);
  assert.equal(human.purpose, "BROKER_RECOVERY_SUCCESSOR");
  for (const [field, value] of Object.entries({ sourceSha: approval.successor.sourceSha, transitionId: approval.transitionId, authorizationSha256 })) assert.equal(human[field], value);
  assert(Date.parse(human.issuanceEventTime) >= Date.parse(approval.approvalObservedAt) - 999);
  const authorize = async () => { assertBrokerRecoverySuccessorAuthorization(approval, packageEvidence, approval.firstClosure, now()); assert(now() < Date.parse(human.expiresAt)); await authenticate(); };
  const read = async key => { const result = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key }); assert(result.ETag); return { value: JSON.parse(await result.Body.transformToString()), metadata: result.Metadata || {}, etag: result.ETag }; };
  const [first, initial, partial] = await Promise.all([read(`${identityBootstrap.prefix}broker-policy-successor.json`), read(journalKey), read(brokerRecoverySuccessor.reservationKey)]);
  const lineage = authenticateFirstSuccessorLineage({ reservation: first.value, reservationEtag: first.etag, metadata: initial.metadata });
  assert.deepEqual(lineage.closure, approval.firstClosure);
  assert.deepEqual(Object.keys(initial.metadata), ["broker-policy-successor"], "Second successor closure already exists");
  assertHistoricalBrokerChangeClosure(initial.value);
  const bindings = assertVerifiedRecoveryClosurePredecessor(partial.value, lineage.closure);
  assert.equal(approval.transitionId, partial.value.transitionId);
  assert.deepEqual(approval.resume, { reservationSha256: digest(partial.value), reservationEtagSha256: digest(partial.etag) }, "Closure reservation changed after authorization");
  assert.notEqual(partial.value.authorizationSha256, authorizationSha256, "Consumed authorization cannot replay");
  const fence = Math.max(Date.parse(partial.value.authorizationExpiresAt), Date.parse(partial.value.sessionExpiresAt)) + 120000;
  assert(now() > fence && Date.parse(human.issuanceEventTime) > fence, "Prior successor owner is not safely fenced");
  await authorize();
  const versions = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName });
  assert.equal(versions.NextMarker, undefined);
  const listed = versions.Versions.map(({ Version }) => Version).filter(value => value !== "$LATEST").sort((a, b) => Number(a) - Number(b));
  assert(listed.length >= 12 && listed.length <= 15);
  assert.deepEqual(listed, Array.from({ length: listed.length }, (_, i) => String(i + 1)), "Unexpected or skipped immutable broker generation");
  const configurations = Object.fromEntries(Object.keys(brokerRecoverySuccessorEntryPoints).map(entryPoint => [entryPoint,
    brokerConfiguration({ packageSha256: bindings.successor.packageSha256, manifestSha256: bindings.successor.manifestSha256, entryPoint, entryPoints: brokerRecoverySuccessorEntryPoints })]));
  const runtimeVersions = {};
  for (const [entryPoint, version] of Object.entries(brokerRecoverySuccessorEntryPoints)) {
    const functionState = await lambda("GetFunction", { FunctionName: installationIdentity.functionName, Qualifier: version });
    const controls = { concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }), signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }), runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, Qualifier: version }) };
    assertBrokerConfiguration(functionState, configurations[entryPoint], controls);
    runtimeVersions[version] = functionState.Configuration.RuntimeVersionConfig.RuntimeVersionArn;
  }
  const oldIdentities = brokerRecoverySuccessorManagedIdentities(), nextIdentities = brokerSignerSuccessorManagedIdentities();
  for (const old of oldIdentities) {
    const next = nextIdentities.find(item => item.role === old.role);
    assert(next && next.policyName === old.policyName && next.arn === old.arn);
    const observed = await iam("GetRolePolicy", { RoleName: old.role, PolicyName: old.policyName });
    assert([old.policySha256, next.policySha256].includes(digest(normalizeIamPolicyDocument(observed.PolicyDocument))), "Successor IAM policy is outside exact generations");
  }
  for (const qualifier of [null, ...Array.from({ length: listed.length }, (_, i) => String(i + 1))]) {
    try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); assert.fail("Unexpected broker invocation bypass"); }
    catch (error) { if (!absent(error)) throw error; }
  }
  const current = await read(brokerRecoverySuccessor.reservationKey); assert.equal(current.etag, partial.etag); assert.deepEqual(current.value, partial.value);
  const previous = { authorizationSha256: partial.value.authorizationSha256, authorizationExpiresAt: partial.value.authorizationExpiresAt, sessionExpiresAt: partial.value.sessionExpiresAt, owner: partial.value.owner };
  const record = { ...partial.value, owner: randomUUID(), authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [...partial.value.authorizationHistory, previous] };
  await authorize();
  assertS3UserMetadataSize({});
  try { await s3("PutObject", { Bucket: identityBootstrap.bucket, Key: brokerRecoverySuccessor.reservationKey, Body: canonical(record), ServerSideEncryption: "AES256", IfMatch: partial.etag }); }
  catch (error) { const observed = await read(brokerRecoverySuccessor.reservationKey); assert.deepEqual(observed.value, record, `Recovery reservation CAS failed after ${error?.name || "AWS persistence failure"}`); }
  const reserved = await read(brokerRecoverySuccessor.reservationKey); assert.deepEqual(reserved.value, record);
  const guard = async () => { await authorize(); const observed = await read(brokerRecoverySuccessor.reservationKey); assert.deepEqual(observed.value, record, "Recovery owner changed"); assert.equal(observed.etag, reserved.etag, "Recovery reservation ETag changed"); };
  const { successorConfigurations, ready, controls } = await convergeCompatibleSignerRuntime({ iam, lambda, packageEvidence, guard, oldPackageSha256: bindings.successor.packageSha256, sleep });
  const currentJournal = await read(journalKey); assert.equal(currentJournal.etag, initial.etag, "Bootstrap journal changed during closure");
  assert.deepEqual(currentJournal.metadata, initial.metadata); assert.deepEqual(currentJournal.value, initial.value);
  const pending = assertEffectiveBootstrapTrustAnchor(currentJournal.value, packageEvidence.manifest, packageEvidence.packageSha256, currentJournal.metadata, first, reserved, null, true);
  assert.equal(pending.pendingSignerClosure, true, "Active compatible broker cannot authenticate pending lineage");
  const closure = brokerRecoverySuccessorClosure(record, bindings, runtimeVersions, reserved.etag, new Date(now()).toISOString(), currentJournal.metadata);
  const body = { ...currentJournal.value, brokerRecoverySuccessorClosure: closure.value };
  await guard();
  assert.deepEqual(await inspectBrokerSignerSuccessorIdentities(iam), nextIdentities.map(({ arn }) => ({ arn, role: "EXPECTED", policy: "EXPECTED" })), "Active compatible reader changed before closure");
  for (const [entryPoint, version] of Object.entries(brokerSignerSuccessorEntryPoints)) assertBrokerConfiguration(await ready(version), successorConfigurations[entryPoint], await controls(version));
  assertS3UserMetadataSize(closure.metadata);
  try { await s3("PutObject", { Bucket: identityBootstrap.bucket, Key: journalKey, Body: canonical(body), Metadata: closure.metadata, ServerSideEncryption: "AES256", IfMatch: currentJournal.etag }); }
  catch (error) { const observed = await read(journalKey); assert.deepEqual(observed.value, body, `Recovery closure persistence failed after ${error?.name || "AWS persistence failure"}`); assert.deepEqual(observed.metadata, closure.metadata); }
  const closed = await read(journalKey); assert.deepEqual(closed.value, body); assert.deepEqual(closed.metadata, closure.metadata);
  assertBrokerRecoverySuccessorClosureMetadata(closed.metadata, bindings, record, reserved.etag, closed.value);
  return { state: "BROKER_RECOVERY_SUCCESSOR_CLOSED", closure: closure.value };
}
