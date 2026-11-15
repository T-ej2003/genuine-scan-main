import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { assertBrokerConfiguration, brokerConfiguration, brokerSignerSuccessorEntryPoints, brokerStaleSignerSuccessorEntryPoints } from "./component-broker-configuration.mjs";
import { authenticateSecondSuccessorLineage } from "./component-broker-signer-successor-authorization.mjs";
import { assertBrokerSignerSuccessorClosureMetadata } from "./component-broker-signer-successor-contract.mjs";
import { assertStaleSignerSuccessorAuthorization } from "./component-broker-stale-signer-successor-authorization.mjs";
import { assertStaleSignerSuccessorClosure, staleSignerPublisherPolicy, staleSignerSuccessor, staleSignerSuccessorBindings, staleSignerSuccessorClosure, staleSignerSuccessorConfigurations } from "./component-broker-stale-signer-successor-contract.mjs";
import { assertS3UserMetadataSize } from "./component-broker-recovery-successor-contract.mjs";
import { assertEffectiveBootstrapTrustAnchor } from "./component-bootstrap-trust-anchor.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { brokerSignerSuccessorManagedIdentities, brokerStaleSignerSuccessorManagedIdentities, componentBrokerArn, identityBootstrap, inspectBrokerSignerSuccessorIdentities, inspectBrokerStaleSignerSuccessorIdentities } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const journalKey = `${identityBootstrap.prefix}identity-bootstrap.json`;
const absent = error => ["NoSuchKey", "NotFound", "ResourceNotFoundException"].includes(error?.name);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
const releasePolicyArn = `arn:aws:iam::${identityBootstrap.account}:policy/MSCQRProductionGreenStageARelease`;
const steadyPolicy = normalizeIamPolicyDocument(JSON.parse(fs.readFileSync(new URL("../../documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", import.meta.url), "utf8")));
const publisherTrust = normalizeIamPolicyDocument(JSON.parse(fs.readFileSync(new URL("../../infra/aws/terraform/production-initial-activation-policy-reconciler/signer-policy-installer-trust-policy.json", import.meta.url), "utf8")));

export async function executeStaleSignerSuccessor({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay,
  verifyEffective = assertEffectiveBootstrapTrustAnchor, inspectPredecessor = inspectBrokerSignerSuccessorIdentities, inspectSuccessor = inspectBrokerStaleSignerSuccessorIdentities }) {
  assert.equal(createHash("sha256").update(packageEvidence.bytes).digest("hex"), packageEvidence.packageSha256, "Successor package bytes differ");
  const readObject = async key => { const received = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key }); const text = await received.Body.transformToString(); assert(typeof received.ETag === "string" && received.ETag); return { value: JSON.parse(text), etag: received.ETag, metadata: received.Metadata || {} }; };
  const readJournal = () => readObject(journalKey);
  const readReservation = async () => { try { return await readObject(staleSignerSuccessor.reservationKey); } catch (error) { if (absent(error)) return null; throw error; } };
  const firstReservation = await readObject(`${identityBootstrap.prefix}broker-policy-successor.json`);
  const secondReservation = await readObject(`${identityBootstrap.prefix}broker-recovery-successor.json`);
  const thirdReservation = await readObject(`${identityBootstrap.prefix}broker-signer-successor.json`), initialJournal = await readJournal();
  const secondLineage = authenticateSecondSuccessorLineage({ reservation: secondReservation.value, reservationEtag: secondReservation.etag, metadata: initialJournal.metadata, bootstrap: initialJournal.value });
  const historicalMetadata = initialJournal.metadata;
  const thirdClosure = assertBrokerSignerSuccessorClosureMetadata(historicalMetadata, thirdReservation.value.bindings, thirdReservation.value, thirdReservation.etag, initialJournal.value);
  assert.equal(digest(thirdReservation.value.bindings.secondClosure), digest(secondLineage.closure), "Signer predecessor closure differs");
  const predecessor = { closure: thirdClosure };
  const approval = structuredClone(authorization), authorizationSha256 = assertStaleSignerSuccessorAuthorization(approval, packageEvidence, predecessor, now());
  const human = structuredClone(operatorProof); assertComponentSessionRecord(human); assert.equal(human.purpose, "BROKER_STALE_SIGNER_SUCCESSOR");
  for (const [field, value] of Object.entries({ sourceSha: approval.sourceSha, transitionId: approval.transitionId, authorizationSha256 })) assert.equal(human[field], value);
  assert(Date.parse(human.issuanceEventTime) >= Date.parse(approval.approvalObservedAt) - 999);
  const bindings = staleSignerSuccessorBindings(packageEvidence, thirdClosure, thirdReservation.value, thirdReservation.etag, historicalMetadata, initialJournal.value), owner = randomUUID();
  const authorize = async () => { assertStaleSignerSuccessorAuthorization(approval, packageEvidence, predecessor, now()); assert(now() < Date.parse(human.expiresAt)); await authenticate(); };
  const put = async (key, value, condition, metadata) => {
    await authorize(); assertS3UserMetadataSize(metadata || {}); const input = { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(value), ServerSideEncryption: "AES256", ...(metadata ? { Metadata: metadata } : {}), ...condition };
    try { await s3("PutObject", input); } catch { const observed = await readObject(key); assert.equal(canonical(observed.value), canonical(value), "Successor checkpoint CAS lost"); if (metadata) assert.deepEqual(observed.metadata, metadata, "Successor closure metadata differs"); return observed; }
    const observed = await readObject(key); assert.equal(canonical(observed.value), canonical(value), "Successor checkpoint readback differs"); if (metadata) assert.deepEqual(observed.metadata, metadata, "Successor closure metadata differs"); return observed;
  };
  const readFunction = async qualifier => lambda("GetFunction", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) });
  const ready = async qualifier => { for (let attempt = 0; attempt < 12; attempt++) { const fn = await readFunction(qualifier); if (fn.Configuration.State === "Active" && fn.Configuration.LastUpdateStatus === "Successful") return fn; await sleep(1000); } throw new Error("Broker successor did not converge"); };
  const controls = async qualifier => ({ concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }), signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }), runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }) });
  const noPolicies = async () => { for (const qualifier of [null, ...Array.from({ length: 18 }, (_, i) => String(i + 1))]) try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); throw new Error("Unexpected broker invocation bypass"); } catch (error) { if (!absent(error)) throw error; } };
  const versions = async () => { const response = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName }); assert.equal(response.NextMarker, undefined); return response.Versions.map(({ Version }) => Version).filter(value => value !== "$LATEST").sort((a, b) => Number(a) - Number(b)); };
  const oldConfigurations = Object.fromEntries(Object.keys(brokerSignerSuccessorEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: thirdReservation.value.bindings.successor.packageSha256, manifestSha256: thirdReservation.value.bindings.successor.manifestSha256, entryPoint, entryPoints: brokerSignerSuccessorEntryPoints })]));
  const publisherRole = "mscqr-production-signer-policy-installer", publisherPolicyName = "ProductionSignerPolicyInstaller";
  const predecessorPublisherPolicy = { ...staleSignerPublisherPolicy, Statement: [{ ...staleSignerPublisherPolicy.Statement[0], Resource: `${componentBrokerArn}:15` }] };
  const publisher = async () => iam("GetRolePolicy", { RoleName: publisherRole, PolicyName: publisherPolicyName });
  const successorStates = ["EXECUTING", "CODE_UPDATED", "INSTALL_DESCRIPTION_SET", "INSTALL_VERSION_PUBLISHED", "CLEANUP_DESCRIPTION_SET", "CLEANUP_VERSION_PUBLISHED", "AUTHORIZE_DESCRIPTION_SET", "AUTHORIZE_VERSION_PUBLISHED", "BROKER_POLICY_INSTALLED", "POLICY_INSTALLED", "INSTALLATION_SESSION_POLICY_INSTALLED", "CLEANUP_SESSION_POLICY_INSTALLED", "AUTHORIZATION_SESSION_POLICY_INSTALLED", "PUBLISHER_POLICY_INSTALLED", "VERIFIED"];
  const authenticatePredecessor = async journal => {
    const retired = (await readObject(`${identityBootstrap.prefix}signer-policy-transition.json`)).value;
    assert.equal(retired.state, "REVOKED"); assert.equal(retired.authorization.sourceSha, "864b0f349e7f33b6274a44017ea33b625c8c6e0e");
    assert.equal(retired.authorization.transitionId, "c0f3a7b9-2ed7-4c2b-98a6-1482a6ee93ad"); assert.equal(retired.authorization.operation, "REVOKE");
    assert.equal(retired.steadyVersionId, "v24"); assert.equal(retired.temporaryVersionId, null);
    for (const field of ["planSha256", "approvalReference", "signerReadbackSha256", "recovery"]) assert.equal(retired[field], null);
    assert.deepEqual(retired.recoveryPlanHistory, []);
    assert.deepEqual(retired.history.map(({ state }) => state), ["INSTALLING"]);
    const active = await iam("GetPolicy", { PolicyArn: releasePolicyArn }); assert.equal(active.Policy.DefaultVersionId, "v24");
    const version = await iam("GetPolicyVersion", { PolicyArn: releasePolicyArn, VersionId: "v24" });
    assert.equal(canonical(normalizeIamPolicyDocument(version.PolicyVersion.Document)), canonical(steadyPolicy), "Release policy differs from steady v24");
    const observed = assertBrokerSignerSuccessorClosureMetadata(journal.metadata, thirdReservation.value.bindings, thirdReservation.value, thirdReservation.etag, journal.value);
    assert.equal(canonical(observed), canonical(thirdClosure), "Signer predecessor closure changed");
    assert.deepEqual(await versions(), Array.from({ length: 15 }, (_, i) => String(i + 1)), "Signer predecessor generations differ");
    for (const [entryPoint, version] of Object.entries(brokerSignerSuccessorEntryPoints)) assertBrokerConfiguration(await ready(version), oldConfigurations[entryPoint], await controls(version));
    const live = brokerSignerSuccessorManagedIdentities().find(({ role }) => role === installationIdentity.terraformRole), policy = await iam("GetRolePolicy", { RoleName: live.role, PolicyName: live.policyName });
    assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), live.policySha256, "Signer predecessor executor policy differs");
    assert((await inspectPredecessor(iam)).every(({ role, policy: state }) => role === "EXPECTED" && state === "EXPECTED"), "Signer predecessor identities differ");
    const role = await iam("GetRole", { RoleName: publisherRole });
    assert.equal(role.Role.Arn, `arn:aws:iam::${identityBootstrap.account}:role/${publisherRole}`);
    assert.equal(canonical(normalizeIamPolicyDocument(role.Role.AssumeRolePolicyDocument)), canonical(publisherTrust), "Publisher trust differs");
    const inline = await iam("ListRolePolicies", { RoleName: publisherRole });
    assert.equal(inline.IsTruncated, false); assert.deepEqual(inline.PolicyNames, [publisherPolicyName]);
    const attached = await iam("ListAttachedRolePolicies", { RoleName: publisherRole });
    assert.equal(attached.IsTruncated, false); assert.deepEqual(attached.AttachedPolicies, []);
    assert.equal(digest(normalizeIamPolicyDocument((await publisher()).PolicyDocument)), digest(predecessorPublisherPolicy), "Publisher predecessor differs");
  };
  const claim = { schemaVersion: 1, state: "EXECUTING", transitionId: approval.transitionId, owner, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [], bindings };
  const assertClaim = value => { assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "bindings", "owner", "schemaVersion", "sessionExpiresAt", "state", "transitionId"].sort()); assert.equal(value.schemaVersion, 1); uuid(value.owner); assert.match(value.authorizationSha256 || "", /^[a-f0-9]{64}$/); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(value[field])).toISOString(), value[field]); assert.equal(canonical(value.bindings), canonical(bindings)); assert(successorStates.includes(value.state)); assert(Array.isArray(value.authorizationHistory)); const seen = new Set([value.authorizationSha256]); for (const prior of value.authorizationHistory) { assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]); assert.match(prior.authorizationSha256 || "", /^[a-f0-9]{64}$/); assert(!seen.has(prior.authorizationSha256)); seen.add(prior.authorizationSha256); uuid(prior.owner); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(prior[field])).toISOString(), prior[field]); } };
  await authorize(); const journal = await readJournal(); assert.equal(journal.etag, initialJournal.etag, "Signer predecessor lineage changed before reservation");
  if (Object.hasOwn(journal.metadata, staleSignerSuccessor.metadataKey)) { assertStaleSignerSuccessorClosure(journal.metadata, bindings, undefined, undefined, journal.value); assert.fail("Broker stale-signer successor is already closed"); }
  let reservation = await readReservation(), reservationEtag;
  if (!reservation) { await authenticatePredecessor(journal); ({ etag: reservationEtag } = await put(staleSignerSuccessor.reservationKey, claim, { IfNoneMatch: "*" })); reservation = { value: claim, etag: reservationEtag }; }
  else {
    assertClaim(reservation.value); assert.equal(reservation.value.transitionId, approval.transitionId); reservationEtag = reservation.etag;
    assert.notEqual(reservation.value.authorizationSha256, authorizationSha256, "Successor authorization already consumed");
    const fence = Math.max(Date.parse(reservation.value.authorizationExpiresAt), Date.parse(reservation.value.sessionExpiresAt)) + 120000;
    assert(now() > fence && Date.parse(human.issuanceEventTime) > fence, "Prior successor owner is not safely fenced");
    const previous = { authorizationSha256: reservation.value.authorizationSha256, authorizationExpiresAt: reservation.value.authorizationExpiresAt, sessionExpiresAt: reservation.value.sessionExpiresAt, owner: reservation.value.owner };
    reservation.value = { ...reservation.value, owner, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [...reservation.value.authorizationHistory, previous] };
    ({ etag: reservationEtag } = await put(staleSignerSuccessor.reservationKey, reservation.value, { IfMatch: reservationEtag }));
  }
  let record = reservation.value;
  const checkpoint = async state => { record = { ...record, state }; ({ etag: reservationEtag } = await put(staleSignerSuccessor.reservationKey, record, { IfMatch: reservationEtag })); };
  const guard = async () => { await authorize(); const observed = await readReservation(); assert.equal(canonical(observed?.value), canonical(record), "Successor owner changed"); reservationEtag = observed.etag; };
  const mutate = async (service, operation, input, reconcile) => { await guard(); try { await service(operation, input); } catch {} await reconcile(); };
  const successorConfigurations = staleSignerSuccessorConfigurations(packageEvidence), successorCode = bindings.successor.lambdaCodeSha256;
  let latest = await ready();
  if (latest.Configuration.CodeSha256 !== successorCode) {
    assert.equal(latest.Configuration.CodeSha256, Buffer.from(thirdReservation.value.bindings.successor.packageSha256, "hex").toString("base64"));
    await mutate(lambda, "UpdateFunctionCode", { FunctionName: installationIdentity.functionName, ZipFile: Buffer.from(packageEvidence.bytes), Publish: false, RevisionId: latest.Configuration.RevisionId }, async () => { latest = await ready(); assert.equal(latest.Configuration.CodeSha256, successorCode); });
    await checkpoint("CODE_UPDATED");
  }
  const published = {};
  for (const entryPoint of Object.keys(brokerStaleSignerSuccessorEntryPoints)) {
    const version = brokerStaleSignerSuccessorEntryPoints[entryPoint], configuration = successorConfigurations[entryPoint];
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
  assert.deepEqual(await versions(), Array.from({ length: 18 }, (_, i) => String(i + 1)));
  const predecessorIdentities = brokerSignerSuccessorManagedIdentities(), successorIdentities = brokerStaleSignerSuccessorManagedIdentities();
  const installPolicy = async (role, predecessorSha256, successorSha256, state, label) => {
    const target = successorIdentities.find(identity => identity.role === role), predecessorTarget = predecessorIdentities.find(identity => identity.role === role);
    assert(target && predecessorTarget && target.policyName === predecessorTarget.policyName);
    let policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }), policySha = digest(normalizeIamPolicyDocument(policy.PolicyDocument));
    assert([predecessorSha256, successorSha256].includes(policySha), `${label} policy is outside authorized generation lineage`);
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
  let publisherSha = digest(normalizeIamPolicyDocument((await publisher()).PolicyDocument));
  assert([digest(predecessorPublisherPolicy), digest(staleSignerPublisherPolicy)].includes(publisherSha), "Publisher policy is outside signer lineage");
  if (publisherSha !== digest(staleSignerPublisherPolicy)) {
    await guard(); assert.equal(digest(normalizeIamPolicyDocument((await publisher()).PolicyDocument)), digest(predecessorPublisherPolicy), "Publisher predecessor changed");
    await authorize(); try { await iam("PutRolePolicy", { RoleName: publisherRole, PolicyName: publisherPolicyName, PolicyDocument: canonical(staleSignerPublisherPolicy) }); } catch {}
    publisherSha = digest(normalizeIamPolicyDocument((await publisher()).PolicyDocument));
    assert.equal(publisherSha, digest(staleSignerPublisherPolicy), "Publisher policy successor did not converge");
  }
  if (successorStates.indexOf(record.state) < successorStates.indexOf("PUBLISHER_POLICY_INSTALLED")) await checkpoint("PUBLISHER_POLICY_INSTALLED");
  const identities = await inspectSuccessor(iam); assert(identities.every(({ role, policy: state }) => role === "EXPECTED" && state === "EXPECTED")); await noPolicies(); await checkpoint("VERIFIED");
  const closedAt = new Date(now()).toISOString(), runtimeVersions = Object.fromEntries(Object.entries(brokerStaleSignerSuccessorEntryPoints).map(([, version]) => [version, published[version].Configuration.RuntimeVersionConfig.RuntimeVersionArn]));
  const finalRecord = { ...record, state: "BROKER_STALE_SIGNER_SUCCESSOR_CLOSED", closedAt, runtimeVersions };
  const currentJournal = await readJournal(); assert.equal(currentJournal.etag, journal.etag, "Bootstrap lineage changed during successor transition");
  assert.equal(canonical(assertBrokerSignerSuccessorClosureMetadata(currentJournal.metadata, thirdReservation.value.bindings, thirdReservation.value, thirdReservation.etag, currentJournal.value)), canonical(thirdClosure), "Signer predecessor closure changed during successor transition");
  const closure = staleSignerSuccessorClosure(record, bindings, runtimeVersions, reservationEtag, closedAt, currentJournal.metadata);
  const closedBody = { ...currentJournal.value, brokerStaleSignerSuccessorClosure: closure.value };
  await put(journalKey, closedBody, { IfMatch: currentJournal.etag }, closure.metadata); assertStaleSignerSuccessorClosure(closure.metadata, bindings, record, reservationEtag, closedBody);
  const closedJournal = await readJournal(); verifyEffective(closedJournal.value, packageEvidence.manifest, packageEvidence.packageSha256, closedJournal.metadata, firstReservation, secondReservation, thirdReservation, false, { value: record, etag: reservationEtag });
  return { ...closedJournal.value, brokerStaleSignerSuccessor: finalRecord };
}
