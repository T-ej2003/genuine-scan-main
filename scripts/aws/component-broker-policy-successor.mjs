import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { assertBrokerConfiguration, brokerChangeEntryPoints, brokerConfiguration } from "./component-broker-configuration.mjs";
import { assertBrokerPolicySuccessorAuthorization } from "./component-broker-policy-successor-authorization.mjs";
import { brokerPolicyPredecessor, brokerPolicySuccessor, brokerPolicySuccessorBindings, brokerPolicySuccessorConfiguration, predecessorExecutorPolicySha256, successorExecutorPolicySha256 } from "./component-broker-policy-successor-contract.mjs";
import { assertEffectiveBootstrapTrustAnchor, assertHistoricalBrokerChangeClosure } from "./component-bootstrap-trust-anchor.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { brokerChangeManagedIdentities, brokerPolicySuccessorManagedIdentities, componentBrokerArn, identityBootstrap, inspectBrokerChangeIdentities, inspectBrokerPolicySuccessorIdentities } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const journalKey = `${identityBootstrap.prefix}identity-bootstrap.json`;
const absent = error => ["NoSuchKey", "NotFound", "ResourceNotFoundException"].includes(error?.name);
const uuid = value => assert.match(value || "", /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);

export async function executeBrokerPolicySuccessor({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay,
  verifyPredecessor = assertHistoricalBrokerChangeClosure, verifyEffective = assertEffectiveBootstrapTrustAnchor, inspectPredecessor = inspectBrokerChangeIdentities, inspectSuccessor = inspectBrokerPolicySuccessorIdentities }) {
  assert.equal(createHash("sha256").update(packageEvidence.bytes).digest("hex"), packageEvidence.packageSha256, "Successor package bytes differ");
  const approval = structuredClone(authorization), authorizationSha256 = assertBrokerPolicySuccessorAuthorization(approval, packageEvidence, now());
  const human = structuredClone(operatorProof); assertComponentSessionRecord(human); assert.equal(human.purpose, "BROKER_POLICY_SUCCESSOR");
  for (const [field, value] of Object.entries({ sourceSha: approval.successor.sourceSha, transitionId: approval.transitionId, authorizationSha256 })) assert.equal(human[field], value);
  assert(Date.parse(human.issuanceEventTime) >= Date.parse(approval.approvalObservedAt) - 999);
  const bindings = brokerPolicySuccessorBindings(packageEvidence), owner = randomUUID();
  const authorize = async () => { assertBrokerPolicySuccessorAuthorization(approval, packageEvidence, now()); assert(now() < Date.parse(human.expiresAt)); await authenticate(); };
  const readObject = async key => { const received = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key }); const text = await received.Body.transformToString(); assert(typeof received.ETag === "string" && received.ETag); return { value: JSON.parse(text), etag: received.ETag }; };
  const readJournal = () => readObject(journalKey);
  const readReservation = async () => { try { return await readObject(brokerPolicySuccessor.reservationKey); } catch (error) { if (absent(error)) return null; throw error; } };
  const put = async (key, value, condition) => {
    await authorize(); const input = { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(value), ServerSideEncryption: "AES256", ...condition };
    try { await s3("PutObject", input); } catch { const observed = await readObject(key); assert.equal(canonical(observed.value), canonical(value), "Successor checkpoint CAS lost"); return observed; }
    const observed = await readObject(key); assert.equal(canonical(observed.value), canonical(value), "Successor checkpoint readback differs"); return observed;
  };
  const readFunction = async qualifier => lambda("GetFunction", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) });
  const ready = async qualifier => { for (let attempt = 0; attempt < 12; attempt++) { const fn = await readFunction(qualifier); if (fn.Configuration.State === "Active" && fn.Configuration.LastUpdateStatus === "Successful") return fn; await sleep(1000); } throw new Error("Broker successor did not converge"); };
  const controls = async qualifier => ({ concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }), signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }), runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }) });
  const noPolicies = async () => { for (const qualifier of [null, "1", "2", "3", "4", "5", "6", "7"]) try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); throw new Error("Unexpected broker invocation bypass"); } catch (error) { if (!absent(error)) throw error; } };
  const versions = async () => { const response = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName }); assert.equal(response.NextMarker, undefined); return response.Versions.map(({ Version }) => Version).filter(value => value !== "$LATEST").sort((a, b) => Number(a) - Number(b)); };
  const oldConfigurations = Object.fromEntries(Object.keys(brokerChangeEntryPoints).map(entryPoint => [entryPoint, brokerConfiguration({ packageSha256: brokerPolicyPredecessor.packageSha256, manifestSha256: brokerPolicyPredecessor.manifestSha256, entryPoint, entryPoints: brokerChangeEntryPoints })]));
  const authenticatePredecessor = async journal => {
    const anchor = verifyPredecessor(journal.value);
    for (const field of ["sourceSha", "packageSha256", "manifestSha256", "configurationSha256", "identitySetSha256"]) assert.equal(anchor[field], brokerPolicyPredecessor[field]);
    assert.deepEqual(await versions(), ["1", "2", "3", "4", "5", "6"]);
    for (const [entryPoint, version] of Object.entries(brokerChangeEntryPoints)) assertBrokerConfiguration(await ready(version), oldConfigurations[entryPoint], await controls(version));
    const live = brokerChangeManagedIdentities().find(({ role }) => role === installationIdentity.terraformRole), policy = await iam("GetRolePolicy", { RoleName: live.role, PolicyName: live.policyName });
    assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), predecessorExecutorPolicySha256, "Generation-N executor policy differs");
    assert((await inspectPredecessor(iam)).every(({ role, policy: state }) => role === "EXPECTED" && state === "EXPECTED"), "Generation-N identities differ");
  };
  const claim = { schemaVersion: 1, state: "EXECUTING", transitionId: approval.transitionId, owner, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [], bindings };
  const assertClaim = value => { assert.deepEqual(Object.keys(value || {}).sort(), ["authorizationExpiresAt", "authorizationHistory", "authorizationSha256", "bindings", "owner", "schemaVersion", "sessionExpiresAt", "state", "transitionId"].sort()); assert.equal(value.schemaVersion, 1); uuid(value.owner); assert.match(value.authorizationSha256 || "", /^[a-f0-9]{64}$/); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(value[field])).toISOString(), value[field]); assert.equal(canonical(value.bindings), canonical(bindings)); assert(["EXECUTING", "CODE_UPDATED", "DESCRIPTION_SET", "VERSION_PUBLISHED", "POLICY_INSTALLED", "VERIFIED"].includes(value.state)); assert(Array.isArray(value.authorizationHistory)); const seen = new Set([value.authorizationSha256]); for (const prior of value.authorizationHistory) { assert.deepEqual(Object.keys(prior).sort(), ["authorizationExpiresAt", "authorizationSha256", "owner", "sessionExpiresAt"]); assert.match(prior.authorizationSha256 || "", /^[a-f0-9]{64}$/); assert(!seen.has(prior.authorizationSha256)); seen.add(prior.authorizationSha256); uuid(prior.owner); for (const field of ["authorizationExpiresAt", "sessionExpiresAt"]) assert.equal(new Date(Date.parse(prior[field])).toISOString(), prior[field]); } };
  await authorize(); const journal = await readJournal(); assert(!Object.hasOwn(journal.value, "brokerPolicySuccessor"), "Broker-policy successor is already closed");
  let reservation = await readReservation(), reservationEtag;
  if (!reservation) { await authenticatePredecessor(journal); ({ etag: reservationEtag } = await put(brokerPolicySuccessor.reservationKey, claim, { IfNoneMatch: "*" })); reservation = { value: claim, etag: reservationEtag }; }
  else {
    assertClaim(reservation.value); assert.equal(reservation.value.transitionId, approval.transitionId); reservationEtag = reservation.etag;
    assert.notEqual(reservation.value.authorizationSha256, authorizationSha256, "Successor authorization already consumed");
    const fence = Math.max(Date.parse(reservation.value.authorizationExpiresAt), Date.parse(reservation.value.sessionExpiresAt)) + 120000;
    assert(now() > fence && Date.parse(human.issuanceEventTime) > fence, "Prior successor owner is not safely fenced");
    const previous = { authorizationSha256: reservation.value.authorizationSha256, authorizationExpiresAt: reservation.value.authorizationExpiresAt, sessionExpiresAt: reservation.value.sessionExpiresAt, owner: reservation.value.owner };
    reservation.value = { ...reservation.value, owner, authorizationSha256, authorizationExpiresAt: approval.expiresAt, sessionExpiresAt: human.expiresAt, authorizationHistory: [...reservation.value.authorizationHistory, previous] };
    ({ etag: reservationEtag } = await put(brokerPolicySuccessor.reservationKey, reservation.value, { IfMatch: reservationEtag }));
  }
  let record = reservation.value;
  const checkpoint = async state => { record = { ...record, state }; ({ etag: reservationEtag } = await put(brokerPolicySuccessor.reservationKey, record, { IfMatch: reservationEtag })); };
  const guard = async () => { await authorize(); const observed = await readReservation(); assert.equal(canonical(observed?.value), canonical(record), "Successor owner changed"); reservationEtag = observed.etag; };
  const mutate = async (service, operation, input, reconcile) => { await guard(); try { await service(operation, input); } catch {} await reconcile(); };
  const successorConfiguration = brokerPolicySuccessorConfiguration(packageEvidence), successorCode = bindings.successor.lambdaCodeSha256;
  let latest = await ready();
  if (latest.Configuration.CodeSha256 !== successorCode) {
    assert.equal(latest.Configuration.CodeSha256, Buffer.from(brokerPolicyPredecessor.packageSha256, "hex").toString("base64"));
    await mutate(lambda, "UpdateFunctionCode", { FunctionName: installationIdentity.functionName, ZipFile: Buffer.from(packageEvidence.bytes), Publish: false, RevisionId: latest.Configuration.RevisionId }, async () => { latest = await ready(); assert.equal(latest.Configuration.CodeSha256, successorCode); });
    await checkpoint("CODE_UPDATED");
  }
  let version7; try { version7 = await ready("7"); } catch (error) { if (!absent(error)) throw error; }
  if (!version7) {
    latest = await ready(); if (latest.Configuration.Description !== successorConfiguration.Description) {
      await mutate(lambda, "UpdateFunctionConfiguration", { FunctionName: installationIdentity.functionName, Description: successorConfiguration.Description, RevisionId: latest.Configuration.RevisionId }, async () => { latest = await ready(); assert.equal(latest.Configuration.Description, successorConfiguration.Description); });
      await checkpoint("DESCRIPTION_SET");
    }
    await mutate(lambda, "PublishVersion", { FunctionName: installationIdentity.functionName, Description: successorConfiguration.Description, CodeSha256: successorConfiguration.CodeSha256, RevisionId: latest.Configuration.RevisionId }, async () => { version7 = await ready("7"); assertBrokerConfiguration(version7, successorConfiguration, await controls("7")); });
    await checkpoint("VERSION_PUBLISHED");
  }
  assert.deepEqual(await versions(), ["1", "2", "3", "4", "5", "6", "7"]); assertBrokerConfiguration(version7, successorConfiguration, await controls("7"));
  const target = brokerPolicySuccessorManagedIdentities().find(({ role }) => role === installationIdentity.terraformRole);
  let policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }), policySha = digest(normalizeIamPolicyDocument(policy.PolicyDocument));
  assert([predecessorExecutorPolicySha256, successorExecutorPolicySha256].includes(policySha), "Executor policy is outside authorized generation lineage");
  if (policySha !== successorExecutorPolicySha256) {
    await guard(); policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }); assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), predecessorExecutorPolicySha256, "Executor policy CAS predecessor changed");
    await authorize();
    try { await iam("PutRolePolicy", { RoleName: target.role, PolicyName: target.policyName, PolicyDocument: canonical(target.policy) }); } catch {}
    policy = await iam("GetRolePolicy", { RoleName: target.role, PolicyName: target.policyName }); assert.equal(digest(normalizeIamPolicyDocument(policy.PolicyDocument)), successorExecutorPolicySha256, "Executor policy successor did not converge");
    await checkpoint("POLICY_INSTALLED");
  }
  const identities = await inspectSuccessor(iam); assert(identities.every(({ role, policy: state }) => role === "EXPECTED" && state === "EXPECTED")); await noPolicies(); await checkpoint("VERIFIED");
  const finalRecord = { ...record, state: "BROKER_POLICY_SUCCESSOR_CLOSED", closedAt: new Date(now()).toISOString(), runtimeVersionArn: version7.Configuration.RuntimeVersionConfig.RuntimeVersionArn };
  const currentJournal = await readJournal(); assert.equal(currentJournal.etag, journal.etag, "Bootstrap lineage changed during successor transition"); verifyPredecessor(currentJournal.value);
  const closedJournal = { ...currentJournal.value, brokerPolicySuccessor: finalRecord }; await put(journalKey, closedJournal, { IfMatch: currentJournal.etag });
  verifyEffective((await readJournal()).value, packageEvidence.manifest, packageEvidence.packageSha256);
  return closedJournal;
}
