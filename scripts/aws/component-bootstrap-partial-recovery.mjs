import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { assertBrokerConfiguration, brokerConfiguration } from "./component-broker-configuration.mjs";
import { bootstrapFixedBroker } from "./component-broker-bootstrap.mjs";
import { assertBootstrapRecoveryAuthorization } from "./component-bootstrap-partial-recovery-authorization.mjs";
import { bootstrapPartialStateDigest, bootstrapRecoveryOperations, historicalBootstrapAuthorization, historicalBootstrapIncident, historicalBrokerConfiguration } from "./component-bootstrap-partial-recovery-contract.mjs";
import { canonical, digest, installationIdentity } from "./component-iam-installation-contract.mjs";
import { componentBrokerArn, identityBootstrap, inspectBootstrapIdentities } from "./component-installation-identity-contract.mjs";
import { assertComponentSessionRecord } from "./component-session-proof.mjs";

const key = `${identityBootstrap.prefix}identity-bootstrap.json`;
const absent = error => error?.name === "ResourceNotFoundException";

export async function executeBootstrapRecovery({ authorization, packageEvidence, operatorProof }, { iam, lambda, s3, authenticate, now = Date.now, sleep = delay }) {
  assert.equal(createHash("sha256").update(packageEvidence.bytes).digest("hex"), packageEvidence.packageSha256, "Corrected package bytes differ");
  const approval = structuredClone(authorization);
  const authorizationSha256 = assertBootstrapRecoveryAuthorization(approval, packageEvidence, now());
  const human = structuredClone(operatorProof);
  assertComponentSessionRecord(human); assert.equal(human.purpose, "IDENTITY_BOOTSTRAP_RECOVERY");
  for (const [field, value] of Object.entries({ sourceSha: approval.newSourceSha, transitionId: approval.transitionId, authorizationSha256 })) assert.equal(human[field], value);
  assert(Date.parse(human.issuanceEventTime) >= Date.parse(approval.approvalObservedAt) - 999, "Recovery human session predates approval");
  const owner = randomUUID();
  let activeRecord, activeEtag;
  const authorize = async () => {
    assertBootstrapRecoveryAuthorization(approval, packageEvidence, now());
    assert(now() < Date.parse(human.expiresAt), "Recovery human session expired");
    await authenticate();
  };
  const readJournal = async () => {
    const listing = await s3("ListObjectsV2", { Bucket: identityBootstrap.bucket, Prefix: key });
    assert.equal(listing.IsTruncated, false); assert.deepEqual((listing.Contents || []).map(value => value.Key), [key], "Exact historical bootstrap journal required");
    const response = await s3("GetObject", { Bucket: identityBootstrap.bucket, Key: key });
    assert(typeof response.ETag === "string" && response.ETag); const value = JSON.parse(await response.Body.transformToString());
    return { value, etag: response.ETag };
  };
  const assertHistoricalJournal = ({ value, etag }, allowRecovery = false) => {
    assert.equal(value.schemaVersion, 1); assert.equal(value.state, "BOOTSTRAP_EXECUTING");
    for (const [field, expected] of Object.entries({ sourceSha: historicalBootstrapIncident.sourceSha, transitionId: historicalBootstrapIncident.transitionId,
      authorizationSha256: historicalBootstrapIncident.authorizationSha256, manifestSha256: historicalBootstrapIncident.manifestSha256,
      identitySetSha256: historicalBootstrapIncident.identitySetSha256, packageSha256: historicalBootstrapIncident.packageSha256 })) assert.equal(value[field], expected, `Historical journal ${field} differs`);
    assert.deepEqual(value.authorization, historicalBootstrapAuthorization(), "Historical authorization bytes differ");
    assert.equal(value.authorization.runId, historicalBootstrapIncident.authorizationRunId);
    assert.equal(value.operatorProof?.purpose, "IDENTITY_BOOTSTRAP"); assert.equal(value.operatorProof?.transitionId, historicalBootstrapIncident.transitionId);
    assert.equal(value.operatorProof?.authorizationSha256, historicalBootstrapIncident.authorizationSha256);
    if (!allowRecovery) { assert.equal(etag, historicalBootstrapIncident.journalEtag, "Historical journal version differs"); assert.equal(value.recovery, undefined); }
    return value;
  };
  const inspectIdentities = async () => {
    const live = await inspectBootstrapIdentities(iam);
    assert(live.every(target => target.role === "EXPECTED" && target.policy === "EXPECTED"), "Bootstrap identities differ from exact source");
    return live;
  };
  const readFunction = async qualifier => {
    const value = await lambda("GetFunction", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) });
    assert.equal(value.Configuration?.FunctionName, installationIdentity.functionName); return value;
  };
  const versions = async () => {
    const result = [], markers = new Set(); let Marker;
    do {
      const page = await lambda("ListVersionsByFunction", { FunctionName: installationIdentity.functionName, ...(Marker ? { Marker } : {}) });
      assert(Array.isArray(page.Versions)); result.push(...page.Versions.map(({ Version }) => Version)); Marker = page.NextMarker;
      if (Marker) { assert(typeof Marker === "string" && !markers.has(Marker) && markers.size < 20, "Incomplete broker version inventory"); markers.add(Marker); }
    } while (Marker);
    assert.equal(new Set(result).size, result.length); assert(result.includes("$LATEST"));
    const published = result.filter(value => value !== "$LATEST").sort(); assert.deepEqual(published, ["1", "2", "3"].slice(0, published.length)); return published;
  };
  const noPolicies = async () => {
    for (const qualifier of [null, "1", "2", "3"]) {
      try { await lambda("GetPolicy", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }); }
      catch (error) { if (absent(error)) continue; throw error; }
      throw new Error("Unexpected broker resource policy");
    }
  };
  const controls = async qualifier => ({
    concurrency: await lambda("GetFunctionConcurrency", { FunctionName: installationIdentity.functionName }),
    signing: await lambda("GetFunctionCodeSigningConfig", { FunctionName: installationIdentity.functionName }),
    runtime: await lambda("GetRuntimeManagementConfig", { FunctionName: installationIdentity.functionName, ...(qualifier ? { Qualifier: qualifier } : {}) }),
  });
  const ready = async () => {
    for (let attempt = 0; attempt < 12; attempt++) {
      const value = await readFunction(); const { State, LastUpdateStatus } = value.Configuration;
      if (State === "Active" && LastUpdateStatus === "Successful") return value;
      assert(["Pending", "Active"].includes(State) && [undefined, "InProgress", "Successful"].includes(LastUpdateStatus), "Broker update cannot converge");
      await sleep(1000);
    }
    throw new Error("Broker update did not converge");
  };
  const inspectPartial = async () => {
    const identities = await inspectIdentities(), fn = await ready(), published = await versions(), settings = await controls(); await noPolicies();
    assert.deepEqual(published, [], "Historical defective package must never have been published");
    assert.equal(fn.Configuration.CodeSha256, historicalBootstrapIncident.lambdaCodeSha256); assert.equal(fn.Configuration.RevisionId, historicalBootstrapIncident.revisionId);
    assert([undefined, 1].includes(settings.concurrency.ReservedConcurrentExecutions));
    assert.equal(settings.runtime.UpdateRuntimeOn, "Auto"); assert(settings.runtime.RuntimeVersionArn == null);
    assertBrokerConfiguration(fn, historicalBrokerConfiguration(), { ...settings, concurrency: { ReservedConcurrentExecutions: 1 }, runtime: { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null } });
    assert.equal(digest(identities.map(({ arn, role, policy }) => ({ arn, role, policy }))).length, 64);
    assert.equal(bootstrapPartialStateDigest(), approval.partialStateSha256);
    return { identities, fn };
  };
  await authorize();
  const initial = await readJournal(); assertHistoricalJournal(initial, Boolean(initial.value.recovery));
  if (initial.value.state === "BOOTSTRAP_CLOSED") throw new Error("Bootstrap is already closed");
  if (!initial.value.recovery) await inspectPartial();
  const claim = { schemaVersion: 1, state: "RECOVERY_EXECUTING", transitionId: approval.transitionId, authorizationSha256,
    sourceSha: approval.newSourceSha, oldPackageSha256: historicalBootstrapIncident.packageSha256, newPackageSha256: approval.newPackageSha256,
    newManifestSha256: approval.newManifestSha256, partialStateSha256: approval.partialStateSha256, remainingOperations: bootstrapRecoveryOperations, owner };
  if (!initial.value.recovery) {
    activeRecord = { ...initial.value, recovery: claim };
    await authorize();
    try { await s3("PutObject", { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(activeRecord), ServerSideEncryption: "AES256", IfMatch: initial.etag }); }
    catch (error) {
      const observed = await readJournal();
      assert.equal(canonical(observed.value), canonical(activeRecord), "Concurrent recovery won reservation");
    }
  } else {
    assert.equal(initial.value.recovery.authorizationSha256, authorizationSha256, "Different recovery already reserved");
    assert.equal(initial.value.recovery.sourceSha, approval.newSourceSha); assert.equal(initial.value.recovery.newPackageSha256, approval.newPackageSha256);
    activeRecord = initial.value;
  }
  ({ etag: activeEtag } = await readJournal());
  const guard = async () => {
    await authorize(); const observed = await readJournal();
    assert.equal(canonical(observed.value), canonical(activeRecord), "Recovery reservation no longer owned"); activeEtag = observed.etag; return activeEtag;
  };
  await guard(); await inspectIdentities(); await noPolicies();
  let fn = await ready(); const existing = await versions();
  assert(existing.length === 0 || fn.Configuration.CodeSha256 === approval.newLambdaCodeSha256, "Defective code cannot have published versions");
  if (fn.Configuration.CodeSha256 === historicalBootstrapIncident.lambdaCodeSha256) {
    assert.deepEqual(existing, []); assert.equal(fn.Configuration.RevisionId, historicalBootstrapIncident.revisionId);
    await guard();
    try { await lambda("UpdateFunctionCode", { FunctionName: installationIdentity.functionName, ZipFile: Buffer.from(packageEvidence.bytes), Publish: false, RevisionId: historicalBootstrapIncident.revisionId }); }
    catch { /* Exact readback below resolves accepted-but-lost responses. */ }
    fn = await ready();
    assert.equal(fn.Configuration.CodeSha256, approval.newLambdaCodeSha256, "Ambiguous code update did not converge to the exact reviewed package");
  } else assert.equal(fn.Configuration.CodeSha256, approval.newLambdaCodeSha256, "Broker code is neither exact historical nor exact corrected package");
  if (existing.length === 0) {
    const settings = await controls(); await noPolicies();
    const correctedInstall = brokerConfiguration({ packageSha256: approval.newPackageSha256, manifestSha256: approval.newManifestSha256, entryPoint: "INSTALL" });
    const historicalDescription = historicalBrokerConfiguration().Description;
    const barrier = { ...correctedInstall, FunctionArn: componentBrokerArn, Version: "$LATEST", Description: fn.Configuration.Description };
    assert([historicalDescription, correctedInstall.Description].includes(fn.Configuration.Description), "Unexpected recovery description phase");
    assertBrokerConfiguration(fn, barrier, { ...settings, concurrency: { ReservedConcurrentExecutions: 1 }, runtime: { UpdateRuntimeOn: "FunctionUpdate", RuntimeVersionArn: null } });
    if (fn.Configuration.Description === historicalDescription) {
      assert(typeof fn.Configuration.RevisionId === "string" && fn.Configuration.RevisionId); await guard();
      try { await lambda("UpdateFunctionConfiguration", { FunctionName: installationIdentity.functionName, Description: correctedInstall.Description, RevisionId: fn.Configuration.RevisionId }); }
      catch { /* Readback authenticates ambiguous acceptance. */ }
      fn = await ready(); assert.equal(fn.Configuration.Description, correctedInstall.Description, "Corrected package description did not converge");
    }
  }
  const broker = await bootstrapFixedBroker(packageEvidence, { lambda, authorize: guard, sleep });
  const live = await inspectIdentities();
  const closed = { ...activeRecord, state: "BOOTSTRAP_CLOSED", identities: live, broker, runtimeVersions: broker.runtimeVersions,
    closedAt: new Date(now()).toISOString(), identityReadbackSha256: digest(live), recovery: { ...claim, state: "RECOVERY_CLOSED", closedAt: new Date(now()).toISOString(),
      oldRevisionId: historicalBootstrapIncident.revisionId, finalPackageSha256: broker.packageSha256, finalManifestSha256: broker.manifestSha256,
      versions: Object.keys(broker.runtimeVersions) } };
  await guard();
  try { await s3("PutObject", { Bucket: identityBootstrap.bucket, Key: key, Body: canonical(closed), ServerSideEncryption: "AES256", IfMatch: activeEtag }); }
  catch { assert.equal(canonical((await readJournal()).value), canonical(closed), "Ambiguous recovery closure"); }
  assert.equal(canonical((await readJournal()).value), canonical(closed), "Recovery closure readback differs");
  return closed;
}
