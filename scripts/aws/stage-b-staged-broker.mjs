import assert from "node:assert/strict";
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_CENSUS, brokerDigest, brokerAliasIdentity,
  brokerPrerequisiteIdentity, brokerTargetIdentity, brokerStateReservation, assertBrokerPreparation, assertBrokerAuthorization,
  assertBrokerPublicationPlan, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan } from "./stage-b-staged-broker-contract.mjs";
import { STAGE_B, canonicalJson } from "./production-green-stage-b-contract.mjs";

const equal = (a, b, message) => assert.equal(canonicalJson(a), canonicalJson(b), message);
const context = (input, purpose) => {
  const p = structuredClone(input); assertBrokerPreparation(p); assert.equal(p.purpose, purpose); return p;
};
async function authenticate(preparation, authorization, deps) {
  const digest = await assertBrokerAuthorization(authorization, preparation, { verify: deps.verifyAuthorization, now: deps.now?.() || new Date() });
  equal(await deps.readCheckout(), { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 }, "Checkout authority changed");
  equal(brokerPrerequisiteIdentity(await deps.readPrerequisites()), preparation.prerequisites, "Broker prerequisite changed");
  equal(await deps.readStateIdentity(), preparation.state, "State predecessor changed");
  return digest;
}
function assertPlanArtifacts(p, artifacts) {
  assert.ok(Buffer.isBuffer(artifacts.bytes)); assert.equal(brokerDigest(artifacts.bytes), p.savedPlanSha256);
  assert.equal(brokerDigest(artifacts.plan), p.logicalPlanSha256);
  assert.equal(artifacts.artifactSetSha256, p.artifactSetSha256);
}

export async function executeBrokerPublication({ preparation, authorization }, deps) {
  const p = context(preparation, BROKER_PUBLICATION), auth = structuredClone(authorization);
  const authorizationSha256 = await authenticate(p, auth, deps);
  const artifacts = await deps.readPlan(); assertPlanArtifacts(p, artifacts);
  assertBrokerPublicationPlan(artifacts.plan, { sourceSha: p.sourceSha, prerequisites: p.prerequisites, canonicalAddresses: p.canonicalAddresses });
  const fn = artifacts.plan.resource_changes.find(c => c.address === "aws_lambda_function.broker");
  equal(fn.change.after.environment[0].variables, p.configuration);
  assert.equal(fn.change.after.source_code_hash, Buffer.from(p.packageSha256, "hex").toString("base64"));
  const predecessor = brokerTargetIdentity(await deps.getVersion(p.alias.FunctionVersion), p.packageSha256);
  equal(predecessor.configuration.Environment.Variables, fn.change.before.environment[0].variables, "Publication predecessor configuration changed");
  assert.equal(fn.change.before.version, p.alias.FunctionVersion, "Unapproved publication precedes target plan");
  equal(brokerAliasIdentity(await deps.getAlias()), p.alias, "Alias predecessor changed before publication");
  // Reservation failure is fatal, and the durable intent precedes Terraform reachability.
  await deps.reserve(authorizationSha256, { purpose: p.purpose, nonce: auth.nonce, preparationSha256: brokerDigest(p) });
  const authorizedAt = (deps.now?.() || new Date()).toISOString();
  await deps.record(authorizationSha256, "PUBLICATION_INTENT", { savedPlanSha256: p.savedPlanSha256, authorizedAt });
  await authenticate(p, auth, deps);
  equal(brokerAliasIdentity(await deps.getAlias()), p.alias, "Alias changed at publication boundary");
  try { await deps.applyPublication(artifacts.bytes); }
  catch (error) { await deps.record(authorizationSha256, "PUBLICATION_UNKNOWN", {}); throw error; }
  equal(brokerAliasIdentity(await deps.getAlias()), p.alias, "Publication changed alias");
  const published = await deps.readPublicationResult({ savedPlanSha256: p.savedPlanSha256, authorizationSha256 });
  // Version comes from this saved-plan execution/state result, never ListVersions' maximum.
  assert.equal(published.savedPlanSha256, p.savedPlanSha256); assert.equal(published.authorizationSha256, authorizationSha256);
  const target = brokerTargetIdentity(await deps.getVersion(published.version), p.packageSha256);
  assert.equal(target.version, published.version, "Publication result is not the requested immutable version");
  equal(target.configuration.Environment.Variables, p.configuration, "Published configuration differs from approved plan");
  equal(await deps.readPrerequisites(), p.prerequisites);
  const result = { schemaVersion: 1, status: "PUBLISHED", sourceSha: p.sourceSha, authorizationSha256,
    preparationSha256: brokerDigest(p), savedPlanSha256: p.savedPlanSha256, target, alias: p.alias, authorizedAt };
  await deps.record(authorizationSha256, "PUBLISHED", result); return result;
}

export async function prepareBrokerCutover({ publicationPreparation, publicationAuthorization, publicationResult, plan, bytes, state, artifactSetSha256 }, deps) {
  const old = context(publicationPreparation, BROKER_PUBLICATION);
  const authHash = await assertBrokerAuthorization(publicationAuthorization, old, { verify: deps.verifyAuthorization, now: new Date(publicationResult.authorizedAt) });
  assert.equal(publicationResult.status, "PUBLISHED"); assert.equal(publicationResult.authorizationSha256, authHash);
  assert.equal(publicationResult.preparationSha256, brokerDigest(old)); assert.equal(publicationResult.savedPlanSha256, old.savedPlanSha256);
  await deps.authenticatePublicationResult(publicationResult, authHash);
  const target = brokerTargetIdentity(await deps.getVersion(publicationResult.target.version), old.packageSha256);
  equal(target, publicationResult.target); equal(target.configuration.Environment.Variables, old.configuration);
  equal(brokerAliasIdentity(await deps.getAlias()), old.alias, "Publication predecessor no longer current");
  equal(await deps.readPrerequisites(), old.prerequisites);
  equal(await deps.readCheckout(), { sourceSha: old.sourceSha, treeSha256: old.treeSha256 });
  equal(await deps.readStateIdentity(), state);
  const p = { ...old, purpose: BROKER_CUTOVER, state, savedPlanSha256: brokerDigest(bytes), logicalPlanSha256: brokerDigest(plan),
    artifactSetSha256, target, publication: structuredClone(publicationResult) };
  assertBrokerPreparation(p); assertBrokerCutoverPlan(plan, p); return p;
}

export async function executeBrokerAliasCas({ preparation, authorization }, deps) {
  const p = context(preparation, BROKER_CUTOVER), auth = structuredClone(authorization);
  const authorizationSha256 = await authenticate(p, auth, deps);
  await deps.authenticatePublicationResult(p.publication, p.publication.authorizationSha256);
  const artifacts = await deps.readPlan(); assertPlanArtifacts(p, artifacts); assertBrokerCutoverPlan(artifacts.plan, p);
  equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target, "Immutable target changed");
  await deps.reserve(authorizationSha256, { purpose: p.purpose, nonce: auth.nonce, preparationSha256: brokerDigest(p) });
  const authorizedAt = (deps.now?.() || new Date()).toISOString();
  await deps.record(authorizationSha256, "CUTOVER_INTENT", { predecessor: p.alias, target: p.target, authorizedAt });
  await authenticate(p, auth, deps);
  equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target);
  // The second read is immediate; native RevisionId closes the remaining read/write race.
  equal(brokerAliasIdentity(await deps.getAlias()), p.alias, "Alias predecessor changed before CAS");
  const input = { FunctionName: STAGE_B.brokerFunctionArn, Name: p.alias.Name, FunctionVersion: p.target.version,
    RevisionId: p.alias.RevisionId, Description: p.alias.Description, RoutingConfig: p.alias.RoutingConfig };
  let alias;
  try { alias = await deps.updateAlias(input); }
  catch (error) {
    const conflict = error?.name === "PreconditionFailedException" || error?.$metadata?.httpStatusCode === 412;
    await deps.record(authorizationSha256, conflict ? "CUTOVER_CONFLICT" : "CUTOVER_UNKNOWN", {});
    throw error; // No retry, replan, fresh revision or Terraform apply fallback.
  }
  let observed;
  try {
    observed = brokerAliasIdentity(await deps.getAlias());
    equal(brokerAliasIdentity(alias), observed); assert.equal(observed.FunctionVersion, p.target.version);
    equal({ ...observed, RevisionId: p.alias.RevisionId, FunctionVersion: p.alias.FunctionVersion }, p.alias);
    assert.notEqual(observed.RevisionId, p.alias.RevisionId);
  } catch (error) { await deps.record(authorizationSha256, "CUTOVER_UNKNOWN", {}); throw error; }
  const result = { status: "CUTOVER_COMMITTED_STATE_PENDING", authorizationSha256, preparationSha256: brokerDigest(p), alias: observed, authorizedAt };
  await deps.record(authorizationSha256, result.status, result); return result;
}

export async function reconcileBrokerAlias({ preparation, authorization, casResult }, deps) {
  const p = context(preparation, BROKER_CUTOVER);
  const authHash = await assertBrokerAuthorization(authorization, p, { verify: deps.verifyAuthorization, now: deps.now?.() || new Date() });
  assert.equal(casResult.status, "CUTOVER_COMMITTED_STATE_PENDING"); assert.equal(casResult.authorizationSha256, authHash);
  assert.equal(casResult.preparationSha256, brokerDigest(p));
  await deps.authenticateCasResult(casResult, authHash);
  const revalidate = async () => {
    equal(await deps.readCheckout(), { sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
    equal(brokerAliasIdentity(await deps.getAlias()), casResult.alias);
    equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target);
    equal(await deps.readPrerequisites(), p.prerequisites);
    assert.equal(await deps.readTerraformFunctionVersion(), p.target.version, "New publication invalidates desired alias");
  };
  await revalidate(); equal(await deps.readStateIdentity(), p.state);
  const refresh = await deps.captureRefreshOnlyPlan(); assertBrokerRefreshPlan(refresh.plan, p, casResult.alias);
  assert.ok(Buffer.isBuffer(refresh.bytes)); const refreshPlanSha256 = brokerDigest(refresh.bytes);
  await revalidate(); equal(await deps.readStateIdentity(), p.state);
  await deps.reserve(brokerStateReservation(authHash), { purpose: "STAGE_B_BROKER_STATE_ONLY", parent: authHash, refreshPlanSha256 });
  await deps.record(authHash, "STATE_REFRESH_INTENT", { refreshPlanSha256 });
  await assertBrokerAuthorization(authorization, p, { verify: deps.verifyAuthorization, now: deps.now?.() || new Date() });
  await revalidate(); equal(await deps.readStateIdentity(), p.state);
  try { await deps.applyRefreshOnlyPlan(refresh.bytes); }
  catch (error) { await deps.record(authHash, "STATE_REFRESH_UNKNOWN", {}); throw error; }
  await revalidate();
  const closure = await deps.captureNormalPlan(); assertBrokerClosurePlan(closure.plan, p);
  assert.ok(Buffer.isBuffer(closure.bytes));
  await revalidate(); await deps.authenticateTerraformState(p.target, casResult.alias);
  const record = { status: "RECONCILED_PENDING_RELEASE_CAS", sourceSha: p.sourceSha,
    mutationAddresses: [...BROKER_CENSUS], publicationAuthorizationSha256: p.publication.authorizationSha256,
    publicationResultSha256: brokerDigest(p.publication), cutoverAuthorizationSha256: authHash,
    casResultSha256: brokerDigest(casResult), refreshPlanSha256, closurePlanSha256: brokerDigest(closure.bytes),
    closurePlan: closure.plan, closurePlanJsonSha256: brokerDigest(closure.plan),
    stateAfter: await deps.readStateIdentity(), target: p.target, alias: casResult.alias };
  await deps.record(authHash, record.status, record);
  await deps.publishTerminalHandoff({ preparation: p, authorization, casResult, record });
  return record;
}

export function brokerTransitionRequired({ desiredConfiguration, liveConfiguration }) {
  return canonicalJson(desiredConfiguration) !== canonicalJson(liveConfiguration);
}
