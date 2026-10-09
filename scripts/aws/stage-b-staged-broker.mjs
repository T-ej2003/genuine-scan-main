import { authenticateStagedBrokerClosure } from "./stage-b-staged-broker-closure.mjs";
import assert from "node:assert/strict";
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_STATE_REFRESH, BROKER_CENSUS, brokerDigest, brokerAliasIdentity, prepareBrokerStateRefresh,
  brokerExecutionCheckout, brokerPrerequisiteIdentity, brokerTargetIdentity, brokerStateReservation, assertBrokerPreparation, assertBrokerAuthorization,
  assertBrokerPublicationPlan, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan } from "./stage-b-staged-broker-contract.mjs";
import { STAGE_B, canonicalJson } from "./production-green-stage-b-contract.mjs";

const equal = (a, b, message) => assert.equal(canonicalJson(a), canonicalJson(b), message);
const context = (input, purpose) => {
  const p = structuredClone(input); assertBrokerPreparation(p); assert.equal(p.purpose, purpose); return p;
};
async function authenticate(preparation, authorization, deps) {
  const digest = await assertBrokerAuthorization(authorization, preparation, { verify: deps.verifyAuthorization, now: deps.now?.() || new Date() });
  equal(await deps.readCheckout(), brokerExecutionCheckout(preparation), "Checkout authority changed");
  if (preparation.outputReconciliation) await deps.authenticateOutputReconciliation(preparation);
  if (preparation.prerequisiteChain) await deps.authenticatePrerequisiteChain(preparation.prerequisiteChain);
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
  assertBrokerPublicationPlan(artifacts.plan, p);
  const fn = artifacts.plan.resource_changes.find(c => c.address === "aws_lambda_function.broker");
  equal(fn.change.after.environment[0].variables, p.configuration);
  assert.equal(fn.change.after.source_code_hash, Buffer.from(p.packageSha256, "hex").toString("base64"));
  const predecessorPackageSha256 = Buffer.from(fn.change.before.source_code_hash, 'base64').toString('hex');
  assert.match(predecessorPackageSha256, /^[a-f0-9]{64}$/);
  const predecessor = brokerTargetIdentity(await deps.getVersion(p.alias.FunctionVersion), predecessorPackageSha256);
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

export async function prepareBrokerCutover({ publicationPreparation, publicationAuthorization, publicationResult, plan, bytes, state, artifactSetSha256, outputReconciliation }, deps) {
  const old = context(publicationPreparation, BROKER_PUBLICATION);
  const authHash = await assertBrokerAuthorization(publicationAuthorization, old, { verify: deps.verifyAuthorization, now: new Date(publicationResult.authorizedAt) });
  assert.equal(publicationResult.status, "PUBLISHED"); assert.equal(publicationResult.authorizationSha256, authHash);
  assert.equal(publicationResult.preparationSha256, brokerDigest(old)); assert.equal(publicationResult.savedPlanSha256, old.savedPlanSha256);
  await deps.authenticatePublicationResult(publicationResult, authHash);
  if (old.prerequisiteChain) await deps.authenticatePrerequisiteChain(old.prerequisiteChain);
  const target = brokerTargetIdentity(await deps.getVersion(publicationResult.target.version), old.packageSha256);
  equal(target, publicationResult.target); equal(target.configuration.Environment.Variables, old.configuration);
  equal(brokerAliasIdentity(await deps.getAlias()), old.alias, "Publication predecessor no longer current");
  equal(await deps.readPrerequisites(), old.prerequisites);
  const checkout = await deps.readCheckout();
  const recoveryTooling = checkout.sourceSha === old.sourceSha ? undefined
    : await deps.authenticateBrokerRecoveryTooling(old, publicationResult, checkout);
  if (!recoveryTooling) equal(checkout, brokerExecutionCheckout(old));
  equal(await deps.readStateIdentity(), state);
  const p = { ...old, purpose: BROKER_CUTOVER, state, savedPlanSha256: brokerDigest(bytes), logicalPlanSha256: brokerDigest(plan),
    artifactSetSha256, target, publication: structuredClone(publicationResult) };
  if (recoveryTooling) p.recoveryTooling = recoveryTooling;
  if (outputReconciliation) p.outputReconciliation = outputReconciliation;
  assertBrokerPreparation(p);
  if (p.outputReconciliation) await deps.authenticateOutputReconciliation(p);
  assertBrokerCutoverPlan(plan, p); return p;
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

export async function reconcileBrokerAlias({ preparation, authorization, casResult, cutoverPreparation, cutoverAuthorization }, deps) {
  const p = context(preparation, cutoverPreparation ? BROKER_STATE_REFRESH : BROKER_CUTOVER);
  const authHash = await assertBrokerAuthorization(authorization, p, { verify: deps.verifyAuthorization, now: deps.now?.() || new Date() });
  const old = cutoverPreparation ? context(cutoverPreparation,BROKER_CUTOVER) : p;
  const oldAuthorization = cutoverPreparation ? cutoverAuthorization : authorization;
  if(cutoverPreparation)equal(p,prepareBrokerStateRefresh({preparation:old,authorization:oldAuthorization,casResult}));
  const cutoverHash=await assertBrokerAuthorization(oldAuthorization,old,{verify:deps.verifyAuthorization,now:new Date(casResult.authorizedAt)});
  assert.equal(casResult.status, "CUTOVER_COMMITTED_STATE_PENDING"); assert.equal(casResult.authorizationSha256, cutoverHash);
  assert.equal(casResult.preparationSha256, brokerDigest(old));
  await deps.authenticateCasResult(casResult, cutoverHash);
  const revalidate = async () => {
    equal(await deps.readCheckout(), brokerExecutionCheckout(p));
    equal(brokerAliasIdentity(await deps.getAlias()), casResult.alias);
    equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target);
    equal(await deps.readPrerequisites(), p.prerequisites);
    assert.equal(await deps.readTerraformFunctionVersion(), p.target.version, "New publication invalidates desired alias");
  };
  if (p.outputReconciliation) await deps.authenticateOutputReconciliation(p);
  await revalidate(); equal(await deps.readStateIdentity(), p.state);
  const refresh = await deps.captureRefreshOnlyPlan(); assertBrokerRefreshPlan(refresh.plan, p, casResult.alias);
  assert.ok(Buffer.isBuffer(refresh.bytes)); const refreshPlanSha256 = brokerDigest(refresh.bytes);
  if (p.outputReconciliation) await deps.authenticateOutputReconciliation(p);
  await revalidate(); equal(await deps.readStateIdentity(), p.state);
  await deps.reserve(brokerStateReservation(authHash), { purpose: "STAGE_B_BROKER_STATE_ONLY", parent: authHash, refreshPlanSha256 });
  const stateAuthorizedAt=(deps.now?.() || new Date()).toISOString();
  await deps.record(authHash, "STATE_REFRESH_INTENT", { refreshPlanSha256, authorizedAt:stateAuthorizedAt });
  await assertBrokerAuthorization(authorization, p, { verify: deps.verifyAuthorization, now: deps.now?.() || new Date() });
  if (p.outputReconciliation) await deps.authenticateOutputReconciliation(p);
  await revalidate(); equal(await deps.readStateIdentity(), p.state);
  try { await deps.applyRefreshOnlyPlan(refresh.bytes); }
  catch (error) { await deps.record(authHash, "STATE_REFRESH_UNKNOWN", {}); throw error; }
  await revalidate();
  const closure = await deps.captureNormalPlan(); assertBrokerClosurePlan(closure.plan, p);
  assert.ok(Buffer.isBuffer(closure.bytes));
  await revalidate(); await deps.authenticateTerraformState(p.target, casResult.alias);
  const record = { status: "RECONCILED_PENDING_RELEASE_CAS", sourceSha: p.sourceSha,
    mutationAddresses: [...BROKER_CENSUS], publicationAuthorizationSha256: p.publication.authorizationSha256,
    publicationResultSha256: brokerDigest(p.publication), cutoverAuthorizationSha256: cutoverHash,
    ...(cutoverPreparation?{stateRefreshAuthorizationSha256:authHash,stateAuthorizedAt}:{}),
    casResultSha256: brokerDigest(casResult), refreshPlanSha256, closurePlanSha256: brokerDigest(closure.bytes),
    closurePlan: closure.plan, closurePlanJsonSha256: brokerDigest(closure.plan),
    stateAfter: await deps.readStateIdentity(), target: p.target, alias: casResult.alias };
  await deps.record(authHash, record.status, record);
  await deps.publishTerminalHandoff({ preparation: old, authorization: oldAuthorization,
    ...(cutoverPreparation?{closure:{preparation:p,authorization}}:{}),casResult, record });
  return record;
}

export function brokerTransitionRequired({ desiredConfiguration, liveConfiguration }) {
  return canonicalJson(desiredConfiguration) !== canonicalJson(liveConfiguration);
}


export async function recoverBrokerPublication({ preparation: p, authorization }, deps) {
  context(p, BROKER_PUBLICATION);
  const { id, authorizedAt } = await deps.authenticateRecoveryIntent('PUBLICATION_INTENT', { savedPlanSha256: p.savedPlanSha256 });
  assert.equal(id, brokerDigest(authorization));
  const artifacts = await deps.readPlan(); assertPlanArtifacts(p, artifacts); assertBrokerPublicationPlan(artifacts.plan, p);
  equal(await deps.readCheckout(), brokerExecutionCheckout(p));
  if (p.prerequisiteChain) await deps.authenticatePrerequisiteChain(p.prerequisiteChain);
  equal(await deps.readPrerequisites(), p.prerequisites); equal(brokerAliasIdentity(await deps.getAlias()), p.alias);
  const before = await deps.readStateIdentity(); assert.equal(before.lineage, p.state.lineage); assert.ok(before.serial > p.state.serial);
  await deps.authenticatePublicationRecoveryState(artifacts.plan);
  const published = await deps.readPublicationResult({ savedPlanSha256: p.savedPlanSha256, authorizationSha256: id });
  assert.notEqual(published.version, p.alias.FunctionVersion); assert.equal(published.savedPlanSha256, p.savedPlanSha256); assert.equal(published.authorizationSha256, id);
  const target = brokerTargetIdentity(await deps.getVersion(published.version), p.packageSha256);
  assert.equal(target.version, published.version); equal(target.configuration.Environment.Variables, p.configuration);
  equal(await deps.readStateIdentity(), before); equal(brokerAliasIdentity(await deps.getAlias()), p.alias); equal(await deps.readPrerequisites(), p.prerequisites);
  const result = { schemaVersion: 1, status: 'PUBLISHED', sourceSha: p.sourceSha, authorizationSha256: id, preparationSha256: brokerDigest(p), savedPlanSha256: p.savedPlanSha256, target, alias: p.alias, authorizedAt };
  const receipt = await deps.readRecoveryReceipt(id, 'PUBLISHED'); if (receipt) equal(receipt, result); else await deps.record(id, 'PUBLISHED', result);
  return result;
}

export async function recoverBrokerAliasCas({ preparation: p, authorization }, deps) {
  context(p, BROKER_CUTOVER);
  const { id, authorizedAt } = await deps.authenticateRecoveryIntent('CUTOVER_INTENT', { predecessor: p.alias, target: p.target });
  assert.equal(id, brokerDigest(authorization));
  equal(await deps.readCheckout(), brokerExecutionCheckout(p));
  if (p.prerequisiteChain) await deps.authenticatePrerequisiteChain(p.prerequisiteChain);
  await deps.authenticatePublicationResult(p.publication, p.publication.authorizationSha256);
  const artifacts = await deps.readPlan(); assertPlanArtifacts(p, artifacts); assertBrokerCutoverPlan(artifacts.plan, p);
  equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target); equal(await deps.readPrerequisites(), p.prerequisites);
  const alias = brokerAliasIdentity(await deps.getAlias()); assert.equal(alias.FunctionVersion, p.target.version); assert.notEqual(alias.RevisionId, p.alias.RevisionId);
  equal({ ...alias, FunctionVersion: p.alias.FunctionVersion, RevisionId: p.alias.RevisionId }, p.alias);
  const receipt = await deps.readRecoveryReceipt(id, 'CUTOVER_COMMITTED_STATE_PENDING');
  if (receipt) { assert.equal(receipt.status, 'CUTOVER_COMMITTED_STATE_PENDING'); equal(receipt.alias, alias); assert.equal(receipt.authorizationSha256, id); assert.equal(receipt.preparationSha256, brokerDigest(p)); assert.equal(receipt.authorizedAt, authorizedAt); return receipt; }
  equal(await deps.readStateIdentity(), p.state, 'Missing CAS receipt requires unchanged Terraform predecessor');
  // A readback alone cannot establish that the approved native RevisionId CAS ran.
  const evidence = await deps.authenticateAliasCasRecovery({ preparation: p, authorization, authorizedAt, alias });
  equal(brokerAliasIdentity(await deps.getAlias()), alias); equal(await deps.readStateIdentity(), p.state);
  const result = { status: 'CUTOVER_COMMITTED_STATE_PENDING', authorizationSha256: id, preparationSha256: brokerDigest(p), alias, authorizedAt, recoveryEvidence: evidence };
  await deps.record(id, result.status, result); return result;
}

export async function recoverBrokerReconciliation({ preparation: p, authorization, casResult, cutoverPreparation, cutoverAuthorization }, deps) {
  context(p, cutoverPreparation ? BROKER_STATE_REFRESH : BROKER_CUTOVER);
  const old=cutoverPreparation?context(cutoverPreparation,BROKER_CUTOVER):p;
  const oldAuthorization=cutoverPreparation?cutoverAuthorization:authorization;
  if(cutoverPreparation)equal(p,prepareBrokerStateRefresh({preparation:old,authorization:oldAuthorization,casResult}));
  const { refreshPlanSha256 } = await deps.readRecoveryStateIntent();
  const { id,authorizedAt:stateAuthorizedAt } = await deps.authenticateRecoveryIntent('STATE_REFRESH_INTENT', { refreshPlanSha256 });
  assert.equal(id, brokerDigest(authorization));
  assert.equal(casResult.status, 'CUTOVER_COMMITTED_STATE_PENDING');
  assert.equal(casResult.alias.FunctionVersion, p.target.version); assert.notEqual(casResult.alias.RevisionId, p.alias.RevisionId);
  equal({ ...brokerAliasIdentity(casResult.alias), FunctionVersion: p.alias.FunctionVersion, RevisionId: p.alias.RevisionId }, p.alias);
  const cutoverHash=await assertBrokerAuthorization(oldAuthorization,old,{verify:deps.verifyAuthorization,now:new Date(casResult.authorizedAt)});
  await deps.authenticateCasResult(casResult, cutoverHash); assert.equal(casResult.authorizationSha256, cutoverHash); assert.equal(casResult.preparationSha256, brokerDigest(old));
  equal(await deps.readCheckout(), brokerExecutionCheckout(p));
  if (p.prerequisiteChain) await deps.authenticatePrerequisiteChain(p.prerequisiteChain);
  equal(brokerAliasIdentity(await deps.getAlias()), casResult.alias); equal(brokerTargetIdentity(await deps.getVersion(p.target.version), p.packageSha256), p.target);
  equal(await deps.readPrerequisites(), p.prerequisites); assert.equal(await deps.readTerraformFunctionVersion(), p.target.version);
  const state = await deps.readStateIdentity(); assert.equal(state.lineage, p.state.lineage); assert.ok(state.serial > p.state.serial);
  const closure = await deps.captureNormalPlan(); assertBrokerClosurePlan(closure.plan, p); assert.ok(Buffer.isBuffer(closure.bytes));
  await deps.authenticateTerraformState(p.target, casResult.alias); equal(await deps.readStateIdentity(), state); equal(brokerAliasIdentity(await deps.getAlias()), casResult.alias);
  const existing = await deps.readRecoveryReceipt(id, 'RECONCILED_PENDING_RELEASE_CAS');
  let record;
  if (existing) {
    assert.equal(existing.status, 'RECONCILED_PENDING_RELEASE_CAS'); assert.equal(existing.sourceSha, p.sourceSha); equal(existing.stateAfter, state); equal(existing.target, p.target); equal(existing.alias, casResult.alias);
    assert.equal(existing.cutoverAuthorizationSha256, cutoverHash);assert.equal(existing.stateRefreshAuthorizationSha256,cutoverPreparation?id:undefined);
    if(cutoverPreparation)assert.equal(existing.stateAuthorizedAt,stateAuthorizedAt);
    assert.equal(existing.casResultSha256, brokerDigest(casResult)); assert.equal(existing.refreshPlanSha256, refreshPlanSha256);
    assert.equal(existing.publicationResultSha256, brokerDigest(p.publication)); assert.equal(existing.publicationAuthorizationSha256, p.publication.authorizationSha256);
    equal(existing.mutationAddresses, BROKER_CENSUS); assertBrokerClosurePlan(existing.closurePlan, p); assert.equal(existing.closurePlanJsonSha256, brokerDigest(existing.closurePlan)); record = existing;
  } else {
    record = { status: 'RECONCILED_PENDING_RELEASE_CAS', sourceSha: p.sourceSha, mutationAddresses: [...BROKER_CENSUS], publicationAuthorizationSha256: p.publication.authorizationSha256,
      publicationResultSha256: brokerDigest(p.publication), cutoverAuthorizationSha256: cutoverHash,
      ...(cutoverPreparation?{stateRefreshAuthorizationSha256:id,stateAuthorizedAt}:{}),casResultSha256: brokerDigest(casResult), refreshPlanSha256,
      closurePlanSha256: brokerDigest(closure.bytes), closurePlan: closure.plan, closurePlanJsonSha256: brokerDigest(closure.plan), stateAfter: state, target: p.target, alias: casResult.alias };
    await deps.record(id, record.status, record);
  }
  await deps.publishTerminalHandoff({ preparation: old, authorization: oldAuthorization,
    ...(cutoverPreparation?{closure:{preparation:p,authorization}}:{}),casResult, record }); return record;
}

const authenticatedRecoveryApprovals = new WeakMap();
export const isAuthenticatedBrokerRecoveryApproval = value => authenticatedRecoveryApprovals.has(value) && authenticatedRecoveryApprovals.get(value) === brokerDigest(value);

export async function authenticateBrokerRecoveryApproval({ preparation, authorization, result }, deps) {
  assertBrokerPreparation(preparation);
  assert.ok([BROKER_CUTOVER, BROKER_STATE_REFRESH].includes(preparation.purpose));
  assert.ok(preparation.recoveryTooling, 'Approval recovery requires explicit tooling lineage');
  assert.equal(result.status, 'RECONCILED_PENDING_RELEASE_CAS');
  const closure = await authenticateStagedBrokerClosure({ sourceSha: preparation.sourceSha, deps });
  assert.ok(closure, 'Completed native terminal handoff is required');
  assert.equal(closure.evidenceSha256, brokerDigest(result));
  const id = await assertBrokerAuthorization(authorization, preparation, { verify: deps.verifyAuthorization,
    now: new Date(result.stateAuthorizedAt || authorization.issuedAt) });
  assert.equal(id, result.stateRefreshAuthorizationSha256 || result.cutoverAuthorizationSha256);
  await deps.authenticateReconciliation(result, id);
  await deps.authenticatePublicationResult(preparation.publication, preparation.publication.authorizationSha256);
  equal(await deps.readCheckout(), brokerExecutionCheckout(preparation));
  equal(result.target, preparation.target); equal(result.sourceSha, preparation.sourceSha);
  equal(result.publicationResultSha256, brokerDigest(preparation.publication));
  equal(await deps.getAlias(), result.alias);
  equal(brokerTargetIdentity(await deps.getVersion(result.target.version), preparation.packageSha256), result.target);
  equal(await deps.readStateIdentity(), result.stateAfter);
  assert.equal(result.closurePlanJsonSha256, brokerDigest(result.closurePlan));
  assertBrokerClosurePlan(result.closurePlan, preparation);
  const context = Object.freeze({ sourceSha: preparation.sourceSha, tooling: brokerExecutionCheckout(preparation),
    publicationResultSha256: brokerDigest(preparation.publication), preparationSha256: brokerDigest(preparation),
    closureResultSha256: brokerDigest(result), target: structuredClone(result.target), alias: structuredClone(result.alias) });
  authenticatedRecoveryApprovals.set(context, brokerDigest(context)); return context;
}
