import assert from "node:assert/strict";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";
import { BROKER_CUTOVER, BROKER_STATE_REFRESH, brokerDigest, brokerExecutionCheckout, brokerTargetIdentity, assertBrokerPreparation, assertBrokerAuthorization, assertBrokerClosurePlan } from "./stage-b-staged-broker-contract.mjs";
const equal = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
const authenticatedRecoveryApprovals = new WeakMap();
export const isAuthenticatedBrokerRecoveryApproval = value => authenticatedRecoveryApprovals.has(value) && authenticatedRecoveryApprovals.get(value) === brokerDigest(value);

export async function authenticateBrokerRecoveryApproval({ preparation, authorization, result }, deps) {
  assertBrokerPreparation(preparation);
  assert.ok([BROKER_CUTOVER, BROKER_STATE_REFRESH].includes(preparation.purpose));
  assert.ok(preparation.recoveryTooling, 'Approval recovery requires explicit tooling lineage');
  assert.equal(result.status, 'RECONCILED_PENDING_RELEASE_CAS');
  const { authenticateStagedBrokerClosure } = await import("./stage-b-staged-broker-closure.mjs");
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
