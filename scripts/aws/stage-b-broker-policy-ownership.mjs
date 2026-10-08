import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { assertBrokerWriterSession } from './stage-b-broker-writer-session.mjs';
import { PRODUCTION_COMPONENT_STATE } from './production-component-deployment-state.mjs';
import { canonicalJson } from './production-green-stage-b-contract.mjs';
import { STAGE_B_BROKER_POLICY } from './stage-b-deployment-contract.mjs';

export const BROKER_POLICY_OWNERSHIP_KEY = `production#iam-policy-owner#${STAGE_B_BROKER_POLICY.arn}`;
const same = (a, b) => assert.equal(canonicalJson(a), canonicalJson(b));
const digest = value => assert.match(value || '', /^[a-f0-9]{64}$/);
function identity(value) {
  assert.deepEqual(Object.keys(value).sort(), ['generation', 'operationIdentity', 'owner', 'policyArn', 'sourceSha', ...(value.writerSession ? ['writerSession'] : [])].sort());
  if (value.writerSession) assertBrokerWriterSession(value.writerSession);
  assert.equal(value.policyArn, STAGE_B_BROKER_POLICY.arn);
  assert.match(value.owner || '', /^[a-f0-9-]{36}$/);
  assert.ok(Number.isSafeInteger(value.generation) && value.generation > 0);
  assert.match(value.sourceSha || '', /^[a-f0-9]{40}$/); digest(value.operationIdentity);
  return value;
}
function record(value) {
  assert.deepEqual(Object.keys(value).sort(), ['acquisition', 'identity', 'mutation', 'status', 'terminal'].sort());
  identity(value.identity);
  assert.deepEqual(Object.keys(value.acquisition).sort(), ['authorizedAt', 'preparationSha256', 'purpose', 'reservationSha256']);
  assert.ok(['STAGE_B_BROKER_POLICY_CONVERGENCE', 'STAGE_B_BROKER_POLICY_PRUNING'].includes(value.acquisition.purpose));
  digest(value.acquisition.preparationSha256); digest(value.acquisition.reservationSha256);
  assert.equal(new Date(value.acquisition.authorizedAt).toISOString(), value.acquisition.authorizedAt);
  if (value.mutation !== null) { assert.deepEqual(Object.keys(value.mutation), ['intentSha256']); digest(value.mutation.intentSha256); }
  assert.ok(['HELD', 'RELEASED'].includes(value.status));
  if (value.terminal !== null) {
    assert.deepEqual(Object.keys(value.terminal).sort(), ['outcome', 'receiptSha256']);
    assert.ok(['SUCCEEDED', 'RECOVERED_NO_WRITE'].includes(value.terminal.outcome)); digest(value.terminal.receiptSha256);
    if (value.terminal.outcome === 'SUCCEEDED') assert.ok(value.mutation, 'Success requires durable mutation intent');
  }
  if (value.status === 'RELEASED') assert.ok(value.terminal);
  return value;
}

// Historical RELEASED provenance remains immutable when this exact convergence
// acquires its next generation. This is not permission to accept another owner.
export function assertBrokerPolicyPredecessorOwnership(previous, current, transition) {
  record(previous); record(current);
  assert.equal(previous.status, 'RELEASED'); assert.equal(previous.terminal.outcome, 'SUCCEEDED');
  if (!transition) { same(current, previous); return true; }
  const { owner, operation } = transition;
  assert.equal(operation.acquisition.purpose, 'STAGE_B_BROKER_POLICY_CONVERGENCE');
  same(current.identity, identity(owner));
  assert.equal(current.status, 'HELD'); assert.equal(current.terminal, null);
  assert.equal(owner.generation, previous.identity.generation + 1);
  assert.equal(owner.policyArn, previous.identity.policyArn);
  for (const field of ['policyArn', 'sourceSha', 'operationIdentity', 'writerSession']) same(owner[field], operation[field]);
  same(current.acquisition, operation.acquisition);
  return true;
}

// A fixed policy domain, not a release lease. No TTL, stealing, or exception unlock.
export function createBrokerPolicyOwnershipClient({ run }) {
  const key = { stateKey: { S: BROKER_POLICY_OWNERSHIP_KEY } };
  const commands = { 'get-item': ['dynamodb', 'get-item'], 'put-item': ['dynamodb', 'put-item'], 'update-item': ['dynamodb', 'update-item'] };
  const invoke = (operation, args) => JSON.parse(run([...commands[operation], '--table-name', PRODUCTION_COMPONENT_STATE.table,
    ...args, '--region', PRODUCTION_COMPONENT_STATE.region, '--output', 'json', '--no-cli-pager']) || '{}');
  const read = () => {
    const item = invoke('get-item', ['--key', JSON.stringify(key), '--consistent-read']).Item;
    if (!item) return null;
    assert.equal(item.stateKey.S, BROKER_POLICY_OWNERSHIP_KEY);
    const value = record(JSON.parse(item.state.S));
    assert.equal(item.generation.N, String(value.identity.generation)); return value;
  };
  const update = (owner, current, next) => {
    identity(owner); same(current.identity, owner); record(next);
    const result = invoke('update-item', ['--key', JSON.stringify(key), '--update-expression', 'SET #state = :next', '--return-values', 'ALL_NEW',
      '--condition-expression', '#generation = :generation AND #state = :current',
      '--expression-attribute-names', JSON.stringify({ '#state': 'state', '#generation': 'generation' }),
      '--expression-attribute-values', JSON.stringify({ ':next': { S: canonicalJson(next) }, ':current': { S: canonicalJson(current) }, ':generation': { N: String(owner.generation) } })]);
    assert.equal(result.Attributes.state.S, canonicalJson(next)); assert.equal(result.Attributes.generation.N, String(owner.generation));
    return next; // The authenticated write response cannot race a subsequent acquisition.
  };
  return Object.freeze({
    read,
    acquire({ policyArn, sourceSha, operationIdentity, writerSession, acquisition, owner = randomUUID() }) {
      assertBrokerWriterSession(writerSession);
      const previous = read();
      assert.ok(previous === null || previous.status === 'RELEASED', 'Broker policy ownership already held; recovery required');
      const next = record({ identity: identity({ policyArn, sourceSha, operationIdentity, owner, ...(writerSession ? { writerSession } : {}), generation: (previous?.identity.generation || 0) + 1 }), acquisition, mutation: null, status: 'HELD', terminal: null });
      // One conditional write decides the winner, including racing absent-item reads.
      try { invoke('put-item', ['--item', JSON.stringify({ ...key, generation: { N: String(next.identity.generation) }, state: { S: canonicalJson(next) } }),
        '--condition-expression', previous ? '#state = :previous AND #generation = :generation' : 'attribute_not_exists(#key)',
        '--expression-attribute-names', JSON.stringify(previous ? { '#state': 'state', '#generation': 'generation' } : { '#key': 'stateKey' }),
        ...(previous ? ['--expression-attribute-values', JSON.stringify({ ':previous': { S: canonicalJson(previous) }, ':generation': { N: String(previous.identity.generation) } })] : [])]); }
      catch (cause) { throw Object.assign(new Error('Ownership acquisition failed; do not retry blindly', { cause }), { ownership: next.identity, recoveryRequired: true }); }
      same(read(), next); return next.identity;
    },
    assertHeld(owner) { const current = read(); assert.ok(current); same(current.identity, identity(owner)); assert.equal(current.status, 'HELD'); assert.equal(current.terminal, null); return current; },
    commitMutation(owner, intentSha256) {
      digest(intentSha256); const current = this.assertHeld(owner); assert.equal(current.mutation, null, 'Mutation authority already committed');
      return update(owner, current, { ...current, mutation: { intentSha256 } });
    },
    assertCommitted(owner, intentSha256) { const current = this.assertHeld(owner); same(current.mutation, { intentSha256 }); return current; },
    complete(owner, terminal) { const current = this.assertHeld(owner);
      if (terminal.outcome === 'SUCCEEDED') assert.ok(current.mutation, 'Success requires durable mutation intent');
      return update(owner, current, { ...current, terminal }); },
    release(owner) {
      const current = read(); assert.ok(current); same(current.identity, identity(owner)); assert.equal(current.status, 'HELD');
      assert.ok(current.terminal, 'A persisted terminal receipt is required before release');
      return update(owner, current, { ...current, status: 'RELEASED' });
    },
  });
}

// The caller authenticates signed saved-plan authority before entry. Both policy
// convergence and separately approved pruning must use this critical section.
export async function executeOwnedBrokerPolicyMutation({ ownership, operation, reserve, authenticate, readPolicy, persistIntent, mutate, persistReceipt }) {
  // One-use authority is consumed without IAM writes before any new generation.
  // A failed/uncertain acquisition retains that reservation; never retry it.
  assert.equal(typeof reserve, 'function');
  await reserve();
  let owner;
  try { owner = ownership.acquire(operation); }
  catch (cause) {
    throw Object.assign(new Error('Authority reserved; ownership acquisition failed; read-only diagnosis required', { cause }),
      { reservationConsumed: true, operationIdentity: operation.operationIdentity, ownership: cause.ownership, recoveryRequired: true });
  }
  try {
    const approved = await authenticate(owner); ownership.assertHeld(owner);
    same(await readPolicy(), approved.predecessor);
    ownership.assertHeld(owner);
    assert.equal(typeof persistIntent, 'function');
    const intent = await persistIntent({ approved, owner }); digest(intent.sha256);
    ownership.commitMutation(owner, intent.sha256);
    ownership.assertCommitted(owner, intent.sha256);
    const result = await mutate(approved, owner, intent); // exactly one attempt; never retry
    const successor = await readPolicy(); same(successor, approved.successor);
    const receiptSha256 = await persistReceipt({ owner, approved, result, successor }); digest(receiptSha256);
    ownership.complete(owner, { outcome: 'SUCCEEDED', receiptSha256 }); ownership.release(owner);
    return { owner, receiptSha256, status: 'SUCCEEDED' };
  } catch (cause) {
    throw Object.assign(new Error('Broker policy ownership retained; read-only recovery required', { cause }), { ownership: owner, recoveryRequired: true });
  }
}

// Recovery is diagnosis, never another IAM mutation. The original execution
// credentials must be proved unusable before completing its exact held generation.
export async function recoverOwnedBrokerPolicyMutation({ ownership, owner, authenticateTermination, authenticateRecovery, readPolicy, persistReceipt }) {
  const current = ownership.read(); assert.ok(current); same(current.identity, identity(owner)); assert.equal(current.status, 'HELD');
  assert.equal(typeof authenticateTermination, 'function', 'Independent termination verifier required');
  const termination = await authenticateTermination(owner);
  assert.equal(termination.mechanism, 'AWS_STS_AUTHENTICATED_EXPIRY');
  assert.equal(termination.ownerSha256, createHash('sha256').update(canonicalJson(owner)).digest('hex'));
  same(termination.session, owner.writerSession); assertBrokerWriterSession(termination.session);
  assert.ok(Date.parse(termination.observedAt) > Date.parse(termination.session.expiresAt));
  assert.equal(termination.previousWriterCannotContinue, true);
  const recovery = await authenticateRecovery(owner, termination);
  assert.equal(recovery.previousExecutionCannotContinue, true);
  assert.equal(recovery.authorizationConsumed, true);
  assert.ok(['SUCCEEDED', 'RECOVERED_NO_WRITE'].includes(recovery.outcome));
  if (recovery.outcome === 'SUCCEEDED') assert.ok(current.mutation, 'Uncommitted owner cannot authenticate mutation success');
  same(await readPolicy(), recovery.expectedPolicy);
  if (current.terminal) {
    same(current.terminal, { outcome: recovery.outcome, receiptSha256: recovery.receiptSha256 });
    same(ownership.read(), current); ownership.release(owner);
    return { owner, ...current.terminal, status: recovery.outcome };
  }
  ownership.assertHeld(owner);
  const receiptSha256 = await persistReceipt({ owner, recovery }); digest(receiptSha256);
  ownership.complete(owner, { outcome: recovery.outcome, receiptSha256 }); ownership.release(owner);
  return { owner, receiptSha256, status: recovery.outcome };
}
