import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import { writerSession } from './fixtures/broker-writer-session.mjs';
import { proveBrokerWriterUnusable } from '../aws/stage-b-broker-writer-session.mjs';
import { assertBrokerPolicyPredecessorOwnership, createBrokerPolicyOwnershipClient, BROKER_POLICY_OWNERSHIP_KEY, executeOwnedBrokerPolicyMutation, recoverOwnedBrokerPolicyMutation } from '../aws/stage-b-broker-policy-ownership.mjs';
import { STAGE_B_BROKER_POLICY } from '../aws/stage-b-deployment-contract.mjs';

function rig() {
  let item; const calls = [];
  const run = args => {
    calls.push(args); const value = name => JSON.parse(args[args.indexOf(name) + 1]);
    assert.equal(args[args.indexOf('--table-name') + 1], 'mscqr-production-component-deployment-state');
    if (args[1] === 'get-item') { assert.ok(args.includes('--consistent-read')); return JSON.stringify(item ? { Item: item } : {}); }
    const values = args.includes('--expression-attribute-values') ? value('--expression-attribute-values') : {};
    const reject = () => { throw Object.assign(new Error('ConditionalCheckFailedException'), { name: 'ConditionalCheckFailedException' }); };
    if (args[1] === 'put-item') {
      if (values[':previous']) { if (item?.state.S !== values[':previous'].S || item?.generation.N !== values[':generation'].N) reject(); }
      else if (item) reject();
      item = value('--item');
    } else {
      assert.equal(args[1], 'update-item');
      if (item?.state.S !== values[':current'].S || item?.generation.N !== values[':generation'].N) reject();
      item.state = values[':next'];
      return JSON.stringify({ Attributes: item });
    }
    return '{}';
  };
  return { client: createBrokerPolicyOwnershipClient({ run }), calls, run };
}
const operation = { policyArn: STAGE_B_BROKER_POLICY.arn, sourceSha: 'a'.repeat(40), operationIdentity: 'b'.repeat(64), writerSession, acquisition: { purpose: 'STAGE_B_BROKER_POLICY_CONVERGENCE', preparationSha256: 'e'.repeat(64), reservationSha256: 'f'.repeat(64), authorizedAt: '2026-10-04T00:00:00.000Z' } };
const receipt = 'c'.repeat(64);
test('one fixed key, one winner, no time-based stealing; exact terminal release increments generation', () => {
  const { client, calls } = rig(), owner = client.acquire(operation);
  assert.throws(() => client.acquire({ ...operation, sourceSha: 'd'.repeat(40) }));
  assert.throws(() => client.release(owner));
  assert.throws(() => client.complete({ ...owner, owner: '0'.repeat(36) }, { outcome: 'SUCCEEDED', receiptSha256: receipt }));
  assert.throws(() => client.complete({ ...owner, generation: 2 }, { outcome: 'SUCCEEDED', receiptSha256: receipt }));
  client.commitMutation(owner, receipt); client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt }); client.release(owner);
  assert.equal(client.acquire(operation).generation, 2);
  for (const args of calls) {
    if (args.includes('--item')) {
      const stored = JSON.parse(JSON.parse(args[args.indexOf('--item') + 1]).state.S);
      assert.equal(stored.expiresAt, undefined); assert.equal(stored.ttl, undefined);
    }
    if (args.includes('--key')) assert.equal(JSON.parse(args[args.indexOf('--key') + 1]).stateKey.S, BROKER_POLICY_OWNERSHIP_KEY);
  }
});
test('wrong policy is rejected before acquisition', () => { const { client } = rig(); assert.throws(() => client.acquire({ ...operation, policyArn: `${operation.policyArn}-other` })); assert.equal(client.read(), null); });
for (const failure of ['authentication', 'predecessor', 'before-write', 'after-write', 'successor', 'receipt']) test(`${failure} retains ownership and prevents normal/recovery race`, async () => {
  const { client } = rig(); let writes = 0;
  const predecessor = { version: 'v1', policy: 'old' }, successor = { version: 'v2', policy: 'new' };
  await assert.rejects(() => executeOwnedBrokerPolicyMutation({ ownership: client, operation, reserve: () => {},
    persistIntent: () => ({ sha256: receipt }), authenticate: () => { if (failure === 'authentication') throw new Error('invalid/replay'); return { predecessor, successor }; },
    readPolicy: () => failure === 'predecessor' || failure === 'successor' ? {} : writes ? successor : predecessor,
    mutate: () => { if (failure === 'before-write') throw new Error('crash'); writes++; if (failure === 'after-write') throw new Error('timeout'); },
    persistReceipt: () => { if (failure === 'receipt') throw new Error('crash'); return receipt; },
  }));
  assert.equal(client.read().status, 'HELD'); assert.throws(() => client.acquire(operation)); assert.ok(writes <= 1);
  const owner = client.read().identity;
  await assert.rejects(() => recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: held => proveBrokerWriterUnusable(held, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => ({ previousExecutionCannotContinue: false, authorizationConsumed: true, outcome: 'SUCCEEDED', expectedPolicy: successor }),
    readPolicy: () => successor, persistReceipt: () => receipt }));
  assert.equal(client.read().status, 'HELD');
});
test('exact successor and persisted receipt release; replay authentication cannot mutate', async () => {
  const { client } = rig(); let writes = 0, consumed = false;
  const execute = () => executeOwnedBrokerPolicyMutation({ ownership: client, operation,
    reserve: () => { assert.equal(consumed, false); consumed = true; }, persistIntent: () => ({ sha256: receipt }), authenticate: () => ({ predecessor: 0, successor: 1 }),
    readPolicy: () => writes, mutate: () => ++writes, persistReceipt: () => receipt });
  await execute(); assert.equal(client.read().status, 'RELEASED');
  await assert.rejects(execute); assert.equal(writes, 1); assert.equal(client.read().status, 'RELEASED'); assert.equal(client.read().identity.generation, 1);
});
test('read-only recovery uses original generation and cannot launch a competing mutation', async () => {
  const { client } = rig(), owner = client.acquire(operation);
  const recovered = await recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: held => proveBrokerWriterUnusable(held, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => ({ previousExecutionCannotContinue: true, authorizationConsumed: true, outcome: 'RECOVERED_NO_WRITE', expectedPolicy: 'old' }),
    readPolicy: () => 'old', persistReceipt: () => receipt });
  assert.equal(recovered.status, 'RECOVERED_NO_WRITE'); assert.equal(client.read().status, 'RELEASED');
  assert.equal(client.acquire(operation).generation, owner.generation + 1);
});
test('pruning and convergence contend on the same policy record', () => {
  const { client } = rig(); client.acquire(operation);
  assert.throws(() => client.acquire({ ...operation, operationIdentity: 'e'.repeat(64) }));
});
test('two asynchronous releases race: only the first can enter the IAM critical section', async () => {
  const { client } = rig(); let releaseAuthentication, entered = false, writes = 0;
  const waiting = new Promise(resolve => releaseAuthentication = resolve);
  const input = { ownership: client, operation, reserve: () => {}, persistIntent: () => ({ sha256: receipt }), authenticate: async () => { entered = true; await waiting; return { predecessor: 0, successor: 1 }; },
    readPolicy: () => writes, mutate: () => ++writes, persistReceipt: () => receipt };
  const first = executeOwnedBrokerPolicyMutation(input); await Promise.resolve(); assert.equal(entered, true);
  await assert.rejects(() => executeOwnedBrokerPolicyMutation({ ...input, operation: { ...operation, sourceSha: 'e'.repeat(40) } }));
  releaseAuthentication(); await first; assert.equal(writes, 1);
});
test('crash after persisted terminal can recover the original generation without an IAM retry', async () => {
  const { client } = rig(), owner = client.acquire(operation);
  client.commitMutation(owner, receipt); client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt });
  await recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: held => proveBrokerWriterUnusable(held, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => ({ previousExecutionCannotContinue: true, authorizationConsumed: true, outcome: 'SUCCEEDED', expectedPolicy: 'new', receiptSha256: receipt }),
    readPolicy: () => 'new', persistReceipt: () => { assert.fail('Do not replace the existing receipt'); } });
  assert.equal(client.read().status, 'RELEASED');
});
test('persistent administrative drift blocks recovery instead of rebaselining', async () => {
  const { client } = rig(), owner = client.acquire(operation);
  await assert.rejects(() => recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: held => proveBrokerWriterUnusable(held, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => ({ previousExecutionCannotContinue: true, authorizationConsumed: true, outcome: 'SUCCEEDED', expectedPolicy: 'approved' }),
    readPolicy: () => 'administrative drift', persistReceipt: () => receipt }));
  assert.equal(client.read().status, 'HELD');
});
test('approved pruning occupies the same critical section and verifies its exact inventory successor', async () => {
  const { client } = rig(); let versions = ['v1', 'v2'];
  await executeOwnedBrokerPolicyMutation({ ownership: client, operation: { ...operation, operationIdentity: 'f'.repeat(64) }, reserve: () => {},
    persistIntent: () => ({ sha256: receipt }), authenticate: () => ({ predecessor: ['v1', 'v2'], successor: ['v2'] }), readPolicy: () => versions,
    mutate: () => { assert.throws(() => client.acquire(operation)); versions = ['v2']; }, persistReceipt: () => receipt });
  assert.equal(client.read().status, 'RELEASED');
});

test('stale absent-row read cannot acquire a second owner', () => {
  const r = rig(); r.client.acquire(operation);
  let stale = true;
  const contender = createBrokerPolicyOwnershipClient({ run: args => {
    if (args[1] === 'get-item' && stale) { stale = false; return '{}'; }
    return r.run(args);
  } });
  assert.throws(() => contender.acquire(operation), /do not retry blindly/);
  assert.equal(r.client.read().status, 'HELD');
});
test('ownership IAM authority covers only the fixed key, table, region and conditional operations', () => {
  const policy = JSON.parse(fs.readFileSync(new URL('../../documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json', import.meta.url)));
  const statement = policy.Statement.find(s => s.Sid === 'OwnExactBrokerPolicyMutationDomain');
  assert.deepEqual(statement, { Sid: 'OwnExactBrokerPolicyMutationDomain', Effect: 'Allow',
    Action: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
    Resource: 'arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-component-deployment-state',
    Condition: { 'ForAllValues:StringEquals': { 'dynamodb:LeadingKeys': [BROKER_POLICY_OWNERSHIP_KEY] },
      StringEquals: { 'aws:RequestedRegion': 'eu-west-2' }, Null: { 'dynamodb:LeadingKeys': 'false' } } });
});

test('proof from another generation cannot release this owner', async () => {
  const { client } = rig(), owner = client.acquire(operation);
  await assert.rejects(() => recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: () => proveBrokerWriterUnusable({ ...owner, generation: owner.generation + 1 }, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => assert.fail('Wrong generation must fail before outcome authentication'), readPolicy: () => 0, persistReceipt: () => receipt }));
  assert.equal(client.read().status, 'HELD');
});
test('old terminal receipt substitution cannot complete an authenticated expired owner', async () => {
  const { client } = rig(), owner = client.acquire(operation); client.commitMutation(owner, receipt); client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt });
  await assert.rejects(() => recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: held => proveBrokerWriterUnusable(held, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => ({ previousExecutionCannotContinue: true, authorizationConsumed: true, outcome: 'SUCCEEDED', expectedPolicy: 'exact', receiptSha256: 'd'.repeat(64) }),
    readPolicy: () => 'exact', persistReceipt: () => assert.fail('Cannot replace the existing terminal receipt') }));
  assert.equal(client.read().status, 'HELD');
});

for (const purpose of ['convergence', 'pruning']) test(`consumed ${purpose} approval is rejected before any ownership generation`, async () => {
  const { client, calls } = rig(); let reserved = false, writes = 0;
  const input = { ownership: client, operation,
    reserve: () => { assert.equal(reserved, false); reserved = true; },
    persistIntent: () => ({ sha256: receipt }), authenticate: () => ({ predecessor: 0, successor: 1 }), readPolicy: () => writes,
    mutate: () => ++writes, persistReceipt: () => receipt };
  await executeOwnedBrokerPolicyMutation(input);
  const acquisitions = calls.filter(a => a[1] === 'put-item').length;
  await assert.rejects(() => executeOwnedBrokerPolicyMutation(input));
  assert.equal(calls.filter(a => a[1] === 'put-item').length, acquisitions);
  assert.equal(client.read().status, 'RELEASED'); assert.equal(client.read().identity.generation, 1); assert.equal(writes, 1);
});
test('concurrent same-approval reservation has one winner, one generation and one mutation', async () => {
  const { client, calls } = rig(); let reserved = false, writes = 0;
  const input = { ownership: client, operation,
    reserve: () => { assert.equal(reserved, false); reserved = true; },
    persistIntent: () => ({ sha256: receipt }), authenticate: () => ({ predecessor: 0, successor: 1 }), readPolicy: () => writes, mutate: () => ++writes, persistReceipt: () => receipt };
  const results = await Promise.allSettled([executeOwnedBrokerPolicyMutation(input), executeOwnedBrokerPolicyMutation(input)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1); assert.equal(writes, 1);
  assert.equal(calls.filter(a => a[1] === 'put-item').length, 1); assert.equal(client.read().status, 'RELEASED');
});
test('reserved authority cannot steal held ownership or be silently reused after acquisition failure', async () => {
  const { client } = rig(), held = client.acquire({ ...operation, operationIdentity: 'd'.repeat(64) });
  let reserved = false, writes = 0;
  const input = { ownership: client, operation,
    reserve: () => { assert.equal(reserved, false); reserved = true; },
    persistIntent: () => ({ sha256: receipt }), authenticate: () => assert.fail('No predecessor read without ownership'), readPolicy: () => 0,
    mutate: () => ++writes, persistReceipt: () => receipt };
  await assert.rejects(() => executeOwnedBrokerPolicyMutation(input), error => error.reservationConsumed === true && error.recoveryRequired === true && error.operationIdentity === operation.operationIdentity);
  assert.equal(reserved, true); assert.deepEqual(client.read().identity, held); assert.equal(writes, 0);
  await assert.rejects(() => executeOwnedBrokerPolicyMutation(input)); assert.deepEqual(client.read().identity, held);
});

const crashWindows = ['reservation-before','reservation-after','acquire-before','acquire-after','authentication-before','authentication-after',
  'predecessor-before','predecessor-after','intent-before','intent-after','commit-before','commit-after','iam-before','iam-after',
  'successor-before','successor-after','receipt-before','receipt-after','completion-before','completion-after','release-before','release-after'];
for (const window of crashWindows) test(`complete owned mutation crash boundary ${window} retains or recovers exact generation without retry`, async () => {
  const { client } = rig(); let reserved = false, intent, terminal, writes = 0, receiptWrites = 0;
  const crash = at => { if (at === window) throw new Error(`process exit ${at}`); };
  const ownership = { ...client,
    acquire: value => { crash('acquire-before'); const owner = client.acquire(value); crash('acquire-after'); return owner; },
    commitMutation: (...args) => { crash('commit-before'); const value = client.commitMutation(...args); crash('commit-after'); return value; },
    complete: (...args) => { crash('completion-before'); const value = client.complete(...args); crash('completion-after'); return value; },
    release: (...args) => { crash('release-before'); const value = client.release(...args); crash('release-after'); return value; } };
  const input = { ownership, operation,
    reserve: () => { assert.equal(reserved, false); crash('reservation-before'); reserved = true; crash('reservation-after'); },
    authenticate: () => { crash('authentication-before'); const value = { predecessor: 0, successor: 1 }; crash('authentication-after'); return value; },
    readPolicy: () => { const boundary = writes ? 'successor' : 'predecessor'; crash(`${boundary}-before`); const value = writes; crash(`${boundary}-after`); return value; },
    persistIntent: ({ owner }) => { crash('intent-before'); intent = { owner }; crash('intent-after'); return { sha256: receipt }; },
    mutate: () => { assert.equal(client.read().mutation.intentSha256, receipt); crash('iam-before'); writes++; crash('iam-after'); },
    persistReceipt: () => { crash('receipt-before'); terminal = { outcome: 'SUCCEEDED', receiptSha256: receipt }; receiptWrites++; crash('receipt-after'); return receipt; } };
  await assert.rejects(() => executeOwnedBrokerPolicyMutation(input)); assert.ok(writes <= 1);
  const held = client.read();
  if (held?.status === 'HELD') {
    assert.deepEqual(held.acquisition, operation.acquisition); assert.deepEqual(held.identity.writerSession, writerSession);
    if (held.mutation) { assert.ok(intent); assert.equal(held.mutation.intentSha256, receipt); }
    const result = await recoverOwnedBrokerPolicyMutation({ ownership: client, owner: held.identity,
      authenticateTermination: owner => proveBrokerWriterUnusable(owner, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
      authenticateRecovery: () => ({ previousExecutionCannotContinue: true, authorizationConsumed: reserved,
        outcome: writes ? 'SUCCEEDED' : 'RECOVERED_NO_WRITE', expectedPolicy: writes, receiptSha256: receipt }),
      readPolicy: () => writes, persistReceipt: () => { if (!terminal) { receiptWrites++; terminal = { outcome: writes ? 'SUCCEEDED' : 'RECOVERED_NO_WRITE', receiptSha256: receipt }; } return receipt; } });
    assert.equal(result.status, writes ? 'SUCCEEDED' : 'RECOVERED_NO_WRITE'); assert.equal(client.read().status, 'RELEASED'); assert.equal(receiptWrites, 1);
  } else assert.ok(held === null || held.status === 'RELEASED');
  const generations = client.read()?.identity.generation;
  if (reserved) { await assert.rejects(() => executeOwnedBrokerPolicyMutation(input)); assert.equal(client.read()?.identity.generation, generations); }
  assert.ok(writes <= 1);
});
test('two recoveries and an old writer waking contend on the same exact generation', async () => {
  const { client } = rig(); let reserved = false, writes = 0, awaken;
  const paused = new Promise(resolve => awaken = resolve);
  const executing = executeOwnedBrokerPolicyMutation({ ownership: client, operation,
    reserve: () => { assert.equal(reserved, false); reserved = true; }, authenticate: async () => { await paused; return { predecessor: 0, successor: 1 }; },
    readPolicy: () => writes, persistIntent: () => ({ sha256: receipt }), mutate: () => ++writes, persistReceipt: () => receipt });
  await Promise.resolve(); const owner = client.read().identity;
  let receiptPersisted = false;
  const input = { ownership: client, owner,
    authenticateTermination: value => proveBrokerWriterUnusable(value, { readIssuance: s => s, readClock: () => '2026-10-04T01:00:01.000Z' }),
    authenticateRecovery: () => ({ previousExecutionCannotContinue: true, authorizationConsumed: true, outcome: 'RECOVERED_NO_WRITE', expectedPolicy: 0 }),
    readPolicy: () => 0, persistReceipt: () => { assert.equal(receiptPersisted, false); receiptPersisted = true; return receipt; } };
  const results = await Promise.allSettled([recoverOwnedBrokerPolicyMutation(input), recoverOwnedBrokerPolicyMutation(input)]);
  assert.equal(results.filter(v => v.status === 'fulfilled').length, 1); assert.equal(client.read().status, 'RELEASED');
  const next = client.acquire({ ...operation, operationIdentity: '1'.repeat(64) });
  awaken(); await assert.rejects(() => executing); assert.equal(writes, 0); assert.deepEqual(client.read().identity, next);
});
test('old writer with valid credentials cannot be released, even before an intent exists', async () => {
  const { client } = rig(), owner = client.acquire(operation);
  await assert.rejects(() => recoverOwnedBrokerPolicyMutation({ ownership: client, owner,
    authenticateTermination: value => proveBrokerWriterUnusable(value, { readIssuance: s => s, readClock: () => writerSession.expiresAt }),
    authenticateRecovery: () => assert.fail('Must prove credential expiry first'), readPolicy: () => 0, persistReceipt: () => receipt }));
  assert.equal(client.read().status, 'HELD');
});
test('mutation commit is single-use and success cannot be fabricated for an uncommitted acquisition', () => {
  const { client } = rig(), owner = client.acquire(operation);
  assert.throws(() => client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt }));
  client.commitMutation(owner, receipt); assert.throws(() => client.commitMutation(owner, receipt));
  assert.throws(() => client.assertCommitted({ ...owner, generation: owner.generation + 1 }, receipt));
  assert.throws(() => client.assertCommitted(owner, '0'.repeat(64))); assert.equal(client.read().status, 'HELD');
});


test('authenticated released policy provenance survives exactly its next owned convergence without bypassing held-generation checks', async () => {
  const { client } = rig(), historicalOwner = client.acquire(operation);
  client.commitMutation(historicalOwner, receipt);
  client.complete(historicalOwner, { outcome: 'SUCCEEDED', receiptSha256: receipt });
  client.release(historicalOwner);
  const historical = structuredClone(client.read());
  assert.equal(assertBrokerPolicyPredecessorOwnership(historical, client.read()), true);
  const next = { ...operation, operationIdentity: '1'.repeat(64), sourceSha: '2'.repeat(40),
    acquisition: { ...operation.acquisition, preparationSha256: '3'.repeat(64), reservationSha256: '4'.repeat(64) } };
  let writes = 0, transition;
  await executeOwnedBrokerPolicyMutation({ ownership: client, operation: next, reserve: () => {},
    authenticate: owner => {
      transition = { owner, operation: next };
      assert.equal(assertBrokerPolicyPredecessorOwnership(historical, client.read(), transition), true);
      assert.throws(() => assertBrokerPolicyPredecessorOwnership(historical, client.read()));
      for (const alter of [v => v.owner.generation++, v => v.operation.sourceSha = '9'.repeat(40),
        v => v.operation.operationIdentity = '9'.repeat(64), v => v.operation.writerSession.sessionName += '-other',
        v => v.operation.acquisition.preparationSha256 = '9'.repeat(64),
        v => v.operation.acquisition.reservationSha256 = '9'.repeat(64),
        v => v.operation.acquisition.purpose = 'STAGE_B_BROKER_POLICY_PRUNING']) {
        const bad = structuredClone(transition); alter(bad);
        assert.throws(() => assertBrokerPolicyPredecessorOwnership(historical, client.read(), bad));
        assert.equal(writes, 0);
      }
      return { predecessor: 'old', successor: 'new' };
    },
    readPolicy: () => writes ? 'new' : 'old', persistIntent: () => ({ sha256: receipt }),
    mutate: () => { assert.equal(assertBrokerPolicyPredecessorOwnership(historical, client.read(), transition), true); writes++; },
    persistReceipt: () => receipt,
  });
  assert.equal(writes, 1); assert.equal(client.read().status, 'RELEASED');
  assert.deepEqual(historical.identity, historicalOwner);
  assert.throws(() => assertBrokerPolicyPredecessorOwnership(historical, client.read(), transition));
});
