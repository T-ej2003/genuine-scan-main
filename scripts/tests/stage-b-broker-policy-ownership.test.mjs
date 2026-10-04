import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import { writerSession } from './fixtures/broker-writer-session.mjs';
import { proveBrokerWriterUnusable } from '../aws/stage-b-broker-writer-session.mjs';
import { createBrokerPolicyOwnershipClient, BROKER_POLICY_OWNERSHIP_KEY, executeOwnedBrokerPolicyMutation, recoverOwnedBrokerPolicyMutation } from '../aws/stage-b-broker-policy-ownership.mjs';
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
const operation = { policyArn: STAGE_B_BROKER_POLICY.arn, sourceSha: 'a'.repeat(40), operationIdentity: 'b'.repeat(64), writerSession };
const receipt = 'c'.repeat(64);
test('one fixed key, one winner, no time-based stealing; exact terminal release increments generation', () => {
  const { client, calls } = rig(), owner = client.acquire(operation);
  assert.throws(() => client.acquire({ ...operation, sourceSha: 'd'.repeat(40) }));
  assert.throws(() => client.release(owner));
  assert.throws(() => client.complete({ ...owner, owner: '0'.repeat(36) }, { outcome: 'SUCCEEDED', receiptSha256: receipt }));
  assert.throws(() => client.complete({ ...owner, generation: 2 }, { outcome: 'SUCCEEDED', receiptSha256: receipt }));
  client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt }); client.release(owner);
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
    authenticate: () => { if (failure === 'authentication') throw new Error('invalid/replay'); return { predecessor, successor }; },
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
    reserve: () => { assert.equal(consumed, false); consumed = true; }, authenticate: () => ({ predecessor: 0, successor: 1 }),
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
  const input = { ownership: client, operation, reserve: () => {}, authenticate: async () => { entered = true; await waiting; return { predecessor: 0, successor: 1 }; },
    readPolicy: () => writes, mutate: () => ++writes, persistReceipt: () => receipt };
  const first = executeOwnedBrokerPolicyMutation(input); await Promise.resolve(); assert.equal(entered, true);
  await assert.rejects(() => executeOwnedBrokerPolicyMutation({ ...input, operation: { ...operation, sourceSha: 'e'.repeat(40) } }));
  releaseAuthentication(); await first; assert.equal(writes, 1);
});
test('crash after persisted terminal can recover the original generation without an IAM retry', async () => {
  const { client } = rig(), owner = client.acquire(operation);
  client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt });
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
    authenticate: () => ({ predecessor: ['v1', 'v2'], successor: ['v2'] }), readPolicy: () => versions,
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
  const { client } = rig(), owner = client.acquire(operation); client.complete(owner, { outcome: 'SUCCEEDED', receiptSha256: receipt });
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
    authenticate: () => ({ predecessor: 0, successor: 1 }), readPolicy: () => writes,
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
    authenticate: () => ({ predecessor: 0, successor: 1 }), readPolicy: () => writes, mutate: () => ++writes, persistReceipt: () => receipt };
  const results = await Promise.allSettled([executeOwnedBrokerPolicyMutation(input), executeOwnedBrokerPolicyMutation(input)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1); assert.equal(writes, 1);
  assert.equal(calls.filter(a => a[1] === 'put-item').length, 1); assert.equal(client.read().status, 'RELEASED');
});
test('reserved authority cannot steal held ownership or be silently reused after acquisition failure', async () => {
  const { client } = rig(), held = client.acquire({ ...operation, operationIdentity: 'd'.repeat(64) });
  let reserved = false, writes = 0;
  const input = { ownership: client, operation,
    reserve: () => { assert.equal(reserved, false); reserved = true; },
    authenticate: () => assert.fail('No predecessor read without ownership'), readPolicy: () => 0,
    mutate: () => ++writes, persistReceipt: () => receipt };
  await assert.rejects(() => executeOwnedBrokerPolicyMutation(input), error => error.reservationConsumed === true && error.recoveryRequired === true && error.operationIdentity === operation.operationIdentity);
  assert.equal(reserved, true); assert.deepEqual(client.read().identity, held); assert.equal(writes, 0);
  await assert.rejects(() => executeOwnedBrokerPolicyMutation(input)); assert.deepEqual(client.read().identity, held);
});
