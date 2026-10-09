import assert from 'node:assert/strict';
import test from 'node:test';
import { runProductionPreflightCli } from '../aws/run-production-green-stage-b-preflight.mjs';
import { ready, sourceSha, now, configuration, authorization as signFixture } from './fixtures/staged-broker-runtime.mjs';
import { executeBrokerAliasCas, reconcileBrokerAlias, authenticateBrokerRecoveryApproval, isAuthenticatedBrokerRecoveryApproval } from '../aws/stage-b-staged-broker.mjs';
import { authenticateStagedBrokerClosure, assertStagedBrokerProof, assertStagedBrokerTerminal } from '../aws/stage-b-staged-broker-closure.mjs';
import { brokerDigest, prepareBrokerStateRefresh } from '../aws/stage-b-staged-broker-contract.mjs';
import { createProductionComponentDeploymentState, advanceProductionComponentDeploymentState } from '../aws/production-component-deployment-state.mjs';
import { canonicalSha256 } from '../aws/production-green-stage-b-contract.mjs';
import { commitSecurityComponentState } from '../aws/commit-production-component-security-state.mjs';

async function terminal(separate = false, recoveryTooling) {
  const r = await ready();
  if (recoveryTooling) {
    r.p.recoveryTooling = { ...recoveryTooling, publicationResultSha256: brokerDigest(r.p.publication) };
    r.auth = signFixture(r.p); r.deps.readCheckout = async () => recoveryTooling;
    r.deps.authenticateRecoveryTooling = async (p, checkout) => {
      assert.equal(p.sourceSha, sourceSha); assert.deepEqual(checkout, recoveryTooling);
      assert.equal(p.recoveryTooling.publicationResultSha256, brokerDigest(p.publication));
    };
  }
  const pub = r.entries.find(e => e[1] === 'PUBLISHED')[2];
  // The publication preparation/approval are independently retained by the
  // source reservation, not reconstructed from the cutover approval.
  const { preparation, authorization } = await import('./fixtures/staged-broker-runtime.mjs');
  const publicationPreparation = preparation(), publicationAuthorization = authorization(publicationPreparation);
  const casResult = await executeBrokerAliasCas({ preparation: r.p, authorization: r.auth }, r.deps);
  const closure = separate ? { preparation: prepareBrokerStateRefresh({ preparation: r.p, authorization: r.auth, casResult }) } : null;
  if (closure) closure.authorization = signFixture(closure.preparation);
  const record = await reconcileBrokerAlias({ preparation: closure?.preparation || r.p, authorization: closure?.authorization || r.auth,
    casResult, ...(closure ? { cutoverPreparation: r.p, cutoverAuthorization: r.auth } : {}) }, r.deps);
  const handoff = { preparation: r.p, authorization: r.auth, ...(closure ? { closure } : {}), casResult, record };
  const source = { kind: 'STAGED_BROKER_SOURCE', sourceSha, preparation: publicationPreparation, authorization: publicationAuthorization };
  const deps = { ...r.deps, readSource: async () => source, readReceipt: async (id, status) => {
    if (status === 'STAGED_BROKER_TERMINAL_HANDOFF') return handoff;
    const found = r.entries.find(e => e[0] === id && e[1] === status); assert.ok(found, 'Missing durable receipt'); return found[2];
  }, authenticateState: async (target, alias) => { assert.equal(target.version, alias.FunctionVersion); } };
  assert.equal(brokerDigest(source.authorization), pub.authorizationSha256);
  return { ...r, source, handoff, deps };
}
test('terminal proof authenticates a distinct state-refresh authorization bound to completed cutover', async () => {
  const r = await terminal(true), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  assertStagedBrokerProof(proof, sourceSha);
  assert.notEqual(r.handoff.record.cutoverAuthorizationSha256, r.handoff.record.stateRefreshAuthorizationSha256);
  r.handoff.closure.authorization.preparationSha256 = '0'.repeat(64);
  await assert.rejects(() => authenticateStagedBrokerClosure({ sourceSha, deps: r.deps }));
});
test('verified four-phase closure requires a real component-state CAS readback', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  assertStagedBrokerProof(proof, sourceSha);
  let current = createProductionComponentDeploymentState({ components: { backend: null, frontend: null, database: null, security: null } });
  const client = { read: () => current, advance: (_before, next) => { current = next; } };
  const body = { sourceSha, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const result = await commitSecurityComponentState({ sourceSha, authorization, client, stagedBrokerProof: proof });
  assert.equal(result.stagedBroker.status, 'COMMITTED'); assert.equal(current.generation, 2);
  const priorApplication = { sourceSha: 'c'.repeat(40), establishedThroughSha: 'c'.repeat(40), imageDigest: `sha256:${'b'.repeat(64)}`, taskDefinitionArn: 'arn:aws:ecs:eu-west-2:368992683803:task-definition/example:1', desiredCount: 1 };
  let later = advanceProductionComponentDeploymentState({ current, expectedGeneration: current.generation, lane: 'SECURITY_INFRASTRUCTURE', changes: { backend: priorApplication, frontend: priorApplication }, updatedByWorkflow: 'local-test', githubRunId: 'local-test' });
  for (const component of ['backend', 'frontend']) {
    later = advanceProductionComponentDeploymentState({ current: later, expectedGeneration: later.generation, lane: 'NORMAL_APPLICATION', changes: { [component]: { sourceSha, establishedThroughSha: sourceSha, imageDigest: `sha256:${'c'.repeat(64)}`, taskDefinitionArn: 'arn:aws:ecs:eu-west-2:368992683803:task-definition/example:1', desiredCount: 1 } }, updatedByWorkflow: 'local-test', githubRunId: 'local-test' });
    assert.equal(assertStagedBrokerTerminal(proof, { client: { read: () => later }, result, previousGeneration: 1 }).status, 'COMMITTED');
  }
  for (const mutated of [
    { ...current, generation: 1 },
    { ...current, generation: 3, components: { ...current.components, security: { ...current.components.security, stagedBrokerEvidenceSha256: '0'.repeat(64) } } },
    { ...current, generation: 3, componentProvenance: { ...current.componentProvenance, security: { ...current.componentProvenance.security, generation: 3 } } },
    { ...current, generation: 3, repository: 'untrusted' },
  ]) assert.throws(() => assertStagedBrokerTerminal(proof, { client: { read: () => mutated }, result, previousGeneration: 1 }));
});
test('terminal generation comes from the same authenticated read used by the CAS', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  let current = createProductionComponentDeploymentState({ components: { backend: null, frontend: null, database: null, security: null } });
  let committed = false, baselineReads = 0;
  const client = {
    read: () => {
      if (!committed && ++baselineReads > 1) current = { ...current, generation: current.generation + 1 };
      return current;
    },
    advance: (before, next) => { assert.equal(before.generation, current.generation); current = next; committed = true; },
  };
  const body = { sourceSha, valid: true }, authorization = { ...body, authorizationSha256: canonicalSha256(body) };
  const result = await commitSecurityComponentState({ sourceSha, authorization, client, stagedBrokerProof: proof });
  assert.equal(result.stagedBroker.status, 'COMMITTED'); assert.equal(baselineReads, 1);
  const replay = await commitSecurityComponentState({ sourceSha, authorization, client, stagedBrokerProof: proof });
  assert.equal(replay.alreadyCurrent, true); assert.equal(replay.stagedBroker.generation, result.stagedBroker.generation);
});
test('raw authenticated boolean cannot authorize terminal writer', () => {
  assert.throws(() => commitSecurityComponentState({ sourceSha, stagedBrokerProof: { sourceSha, authenticated: true } }));
});
test('ordinary deployment has no staged source reservation', async () => {
  assert.equal(await authenticateStagedBrokerClosure({ sourceSha, deps: { readSource: async () => null } }), null);
});
for (const [name, mutate] of [
  ['missing terminal handoff', r => r.deps.readReceipt = async () => { throw new Error('Missing receipt'); }],
  ['unsigned authority', r => r.deps.verifyAuthorization = async () => false],
  ['expired publication at execution', r => r.source.authorization.expiresAt = now.toISOString()],
  ['expired cutover at execution', r => r.handoff.authorization.expiresAt = now.toISOString()],
  ['wrong target', r => r.handoff.preparation.target.version = '99'],
  ['missing concrete version ARN', r => delete r.handoff.preparation.target.versionArn],
  ['altered code identity', r => r.handoff.preparation.target.codeSha256 = 'bad'],
  ['publication lineage mismatch', r => r.source.preparation.packageSha256 = '0'.repeat(64)],
  ['omitted aggregate address', r => r.handoff.record.mutationAddresses.pop()],
  ['unreconciled status', r => r.handoff.record.status = 'PUBLISHED'],
  ['stale alias revision', r => r.deps.getAlias = async () => ({ ...r.handoff.casResult.alias, RevisionId: 'concurrent' })],
  ['state substitution', r => r.deps.readStateIdentity = async () => ({ ...r.state(), serial: 999 })],
  ['closure plan mutation', r => r.handoff.record.closurePlan.resource_changes[0].change.actions = ['update']],
  ['runtime changes', r => r.deps.getVersion = async () => ({ ...configuration(), Runtime: 'unknown' })],
  ['IAM drift', r => r.deps.readPrerequisites = async () => ({})],
  ['Terraform desired target differs', r => r.deps.authenticateState = async () => { throw new Error('Newer publication'); }],
]) test(`terminal closure rejects ${name}`, async () => {
  const r = await terminal(); mutate(r);
  await assert.rejects(() => authenticateStagedBrokerClosure({ sourceSha, deps: r.deps }));
});
test('verified proof revalidates before later use', async () => {
  const r = await terminal(), proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  r.deps.getAlias = async () => ({ ...r.handoff.casResult.alias, RevisionId: 'changed' });
  await assert.rejects(() => proof.revalidate());
});

test('terminal closure preserves original release under authenticated descendant tooling', async () => {
  const tooling = { sourceSha: 'd'.repeat(40), treeSha256: 'e'.repeat(64) };
  const r = await terminal(true, tooling);
  const proof = await authenticateStagedBrokerClosure({ sourceSha, deps: r.deps });
  assertStagedBrokerProof(proof, sourceSha);
  assert.equal(r.handoff.record.sourceSha, sourceSha);
  assert.equal(r.handoff.preparation.publication.sourceSha, sourceSha);
  assert.equal(r.calls.filter(c => typeof c === 'object').length, 1);
  r.deps.authenticateRecoveryTooling = async () => { throw new Error('Unrelated tooling'); };
  await assert.rejects(() => proof.revalidate(), /Unrelated/);
});

test('approval recovery authenticates the native terminal handoff without rewriting publication identity', async () => {
  const tooling = { sourceSha: 'd'.repeat(40), treeSha256: 'e'.repeat(64) };
  const r = await terminal(true, tooling);
  r.deps.authenticateReconciliation = async (record, id) => assert.ok(r.entries.some(e => e[0] === id && e[1] === record.status && brokerDigest(e[2]) === brokerDigest(record)));
  const input = { ...r.handoff.closure, result: r.handoff.record };
  const context = await authenticateBrokerRecoveryApproval(input, r.deps);
  assert.equal(isAuthenticatedBrokerRecoveryApproval(context), true);
  assert.equal(context.sourceSha, sourceSha); assert.equal(context.tooling.sourceSha, tooling.sourceSha);
  assert.equal(context.target.version, '13');
  assert.equal(r.calls.filter(c => c === 'publish').length, 1);
  assert.equal(isAuthenticatedBrokerRecoveryApproval(structuredClone(context)), false);
  const argv = ['--identity', 'administrator', '--phase', 'initial', '--source-sha', sourceSha, '--output', '/private/tmp/not-written.json',
    '--image-authorization', '/private/tmp/not-read.json', '--image-authorization-sha256', 'a'.repeat(64)];
  const dependencies = { recoveryApproval: context, commandRun: () => { throw new Error('Unexpected external access'); },
    caller: () => 'arn:aws:iam::368992683803:root', validateCapabilityGraph: () => ({}),
    readProtectedMainCheckout: () => ({ toolingSha: tooling.sourceSha, currentHead: tooling.sourceSha, originMainHead: tooling.sourceSha, porcelainStatus: '' }),
    readImageAuthorization: (_path, _hash, release) => { assert.equal(release, sourceSha); throw new Error('Authenticated original-release image boundary'); } };
  assert.throws(() => runProductionPreflightCli(argv, dependencies), /Authenticated original-release image boundary/);
  for (const contradiction of [{ porcelainStatus: ' M file' }, { originMainHead: 'f'.repeat(40) }]) {
    const read = dependencies.readProtectedMainCheckout;
    assert.throws(() => runProductionPreflightCli(argv, { ...dependencies, readProtectedMainCheckout: () => ({ ...read(), ...contradiction }) }), /clean protected-main/);
  }
  assert.throws(() => runProductionPreflightCli(argv, { ...dependencies, recoveryApproval: structuredClone(context) }), /unauthenticated/);
  context.tooling.sourceSha = 'f'.repeat(40);
  assert.equal(isAuthenticatedBrokerRecoveryApproval(context), false);
  const altered = structuredClone(input); altered.result.sourceSha = tooling.sourceSha;
  await assert.rejects(() => authenticateBrokerRecoveryApproval(altered, r.deps));
});
