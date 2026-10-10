import assert from 'node:assert/strict';
import test from 'node:test';
import { rig, ready, authorization, cutoverPlan, sourceSha } from './fixtures/staged-broker-runtime.mjs';
import { prepareBrokerCutover, executeBrokerAliasCas, reconcileBrokerAlias, assertSuccessorCasTime } from '../aws/stage-b-staged-broker.mjs';
import { assertBrokerPreparation, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan, brokerDigest } from '../aws/stage-b-staged-broker-contract.mjs';
import { assertReceiptBoundHistoricalSourceAncestry } from '../aws/stage-b-staged-broker-executor.mjs';

const tooling = { sourceSha: 'd'.repeat(40), treeSha256: '5'.repeat(64) };
function evidence(p) {
  return { sourceSha, publicationResultSha256: brokerDigest(p.publication), targetSha256: brokerDigest(p.target), state: structuredClone(p.state),
    refreshReportPath: '/private/refresh.json', refreshReportSha256: '6'.repeat(64), bindingReportPath: '/private/binding.json', bindingReportSha256: '7'.repeat(64),
    outputChanges: [{ name: 'bound_images', before: { backend: 'old' }, after: { backend: 'authenticated' } }] };
}
const output = e => ({ actions: ['update'], before: e.before, after: e.after, after_unknown: false, before_sensitive: false, after_sensitive: false });

test('same-source publication, descendant cutover, identical reviewed refresh and closure preserve immutable release', async () => {
  const r = await ready(rig()); const original = structuredClone(r.p.publication);
  r.deps.readCheckout = async () => tooling;
  r.deps.authenticateBrokerRecoveryTooling = async (p, result, checkout) => {
    assert.equal(p.sourceSha, sourceSha); assert.deepEqual(result, original);
    assertReceiptBoundHistoricalSourceAncestry({ historicalSourceSha: p.sourceSha, consumerSourceSha: checkout.sourceSha,
      isAncestor: (a, b) => a === sourceSha && b === tooling.sourceSha });
    return { ...checkout, publicationResultSha256: brokerDigest(result) };
  };
  const e = evidence(r.p), plan = cutoverPlan(); plan.output_changes = { bound_images: output(e.outputChanges[0]) };
  r.deps.authenticateOutputReconciliation = async p => assert.deepEqual(p.outputReconciliation, e);
  const p = await prepareBrokerCutover({ publicationPreparation: rig().p,
    publicationAuthorization: rig().auth, publicationResult: original, plan, bytes: Buffer.from('cutover-reviewed'), state: r.state(),
    artifactSetSha256: r.p.artifactSetSha256, outputReconciliation: e }, r.deps);
  assert.equal(p.sourceSha, sourceSha); assert.equal(p.publication.sourceSha, sourceSha); assert.equal(p.target.version, '13');
  assert.deepEqual(p.recoveryTooling, { ...tooling, publicationResultSha256: brokerDigest(original) });
  const auth = authorization(p);
  r.deps.readPlan = async () => ({ plan, bytes: Buffer.from('cutover-reviewed'), artifactSetSha256: p.artifactSetSha256 });
  const refresh = r.deps.captureRefreshOnlyPlan;
  r.deps.captureRefreshOnlyPlan = async () => { const captured = await refresh(); captured.plan.output_changes = structuredClone(plan.output_changes); return captured; };
  const closure = r.deps.captureNormalPlan;
  r.deps.captureNormalPlan = async () => { const captured = await closure(); const after = e.outputChanges[0].after; captured.plan.output_changes = { bound_images: { actions: ['no-op'], before: after, after } }; return captured; };
  const cas = await executeBrokerAliasCas({ preparation: p, authorization: auth }, r.deps);
  const result = await reconcileBrokerAlias({ preparation: p, authorization: auth, casResult: cas }, r.deps);
  assert.equal(result.sourceSha, sourceSha); assert.equal(result.target.version, '13');
  assert.equal(r.calls.filter(c => typeof c === 'object').length, 1); assert.equal(r.calls.filter(c => c === 'publish').length, 1);
  assert.equal(r.calls.filter(c => c === 'refresh-only').length, 1);
});

test('receipt-bound successor cutover uses new evidence without relabeling the published version', async () => {
  const r = await ready(rig());
  r.deps.readCheckout = async () => tooling;
  r.deps.authenticateBrokerRecoveryTooling = async (_old, result, checkout) =>
    ({ ...checkout, publicationResultSha256: brokerDigest(result) });
  const paths = Object.fromEntries(['historicalStatePath', 'currentStatePath', 'bindingReportPath',
    'imageEvidencePath', 'imageSignaturePath'].map(name => [name, `/private/${name}.json`]));
  const transition = { name: 'bound_images', before: { backend: 'old' }, after: { backend: 'authenticated' } };
  const plan = cutoverPlan(); plan.output_changes = { bound_images: output(transition) };
  r.deps.createSuccessorReconciliation = async p => {
    const publicationResultSha256 = brokerDigest(p.publication), historicalStateSha256 = '6'.repeat(64),
      currentStateSha256 = p.state.stateSha256, bindingReportSha256 = '7'.repeat(64);
    return { ...paths, operationId: brokerDigest({ purpose: 'STAGE_B_BROKER_ALIAS_CAS', sourceSha: p.sourceSha,
      recoveryTooling: p.recoveryTooling, publicationResultSha256, historicalStateSha256, currentStateSha256,
      alias: p.alias, target: p.target, bindingReportSha256, imageEvidenceSha256: '8'.repeat(64),
      imageSignatureSha256: '9'.repeat(64), outputChanges: [transition] }), publicationResultSha256, historicalStateSha256,
      currentStateSha256, bindingReportSha256, imageEvidenceSha256: '8'.repeat(64), imageSignatureSha256: '9'.repeat(64),
      outputChanges: [transition], createdAt: '2026-10-04T11:59:00.000Z', expiresAt: '2026-10-04T12:29:00.000Z' };
  };
  r.deps.authenticateSuccessorReconciliation = async p => {
    assert.deepEqual(p.successorReconciliation.outputChanges, [transition]);
    assert.ok(Date.parse(p.successorReconciliation.createdAt) <= r.deps.now().getTime()
      && r.deps.now().getTime() < Date.parse(p.successorReconciliation.expiresAt));
  };
  const p = await prepareBrokerCutover({ publicationPreparation: rig().p, publicationAuthorization: rig().auth,
    publicationResult: r.p.publication, plan, bytes: Buffer.from('successor-cutover'), state: r.state(),
    artifactSetSha256: r.p.artifactSetSha256, successorRecovery: paths }, r.deps);
  assert.equal(p.sourceSha, sourceSha); assert.equal(p.target.version, '13');
  assert.equal(p.recoveryTooling.sourceSha, tooling.sourceSha); assert.equal(p.outputReconciliation, undefined);
  assert.doesNotThrow(() => assertSuccessorCasTime(p, '2026-10-04T12:00:00.000Z'));
  assert.throws(() => assertSuccessorCasTime(p, '2026-10-04T12:30:00.000Z'));
  for (const alter of [
    copy => { delete copy.successorReconciliation; },
    copy => { copy.successorReconciliation.publicationResultSha256 = '0'.repeat(64); },
    copy => { copy.successorReconciliation.operationId = '0'.repeat(64); },
    copy => { copy.successorReconciliation.outputChanges[0].after.backend = 'unapproved'; },
    copy => { copy.successorReconciliation.outputChanges.push({ name: 'other', before: 'a', after: 'b' }); },
    copy => { copy.successorReconciliation.expiresAt = copy.successorReconciliation.createdAt; },
    copy => { copy.successorReconciliation.historicalStateSha256 = '0'.repeat(64); },
  ]) {
    const bad = structuredClone(p); alter(bad);
    assert.throws(() => { assertBrokerPreparation(bad); assertBrokerCutoverPlan(plan, bad); });
  }
  const auth = authorization(p);
  r.deps.readPlan = async () => ({ plan, bytes: Buffer.from('successor-cutover'), artifactSetSha256: p.artifactSetSha256 });
  r.deps.readCheckout = async () => ({ sourceSha: 'f'.repeat(40), treeSha256: tooling.treeSha256 });
  await assert.rejects(() => executeBrokerAliasCas({ preparation: p, authorization: auth }, r.deps));
  assert.equal(r.calls.filter(call => typeof call === 'object').length, 0);
  r.deps.readCheckout = async () => tooling;
  const refresh = r.deps.captureRefreshOnlyPlan;
  r.deps.captureRefreshOnlyPlan = async () => { const captured = await refresh(); captured.plan.output_changes = structuredClone(plan.output_changes); return captured; };
  const closure = r.deps.captureNormalPlan;
  r.deps.captureNormalPlan = async () => { const captured = await closure(); captured.plan.output_changes = {
    bound_images: { actions: ['no-op'], before: transition.after, after: transition.after } }; return captured; };
  const cas = await executeBrokerAliasCas({ preparation: p, authorization: auth }, r.deps);
  const result = await reconcileBrokerAlias({ preparation: p, authorization: auth, casResult: cas }, r.deps);
  assert.equal(result.target.version, '13'); assert.equal(result.sourceSha, sourceSha);
  assert.equal(r.calls.filter(call => typeof call === 'object').length, 1);
  assert.equal(r.calls.filter(call => call === 'publish').length, 1);
});

test('output reconciliation rejects absent, extra, missing, wrong-value and foreign evidence', async () => {
  const r = await ready(); const p = r.p; p.outputReconciliation = evidence(p);
  const plan = cutoverPlan(); plan.output_changes = { bound_images: output(p.outputReconciliation.outputChanges[0]) };
  assertBrokerPreparation(p); assertBrokerCutoverPlan(plan, p);
  for (const alter of [
    (p) => { delete p.outputReconciliation; },
    (_, plan) => { plan.output_changes.unapproved = { actions: ['update'], before: 'a', after: 'b' }; },
    (_, plan) => { delete plan.output_changes.bound_images; },
    (_, plan) => { plan.output_changes.bound_images.before.backend = 'substituted'; },
    (_, plan) => { plan.output_changes.bound_images.after.backend = 'substituted'; },
    (p) => { p.outputReconciliation.sourceSha = tooling.sourceSha; },
    (p) => { p.outputReconciliation.targetSha256 = '8'.repeat(64); },
    (p) => { p.outputReconciliation.state.serial++; },
    (p) => { p.outputReconciliation.publicationResultSha256 = '9'.repeat(64); },
  ]) {
    const copyP = structuredClone(p), copyPlan = structuredClone(plan); alter(copyP, copyPlan);
    assert.throws(() => { assertBrokerPreparation(copyP); assertBrokerCutoverPlan(copyPlan, copyP); });
  }
});

test('canonical ancestry rejects unrelated, sibling, ancestor and unverifiable tooling', () => {
  for (const source of ['b'.repeat(40), 'c'.repeat(40), 'e'.repeat(40)]) assert.throws(() =>
    assertReceiptBoundHistoricalSourceAncestry({ historicalSourceSha: sourceSha, consumerSourceSha: source, isAncestor: () => false }));
  assert.throws(() => assertReceiptBoundHistoricalSourceAncestry({ historicalSourceSha: sourceSha, consumerSourceSha: tooling.sourceSha }));
});

test('post-CAS refresh consumes the same exact reconciliation and closure requires its converged outputs', async () => {
  const r = await ready(), p = r.p; p.outputReconciliation = evidence(p);
  const refresh = (await r.deps.captureRefreshOnlyPlan()).plan;
  refresh.output_changes = { bound_images: output(p.outputReconciliation.outputChanges[0]) };
  const aliasAfter = { ...p.alias, FunctionVersion: p.target.version, RevisionId: 'after' };
  assertBrokerRefreshPlan(refresh, p, aliasAfter);
  for (const mutate of [
    plan => { delete plan.output_changes.bound_images; },
    plan => { plan.output_changes.bound_images.before.backend = 'wrong'; },
    plan => { plan.output_changes.bound_images.after.backend = 'wrong'; },
    plan => { plan.output_changes.other = { actions: ['update'], before: 'old', after: 'new' }; },
  ]) {
    const copy = structuredClone(refresh); mutate(copy);
    assert.throws(() => assertBrokerRefreshPlan(copy, p, aliasAfter));
  }
  const closure = (await r.deps.captureNormalPlan()).plan;
  const after = p.outputReconciliation.outputChanges[0].after;
  closure.output_changes = { bound_images: { actions: ['no-op'], before: after, after } };
  assertBrokerClosurePlan(closure, p);
  for (const mutate of [
    plan => { delete plan.output_changes.bound_images; },
    plan => { plan.output_changes.bound_images.after = { backend: 'wrong' }; },
    plan => { plan.output_changes.bound_images.actions = ['update']; },
  ]) {
    const copy = structuredClone(closure); mutate(copy);
    assert.throws(() => assertBrokerClosurePlan(copy, p));
  }
});
