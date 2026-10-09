import assert from 'node:assert/strict';
import test from 'node:test';
import { rig, ready, authorization, cutoverPlan, sourceSha } from './fixtures/staged-broker-runtime.mjs';
import { prepareBrokerCutover, executeBrokerAliasCas, reconcileBrokerAlias } from '../aws/stage-b-staged-broker.mjs';
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
