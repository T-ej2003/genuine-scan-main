import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { authenticateSuccessorStateHistory, deriveSuccessorOutputTransition, reconcileReviewedLifecycleMetadata, reviewedPublicationLifecycleFor } from '../aws/stage-b-successor-cutover-contract.mjs';
import { brokerDigest } from '../aws/stage-b-staged-broker-contract.mjs';
import { STAGE_B } from '../aws/production-green-stage-b-contract.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const source = 'a'.repeat(40), oldCode = Buffer.from('1'.repeat(64), 'hex').toString('base64');
const packageSha256 = '2'.repeat(64), codeSha256 = Buffer.from(packageSha256, 'hex').toString('base64');
const digest = '3'.repeat(64), image = kind => `example.invalid/${kind}@sha256:${digest}`;
const aliasArn = STAGE_B.brokerFunctionArn;
const variables = { BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ releaseSha: source }) };
const resource = (version, code, fields = {}) => ({ mode: 'managed', type: 'aws_lambda_function', name: 'broker', instances: [{
  attributes: { version, code_sha256: code, source_code_hash: code, qualified_arn: `${aliasArn}:${version}`,
    environment: [{ variables: version === '13' ? structuredClone(variables) : { BROKER_APPROVAL_EXPECTED_JSON: '{}' } }], ...fields },
}] });
const check = (status, objects) => ({ object_kind: 'resource', config_addr: 'aws_lambda_function.broker', status, objects });
const state = (serial, version, code, fields) => ({ lineage: '4e438e59-8b8b-194d-030c-5ede0c26344a', serial,
  outputs: { bound_images: { value: { backend: 'old' }, type: ['object', { backend: 'string' }] } },
  check_results: [check(version === '12' ? 'unknown' : 'pass', version === '12' ? null : [{ object_addr: 'aws_lambda_function.broker', status: 'pass' }])],
  resources: [resource(version, code, fields), { mode: 'managed', type: 'aws_iam_policy', name: 'broker', instances: [{ attributes: { id: 'policy' } }] }],
});
const fixture = () => {
  const before = state(120, '12', oldCode), after = state(121, '13', codeSha256, { source_code_hash: codeSha256 });
  const historicalBytes = Buffer.from(JSON.stringify(before)), currentBytes = Buffer.from(JSON.stringify(after));
  const publicationPreparation = { state: { lineage: before.lineage, serial: before.serial, stateSha256: sha(historicalBytes) },
    alias: { FunctionVersion: '12' }, packageSha256, configuration: structuredClone(variables) };
  const publicationResult = { target: { version: '13', versionArn: `${aliasArn}:13`, codeSha256,
    configuration: { Environment: { Variables: { BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ releaseSha: source,
      sourceContractSha256: digest, migrationSetDigest: digest, packageChecksumSha256: digest }),
      BROKER_IMAGE_RELEASE_SHA: '4'.repeat(40), BROKER_IMAGES_JSON: JSON.stringify({ backendImageDigest: image('backend'),
        workerImageDigest: image('worker'), executorImageDigest: image('executor'), canaryImageDigest: image('canary') }) } } } } };
  const currentIdentity = { lineage: after.lineage, serial: after.serial, stateSha256: sha(currentBytes) };
  return { before, after, historicalBytes, currentBytes, publicationPreparation, publicationResult, currentIdentity };
};
const checkHistory = f => authenticateSuccessorStateHistory(f);

test('v14 lifecycle allowance requires the exact historical state, live state, and publication receipt', () => {
  const historical = 'f57ed870a744639d4a51744d614fcf57db17c37c03ffdf43f847d8046fc93daa';
  const current = '7a26d89ef35427227eb76f31c0a581974a3bc71e4a0b52c668193cc4392cc8ce';
  const publication = 'e71190e02451ccd687b449104eca344eba69282c0b841cdf2d291bafcb0940dc';
  const reviewed = reviewedPublicationLifecycleFor(historical, current, publication);
  assert.equal(reviewed?.removedInstancesSha256, '4be4950798e3ec041f9a312563f3d46e05728fdd9f611148526df9f7780c04ec');
  for (const field of ['historical', 'current', 'publication']) {
    const identity = { historical, current, publication }; identity[field] = '0'.repeat(64);
    assert.equal(reviewedPublicationLifecycleFor(identity.historical, identity.current, identity.publication), null);
  }
  assert.equal(reviewedPublicationLifecycleFor(
    '747d0e50cf0a4ace40bce60bd75e997be9631539fd38af0381afe043c49da3d4',
    'fd34c9d740a9d1335d2b54bc892fc99b210f793bd7379cf9cd7681b382d20c96',
    'dfd1382bc16d3c786b64b1f7a7c0465d860c13cf9b4301309e409a95e655ff5b')?.removedInstancesSha256,
  reviewed.removedInstancesSha256);
});

test('v15 publication lifecycle is bound to exact serial-128/129 states and immutable publication receipt', () => {
  const identity = {
    historical: 'bd7bc7c3aa78515a34c79713ba49d176056f3c9efb52c5e633d825bea1123e0d',
    current: 'ed3ee15901c57e3245f5e1309ffc910d758ca7dd77a5858fd0a4fb46cb60af5c',
    publication: '0f8b8fffb7626bb9350ea5677aed2d8f6a6c29fb714771cfcccaf3e1c71f59a9',
  };
  const reviewed = value => reviewedPublicationLifecycleFor(value.historical, value.current, value.publication);
  assert.equal(reviewed(identity)?.removedInstancesSha256,
    '4be4950798e3ec041f9a312563f3d46e05728fdd9f611148526df9f7780c04ec');
  for (const field of Object.keys(identity)) {
    const changed = { ...identity, [field]: '0'.repeat(64) };
    assert.equal(reviewed(changed), null);
  }
});

test('v18 publication lifecycle requires exact serial-136/137 states and immutable receipt', () => {
  const identity = {
    historical: '64a84a25dcfc7a11cc0396fec48bfc5b9e70e778520a4906a0b4921c959f7825',
    current: '45816ae26583b6d2b2ae7e0eea01918d7d90e3bbfa76165185889be76c41a08a',
    publication: 'b79b8165efca63ac53415df99597432a234c270524deecf5d65c78a08e9628b8',
  };
  const reviewed = value => reviewedPublicationLifecycleFor(value.historical, value.current, value.publication);
  assert.equal(reviewed(identity)?.removedInstancesSha256,
    '4be4950798e3ec041f9a312563f3d46e05728fdd9f611148526df9f7780c04ec');
  for (const field of Object.keys(identity)) {
    const changed = { ...identity, [field]: '0'.repeat(64) };
    assert.equal(reviewed(changed), null);
  }
});

test('publication may clear only historical propagated lifecycle metadata on unchanged dependencies', () => {
  const f = fixture();
  f.before.resources[1].instances[0].create_before_destroy = true;
  f.historicalBytes = Buffer.from(JSON.stringify(f.before));
  f.publicationPreparation.state.stateSha256 = sha(f.historicalBytes);
  assert.throws(() => checkHistory(f), /Terraform state changed outside/);
  const reviewedAddressSha256 = brokerDigest(['aws_iam_policy.broker']);
  const prior = structuredClone(f.before), next = structuredClone(f.after);
  reconcileReviewedLifecycleMetadata(prior, next, f.after, reviewedAddressSha256);
  assert.equal(Object.hasOwn(prior.resources[1].instances[0], 'create_before_destroy'), false);
  for (const change of [
    x => { x.after.resources[1].instances[0].create_before_destroy = false; },
    x => { x.before.resources[1].instances[0].index_key = 'other'; },
    x => { x.after.resources[1].instances = []; },
  ]) {
    const altered = structuredClone(f);
    altered.historicalBytes = Buffer.from(f.historicalBytes);
    change(altered);
    assert.throws(() => reconcileReviewedLifecycleMetadata(altered.before, altered.after, altered.after, reviewedAddressSha256));
  }
  assert.throws(() => reconcileReviewedLifecycleMetadata(structuredClone(f.before), structuredClone(f.after), f.after, '0'.repeat(64)));
  const brokerLifecycle = fixture();
  brokerLifecycle.before.resources[0].instances[0].create_before_destroy = true;
  assert.throws(() => reconcileReviewedLifecycleMetadata(brokerLifecycle.before, brokerLifecycle.after, brokerLifecycle.after, reviewedAddressSha256));
});
const mutate = (f, target, fn) => { fn(f[target]); f[`${target === 'before' ? 'historical' : 'current'}Bytes`] = Buffer.from(JSON.stringify(f[target]));
  if (target === 'after') f.currentIdentity.stateSha256 = sha(f.currentBytes); };

test('exact receipt-bound publication state transition is accepted', () => {
  const f = fixture(); const result = checkHistory(f);
  assert.equal(result.historicalSerial, 120); assert.equal(result.currentSerial, 121);
  mutate(f, 'after', x => { x.resources[1].instances[0].create_before_destroy = false; });
  assert.equal(checkHistory(f).currentSerial, 121);
});

test('state history rejects changed receipts, lineage, outputs, and unrelated resources', () => {
  for (const change of [
    f => { f.publicationPreparation.state.stateSha256 = '0'.repeat(64); },
    f => mutate(f, 'after', x => { x.lineage = '00000000-0000-0000-0000-000000000000'; }),
    f => mutate(f, 'after', x => { x.outputs.bound_images.value.backend = 'other'; }),
    f => mutate(f, 'after', x => { x.resources[1].instances[0].attributes.id = 'other'; }),
    f => mutate(f, 'after', x => { x.resources[1].instances[0].create_before_destroy = true; }),
    f => mutate(f, 'after', x => { x.resources[0].instances[0].create_before_destroy = true; }),
    f => mutate(f, 'after', x => { x.resources[0].instances[0].attributes.version = '14'; }),
    f => mutate(f, 'after', x => { x.resources[0].instances[0].attributes.code_sha256 = oldCode; }),
    f => mutate(f, 'after', x => { x.resources[0].instances[0].attributes.source_code_hash = oldCode; }),
    f => mutate(f, 'after', x => { x.resources[0].instances[0].attributes.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON = '{}'; }),
    f => mutate(f, 'after', x => { x.resources[0].instances[0].attributes.role = 'different'; }),
    f => mutate(f, 'after', x => { x.check_results[0].status = 'fail'; }),
  ]) { const f = fixture(); change(f); assert.throws(() => checkHistory(f)); }
});

test('successor output derives only from current state and the bound published images', () => {
  const f = fixture(), history = checkHistory(f);
  const images = Object.fromEntries([['backend','backend_image'],['worker','worker_image'],['executor','executor_image'],
    ['canary','canary_image'],['readOnlyCanary','read_only_canary_image']].map(([key,terraformVariable]) =>
    [key,{terraformVariable,imageReference:image(key === 'readOnlyCanary' ? 'canary' : key)}]));
  const report = { toolingSha: source, toolingTreeSha256: '5'.repeat(64), stateLineage: history.lineage,
    stateSerial: history.currentSerial, stateBackupSha256: history.currentStateSha256,
    brokerPackageRawSha256: packageSha256, sourceContractSha256: digest, migrationSetDigest: digest,
    packageChecksumSha256: digest, imageReleaseSha: '4'.repeat(40), images };
  f.publicationPreparation.sourceSha = source; f.publicationPreparation.treeSha256 = report.toolingTreeSha256;
  const args = { stateHistory: history, bindingReport: report, publicationPreparation: f.publicationPreparation,
    publicationResult: f.publicationResult };
  assert.deepEqual(deriveSuccessorOutputTransition(args).map(x => x.name), ['bound_images']);
  const unchanged = structuredClone(args);
  unchanged.stateHistory.boundImagesBefore = deriveSuccessorOutputTransition(args)[0].after;
  assert.deepEqual(deriveSuccessorOutputTransition(unchanged), []);
  for (const change of [
    value => { value.bindingReport.sourceContractSha256 = '0'.repeat(64); },
    value => { value.bindingReport.stateBackupSha256 = '0'.repeat(64); },
    value => { value.bindingReport.images.canary.imageReference = image('other'); },
    value => { value.publicationResult.target.configuration.Environment.Variables.BROKER_IMAGES_JSON = '{}'; },
    value => { value.publicationPreparation.sourceSha = 'b'.repeat(40); },
  ]) { const copy = structuredClone(args); change(copy); assert.throws(() => deriveSuccessorOutputTransition(copy)); }
});
