import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { authenticateSuccessorStateHistory, deriveSuccessorOutputTransition } from '../aws/stage-b-successor-cutover-contract.mjs';
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

test('publication may clear only historical propagated lifecycle metadata on unchanged dependencies', () => {
  const f = fixture();
  f.before.resources[1].instances[0].create_before_destroy = true;
  f.historicalBytes = Buffer.from(JSON.stringify(f.before));
  f.publicationPreparation.state.stateSha256 = sha(f.historicalBytes);
  assert.equal(checkHistory(f).currentSerial, 121);
  for (const change of [
    x => { x.after.resources[1].instances[0].create_before_destroy = false; },
    x => { x.after.resources[1].instances[0].attributes.id = 'changed'; },
    x => { x.after.resources[1].instances = []; },
  ]) {
    const altered = structuredClone(f);
    altered.historicalBytes = Buffer.from(f.historicalBytes);
    change(altered);
    altered.currentBytes = Buffer.from(JSON.stringify(altered.after));
    altered.currentIdentity.stateSha256 = sha(altered.currentBytes);
    assert.throws(() => checkHistory(altered));
  }
  const brokerLifecycle = fixture();
  brokerLifecycle.before.resources[0].instances[0].create_before_destroy = true;
  brokerLifecycle.historicalBytes = Buffer.from(JSON.stringify(brokerLifecycle.before));
  brokerLifecycle.publicationPreparation.state.stateSha256 = sha(brokerLifecycle.historicalBytes);
  assert.throws(() => checkHistory(brokerLifecycle));
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
