import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson } from './production-green-stage-b-contract.mjs';
import { BROKER_FUNCTION, brokerDigest } from './stage-b-staged-broker-contract.mjs';
import { stageBBoundImagesFromBindingReport } from './generate-production-green-stage-b-tfvars.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const equal = (actual, expected, message) => assert.ok(canonicalJson(actual) === canonicalJson(expected), message);

function brokerInstance(state) {
  const resources = (state.resources || []).filter(r => r.mode === 'managed' && r.type === 'aws_lambda_function' && r.name === 'broker' && !r.module);
  assert.equal(resources.length, 1, 'State requires one managed broker function');
  assert.equal(resources[0].instances?.length, 1, 'State requires one current broker instance');
  return resources[0].instances[0].attributes;
}

function normalizeRepresentation(state) {
  const copy = structuredClone(state);
  delete copy.serial;
  if (copy.check_results) {
    const key = item => canonicalJson([item.object_kind, item.config_addr]);
    assert.equal(new Set(copy.check_results.map(key)).size, copy.check_results.length, 'Duplicate Terraform check result');
    copy.check_results.sort((a, b) => key(a).localeCompare(key(b)));
  }
  for (const resource of copy.resources || []) {
    for (const instance of resource.instances || []) if (instance.create_before_destroy === false) delete instance.create_before_destroy;
  }
  return copy;
}

export function authenticateSuccessorStateHistory({ historicalBytes, currentBytes, publicationPreparation, publicationResult, currentIdentity }) {
  assert.ok(Buffer.isBuffer(historicalBytes) && Buffer.isBuffer(currentBytes), 'Exact Terraform state bytes are required');
  assert.equal(sha256(historicalBytes), publicationPreparation.state.stateSha256, 'Historical state differs from signed publication predecessor');
  assert.equal(sha256(currentBytes), currentIdentity.stateSha256, 'Current state differs from live backend readback');
  const historical = JSON.parse(historicalBytes), current = JSON.parse(currentBytes);
  assert.equal(historical.lineage, publicationPreparation.state.lineage);
  assert.equal(historical.serial, publicationPreparation.state.serial);
  assert.equal(current.lineage, historical.lineage, 'Terraform lineage changed');
  assert.ok(Number.isSafeInteger(current.serial) && current.serial > historical.serial, 'Terraform did not advance after publication');
  assert.equal(current.serial, currentIdentity.serial);
  equal(historical.outputs, current.outputs, 'Terraform outputs changed outside the successor preparation');
  const before = brokerInstance(historical), after = brokerInstance(current);
  assert.equal(before.version, publicationPreparation.alias.FunctionVersion, 'Historical broker version differs from reviewed alias predecessor');
  assert.equal(after.version, publicationResult.target.version, 'Current Terraform broker version differs from published target');
  assert.equal(after.code_sha256, publicationResult.target.codeSha256, 'Current Terraform broker code differs from published target');
  assert.equal(after.source_code_hash, Buffer.from(publicationPreparation.packageSha256, 'hex').toString('base64'), 'Current Terraform package differs from publication');
  equal(after.environment?.[0]?.variables, publicationPreparation.configuration, 'Current Terraform broker configuration differs from publication');
  assert.equal(after.qualified_arn, publicationResult.target.versionArn, 'Current Terraform broker ARN differs from publication');
  const allowedBrokerFields = new Set(['version', 'code_sha256', 'source_code_hash', 'source_code_size', 'environment', 'filename', 'last_modified', 'qualified_arn', 'qualified_invoke_arn']);
  const normalizedBefore = normalizeRepresentation(historical), normalizedAfter = normalizeRepresentation(current);
  const oldAttributes = brokerInstance(normalizedBefore), newAttributes = brokerInstance(normalizedAfter);
  for (const field of allowedBrokerFields) { delete oldAttributes[field]; delete newAttributes[field]; }
  const brokerCheck = state => (state.check_results || []).find(item => item.object_kind === 'resource' && item.config_addr === BROKER_FUNCTION);
  const beforeCheck = brokerCheck(normalizedBefore), afterCheck = brokerCheck(normalizedAfter);
  assert.deepEqual({ status: beforeCheck?.status, objects: beforeCheck?.objects }, { status: 'unknown', objects: null });
  assert.deepEqual({ status: afterCheck?.status, objects: afterCheck?.objects },
    { status: 'pass', objects: [{ object_addr: BROKER_FUNCTION, status: 'pass' }] });
  const beforeIndex = normalizedBefore.check_results.indexOf(beforeCheck), afterIndex = normalizedAfter.check_results.indexOf(afterCheck);
  assert.equal(beforeIndex, afterIndex, 'Broker check-result identity moved');
  normalizedBefore.check_results.splice(beforeIndex, 1); normalizedAfter.check_results.splice(afterIndex, 1);
  equal(normalizedAfter, normalizedBefore, 'Terraform state changed outside the authenticated broker publication');
  assert.ok(current.outputs?.bound_images && historical.outputs?.bound_images, 'Missing bound image output');
  return Object.freeze({ historicalStateSha256: sha256(historicalBytes), currentStateSha256: sha256(currentBytes),
    historicalSerial: historical.serial, currentSerial: current.serial, lineage: current.lineage,
    boundImagesBefore: structuredClone(current.outputs.bound_images.value), publicationResultSha256: brokerDigest(publicationResult) });
}

export function deriveSuccessorOutputTransition({ stateHistory, bindingReport, publicationPreparation, publicationResult }) {
  assert.equal(bindingReport.toolingSha, publicationPreparation.sourceSha, 'Successor tfvars changed original release source');
  assert.equal(bindingReport.toolingTreeSha256, publicationPreparation.treeSha256, 'Successor tfvars changed original release contracts');
  assert.equal(bindingReport.stateLineage, stateHistory.lineage);
  assert.equal(bindingReport.stateSerial, stateHistory.currentSerial);
  assert.equal(bindingReport.stateBackupSha256, stateHistory.currentStateSha256);
  assert.equal(bindingReport.brokerPackageRawSha256, publicationPreparation.packageSha256);
  const configuration = publicationResult.target.configuration.Environment.Variables;
  const expected = JSON.parse(configuration.BROKER_APPROVAL_EXPECTED_JSON);
  assert.equal(expected.releaseSha, publicationPreparation.sourceSha);
  for (const name of ['sourceContractSha256', 'migrationSetDigest', 'packageChecksumSha256'])
    assert.equal(bindingReport[name], expected[name], `Successor ${name} differs from published broker`);
  assert.equal(bindingReport.imageReleaseSha, configuration.BROKER_IMAGE_RELEASE_SHA);
  const after = stageBBoundImagesFromBindingReport(bindingReport);
  const brokerImages = JSON.parse(configuration.BROKER_IMAGES_JSON);
  for (const [name, field] of Object.entries({ backend: 'backendImageDigest', worker: 'workerImageDigest',
    executor: 'executorImageDigest', canary: 'canaryImageDigest' }))
    assert.equal(after[name], brokerImages[field], `Successor ${name} image differs from published broker`);
  assert.equal(after.read_only_canary, after.canary, 'Read-only canary image differs from authenticated canary image');
  return canonicalJson(stateHistory.boundImagesBefore) === canonicalJson(after) ? []
    : [{ name: 'bound_images', before: stateHistory.boundImagesBefore, after }];
}
