const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync, randomUUID } = require('node:crypto');
const path = require('node:path');
const dist = path.resolve(__dirname, '../dist');
const mock = (name, exports) => { const filename = require.resolve(path.join(dist, name)); require.cache[filename] = { id: filename, filename, loaded: true, exports }; };

const keys = generateKeyPairSync('ed25519');
const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const printerId = 'd5e8d13e-4d73-411b-9b3f-6d1800e73609';
const registrationId = '839e55cd-86ea-4523-8544-ff4a62a15158';
const binding = { attemptId: randomUUID(), agentId: 'agent-test', deviceFingerprint: 'device-test', manufacturerId: 'manufacturer-1',
  tenantId: 'tenant-1', printerId, registrationId, sourceVersion: '2026.11.19.1',
  currentVersion: '2026.11.19.1', targetVersion: '2026.11.22.1' };
const proof = require(path.join(dist, 'services/connectorUpgradeDeviceProof'));

const challenge = proof.createUpgradeDeviceChallenge(binding, 1000);
const signature = proof.signUpgradeDeviceChallenge(privateKeyPem, challenge);
assert.equal(proof.verifyUpgradeDeviceChallenge({ challenge, signature, publicKeyPem, binding, now: 2000 }).attemptId, challenge.attemptId);
for (const altered of [
  { ...binding, manufacturerId: 'manufacturer-2' },
  { ...binding, deviceFingerprint: 'device-other' },
  { ...binding, targetVersion: '2026.11.21.1' },
  { ...binding, registrationId: 'bb058032-0d67-4b60-8430-c762e4d8bab5' },
]) assert.throws(() => proof.verifyUpgradeDeviceChallenge({ challenge, signature, publicKeyPem, binding: altered, now: 2000 }));
assert.throws(() => proof.verifyUpgradeDeviceChallenge({ challenge, signature, publicKeyPem, binding, now: 121000 }));
assert.throws(() => proof.verifyUpgradeDeviceChallenge({ challenge: { ...challenge, attemptId: 'bb058032-0d67-4b60-8430-c762e4d8bab5' }, signature, publicKeyPem, binding, now: 2000 }));
assert.throws(() => proof.verifyUpgradeDeviceChallenge({ challenge, signature, publicKeyPem: generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString(), binding, now: 2000 }));

const currentChallenge = proof.createUpgradeDeviceChallenge(binding);
const entries = Array.from({ length: 10_000 }, (_, index) => ({
  name: `${index.toString(16).padStart(64, '0')}.gateway-attempt.json`, sha256: 'a'.repeat(64),
  printJobId: `job-${String(index).padStart(176, '0')}`, printItemId: `item-${String(index).padStart(175, '0')}`,
  attemptId: `attempt-${String(index).padStart(172, '0')}`, state: 'PRE_DISPATCH_REPORTED',
}));
entries[0].gatewayId = 'gateway-fixture';
const checkpoint = proof.signMaintenanceCheckpoint(privateKeyPem, {
  purpose: 'mscqr-connector-maintenance-checkpoint-v1', challenge: currentChallenge,
  observedAt: new Date().toISOString(),
  fence: { fenced: true, active: 0, idle: true, socketClosed: true },
  journal: { count: entries.length, entries,
    sha256: createHash('sha256').update(JSON.stringify(entries.map(({ name, sha256 }) => [name, sha256]))).digest('hex') },
  physicalOutcomes: 'UNVERIFIED',
});
assert(checkpoint.statement.length > 900_000 && checkpoint.statement.length <= proof.MAX_MAINTENANCE_CHECKPOINT_CHARS);
assert.equal(proof.verifyMaintenanceCheckpoint(checkpoint, currentChallenge, publicKeyPem).journal.count, 10_000);
assert.throws(() => proof.verifyMaintenanceCheckpoint({ ...checkpoint,
  statement: checkpoint.statement.padEnd(proof.MAX_MAINTENANCE_CHECKPOINT_CHARS + 1) }, currentChallenge, publicKeyPem));

const redisRecords = new Map();
const redis = {
  set: async (key, value, _px, _ttl, nx) => { if (nx === 'NX' && redisRecords.has(key)) return null; redisRecords.set(key, value); return 'OK'; },
  get: async key => redisRecords.get(key) || null,
  eval: async (_script, _count, key) => { const value = redisRecords.get(key) || null; redisRecords.delete(key); return value; },
};
let tenantId = binding.tenantId;
let activeVersion = binding.sourceVersion;
mock('rls-waves/session-c/c02/printingLifecycleRepository.js', { administerPrintingPrinter: async () => ({state:'DISPATCH_FENCED',requestId:'fence-1'}), readUpgradeDeviceBinding: async ({ printerId: id }) => {
  assert.equal(id, printerId);
  return { ...binding, tenantId, sourceVersion: activeVersion, publicKeyPem, historicalSession: false };
} });
let installationScope = 'certified-upgrade';
let publishedFreshOnly = false;
let candidateAvailable = true;
let candidateProvenance = null;
mock('services/connectorReleaseService.js', { getConnectorReleaseManifest: () => ({ releases: [{ version: binding.targetVersion,
  publishedAt: installationScope === 'certified-upgrade' || publishedFreshOnly ? '2026-11-22T00:00:00.000Z' : null,
  productionSignedAvailable: installationScope === 'certified-upgrade' || publishedFreshOnly,
  platforms: { windows: installationScope === 'certified-upgrade' || publishedFreshOnly ? { installationScope } : null },
  certification: candidateAvailable ? candidateProvenance : null }] }) });
mock('services/redisService.js', { getRedisClient: async () => redis });
const controller = require(path.join(dist, 'controllers/connectorUpgradeDeviceProofController'));
const request = (body) => ({ body, params: { id: printerId }, user: { userId: binding.manufacturerId }, databaseSessionCapability: 'fixture-capability', requestId: 'fixture-request' });
const response = () => ({ code: 200, setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });

(async () => {
  const issued = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), issued);
  assert.equal(issued.code, 200);
  const signed = proof.signUpgradeDeviceChallenge(privateKeyPem, issued.body.data.challenge);
  const accepted = response();
  await controller.verifyConnectorUpgradeProof(request({ challengeId: issued.body.data.challenge.challengeId, signature: signed }), accepted);
  assert.equal(accepted.code, 200);
  const replay = response();
  await controller.verifyConnectorUpgradeProof(request({ challengeId: issued.body.data.challenge.challengeId, signature: signed }), replay);
  assert.equal(issued.body.data.challenge.attemptId, accepted.body.attemptId);
  redisRecords.set(proof.upgradeAttemptKey(accepted.body.attemptId), JSON.stringify({ ...binding,
    attemptId: undefined, fenceRequestId: 'fence-1', historicalSession: false }));
  const recovery = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion,
    attemptId: accepted.body.attemptId }), recovery);
  assert.equal(recovery.code, 200);
  assert.equal(recovery.body.data.challenge.attemptId, accepted.body.attemptId);
  assert.notEqual(recovery.body.data.challenge.challengeId, issued.body.data.challenge.challengeId);
  const recovered = response();
  await controller.verifyConnectorUpgradeProof(request({challengeId: recovery.body.data.challenge.challengeId,
    signature: proof.signUpgradeDeviceChallenge(privateKeyPem, recovery.body.data.challenge)}), recovered);
  assert.equal(recovered.code, 200);
  activeVersion = binding.targetVersion;
  const replacedRecovery = response();
  await controller.issueConnectorUpgradeChallenge(request({targetVersion:binding.targetVersion,
    attemptId:accepted.body.attemptId}), replacedRecovery);
  assert.equal(replacedRecovery.code, 200);
  assert.equal(replacedRecovery.body.data.challenge.sourceVersion, binding.sourceVersion);
  assert.equal(replacedRecovery.body.data.challenge.currentVersion, binding.targetVersion);
  activeVersion = binding.sourceVersion;
  assert.equal(replay.code, 403);
  const second = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), second);
  const forged = response();
  await controller.verifyConnectorUpgradeProof(request({ challengeId: second.body.data.challenge.challengeId,
    signature: proof.signUpgradeDeviceChallenge(generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), second.body.data.challenge) }), forged);
  assert.equal(forged.code, 403);
  const crossManufacturer = response();
  await controller.issueConnectorUpgradeChallenge({ ...request({ targetVersion: binding.targetVersion }), user: { userId: 'other-manufacturer' } }, crossManufacturer);
  assert.equal(crossManufacturer.code, 409);
  installationScope = 'fresh-install-only';
  const uncertified = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), uncertified);
  assert.equal(uncertified.code, 409, 'fresh-install-only artifact cannot receive an upgrade challenge');
  const candidateAttemptId = randomUUID();
  const backendSourceSha = '1'.repeat(40), targetSourceSha = '2'.repeat(40);
  process.env.GIT_SHA = backendSourceSha;
  process.env.RELEASE_GIT_SHA = backendSourceSha;
  const permit = { attemptId: candidateAttemptId, agentId: binding.agentId,
    deviceFingerprint: binding.deviceFingerprint, manufacturerId: binding.manufacturerId,
    tenantId: binding.tenantId, printerId, registrationId,
    sourceVersion: binding.sourceVersion, targetVersion: binding.targetVersion,
    sourceRuntimeSha256: 'a'.repeat(64), targetRuntimeSha256: 'b'.repeat(64),
    targetInstallerSha256: 'c'.repeat(64), targetSourceSha, backendSourceSha,
    issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() };
  candidateProvenance = { targetSourceSha, installerSha256: permit.targetInstallerSha256,
    runtimeSha256: permit.targetRuntimeSha256 };
  process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify(permit);
  const preflightBody = { agentId: binding.agentId, deviceFingerprint: binding.deviceFingerprint,
    sourceVersion: binding.sourceVersion, sourceSha256: permit.sourceRuntimeSha256,
    targetVersion: binding.targetVersion, installerSha256: permit.targetInstallerSha256 };
  const preflight = response();
  await controller.preflightConnectorUpgradeCertification(request(preflightBody), preflight);
  assert.equal(preflight.code, 200);
  candidateAvailable = false;
  const missingCandidate = response();
  await controller.preflightConnectorUpgradeCertification(request(preflightBody), missingCandidate);
  assert.equal(missingCandidate.code, 403);
  candidateAvailable = true;
  candidateProvenance = { ...candidateProvenance, targetSourceSha: '3'.repeat(40) };
  const forgedSource = response();
  await controller.preflightConnectorUpgradeCertification(request(preflightBody), forgedSource);
  assert.equal(forgedSource.code, 403);
  candidateProvenance = { targetSourceSha, installerSha256: permit.targetInstallerSha256,
    runtimeSha256: permit.targetRuntimeSha256 };
  publishedFreshOnly = true;
  const published = response();
  await controller.preflightConnectorUpgradeCertification(request(preflightBody), published);
  assert.equal(published.code, 403, 'published fresh-install-only release cannot use certification permit');
  publishedFreshOnly = false;
  const wrongInstaller = response();
  await controller.preflightConnectorUpgradeCertification(request({ ...preflightBody, installerSha256: 'd'.repeat(64) }), wrongInstaller);
  assert.equal(wrongInstaller.code, 403);
  activeVersion = '2026.11.6.2';
  const mismatchedInitial = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), mismatchedInitial);
  assert.equal(mismatchedInitial.code, 409);
  assert.equal(redisRecords.has(proof.upgradeAttemptKey(candidateAttemptId)), false,
    'mismatched trusted source must not reserve the controlled attempt');
  activeVersion = binding.sourceVersion;
  const candidate = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), candidate);
  assert.equal(candidate.code, 200, 'one exact-device certification attempt may start');
  assert.equal(candidate.body.data.challenge.attemptId, candidateAttemptId);
  const candidateProof = proof.signUpgradeDeviceChallenge(privateKeyPem, candidate.body.data.challenge);
  const acceptedCandidate = response();
  await controller.verifyConnectorUpgradeProof(request({ challengeId: candidate.body.data.challenge.challengeId,
    signature: candidateProof }), acceptedCandidate);
  assert.equal(acceptedCandidate.code, 200);
  const replayCandidate = response();
  await controller.verifyConnectorUpgradeProof(request({ challengeId: candidate.body.data.challenge.challengeId,
    signature: candidateProof }), replayCandidate);
  assert.equal(replayCandidate.code, 403);
  redisRecords.set(proof.upgradeAttemptKey(candidateAttemptId), JSON.stringify({
    ...JSON.parse(redisRecords.get(proof.upgradeAttemptKey(candidateAttemptId))), fenceRequestId: 'fence-1',
  }));
  activeVersion = binding.targetVersion;
  const recoveredCandidate = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion,
    attemptId: candidateAttemptId }), recoveredCandidate);
  assert.equal(recoveredCandidate.code, 200, 'explicit fenced recovery retains the original attempt');
  assert.equal(recoveredCandidate.body.data.challenge.attemptId, candidateAttemptId);
  assert.notEqual(recoveredCandidate.body.data.challenge.challengeId, candidate.body.data.challenge.challengeId);
  activeVersion = binding.sourceVersion;
  const secondCandidate = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), secondCandidate);
  assert.equal(secondCandidate.code, 409, 'certification permit cannot create a second attempt');
  const crossDevice = response();
  tenantId = 'other-tenant';
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), crossDevice);
  assert.equal(crossDevice.code, 409);
  tenantId = binding.tenantId;
  process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit,
    expiresAt: new Date(Date.now() - 1).toISOString() });
  const expired = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), expired);
  assert.equal(expired.code, 409);
  delete process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT;
  console.log('connector upgrade device proof tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
