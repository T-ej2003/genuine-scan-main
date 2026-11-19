const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const path = require('node:path');
const dist = path.resolve(__dirname, '../dist');
const mock = (name, exports) => { const filename = require.resolve(path.join(dist, name)); require.cache[filename] = { id: filename, filename, loaded: true, exports }; };

const keys = generateKeyPairSync('ed25519');
const privateKeyPem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const printerId = 'd5e8d13e-4d73-411b-9b3f-6d1800e73609';
const registrationId = '839e55cd-86ea-4523-8544-ff4a62a15158';
const binding = { agentId: 'agent-test', deviceFingerprint: 'device-test', manufacturerId: 'manufacturer-1',
  tenantId: 'tenant-1', printerId, registrationId, sourceVersion: '2026.11.19.1', targetVersion: '2026.11.20.1' };
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

const redisRecords = new Map();
const redis = {
  set: async (key, value, _px, _ttl, _nx) => { if (redisRecords.has(key)) return null; redisRecords.set(key, value); return 'OK'; },
  eval: async (_script, _count, key) => { const value = redisRecords.get(key) || null; redisRecords.delete(key); return value; },
};
let tenantId = binding.tenantId;
mock('rls-waves/session-c/c02/printingLifecycleRepository.js', { readUpgradeDeviceBinding: async ({ printerId: id }) => {
  assert.equal(id, printerId);
  return { ...binding, tenantId, publicKeyPem };
} });
let installationScope = 'certified-upgrade';
mock('services/connectorReleaseService.js', { getConnectorReleaseManifest: () => ({ releases: [{ version: binding.targetVersion,
  productionSignedAvailable: true, platforms: { windows: { installationScope } } }] }) });
mock('services/redisService.js', { getRedisClient: async () => redis });
const controller = require(path.join(dist, 'controllers/connectorUpgradeDeviceProofController'));
const request = (body) => ({ body, params: { id: printerId }, user: { userId: binding.manufacturerId }, databaseSessionCapability: 'fixture-capability', requestId: 'fixture-request' });
const response = () => ({ code: 200, setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });

(async () => {
  const issued = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), issued);
  assert.equal(issued.code, 200);
  const signed = proof.signUpgradeDeviceChallenge(privateKeyPem, issued.body.challenge);
  const accepted = response();
  await controller.verifyConnectorUpgradeProof(request({ attemptId: issued.body.challenge.attemptId, signature: signed }), accepted);
  assert.equal(accepted.code, 200);
  const replay = response();
  await controller.verifyConnectorUpgradeProof(request({ attemptId: issued.body.challenge.attemptId, signature: signed }), replay);
  assert.equal(replay.code, 403);
  const second = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), second);
  const forged = response();
  await controller.verifyConnectorUpgradeProof(request({ attemptId: second.body.challenge.attemptId,
    signature: proof.signUpgradeDeviceChallenge(generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), second.body.challenge) }), forged);
  assert.equal(forged.code, 403);
  const crossManufacturer = response();
  await controller.issueConnectorUpgradeChallenge({ ...request({ targetVersion: binding.targetVersion }), user: { userId: 'other-manufacturer' } }, crossManufacturer);
  assert.equal(crossManufacturer.code, 409);
  installationScope = 'fresh-install-only';
  const uncertified = response();
  await controller.issueConnectorUpgradeChallenge(request({ targetVersion: binding.targetVersion }), uncertified);
  assert.equal(uncertified.code, 409, 'fresh-install-only artifact cannot receive an upgrade challenge');
  console.log('connector upgrade device proof tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
