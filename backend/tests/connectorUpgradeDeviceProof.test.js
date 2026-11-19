const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const path = require('node:path');
const dist = path.resolve(__dirname, '../dist');

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
const licenseeBinding = { ...binding, tenantId: null };
const licenseeChallenge = proof.createUpgradeDeviceChallenge(licenseeBinding, 1000);
const licenseeSignature = proof.signUpgradeDeviceChallenge(privateKeyPem, licenseeChallenge);
assert.equal(proof.verifyUpgradeDeviceChallenge({ challenge: licenseeChallenge, signature: licenseeSignature, publicKeyPem, binding: licenseeBinding, now: 2000 }).attemptId, licenseeChallenge.attemptId);

console.log('connector upgrade device proof tests passed');
