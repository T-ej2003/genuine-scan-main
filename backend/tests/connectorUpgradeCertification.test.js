const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { getConnectorUpgradeCertificationPermit, matchesConnectorUpgradeCertification } =
  require('../dist/services/connectorUpgradeCertification');

const now = Date.now();
const sourceSha = '1'.repeat(40);
process.env.GIT_SHA = sourceSha;
process.env.RELEASE_GIT_SHA = sourceSha;
const permit = {
  attemptId: randomUUID(), manufacturerId: 'maker', tenantId: 'tenant', agentId: 'agent-test',
  deviceFingerprint: 'device-test', printerId: randomUUID(), registrationId: randomUUID(),
  sourceVersion: '2026.11.6.2', targetVersion: '2026.11.22.1',
  sourceRuntimeSha256: 'a'.repeat(64), targetRuntimeSha256: 'b'.repeat(64),
  targetInstallerSha256: 'c'.repeat(64), targetSourceSha: sourceSha,
  issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(),
};
const binding = { attemptId: permit.attemptId, manufacturerId: permit.manufacturerId,
  tenantId: permit.tenantId, agentId: permit.agentId, deviceFingerprint: permit.deviceFingerprint,
  printerId: permit.printerId, registrationId: permit.registrationId,
  sourceVersion: permit.sourceVersion, targetVersion: permit.targetVersion,
  sourceSha256: permit.sourceRuntimeSha256, targetSha256: permit.targetRuntimeSha256,
  installerSha256: permit.targetInstallerSha256 };
assert.equal(getConnectorUpgradeCertificationPermit(now), null);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify(permit);
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), true);
for (const [key, value] of Object.entries({ manufacturerId: 'other', agentId: 'other',
  deviceFingerprint: 'other-device', printerId: randomUUID(), registrationId: randomUUID(),
  targetVersion: '2026.11.23.1', sourceSha256: 'd'.repeat(64),
  targetSha256: 'e'.repeat(64), installerSha256: 'f'.repeat(64) })) {
  assert.equal(matchesConnectorUpgradeCertification({ ...binding, [key]: value }, now, true), false, key);
}
assert.equal(matchesConnectorUpgradeCertification(binding, now + 60_001, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit, targetSourceSha: '2'.repeat(40) });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit,
  expiresAt: new Date(now + 5 * 60 * 60_000).toISOString() });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
delete process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT;
console.log('connector upgrade certification permit tests passed');
