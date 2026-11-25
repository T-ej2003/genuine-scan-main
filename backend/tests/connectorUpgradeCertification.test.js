const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const now = Date.now();
const sourceSha = '1'.repeat(40);
const historicalRelease = JSON.parse(readFileSync(join(__dirname, '../local-print-agent/releases/manifest.json')))
  .releases.find((item) => item.version === '2026.11.22.1');
assert.deepEqual(historicalRelease.certification, {
  targetSourceSha: '4e0a238977266aa4ab820be82e922c4ae8ea9f62',
  installerSha256: '623bb018f8212e4b245feab7b860d1569e7fb172289b6cb6cd30d5693c9cb470',
  runtimeSha256: '24dffef7e8441fce900559e194ccd9bd04686515e7ee29679f04336f8c379f27',
});
const { LOCAL_PRINT_AGENT_SOURCE_VERSION } = require('../dist/local-print-agent/version');
const candidate = { targetSourceSha: '2'.repeat(40), installerSha256: '3'.repeat(64), runtimeSha256: '4'.repeat(64) };
const release = { ...historicalRelease, version: LOCAL_PRINT_AGENT_SOURCE_VERSION, certification: candidate, platforms: {} };
const filename = require.resolve('../dist/services/connectorReleaseService');
require.cache[filename] = { id: filename, filename, loaded: true, exports: {
  getConnectorReleaseManifest: () => ({ releases: [historicalRelease, { ...release, productionSignedAvailable: false }] }),
} };
const { getConnectorUpgradeCertificationPermit, matchesConnectorUpgradeCertification } =
  require('../dist/services/connectorUpgradeCertification');
process.env.GIT_SHA = sourceSha;
process.env.RELEASE_GIT_SHA = sourceSha;
const permit = {
  attemptId: randomUUID(), manufacturerId: 'maker', tenantId: 'tenant', agentId: 'agent-test',
  deviceFingerprint: 'device-test', printerId: randomUUID(), registrationId: randomUUID(),
  sourceVersion: '2026.11.6.2', targetVersion: LOCAL_PRINT_AGENT_SOURCE_VERSION,
  sourceRuntimeSha256: 'a'.repeat(64), targetRuntimeSha256: candidate.runtimeSha256,
  targetInstallerSha256: candidate.installerSha256, targetSourceSha: candidate.targetSourceSha,
  backendSourceSha: sourceSha,
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
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit, targetVersion: historicalRelease.version,
  targetSourceSha: historicalRelease.certification.targetSourceSha,
  targetInstallerSha256: historicalRelease.certification.installerSha256,
  targetRuntimeSha256: historicalRelease.certification.runtimeSha256 });
assert.equal(matchesConnectorUpgradeCertification({ ...binding, targetVersion: historicalRelease.version }, now, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify(permit);
process.env.RELEASE_GIT_SHA = '3'.repeat(40);
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
process.env.RELEASE_GIT_SHA = sourceSha;
release.publishedAt = new Date(now).toISOString();
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
release.publishedAt = null;
release.platforms = { windows: {} };
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
release.platforms = {};
for (const [key, value] of Object.entries({ manufacturerId: 'other', agentId: 'other',
  deviceFingerprint: 'other-device', printerId: randomUUID(), registrationId: randomUUID(),
  targetVersion: '2026.11.23.1', sourceSha256: 'd'.repeat(64),
  targetSha256: 'e'.repeat(64), installerSha256: 'f'.repeat(64) })) {
  assert.equal(matchesConnectorUpgradeCertification({ ...binding, [key]: value }, now, true), false, key);
}
assert.equal(matchesConnectorUpgradeCertification(binding, now + 60_001, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit, targetSourceSha: '5'.repeat(40) });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit, backendSourceSha: permit.targetSourceSha });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit, targetRuntimeSha256: 'b'.repeat(64) });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit, targetInstallerSha256: 'c'.repeat(64) });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT = JSON.stringify({ ...permit,
  expiresAt: new Date(now + 5 * 60 * 60_000).toISOString() });
assert.equal(matchesConnectorUpgradeCertification(binding, now, true), false);
delete process.env.CONNECTOR_UPGRADE_CERTIFICATION_PERMIT;
console.log('connector upgrade certification permit tests passed');
