const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { isCertifiedUpgradeSource, getConnectorReleaseManifest } = require('../dist/services/connectorReleaseService');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-offline-policy-'));
const previous = process.cwd();
const target = '2026.11.19.1';
const source = '2026.11.6.2';
const digest = 'a'.repeat(64);
try {
  const releases = path.join(root, 'local-print-agent', 'releases');
  fs.mkdirSync(releases, { recursive: true });
  fs.writeFileSync(path.join(releases, 'installer.exe'), 'signed fixture');
  const windows = { label: 'Windows installer', installationScope: 'certified-upgrade',
    certifiedUpgradeSources: [{ version: source, runtimeSha256: digest }],
    installerKind: 'exe', trustLevel: 'production', signatureStatus: 'signed',
    filename: 'installer.exe', relativePath: 'installer.exe', contentType: 'application/octet-stream',
    architecture: 'x64', bytes: 14, sha256: 'b'.repeat(64) };
  const write = () => fs.writeFileSync(path.join(releases, 'manifest.json'), JSON.stringify({
    productName: 'MSCQR Connector', latestVersion: target,
    releases: [{ version: target, publishedAt: new Date().toISOString(), summary: 'Certified fixture release',
      platforms: { windows } }],
  }));
  process.chdir(root);
  write();
  assert.equal(isCertifiedUpgradeSource(target, source, digest), true);
  assert.equal(isCertifiedUpgradeSource(target, source, 'c'.repeat(64)), false, 'modified source');
  assert.equal(isCertifiedUpgradeSource(target, '2026.10.29.1', digest), false, 'unsupported version');
  assert.deepEqual(getConnectorReleaseManifest().releases[0].platforms.windows.certifiedUpgradeSources,
    windows.certifiedUpgradeSources, 'authenticated backend release metadata exposes the same policy');
  windows.certifiedUpgradeSources.push({ version: '2026.11.9.1', runtimeSha256: 'd'.repeat(64) });
  write();
  let refreshed = new Date(Date.now() + 2000);
  fs.utimesSync(path.join(releases, 'manifest.json'), refreshed, refreshed);
  assert.equal(isCertifiedUpgradeSource(target, '2026.11.9.1', 'd'.repeat(64)), true,
    'a future certified source needs metadata, not installer code');
  windows.installationScope = 'fresh-install-only';
  write();
  const manifestPath = path.join(releases, 'manifest.json');
  refreshed = new Date(Date.now() + 4000);
  fs.utimesSync(manifestPath, refreshed, refreshed);
  assert.equal(isCertifiedUpgradeSource(target, source, digest), false, 'fresh-only release');
} finally {
  process.chdir(previous);
  fs.rmSync(root, { recursive: true, force: true });
}
console.log('Certified offline source policy checks passed.');
