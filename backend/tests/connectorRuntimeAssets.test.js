const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const script = path.join(__dirname, '../scripts/create-connector-runtime-assets.mjs');
const latest = '2026.11.6.2', predecessor = '2026.10.29.1', older = '2026.6.26';
const release = (version, { scope, published = true, signature = 'signed', trust = 'production', packageMissing = false, fileMissing = false } = {}) => ({
  version, publishedAt: published ? '2026-11-06T00:00:00Z' : null, fileMissing,
  platforms: packageMissing ? {} : { windows: {
    signatureStatus: signature, trustLevel: trust, ...(scope ? { installationScope: scope } : {}),
    relativePath: `${version}/windows/${version}.exe`,
  } },
});

const cases = [
  { name: 'published fresh-only retains newest eligible predecessor', releases: [release(older), release(latest, { scope: 'fresh-install-only' }), release(predecessor)], expected: [latest, predecessor] },
  { name: 'normal upgrade keeps latest only', releases: [release(latest), release(predecessor)], expected: [latest] },
  { name: 'missing scope keeps latest only', releases: [release(latest), release(predecessor)], expected: [latest] },
  { name: 'pending latest exposes no installer', releases: [release(latest, { scope: 'fresh-install-only', published: false }), release(predecessor)], expected: [latest], noLatestFile: true },
  { name: 'fresh-only with no predecessor keeps latest only', releases: [release(latest, { scope: 'fresh-install-only' })], expected: [latest] },
  { name: 'unsigned predecessor is skipped', releases: [release(latest, { scope: 'fresh-install-only' }), release(predecessor, { signature: 'unsigned' }), release(older)], expected: [latest, older] },
  { name: 'untrusted predecessor is skipped', releases: [release(latest, { scope: 'fresh-install-only' }), release(predecessor, { trust: 'internal-test' }), release(older)], expected: [latest, older] },
  { name: 'missing latest Windows metadata exposes no predecessor', releases: [release(latest, { packageMissing: true }), release(predecessor)], expected: [latest], noLatestFile: true },
  { name: 'missing published latest file fails closed', releases: [release(latest, { fileMissing: true }), release(predecessor)], error: /Published connector artifact is missing/ },
  { name: 'unsigned published latest fails closed', releases: [release(latest, { signature: 'unsigned' }), release(predecessor)], error: /not signed and production-trusted/ },
  { name: 'missing eligible predecessor file fails closed', releases: [release(latest, { scope: 'fresh-install-only' }), release(predecessor, { fileMissing: true })], error: /Previous signed connector is missing/ },
  { name: 'stale latest metadata fails closed', latestVersion: predecessor, releases: [release(predecessor), release(latest)], error: /invalid or stale latestVersion/ },
  { name: 'malformed version metadata fails closed', releases: [release(latest), release('2026.bad')], error: /invalid or stale latestVersion/ },
];

for (const testCase of cases) {
  const root = mkdtempSync(path.join(tmpdir(), 'mscqr-connector-runtime-'));
  try {
    const source = path.join(root, 'source'), output = path.join(root, 'output');
    mkdirSync(source, { recursive: true });
    for (const item of testCase.releases) {
      if (!item.platforms.windows || item.fileMissing) continue;
      const file = path.join(source, item.platforms.windows.relativePath);
      mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, item.version);
    }
    writeFileSync(path.join(source, 'manifest.json'), JSON.stringify({ latestVersion: testCase.latestVersion || latest, releases: testCase.releases }));
    const result = spawnSync(process.execPath, [script, source, output], { encoding: 'utf8' });
    if (testCase.error) {
      assert.notEqual(result.status, 0, testCase.name);
      assert.match(result.stderr, testCase.error, testCase.name);
      continue;
    }
    assert.equal(result.status, 0, `${testCase.name}: ${result.stderr}`);
    const packaged = JSON.parse(readFileSync(path.join(output, 'releases/manifest.json')));
    assert.deepEqual(packaged.releases.map((item) => item.version), testCase.expected, testCase.name);
    assert.equal(Boolean(packaged.releases[0].platforms.windows), !testCase.noLatestFile, testCase.name);
    assert.equal(existsSync(path.join(output, 'releases', latest, 'windows', `${latest}.exe`)), !testCase.noLatestFile, testCase.name);
    for (const item of testCase.releases.filter((item) => item.version !== (testCase.latestVersion || latest))) {
      const retained = testCase.expected.includes(item.version);
      assert.equal(existsSync(path.join(output, 'releases', item.version, 'windows', `${item.version}.exe`)), retained, testCase.name);
      assert.equal(packaged.releases.some((entry) => entry.version === item.version), retained, `${testCase.name}: direct versioned URL scope`);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
}
console.log(`PASS ${cases.length} connector runtime retention cases`);
