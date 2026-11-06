const assert = require('node:assert/strict');
const { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = mkdtempSync(path.join(tmpdir(), 'mscqr-connector-runtime-'));
try {
  const source = path.join(root, 'source'), output = path.join(root, 'output');
  for (const version of ['2026.11.6.2', '2026.10.29.1', '2026.6.26']) {
    mkdirSync(path.join(source, version, 'windows'), { recursive: true });
    writeFileSync(path.join(source, version, 'windows', `${version}.exe`), version);
  }
  const release = (version, publishedAt) => ({ version, publishedAt, platforms: { windows: {
    signatureStatus: 'signed', trustLevel: 'production', relativePath: `${version}/windows/${version}.exe`,
  } } });
  writeFileSync(path.join(source, 'manifest.json'), JSON.stringify({ latestVersion: '2026.11.6.2', releases: [
    release('2026.11.6.2', '2026-11-06T00:00:00Z'),
    release('2026.10.29.1', '2026-10-29T00:00:00Z'),
    release('2026.6.26', '2026-06-26T00:00:00Z'),
  ] }));
  const script = path.join(__dirname, '../scripts/create-connector-runtime-assets.mjs');
  const result = spawnSync(process.execPath, [script, source, output], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const packaged = JSON.parse(readFileSync(path.join(output, 'releases/manifest.json')));
  assert.deepEqual(packaged.releases.map(entry => entry.version), ['2026.11.6.2', '2026.10.29.1']);
  assert(existsSync(path.join(output, 'releases/2026.10.29.1/windows/2026.10.29.1.exe')));
  assert(!existsSync(path.join(output, 'releases/2026.6.26/windows/2026.6.26.exe')));
  rmSync(path.join(source, '2026.10.29.1/windows/2026.10.29.1.exe'));
  assert.notEqual(spawnSync(process.execPath, [script, source, output], { encoding: 'utf8' }).status, 0,
    'a missing previous signed installer must fail image packaging');
  console.log('PASS connector runtime retains the prior signed installer only');
} finally { rmSync(root, { recursive: true, force: true }); }
