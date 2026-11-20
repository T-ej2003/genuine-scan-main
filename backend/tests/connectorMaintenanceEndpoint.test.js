const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { once } = require('node:events');

const connector = path.resolve(__dirname, '../dist/local-print-agent/index.js');

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mscqr-maintenance-http-'));
  const probe = net.createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise(resolve => probe.close(resolve));
  const env = { ...process.env, PRINT_AGENT_PORT: String(port), PRINT_AGENT_STATE_FILE: path.join(root, 'state.json'),
    PRINT_AGENT_LOCK_DIR: path.join(root, 'lock'), PRINT_AGENT_DISPATCH_JOURNAL_DIR: path.join(root, 'journal'),
    PRINT_AGENT_BACKEND_URL: '', PRINT_GATEWAY_BACKEND_URL: '' };
  let child;
  const start = async () => {
    child = spawn(process.execPath, [connector], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Connector did not start')), 10000);
      child.stdout.on('data', chunk => { if (String(chunk).includes('local print agent listening')) { clearTimeout(timeout); resolve(); } });
      child.once('exit', code => { clearTimeout(timeout); reject(new Error(`Connector exited: ${code}`)); });
    });
  };
  const stop = async () => { if (child && child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'exit'); } };
  try {
    assert.equal(spawnSync(process.execPath, [connector, '--initialize-state'], { env }).status, 0);
    await start();
    const url = `http://127.0.0.1:${port}/maintenance`;
    const state = JSON.parse(await fs.readFile(env.PRINT_AGENT_STATE_FILE, 'utf8'));
    const sourceVersion = spawnSync(process.execPath, [connector, '--version'], { env, encoding: 'utf8' }).stdout.trim();
    const deviceProof = require('../dist/services/connectorUpgradeDeviceProof');
    const challenge = deviceProof.createUpgradeDeviceChallenge({ attemptId: randomUUID(), agentId: state.agentId,
      deviceFingerprint: state.deviceFingerprint, manufacturerId: 'manufacturer-test', tenantId: 'tenant-test',
      printerId: 'd5e8d13e-4d73-411b-9b3f-6d1800e73609', registrationId: '839e55cd-86ea-4523-8544-ff4a62a15158',
      sourceVersion, currentVersion: sourceVersion, targetVersion: '2026.11.20.1' });
    const proofResponse = await fetch(`${url}/device-proof`, { method: 'POST', headers: { origin: 'https://www.mscqr.com', 'content-type': 'application/json' },
      body: JSON.stringify(challenge) });
    assert.equal(proofResponse.status, 200);
    const signed = await proofResponse.json();
    assert.equal(deviceProof.verifyUpgradeDeviceChallenge({ challenge, signature: signed.signature,
      publicKeyPem: state.publicKeyPem, binding: { agentId: state.agentId, deviceFingerprint: state.deviceFingerprint,
        attemptId: challenge.attemptId, manufacturerId: 'manufacturer-test', tenantId: 'tenant-test', printerId: challenge.printerId,
        registrationId: challenge.registrationId, sourceVersion, currentVersion: sourceVersion,
        targetVersion: challenge.targetVersion } }).attemptId, challenge.attemptId);
    assert.equal((await fetch(`${url}/checkpoint-evidence`, { method: 'POST',
      headers: { origin: 'https://www.mscqr.com', 'content-type': 'application/json' },
      body: JSON.stringify(challenge) })).status, 403, 'device proof cannot silently create a maintenance fence');
    const wrongDevice = await fetch(`${url}/device-proof`, { method: 'POST', headers: { origin: 'https://www.mscqr.com', 'content-type': 'application/json' },
      body: JSON.stringify({ ...challenge, deviceFingerprint: 'device-other' }) });
    assert.equal(wrongDevice.status, 403);
    const skewed = await fetch(`${url}/device-proof`, { method: 'POST', headers: { origin: 'https://www.mscqr.com', 'content-type': 'application/json' },
      body: JSON.stringify({ ...challenge, expiresAt: new Date(Date.now() + 250_000).toISOString() }) });
    assert.equal(skewed.status, 200, 'connector clock skew must not block a plausible server challenge');
    const implausible = await fetch(`${url}/device-proof`, { method: 'POST', headers: { origin: 'https://www.mscqr.com', 'content-type': 'application/json' },
      body: JSON.stringify({ ...challenge, expiresAt: new Date(Date.now() + 360_000).toISOString() }) });
    assert.equal(implausible.status, 403);
    assert.equal((await fetch(`${url}/fence`, { method: 'POST', headers: { origin: 'https://evil.example' } })).status, 403);
    const response = await fetch(`${url}/fence`, { method: 'POST', headers: { origin: 'https://www.mscqr.com' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await response.json()).checkpoint, { fenced: true, active: 0, idle: true, socketClosed: true });
    const checkpointEvidence = await fetch(`${url}/checkpoint-evidence`, { method: 'POST',
      headers: { origin: 'https://www.mscqr.com', 'content-type': 'application/json' }, body: JSON.stringify(challenge) });
    assert.equal(checkpointEvidence.status, 200);
    const envelope = (await checkpointEvidence.json()).evidence;
    const verified = deviceProof.verifyMaintenanceCheckpoint(envelope, challenge, state.publicKeyPem);
    assert.equal(verified.physicalOutcomes, 'UNVERIFIED');
    assert.equal(verified.journal.count, 0);
    assert.throws(() => deviceProof.verifyMaintenanceCheckpoint(envelope, { ...challenge, attemptId: randomUUID() }, state.publicKeyPem));
    assert.throws(() => deviceProof.verifyMaintenanceCheckpoint(envelope, challenge, state.publicKeyPem, Date.now() + 300_000));
    await stop();
    await start();
    const checkpoint = await fetch(`${url}/checkpoint`);
    assert.deepEqual(await checkpoint.json(), { fenced: true, active: 0, idle: true, socketClosed: true });
    console.log('connector maintenance endpoint tests passed');
  } finally { await stop(); await fs.rm(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
