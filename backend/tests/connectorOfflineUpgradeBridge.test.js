const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');

const executable = path.resolve(__dirname, '../dist/local-print-agent/index.js');
const proof = require('../dist/services/connectorUpgradeDeviceProof');
const journal = require('../dist/local-print-agent/dispatchJournal');
const origin = 'https://www.mscqr.com';

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mscqr-offline-upgrade-'));
  const server = net.createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  const env = { ...process.env, PRINT_AGENT_PORT: String(port), PRINT_AGENT_STATE_FILE: path.join(root, 'state.json'),
    PRINT_AGENT_LOCK_DIR: path.join(root, 'lock'), PRINT_AGENT_DISPATCH_JOURNAL_DIR: path.join(root, 'journal'),
    MSCQR_OFFLINE_SOURCE_VERSION: '2026.11.6.2', PRINT_AGENT_BACKEND_URL: '', PRINT_GATEWAY_BACKEND_URL: '' };
  let child;
  try {
    assert.equal(spawnSync(process.execPath, [executable, '--initialize-state'], { env }).status, 0);
    const state = JSON.parse(await fs.readFile(env.PRINT_AGENT_STATE_FILE, 'utf8'));
    const fence = path.join(root, 'maintenance-fence.json');
    assert.equal(spawnSync(process.execPath, [executable, '--offline-existing-install'], { env }).status, 1,
      'the offline bridge cannot run without a durable local fence');
    await fs.writeFile(fence, JSON.stringify({ version: 1, state: 'FENCED', createdAt: new Date().toISOString() }));
    process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR = env.PRINT_AGENT_DISPATCH_JOURNAL_DIR;
    await fs.mkdir(env.PRINT_AGENT_DISPATCH_JOURNAL_DIR);
    for (let index = 0; index < 12; index++) {
      const printJobId = `job-${index}`;
      const printItemId = `item-${index}`;
      const name = `${journal.dispatchReservationKey(printJobId, printItemId)}.json`;
      await fs.writeFile(path.join(env.PRINT_AGENT_DISPATCH_JOURNAL_DIR, name), JSON.stringify({
        journalVersion: 2, state: 'ATTEMPT_RESERVED', printJobId, printItemId,
        printerId: 'printer-1', payloadHash: 'a'.repeat(64),
      }));
    }
    const corrupt = path.join(env.PRINT_AGENT_DISPATCH_JOURNAL_DIR, 'unexpected.json');
    await fs.writeFile(corrupt, '{}');
    assert.equal(spawnSync(process.execPath, [executable, '--offline-existing-install'], { env }).status, 1,
      'unknown journal content cannot be authorized');
    await fs.unlink(corrupt);
    assert.equal(spawnSync(process.execPath, [executable, '--offline-existing-install'],
      { env: { ...env, MSCQR_OFFLINE_SOURCE_VERSION: '2026.11.1.1' } }).status, 1);
    assert.equal(spawnSync(process.execPath, [executable, '--offline-existing-install'],
      { env: { ...env, PRINT_AGENT_STATE_FILE: path.join(root, 'missing.json') } }).status, 1);
    child = spawn(process.execPath, [executable, '--offline-existing-install'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Offline bridge did not start')), 10000);
      child.stdout.on('data', bytes => { if (String(bytes).includes('local print agent listening')) { clearTimeout(timer); resolve(); } });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`Offline bridge exited: ${code}`)); });
    });
    const base = `http://127.0.0.1:${port}`;
    const status = await (await fetch(`${base}/status`)).json();
    assert.equal(status.buildVersion, '2026.11.6.2', JSON.stringify({ error: status.error, keys: Object.keys(status) }));
    assert.equal(status.agentId, state.agentId);
    assert.equal((await fetch(`${base}/print`, { method: 'POST', headers: { origin } })).status, 403);
    const targetVersion = spawnSync(process.execPath, [executable, '--version'], { env, encoding: 'utf8' }).stdout.trim();
    const challenge = proof.createUpgradeDeviceChallenge({ attemptId: randomUUID(), agentId: state.agentId,
      deviceFingerprint: state.deviceFingerprint, manufacturerId: 'manufacturer-1', tenantId: 'tenant-1',
      printerId: randomUUID(), registrationId: randomUUID(), sourceVersion: '2026.11.6.2',
      currentVersion: '2026.11.6.2', targetVersion });
    const post = (route, value) => fetch(`${base}${route}`, { method: 'POST', headers: { origin, 'content-type': 'application/json' },
      body: JSON.stringify(value) });
    const signed = await (await post('/maintenance/device-proof', challenge)).json();
    assert(proof.verifyUpgradeDeviceChallenge({ challenge, signature: signed.signature,
      publicKeyPem: state.publicKeyPem, binding: { attemptId: challenge.attemptId, agentId: state.agentId,
        deviceFingerprint: state.deviceFingerprint, manufacturerId: challenge.manufacturerId,
        tenantId: challenge.tenantId, printerId: challenge.printerId, registrationId: challenge.registrationId,
        sourceVersion: challenge.sourceVersion, currentVersion: challenge.currentVersion,
        targetVersion: challenge.targetVersion } }));
    assert.equal((await post('/maintenance/device-proof', { ...challenge, deviceFingerprint: 'other-device' })).status, 403);
    assert.equal((await post('/maintenance/device-proof', { ...challenge, targetVersion: '2026.11.20.1' })).status, 403);
    const checkpoint = await (await post('/maintenance/checkpoint-evidence', challenge)).json();
    const verified = proof.verifyMaintenanceCheckpoint(checkpoint.evidence, challenge, state.publicKeyPem);
    assert.equal(verified.journal.count, 12);
    assert(verified.journal.entries.every(entry => entry.state === 'ATTEMPT_RESERVED'));
    assert.equal(verified.physicalOutcomes, 'UNVERIFIED');
    assert.equal((await post('/maintenance/shutdown', {})).status, 200);
    if (child.exitCode === null) await once(child, 'exit');
    assert.equal((await journal.inspectDispatchJournal()).count, 12);
  } finally {
    if (child && child.exitCode === null) { child.kill('SIGTERM'); await once(child, 'exit'); }
    delete process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR;
    await fs.rm(root, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
