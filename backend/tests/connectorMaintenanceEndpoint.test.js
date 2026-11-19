const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { spawn, spawnSync } = require('node:child_process');
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
    PRINT_AGENT_LOCK_DIR: path.join(root, 'lock'), PRINT_AGENT_BACKEND_URL: '', PRINT_GATEWAY_BACKEND_URL: '' };
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
    assert.equal((await fetch(`${url}/fence`, { method: 'POST', headers: { origin: 'https://evil.example' } })).status, 403);
    const response = await fetch(`${url}/fence`, { method: 'POST', headers: { origin: 'https://www.mscqr.com' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual((await response.json()).checkpoint, { fenced: true, active: 0, idle: true, socketClosed: true });
    await stop();
    await start();
    const checkpoint = await fetch(`${url}/checkpoint`);
    assert.deepEqual(await checkpoint.json(), { fenced: true, active: 0, idle: true, socketClosed: true });
    console.log('connector maintenance endpoint tests passed');
  } finally { await stop(); await fs.rm(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
