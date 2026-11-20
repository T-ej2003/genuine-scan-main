const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { generateKeyPairSync } = require('node:crypto');
const WebSocket = require('ws');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-fenced-session-'));
process.env.PRINT_AGENT_STATE_FILE = path.join(root, 'state.json');
process.env.PRINT_AGENT_DIRECT_POLL_MS = '2000';
const dist = path.resolve(__dirname, '../dist');
const pair = generateKeyPairSync('ed25519');
const state = { agentId: 'test-agent', deviceFingerprint: 'test-device', selectedPrinterId: 'test-printer',
  backendUrl: null, privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
const mock = (name, exports) => { const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports }; };
mock('local-print-agent/state.js', { loadAgentState: async () => state });
mock('local-print-agent/cups.js', { listLocalPrinters: async () => ({ printers: [{ printerId: 'test-printer' }], error: null }),
  resolveSelectedPrinter: () => ({ printerId: 'test-printer', printerName: 'Test printer' }) });
const fence = require('../dist/local-print-agent/maintenanceFence');
fence.enterMaintenanceFence();
const worker = require('../dist/local-print-agent/directPrintWorker');
const waitFor = async condition => { const deadline = Date.now() + 5000;
  while (!condition()) { if (Date.now() > deadline) throw new Error('Fenced session did not recover');
    await new Promise(resolve => setTimeout(resolve, 20)); } };

(async () => {
  let upgrades = 0;
  let messages = [];
  const server = http.createServer();
  const wss = new WebSocket.Server({ noServer: true });
  server.on('upgrade', (request, socket, head) => {
    upgrades++;
    wss.handleUpgrade(request, socket, head, ws => {
      ws.on('message', raw => {
        const message = JSON.parse(String(raw));
        messages.push(message.type);
        if (message.type === 'hello') {
          ws.send(JSON.stringify({ type: 'session_ready', sessionId: 'fenced-session', registrationId: 'test-registration' }));
          ws.send(JSON.stringify({ type: 'print_chunk', printJobId: 'blocked-job', printItemId: 'blocked-item' }));
        }
      });
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  state.backendUrl = `http://127.0.0.1:${server.address().port}`;
  const stop = worker.startDirectPrintWorker();
  try {
    await waitFor(() => worker.getPersistentPrintSessionStatus().connected);
    await new Promise(resolve => setTimeout(resolve, 200));
    assert.equal(upgrades, 1);
    assert(messages.includes('hello') && messages.includes('heartbeat') &&
      messages.every(type => ['hello', 'heartbeat'].includes(type)),
    'fenced runtime may authenticate and heartbeat but must not acknowledge or dispatch offered work');
    worker.stopDirectPrintAcquisition();
    await waitFor(() => !worker.getPersistentPrintSessionStatus().connected);
    await new Promise(resolve => setTimeout(resolve, 2200));
    assert.equal(upgrades, 1, 'old runtime must not reconnect after maintenance shutdown request');
    console.log('connector maintenance session recovery tests passed');
  } finally {
    stop();
    for (const ws of wss.clients) ws.terminate();
    wss.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
