const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-maintenance-race-'));
process.env.PRINT_AGENT_STATE_FILE = path.join(root, 'state.json');
process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR = path.join(root, 'journal');
const { enterMaintenanceFence, maintenanceCheckpoint } = require('../dist/local-print-agent/maintenanceFence');
const { runGatewayCycle } = require('../dist/local-print-agent/gateway');

(async () => {
  const calls = [];
  let claimStarted;
  let finishClaim;
  const started = new Promise(resolve => { claimStarted = resolve; });
  const pendingClaim = new Promise(resolve => { finishClaim = resolve; });
  const previousFetch = global.fetch;
  global.fetch = async url => {
    calls.push(String(url));
    if (String(url).endsWith('/print-gateway/test/claim')) {
      claimStarted();
      await pendingClaim;
      return { ok: true, json: async () => ({ success: true, data: { testJobId: 'synthetic-diagnostic' } }) };
    }
    return { ok: true, json: async () => ({ success: true, data: null }) };
  };
  try {
    const cycle = runGatewayCycle('NETWORK_DIRECT');
    await started;
    assert.equal(enterMaintenanceFence().idle, false, 'an in-flight claim must keep the checkpoint busy');
    finishClaim();
    await assert.rejects(cycle, /maintenance began before dispatch/);
    assert.equal(maintenanceCheckpoint().idle, true);
    assert.equal(calls.length, 2, 'fence must fail the committed test claim without opening a normal claim');
    assert.match(calls[1], /\/print-gateway\/test\/fail$/);
    const outbox = fs.readdirSync(path.join(root, 'journal')).find(name => name.endsWith('.gateway-attempt.json'));
    assert.equal(JSON.parse(fs.readFileSync(path.join(root, 'journal', outbox), 'utf8')).state, 'PRE_DISPATCH_REPORTED');
    console.log('connector maintenance claim race tests passed');
  } finally { global.fetch = previousFetch; fs.rmSync(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
