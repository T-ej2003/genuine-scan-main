const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const modulePath = require.resolve('../dist/local-print-agent/dispatchJournal');

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mscqr-dispatch-test-'));
  const input = { printJobId: 'synthetic-job', printItemId: 'synthetic-item', printerId: 'simulator', payloadHash: 'synthetic-hash' };
  try {
    const worker = () => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['-e', `require(${JSON.stringify(modulePath)}).reserveAutomaticDispatch(${JSON.stringify(input)}).then(x=>process.exit(x?0:2)).catch(()=>process.exit(3))`], {
        env: { ...process.env, PRINT_AGENT_DISPATCH_JOURNAL_DIR: root }, stdio: 'ignore',
      });
      child.on('error', reject); child.on('exit', resolve);
    });
    const results = await Promise.all(Array.from({ length: 8 }, worker));
    assert.equal(results.filter(x => x === 0).length, 1, 'only one process may reserve automatic dispatch');
    assert.equal(results.filter(x => x === 2).length, 7);
    assert.equal(await worker(), 2, 'restart after reservation must not authorize a second spool');
    const files = await fs.readdir(root);
    assert.equal(files.length, 1);
    await fs.writeFile(path.join(root, files[0]), '{interrupted journal');
    assert.equal(await worker(), 2, 'incomplete evidence must also block replay');
    process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR = root;
    const { createHash } = require('node:crypto');
    const { runPersistentPrintChunk, runPersistentDiagnosticTestJob } = require('../dist/local-print-agent/directPrintWorker');
    const zpl = '^XA^FDLOCAL-SYNTHETIC^FS^XZ';
    const payloadHash = createHash('sha256').update(zpl).digest('hex');
    const payload = { chunkId: 'first-chunk', printJobId: 'synthetic-job', printer: {}, labels: [{
      printItemId: 'reconnect-item', code: 'synthetic', scanUrl: 'http://127.0.0.1/synthetic',
      payloadContent: zpl, payloadHash, payloadType: 'ZPL', commandLanguage: 'ZPL',
    }] };
    let spools = 0;
    const events = [];
    const adapters = {
      send: async (_ws, _session, _printer, event) => {
        events.push(event.type);
        if (event.type === 'label_spooled') throw new Error('injected lost receipt');
      },
      print: async () => { spools++; return { printPath: 'USB_RAW', labelLanguage: 'ZPL', jobRef: 'simulated' }; },
      wait: async () => { throw new Error('unexpected confirmation'); },
    };
    const session = () => ({ sessionId: 'synthetic', registrationId: 'synthetic', selectedPrinterId: 'simulator', messageSeq: 0 });
    await assert.rejects(runPersistentPrintChunk({}, session(), payload, 'simulator', adapters), /injected lost receipt/);
    await assert.rejects(runPersistentPrintChunk({}, session(), { ...payload, chunkId: 'reconnected-chunk' }, 'simulator', adapters),
      { errorCode: 'dispatch_reconciliation_required' });
    assert.equal(spools, 1, 'reconnect must not submit a second automatic physical attempt');
    assert(!events.includes('label_failed') && !events.includes('chunk_failed'), 'uncertain delivery must not be classified as failed');
    let testSpools = 0;
    const diagnosticEvents = [];
    const diagnostic = { testJobId: 'diagnostic-item', payloadContent: zpl, payloadHash, payloadType: 'ZPL' };
    const diagnosticAdapters = {
      send: async (_ws, _session, _printer, event) => diagnosticEvents.push(event.type),
      print: async () => { testSpools++; return { printPath: 'USB_RAW', labelLanguage: 'ZPL', jobRef: 'simulated' }; },
      wait: async () => ({ confirmed: false, confirmationUnavailable: true }),
    };
    await assert.rejects(runPersistentDiagnosticTestJob({}, session(), diagnostic, 'simulator', diagnosticAdapters),
      { errorCode: 'queue_confirmation_unavailable' });
    await assert.rejects(runPersistentDiagnosticTestJob({}, session(), diagnostic, 'simulator', diagnosticAdapters),
      { errorCode: 'dispatch_reconciliation_required' });
    assert.equal(testSpools, 1);
    assert.deepEqual(diagnosticEvents, ['test_ack'], 'spool acceptance alone must not confirm or fail the diagnostic');
    console.log('Connector dispatch journal concurrency and restart tests passed');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
