const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { constants } = require('node:fs');
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
    const {reserveAutomaticDispatch}=require(modulePath);
    const {shouldReportLocalPrintFailureToBackend}=require('../dist/local-print-agent/directPrintWorker');
    const realOpen=fs.open;
    fs.open=async(...args)=>{
      const handle=await realOpen(...args);
      handle.sync=async()=>{throw new Error('injected fsync ambiguity after reservation creation');};
      return handle;
    };
    try {
      await assert.rejects(reserveAutomaticDispatch({...input,printItemId:'fsync-uncertain'}),error=>{
        assert.equal(error.errorCode,'dispatch_reconciliation_required');
        assert.equal(shouldReportLocalPrintFailureToBackend(error,false),false,'REST must preserve reservation-write uncertainty');
        return true;
      });
    } finally {fs.open=realOpen;}
    assert.equal(await reserveAutomaticDispatch({...input,printItemId:'fsync-uncertain'}),false,'partial write must remain non-replayable');
    fs.open=async(...args)=>{
      const handle=await realOpen(...args);
      if(String(args[0]).endsWith('.json')) {
        const close=handle.close.bind(handle);
        handle.close=async()=>{await close();throw Error('injected close uncertainty');};
      }
      return handle;
    };
    try {await assert.rejects(reserveAutomaticDispatch({...input,printItemId:'close-uncertain'}),
      {errorCode:'dispatch_reconciliation_required'});} finally {fs.open=realOpen;}
    assert.equal(await reserveAutomaticDispatch({...input,printItemId:'close-uncertain'}),false,
      'close failure cannot authorize a second attempt');
    const ordering = [];
    fs.open = async (...args) => {
      const handle = await realOpen(...args);
      if (String(args[0]).endsWith('.json')) {
        if(process.platform==='win32') assert.equal(args[1],'wx','Windows must retain exclusive creation');
        else assert(Number(args[1]) & constants.O_SYNC, 'POSIX reservation creation must request synchronized metadata writes');
        const write = handle.writeFile.bind(handle), sync = handle.sync.bind(handle);
        handle.writeFile = async (...writeArgs) => { ordering.push('FILE_WRITE'); return write(...writeArgs); };
        handle.sync = async () => { ordering.push('FILE_SYNC'); return sync(); };
      } else {
        const sync = handle.sync.bind(handle);
        handle.sync = async () => { ordering.push('DIRECTORY_SYNC'); return sync(); };
      }
      return handle;
    };
    try {
      assert.equal(await reserveAutomaticDispatch({...input,printItemId:'ordered'}),true);
      ordering.push('DISPATCH');
    } finally { fs.open=realOpen; }
    assert.deepEqual(ordering,process.platform==='win32' ? ['FILE_WRITE','FILE_SYNC','DISPATCH'] :
      ['FILE_WRITE','FILE_SYNC','DIRECTORY_SYNC','DISPATCH']);
    if (process.platform !== 'win32') {
      fs.open = async (...args) => {
        const handle=await realOpen(...args);
        if (String(args[0])===root) handle.sync=async()=>{throw Error('injected directory sync failure');};
        return handle;
      };
      try {
        await assert.rejects(reserveAutomaticDispatch({...input,printItemId:'directory-uncertain'}),error=>{
          assert.equal(error.errorCode,'dispatch_reconciliation_required'); return true;
        });
      } finally {fs.open=realOpen;}
      assert.equal(await reserveAutomaticDispatch({...input,printItemId:'directory-uncertain'}),false,
        'failed directory sync cannot authorize a second physical attempt');
    }
    assert.equal(await reserveAutomaticDispatch({...input,printJobId:'new-governed-reissue'}),true,'governed replacement job may retain the existing item identity');
    assert.equal(await reserveAutomaticDispatch({...input,printJobId:'new-governed-reissue'}),false,'replacement job is itself at most once');
    const {legacyDispatchKey}=require(modulePath);
    const legacy={...input,printItemId:'legacy-item',state:'ATTEMPT_RESERVED'};
    await fs.writeFile(path.join(root,`${legacyDispatchKey(legacy.printItemId)}.json`),JSON.stringify(legacy));
    assert.equal(await reserveAutomaticDispatch(legacy),false,'v1 original reservation blocks original job redelivery');
    assert.equal(await reserveAutomaticDispatch({...legacy,printJobId:'approved-reissue-of-legacy'}),false,'ambiguous item-only markers must not be inferred to authorize another physical attempt');
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
    if (process.platform !== 'win32') {
      const newRoot=path.join(root,'created-parent','journal');
      const synced=[];
      process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR=newRoot;
      fs.open=async (...args)=>{
        const handle=await realOpen(...args);
        if(!String(args[0]).endsWith('.json')) {
          const sync=handle.sync.bind(handle);
          handle.sync=async()=>{synced.push(String(args[0]));return sync();};
        }
        return handle;
      };
      try {assert.equal(await reserveAutomaticDispatch({...input,printItemId:'new-root'}),true);}
      finally {fs.open=realOpen;process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR=root;}
      assert(synced.includes(root) && synced.includes(path.join(root,'created-parent')) && synced.includes(newRoot),
        'new journal ancestors and the reservation directory must be synced');
    }
    console.log('Connector dispatch journal concurrency and restart tests passed');
  } finally { await fs.rm(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
