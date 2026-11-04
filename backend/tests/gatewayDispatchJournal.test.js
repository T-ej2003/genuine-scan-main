const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { createHash } = require('node:crypto');

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mscqr-gateway-journal-'));
  process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR = root;
  process.env.PRINT_GATEWAY_ID = 'synthetic-gateway';
  process.env.PRINT_GATEWAY_SECRET = 'synthetic-only';
  process.env.PRINT_GATEWAY_BACKEND_URL = 'http://127.0.0.1:1';
  let submissions = 0;
  const injectedTransport = async () => { submissions++; throw new Error('injected disconnect after submission'); };
  require('../dist/services/networkPrinterSocketService').sendRawPayloadToNetworkPrinter = injectedTransport;
  require('../dist/printing/ippClient').submitPdfToIppPrinter = injectedTransport;
  require('../dist/printing/pdfLabel').renderPdfLabelBuffer = async () => Buffer.from('synthetic-pdf');
  require('../dist/services/zebraPrinterStatusService').getZebraTotalLabelCount = async () => 0;
  const { runGatewayCycle, normalizeGatewayClaim } = require('../dist/local-print-agent/gateway');
  const originalFetch = global.fetch;
  try {
    assert.throws(() => normalizeGatewayClaim({ job: { id: 'one' }, item: { id: 'two' }, printItemId: 'other' }), /inconsistent/);
    for (const mode of ['NETWORK_DIRECT', 'NETWORK_IPP']) {
      for (const diagnostic of [false, true]) {
        const id = `${mode}-${diagnostic}`;
        const content = '^XA^FDLOCAL-SYNTHETIC^FS^XZ';
        const payload = { printJobId: id, printItemId: id, ...(diagnostic ? { testJobId: id } : {}),
          code: 'synthetic', scanUrl: 'http://127.0.0.1/test', payloadContent: content,
          payloadHash: createHash('sha256').update(content).digest('hex'),
          printer: { ipAddress: '127.0.0.1', port: 1, printerUri: 'ipp://127.0.0.1:1/test' } };
        const events = [];
        global.fetch = async url => {
          events.push(String(url));
          const isTest = String(url).endsWith('/test/claim');
          const data = diagnostic ? (isTest ? payload : null) : {
            job: { id, jobNumber: 'synthetic' }, item: { id, code: 'synthetic' }, printer: payload.printer,
            payload: { payloadContent: content, payloadHash: payload.payloadHash, scanUrl: payload.scanUrl },
          };
          return { ok: true, json: async () => ({ success: true, data }) };
        };
        const before = submissions;
        await assert.rejects(runGatewayCycle(mode), /injected disconnect after submission/);
        await assert.rejects(runGatewayCycle(mode), { errorCode: 'dispatch_reconciliation_required' });
        assert.equal(submissions - before, 1, `${id}: redelivery must not resubmit`);
        assert(!events.some(url => url.endsWith('/fail')), 'uncertain physical outcome must not be classified as failed');
      }
    }
    console.log('Gateway direct/IPP and diagnostic durable dispatch tests passed');
  } finally { global.fetch = originalFetch; await fs.rm(root, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
