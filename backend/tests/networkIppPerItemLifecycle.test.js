const assert = require('node:assert/strict');
const path = require('node:path');
const dist = path.resolve(__dirname, '../dist');
const loaded = name => require(path.join(dist, name));
const repository = loaded('rls-waves/session-c/c02/printingLifecycleRepository');
const renderer = loaded('printing/pdfLabel');
const ipp = loaded('printing/ippClient');
const payload = loaded('services/printPayloadService');
const originals = {
  run: repository.runNetworkPrintingWorker,
  render: renderer.renderPdfLabelBuffer,
  connection: ipp.buildIppConnectionInfo,
  submit: ipp.submitPdfToIppPrinter,
  inspect: ipp.inspectIppJob,
  context: payload.buildApprovedPrintContext,
};
const service = loaded('services/networkIppPrintService');
const items = [1, 2, 3].map(n => ({ id: `item-${n}`, qrCodeId: `qr-${n}`, code: `synthetic-${n}`, displayCode: `S-${n}`, batchId: 'batch', licenseeId: 'tenant' }));

(async () => {
  try {
    let operations, claims, submissions, failRenderAt, failSubmitAt, failReserveAt, failFailureReport;
    const reset = () => {
      operations = []; claims = 0; submissions = []; failRenderAt = 0; failSubmitAt = 0; failReserveAt = 0; failFailureReport = false;
    };
    payload.buildApprovedPrintContext = () => ({ scanUrl: 'https://isolated.invalid/synthetic', previewLabel: 'SYNTHETIC' });
    renderer.renderPdfLabelBuffer = async input => {
      const index = Number(input.code.slice(-1));
      if (failRenderAt === index) throw Error('deterministic preparation failure');
      return Buffer.from(`synthetic-pdf-${index}`);
    };
    ipp.buildIppConnectionInfo = () => ({ host: '127.0.0.2', port: 631 });
    ipp.submitPdfToIppPrinter = async input => {
      const index = Number(input.jobName.slice(-1));
      submissions.push(index);
      if (failSubmitAt === index) throw Error('ambiguous physical submission');
      return { jobId: index };
    };
    ipp.inspectIppJob = async () => ({ jobState: 9, jobStateReasons: [] });
    repository.runNetworkPrintingWorker = async input => {
      operations.push({ operation: input.operation, itemIds: input.details?.itemIds });
      if (input.operation === 'CLAIM_IPP') {
        claims++;
        return claims === 1 ? { available: true, job: { id: 'job', jobNumber: 'synthetic', manufacturerId: 'maker' },
          printer: { id: 'printer', host: '127.0.0.2', port: 631 }, items } : { available: false };
      }
      if (input.operation === 'RESERVE_DISPATCH' && failReserveAt === Number(input.details.itemIds[0].slice(-1))) throw Error('reservation outcome unknown');
      if (input.operation === 'FAIL' && failFailureReport) throw Error('authoritative failure report unavailable');
      return {};
    };
    const run = () => service.resumePendingNetworkIppJobs();
    const ids = op => operations.filter(entry => entry.operation === op).flatMap(entry => entry.itemIds || []);

    reset(); failRenderAt = 1;
    await assert.rejects(run(), /deterministic preparation failure/);
    assert.deepEqual(submissions, []);
    assert.deepEqual(ids('FAIL'), items.map(item => item.id));

    reset(); failRenderAt = 2;
    await assert.rejects(run(), /deterministic preparation failure/);
    assert.deepEqual(submissions, [1]);
    assert.deepEqual(ids('CONFIRM'), ['item-1']);
    assert.deepEqual(ids('FAIL'), ['item-2', 'item-3']);

    reset(); failRenderAt = 1; failFailureReport = true;
    await assert.rejects(run(), /failure reporting is unverified/);
    assert.deepEqual(submissions, []);
    assert.deepEqual(ids('FAIL'), items.map(item => item.id));

    reset(); failReserveAt = 2;
    await assert.rejects(run(), /reservation outcome unknown/);
    assert.deepEqual(submissions, [1]);
    assert.deepEqual(ids('FAIL'), ['item-3']);

    reset(); failSubmitAt = 2;
    await assert.rejects(run(), /ambiguous physical submission/);
    assert.deepEqual(submissions, [1, 2]);
    assert.deepEqual(ids('FAIL'), ['item-3']);
    assert.deepEqual(ids('CONFIRM'), ['item-1']);
    console.log('PASS IPP item-level preparation, reservation and transport uncertainty');
  } finally {
    repository.runNetworkPrintingWorker = originals.run;
    renderer.renderPdfLabelBuffer = originals.render;
    ipp.buildIppConnectionInfo = originals.connection;
    ipp.submitPdfToIppPrinter = originals.submit;
    ipp.inspectIppJob = originals.inspect;
    payload.buildApprovedPrintContext = originals.context;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
