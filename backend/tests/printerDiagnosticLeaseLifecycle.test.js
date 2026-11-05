const assert = require('node:assert/strict');
const path = require('node:path');
const { PrinterConnectionType, PrinterDeliveryMode } = require('@prisma/client');

const dist = path.resolve(__dirname, '../dist');
const loaded = name => require(path.join(dist, name));
const repository = loaded('rls-waves/session-c/c02/printingLifecycleRepository');
const zebra = loaded('services/zebraPrinterStatusService');
const socket = loaded('services/networkPrinterSocketService');
const renderer = loaded('printing/renderers');
const tokens = loaded('services/qrTokenService');
const originals = {
  administer: repository.administerPrintingPrinter,
  baseline: zebra.getZebraTotalLabelCount,
  confirm: zebra.waitForZebraLabelConfirmation,
  send: socket.sendRawPayloadToNetworkPrinter,
  render: renderer.resolvePrinterLanguageRenderer,
  sign: tokens.signQrPayload,
  scan: tokens.buildScanUrl,
};
const { printTestLabelForRegisteredPrinter } = loaded('services/printerTestLabelService');
const printer = {
  id: 'diagnostic-printer', vendor: 'Zebra', model: 'ZT410', name: 'Zebra ZT410',
  connectionType: PrinterConnectionType.NETWORK_DIRECT, deliveryMode: PrinterDeliveryMode.DIRECT,
  commandLanguage: 'ZPL', ipAddress: '127.0.0.2', port: 9100, calibrationProfile: null,
  profile: { statusConfig: { confirmationMode: 'ZEBRA_ODOMETER' }, activeLanguage: 'ZPL' },
};
const boundary = { capability: 'isolated-authorized-capability', requestId: '50000000-0000-4000-8000-000000000041' };

(async () => {
  try {
    tokens.signQrPayload = () => 'synthetic-signed-token';
    tokens.buildScanUrl = () => 'https://isolated.invalid/scan/synthetic';
    renderer.resolvePrinterLanguageRenderer = () => ({ render: () => ({ payloadType: 'ZPL', payloadContent: '^XA^XZ' }) });
    let operations, sends, baselineFailure, sendFailure, closureFailure, renderFailure;
    const reset = () => {
      operations = []; sends = 0; baselineFailure = false; sendFailure = false; closureFailure = false; renderFailure = false;
    };
    repository.administerPrintingPrinter = async input => {
      operations.push(input.operation);
      assert.equal(input.printerId, printer.id);
      assert.equal(input.capability, boundary.capability);
      assert.equal(input.requestId, boundary.requestId);
      if (input.operation === 'DIAGNOSTIC_ABORT' && closureFailure) throw Error('authoritative closure unavailable');
      return {};
    };
    zebra.getZebraTotalLabelCount = async () => {
      if (baselineFailure) throw Error('baseline unavailable');
      return 10;
    };
    zebra.waitForZebraLabelConfirmation = async () => ({ confirmed: true, lastCount: 11 });
    socket.sendRawPayloadToNetworkPrinter = async () => {
      sends++;
      if (sendFailure) throw Error('transport outcome uncertain');
      return { bytesWritten: 6 };
    };
    const realRender = renderer.resolvePrinterLanguageRenderer;
    const run = () => printTestLabelForRegisteredPrinter({ printer, actorUserId: 'isolated-maker', boundary });

    reset();
    await assert.rejects(printTestLabelForRegisteredPrinter({ printer: { ...printer, connectionType: 'UNSUPPORTED' }, actorUserId: 'isolated-maker', boundary }),
      /Unsupported printer route/);
    assert.deepEqual(operations, [], 'unsupported routes never acquire a diagnostic lease');

    reset(); renderFailure = true;
    renderer.resolvePrinterLanguageRenderer = () => { throw Error('deterministic render rejection'); };
    await assert.rejects(run(), /deterministic render rejection/);
    assert.deepEqual(operations, ['DIAGNOSTIC_LEASE', 'DIAGNOSTIC_ABORT']);
    assert.equal(sends, 0);
    renderer.resolvePrinterLanguageRenderer = realRender;

    reset();
    renderer.resolvePrinterLanguageRenderer = () => { throw Error('gateway deterministic render rejection'); };
    await assert.rejects(printTestLabelForRegisteredPrinter({ printer: { ...printer, deliveryMode: PrinterDeliveryMode.SITE_GATEWAY }, actorUserId: 'isolated-maker', boundary }),
      /gateway deterministic render rejection/);
    assert.deepEqual(operations, ['DIAGNOSTIC_LEASE', 'DIAGNOSTIC_ABORT']);
    assert.equal(sends, 0);
    renderer.resolvePrinterLanguageRenderer = realRender;

    reset(); baselineFailure = true;
    await assert.rejects(run(), /baseline unavailable/);
    assert.deepEqual(operations, ['DIAGNOSTIC_LEASE', 'DIAGNOSTIC_ABORT']);
    assert.equal(sends, 0);

    reset(); sendFailure = true;
    await assert.rejects(run(), /transport outcome uncertain/);
    assert.deepEqual(operations, ['DIAGNOSTIC_LEASE']);
    assert.equal(sends, 1);

    reset();
    const completed = await run();
    assert.equal(completed.outcome, 'confirmed');
    assert.deepEqual(operations, ['DIAGNOSTIC_LEASE', 'DIAGNOSTIC_COMPLETE']);
    assert.equal(sends, 1);

    reset(); baselineFailure = true; closureFailure = true;
    await assert.rejects(run(), /lease closure is unverified/);
    assert.deepEqual(operations, ['DIAGNOSTIC_LEASE', 'DIAGNOSTIC_ABORT']);
    assert.equal(sends, 0);
    console.log('PASS diagnostic lease pre-dispatch closure, uncertain send and completion');
  } finally {
    repository.administerPrintingPrinter = originals.administer;
    zebra.getZebraTotalLabelCount = originals.baseline;
    zebra.waitForZebraLabelConfirmation = originals.confirm;
    socket.sendRawPayloadToNetworkPrinter = originals.send;
    renderer.resolvePrinterLanguageRenderer = originals.render;
    tokens.signQrPayload = originals.sign;
    tokens.buildScanUrl = originals.scan;
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
