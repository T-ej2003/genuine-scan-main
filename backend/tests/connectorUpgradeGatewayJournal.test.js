const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { inspectDispatchJournal, dispatchReservationKey } = require('../dist/local-print-agent/dispatchJournal');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-upgrade-gateway-journal-'));
process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR = root;
process.env.PRINT_GATEWAY_ID = 'gateway-fixture';
const write = (job, item, record, suffix = '') => {
  fs.writeFileSync(path.join(root, `${dispatchReservationKey(job, item)}${suffix}.json`),
    JSON.stringify({ journalVersion: 2, printJobId: job, printItemId: item, ...record }));
};

(async () => {
  try {
    write('local-job', 'local-item', { printerId: 'selected-local-printer', state: 'ATTEMPT_RESERVED' });
    write('gateway-job', 'gateway-item', { printerId: 'gateway-fixture', gatewayId: 'gateway-fixture', state: 'ATTEMPT_RESERVED' });
    write('gateway-job', 'gateway-item', { gatewayId: 'gateway-fixture', state: 'PREPARING' }, '.gateway-attempt');
    write('historical-gateway-job', 'historical-gateway-item', { printerId: 'gateway-fixture', state: 'ATTEMPT_RESERVED' });
    write('historical-gateway-job', 'historical-gateway-item', { gatewayId: 'gateway-fixture', state: 'PREPARING' }, '.gateway-attempt');
    process.env.PRINT_GATEWAY_ID = 'replacement-gateway';
    const journal = await inspectDispatchJournal();
    assert.equal(journal.count, 5);
    assert.equal(journal.entries.filter(entry => entry.gatewayId === 'gateway-fixture').length, 4);
    assert.equal(journal.entries.filter(entry => entry.gatewayId === undefined).length, 1);
    write('forged-job', 'forged-item', { printerId: 'selected-local-printer', gatewayId: 'gateway-fixture', state: 'ATTEMPT_RESERVED' });
    await assert.rejects(inspectDispatchJournal(), /reconciliation/i);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
