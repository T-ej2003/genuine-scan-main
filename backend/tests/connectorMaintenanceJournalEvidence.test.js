const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');

(async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'mscqr-upgrade-journal-'));
  process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR = path.join(root, 'journal');
  const journal = require('../dist/local-print-agent/dispatchJournal');
  try {
    const empty = await journal.inspectDispatchJournal();
    assert.equal(empty.count, 0);
    for (let index = 0; index < 12; index++) {
      assert.equal(await journal.reserveAutomaticDispatch({ printJobId: `job-${index}`, printItemId: `item-${index}`,
        printerId: 'printer-1', payloadHash: createHash('sha256').update(String(index)).digest('hex') }), true);
    }
    const result = await journal.inspectDispatchJournal();
    assert.equal(result.count, 12);
    assert.equal(result.entries.length, 12);
    assert(result.entries.every(entry => entry.state === 'ATTEMPT_RESERVED'));
    assert.notEqual(result.sha256, empty.sha256);
    assert.equal((await journal.inspectDispatchJournal()).sha256, result.sha256);
    assert.equal(await journal.priorDispatchExists({ printJobId: 'job-0', printItemId: 'item-0' }), true);
    await fs.writeFile(path.join(process.env.PRINT_AGENT_DISPATCH_JOURNAL_DIR, 'unexpected.txt'), 'unsafe');
    await assert.rejects(journal.inspectDispatchJournal(), { errorCode: 'dispatch_reconciliation_required' });
    console.log('connector maintenance journal evidence tests passed');
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
