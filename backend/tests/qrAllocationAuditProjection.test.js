const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const originalFunctions = require('../dist/rls-waves/session-b/b03/repositoryFunctions');
const digest = originalFunctions.b03PayloadDigest;
let claims = [], delivered = [], invalidations = [], completed = 0, skipped = 0, failed = 0, uncertain = false, unavailable = false, cacheFailure = false, subscriber;
const stub = (name, exports) => { const id = require.resolve('../dist/' + name); require.cache[id] = { id, filename: id, loaded: true, exports }; };
stub('config/database', { default: {} });
stub('services/redisService', { getRedisInstanceId: () => 'fixture', subscribeRedisJson: async (_, cb) => { subscriber = cb; },
  publishRedisJson: async (_, value) => { if (unavailable) return false; subscriber?.({ ...value, origin: 'other-instance' }); if (uncertain) { uncertain = false; throw new Error('UNCERTAIN_REDIS_RESPONSE'); } return true; } });
stub('services/versionedCacheService', { bumpCacheNamespaceVersion: async name => { if (cacheFailure) throw new Error('CACHE_UNAVAILABLE'); invalidations.push(name); } });
stub('rls-waves/session-b/b03/repositoryFunctions', { ...originalFunctions,
  claimSecurityEventOutboxSlice: async (_, input) => input.jobType === 'AUDIT_LOG' ? claims.filter(row => !row.terminal) : [],
  completeSecurityEventOutbox: async (_, input) => {
    const row = claims.find(row => row.id === input.jobId);
    if (input.sinkEventId === `projection:${row.id}`) { row.projectionCompleted = true; return; }
    row.terminal = true;
    if (input.sinkEventId === `disabled:${row.id}`) { skipped++; } else { completed++; }
  }, failSecurityEventOutbox: async () => { failed++; } });
stub('rls-waves/session-b/b03/systemContext', { withB03SiemWorkerContext: async (_, cb) => cb({}) });
process.env.SIEM_SINK_MODE = 'stdout';
const { onAuditLog } = require('../dist/services/auditService');
const { flushSecurityEventOutbox, startSecurityEventOutboxWorker, stopSecurityEventOutboxWorker } = require('../dist/services/siemOutboxService');
const { appendForensicChainFromAuditLog } = require('../dist/services/forensicChainService');
const { createTraceEventFromAuditLog } = require('../dist/services/traceEventService');
const claim = action => { const log = { id: crypto.randomUUID(), action, entityType: 'QrAllocationRequest', entityId: crypto.randomUUID(), userId: crypto.randomUUID(), orgId: crypto.randomUUID(), licenseeId: crypto.randomUUID(), details: { quantity: 3 }, createdAt: new Date().toISOString() };
  return { id: crypto.randomUUID(), jobType: 'AUDIT_LOG', eventType: 'AUDIT_LOG', eventPayload: log, payloadDigest: digest(log), requestId: crypto.randomUUID(), organizationId: log.orgId, licenseeId: log.licenseeId, manufacturerId: null, initiatingUserId: log.userId, expiresAt: new Date(Date.now() + 86400000), attempt: 1, createdAt: new Date() }; };

test('CREATE/REJECT durable audit projections retry safely without inserting audit or forensic duplicates', async () => {
  const stop = onAuditLog(log => delivered.push(log));
  try {
    for (const action of ['CREATE_QR_ALLOCATION_REQUEST', 'REJECT_QR_ALLOCATION_REQUEST']) {
      const row = claim(action); claims = [row]; uncertain = true;
      const before = delivered.length, beforeComplete = completed, beforeFailed = failed;
      await flushSecurityEventOutbox(); assert.equal(failed, beforeFailed + 1); assert.equal(completed, beforeComplete);
      await flushSecurityEventOutbox(); assert.equal(completed, beforeComplete + 1); assert.equal(delivered.length, before + 1);
      assert.equal(delivered.at(-1).id, row.eventPayload.id);
      // Historical classification is null for both actions, not a missing chain write.
      assert.equal(await appendForensicChainFromAuditLog({ ...row.eventPayload, createdAt: new Date() }, {
        $executeRaw: () => { throw new Error('Unexpected forensic write'); }, forensicEventChain: new Proxy({}, { get() { throw new Error('Unexpected forensic access'); } }) }), null);
      assert.equal(await createTraceEventFromAuditLog({ ...row.eventPayload, createdAt: new Date() }), null);
      assert.deepEqual(new Set(invalidations), new Set(['dashboard-snapshot', 'attention-queue', 'qr-batches', 'print-jobs']));
    }
    for (const failure of ['cache', 'redis']) {
      claims = [claim('REJECT_QR_ALLOCATION_REQUEST')];
      cacheFailure = failure === 'cache'; unavailable = failure === 'redis';
      const before = delivered.length, sent = completed, rejected = failed;
      await flushSecurityEventOutbox();
      assert.equal(completed, sent); assert.equal(delivered.length, before); assert.equal(failed, rejected + 1);
      cacheFailure = false; unavailable = false;
    }
    const row = claim('CREATE_QR_ALLOCATION_REQUEST'); row.licenseeId = crypto.randomUUID(); claims = [row]; const before = delivered.length, sent = completed;
    await flushSecurityEventOutbox(); assert.equal(delivered.length, before); assert.equal(completed, sent);
    row.licenseeId = row.eventPayload.licenseeId; row.eventPayload.details = { substituted: true };
    await flushSecurityEventOutbox(); assert.equal(delivered.length, before); assert.equal(completed, sent);
  } finally { stop(); claims = []; }
});


test('optional SIEM delivery does not gate internal projections or claim disabled delivery succeeded', async () => {
  const stop = onAuditLog(log => delivered.push(log));
  const oldFetch = global.fetch;
  try {
    process.env.SIEM_SINK_MODE = 'webhook'; delete process.env.SIEM_WEBHOOK_URL;
    const originalSetInterval = global.setInterval, originalClearInterval = global.clearInterval;
    let scheduled = false;
    try {
      global.setInterval = () => { scheduled = true; return { unref() {} }; };
      global.clearInterval = () => {};
      startSecurityEventOutboxWorker(); assert.equal(scheduled, true); stopSecurityEventOutboxWorker();
    } finally { global.setInterval = originalSetInterval; global.clearInterval = originalClearInterval; }
    let networkCalls = 0;
    global.fetch = async () => { networkCalls++; throw new Error('Unexpected webhook'); };
    for (const action of ['CREATE_QR_ALLOCATION_REQUEST', 'REJECT_QR_ALLOCATION_REQUEST']) {
      claims = [claim(action)];
      const before = delivered.length, bumps = invalidations.length, sent = completed, disabled = skipped;
      await flushSecurityEventOutbox(); await flushSecurityEventOutbox();
      assert.equal(delivered.length, before + 1); assert.equal(invalidations.length, bumps + 4);
      assert.equal(completed, sent); assert.equal(skipped, disabled + 1); assert.equal(networkCalls, 0);
    }
    process.env.SIEM_WEBHOOK_URL = 'https://siem.example.invalid/events';
    for (const action of ['CREATE_QR_ALLOCATION_REQUEST', 'REJECT_QR_ALLOCATION_REQUEST']) {
      let attempts = 0;
      global.fetch = async (_url, options) => {
        assert.equal(options.headers['Idempotency-Key'], claims[0].id);
        return { ok: ++attempts > 1, status: 503 };
      };
      claims = [claim(action)];
      const before = delivered.length, bumps = invalidations.length, sent = completed;
      await flushSecurityEventOutbox();
      assert.equal(claims[0].projectionCompleted, true); assert.equal(completed, sent);
      await flushSecurityEventOutbox(); await flushSecurityEventOutbox();
      assert.equal(attempts, 2); assert.equal(completed, sent + 1);
      assert.equal(delivered.length, before + 1); assert.equal(invalidations.length, bumps + 4);
    }
  } finally { stop(); claims = []; global.fetch = oldFetch; delete process.env.SIEM_WEBHOOK_URL; process.env.SIEM_SINK_MODE = 'stdout'; }
});


test('QR rollback names the exact IP-attributed audit function signatures', () => {
  const fs = require('node:fs'), path = require('node:path');
  const sql = fs.readFileSync(path.join(__dirname, '../src/rls-waves/session-c/c01/qrSystemRollback.sql'), 'utf8');
  for (const signature of ['qr_create_allocation_request(text,text,text,text,integer,text,text,text)',
    'qr_reject_allocation_request(text,text,text,text,text,text)', 'qr_write_audit(text,text,text,text,text,text,jsonb,text)']) {
    assert(sql.includes(`DROP FUNCTION IF EXISTS app_rls.${signature};`));
  }
});
