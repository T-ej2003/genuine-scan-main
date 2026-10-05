const assert = require('node:assert/strict');
const { test } = require('node:test');
const crypto = require('node:crypto');
const originalFunctions = require('../dist/rls-waves/session-b/b03/repositoryFunctions');
const digest = originalFunctions.b03PayloadDigest;
let claims = [], delivered = [], invalidations = [], completed = 0, failed = 0, uncertain = false, unavailable = false, cacheFailure = false, subscriber;
const stub = (name, exports) => { const id = require.resolve('../dist/' + name); require.cache[id] = { id, filename: id, loaded: true, exports }; };
stub('config/database', { default: {} });
stub('services/redisService', { getRedisInstanceId: () => 'fixture', subscribeRedisJson: async (_, cb) => { subscriber = cb; },
  publishRedisJson: async (_, value) => { if (unavailable) return false; subscriber?.({ ...value, origin: 'other-instance' }); if (uncertain) { uncertain = false; throw new Error('UNCERTAIN_REDIS_RESPONSE'); } return true; } });
stub('services/versionedCacheService', { bumpCacheNamespaceVersion: async name => { if (cacheFailure) throw new Error('CACHE_UNAVAILABLE'); invalidations.push(name); } });
stub('rls-waves/session-b/b03/repositoryFunctions', { ...originalFunctions,
  claimSecurityEventOutboxSlice: async (_, input) => input.jobType === 'AUDIT_LOG' ? claims : [],
  completeSecurityEventOutbox: async () => { completed++; }, failSecurityEventOutbox: async () => { failed++; } });
stub('rls-waves/session-b/b03/systemContext', { withB03SiemWorkerContext: async (_, cb) => cb({}) });
process.env.SIEM_SINK_MODE = 'stdout';
const { onAuditLog } = require('../dist/services/auditService');
const { flushSecurityEventOutbox } = require('../dist/services/siemOutboxService');
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
