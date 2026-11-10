const assert = require("node:assert/strict");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const diagnostics = { setupMs: 0, projectionMs: 0, deny: false, projectionFails: false };
const projection = {
  incidents: { count: 0, latest: null },
  policyAlerts: { count: 0, latest: null },
  supportTickets: { count: 0, latest: null },
  auditEvents: { count: 0, latest: null },
};
const mocks = {
  "middleware/tenantIsolation": { getEffectiveLicenseeId: () => null },
  "services/manufacturerScopeService": {
    isManufacturerRole: () => true,
    resolveAccessibleLicenseeIdsForUser: async () => [],
  },
  "services/notificationService": {
    listNotificationsForUser: async () => ({ notifications: [], unread: 0, total: 0 }),
  },
  "services/versionedCacheService": {
    getOrComputeVersionedCache: async (_namespace, _key, _ttl, work) => work(),
  },
  "rls-waves/session-c/c02/printingLifecycleRepository": {
    readPrintingProjection: async () => ({ count: 0, latest: null }),
  },
  "rls-waves/session-b/b03/requestBoundary": {
    b03BoundaryForRequest: () => ({
      requestId: "11111111-1111-4111-8111-111111111111",
      run: async (callback) => {
        if (diagnostics.setupMs) await sleep(diagnostics.setupMs);
        if (diagnostics.deny) throw new Error("sensitive authentication detail");
        return callback({});
      },
    }),
  },
  "rls-waves/session-b/b03/repositoryFunctions": {
    readAttentionQueueProjection: async () => {
      if (diagnostics.projectionMs) await sleep(diagnostics.projectionMs);
      if (diagnostics.projectionFails) throw new Error("sensitive projection detail");
      return projection;
    },
  },
};
for (const [module, exports] of Object.entries(mocks)) {
  const id = require.resolve(`../dist/${module}`);
  require.cache[id] = { id, filename: id, loaded: true, exports };
}
const { getAttentionQueueSnapshot } = require("../dist/services/attentionQueueService");
const requestId = "11111111-1111-4111-8111-111111111111";
const diagnosticRequestId = "22222222-2222-4222-8222-222222222222";
const req = {
  requestId,
  diagnosticRequestId,
  user: { userId: "fixture-actor", role: "MANUFACTURER_ADMIN" },
  databaseSessionCapability: "fixture-capability",
};

(async () => {
  const originalInfo = console.info;
  const events = [];
  console.info = (message) => events.push(JSON.parse(message));
  try {
    diagnostics.setupMs = 260;
    await getAttentionQueueSnapshot(req);
    assert.deepEqual(events.map(({ stage }) => stage), ["attention-transaction"]);
    assert.equal(events[0].diagnosticRequestId, diagnosticRequestId);
    events.length = 0;

    diagnostics.setupMs = 0;
    diagnostics.projectionMs = 260;
    await getAttentionQueueSnapshot(req);
    assert.deepEqual(events.map(({ stage }) => stage), ["attention-projection", "attention-transaction"]);
    events.length = 0;

    diagnostics.projectionMs = 0;
    diagnostics.deny = true;
    await assert.rejects(getAttentionQueueSnapshot(req), /sensitive authentication detail/);
    assert.deepEqual(events.map(({ stage, outcome }) => [stage, outcome]), [["attention-transaction", "error"]]);
    events.length = 0;

    diagnostics.deny = false;
    diagnostics.projectionFails = true;
    await assert.rejects(getAttentionQueueSnapshot(req), /sensitive projection detail/);
    assert.deepEqual(events.map(({ stage, outcome }) => [stage, outcome]), [
      ["attention-projection", "error"], ["attention-transaction", "error"],
    ]);
    assert.ok(events.every((event) => !JSON.stringify(event).includes("sensitive")));
  } finally {
    console.info = originalInfo;
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
