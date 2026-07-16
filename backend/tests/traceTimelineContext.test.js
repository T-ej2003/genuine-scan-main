const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { TraceEventType, UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const { withCanonicalDbContext } = require("../dist/lib/canonicalDbContext");
const {
  TraceTimelineAccessError,
  buildTraceTimelineBoundary,
  getTraceTimeline,
} = require("../dist/services/traceEventService");

const ids = {
  tenant: "11111111-1111-4111-8111-111111111111",
  foreignTenant: "22222222-2222-4222-8222-222222222222",
  org: "33333333-3333-4333-8333-333333333333",
  actor: "44444444-4444-4444-8444-444444444444",
  manufacturer: "55555555-5555-4555-8555-555555555555",
  platform: "66666666-6666-4666-8666-666666666666",
};

const actor = (overrides = {}) => ({
  userId: ids.actor,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.org,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  mfaVerifiedAt: null,
  ...overrides,
});

const query = (overrides = {}) => ({ limit: 50, offset: 0, ...overrides });

const fakeRunner = () => {
  const events = [];
  const calls = { find: [], count: [], contextValues: [] };
  let contextInstalled = false;
  const requireContext = () => assert(contextInstalled, "protected query attempted before canonical context installation");
  const tx = {
    $executeRaw: async (strings, ...values) => {
      events.push("context");
      calls.contextValues.push(values);
      contextInstalled = true;
      assert.match(strings.join("?"), /set_config\('app\.purpose'/);
      return 1;
    },
    traceEvent: {
      findMany: async (args) => {
        requireContext();
        events.push("list");
        calls.find.push(args);
        return [{
          id: "event-a",
          eventType: TraceEventType.SCANNED,
          licenseeId: ids.tenant,
          batchId: null,
          qrCodeId: null,
          manufacturerId: null,
          userId: ids.actor,
          sourceAction: "SCAN",
          details: { safe: "retained", accessToken: "secret", nested: [{ privateKey: "secret-key" }] },
          createdAt: new Date("2026-07-16T10:00:00.000Z"),
          user: { id: ids.actor, name: "Tenant Admin", email: "admin@example.test" },
          manufacturer: null,
          batch: null,
          qrCode: null,
        }];
      },
      count: async (args) => {
        requireContext();
        events.push("count");
        calls.count.push(args);
        return 1;
      },
    },
  };
  return {
    calls,
    events,
    tx,
    runner: {
      $transaction: async (callback, options) => {
        calls.transactionOptions = options;
        events.push("transaction-begin");
        const result = await callback(tx);
        events.push("transaction-end");
        contextInstalled = false;
        return result;
      },
    },
  };
};

const read = async (user, input, requestId = "request-a") => {
  const fake = fakeRunner();
  const boundary = buildTraceTimelineBoundary(user, input, requestId);
  const result = await withCanonicalDbContext(
    fake.runner,
    boundary.context,
    (tx) => getTraceTimeline(tx, boundary.query, boundary.context),
    { isolationLevel: "RepeatableRead" }
  );
  return { boundary, fake, result };
};

const denied = (user, input, message, requestId = "request-denied") => {
  assert.throws(
    () => buildTraceTimelineBoundary(user, input, requestId),
    (error) => error instanceof TraceTimelineAccessError && error.message.includes(message)
  );
};

(async () => {
  const tenant = await read(actor(), query({ eventType: TraceEventType.SCANNED }));
  assert.deepStrictEqual(tenant.fake.events, ["transaction-begin", "context", "list", "count", "transaction-end"]);
  assert.strictEqual(tenant.fake.calls.find[0].where, tenant.fake.calls.count[0].where, "list and count must share one scope object");
  assert.strictEqual(tenant.fake.calls.find[0].where.licenseeId, ids.tenant);
  assert.strictEqual(tenant.fake.calls.transactionOptions.isolationLevel, "RepeatableRead");
  assert.deepStrictEqual(tenant.fake.calls.find[0].orderBy, [{ createdAt: "desc" }, { id: "desc" }]);
  assert(tenant.fake.calls.find[0].select && !tenant.fake.calls.find[0].include, "trace rows require an explicit projection");
  assert.doesNotMatch(JSON.stringify(tenant.result), /secret|secret-key/);
  assert.match(JSON.stringify(tenant.result), /retained/);

  const manufacturer = await read(actor({
    userId: ids.manufacturer,
    role: UserRole.MANUFACTURER,
    licenseeId: null,
    linkedLicenseeIds: [ids.tenant],
  }), query({ licenseeId: ids.tenant }));
  assert.strictEqual(manufacturer.boundary.query.manufacturerId, ids.manufacturer);
  assert.strictEqual(manufacturer.fake.calls.find[0].where.manufacturerId, ids.manufacturer);

  const platform = await read(actor({
    userId: ids.platform,
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date().toISOString(),
  }), query({ licenseeId: ids.tenant, purpose: "review trace incident IR-42" }));
  assert.strictEqual(platform.boundary.context.licenseeId, ids.tenant);
  assert.strictEqual(platform.boundary.context.authAssurance, "mfa-verified");
  assert.strictEqual(platform.fake.calls.contextValues[0][7], "review trace incident IR-42");

  denied(actor(), query({ licenseeId: ids.foreignTenant }), "licensee");
  denied(actor({ licenseeId: null }), query(), "tenant scope");
  denied(actor({ licenseeId: " " }), query(), "tenant scope");
  denied(actor({ sessionStage: "MFA_BOOTSTRAP" }), query(), "actor context");
  denied(actor({ authAssurance: "unsupported" }), query(), "Unsupported");
  denied(actor({ userId: "" }), query(), "actor context");
  denied(actor(), query(), "actor context", "");
  denied(actor({ userId: ids.manufacturer, role: UserRole.MANUFACTURER, linkedLicenseeIds: [ids.tenant] }), query({ licenseeId: ids.foreignTenant }), "licensee");
  denied(actor({ userId: ids.manufacturer, role: UserRole.MANUFACTURER, linkedLicenseeIds: [ids.tenant] }), query({ licenseeId: ids.tenant, manufacturerId: ids.platform }), "manufacturer");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null }), query({ licenseeId: ids.tenant, purpose: "review" }), "MFA");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, authAssurance: "ADMIN_MFA", mfaVerifiedAt: new Date().toISOString() }), query({ purpose: "review" }), "bounded licensee");
  denied(actor({ userId: ids.platform, role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, authAssurance: "ADMIN_MFA", mfaVerifiedAt: new Date().toISOString() }), query({ licenseeId: ids.tenant }), "purpose");

  const mismatch = fakeRunner();
  const boundary = buildTraceTimelineBoundary(actor(), query(), "request-mismatch");
  await assert.rejects(
    withCanonicalDbContext(mismatch.runner, boundary.context, (tx) => getTraceTimeline(tx, { ...boundary.query, licenseeId: ids.foreignTenant }, boundary.context)),
    /scope does not match/
  );
  assert.deepStrictEqual(mismatch.events, ["transaction-begin", "context"]);

  const beforeContext = fakeRunner();
  await assert.rejects(getTraceTimeline(beforeContext.tx, boundary.query, boundary.context), /before canonical context installation/);

  const root = path.resolve(__dirname, "..");
  const serviceSource = fs.readFileSync(path.join(root, "src/services/traceEventService.ts"), "utf8");
  const controllerSource = fs.readFileSync(path.join(root, "src/controllers/tracePolicyController.ts"), "utf8");
  const timelineBody = serviceSource.match(/export const getTraceTimeline[\s\S]*?\n};/)?.[0] || "";
  const controllerBody = controllerSource.match(/export const getTraceTimelineController[\s\S]*?export const getBatchSlaAnalyticsController/)?.[0] || "";
  assert(!/prisma\.traceEvent\./.test(timelineBody), "timeline query must use only its transaction client");
  assert.match(controllerBody, /withCanonicalDbContext\(/);
  assert.match(controllerBody, /TransactionIsolationLevel\.RepeatableRead/);

  console.log("trace timeline context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
