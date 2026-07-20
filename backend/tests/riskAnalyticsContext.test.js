const assert = require("assert");
const { execFileSync } = require("node:child_process");
const fs = require("fs");
const path = require("path");
const { UserRole, UserStatus } = require("@prisma/client");

process.env.NODE_ENV = "test";

const { withCanonicalDbContext } = require("../dist/lib/canonicalDbContext");
const {
  buildRiskAnalyticsBoundary,
  getRiskAnalytics,
  RISK_ANALYTICS_MAX_CANDIDATE_BATCHES,
  RISK_ANALYTICS_MAX_DIMENSION_ROWS,
  RISK_ANALYTICS_MAX_OPEN_ALERT_ROWS,
  RiskAnalyticsAccessError,
} = require("../dist/services/analyticsService");

const ids = {
  tenant: "11111111-1111-4111-8111-111111111111",
  foreign: "22222222-2222-4222-8222-222222222222",
  organization: "33333333-3333-4333-8333-333333333333",
  actor: "44444444-4444-4444-8444-444444444444",
};
const now = new Date("2026-07-16T12:00:00.000Z");

const actor = (overrides = {}) => ({
  userId: ids.actor,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.organization,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  mfaVerifiedAt: null,
  ...overrides,
});

const input = (overrides = {}) => ({
  requestedLicenseeId: ids.tenant,
  lookbackHours: 24,
  limit: 20,
  ...overrides,
});

const scanRow = (overrides = {}) => {
  const batchId = Object.prototype.hasOwnProperty.call(overrides, "batchId") ? overrides.batchId : "batch-a";
  const qrCodeId = overrides.qrCodeId || "qr-a";
  const licenseeId = overrides.licenseeId || ids.tenant;
  return {
    id: overrides.id || `scan-${qrCodeId}-${overrides.scannedAt?.getTime?.() || "1"}`,
    licenseeId,
    qrCodeId,
    batchId,
    latitude: overrides.latitude ?? null,
    longitude: overrides.longitude ?? null,
    scannedAt: overrides.scannedAt || now,
    qrCode: Object.prototype.hasOwnProperty.call(overrides, "qrCode")
      ? overrides.qrCode
      : { id: qrCodeId, licenseeId: overrides.qrLicenseeId || licenseeId, batchId: overrides.qrBatchId === undefined ? batchId : overrides.qrBatchId },
    batch: Object.prototype.hasOwnProperty.call(overrides, "batch")
      ? overrides.batch
      : batchId ? { id: batchId, licenseeId: overrides.batchLicenseeId || licenseeId } : null,
  };
};

const alertRow = (batchId = "batch-a", overrides = {}) => ({
  id: overrides.id || `alert-${batchId}`,
  licenseeId: overrides.licenseeId || ids.tenant,
  batchId,
  qrCodeId: overrides.qrCodeId ?? null,
  manufacturerId: overrides.manufacturerId ?? null,
  incidentId: overrides.incidentId ?? null,
  policyRuleId: overrides.policyRuleId ?? null,
  acknowledgedAt: null,
});

const actorRow = (overrides = {}) => ({
  id: ids.actor,
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.organization,
  isActive: true,
  status: UserStatus.ACTIVE,
  deletedAt: null,
  disabledAt: null,
  ...overrides,
});

const fakeRunner = (overrides = {}) => {
  const events = [];
  const calls = { contextValues: [], actor: [], licensee: [], organization: [], policy: [], batch: [], qr: [], alertQr: [], scan: [], alert: [], manufacturer: [], alertManufacturer: [], manufacturerLink: [], incident: [], policyRule: [], audit: [], transactionOptions: null };
  let contextInstalled = false;
  const protectedCall = (name, collection, value) => async (args) => {
    assert(contextInstalled, `${name} attempted before canonical context installation`);
    events.push(name);
    calls[collection].push(args);
    return value;
  };
  const tenant = overrides.tenant === undefined
    ? { id: ids.tenant, orgId: ids.organization, isActive: true, suspendedAt: null }
    : overrides.tenant;
  const organization = overrides.organization === undefined
    ? { id: ids.organization, isActive: true }
    : overrides.organization;
  const batchRows = overrides.batchRows === undefined ? [{
    id: "batch-a",
    name: "Batch A",
    licenseeId: ids.tenant,
    manufacturerId: "manufacturer-a",
  }] : overrides.batchRows;
  const tx = {
    $executeRaw: async (strings, ...values) => {
      const sql = strings.join("?");
      if (/INSERT INTO public\."AuditLog"/.test(sql)) {
        assert(contextInstalled, "audit attempted before canonical context installation");
        assert.match(sql, /\("id", "userId", "orgId", "licenseeId", "action", "entityType", "entityId", "details"\)/);
        assert(!sql.includes("createdAt"), "database owns immutable audit creation time");
        events.push("audit");
        calls.audit.push({
          data: {
            userId: values[1],
            orgId: values[2],
            licenseeId: values[3],
            action: "RISK_ANALYTICS_READ",
            entityType: "Licensee",
            entityId: values[4],
            details: JSON.parse(values[5]),
          },
        });
        return 1;
      }
      events.push("context");
      contextInstalled = true;
      calls.contextValues.push(values);
      assert.match(sql, /set_config\('app\.licensee_id'/);
      assert.strictEqual(values[7], "tenant-risk-analytics");
      return 1;
    },
    $queryRaw: async (strings, ...values) => {
      assert(contextInstalled, "policy attempted before canonical context installation");
      assert.match(strings.join("?"), /SELECT "multiScanThreshold", "geoDriftThresholdKm", "velocitySpikeThresholdPerMin"[\s\S]*FROM public\."SecurityPolicy"[\s\S]*WHERE "licenseeId" = \?/);
      events.push("policy");
      calls.policy.push(values);
      return [{
        multiScanThreshold: 2,
        geoDriftThresholdKm: 300,
        velocitySpikeThresholdPerMin: 2,
      }];
    },
    licensee: { findUnique: protectedCall("licensee", "licensee", tenant) },
    organization: { findUnique: protectedCall("organization", "organization", organization) },
    user: {
      findUnique: protectedCall("actor", "actor", overrides.actorRow === undefined ? actorRow() : overrides.actorRow),
      findMany: async (args) => args.select?.name
        ? protectedCall("manufacturer", "manufacturer", overrides.manufacturerRows === undefined ? [{ id: "manufacturer-a", name: "Manufacturer A" }] : overrides.manufacturerRows)(args)
        : protectedCall("alert-manufacturer", "alertManufacturer", overrides.alertManufacturerRows || [])(args),
    },
    batch: {
      findMany: protectedCall("batch", "batch", batchRows),
    },
    qRCode: {
      findMany: async (args) => args.select?.scanCount
        ? protectedCall("qr", "qr", overrides.qrRows || [{ batchId: "batch-a", scanCount: 2 }])(args)
        : protectedCall("alert-qr", "alertQr", overrides.alertQrRows || [])(args),
    },
    qrScanLog: {
      findMany: protectedCall("scan", "scan", overrides.scanRows === undefined ? [
        scanRow({ id: "scan-a-1", latitude: 0, longitude: 0, scannedAt: new Date("2026-07-16T11:00:00.000Z") }),
        scanRow({ id: "scan-a-2", latitude: 0, longitude: 10, scannedAt: new Date("2026-07-16T11:00:30.000Z") }),
      ] : overrides.scanRows),
    },
    policyAlert: {
      findMany: protectedCall("alert", "alert", overrides.alertRows === undefined ? [alertRow("batch-a", { id: "alert-a" }), alertRow("batch-a", { id: "alert-b" })] : overrides.alertRows),
    },
    manufacturerLicenseeLink: {
      findMany: protectedCall("manufacturer-link", "manufacturerLink", overrides.alertManufacturerLinkRows || []),
    },
    incident: { findMany: protectedCall("incident", "incident", overrides.incidentRows || []) },
    policyRule: { findMany: protectedCall("policy-rule", "policyRule", overrides.policyRuleRows || []) },
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
        return result;
      },
    },
  };
};

const denied = (user, query, requestId, message) => assert.throws(
  () => buildRiskAnalyticsBoundary(user, query, requestId),
  (error) => error instanceof RiskAnalyticsAccessError && error.message.includes(message)
);

(async () => {
  const fake = fakeRunner();
  const boundary = buildRiskAnalyticsBoundary(actor(), input(), "request-risk-a");
  let serialized = false;
  const result = await withCanonicalDbContext(
    fake.runner,
    boundary.context,
    async (tx, installed) => {
      const data = await getRiskAnalytics(tx, boundary.query, installed, now);
      assert.strictEqual(serialized, false, "serialization must happen after protected reads");
      return data;
    },
    { isolationLevel: "RepeatableRead" }
  );
  serialized = true;

  assert.deepStrictEqual(fake.events, [
    "transaction-begin", "context", "actor", "licensee", "organization", "policy", "scan", "alert", "batch", "qr", "manufacturer", "audit", "transaction-end",
  ]);
  assert.strictEqual(fake.calls.transactionOptions.isolationLevel, "RepeatableRead");
  assert.strictEqual(fake.calls.contextValues[0][3], ids.tenant);
  assert.deepStrictEqual(fake.calls.actor[0].select, {
    id: true,
    role: true,
    licenseeId: true,
    orgId: true,
    isActive: true,
    status: true,
    deletedAt: true,
    disabledAt: true,
  });
  assert.deepStrictEqual(Object.keys(fake.calls.actor[0].select), [
    "id", "role", "licenseeId", "orgId", "isActive", "status", "deletedAt", "disabledAt",
  ]);
  assert.strictEqual(fake.calls.batch[0].where.licenseeId, ids.tenant);
  assert(!("id" in fake.calls.batch[0].where), "every scoped tenant batch remains in the historical analytics universe");
  assert.deepStrictEqual(fake.calls.batch[0].orderBy, { id: "asc" });
  assert.strictEqual(fake.calls.batch[0].take, RISK_ANALYTICS_MAX_CANDIDATE_BATCHES + 1);
  assert(!("createdAt" in fake.calls.batch[0].where), "batch creation time must not replace activity lookback");
  assert.strictEqual(fake.calls.qr[0].where.licenseeId, ids.tenant);
  assert.strictEqual(fake.calls.qr[0].take, RISK_ANALYTICS_MAX_DIMENSION_ROWS + 1);
  assert.strictEqual(fake.calls.scan[0].where.licenseeId, ids.tenant);
  assert.deepStrictEqual(fake.calls.scan[0].where.batchId, { not: null });
  assert.strictEqual(fake.calls.scan[0].take, RISK_ANALYTICS_MAX_DIMENSION_ROWS + 1);
  assert.strictEqual(fake.calls.alert[0].where.licenseeId, ids.tenant);
  assert.deepStrictEqual(fake.calls.alert[0].where.batchId, { not: null }, "nullable unresolved alerts remain outside batch scoring");
  assert.strictEqual(fake.calls.scan[0].where.scannedAt.gte.toISOString(), "2026-07-15T12:00:00.000Z");
  assert.strictEqual(fake.calls.scan[0].where.scannedAt.lte, now);
  assert.strictEqual(fake.calls.alert[0].where.acknowledgedAt, null);
  assert(!("createdAt" in fake.calls.alert[0].where), "old unresolved alerts must remain open");
  assert.strictEqual(fake.calls.alert[0].take, RISK_ANALYTICS_MAX_OPEN_ALERT_ROWS + 1);
  assert.deepStrictEqual(fake.calls.scan[0].select, {
    id: true,
    licenseeId: true,
    qrCodeId: true,
    batchId: true,
    latitude: true,
    longitude: true,
    scannedAt: true,
    qrCode: { select: { id: true, licenseeId: true, batchId: true } },
    batch: { select: { id: true, licenseeId: true } },
  });
  assert.deepStrictEqual(fake.calls.alert[0].select, {
    id: true,
    licenseeId: true,
    batchId: true,
    qrCodeId: true,
    manufacturerId: true,
    incidentId: true,
    policyRuleId: true,
    acknowledgedAt: true,
  });
  assert.deepStrictEqual(fake.calls.manufacturer[0].select, { id: true, name: true });
  assert.deepStrictEqual(Object.keys(fake.calls.manufacturer[0].select), ["id", "name"]);
  assert.strictEqual(fake.calls.manufacturer[0].where.assignedBatches.some.licenseeId, ids.tenant);
  assert.strictEqual(fake.calls.audit[0].data.licenseeId, ids.tenant);
  assert.deepStrictEqual(fake.calls.audit[0].data.details, {
    actorId: ids.actor,
    role: UserRole.LICENSEE_ADMIN,
    assurance: "password-verified",
    requestId: "request-risk-a",
    purposeCode: "tenant-risk-analytics",
    organizationId: ids.organization,
    licenseeId: ids.tenant,
    workflowId: "workflow-internal-backend-src-services-analytics-service-ts-get-risk-analytics",
    route: "GET /api/analytics/risk-scores",
    outcome: "SUCCESS",
    lookbackHours: 24,
    limit: 20,
    analyzedBatchCount: 1,
    returnedBatchCount: 1,
    analyzedManufacturerCount: 1,
    timestamp: now.toISOString(),
  });
  assert.strictEqual(result.batchRisk[0].score, 72);
  assert.strictEqual(result.batchRisk[0].manufacturerName, "Manufacturer A");
  assert.strictEqual(result.manufacturerRisk[0].manufacturerName, "Manufacturer A");
  assert.strictEqual(result.batchRisk[0].openAlerts, 2, "old unacknowledged alerts contribute regardless of age");
  assert.doesNotMatch(JSON.stringify(result), /latitude|longitude|ipAddress|device|token|details/);

  const platformUser = actor({
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date().toISOString(),
  });
  const platformBoundary = buildRiskAnalyticsBoundary(platformUser, input(), "request-platform-risk");
  assert.equal(platformBoundary.context.licenseeId, ids.tenant);
  assert.equal(platformBoundary.context.organizationId, null, "selected organization is derived from the database in-transaction");
  assert.equal(platformBoundary.context.authAssurance, "mfa-verified");
  const platform = fakeRunner({
    actorRow: actorRow({ role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, orgId: null }),
    scanRows: [],
    alertRows: [],
    batchRows: [],
  });
  const platformResult = await withCanonicalDbContext(
    platform.runner,
    platformBoundary.context,
    (tx, installed) => getRiskAnalytics(tx, platformBoundary.query, installed, now)
  );
  assert.equal(platformResult.summary.analyzedBatches, 0);
  assert.equal(platform.calls.audit[0].data.orgId, ids.organization);
  assert.equal(platform.calls.audit[0].data.details.organizationId, ids.organization);
  assert.equal(platform.calls.audit[0].data.details.assurance, "mfa-verified");

  denied(actor({ role: UserRole.MANUFACTURER }), input(), "request", "not authorized");
  denied(actor({ licenseeId: null }), input(), "request", "tenant scope");
  denied(actor({ orgId: null }), input(), "request", "tenant scope");
  denied(actor({ sessionStage: "MFA_BOOTSTRAP" }), input(), "request", "actor context");
  denied(actor({ authAssurance: "unsupported" }), input(), "request", "assurance");
  denied(actor(), input({ requestedLicenseeId: ids.foreign }), "request", "does not match");
  denied(actor(), input({ lookbackHours: 0 }), "request", "date window");
  denied(actor(), input({ limit: 201 }), "request", "page size");
  denied(actor(), input(), "", "actor context");
  denied(platformUser, input({ requestedLicenseeId: undefined }), "request", "valid tenant scope");
  denied({ ...platformUser, authAssurance: "PASSWORD", mfaVerifiedAt: null }, input(), "request", "Fresh administrator MFA");
  denied({ ...platformUser, mfaVerifiedAt: new Date(Date.now() - 31 * 60_000).toISOString() }, input(), "request", "Fresh administrator MFA");
  denied({ ...platformUser, licenseeId: ids.foreign }, input(), "request", "tenant scope must be empty");
  denied(platformUser, input({ requestedLicenseeId: "not-a-licensee" }), "request", "valid tenant scope");

  const orgAdminBoundary = buildRiskAnalyticsBoundary(actor({ role: UserRole.ORG_ADMIN }), input(), "request-org-risk");
  const orgAdmin = fakeRunner({
    actorRow: actorRow({ role: UserRole.ORG_ADMIN }),
    scanRows: [],
    alertRows: [],
    batchRows: [],
  });
  const orgAdminResult = await withCanonicalDbContext(
    orgAdmin.runner,
    orgAdminBoundary.context,
    (tx, installed) => getRiskAnalytics(tx, orgAdminBoundary.query, installed, now)
  );
  assert.equal(orgAdminResult.summary.analyzedBatches, 0, "the existing ORG_ADMIN capability remains supported");

  for (const [name, staleActor] of [
    ["missing actor", null],
    ["changed role", actorRow({ role: UserRole.ORG_ADMIN })],
    ["inactive actor", actorRow({ isActive: false })],
    ["disabled status", actorRow({ status: UserStatus.DISABLED })],
    ["deleted actor", actorRow({ deletedAt: new Date() })],
    ["disabled actor timestamp", actorRow({ disabledAt: new Date() })],
    ["removed tenant membership", actorRow({ licenseeId: ids.foreign })],
    ["removed organization membership", actorRow({ orgId: ids.foreign })],
  ]) {
    const blocked = fakeRunner({ actorRow: staleActor });
    await assert.rejects(
      withCanonicalDbContext(blocked.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
      /actor or tenant authority is stale or inconsistent/,
      name
    );
    assert.deepStrictEqual(blocked.events, ["transaction-begin", "context", "actor"], `${name} must fail before tenant analytics reads`);
  }

  const stalePlatform = fakeRunner({
    actorRow: actorRow({ role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: ids.foreign, orgId: ids.foreign }),
  });
  await assert.rejects(
    withCanonicalDbContext(stalePlatform.runner, platformBoundary.context, (tx, installed) => getRiskAnalytics(tx, platformBoundary.query, installed, now)),
    /actor or tenant authority is stale or inconsistent/
  );
  assert.deepStrictEqual(stalePlatform.events, ["transaction-begin", "context", "actor"]);

  for (const [name, selectorParents] of [
    ["orphan selector", { tenant: null }],
    ["foreign organization parent", {
      tenant: { id: ids.tenant, orgId: ids.foreign, isActive: true, suspendedAt: null },
      organization: { id: ids.organization, isActive: true },
    }],
  ]) {
    const blocked = fakeRunner({
      actorRow: actorRow({ role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, orgId: null }),
      ...selectorParents,
    });
    await assert.rejects(
      withCanonicalDbContext(blocked.runner, platformBoundary.context, (tx, installed) => getRiskAnalytics(tx, platformBoundary.query, installed, now)),
      /Tenant scope is inactive or inconsistent/,
      name
    );
    assert(!blocked.events.includes("batch"), `${name} must fail before analytics reads`);
    assert(!blocked.events.includes("audit"), `${name} must not write success attribution`);
  }

  for (const invalidParent of [
    { tenant: null },
    { tenant: { id: ids.tenant, orgId: ids.organization, isActive: false, suspendedAt: null } },
    { tenant: { id: ids.tenant, orgId: ids.organization, isActive: true, suspendedAt: new Date() } },
    { tenant: { id: ids.tenant, orgId: ids.foreign, isActive: true, suspendedAt: null } },
    { organization: { id: ids.organization, isActive: false } },
  ]) {
    const blocked = fakeRunner(invalidParent);
    await assert.rejects(
      withCanonicalDbContext(blocked.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
      /inactive or inconsistent/
    );
    assert(!blocked.events.includes("batch"), "invalid parent must fail before analytics queries");
  }

  const beforeContext = fakeRunner();
  await assert.rejects(getRiskAnalytics(beforeContext.tx, boundary.query, boundary.context, now), /before canonical context installation/);

  const mismatched = fakeRunner();
  await assert.rejects(
    withCanonicalDbContext(mismatched.runner, { ...boundary.context, licenseeId: ids.foreign }, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /scope does not match/
  );
  assert.deepStrictEqual(mismatched.events, ["transaction-begin", "context"]);

  const rankedBoundary = buildRiskAnalyticsBoundary(actor(), input({ limit: 1 }), "request-ranked-risk");
  const ranked = fakeRunner({
    batchRows: [
      { id: "older-risky", name: "Older Risky", licenseeId: ids.tenant, manufacturerId: "manufacturer-old" },
      { id: "newer-low", name: "Newer Low", licenseeId: ids.tenant, manufacturerId: "manufacturer-new" },
    ],
    qrRows: [
      { batchId: "older-risky", scanCount: 2 },
      { batchId: "newer-low", scanCount: 0 },
    ],
    scanRows: [
      scanRow({ id: "scan-old-1", qrCodeId: "qr-old", batchId: "older-risky", latitude: 0, longitude: 0, scannedAt: new Date("2026-07-16T11:00:00.000Z") }),
      scanRow({ id: "scan-old-2", qrCodeId: "qr-old", batchId: "older-risky", latitude: 0, longitude: 10, scannedAt: new Date("2026-07-16T11:00:30.000Z") }),
      scanRow({ id: "scan-new", qrCodeId: "qr-new", batchId: "newer-low", scannedAt: new Date("2026-07-16T11:30:00.000Z") }),
    ],
    alertRows: [],
    manufacturerRows: [{ id: "manufacturer-old", name: "Older Manufacturer" }, { id: "manufacturer-new", name: "Newer Manufacturer" }],
  });
  const rankedResult = await withCanonicalDbContext(ranked.runner, rankedBoundary.context, (tx, installed) => getRiskAnalytics(tx, rankedBoundary.query, installed, now));
  assert.strictEqual(rankedResult.summary.analyzedBatches, 2);
  assert.strictEqual(rankedResult.batchRisk.length, 1);
  assert.strictEqual(rankedResult.batchRisk[0].batchId, "older-risky", "limit applies only after final score ordering");
  assert.strictEqual(ranked.calls.batch[0].take, RISK_ANALYTICS_MAX_CANDIDATE_BATCHES + 1);

  const alertOnly = fakeRunner({
    scanRows: [],
    alertRows: [alertRow("alert-only", { id: "old-open-alert" })],
    batchRows: [{ id: "alert-only", name: "Alert Only", licenseeId: ids.tenant, manufacturerId: null }],
    qrRows: [],
    manufacturerRows: [],
  });
  const alertOnlyResult = await withCanonicalDbContext(alertOnly.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
  assert.equal(alertOnlyResult.summary.analyzedBatches, 1);
  assert.equal(alertOnlyResult.batchRisk[0].batchId, "alert-only");
  assert.equal(alertOnlyResult.batchRisk[0].openAlerts, 1, "old unresolved alert creates a candidate without recent scans");

  const idle = fakeRunner({
    scanRows: [],
    alertRows: [],
    batchRows: [{ id: "idle-batch", name: "Idle Batch", licenseeId: ids.tenant, manufacturerId: "missing-name" }],
    qrRows: [],
    manufacturerRows: [],
  });
  const idleResult = await withCanonicalDbContext(idle.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
  assert.equal(idleResult.summary.analyzedBatches, 1, "a scoped batch remains analyzed without a recent scan or open alert");
  assert.equal(idleResult.batchRisk[0].batchId, "idle-batch");
  assert.equal(idleResult.batchRisk[0].score, 0);
  assert.equal(idleResult.batchRisk[0].manufacturerName, null);
  assert.equal(idleResult.manufacturerRisk[0].manufacturerName, "missing-name", "aggregate response preserves the manufacturer-ID fallback");

  const consistentAlert = fakeRunner({
    scanRows: [],
    alertRows: [alertRow("batch-a", {
      id: "consistent-alert",
      qrCodeId: "alert-qr-a",
      manufacturerId: "manufacturer-a",
      incidentId: "incident-a",
      policyRuleId: "rule-a",
    })],
    alertQrRows: [{ id: "alert-qr-a", licenseeId: ids.tenant, batchId: "batch-a" }],
    alertManufacturerRows: [{ id: "manufacturer-a" }],
    alertManufacturerLinkRows: [{ manufacturerId: "manufacturer-a", licenseeId: ids.tenant }],
    incidentRows: [{ id: "incident-a", licenseeId: ids.tenant }],
    policyRuleRows: [{ id: "rule-a", licenseeId: ids.tenant, orgId: ids.organization, manufacturerId: "manufacturer-a", isActive: true }],
  });
  const consistentAlertResult = await withCanonicalDbContext(consistentAlert.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
  assert.equal(consistentAlertResult.batchRisk[0].openAlerts, 1);
  assert.deepStrictEqual(consistentAlert.calls.alertQr[0].select, { id: true, licenseeId: true, batchId: true });
  assert.deepStrictEqual(consistentAlert.calls.alertManufacturer[0].select, { id: true });
  assert.deepStrictEqual(consistentAlert.calls.alertManufacturer[0].where, {
    id: { in: ["manufacturer-a"] },
    role: { in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER] },
    isActive: true,
    status: "ACTIVE",
    deletedAt: null,
    disabledAt: null,
  });
  assert.deepStrictEqual(consistentAlert.calls.manufacturerLink[0].select, { manufacturerId: true, licenseeId: true });
  assert.equal(consistentAlert.calls.manufacturerLink[0].where.licenseeId, ids.tenant);
  assert.deepStrictEqual(consistentAlert.calls.incident[0].select, { id: true, licenseeId: true });
  assert.deepStrictEqual(consistentAlert.calls.policyRule[0].select, { id: true, licenseeId: true, orgId: true, manufacturerId: true, isActive: true });

  for (const [name, rule] of [
    ["organization-only active policy rule", { id: "rule-a", licenseeId: null, orgId: ids.organization, manufacturerId: null, isActive: true }],
    ["manufacturer-only active policy rule", { id: "rule-a", licenseeId: null, orgId: null, manufacturerId: "manufacturer-a", isActive: true }],
  ]) {
    const valid = fakeRunner({
      scanRows: [],
      alertRows: [alertRow("batch-a", { manufacturerId: "manufacturer-a", policyRuleId: "rule-a" })],
      alertManufacturerRows: [{ id: "manufacturer-a" }],
      alertManufacturerLinkRows: [{ manufacturerId: "manufacturer-a", licenseeId: ids.tenant }],
      policyRuleRows: [rule],
    });
    const value = await withCanonicalDbContext(valid.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
    assert.equal(value.batchRisk[0].openAlerts, 1, name);
  }

  const invalidAlertParents = [
    ["foreign QR", {
      alertRows: [alertRow("batch-a", { qrCodeId: "alert-qr-a" })],
      alertQrRows: [{ id: "alert-qr-a", licenseeId: ids.foreign, batchId: "batch-a" }],
    }],
    ["QR batch conflict", {
      alertRows: [alertRow("batch-a", { qrCodeId: "alert-qr-a" })],
      alertQrRows: [{ id: "alert-qr-a", licenseeId: ids.tenant, batchId: "other-batch" }],
    }],
    ["unlinked or inactive manufacturer", {
      alertRows: [alertRow("batch-a", { manufacturerId: "manufacturer-a" })],
      alertManufacturerRows: [{ id: "manufacturer-a" }],
      alertManufacturerLinkRows: [],
    }],
    ["foreign manufacturer", {
      alertRows: [alertRow("batch-a", { manufacturerId: "manufacturer-a" })],
      alertManufacturerRows: [],
      alertManufacturerLinkRows: [{ manufacturerId: "manufacturer-a", licenseeId: ids.tenant }],
    }],
    ["foreign incident", {
      alertRows: [alertRow("batch-a", { incidentId: "incident-a" })],
      incidentRows: [{ id: "incident-a", licenseeId: ids.foreign }],
    }],
    ["foreign policy rule", {
      alertRows: [alertRow("batch-a", { policyRuleId: "rule-a" })],
      policyRuleRows: [{ id: "rule-a", licenseeId: ids.foreign, orgId: ids.organization, manufacturerId: null, isActive: true }],
    }],
    ["inactive policy rule", {
      alertRows: [alertRow("batch-a", { policyRuleId: "rule-a" })],
      policyRuleRows: [{ id: "rule-a", licenseeId: ids.tenant, orgId: ids.organization, manufacturerId: null, isActive: false }],
    }],
    ["orphan optional parent", {
      alertRows: [alertRow("batch-a", { qrCodeId: "missing-qr" })],
      alertQrRows: [],
    }],
    ["conflicting manufacturer parent", {
      alertRows: [alertRow("batch-a", { manufacturerId: "manufacturer-b" })],
      alertManufacturerRows: [{ id: "manufacturer-b" }],
      alertManufacturerLinkRows: [{ manufacturerId: "manufacturer-b", licenseeId: ids.tenant }],
    }],
    ["duplicate inconsistent QR parent", {
      alertRows: [alertRow("batch-a", { qrCodeId: "alert-qr-a" })],
      alertQrRows: [
        { id: "alert-qr-a", licenseeId: ids.tenant, batchId: "batch-a" },
        { id: "alert-qr-a", licenseeId: ids.tenant, batchId: "other-batch" },
      ],
    }],
  ];
  for (const [name, parentOverrides] of invalidAlertParents) {
    const invalid = fakeRunner({ scanRows: [], ...parentOverrides });
    await assert.rejects(
      withCanonicalDbContext(invalid.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
      /alert parentage is missing, foreign, inactive, or inconsistent/,
      name
    );
    assert(!invalid.events.includes("qr"), `${name} must fail before risk scoring`);
    assert(!invalid.events.includes("audit"), `${name} must fail before successful attribution`);
  }

  const empty = fakeRunner({ scanRows: [], alertRows: [], batchRows: [], qrRows: [], manufacturerRows: [] });
  const emptyResult = await withCanonicalDbContext(empty.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
  assert.equal(emptyResult.summary.analyzedBatches, 0);
  assert.deepStrictEqual(emptyResult.batchRisk, []);
  assert(!empty.events.includes("qr"), "empty scan and alert sources return before dimension queries");
  assert(empty.events.includes("audit"), "bounded empty success remains attributed");

  const deduplicated = fakeRunner({
    scanRows: [scanRow({ id: "scan-deduplicated" })],
    alertRows: [alertRow("batch-a", { id: "alert-deduplicated" })],
  });
  const deduplicatedResult = await withCanonicalDbContext(deduplicated.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
  assert.deepStrictEqual(deduplicated.calls.batch[0].where, { licenseeId: ids.tenant });
  assert.equal(deduplicatedResult.summary.analyzedBatches, 1);

  const acknowledgedOnly = fakeRunner({ alertRows: [] });
  const acknowledgedResult = await withCanonicalDbContext(acknowledgedOnly.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now));
  assert.strictEqual(acknowledgedOnly.calls.alert[0].where.acknowledgedAt, null);
  assert.strictEqual(acknowledgedResult.batchRisk[0].openAlerts, 0, "acknowledged alerts are excluded by the database predicate");

  const nullableHistoricalRows = fakeRunner({
    scanRows: [scanRow({ id: "unassigned-scan", batchId: null })],
    alertRows: [alertRow(null, { id: "unassigned-alert" })],
    qrRows: [],
  });
  const nullableResult = await withCanonicalDbContext(
    nullableHistoricalRows.runner,
    boundary.context,
    (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)
  );
  assert.equal(nullableResult.summary.analyzedBatches, 1, "a legitimate nullable historical row does not remove tenant batches");
  assert.equal(nullableResult.batchRisk[0].score, 0, "nullable scan and alert rows remain outside batch scoring");
  assert(nullableHistoricalRows.events.includes("audit"), "nullable historical rows preserve successful read attribution");

  const scanCandidateCount = Math.floor(RISK_ANALYTICS_MAX_CANDIDATE_BATCHES / 2) + 1;
  const tooManyCandidates = fakeRunner({
    scanRows: Array.from({ length: scanCandidateCount }, (_, index) => scanRow({ id: `scan-${index}`, qrCodeId: `qr-${index}`, batchId: `scan-batch-${index}` })),
    alertRows: Array.from({ length: RISK_ANALYTICS_MAX_CANDIDATE_BATCHES + 1 - scanCandidateCount }, (_, index) => alertRow(`alert-batch-${index}`, { id: `alert-${index}` })),
  });
  await assert.rejects(
    withCanonicalDbContext(tooManyCandidates.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /candidate batch set exceeds/
  );
  assert(!tooManyCandidates.events.includes("batch"));
  assert(!tooManyCandidates.events.includes("audit"));

  const tooManyTenantBatches = fakeRunner({
    scanRows: [],
    alertRows: [],
    batchRows: Array.from({ length: RISK_ANALYTICS_MAX_CANDIDATE_BATCHES + 1 }, (_, index) => ({
      id: `tenant-batch-${index}`,
      name: `Tenant Batch ${index}`,
      licenseeId: ids.tenant,
      manufacturerId: null,
    })),
  });
  await assert.rejects(
    withCanonicalDbContext(tooManyTenantBatches.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /candidate batch set exceeds/
  );
  assert(!tooManyTenantBatches.events.includes("qr"));
  assert(!tooManyTenantBatches.events.includes("audit"));

  const tooManyScans = fakeRunner({
    scanRows: Array.from({ length: RISK_ANALYTICS_MAX_DIMENSION_ROWS + 1 }, (_, index) => scanRow({ id: `scan-overflow-${index}` })),
  });
  await assert.rejects(
    withCanonicalDbContext(tooManyScans.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /scan dimension exceeds/
  );
  assert(!tooManyScans.events.includes("alert"));
  assert(!tooManyScans.events.includes("audit"));

  const oversized = fakeRunner({ qrRows: Array.from({ length: RISK_ANALYTICS_MAX_DIMENSION_ROWS + 1 }, () => ({ batchId: "batch-a", scanCount: 1 })) });
  await assert.rejects(
    withCanonicalDbContext(oversized.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /dimension exceeds/
  );
  assert(!oversized.events.includes("audit"), "a denied oversized read must not write success attribution");

  const tooManyAlerts = fakeRunner({
    alertRows: Array.from({ length: RISK_ANALYTICS_MAX_OPEN_ALERT_ROWS + 1 }, (_, index) => alertRow("batch-a", { id: `alert-overflow-${index}` })),
  });
  await assert.rejects(
    withCanonicalDbContext(tooManyAlerts.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /open-alert set exceeds/
  );
  assert(!tooManyAlerts.events.includes("batch"));
  assert(!tooManyAlerts.events.includes("audit"), "alert overflow must fail before successful attribution");

  for (const [name, invalidScan] of [
    ["foreign QR", scanRow({ qrLicenseeId: ids.foreign })],
    ["foreign batch", scanRow({ batchLicenseeId: ids.foreign })],
    ["QR/batch mismatch", scanRow({ qrBatchId: "other-batch" })],
    ["orphan QR", scanRow({ qrCode: null })],
    ["orphan batch", scanRow({ batch: null })],
  ]) {
    const inconsistent = fakeRunner({ scanRows: [invalidScan], alertRows: [] });
    await assert.rejects(
      withCanonicalDbContext(inconsistent.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
      /scan parentage is missing, foreign, or inconsistent/,
      name
    );
    assert(!inconsistent.events.includes("alert"), `${name} must fail before later discovery`);
    assert(!inconsistent.events.includes("audit"), `${name} must not write success attribution`);
  }

  const duplicateParent = fakeRunner({
    scanRows: [
      scanRow({ id: "scan-parent-a", qrCodeId: "qr-shared", batchId: "batch-a" }),
      scanRow({ id: "scan-parent-b", qrCodeId: "qr-shared", batchId: "batch-b" }),
    ],
    alertRows: [],
  });
  await assert.rejects(
    withCanonicalDbContext(duplicateParent.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /scan parentage is missing, foreign, or inconsistent/
  );

  const missingCandidateParent = fakeRunner({
    scanRows: [],
    alertRows: [alertRow("missing-batch")],
    batchRows: [],
  });
  await assert.rejects(
    withCanonicalDbContext(missingCandidateParent.runner, boundary.context, (tx, installed) => getRiskAnalytics(tx, boundary.query, installed, now)),
    /candidate parentage is missing, foreign, or inconsistent/
  );
  assert(!missingCandidateParent.events.includes("audit"));

  const root = path.resolve(__dirname, "..");
  const serviceSource = fs.readFileSync(path.join(root, "src/services/analyticsService.ts"), "utf8");
  const controllerSource = fs.readFileSync(path.join(root, "src/controllers/tracePolicyController.ts"), "utf8");
  const authSource = fs.readFileSync(path.join(root, "src/middleware/auth.ts"), "utf8");
  const riskBody = serviceSource.match(/export const getRiskAnalytics = async[\s\S]*?^};/m)?.[0] || "";
  const controllerBody = controllerSource.match(/export const getRiskAnalyticsController[\s\S]*?export const getPolicyConfigController/)?.[0] || "";
  assert(!/\bprisma\./.test(riskBody), "risk analytics must not use global Prisma");
  assert(!riskBody.includes("getOrCreateSecurityPolicy"), "risk analytics must remain read-only apart from attribution");
  assert.match(controllerBody, /withCanonicalDbContext\(/);
  assert.match(controllerBody, /TransactionIsolationLevel\.RepeatableRead/);
  assert.match(authSource, /hydrateTenantIfNeeded[\s\S]*?tx\.user\.findUnique/);
  execFileSync(process.execPath, [path.join(__dirname, "riskAnalyticsRouteChain.test.js")], { stdio: "inherit" });

  console.log("risk analytics context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
