const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";

const { withCanonicalDbContext } = require("../dist/lib/canonicalDbContext");
const {
  buildFraudReportBoundary,
  FraudReportAccessError,
  queryFraudReports,
} = require("../dist/services/fraudReportQueryService");

const platformActor = (overrides = {}) => ({
  userId: "platform-admin",
  email: "platform@example.test",
  role: UserRole.PLATFORM_SUPER_ADMIN,
  licenseeId: null,
  orgId: null,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "ADMIN_MFA",
  mfaVerifiedAt: new Date().toISOString(),
  ...overrides,
});

const query = (overrides = {}) => ({
  licenseeId: "11111111-1111-4111-8111-111111111111",
  purpose: "investigate ticket IR-42",
  status: "ALL",
  limit: 25,
  offset: 0,
  ...overrides,
});

const fakeRunner = () => {
  const events = [];
  const calls = { count: [], find: [], create: [], contextValues: [] };
  const tx = {
    $executeRaw: async (strings, ...values) => {
      const sql = strings.join("?");
      if (/set_config\('app\.licensee_id'/.test(sql)) {
        events.push("context");
        calls.contextValues.push(values);
      } else if (/INSERT INTO public\."AuditLog"/.test(sql)) {
        events.push("audit-attribution");
        calls.create.push({ values });
      } else {
        events.push("audit-outbox");
      }
      return 1;
    },
    $queryRaw: async (strings) => {
      if (/transaction_timestamp/.test(strings.join("?"))) {
        events.push("audit-clock");
        return [{ createdAt: new Date("2026-07-16T11:00:01.000Z") }];
      }
      events.push("network-details");
      return [{ id: "report-a", ipAddress: "192.0.2.1" }];
    },
    auditLog: {
      count: async (args) => {
        events.push("count");
        calls.count.push(args);
        return 1;
      },
      findMany: async (args) => {
        calls.find.push(args);
        if (args.where.action === "CUSTOMER_FRAUD_REPORT") {
          events.push("report-list");
          return [{
            id: "report-a",
            createdAt: new Date("2026-07-16T10:00:00.000Z"),
            licenseeId: "11111111-1111-4111-8111-111111111111",
            ipAddress: "192.0.2.1",
            details: { code: "QR-1", reason: "duplicate", contactEmail: "reporter@example.test" },
          }];
        }
        events.push("response-list");
        return [{
          id: "response-a",
          createdAt: new Date("2026-07-16T11:00:00.000Z"),
          userId: "platform-admin",
          details: {
            reportId: "report-a",
            status: "REVIEWED",
            message: "Investigating",
            delivery: { provider: "mail", accessToken: "must-not-escape", nested: { passwordHash: "also-secret" } },
          },
        }];
      },
    },
  };
  return {
    calls,
    events,
    runner: {
      $transaction: async (callback) => {
        events.push("transaction-begin");
        const result = await callback(tx);
        events.push("transaction-end");
        return result;
      },
    },
  };
};

const expectBoundaryDenied = (actor, input, requestId, message) => {
  assert.throws(
    () => buildFraudReportBoundary(actor, input, requestId),
    (error) => error instanceof FraudReportAccessError && error.message.includes(message)
  );
};

(async () => {
  const fake = fakeRunner();
  const input = query();
  const context = buildFraudReportBoundary(platformActor(), input, "request-a");
  let serialized = false;
  const data = await withCanonicalDbContext(fake.runner, context, async (tx, installedContext) => {
    const result = await queryFraudReports(tx, input, installedContext);
    assert.strictEqual(serialized, false, "response serialization must happen after protected reads");
    return result;
  });
  serialized = true;

  assert.deepStrictEqual(fake.events, [
    "transaction-begin",
    "context",
    "count",
    "report-list",
    "network-details",
    "response-list",
    "audit-clock",
    "audit-attribution",
    "audit-outbox",
    "transaction-end",
  ]);
  assert.strictEqual(fake.calls.contextValues[0][3], "11111111-1111-4111-8111-111111111111");
  assert.strictEqual(fake.calls.contextValues[0][5], "mfa-verified");
  assert.strictEqual(fake.calls.contextValues[0][7], "platform-fraud-report-read");
  assert.strictEqual(fake.calls.count[0].where.licenseeId, "11111111-1111-4111-8111-111111111111");
  assert.strictEqual(fake.calls.find[0].where.licenseeId, "11111111-1111-4111-8111-111111111111");
  assert.strictEqual(fake.calls.find[1].where.licenseeId, "11111111-1111-4111-8111-111111111111");
  assert.deepStrictEqual(fake.calls.find[0].orderBy, [{ createdAt: "desc" }, { id: "desc" }]);
  assert.strictEqual(fake.calls.find[0].take, 25);
  assert(!("ipHash" in fake.calls.find[0].select));
  assert(!("userAgent" in fake.calls.find[0].select));
  const auditDetails = JSON.parse(fake.calls.create[0].values[7]);
  assert.strictEqual(auditDetails.requestId, "request-a");
  assert.strictEqual(auditDetails.purpose, "investigate ticket IR-42");
  assert.strictEqual(auditDetails.purposeCode, "platform-fraud-report-read");
  assert.strictEqual(data.total, 1);
  assert.strictEqual(data.reports[0].licenseeId, "11111111-1111-4111-8111-111111111111");
  assert.deepStrictEqual(data.reports[0].response.delivery, {
    provider: "mail",
    accessToken: "[REDACTED]",
    nested: { passwordHash: "[REDACTED]" },
  });
  assert.doesNotMatch(JSON.stringify(data), /must-not-escape|also-secret/);

  const narrowed = fakeRunner();
  const narrowedInput = query({ status: "REVIEWED", limit: 5, offset: 10 });
  const narrowedContext = buildFraudReportBoundary(platformActor(), narrowedInput, "request-filtered");
  await withCanonicalDbContext(narrowed.runner, narrowedContext, (tx, installed) => queryFraudReports(tx, narrowedInput, installed));
  assert.strictEqual(narrowed.calls.find[0].take, 5);
  assert.strictEqual(narrowed.calls.find[0].skip, 10);

  expectBoundaryDenied(platformActor({ role: UserRole.LICENSEE_ADMIN, licenseeId: "11111111-1111-4111-8111-111111111111" }), query(), "request-a", "Access denied");
  expectBoundaryDenied(platformActor({ role: UserRole.MANUFACTURER, userId: "manufacturer-a" }), query(), "request-a", "Access denied");
  expectBoundaryDenied(platformActor({ userId: "" }), query(), "request-a", "actor context");
  expectBoundaryDenied(platformActor(), query({ licenseeId: "" }), "request-a", "bounded licensee scope");
  expectBoundaryDenied(platformActor({ authAssurance: "PASSWORD" }), query(), "request-a", "MFA");
  expectBoundaryDenied(platformActor({ authAssurance: "unsupported" }), query(), "request-a", "MFA");
  expectBoundaryDenied(platformActor(), query({ purpose: "" }), "request-a", "purpose");
  expectBoundaryDenied(platformActor(), query(), "", "actor context");

  const mismatch = fakeRunner();
  const foreignContext = { ...context, licenseeId: "22222222-2222-4222-8222-222222222222" };
  await assert.rejects(
    withCanonicalDbContext(mismatch.runner, foreignContext, (tx, installed) => queryFraudReports(tx, input, installed)),
    /scope does not match/
  );
  assert.deepStrictEqual(mismatch.events, ["transaction-begin", "context"], "scope mismatch must fail before protected reads");

  const root = path.resolve(__dirname, "..");
  const serviceSource = fs.readFileSync(path.join(root, "src/services/fraudReportQueryService.ts"), "utf8");
  const controllerSource = fs.readFileSync(path.join(root, "src/controllers/auditController.ts"), "utf8");
  const routeSource = fs.readFileSync(path.join(root, "src/routes/auditRoutes.ts"), "utf8");
  assert(!serviceSource.includes('from "../config/database"'), "repository must not import the global Prisma client");
  const controllerBody = controllerSource.match(/export const getFraudReports[\s\S]*?export const respondToFraudReport/)?.[0] || "";
  assert(!/prisma\.auditLog\./.test(controllerBody), "controller must not execute protected queries on the global client");
  assert.match(controllerBody, /withCanonicalDbContext\(prisma, context/);
  assert.match(routeSource, /"\/fraud-reports",[\s\S]{0,300}requirePlatformAdmin,[\s\S]{0,100}requireRecentAdminMfa,/);

  console.log("fraud report query context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
