const assert = require("assert");
const path = require("path");
const { NotificationAudience, NotificationChannel, UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

(async () => {
  const notificationCalls = [];
  mockModule("config/database.js", {
    __esModule: true,
    default: {
      notification: {
        findFirst: async () => ({
          id: "shared-notification",
          userId: null,
          channel: NotificationChannel.WEB,
          audience: NotificationAudience.LICENSEE_ADMIN,
          type: "incident_created",
          title: "Shared",
          body: "Shared",
          readAt: null,
          licenseeId: "lic-a",
          orgId: null,
          data: null,
          createdAt: new Date("2026-05-18T00:00:00.000Z"),
          updatedAt: new Date("2026-05-18T00:00:00.000Z"),
        }),
        update: async () => {
          throw new Error("shared notification rows must not be mutated for a single reader");
        },
        updateMany: async ({ where }) => {
          notificationUpdates.push(where);
          return { count: 3 };
        },
      },
      manufacturerLicenseeLink: {
        findMany: async () => [{
          licenseeId: "lic-a",
          isPrimary: true,
          createdAt: new Date("2026-01-01T00:00:00.000Z"),
          updatedAt: new Date("2026-01-02T00:00:00.000Z"),
          licensee: {
            id: "lic-a",
            name: "Licensee A",
            prefix: "LICA",
            brandName: null,
            orgId: "org-a",
          },
        }],
      },
    },
  });
  mockModule("services/incidentEmailService.js", { sendIncidentEmail: async () => ({ delivered: false }) });
  mockModule("services/auth/authEmailService.js", { sendAuthEmail: async () => ({ delivered: false }) });
  mockModule("utils/prismaStorageGuard.js", {
    isPrismaMissingTableError: () => false,
    warnStorageUnavailableOnce: () => undefined,
  });
  mockModule("services/notificationVisibility.js", {
    canAudienceReceiveNotificationType: () => true,
    hiddenNotificationTypesForRole: () => [],
  });
  mockModule("services/redisService.js", {
    getRedisInstanceId: () => "test",
    publishRedisJson: async () => undefined,
    subscribeRedisJson: async () => undefined,
  });
  mockModule("services/versionedCacheService.js", {
    bumpCacheNamespaceVersion: async () => undefined,
    getOrComputeVersionedCache: async (_ns, _key, _ttl, compute) => compute(),
  });
  mockModule("utils/cursorPagination.js", {
    buildDateCursorWhere: () => null,
    encodeDateCursor: () => null,
  });
  mockModule("rls-waves/session-b/b03/repositoryFunctions.js", {
    requireB03AuthenticatedFunctionBoundary: (boundary) => {
      assert.ok(boundary?.run, "notification mutations require the capability-backed database boundary");
      return boundary;
    },
    markNotificationRead: async (_db, input) => {
      notificationCalls.push({ operation: "read-one", input });
      return {
        notification: {
          id: input.notificationId,
          userId: null,
          channel: NotificationChannel.WEB,
          audience: NotificationAudience.LICENSEE_ADMIN,
          readAt: input.readAt,
        },
      };
    },
    markAllNotificationsRead: async (_db, input) => {
      notificationCalls.push({ operation: "read-all", input });
      return { count: 3 };
    },
  });

  const { buildIncidentScopeWhere, buildScopedUserWhere } = require("../dist/services/accessControlService");

  const licenseeAdmin = {
    userId: "licensee-admin-a",
    email: "admin-a@example.com",
    role: UserRole.LICENSEE_ADMIN,
    licenseeId: "lic-a",
    orgId: "org-a",
    linkedLicenseeIds: [],
  };

  const usersWhere = await buildScopedUserWhere(licenseeAdmin, {
    requestedLicenseeId: "lic-a",
    manufacturerOnly: true,
  });
  assert.deepStrictEqual(
    usersWhere.AND,
    [
      {
        OR: [
          { licenseeId: "lic-a" },
          { manufacturerLicenseeLinks: { some: { licenseeId: "lic-a" } } },
        ],
      },
    ],
    "manufacturer user lists must be constrained to the authenticated licensee"
  );
  assert.deepStrictEqual(usersWhere.role, {
    in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER],
  });

  await assert.rejects(
    () => buildScopedUserWhere(licenseeAdmin, { requestedLicenseeId: "lic-b" }),
    /Access denied/,
    "licensee admins cannot widen user-management scope through query/body licenseeId"
  );

  const manufacturerIncidentWhere = await buildIncidentScopeWhere(
    {
      role: UserRole.MANUFACTURER,
      userId: "manufacturer-a",
      licenseeId: "lic-a",
      linkedLicenseeIds: ["lic-a"],
    },
    { id: "incident-from-url" }
  );
  assert.deepStrictEqual(
    manufacturerIncidentWhere.AND,
    [
      {
        OR: [
          { qrCode: { batch: { manufacturerId: "manufacturer-a" } } },
          { scanEvent: { batch: { manufacturerId: "manufacturer-a" } } },
        ],
      },
      { licenseeId: "lic-a" },
    ],
    "incident details must be scoped by both tenant and manufacturer ownership"
  );

  const {
    markAllNotificationsRead,
    markNotificationRead,
  } = require("../dist/services/notificationService");
  const databaseBoundary = {
    requestId: "tenant-isolation-notification-test",
    run: (callback) => callback({}),
  };

  const sharedRead = await markNotificationRead({
    notificationId: "shared-notification",
    userId: "user-a",
    role: UserRole.LICENSEE_ADMIN,
    licenseeId: "lic-a",
    databaseBoundary,
  });
  assert.strictEqual(sharedRead.userId, null);
  assert.ok(sharedRead.readAt, "shared notification read responses can be presented as read without mutating the shared row");

  const readAllCount = await markAllNotificationsRead({
    userId: "user-a",
    role: UserRole.LICENSEE_ADMIN,
    licenseeId: "lic-a",
    databaseBoundary,
  });
  assert.strictEqual(readAllCount, 3);
  assert.deepStrictEqual(notificationCalls.map((entry) => entry.operation), ["read-one", "read-all"]);
  assert.strictEqual(notificationCalls[0].input.userId, "user-a");
  assert.strictEqual(notificationCalls[1].input.userId, "user-a");

  console.log("extended tenant isolation regression test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
