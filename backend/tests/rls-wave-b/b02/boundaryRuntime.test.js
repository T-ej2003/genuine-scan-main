const assert = require("node:assert/strict");
const test = require("node:test");

process.env.JWT_SECRET ||= "b02-focused-test-secret-with-at-least-32-characters";

const {
  withB02AuthenticatedRequest,
} = require("../../../dist/rls-waves/session-b/b02/authenticatedBoundary");
const {
  listSupportIssueRows,
} = require("../../../dist/rls-waves/session-b/b02/authenticatedRepositories");

const request = (user) => ({
  user,
  requestId: "req-b02-001",
  get: () => undefined,
});

const runnerFor = (tx) => ({
  $transaction: async (callback) => callback(tx),
});

test("B02 authenticates with bootstrap self-read before any protected delegate", async () => {
  const events = [];
  const now = new Date();
  const tx = {
    $executeRaw: async () => { events.push("context"); return 1; },
    user: {
      findFirst: async (args) => {
        events.push("user-self");
        assert.deepEqual(args.where, {
          id: "user-db",
          isActive: true,
          status: "ACTIVE",
          disabledAt: null,
          deletedAt: null,
        });
        assert.deepEqual(Object.keys(args.select).sort(), ["id", "licenseeId", "orgId", "role"]);
        return { id: "user-db", role: "LICENSEE_ADMIN", licenseeId: "lic-db", orgId: "org-db" };
      },
    },
    refreshToken: {
      findFirst: async (args) => {
        events.push("session-self");
        assert.equal(args.where.id, "session-db");
        assert.equal(args.where.userId, "user-db");
        assert.equal(args.where.revokedAt, null);
        return {
          id: "session-db",
          userId: "user-db",
          orgId: "org-db",
          authenticatedAt: new Date(now.getTime() - 60_000),
          mfaVerifiedAt: new Date(now.getTime() - 30_000),
          expiresAt: new Date(now.getTime() + 60_000),
        };
      },
    },
  };

  const result = await withB02AuthenticatedRequest(
    request({
      userId: "user-db",
      sessionId: "session-db",
      role: "SUPER_ADMIN",
      licenseeId: "lic-db",
      orgId: "org-db",
    }),
    { purpose: "support-issue-read", assurance: "mfa-verified" },
    async (_tx, context) => {
      events.push("callback");
      return context;
    },
    runnerFor(tx)
  );

  assert.deepEqual(events, ["context", "user-self", "context", "session-self", "context", "callback"]);
  assert.equal(result.role, "LICENSEE_ADMIN", "database role must override the stale/forged claim role");
  assert.equal(result.licenseeId, "lic-db");
  assert.equal(result.authAssurance, "mfa-verified");
  assert.equal(result.purpose, "support-issue-read");
});

test("B02 denies stale MFA before the protected callback", async () => {
  let callbackRan = false;
  const now = Date.now();
  const tx = {
    $executeRaw: async () => 1,
    user: {
      findFirst: async () => ({ id: "user-db", role: "PLATFORM_SUPER_ADMIN", licenseeId: null, orgId: null }),
    },
    refreshToken: {
      findFirst: async () => ({
        id: "session-db",
        userId: "user-db",
        orgId: null,
        authenticatedAt: new Date(now - 60_000),
        mfaVerifiedAt: new Date(now - 31 * 60_000),
        expiresAt: new Date(now + 60_000),
      }),
    },
  };

  await assert.rejects(
    withB02AuthenticatedRequest(
      request({ userId: "user-db", sessionId: "session-db", role: "PLATFORM_SUPER_ADMIN" }),
      { purpose: "support-issue-read", assurance: "mfa-verified" },
      async () => { callbackRan = true; },
      runnerFor(tx)
    ),
    /fresh MFA assurance/
  );
  assert.equal(callbackRan, false);
});

test("platform support reads require one active, visible licensee selector", async () => {
  let protectedReads = 0;
  const tx = {
    licensee: { findFirst: async () => null },
    supportIssueReport: {
      findMany: async () => { protectedReads += 1; return []; },
      count: async () => { protectedReads += 1; return 0; },
    },
  };

  await assert.rejects(
    listSupportIssueRows(tx, { platform: true, limit: 50, offset: 0 }),
    /explicit support licensee selector/
  );
  await assert.rejects(
    listSupportIssueRows(tx, { platform: true, licenseeId: "foreign", limit: 50, offset: 0 }),
    /inactive or foreign/
  );
  assert.equal(protectedReads, 0);

  tx.licensee.findFirst = async (args) => {
    assert.equal(args.where.id, "lic-active");
    return { id: "lic-active" };
  };
  await listSupportIssueRows(tx, {
    platform: true,
    licenseeId: "lic-active",
    limit: 50,
    offset: 0,
  });
  assert.equal(protectedReads, 2);
});
