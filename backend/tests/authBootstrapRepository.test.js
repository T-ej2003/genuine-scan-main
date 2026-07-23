const assert = require("node:assert/strict");

const {
  lookupPasswordBootstrapUser,
  recordPasswordLoginFailure,
} = require("../dist/services/auth/authBootstrapRepository");

const missingBoundaryError = () => Object.assign(new Error("boundary absent"), {
  code: "P2010",
  meta: { code: "3F000" },
});

const run = async () => {
  const row = {
    id: "user-1",
    email: "user@example.com",
    passwordHash: "hash",
    name: "User",
    role: "MANUFACTURER",
    licenseeId: null,
    orgId: null,
    status: "ACTIVE",
    isActive: true,
    disabledAt: null,
    deletedAt: null,
    failedLoginAttempts: 0,
    lockedUntil: null,
    lastLoginAt: null,
    emailVerifiedAt: new Date(),
  };
  let lookupFallbacks = 0;
  const missingDb = {
    $queryRaw: async () => { throw missingBoundaryError(); },
    user: {
      findMany: async (query) => {
        lookupFallbacks += 1;
        assert.equal(query.take, 2);
        assert.equal(query.where.email.mode, "insensitive");
        return [row];
      },
    },
  };
  await assert.rejects(lookupPasswordBootstrapUser(row.email, missingDb), /boundary absent/);
  assert.equal(lookupFallbacks, 0, "an absent reviewed boundary must fail closed without direct-table fallback");

  let permissionFallbacks = 0;
  const deniedDb = {
    $queryRaw: async () => { throw Object.assign(new Error("denied"), { code: "P2010", meta: { code: "42501" } }); },
    user: { findMany: async () => { permissionFallbacks += 1; return [row]; } },
  };
  await assert.rejects(lookupPasswordBootstrapUser(row.email, deniedDb), /denied/);
  assert.equal(permissionFallbacks, 0, "permission and RLS failures must never fall back");

  let mutationCalls = 0;
  const mutationDb = {
    $queryRaw: async () => {
      mutationCalls += 1;
      if (mutationCalls === 1) throw missingBoundaryError();
      return [{ failedLoginAttempts: 1, lockedUntil: null }];
    },
    user: { findMany: async () => [] },
  };
  await assert.rejects(recordPasswordLoginFailure({
    normalizedEmail: row.email,
    attemptedAt: new Date(),
    maxAttempts: 5,
    lockoutMinutes: 15,
  }, mutationDb), /boundary absent/);
  assert.equal(mutationCalls, 1, "an absent failure boundary must not retry through a direct mutation");

  console.log("auth bootstrap repository compatibility tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
