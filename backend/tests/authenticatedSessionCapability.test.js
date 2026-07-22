const assert = require("assert");

const {
  AUTHENTICATED_SESSION_CAPABILITY_BYTES,
  AUTHENTICATED_SESSION_HASH_VERSION,
  createAuthenticatedSessionCapability,
  hashAuthenticatedSessionCapability,
  newAuthenticatedSessionCapability,
  revokeAuthenticatedSessionByRefreshToken,
  revokeAuthenticatedSessionsForUser,
} = require("../dist/services/auth/authenticatedSessionCapabilityService");

const uuid = "00000000-0000-4000-8000-000000000001";

async function main() {
  const first = newAuthenticatedSessionCapability();
  const second = newAuthenticatedSessionCapability();
  assert.equal(AUTHENTICATED_SESSION_CAPABILITY_BYTES, 32);
  assert.match(first, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first, second);
  assert.match(hashAuthenticatedSessionCapability(first), /^[a-f0-9]{64}$/);
  assert.throws(() => hashAuthenticatedSessionCapability("not-a-capability"), /CAPABILITY_INVALID/);

  const expiresAt = new Date("2030-01-01T00:00:00.000Z");
  const calls = [];
  const db = {
    $queryRaw: async (strings) => {
      calls.push(strings.join("?"));
      if (calls.length === 1) return [{ id: "00000000-0000-4000-8000-000000000002", expiresAt }];
      if (calls.length === 2) return [{ revoked: true }];
      return [{ revokedCount: 2 }];
    },
  };
  const created = await createAuthenticatedSessionCapability(db, {
    refreshTokenId: "00000000-0000-4000-8000-000000000002",
    refreshTokenHash: "a".repeat(64),
    assurance: "PASSWORD",
    expiresAt,
    now: new Date("2029-12-01T00:00:00.000Z"),
  });
  assert.equal(created.row.expiresAt, expiresAt);
  assert.equal(created.row.id, "00000000-0000-4000-8000-000000000002");
  assert.equal(JSON.stringify(calls).includes(created.rawCapability), false, "raw capability persisted by the test boundary");

  assert.equal(await revokeAuthenticatedSessionByRefreshToken(db, {
    capability: created.rawCapability,
    refreshTokenId: "00000000-0000-4000-8000-000000000003",
    reason: "LOGOUT",
    requestId: "test-request",
  }), true);
  assert.equal(await revokeAuthenticatedSessionsForUser(db, {
    capability: created.rawCapability,
    reason: "PASSWORD_RESET",
    requestId: "test-request",
  }), 2);
  assert(calls[1].includes("revoke_authenticated_session_capability"));
  assert(calls[2].includes("revoke_all_authenticated_session_capabilities"));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
