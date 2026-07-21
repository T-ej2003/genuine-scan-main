const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../../../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

const repository = read("backend/src/rls-waves/session-b/b01/invitationRepository.ts");
const preauth = read("backend/src/rls-waves/session-b/b01/preAuthRepository.ts");
const service = read("backend/src/services/auth/inviteService.ts");
const authController = read("backend/src/controllers/authController.ts");
const resendController = read("backend/src/controllers/licenseeInviteController.ts");
const middleware = read("backend/src/middleware/auth.ts");
const authRoutes = read("backend/src/routes/modules/authRoutes.ts");
const routes = read("backend/src/routes/index.ts");

assert.match(repository, /SELECT \* FROM app_rls\.prepare_invitation\(/);
for (const boundAuthority of ["context.userId", "actorSessionId", "context.requestId", "context.purpose"]) {
  assert.match(repository, new RegExp(boundAuthority.replace(".", "\\.")));
}
assert.match(repository, /unexpected projection/);
assert.doesNotMatch(repository, /\$queryRawUnsafe|\bprisma\./);

for (const boundary of ["app_auth.lookup_invitation_token", "app_auth.consume_invitation_token"]) {
  assert.match(preauth, new RegExp(boundary.replace(".", "\\.")));
}
assert.match(preauth, /requestId/);
assert.match(preauth, /inviteId/);
assert.match(preauth, /unexpected projection/);
assert.doesNotMatch(preauth, /\$queryRawUnsafe|\bprisma\./);

assert.match(service, /INVITE_DATABASE_BOUNDARY_REQUIRED/);
assert.match(service, /INVITE_ACTOR_SESSION_REQUIRED/);
assert.doesNotMatch(service, /createAuditLog|\.(?:user|invite|licensee|organization|manufacturerLicenseeLink)\.(?:find|create|update|delete|upsert)/);
assert.ok(service.indexOf("databaseBoundary.run") < service.indexOf("sendAuthEmail({"));

assert.match(authController, /actorSessionId:\s*claims\.sessionId/);
assert.match(authController, /requestId:\s*getRequestId\(req\)/);
assert.match(resendController, /actorSessionId:\s*req\.user!\.sessionId/);
assert.match(resendController, /isCanonicalAuthDenial/);
assert.match(resendController, /clearAuthCookies\(res\)/);

const recentMfa = middleware.slice(middleware.indexOf("export const requireRecentAdminMfa"));
assert.match(recentMfa, /withCanonicalAuthClaims/);
assert.match(recentMfa, /requireRecentMfaSession/);
assert.doesNotMatch(recentMfa, /req\.user\.mfaVerifiedAt|getAdminMfaStatus/);

for (const registeredRoot of [
  /router\.post\("\/auth\/invite"[^\n]+\binvite\)/,
  /router\.post\("\/auth\/accept-invite"[^\n]+\bacceptInviteController\)/,
  /router\.get\("\/auth\/invite-preview"[^\n]+\binvitePreviewController\)/,
]) {
  assert.match(authRoutes, registeredRoot);
}
assert.match(routes, /"\/licensees\/:id\/admin-invite\/resend"[\s\S]{0,500}\bresendLicenseeAdminInvite/);

const { UserRole, UserStatus } = require("@prisma/client");
const { consumeInvitationBoundary } = require("../../../dist/rls-waves/session-b/b01/preAuthRepository");

const run = async () => {
  let queryCount = 0;
  const acceptedName = "n".repeat(120);
  const db = {
    $queryRaw: async () => {
      queryCount += 1;
      return [{
        inviteId: "invite-1",
        id: "user-1",
        email: "invited@example.com",
        name: acceptedName,
        role: UserRole.LICENSEE_ADMIN,
        licenseeId: "licensee-1",
        orgId: "organization-1",
        status: UserStatus.ACTIVE,
      }];
    },
  };
  const input = {
    tokenHashCandidates: ["a".repeat(64)],
    passwordHash: "$argon2id$accepted-invite-password-hash",
    requestedName: acceptedName,
    consumedAt: new Date(),
    requestId: "request-1",
    ipHash: null,
    userAgent: null,
  };

  assert.equal((await consumeInvitationBoundary(input, db)).name, acceptedName);
  await assert.rejects(
    consumeInvitationBoundary({ ...input, requestedName: "n".repeat(121) }, db),
    /invite name exceeds the product limit/
  );
  assert.equal(queryCount, 1, "an over-limit name must be rejected before database access");

  console.log("B01 invitation shared-boundary tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
