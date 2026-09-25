const assert = require("node:assert/strict");
const path = require("node:path");

process.env.TOKEN_HASH_SECRET_CURRENT = "invite-activation-delivery-local-key";
const distRoot = path.resolve(__dirname, "../dist");
const mock = (name, exports) => {
  const id = require.resolve(path.join(distRoot, name));
  require.cache[id] = { id, filename: id, loaded: true, exports };
};

const binding = {
  inviteId: "00000000-0000-4000-8000-000000000101",
  userId: "00000000-0000-4000-8000-000000000102",
  email: "invited@example.invalid",
};
mock("services/auth/authEmailService.js", { sendAuthEmail: async () => { throw new Error("mail provider unavailable"); } });
mock("rls-waves/session-b/b01/preAuthRepository.js", {
  lookupInvitationBoundary: async () => binding,
  consumeInvitationBoundary: async (input) => ({
    ...binding, challengeId: input.challengeId, challengeExpiresAt: input.challengeExpiresAt,
    orgId: "00000000-0000-4000-8000-000000000103", licenseeId: null,
  }),
  lookupInviteActivationBinding: async () => ({ ...binding, challengeId: "00000000-0000-4000-8000-000000000104" }),
  resendInviteActivationBoundary: async (input) => ({ ...binding, challengeId: input.newChallengeId }),
});

const { acceptInvite, resendInviteActivation } = require("../dist/services/auth/inviteService");
(async () => {
  const pending = await acceptInvite({
    rawToken: "opaque-invite", password: "Good-password-23!", name: null,
    requestId: "test-delivery", ipHash: null, userAgent: null,
  });
  assert.equal(pending.delivered, false);
  assert(pending.challengeId, "committed TX1 remains resumable after mail failure");
  const resent = await resendInviteActivation({
    challengeId: "00000000-0000-4000-8000-000000000104", ipHash: null, userAgent: null,
  });
  assert.equal(resent.delivered, false);
  assert(resent.challengeId, "committed resend remains resumable after mail failure");
  console.log("Invite activation delivery failure tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
