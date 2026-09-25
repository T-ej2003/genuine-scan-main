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
  orgId: "00000000-0000-4000-8000-000000000103",
  licenseeId: "00000000-0000-4000-8000-000000000105",
  expiresAt: new Date(Date.now() + 600_000),
};
const deliveryAttempts = [];
let deliveryShouldFail = false;
mock("services/auth/authEmailService.js", { sendAuthEmail: async (input) => {
  deliveryAttempts.push(input);
  if (deliveryShouldFail) throw new Error("mail provider unavailable");
  return { delivered: true };
} });
let resendScope = { orgId: binding.orgId, licenseeId: binding.licenseeId };
mock("rls-waves/session-b/b01/preAuthRepository.js", {
  lookupInvitationBoundary: async () => binding,
  consumeInvitationBoundary: async (input) => ({
    ...binding, challengeId: input.challengeId, challengeExpiresAt: input.challengeExpiresAt,
  }),
  lookupInviteActivationBinding: async () => ({ ...binding, challengeId: "00000000-0000-4000-8000-000000000104" }),
  resendInviteActivationBoundary: async (input) => ({ ...binding, ...resendScope, challengeId: input.newChallengeId, expiresAt: input.expiresAt }),
});

const { acceptInvite, resendInviteActivation } = require("../dist/services/auth/inviteService");
(async () => {
  const pending = await acceptInvite({
    rawToken: "opaque-invite", password: "Good-password-23!", name: null,
    requestId: "test-delivery", ipHash: null, userAgent: null,
  });
  assert.equal(pending.delivered, true);
  assert.equal(deliveryAttempts[0].orgId, binding.orgId);
  assert.equal(deliveryAttempts[0].licenseeId, binding.licenseeId);

  deliveryShouldFail = true;
  const resent = await resendInviteActivation({
    challengeId: "00000000-0000-4000-8000-000000000104", ipHash: null, userAgent: null,
    orgId: "browser-controlled-org", licenseeId: "browser-controlled-licensee",
  });
  assert.equal(resent.delivered, false);
  assert(resent.challengeId, "committed resend remains resumable after mail failure");
  assert.equal(deliveryAttempts[1].orgId, binding.orgId);
  assert.equal(deliveryAttempts[1].licenseeId, binding.licenseeId);

  deliveryShouldFail = false;
  const deliveredResend = await resendInviteActivation({
    challengeId: "00000000-0000-4000-8000-000000000104", ipHash: null, userAgent: null,
  });
  assert.equal(deliveredResend.delivered, true);
  assert.equal(deliveryAttempts[2].orgId, binding.orgId);
  assert.equal(deliveryAttempts[2].licenseeId, binding.licenseeId);

  resendScope = { orgId: null, licenseeId: null };
  await resendInviteActivation({ challengeId: "00000000-0000-4000-8000-000000000104", ipHash: null, userAgent: null });
  assert.equal(deliveryAttempts[3].orgId, null);
  assert.equal(deliveryAttempts[3].licenseeId, null);
  console.log("Invite activation delivery failure tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });
