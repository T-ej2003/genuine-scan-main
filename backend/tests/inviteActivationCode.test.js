const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

process.env.TOKEN_HASH_SECRET_CURRENT = "invite-activation-test-current-key";
process.env.TOKEN_HASH_SECRET_PREVIOUS = "invite-activation-test-previous-key";

const { newInviteActivationCode, inviteActivationVerifier, inviteActivationVerifierCandidates } =
  require("../dist/services/auth/inviteActivationCode");
const source = fs.readFileSync(path.join(__dirname, "../src/services/auth/inviteActivationCode.ts"), "utf8");
assert.match(source, /randomInt\(0, 1_000_000\)/);
assert.doesNotMatch(source, /Math\.random|createHash\(/);

const binding = {
  challengeId: "00000000-0000-4000-8000-000000000101",
  userId: "user-1",
  inviteId: "invite-1",
  email: "invited@example.invalid",
};
for (let n = 0; n < 100; n++) assert.match(newInviteActivationCode(), /^\d{6}$/);
const code = "000123";
const verifier = inviteActivationVerifier(binding, code);
assert.match(verifier, /^[0-9a-f]{12}:[0-9a-f]{64}$/);
assert(!verifier.includes(code));
assert(inviteActivationVerifierCandidates(binding, code).includes(verifier));
assert.equal(inviteActivationVerifierCandidates(binding, code).length, 2);
for (const field of ["challengeId", "userId", "inviteId", "email"]) {
  assert.notEqual(inviteActivationVerifier({ ...binding, [field]: `${binding[field]}-other` }, code), verifier);
}
assert.notEqual(inviteActivationVerifier(binding, "000124"), verifier);
assert.match(source, /INVITE_ACTIVATION:v1/);

console.log("Invite activation code cryptography tests passed");
