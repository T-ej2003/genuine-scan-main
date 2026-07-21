const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname,"../..");
const source = fs.readFileSync(path.join(repoRoot,"backend/scripts/resend-password-setup-link.js"),"utf8");
assert(source.includes("reissueAccountSetupLink"));
assert(source.includes("app_ops.reissue_account_setup_link"));
assert(source.includes("--target-user-id"));
assert(source.includes("--operator-id"));
assert(source.includes("--approval-id"));
assert(source.includes('assurance: "operator-approved"'));
assert(!source.includes("prisma.user"));
assert(!source.includes("inviteLink"));
assert(!source.includes("resetUrl"));
console.log("password setup link operator-boundary tests passed");
