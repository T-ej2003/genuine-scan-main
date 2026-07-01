const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const script = fs.readFileSync(path.join(repoRoot, "backend/scripts/resend-password-setup-link.js"), "utf8");
const inviteService = fs.readFileSync(path.join(repoRoot, "backend/src/services/auth/inviteService.ts"), "utf8");
const packageJson = JSON.parse(fs.readFileSync(path.join(repoRoot, "backend/package.json"), "utf8"));

assert(script.includes('DEFAULT_EMAIL = "victoria@mscqr.com"'), "script should default to Victoria's account");
assert(script.includes('DEFAULT_ACTOR_EMAIL = "administration@mscqr.com"'), "script should default to the audited platform actor");
assert(script.includes("apply: false"), "script must be dry-run unless --apply is explicit");
assert(script.includes("Target user does not exist; refusing to create"), "script must refuse missing users");
assert(script.includes("requireExistingUser: true"), "setup resend must not create users");
assert(script.includes("requestPasswordReset({"), "script must use reset service when setup invite is not applicable");
assert(script.includes("tokenLogged: false"), "script output must explicitly avoid token logging");
assert(!script.includes("inviteLink"), "script must not print or reference raw invite links");
assert(!script.includes("resetUrl"), "script must not print or reference raw reset links");
assert(script.includes('require("../dist/services/auth/inviteService")'), "runtime script must use compiled backend services");
assert(script.includes('require("../dist/services/auth/passwordResetService")'), "runtime script must use compiled password reset service");
assert.strictEqual(packageJson.scripts["auth:resend-setup-link"], "node scripts/resend-password-setup-link.js");
assert(!packageJson.scripts["auth:resend-setup-link"].includes("tsx"), "runtime script must not depend on tsx");
assert(inviteService.includes("requireExistingUser?: boolean"), "invite service must expose an existing-user guard");
assert(inviteService.includes('if (requireExistingUser) throw new Error("Existing user is required for invite resend")'), "invite service guard must prevent create-on-missing");

console.log("password setup link script contract tests passed");
