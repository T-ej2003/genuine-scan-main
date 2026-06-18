const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const script = fs.readFileSync(path.join(repoRoot, "backend/scripts/repair-admin-accounts.js"), "utf8");
const packageJson = JSON.parse(fs.readFileSync(path.join(repoRoot, "backend/package.json"), "utf8"));

assert(script.includes('const isApply = process.argv.includes("--apply")'), "repair script must be dry-run unless --apply is explicit");
assert(script.includes('const ADMIN_EMAIL = "administration@mscqr.com"'), "administration account must be repaired");
assert(script.includes('const VICTORIA_EMAIL = "victoria@mscqr.com"'), "Victoria platform admin must be repaired");
assert(script.includes("role: UserRole.SUPER_ADMIN"), "administration account must become SUPER_ADMIN");
assert(script.includes("UserRole.PLATFORM_SUPER_ADMIN"), "Victoria must be PLATFORM_SUPER_ADMIN");
assert(script.includes("createInvite({"), "Victoria setup email must use the existing invite flow");
assert(script.includes("allowExistingInvitedUser: true"), "repair script must be idempotent for invited users");
assert(script.includes("tokenLogged: false"), "repair output must explicitly avoid token logging");
assert(!script.includes("inviteLink"), "repair script must not log invite links");
assert(script.includes('require("../dist/services/auth/inviteService")'), "runtime repair script must use compiled backend services");
assert.strictEqual(packageJson.scripts["repair:admin-accounts"], "node scripts/repair-admin-accounts.js");
assert(!packageJson.scripts["repair:admin-accounts"].includes("tsx"), "runtime repair script must not depend on tsx");

console.log("admin account repair script contract tests passed");
