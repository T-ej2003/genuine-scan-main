const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { UserRole } = require("@prisma/client");

const serviceSource = fs.readFileSync(
  path.resolve(__dirname, "../src/services/auth/inviteService.ts"),
  "utf8"
);
const directorySource = fs.readFileSync(
  path.resolve(__dirname, "../src/controllers/userController.ts"),
  "utf8"
);
const directorySql = fs.readFileSync(
  path.resolve(__dirname, "../src/rls-waves/session-a/operationalReadBoundaries.sql"),
  "utf8"
);
const manufacturerHooks = fs.readFileSync(
  path.resolve(__dirname, "../../src/features/manufacturers/hooks.ts"),
  "utf8"
);
const licenseeFlow = fs.readFileSync(
  path.resolve(__dirname, "../../src/features/licensees/useCreateLicenseeFlow.ts"),
  "utf8"
);
const { normalizeInviteRole } = require("../dist/services/auth/inviteService");

assert.equal(normalizeInviteRole("MANUFACTURER"), UserRole.MANUFACTURER_ADMIN);
assert.equal(normalizeInviteRole("MANUFACTURER_ADMIN"), UserRole.MANUFACTURER_ADMIN);
assert.throws(() => normalizeInviteRole("MANUFACTURER_USER"), /Unsupported role/);
assert.throws(() => normalizeInviteRole("ORG_ADMIN"), /Unsupported role/);
assert.match(serviceSource, /const role = normalizeInviteRole\(input\.role\)/);
assert.match(serviceSource, /requestedRole: role/);
assert.match(directorySource, /rawRoleFilter === "MANUFACTURER"\s*\?\s*UserRole\.MANUFACTURER_ADMIN/);
assert.doesNotMatch(directorySql, /role_filter NOT IN \([^)]*'MANUFACTURER'/);
assert.match(manufacturerHooks, /getUsers\(\{ licenseeId: scope, role: "MANUFACTURER" \}\)/);
assert.match(manufacturerHooks, /inviteUser\(\{[\s\S]*?role: "MANUFACTURER"/);
assert.match(licenseeFlow, /inviteUser\(\{[\s\S]*?role: "MANUFACTURER"/);

console.log("Manufacturer transport compatibility tests passed");
