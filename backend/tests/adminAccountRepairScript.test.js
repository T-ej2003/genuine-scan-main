const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const run = spawnSync(process.execPath, [path.resolve(__dirname,"../scripts/repair-admin-accounts.js")], { encoding: "utf8" });
assert.equal(run.status, 1);
assert.equal(run.stderr, "");
const result = JSON.parse(run.stdout);
assert.equal(result.code, "PROHIBITED_PLATFORM_ROLE_REPAIR");
assert.equal(result.tokenLogged, false);
console.log("admin account repair prohibition tests passed");
