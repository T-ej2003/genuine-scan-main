const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const run = spawnSync(process.execPath,[path.resolve(__dirname,"../scripts/seed-launch-smoke-users.js")],{encoding:"utf8"});
assert.equal(run.status,1);
assert.equal(run.stderr,"");
assert.equal(JSON.parse(run.stdout).code,"PROHIBITED_PROTECTED_ENVIRONMENT_SEED");
assert.doesNotMatch(run.stdout,/password|secret|postgresql?:\/\//i);
console.log("launch smoke seed prohibition tests passed");
