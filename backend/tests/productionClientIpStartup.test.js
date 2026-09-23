const assert = require("node:assert/strict");

const { createBackendApp } = require("../dist/app");

const keys = ["NODE_ENV", "REQUIRE_REDIS_FOR_SHARED_STATE", "CLIENT_IP_TRUST_MODE", "CLIENT_IP_TRUSTED_ALB_CIDRS", "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS"];
const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));

Object.assign(process.env, {
  NODE_ENV: "production",
  REQUIRE_REDIS_FOR_SHARED_STATE: "false",
  CLIENT_IP_TRUST_MODE: "cloudfront-alb",
  CLIENT_IP_TRUSTED_ALB_CIDRS: "10.0.0.0/20,10.0.16.0/20",
  CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS: "192.0.2.0/24,198.51.100.0/24",
});

assert(createBackendApp(), "production backend must initialize with the generated client-IP trust runtime");
delete process.env.CLIENT_IP_TRUSTED_ALB_CIDRS;
assert.throws(() => createBackendApp(), /reviewed proxy CIDRs/);
process.env.CLIENT_IP_TRUSTED_ALB_CIDRS = "10.0.0.0/20,10.0.16.0/20";
delete process.env.CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS;
assert.throws(() => createBackendApp(), /reviewed proxy CIDRs/);

for (const [key, value] of Object.entries(previous)) {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

console.log("production client-IP startup tests passed");
