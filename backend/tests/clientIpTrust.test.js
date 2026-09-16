const assert = require("node:assert/strict");

const { resolveClientIp, trustedClientIpMiddleware } = require("../dist/utils/clientIp");

const request = (remoteAddress, forwardedFor = "") => ({
  socket: { remoteAddress },
  get: (name) => name.toLowerCase() === "x-forwarded-for" ? forwardedFor : "",
});

const config = {
  mode: "cloudfront-alb",
  trustedAlb: (ip) => ip === "10.0.0.10" || ip === "2001:db8:10::10",
  trustedCloudFront: (ip) => ip === "198.51.100.10" || ip === "2001:db8:cf::10",
};

assert.equal(resolveClientIp(request("10.0.0.10", "203.0.113.20, 198.51.100.10"), config), "203.0.113.20");
assert.equal(resolveClientIp(request("10.0.0.10", "spoofed, 203.0.113.20, 198.51.100.10"), config), "203.0.113.20");
assert.equal(resolveClientIp(request("2001:db8:10::10", "2001:db8:1::20, 2001:db8:cf::10"), config), "2001:db8:1::20");
assert.equal(resolveClientIp(request("::ffff:127.0.0.1", "spoofed"), { mode: "direct" }), "127.0.0.1");
assert.throws(() => resolveClientIp(request("10.0.0.10", "203.0.113.20"), config), /PROXY_CHAIN_DENIED/);
assert.throws(() => resolveClientIp(request("10.0.0.10", "203.0.113.20, 203.0.113.21"), config), /PROXY_CHAIN_DENIED/);
assert.throws(() => resolveClientIp(request("203.0.113.30", "203.0.113.20, 198.51.100.10"), config), /PROXY_CHAIN_DENIED/);

const req = request("10.0.0.10", "203.0.113.20, 198.51.100.10");
let nextCalled = false;
trustedClientIpMiddleware(config)(req, { status: () => ({ json: () => assert.fail("trusted chain must not reject") }) }, () => { nextCalled = true; });
assert(nextCalled);
assert.equal(req.ip, "203.0.113.20", "all request consumers, including auth risk, receive the validated viewer IP");
console.log("client IP trust tests passed");
