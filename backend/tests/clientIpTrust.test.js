const assert = require("node:assert/strict");

const { getClientIpTrustConfig, resolveClientIp, trustedClientIpMiddleware } = require("../dist/utils/clientIp");

const request = (remoteAddress, forwardedFor = "") => ({
  socket: { remoteAddress },
  get: (name) => name.toLowerCase() === "x-forwarded-for" ? forwardedFor : "",
});
const response = (onReject = () => assert.fail("trusted request must not reject")) => ({
  status: (status) => ({ json: () => onReject(status) }),
});

const previousEnv = Object.fromEntries(["NODE_ENV", "CLIENT_IP_TRUST_MODE", "CLIENT_IP_TRUSTED_NGINX_CIDRS", "CLIENT_IP_TRUSTED_ALB_CIDRS", "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS", "MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY"].map((key) => [key, process.env[key]]));
Object.assign(process.env, {
  NODE_ENV: "production",
  CLIENT_IP_TRUST_MODE: "cloudfront-alb-nginx",
  CLIENT_IP_TRUSTED_NGINX_CIDRS: "172.30.0.2/32",
  CLIENT_IP_TRUSTED_ALB_CIDRS: "10.0.0.0/24",
  CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS: "198.51.100.0/24",
});
assert.equal(getClientIpTrustConfig().mode, "cloudfront-alb-nginx");
delete process.env.CLIENT_IP_TRUSTED_NGINX_CIDRS;
assert.throws(() => getClientIpTrustConfig(), /reviewed proxy CIDRs/);
process.env.CLIENT_IP_TRUST_MODE = "nginx";
process.env.CLIENT_IP_TRUSTED_NGINX_CIDRS = "172.30.10.2/32";
delete process.env.CLIENT_IP_TRUSTED_ALB_CIDRS;
delete process.env.CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS;
assert.equal(getClientIpTrustConfig().mode, "nginx");
process.env.CLIENT_IP_TRUST_MODE = "direct-loopback-canary";
delete process.env.MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY;
assert.throws(() => getClientIpTrustConfig(), /governed application canary/);
process.env.MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY = "true";
assert.equal(getClientIpTrustConfig().mode, "direct-loopback-canary");
for (const [key, value] of Object.entries(previousEnv)) {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

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

const rootNginxConfig = { mode: "nginx", trustedNginx: (ip) => ip === "172.30.10.2" };
assert.equal(resolveClientIp(request("172.30.10.2", "203.0.113.20"), rootNginxConfig), "203.0.113.20");
assert.throws(() => resolveClientIp(request("172.30.10.3", "203.0.113.20"), rootNginxConfig), /PROXY_CHAIN_DENIED/);
assert.throws(() => resolveClientIp(request("172.30.10.2", "spoofed, 203.0.113.20"), rootNginxConfig), /PROXY_CHAIN_DENIED/);

const canaryConfig = { mode: "direct-loopback-canary" };
assert.equal(resolveClientIp(request("127.0.0.1", "203.0.113.20"), canaryConfig), "127.0.0.1");
assert.equal(resolveClientIp(request("::1", "spoofed"), canaryConfig), "::1");
assert.throws(() => resolveClientIp(request("203.0.113.30", "127.0.0.1"), canaryConfig), /CANARY_LOOPBACK_REQUIRED/);

const nginxConfig = {
  mode: "cloudfront-alb-nginx",
  trustedNginx: (ip) => ip === "172.30.0.2" || ip === "2001:db8:30::2",
  trustedAlb: config.trustedAlb,
  trustedCloudFront: config.trustedCloudFront,
};
assert.equal(resolveClientIp(request("172.30.0.2", "spoofed, 203.0.113.20, 198.51.100.10, 10.0.0.10"), nginxConfig), "203.0.113.20");
assert.equal(resolveClientIp(request("2001:db8:30::2", "2001:db8:1::20, 2001:db8:cf::10, 2001:db8:10::10"), nginxConfig), "2001:db8:1::20");
assert.throws(() => resolveClientIp(request("172.30.0.2", "203.0.113.20, 198.51.100.10"), nginxConfig), /PROXY_CHAIN_DENIED/);
assert.throws(() => resolveClientIp(request("172.30.0.3", "203.0.113.20, 198.51.100.10, 10.0.0.10"), nginxConfig), /PROXY_CHAIN_DENIED/);
assert.throws(() => resolveClientIp(request("172.30.0.2", "203.0.113.20, 198.51.100.10, 10.0.0.11"), nginxConfig), /PROXY_CHAIN_DENIED/);

const req = request("10.0.0.10", "203.0.113.20, 198.51.100.10");
let nextCalled = false;
trustedClientIpMiddleware(config)(req, response(), () => { nextCalled = true; });
assert(nextCalled);
assert.equal(req.ip, "203.0.113.20", "all request consumers, including auth risk, receive the validated viewer IP");

const livenessReq = { ...request("::ffff:127.0.0.1"), path: "/health/live" };
trustedClientIpMiddleware(nginxConfig)(livenessReq, response(), () => { nextCalled = true; });
assert.equal(livenessReq.ip, "127.0.0.1");

const albLivenessReq = { ...request("10.0.0.10"), path: "/health/live" };
trustedClientIpMiddleware(nginxConfig)(albLivenessReq, response(), () => {});
assert.equal(albLivenessReq.ip, "10.0.0.10");

for (const deniedReq of [
  { ...request("203.0.113.30"), path: "/health/live" },
  { ...request("10.0.0.10"), path: "/api/auth/login" },
  { ...request("203.0.113.30", "198.51.100.99, 203.0.113.20, 198.51.100.10, 10.0.0.10"), path: "/api/auth/login" },
]) {
  let rejectedStatus;
  trustedClientIpMiddleware(nginxConfig)(deniedReq, response((status) => { rejectedStatus = status; }), () => assert.fail("untrusted request must reject"));
  assert.equal(rejectedStatus, 400);
}

for (const canaryReq of [
  { ...request("127.0.0.1"), path: "/api/health/ready" },
  { ...request("127.0.0.1", "203.0.113.20"), path: "/api/auth/login" },
]) {
  let canaryNext = false;
  trustedClientIpMiddleware(canaryConfig)(canaryReq, response(), () => { canaryNext = true; });
  assert(canaryNext);
  assert.equal(canaryReq.ip, "127.0.0.1");
}
let canaryRejectedStatus;
trustedClientIpMiddleware(canaryConfig)({ ...request("203.0.113.30", "127.0.0.1"), path: "/api/health/ready" }, response((status) => { canaryRejectedStatus = status; }), () => assert.fail("non-loopback canary request must reject"));
assert.equal(canaryRejectedStatus, 400);
console.log("client IP trust tests passed");
