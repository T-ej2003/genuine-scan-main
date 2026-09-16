const assert = require("node:assert/strict");
const { resolveExternalProtocol } = require("../dist/utils/clientIp");

const request = ({ remoteAddress, forwardedFor = "", forwardedProto = "", encrypted = false }) => ({
  socket: { remoteAddress, encrypted },
  get: (name) => ({
    "x-forwarded-for": forwardedFor,
    "x-forwarded-proto": forwardedProto,
  }[name.toLowerCase()] || ""),
});

const direct = { mode: "direct" };
const rootNginx = { mode: "nginx", trustedNginx: (ip) => ip === "172.30.10.2" };
const asg = {
  mode: "cloudfront-alb-nginx",
  trustedNginx: (ip) => ip === "172.30.0.2",
  trustedAlb: (ip) => ip === "10.0.0.10",
  trustedCloudFront: (ip) => ip === "198.51.100.10",
};

assert.equal(resolveExternalProtocol(request({ remoteAddress: "203.0.113.10", encrypted: true, forwardedProto: "http" }), direct), "https");
assert.equal(resolveExternalProtocol(request({ remoteAddress: "172.30.10.2", forwardedFor: "203.0.113.10", forwardedProto: "https" }), rootNginx), "https");
assert.equal(resolveExternalProtocol(request({ remoteAddress: "172.30.0.2", forwardedFor: "203.0.113.10, 198.51.100.10, 10.0.0.10", forwardedProto: "https" }), asg), "https");
assert.equal(resolveExternalProtocol(request({ remoteAddress: "203.0.113.20", forwardedProto: "https" }), rootNginx), "http");
for (const forwardedProto of ["https,http", "https, https", "javascript", "ftp", ""])
  assert.equal(resolveExternalProtocol(request({ remoteAddress: "172.30.10.2", forwardedFor: "203.0.113.10", forwardedProto }), rootNginx), "http");
assert.equal(resolveExternalProtocol(request({ remoteAddress: "172.30.10.2", forwardedFor: "203.0.113.10", forwardedProto: "HTTP" }), rootNginx), "http");

console.log("external protocol trust tests passed");
