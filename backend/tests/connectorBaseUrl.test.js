const assert = require("node:assert/strict");
const { resolveConnectorBaseUrl } = require("../dist/controllers/connectorController");

const request = ({ forwardedProto = "", forwardedFor = "203.0.113.10", origin = "" } = {}) => ({
  socket: { remoteAddress: "172.30.10.2", encrypted: false },
  protocol: "http",
  get: (name) => ({
    host: "mscqr.example",
    origin,
    "x-forwarded-for": forwardedFor,
    "x-forwarded-proto": forwardedProto,
  }[name.toLowerCase()] || ""),
});
const asgRequest = () => ({
  socket: { remoteAddress: "172.30.0.2", encrypted: false },
  protocol: "http",
  get: (name) => ({ host: "mscqr.example", "x-forwarded-for": "203.0.113.10, 198.51.100.10, 10.0.0.10", "x-forwarded-proto": "https" }[name.toLowerCase()] || ""),
});

const keys = ["PUBLIC_API_BASE_URL", "WEB_APP_BASE_URL", "NODE_ENV", "CLIENT_IP_TRUST_MODE", "CLIENT_IP_TRUSTED_NGINX_CIDRS", "CLIENT_IP_TRUSTED_ALB_CIDRS", "CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS"];
const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
try {
  process.env.NODE_ENV = "production";
  process.env.CLIENT_IP_TRUST_MODE = "nginx";
  process.env.CLIENT_IP_TRUSTED_NGINX_CIDRS = "172.30.10.2/32";
  delete process.env.PUBLIC_API_BASE_URL;
  delete process.env.WEB_APP_BASE_URL;
  assert.equal(resolveConnectorBaseUrl(request({ forwardedProto: "https" })), "https://mscqr.example");
  process.env.CLIENT_IP_TRUST_MODE = "cloudfront-alb-nginx";
  process.env.CLIENT_IP_TRUSTED_NGINX_CIDRS = "172.30.0.2/32";
  process.env.CLIENT_IP_TRUSTED_ALB_CIDRS = "10.0.0.0/24";
  process.env.CLIENT_IP_TRUSTED_CLOUDFRONT_CIDRS = "198.51.100.0/24";
  assert.equal(resolveConnectorBaseUrl(asgRequest()), "https://mscqr.example");
  process.env.CLIENT_IP_TRUST_MODE = "nginx";
  assert.equal(resolveConnectorBaseUrl(request({ forwardedProto: "https", origin: "https://origin.example" })), "https://origin.example");
  process.env.PUBLIC_API_BASE_URL = "https://api.example/";
  assert.equal(resolveConnectorBaseUrl(request()), "https://api.example");
  delete process.env.PUBLIC_API_BASE_URL;
  process.env.WEB_APP_BASE_URL = "https://web.example/";
  assert.equal(resolveConnectorBaseUrl(request()), "https://web.example");
} finally {
  for (const [key, value] of Object.entries(previous)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

console.log("connector base URL tests passed");
