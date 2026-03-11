const assert = require("assert");
const { buildPublicVerifyRateLimitKey } = require("../dist/middleware/publicVerifyRateLimit");

const buildRequest = ({ code, token, device, auth, ip }) => ({
  params: code ? { code } : {},
  query: {
    ...(token ? { t: token } : {}),
    ...(device ? { device } : {}),
  },
  ip: ip || "203.0.113.9",
  socket: { remoteAddress: ip || "203.0.113.9" },
  get(name) {
    if (String(name).toLowerCase() === "authorization") return auth || "";
    return "";
  },
});

const verifyKeyOne = buildPublicVerifyRateLimitKey(
  buildRequest({
    code: "AADS00000020171",
    device: "device-a",
    ip: "198.51.100.1",
  }),
  "verify"
);

const verifyKeyTwo = buildPublicVerifyRateLimitKey(
  buildRequest({
    code: "AADS00000020171",
    device: "device-b",
    ip: "198.51.100.1",
  }),
  "verify"
);

assert.notStrictEqual(
  verifyKeyOne,
  verifyKeyTwo,
  "different devices on the same IP should not share the same public verify bucket"
);

const customerKey = buildPublicVerifyRateLimitKey(
  buildRequest({
    token: "signed-scan-token",
    device: "device-a",
    auth: "Bearer customer-session-token",
  }),
  "scan"
);

assert(
  customerKey.includes("public:scan:token:"),
  "scan rate limit key should bind to the signed token resource"
);
assert(
  customerKey.includes(":cust:"),
  "authenticated customer requests should use the bearer token fingerprint as the actor key"
);

console.log("public verify rate-limit tests passed");
