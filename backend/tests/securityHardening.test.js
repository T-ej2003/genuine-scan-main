const assert = require("assert");

const {
  buildPublicActorRateLimitKey,
  buildPublicIpRateLimitKey,
} = require("../dist/middleware/publicRateLimit");
const { sanitizeUnknownInput } = require("../dist/middleware/requestSanitizer");
const { hashIp } = require("../dist/utils/security");

const request = {
  ip: "198.51.100.42",
  socket: { remoteAddress: "198.51.100.42" },
  params: { code: "AADS00000020171" },
  query: { device: "scanner-1" },
  body: { email: "Admin@example.com", note: "ok" },
  get(name) {
    if (String(name).toLowerCase() === "user-agent") return "Mozilla/5.0";
    if (String(name).toLowerCase() === "authorization") return "Bearer sample-token";
    return "";
  },
};

const actorKey = buildPublicActorRateLimitKey(
  request,
  "verify.code",
  (req) => req.body.email,
  (req) => req.params.code
);
const actorKeyOtherEmail = buildPublicActorRateLimitKey(
  { ...request, body: { email: "other@example.com" } },
  "verify.code",
  (req) => req.body.email,
  (req) => req.params.code
);
const ipKey = buildPublicIpRateLimitKey(request, "verify.code", (req) => req.params.code);
const mappedIpKey = buildPublicIpRateLimitKey(
  {
    ...request,
    ip: "::ffff:198.51.100.42",
    socket: { remoteAddress: "::ffff:198.51.100.42" },
  },
  "verify.code",
  (req) => req.params.code
);

assert.notStrictEqual(actorKey, actorKeyOtherEmail, "actor bucket should change when the actor identity changes");
assert(
  actorKey.includes("public:verify.code:actor:"),
  "actor bucket should carry the public scope prefix"
);
assert(
  ipKey.includes("public:verify.code:ip:"),
  "IP bucket should carry the public scope prefix"
);
assert.strictEqual(
  ipKey,
  mappedIpKey,
  "IPv4 and IPv4-mapped IPv6 addresses must resolve to the same public IP rate-limit key"
);
assert.strictEqual(
  hashIp("203.0.113.77"),
  hashIp("::ffff:203.0.113.77"),
  "IP hash canonicalization should treat IPv4 and mapped IPv6 addresses as the same client"
);

const sanitized = sanitizeUnknownInput(
  {
    title: "hi\u0000there",
    nested: { description: "ok\u0007" },
  },
  "body"
);

assert.deepStrictEqual(sanitized, {
  title: "hithere",
  nested: { description: "ok" },
});

const polluted = Object.create(null);
polluted.__proto__ = "boom";

assert.throws(
  () => sanitizeUnknownInput(polluted, "body"),
  /not allowed/i,
  "prototype pollution keys should be rejected"
);

console.log("security hardening tests passed");
