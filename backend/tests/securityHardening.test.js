const assert = require("assert");

const {
  buildPublicActorRateLimitKey,
  buildPublicIpRateLimitKey,
} = require("../dist/middleware/publicRateLimit");
const { sanitizeUnknownInput } = require("../dist/middleware/requestSanitizer");

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

assert.notStrictEqual(actorKey, actorKeyOtherEmail, "actor bucket should change when the actor identity changes");
assert(
  actorKey.includes("public:verify.code:actor:"),
  "actor bucket should carry the public scope prefix"
);
assert(
  ipKey.includes("public:verify.code:ip:"),
  "IP bucket should carry the public scope prefix"
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
