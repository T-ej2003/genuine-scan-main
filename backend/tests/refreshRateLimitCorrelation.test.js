const assert = require("node:assert/strict");

const { recordRateLimitMetric } = require("../dist/observability/rateLimitMetrics");
const originalWarn = console.warn;
const emitted = [];
console.warn = (message, meta) => emitted.push({ message, meta });

try {
  const req = {
    method: "POST",
    path: "/auth/refresh",
    ip: "192.0.2.5",
    requestId: "11111111-1111-4111-8111-111111111111",
    headers: {},
    query: {},
    params: {},
    get: (name) => name === "user-agent" ? "test-browser" : undefined,
    rateLimit: { resetTime: new Date(Date.now() + 5_000) },
  };
  recordRateLimitMetric(req, "account.security:actor");
  assert.equal(emitted[0].meta.requestId, req.requestId);
  assert.equal(emitted[0].meta.offenderKind, "ip-ua");
  assert.doesNotMatch(JSON.stringify(emitted[0]), /192\.0\.2\.5|test-browser/);

  req.requestId = "unvalidated\nrequest";
  recordRateLimitMetric(req, "account.security:actor");
  assert.equal(Object.hasOwn(emitted[1].meta, "requestId"), false);

  req.requestId = "22222222-2222-4222-8222-222222222222";
  recordRateLimitMetric(req, "other:actor");
  assert.equal(Object.hasOwn(emitted[2].meta, "requestId"), false);
} finally {
  console.warn = originalWarn;
}
