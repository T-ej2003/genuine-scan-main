const assert = require("assert");

process.env.JWT_SECRET = process.env.JWT_SECRET || "test-jwt-secret";

const {
  __resetRateLimitMetricsForTests,
  getRateLimitAlertCandidates,
  getRateLimitAnalyticsSummary,
  recordRateLimitMetric,
} = require("../dist/observability/rateLimitMetrics");

const createRequest = ({
  method = "GET",
  baseUrl = "",
  routePath = "/",
  ip = "203.0.113.10",
  headers = {},
  user = undefined,
  query = {},
  params = {},
}) => ({
  method,
  baseUrl,
  route: { path: routePath },
  path: routePath,
  originalUrl: `${baseUrl}${routePath}`,
  ip,
  socket: { remoteAddress: ip },
  params,
  query,
  body: {},
  user,
  authMode: headers.authorization ? "bearer" : user ? "authenticated" : "anonymous",
  get(name) {
    return headers[String(name || "").toLowerCase()] || headers[name] || "";
  },
  rateLimit: {
    resetTime: new Date(Date.now() + 30_000),
  },
});

__resetRateLimitMetricsForTests();

for (let index = 0; index < 22; index += 1) {
  recordRateLimitMetric(
    createRequest({
      baseUrl: "",
      routePath: "/licensees",
      headers: { authorization: "Bearer tenant-licensee-token", "user-agent": "jest-suite" },
      user: { userId: "admin-1", role: "PLATFORM_SUPER_ADMIN", licenseeId: "lic-123" },
    }),
    "licensees.read"
  );
}

for (let index = 0; index < 9; index += 1) {
  recordRateLimitMetric(
    createRequest({
      baseUrl: "/audit",
      routePath: "/logs/export",
      headers: { authorization: "Bearer audit-export-token", "user-agent": "jest-suite" },
      user: { userId: "admin-2", role: "PLATFORM_SUPER_ADMIN", licenseeId: "lic-123" },
    }),
    "audit.export"
  );
}

for (let index = 0; index < 11; index += 1) {
  recordRateLimitMetric(
    createRequest({
      baseUrl: "",
      routePath: "/verify/:code/claim",
      headers: { authorization: "Bearer verify-claim-token", "user-agent": "jest-suite", "x-device-fp": "device-42" },
      params: { code: "AADS00000020171" },
      query: {},
    }),
    "verify.claim"
  );
}

for (let index = 0; index < 26; index += 1) {
  recordRateLimitMetric(
    createRequest({
      baseUrl: "",
      routePath: "/manufacturer/printer-agent/heartbeat",
      headers: { authorization: "Bearer printer-agent-token", "user-agent": "jest-suite", "x-printer-gateway-id": "gateway-1" },
      user: { userId: "ops-1", role: "OPS_USER", licenseeId: "lic-123" },
    }),
    "printer-agent.heartbeat"
  );
}

for (let index = 0; index < 16; index += 1) {
  recordRateLimitMetric(
    createRequest({
      baseUrl: "",
      routePath: "/support/tickets",
      headers: { authorization: "Bearer support-token", "user-agent": "jest-suite" },
      user: { userId: "support-1", role: "PLATFORM_SUPER_ADMIN", licenseeId: "lic-999" },
    }),
    "support.read"
  );
}

const summary = getRateLimitAnalyticsSummary();
assert(summary.totalEvents >= 84, "rate-limit analytics should count the recorded events");
assert(summary.topLimitedRoutes.some((entry) => entry.route.includes("/licensees")), "licensee routes should appear in top limited routes");
assert(summary.repeatedOffenders.length > 0, "repeated offender fingerprints should be reported");
assert(summary.tenantBurstAnomalies.some((entry) => entry.family === "licensees.read"), "tenant burst anomalies should include licensee reads");
assert(summary.exportAbusePatterns.some((entry) => entry.family === "audit.export"), "export abuse patterns should include audit exports");

const alerts = getRateLimitAlertCandidates();
assert(alerts.alerts.some((entry) => entry.family === "licensees.read"), "licensee read spikes should produce alert candidates");
assert(alerts.alerts.some((entry) => entry.family === "verify.claim"), "verify claim spikes should produce alert candidates");

console.log("rate limit analytics tests passed");
