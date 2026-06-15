const assert = require("assert");
const {
  expectPublicResponseSafe,
  stablePublicContract,
} = require("./helpers/publicEgressContract");
const {
  ids,
  request,
  state,
  withServer,
} = require("./helpers/p1TestApp");

const sortKeys = (value) => Object.keys(value || {}).sort();

const assertJsonObject = (response, name) => {
  assert(
    response.payload && typeof response.payload === "object" && !Array.isArray(response.payload),
    `${name}: expected JSON object response, got ${response.text}`
  );
};

const assertExpectedTopLevelKeys = (payload, expectedKeys, name) => {
  if (!expectedKeys) return;
  assert.deepStrictEqual(sortKeys(payload), [...expectedKeys].sort(), `${name}: unexpected top-level public shape`);
};

const assertStableShape = (payload, expectedStableKeys, name) => {
  if (!expectedStableKeys) return;
  const stable = stablePublicContract(payload);
  assert.deepStrictEqual(sortKeys(stable), [...expectedStableKeys].sort(), `${name}: unexpected stable top-level keys`);
};

const configurePublicFixtures = () => {
  Object.assign(state.supportTickets[0], {
    referenceCode: "P1SUPA",
    incidentId: ids.incidentA,
    priority: "P2",
    customerEmail: "customer-a@mscqr.test",
    updatedAt: new Date("2026-04-05T09:00:00.000Z"),
    slaDueAt: new Date("2026-04-06T09:00:00.000Z"),
  });
  Object.assign(state.incidents[0], {
    id: ids.incidentA,
    status: "OPEN",
    severity: "HIGH",
    handoff: {
      currentStage: "INTAKE",
      slaDueAt: new Date("2026-04-06T09:00:00.000Z"),
    },
  });
};

const endpointMatrix = [
  {
    name: "direct health status",
    method: "GET",
    path: "/health",
    statuses: [200],
    topLevelKeys: ["release", "status", "timestamp"],
  },
  {
    name: "direct live health",
    method: "GET",
    path: "/health/live",
    statuses: [200],
    topLevelKeys: ["release", "status", "timestamp"],
  },
  {
    name: "direct ready health",
    method: "GET",
    path: "/health/ready",
    statuses: [200, 503],
    topLevelKeys: ["dependencies", "ms", "release", "status", "success", "timestamp", "uptimeSec"],
  },
  {
    name: "api health status",
    method: "GET",
    path: "/api/health",
    statuses: [200, 503],
    topLevelKeys: ["dependencies", "ms", "release", "status", "success", "timestamp", "uptimeSec"],
  },
  {
    name: "api latency health",
    method: "GET",
    path: "/api/health/latency",
    statuses: [200, 503],
    topLevelKeys: ["dependencies", "latency", "ms", "release", "status", "success", "timestamp", "uptimeSec"],
  },
  {
    name: "customer oauth provider bootstrap",
    method: "GET",
    path: "/api/verify/auth/providers",
    statuses: [200],
    topLevelKeys: ["data", "success"],
  },
  {
    name: "anonymous customer verify auth session",
    method: "GET",
    path: "/api/verify/auth/session",
    statuses: [200],
    topLevelKeys: ["data", "success"],
  },
  {
    name: "public connector releases manifest",
    method: "GET",
    path: "/api/public/connector/releases",
    statuses: [200, 503],
    topLevelKeysByStatus: {
      200: ["data", "success"],
      503: ["error", "success"],
    },
  },
  {
    name: "public connector latest manifest",
    method: "GET",
    path: "/api/public/connector/releases/latest",
    statuses: [200, 503],
    topLevelKeysByStatus: {
      200: ["data", "success"],
      503: ["error", "success"],
    },
  },
  {
    name: "support ticket public tracking success",
    method: "GET",
    path: "/api/support/tickets/track/P1SUPA?email=customer-a%40mscqr.test",
    statuses: [200],
    topLevelKeys: ["data", "success"],
  },
  {
    name: "support ticket public tracking invalid reference",
    method: "GET",
    path: "/api/support/tickets/track/bad!",
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "support ticket public tracking missing reference",
    method: "GET",
    path: "/api/support/tickets/track/NOPE",
    statuses: [404],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "verify invalid code",
    method: "GET",
    path: "/api/verify/A",
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "scan missing token",
    method: "GET",
    path: "/api/scan",
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "scan malformed token",
    method: "GET",
    path: "/api/scan?t=too-short",
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "session start invalid token",
    method: "POST",
    path: "/api/verify/session/start",
    body: {
      sessionStartToken: "invalid-public-session-start-token",
      entryMethod: "SIGNED_SCAN",
    },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "session start missing body",
    method: "POST",
    path: "/api/verify/session/start",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "request access validation error",
    method: "POST",
    path: "/api/public/request-access",
    body: { fullName: "", workEmail: "bad", website: "" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "public support validation error",
    method: "POST",
    path: "/api/public/support",
    body: { name: "", email: "bad", website: "" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "fraud report validation error canonical route",
    method: "POST",
    path: "/api/verify/report-fraud",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "fraud report validation error legacy route",
    method: "POST",
    path: "/api/fraud-report",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "product feedback validation error",
    method: "POST",
    path: "/api/verify/feedback",
    body: { code: "MSC0001", rating: 6, satisfaction: "invalid" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "incident report validation error",
    method: "POST",
    path: "/api/incidents/report",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "oauth exchange validation error",
    method: "POST",
    path: "/api/verify/auth/oauth/exchange",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "email otp request validation error",
    method: "POST",
    path: "/api/verify/auth/email-otp/request",
    body: { email: "not-an-email" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "email otp verify validation error",
    method: "POST",
    path: "/api/verify/auth/email-otp/verify",
    body: { challengeToken: "short", otp: "" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "passkey assertion begin validation error",
    method: "POST",
    path: "/api/verify/auth/passkey/assertion/begin",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "passkey assertion finish validation error",
    method: "POST",
    path: "/api/verify/auth/passkey/assertion/finish",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth login validation error",
    method: "POST",
    path: "/api/auth/login",
    body: { email: "bad" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth forgot password validation error",
    method: "POST",
    path: "/api/auth/forgot-password",
    body: { email: "bad" },
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth reset password validation error",
    method: "POST",
    path: "/api/auth/reset-password",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth accept invite validation error",
    method: "POST",
    path: "/api/auth/accept-invite",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth invite preview validation error",
    method: "GET",
    path: "/api/auth/invite-preview",
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth verify email validation error",
    method: "POST",
    path: "/api/auth/verify-email",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth me anonymous denial",
    method: "GET",
    path: "/api/auth/me",
    statuses: [401],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "auth refresh anonymous denial",
    method: "POST",
    path: "/api/auth/refresh",
    body: {},
    statuses: [401, 403],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "route transition telemetry validation error",
    method: "POST",
    path: "/api/telemetry/route-transition",
    body: {},
    statuses: [400],
    topLevelKeys: ["error", "success"],
  },
  {
    name: "unknown public api route",
    method: "GET",
    path: "/api/public/does-not-exist",
    statuses: [404],
    topLevelKeys: ["error", "success"],
  },
];

(async () => {
  assert.throws(
    () => expectPublicResponseSafe({ result: { decisionId: "decision-internal" } }),
    /Forbidden public key found at response\.result\.decisionId/
  );
  assert.throws(
    () => expectPublicResponseSafe({ error: { details: "Manual Registry Lookup" } }),
    /Forbidden public string found at response\.error\.details: "Manual Registry Lookup"/
  );

  configurePublicFixtures();

  await withServer(async (baseUrl) => {
    for (const endpoint of endpointMatrix) {
      const response = await request(baseUrl, endpoint.method, endpoint.path, null, endpoint.body, endpoint.headers);
      assert(
        endpoint.statuses.includes(response.status),
        `${endpoint.name}: expected ${endpoint.statuses.join("/")}, got ${response.status}: ${response.text}`
      );
      assertJsonObject(response, endpoint.name);
      assertExpectedTopLevelKeys(
        response.payload,
        endpoint.topLevelKeysByStatus?.[response.status] || endpoint.topLevelKeys,
        endpoint.name
      );
      assertStableShape(response.payload, endpoint.stableTopLevelKeys, endpoint.name);
      expectPublicResponseSafe(response.payload, {
        allowedKeys: endpoint.allowedKeys,
        allowedStrings: endpoint.allowedStrings,
        forbiddenKeysExtra: endpoint.forbiddenKeysExtra,
        forbiddenStringsExtra: endpoint.forbiddenStringsExtra,
      });
      assert.doesNotMatch(
        response.text,
        /at\s+\S+\s+\(|PrismaClient|DATABASE_URL|JWT_SECRET|passwordHash|tokenHash|SELECT\s+|INSERT\s+|UPDATE\s+/i,
        `${endpoint.name}: leaked stack, database, or secret-like detail`
      );
    }
  });

  console.log("public egress contract tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
