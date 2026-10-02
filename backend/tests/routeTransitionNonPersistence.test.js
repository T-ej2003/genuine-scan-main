const assert = require("node:assert/strict");
const path = require("node:path");
const siem = require.resolve("../dist/services/siemOutboxService");
require.cache[siem] = { id: siem, filename: siem, loaded: true, exports: { queueSecurityEvent: async () => {} } };
const { captureRouteTransitionMetric, getRouteTransitionSummary } = require("../dist/controllers/telemetryController");
const response = () => ({ statusCode: 200, body: null, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } });
(async () => {
  for (const user of [undefined, { userId: "local-test", role: "LICENSEE_ADMIN" }]) {
    const res = response();
    await captureRouteTransitionMetric({ user, body: { routeTo: "/qr-requests", transitionMs: 25 } }, res);
    assert.equal(res.statusCode, 202);
    assert.equal(res.body.success, false);
    assert.equal(res.body.code, "TELEMETRY_NOT_PERSISTED");
    assert.equal(res.body.errorCode, res.body.code);
    assert.equal(res.body.data.accepted, false);
    assert.equal(res.body.data.persisted, false);
  }
  for (const body of [{}, { routeTo: "/qr", transitionMs: -1 }, { routeTo: "/qr", transitionMs: 1, licenseeId: "forged" }]) {
    const res = response(); await captureRouteTransitionMetric({ body }, res); assert.equal(res.statusCode, 400);
  }
  const summary = response(); await getRouteTransitionSummary({ user: { role: "LICENSEE_ADMIN" } }, summary);
  assert.equal(summary.statusCode, 202); assert.equal(summary.body.data.telemetryAvailable, false);
  // The controller must not even load the runtime database client for capture/summary.
  assert.equal(require.cache[path.resolve(__dirname, "../dist/config/database.js")], undefined);
  console.log("Route-transition controlled non-persistence proof passed");
})().catch(error => { console.error(error); process.exitCode = 1; });
