const assert = require("node:assert/strict");
const http = require("node:http");

process.env.NODE_ENV = "production";
process.env.CLIENT_IP_TRUST_MODE = "direct-loopback-canary";
process.env.MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY = "true";
process.env.REQUIRE_REDIS_FOR_SHARED_STATE = "false";
process.env.DATABASE_URL ||= "postgresql://mscqr_dev_rls_default@127.0.0.1:1/canary?connect_timeout=1";
process.env.PREAUTH_DATABASE_URL ||= "postgresql://mscqr_dev_rls_canary_preauth@127.0.0.1:1/canary?connect_timeout=1";
process.env.AUTHENTICATED_APP_DATABASE_URL ||= "postgresql://mscqr_dev_rls_canary_app@127.0.0.1:1/canary?connect_timeout=1";
process.env.JWT_SECRET ||= "canary-loopback-test-secret";
process.env.IP_HASH_SALT_CURRENT ||= "canary-loopback-ip-salt";

const { createBackendApp } = require("../dist/app");

const request = (server, path, options = {}) => new Promise((resolve, reject) => {
  const port = server.address().port;
  const req = http.request({ host: "127.0.0.1", port, path, method: options.method || "GET", headers: options.headers }, (res) => {
    res.resume();
    res.once("end", () => resolve(res));
  });
  req.once("error", reject);
  if (options.body) req.end(options.body);
  else req.end();
});

const server = http.createServer(createBackendApp());

(async () => {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const ready = await request(server, "/api/health/ready");
    assert.notEqual(ready.statusCode, 400, "canary readiness must pass client-IP middleware");

    const login = await request(server, "/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "canary@example.test", password: "not-a-real-password" }),
    });
    assert.notEqual(login.statusCode, 400, "canary application request must pass client-IP middleware");

    process.env.MSCQR_PRODUCTION_GREEN_APPLICATION_CANARY = "false";
    assert.throws(() => createBackendApp(), /governed application canary/);
    console.log("canary direct-loopback HTTP tests passed");
  } finally {
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
