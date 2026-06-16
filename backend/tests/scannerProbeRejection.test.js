const assert = require("assert");

const { createBackendApp } = require("../dist/app");

const startServer = (app) =>
  new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${address.port}` });
    });
  });

const stopServer = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });

(async () => {
  const { server, baseUrl } = await startServer(createBackendApp());
  try {
    for (const path of ["/api/.env", "/api/.git/config", "/api/actuator/env", "/api/secrets.json"]) {
      const response = await fetch(`${baseUrl}${path}`);
      assert.strictEqual(response.status, 404, `${path} should be cheaply rejected`);
      const payload = await response.json();
      assert.strictEqual(payload.success, false);
    }
  } finally {
    await stopServer(server);
  }

  console.log("scannerProbeRejection.test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
