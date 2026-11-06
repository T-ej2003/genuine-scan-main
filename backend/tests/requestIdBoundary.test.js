const assert = require("node:assert/strict");
const { createBackendApp } = require("../dist/app");

const valid = "aaaa5fab-7f42-474f-8014-e735a1fa8803";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

(async () => {
  const server = await new Promise((resolve) => {
    const listener = createBackendApp().listen(0, "127.0.0.1", () => resolve(listener));
  });
  try {
    const url = `http://127.0.0.1:${server.address().port}/api/dashboard/stats`;
    for (const supplied of [valid, "not-a-uuid", "x".repeat(129), " "]) {
      const response = await fetch(url, { headers: { "x-request-id": supplied } });
      const observed = response.headers.get("x-request-id");
      assert.equal(response.status, 401, "the protected dashboard route still requires authentication");
      assert.match(observed, uuid);
      if (supplied === valid) assert.equal(observed, valid);
      else assert.notEqual(observed, supplied);
    }
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
  console.log("request ID boundary tests passed");
})().catch((error) => { console.error(error); process.exit(1); });
