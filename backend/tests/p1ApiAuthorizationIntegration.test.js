const assert = require("assert");
const {
  assertSafeDenied,
  request,
  tokens,
  withServer,
} = require("./helpers/p1TestApp");

const assertAllowed = ({ status, text }, routeLabel, options = {}) => {
  assert.ok(status >= 200 && status < 300, `${routeLabel} expected 2xx, got ${status}: ${text}`);
  if (!options.allowCrossTenant) {
    assert.doesNotMatch(text, /p1-licensee-b|P1 Brand B|p1-qr-b|p1-batch-b/i, `${routeLabel} leaked cross-tenant fixture data`);
  }
};

(async () => {
  await withServer(async (baseUrl) => {
    assertSafeDenied(await request(baseUrl, "GET", "/api/auth/me", null));
    assertSafeDenied(await request(baseUrl, "GET", "/api/auth/me", tokens.invalid));
    assertSafeDenied(await request(baseUrl, "GET", "/api/auth/me", tokens.licenseeAdminA, undefined, {
      "x-database-session-capability": "tampered-capability",
    }));
    assertAllowed(await request(baseUrl, "GET", "/api/auth/me", tokens.licenseeAdminA), "auth/me licensee");
    assertAllowed(await request(baseUrl, "GET", "/api/auth/me", tokens.manufacturerA), "auth/me manufacturer");
    assertAllowed(await request(baseUrl, "GET", "/api/auth/me", tokens.superAdmin), "auth/me platform");
  });

  console.log("p1 bearer capability integration test passed; database route authorization is covered by P2");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
