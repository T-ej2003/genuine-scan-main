const assert = require("node:assert/strict");
const { isAuthorizedConnectorUiOrigin } = require("../dist/local-print-agent/uiOrigin");

assert.equal(isAuthorizedConnectorUiOrigin("https://www.mscqr.com"), true);
assert.equal(isAuthorizedConnectorUiOrigin("http://localhost:8080"), true);
assert.equal(isAuthorizedConnectorUiOrigin(undefined), true);
assert.equal(isAuthorizedConnectorUiOrigin("https://evil.example"), false);
assert.equal(isAuthorizedConnectorUiOrigin("https://www.mscqr.com.evil.example"), false);
assert.equal(isAuthorizedConnectorUiOrigin("null"), false);
assert.equal(isAuthorizedConnectorUiOrigin("https://staging.mscqr.example", "https://staging.mscqr.example"), true);
const previous = process.env.PRINT_AGENT_WEB_APP_ORIGIN;
try {
  process.env.PRINT_AGENT_WEB_APP_ORIGIN = "https://staging.mscqr.example";
  assert.equal(isAuthorizedConnectorUiOrigin("https://staging.mscqr.example"), true);
  assert.equal(isAuthorizedConnectorUiOrigin("https://dr.mscqr.example", "https://dr.mscqr.example"), true);
  for (const origin of ["https://unconfigured.example", "https://*.mscqr.example", "*", "null", "https://staging.mscqr.example/path", "https://staging.mscqr.example.evil.example"]) {
    assert.equal(isAuthorizedConnectorUiOrigin(origin), false, `${origin} must not be authorized`);
  }
  assert.equal(isAuthorizedConnectorUiOrigin("https://evil.example", "*"), false);
  assert.equal(isAuthorizedConnectorUiOrigin("https://evil.example", "https://evil.example/path"), false);
  assert.equal(isAuthorizedConnectorUiOrigin(undefined), true, "Native requests without Origin must still reach authenticated routes");
} finally {
  if (previous === undefined) delete process.env.PRINT_AGENT_WEB_APP_ORIGIN;
  else process.env.PRINT_AGENT_WEB_APP_ORIGIN = previous;
}
console.log("local print agent UI origin tests passed");
