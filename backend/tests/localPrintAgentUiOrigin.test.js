const assert = require("node:assert/strict");
const { isAuthorizedConnectorUiOrigin } = require("../dist/local-print-agent/uiOrigin");

assert.equal(isAuthorizedConnectorUiOrigin("https://www.mscqr.com"), true);
assert.equal(isAuthorizedConnectorUiOrigin("http://localhost:8080"), true);
assert.equal(isAuthorizedConnectorUiOrigin(undefined), true);
assert.equal(isAuthorizedConnectorUiOrigin("https://evil.example"), false);
assert.equal(isAuthorizedConnectorUiOrigin("https://www.mscqr.com.evil.example"), false);
assert.equal(isAuthorizedConnectorUiOrigin("null"), false);
assert.equal(isAuthorizedConnectorUiOrigin("https://staging.mscqr.example", "https://staging.mscqr.example"), true);
console.log("local print agent UI origin tests passed");
