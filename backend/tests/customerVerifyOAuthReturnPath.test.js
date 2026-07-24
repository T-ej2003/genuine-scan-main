const assert = require("node:assert/strict");

const {
  validateCustomerVerifyReturnTo,
} = require("../dist/services/customerVerifyOAuthService");

const allowed = ["https://app.mscqr.example"];

assert.equal(
  validateCustomerVerifyReturnTo("https://app.mscqr.example/verify/CODE?source=scan", allowed),
  "https://app.mscqr.example/verify/CODE?source=scan"
);
assert.equal(
  validateCustomerVerifyReturnTo("https://app.mscqr.example/scan", allowed),
  "https://app.mscqr.example/scan"
);

for (const unsafe of [
  "https://evil.example/verify/CODE",
  "https://app.mscqr.example.evil/verify/CODE",
  "https://app.mscqr.example/verification",
  "https://app.mscqr.example/scanner",
  "javascript:alert(1)",
  "https://user:secret@app.mscqr.example/verify/CODE",
]) {
  assert.throws(
    () => validateCustomerVerifyReturnTo(unsafe, allowed),
    /Invalid return URL|origin is not allowed|stay inside the verify flow/
  );
}

assert.throws(
  () => validateCustomerVerifyReturnTo("https://app.mscqr.example/verify/CODE", []),
  /origin is not allowed/
);

console.log("customer verification OAuth return-path tests passed");
