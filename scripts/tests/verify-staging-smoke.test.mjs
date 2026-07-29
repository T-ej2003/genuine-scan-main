import assert from "node:assert/strict";
import test from "node:test";
import { stagingSmokeMode, verifyStagingIdentity } from "../verify-staging-smoke.mjs";
const live = { STAGING_SMOKE_ENABLED: "true", STAGING_SMOKE_BASE_URL: "https://staging.example.invalid", STAGING_SMOKE_API_BASE_URL: "https://staging.example.invalid/api", STAGING_SMOKE_LOGIN_EMAIL: "smoke@example.invalid", STAGING_SMOKE_LOGIN_PASSWORD: "not-logged" };
test("disabled staging smoke makes no live target required", () => assert.equal(stagingSmokeMode({ STAGING_SMOKE_ENABLED: "false" }), "staging_not_provisioned"));
test("disabled rejects production URLs", () => assert.throws(() => stagingSmokeMode({ STAGING_SMOKE_ENABLED: "false", STAGING_SMOKE_BASE_URL: "https://www.mscqr.com" }), /prohibited/));
test("enabled requires staging URLs and credentials", () => assert.throws(() => stagingSmokeMode({ STAGING_SMOKE_ENABLED: "true" }), /requires/));
test("enabled accepts complete dedicated staging configuration", () => assert.equal(stagingSmokeMode(live), "live_staging"));
test("staging identity permits authenticated smoke to proceed", async () => assert.equal(await verifyStagingIdentity(live, async () => ({ ok: true, json: async () => ({ release: { environment: "staging" } }) })), true));
for (const environment of ["production", "development", "test", undefined]) test(`identity ${environment || "missing"} rejects before login`, async () => {
  let requests = 0;
  await assert.rejects(() => verifyStagingIdentity(live, async () => { requests += 1; return { ok: true, json: async () => ({ release: { environment } }) }; }), /release\.environment=staging/);
  assert.equal(requests, 1);
});
