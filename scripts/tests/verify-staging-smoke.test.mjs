import assert from "node:assert/strict";
import test from "node:test";
import { stagingSmokeMode } from "../verify-staging-smoke.mjs";
test("disabled staging smoke makes no live target required", () => assert.equal(stagingSmokeMode({ STAGING_SMOKE_ENABLED: "false" }), "staging_not_provisioned"));
test("disabled rejects production URLs", () => assert.throws(() => stagingSmokeMode({ STAGING_SMOKE_ENABLED: "false", STAGING_SMOKE_BASE_URL: "https://www.mscqr.com" }), /prohibited/));
test("enabled requires staging URLs and credentials", () => assert.throws(() => stagingSmokeMode({ STAGING_SMOKE_ENABLED: "true" }), /requires/));
test("enabled accepts a non-production staging origin with credentials", () => assert.equal(stagingSmokeMode({ STAGING_SMOKE_ENABLED: "true", STAGING_SMOKE_BASE_URL: "https://staging.example.invalid", STAGING_SMOKE_API_BASE_URL: "https://staging.example.invalid", STAGING_SMOKE_LOGIN_EMAIL: "smoke@example.invalid", STAGING_SMOKE_LOGIN_PASSWORD: "not-logged" }), "live_staging"));
