import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const smoke = readFileSync("scripts/smoke-release.mjs", "utf8");
const docs = readFileSync("documents/SECURITY_PRODUCTION_ONBOARDING_CONTRACT.md", "utf8");

test("synthetic onboarding smoke is secret-free and tagged", () => {
  for (const value of ["SMOKE_VERIFY_CODE", "SMOKE_LOGIN_EMAIL", "SMOKE_LOGIN_PASSWORD", "SMOKE_ADMIN_MFA_CODE", "SMOKE_ADMIN_MFA_SECRET", "SMOKE_SYNTHETIC_RUN_ID", "X-MSCQR-Synthetic-Smoke", "/auth/login", "/auth/mfa/challenge/begin", "/auth/mfa/challenge/complete", "/auth/me", "/auth/refresh", "/dashboard/stats", "/qr/stats", "/verify/"]) {
    assert.ok(smoke.includes(value), `missing smoke contract: ${value}`);
  }
  assert.doesNotMatch(docs, /password\s*[:=]\s*[^<`\n]+/i);
  assert.match(docs, /synthetic tenant\/account/i);
});
