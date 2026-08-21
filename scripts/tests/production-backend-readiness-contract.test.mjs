import assert from "node:assert/strict";
import test from "node:test";
import { CANONICAL_PRODUCTION_ORIGIN, CANONICAL_PRODUCTION_READINESS_URL, assertProductionBackendReadiness, assertProductionBackendReadinessUrl, parseProductionBackendReadiness } from "../aws/production-backend-readiness-contract.mjs";

const healthy = () => ({
  success: true,
  status: "ready",
  timestamp: "2026-08-21T00:00:00.000Z",
  release: { gitSha: "565f78be803558feb40a543ead464c5410738960" },
  dependencies: {
    database: { configured: true, ready: true },
    redis: { configured: true, ready: true },
    objectStorage: { configured: true, ready: true },
  },
});

test("canonical production readiness requires semantic health, not HTTP reachability", () => {
  assert.equal(assertProductionBackendReadiness(healthy()).healthy, true);
  assert.equal(assertProductionBackendReadiness(healthy(), { expectedReleaseSha: healthy().release.gitSha }).healthy, true);
  for (const payload of [
    { ...healthy(), success: false },
    { ...healthy(), status: "degraded" },
    { ...healthy(), dependencies: { ...healthy().dependencies, database: { configured: true, ready: false } } },
    { ...healthy(), dependencies: { ...healthy().dependencies, redis: { configured: true, ready: false } } },
    { ...healthy(), dependencies: { ...healthy().dependencies, objectStorage: { configured: false, ready: false } } },
    "not-json",
  ]) assert.throws(() => assertProductionBackendReadiness(payload), /readiness|dependencies/);
  assert.throws(() => assertProductionBackendReadiness(healthy(), { expectedReleaseSha: "a".repeat(40) }), /release identity/);
  assert.throws(() => parseProductionBackendReadiness(Buffer.from("not-json")), /JSON/);
  assert.throws(() => parseProductionBackendReadiness(Buffer.from([0xff])), /encoded data/);
});

test("recovery accepts only the canonical public HTTPS readiness path", () => {
  assert.equal(CANONICAL_PRODUCTION_ORIGIN, "https://www.mscqr.com");
  assert.equal(assertProductionBackendReadinessUrl(CANONICAL_PRODUCTION_READINESS_URL), CANONICAL_PRODUCTION_READINESS_URL);
  for (const url of [
    "https://example.invalid/api/health/ready",
    "https://mscqr.com/api/health/ready",
    "http://www.mscqr.com/api/health/ready",
    "https://www.mscqr.com:443/api/health/ready",
    "https://www.mscqr.com:444/api/health/ready",
    "https://user@www.mscqr.com/api/health/ready",
    "https://www.mscqr.com/api/health/ready?ok=1",
    "https://www.mscqr.com/api/health/ready#ok",
    "https://www.mscqr.com/health/ready",
    "https://www.mscqr.com.example.invalid/api/health/ready",
    "https://www.mscqr.com@evil.invalid/api/health/ready",
    "https://127.0.0.1/api/health/ready",
    "malformed",
  ]) {
    assert.throws(() => assertProductionBackendReadinessUrl(url), /readiness URL|canonical/);
  }
});
