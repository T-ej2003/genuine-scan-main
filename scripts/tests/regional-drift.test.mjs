import assert from "node:assert/strict";
import test from "node:test";

import {
  evaluateAlarmPresence,
  evaluateObjectStorage,
  evaluateRuntimeEnvironment,
  evaluateSnapshotFreshness,
  parseJsonHealthResponse,
  redactDeep,
} from "../lib/regional-drift-core.mjs";

test("parseJsonHealthResponse rejects frontend HTML fallback", () => {
  const result = parseJsonHealthResponse({
    url: "https://www.mscqr.com/api/health/ready",
    status: 200,
    contentType: "text/html; charset=utf-8",
    body: "<!doctype html><html><body>MSCQR app</body></html>",
  });

  assert.equal(result.ok, false);
  assert.equal(result.finding.status, "FAIL");
  assert.match(result.finding.remediation, /API routing\/proxy/i);
});

test("object storage IAM-mode invariants pass for region-local S3", () => {
  const findings = evaluateObjectStorage(
    {
      bucket: "mscqr-prod-euw2-artifacts-ACCOUNT_ID-eu-west-2",
      region: "eu-west-2",
      endpoint: null,
      mode: "default-credentials",
    },
    {
      configured: true,
      ready: true,
      bucket: "mscqr-prod-euw2-artifacts-ACCOUNT_ID-eu-west-2",
      region: "eu-west-2",
      endpoint: null,
      mode: "default-credentials",
    }
  );

  assert.deepEqual(
    findings.map((item) => item.status),
    ["PASS", "PASS", "PASS", "PASS", "PASS"]
  );
});

test("object storage invariants fail on MinIO static-credential drift", () => {
  const findings = evaluateObjectStorage(
    {
      bucket: "mscqr-prod-euw2-artifacts-ACCOUNT_ID-eu-west-2",
      region: "eu-west-2",
      endpoint: null,
      mode: "default-credentials",
    },
    {
      configured: true,
      ready: true,
      bucket: "mscqr-artifacts",
      region: "us-east-1",
      endpoint: "http://minio:9000",
      mode: "static-credentials",
    }
  );

  const failedChecks = findings.filter((item) => item.status === "FAIL").map((item) => item.check);
  assert.deepEqual(failedChecks, [
    "object_storage_bucket",
    "object_storage_region",
    "object_storage_endpoint",
    "object_storage_mode",
  ]);
});

test("snapshot freshness warns when latest manual snapshot is stale", () => {
  const findings = evaluateSnapshotFreshness({
    prefix: "mscqr-prod-db-",
    maxAgeHours: 24,
    now: new Date("2026-04-27T12:00:00Z"),
    snapshots: [
      {
        id: "mscqr-prod-db-post-deploy-2026-04-20",
        createdAt: "2026-04-20T12:00:00Z",
        status: "available",
      },
    ],
  });

  assert.equal(findings[0].status, "WARN");
  assert.equal(findings[0].check, "manual_snapshot");
  assert.equal(findings[0].evidence.ageHours, 168);
});

test("alarm presence evaluation reports missing alarms", () => {
  const findings = evaluateAlarmPresence(["mscqr-ec2-cpu-high", "mscqr-rds-cpu-high"], ["mscqr-ec2-cpu-high"]);

  assert.equal(findings[0].status, "FAIL");
  assert.deepEqual(findings[0].evidence.missing, ["mscqr-rds-cpu-high"]);
});

test("runtime inspection catches static keys and bootstrap drift without exposing secrets", () => {
  const findings = evaluateRuntimeEnvironment(
    {
      label: "London",
      runtime: { awsRegion: "eu-west-2" },
      environment: { superAdminBootstrapEnabled: false },
    },
    {
      inspected: true,
      env: {
        AWS_REGION: "eu-west-2",
        OBJECT_STORAGE_ENDPOINT: "http://minio:9000",
        OBJECT_STORAGE_ACCESS_KEY: "AKIAEXAMPLE",
        OBJECT_STORAGE_SECRET_KEY: "secret-value",
        OBJECT_STORAGE_FORCE_PATH_STYLE: "true",
        SUPER_ADMIN_BOOTSTRAP_ENABLED: "true",
      },
      services: [{ name: "genuine-scan-main-minio-1", state: "running" }],
    }
  );

  const failedChecks = findings.filter((item) => item.status === "FAIL").map((item) => item.check);
  assert.deepEqual(failedChecks, [
    "runtime_object_storage_endpoint",
    "runtime_object_storage_static_keys",
    "runtime_object_storage_path_style",
    "super_admin_bootstrap",
  ]);
  assert.equal(findings.find((item) => item.check === "runtime_object_storage_static_keys").evidence.OBJECT_STORAGE_SECRET_KEY, "<redacted>");
});

test("redaction removes sensitive nested values from reports", () => {
  const redacted = redactDeep({
    databaseUrl: "postgresql://user:password@example/db",
    nested: {
      jwtSecret: "secret",
      safeBucket: "mscqr-prod",
    },
  });

  assert.equal(redacted.databaseUrl, "<redacted-url>");
  assert.equal(redacted.nested.jwtSecret, "<redacted>");
  assert.equal(redacted.nested.safeBucket, "mscqr-prod");
});
