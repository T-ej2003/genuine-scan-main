import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import test from "node:test";

import {
  evaluateLondonSshMinioEvidence,
  filterRealMinioContainers,
  filterRealMinioServerProcesses,
  httpCheck,
} from "../dr/check-three-region-truth-table.mjs";
import {
  aliasGeolocationARecord,
  buildRegionalRollbackPlan,
  DEFAULT_REGIONAL_DNS_POLICY,
  evaluateRoute53RegionalPolicy,
  route53BatchChangedSetIdentifiers,
  validateApprovedRegionalRollbackBatch,
} from "../lib/route53-regional-rollback-core.mjs";

async function withHttpServer(handler, callback) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address();
    return await callback(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("rollback Europe plan deletes only europe-london and preserves Africa/default", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-europe",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(route53BatchChangedSetIdentifiers(plan.cutoverBatch), ["europe-london"]);
  assert.equal(plan.cutoverBatch.Changes[0].Action, "DELETE");
  assert.equal(plan.cutoverBatch.Changes[0].ResourceRecordSet.GeoLocation.ContinentCode, "EU");
  assert.doesNotMatch(JSON.stringify(plan.cutoverBatch), /africa-capetown|default-mumbai/);
});

test("rollback Africa plan deletes only africa-capetown and preserves Europe/default", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-africa",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(route53BatchChangedSetIdentifiers(plan.cutoverBatch), ["africa-capetown"]);
  assert.equal(plan.cutoverBatch.Changes[0].Action, "DELETE");
  assert.equal(plan.cutoverBatch.Changes[0].ResourceRecordSet.GeoLocation.ContinentCode, "AF");
  assert.doesNotMatch(JSON.stringify(plan.cutoverBatch), /europe-london|default-mumbai/);
});

test("restore default Mumbai touches only default-mumbai", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "restore-default-mumbai",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(route53BatchChangedSetIdentifiers(plan.cutoverBatch), ["default-mumbai"]);
  assert.equal(plan.cutoverBatch.Changes[0].Action, "UPSERT");
  assert.equal(plan.cutoverBatch.Changes[0].ResourceRecordSet.GeoLocation.CountryCode, "*");
  assert.doesNotMatch(JSON.stringify(plan.cutoverBatch), /africa-capetown|europe-london/);
});

test("approved apply validation fails without manual approval env var", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-europe",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  const findings = validateApprovedRegionalRollbackBatch(plan.cutoverBatch, {
    env: {},
  });

  assert.match(findings.join("\n"), /APPROVED_ROUTE53_ROLLBACK=true/);
});

test("approved apply validation rejects deletion of protected non-A records", () => {
  const findings = validateApprovedRegionalRollbackBatch(
    {
      Changes: [
        {
          Action: "DELETE",
          ResourceRecordSet: {
            Name: "mscqr.com.",
            Type: "MX",
            TTL: 300,
            ResourceRecords: [{ Value: "10 mx1.privateemail.com" }],
          },
        },
        {
          Action: "DELETE",
          ResourceRecordSet: {
            Name: "www.mscqr.com.",
            Type: "CNAME",
            TTL: 300,
            ResourceRecords: [{ Value: "mscqr.com" }],
          },
        },
      ],
    },
    { env: { APPROVED_ROUTE53_ROLLBACK: "true" } },
  );

  assert.match(findings.join("\n"), /protected MX record/);
  assert.match(findings.join("\n"), /protected CNAME record/);
  assert.match(findings.join("\n"), /geolocation A record/);
});

test("approved apply validation accepts generated geolocation A rollback batch with approval", () => {
  const plan = buildRegionalRollbackPlan({
    operation: "rollback-europe",
    policy: DEFAULT_REGIONAL_DNS_POLICY,
  });

  assert.deepEqual(
    validateApprovedRegionalRollbackBatch(plan.cutoverBatch, {
      env: { APPROVED_ROUTE53_ROLLBACK: "true" },
    }),
    [],
  );
});

test("three-region healthz probe follows redirects and passes on final 200", async () => {
  await withHttpServer((request, response) => {
    if (request.url === "/healthz") {
      response.writeHead(302, { Location: "/healthz-final" });
      response.end("redirecting");
      return;
    }
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end("ok");
  }, async (baseUrl) => {
    const result = await httpCheck("mumbai_alb_healthz", "Mumbai", `${baseUrl}/healthz`, 1000, {
      kind: "healthz",
      explicitOverride: false,
      overrideEnvName: "MUMBAI_HEALTHZ_URL",
    });

    assert.equal(result.status, "PASS");
    assert.equal(result.evidence.hops.length, 2);
    assert.equal(result.evidence.hops[0].status, 302);
    assert.equal(result.evidence.hops[1].status, 200);
  });
});

test("three-region ready probe warns when raw ALB redirects to production ready URL", async () => {
  await withHttpServer((request, response) => {
    assert.equal(request.url, "/api/health/ready");
    response.writeHead(301, { Location: "https://www.mscqr.com/api/health/ready" });
    response.end("redirecting");
  }, async (baseUrl) => {
    const result = await httpCheck("london_ready", "London", `${baseUrl}/api/health/ready`, 1000, {
      kind: "ready",
      explicitOverride: false,
      overrideEnvName: "LONDON_READY_URL",
    });

    assert.equal(result.status, "WARN");
    assert.match(result.detail, /LONDON_READY_URL/);
    assert.equal(result.evidence.hops.length, 1);
    assert.equal(result.evidence.finalUrl, "https://www.mscqr.com/api/health/ready");
  });
});

test("Route 53 three-region policy evaluates PASS for expected records", () => {
  const policy = DEFAULT_REGIONAL_DNS_POLICY;
  const records = [
    aliasGeolocationARecord(policy.domainName, policy.records.africaCapeTown),
    aliasGeolocationARecord(policy.domainName, policy.records.europeLondon),
    aliasGeolocationARecord(policy.domainName, policy.records.defaultMumbai),
  ];

  assert.deepEqual(
    evaluateRoute53RegionalPolicy(records, policy).map((row) => row.status),
    ["PASS", "PASS", "PASS"],
  );
});

test("three-region truth-table script has no AWS mutation command", () => {
  const source = readFileSync(new URL("../dr/check-three-region-truth-table.mjs", import.meta.url), "utf8");

  assert.doesNotMatch(source, /change-resource-record-sets/);
  assert.doesNotMatch(source, /\baws["']?\s*,?\s*["']?(s3|s3api|rds|ec2|route53)["']?\s*,?\s*["']?(delete|rm|put|change|terminate|failover)/i);
});

test("London SSH evidence passes with no MinIO and default-credentials readiness", () => {
  const result = evaluateLondonSshMinioEvidence(`
__MINIO_CONTAINERS__

__MINIO_PROCESSES__

__BACKEND_STORAGE__
OBJECT_STORAGE_ENDPOINT_SET=false
OBJECT_STORAGE_FORCE_PATH_STYLE=false
BACKEND_READY_STATUS_CODE=200
BACKEND_OBJECT_STORAGE_MODE=default-credentials
BACKEND_OBJECT_STORAGE_READY=true
BACKEND_OBJECT_STORAGE_BUCKET=mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an
BACKEND_OBJECT_STORAGE_REGION=eu-west-2
`);

  assert.equal(result.status, "PASS");
  assert.deepEqual(result.evidence.activeMinioContainers, []);
  assert.deepEqual(result.evidence.activeMinioProcesses, []);
  assert.equal(result.evidence.backendReadyStatusCode, 200);
  assert.equal(result.evidence.backendObjectStorageMode, "default-credentials");
  assert.equal(result.evidence.backendObjectStorageReady, true);
  assert.equal(result.evidence.backendObjectStorageBucket, "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an");
  assert.equal(result.evidence.backendObjectStorageRegion, "eu-west-2");
  assert.equal(result.evidence.backendStorageDefaultCredentials, true);
});

test("London SSH process filter ignores checker command containing minio", () => {
  assert.deepEqual(
    filterRealMinioServerProcesses([
      "bash -c set -eu minio_containers=$(docker ps --format '{{.Names}} {{.Image}}' | awk '/minio/')",
      "bash bash -lc ps -eo comm=,args= | awk 'BEGIN{IGNORECASE=1} $1 == \"minio\" && $0 ~ /minio server/'",
      "grep grep -Ei minio",
      "ssh ssh ubuntu@host set -eu; minio_processes=$(ps -eo comm,args)",
    ]),
    [],
  );
});

test("London SSH evidence fails when a real MinIO container is present", () => {
  const result = evaluateLondonSshMinioEvidence(`
__MINIO_CONTAINERS__
minio\tminio/minio:latest\tUp 1 hour
__MINIO_PROCESSES__

__BACKEND_STORAGE__
OBJECT_STORAGE_ENDPOINT_SET=false
OBJECT_STORAGE_FORCE_PATH_STYLE=false
BACKEND_READY_STATUS_CODE=200
BACKEND_OBJECT_STORAGE_MODE=default-credentials
BACKEND_OBJECT_STORAGE_READY=true
BACKEND_OBJECT_STORAGE_BUCKET=mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an
BACKEND_OBJECT_STORAGE_REGION=eu-west-2
`);

  assert.equal(result.status, "FAIL");
  assert.deepEqual(result.evidence.activeMinioContainers, ["minio\tminio/minio:latest\tUp 1 hour"]);
  assert.deepEqual(filterRealMinioContainers(["genuine-scan-backend\tmscqr/backend\tUp", "minio\tminio/minio\tUp"]), [
    "minio\tminio/minio\tUp",
  ]);
});

test("London SSH evidence fails when a real minio server process is present", () => {
  const result = evaluateLondonSshMinioEvidence(`
__MINIO_CONTAINERS__

__MINIO_PROCESSES__
minio minio server /data
__BACKEND_STORAGE__
OBJECT_STORAGE_ENDPOINT_SET=false
OBJECT_STORAGE_FORCE_PATH_STYLE=false
BACKEND_READY_STATUS_CODE=200
BACKEND_OBJECT_STORAGE_MODE=default-credentials
BACKEND_OBJECT_STORAGE_READY=true
BACKEND_OBJECT_STORAGE_BUCKET=mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an
BACKEND_OBJECT_STORAGE_REGION=eu-west-2
`);

  assert.equal(result.status, "FAIL");
  assert.deepEqual(result.evidence.activeMinioProcesses, ["minio minio server /data"]);
  assert.equal(result.evidence.backendStorageDefaultCredentials, true);
});

test("London SSH evidence fails when backend readiness evidence is empty", () => {
  const result = evaluateLondonSshMinioEvidence(`
__MINIO_CONTAINERS__

__MINIO_PROCESSES__

__BACKEND_STORAGE__

`);

  assert.equal(result.status, "FAIL");
  assert.equal(result.evidence.backendReadyStatusCode, 0);
  assert.equal(result.evidence.backendObjectStorageMode, "");
  assert.equal(result.evidence.backendObjectStorageReady, false);
  assert.equal(result.evidence.backendStorageDefaultCredentials, false);
});

test("London ready override passes when JSON proves default-credentials London object storage", async () => {
  await withHttpServer((request, response) => {
    assert.equal(request.url, "/api/health/ready");
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end(
      JSON.stringify({
        dependencies: {
          objectStorage: {
            mode: "default-credentials",
            ready: true,
            bucket: "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
            region: "eu-west-2",
          },
        },
      }),
    );
  }, async (baseUrl) => {
    const result = await httpCheck("london_ready", "London", `${baseUrl}/api/health/ready`, 1000, {
      kind: "ready",
      explicitOverride: true,
      overrideEnvName: "LONDON_READY_URL",
    });

    assert.equal(result.status, "PASS");
    assert.equal(result.evidence.backendObjectStorageMode, "default-credentials");
    assert.equal(result.evidence.backendObjectStorageReady, true);
    assert.equal(result.evidence.backendObjectStorageRegion, "eu-west-2");
  });
});
