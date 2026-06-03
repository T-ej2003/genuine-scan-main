import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { evaluateAutoFailover } from "../lib/auto-failover-core.mjs";

const repoRoot = path.resolve(import.meta.dirname, "../..");

function sample(rows, generatedAt = "2026-06-03T00:00:00.000Z") {
  return { generatedAt, rows };
}

function passRows() {
  return [
    { check: "route53_africa-capetown", scope: "Africa AF -> Cape Town ALB", status: "PASS", detail: "ok" },
    { check: "route53_europe-london", scope: "Europe EU -> London ALB", status: "PASS", detail: "ok" },
    { check: "route53_default-mumbai", scope: "Default/global * -> Mumbai ALB", status: "PASS", detail: "ok" },
    { check: "mumbai_alb_healthz", scope: "Mumbai", status: "PASS", detail: "200" },
    { check: "mumbai_ready", scope: "Mumbai", status: "PASS", detail: "200" },
    { check: "capetown_alb_healthz", scope: "Cape Town", status: "PASS", detail: "200" },
    { check: "capetown_ready", scope: "Cape Town", status: "PASS", detail: "200" },
    { check: "london_alb_healthz", scope: "London", status: "PASS", detail: "200" },
    { check: "london_ready", scope: "London", status: "PASS", detail: "200" },
    { check: "london_no_active_minio_ssh", scope: "London", status: "PASS", detail: "no MinIO" },
  ];
}

function withRowStatus(rows, check, status, detail = status) {
  return rows.map((row) => (row.check === check ? { ...row, status, detail } : row));
}

test("all regions healthy returns NOOP", () => {
  const decision = evaluateAutoFailover([sample(passRows()), sample(passRows())]);

  assert.equal(decision.decisionStatus, "NOOP");
  assert.equal(decision.selectedOperation, "");
  assert.deepEqual(decision.failedChecks, []);
});

test("London health fails for one sample returns NOOP transient", () => {
  const decision = evaluateAutoFailover([
    sample(passRows(), "2026-06-03T00:00:00.000Z"),
    sample(withRowStatus(passRows(), "london_alb_healthz", "FAIL", "fetch failed"), "2026-06-03T00:01:00.000Z"),
  ]);

  assert.equal(decision.decisionStatus, "NOOP");
  assert.equal(decision.selectedOperation, "");
  assert.match(decision.reason, /transient failures observed: europe:1\/2/);
});

test("London health fails for threshold samples recommends rollback-europe", () => {
  const failedRows = withRowStatus(passRows(), "london_alb_healthz", "FAIL", "fetch failed");
  const decision = evaluateAutoFailover([
    sample(failedRows, "2026-06-03T00:00:00.000Z"),
    sample(failedRows, "2026-06-03T00:01:00.000Z"),
  ]);

  assert.equal(decision.decisionStatus, "RECOMMEND_FAILOVER");
  assert.equal(decision.selectedOperation, "rollback-europe");
  assert.equal(decision.failedChecks[0].check, "london_alb_healthz");
});

test("Cape Town health fails for threshold samples recommends rollback-africa", () => {
  const failedRows = withRowStatus(passRows(), "capetown_ready", "FAIL", "500");
  const decision = evaluateAutoFailover([
    sample(failedRows, "2026-06-03T00:00:00.000Z"),
    sample(failedRows, "2026-06-03T00:01:00.000Z"),
  ]);

  assert.equal(decision.decisionStatus, "RECOMMEND_FAILOVER");
  assert.equal(decision.selectedOperation, "rollback-africa");
});

test("Mumbai default health fails for threshold samples blocks manual review", () => {
  const failedRows = withRowStatus(passRows(), "mumbai_ready", "FAIL", "500");
  const decision = evaluateAutoFailover([
    sample(failedRows, "2026-06-03T00:00:00.000Z"),
    sample(failedRows, "2026-06-03T00:01:00.000Z"),
  ]);

  assert.equal(decision.decisionStatus, "BLOCKED_MANUAL_REVIEW");
  assert.equal(decision.selectedOperation, "");
  assert.match(decision.reason, /Default\/global Mumbai/);
});

test("WARN-only London ready redirect does not trigger failover unless strict", () => {
  const warnRows = withRowStatus(passRows(), "london_ready", "WARN", "raw ALB ready redirected");
  const lenient = evaluateAutoFailover([
    sample(warnRows, "2026-06-03T00:00:00.000Z"),
    sample(warnRows, "2026-06-03T00:01:00.000Z"),
  ]);
  const strict = evaluateAutoFailover(
    [sample(warnRows, "2026-06-03T00:00:00.000Z"), sample(warnRows, "2026-06-03T00:01:00.000Z")],
    { strictWarn: true },
  );

  assert.equal(lenient.decisionStatus, "NOOP");
  assert.equal(strict.decisionStatus, "RECOMMEND_FAILOVER");
  assert.equal(strict.selectedOperation, "rollback-europe");
});

test("CLI writes hashed recommendation artifact and does not mutate AWS", () => {
  const tmp = mkdtempSync(path.join(tmpdir(), "mscqr-auto-failover-"));
  const evidenceDir = path.join(tmp, "sample", "three-region-truth-table");
  execFileSync("/bin/mkdir", ["-p", evidenceDir]);
  const failedRows = withRowStatus(passRows(), "london_alb_healthz", "FAIL", "fetch failed");
  const first = path.join(evidenceDir, "truth-table-summary.json.gz");
  writeFileSync(first, gzipSync(`${JSON.stringify(sample(failedRows), null, 2)}\n`));
  const secondDir = path.join(tmp, "sample-2", "three-region-truth-table");
  execFileSync("/bin/mkdir", ["-p", secondDir]);
  const second = path.join(secondDir, "truth-table-summary.json.gz");
  writeFileSync(second, gzipSync(`${JSON.stringify(sample(failedRows, "2026-06-03T00:01:00.000Z"), null, 2)}\n`));

  const stdout = execFileSync(
    "node",
    ["scripts/dr/auto-failover-dry-run.mjs", "--evidence-dir", tmp, "--threshold", "2"],
    { cwd: repoRoot, encoding: "utf8", env: { ...process.env, TARGET_SHA: "test-sha" } },
  );

  assert.match(stdout, /Decision status: RECOMMEND_FAILOVER/);
  const decisionPath = stdout.match(/Decision JSON: (.+)/)?.[1].trim();
  assert(decisionPath);
  const decision = JSON.parse(readFileSync(decisionPath, "utf8"));
  assert.equal(decision.targetSha, "test-sha");
  assert.equal(decision.selectedOperation, "rollback-europe");
  assert.equal(decision.decisionStatus, "RECOMMEND_FAILOVER");
  assert.match(decision.recommendedPlanJsonSha256, /^[a-f0-9]{64}$/);
  assert.equal(existsSync(decision.recommendedPlanJsonPath), true);

  const source = readFileSync(path.join(repoRoot, "scripts/dr/auto-failover-dry-run.mjs"), "utf8");
  assert.doesNotMatch(source, /change-resource-record-sets/);
  assert.doesNotMatch(source, /\baws\b/);
});
