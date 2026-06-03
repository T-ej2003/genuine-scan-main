import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const repoRoot = path.resolve(import.meta.dirname, "../..");
const readRepoFile = (filePath) => readFileSync(path.join(repoRoot, filePath), "utf8");

test("production compose path excludes MinIO and minio-init", () => {
  const compose = readRepoFile("docker-compose.yml");

  assert.doesNotMatch(compose, /^\s{2}minio:/m);
  assert.doesNotMatch(compose, /^\s{2}minio-init:/m);
  assert.doesNotMatch(compose, /minio\/(?:minio|mc)/i);
  assert.doesNotMatch(compose, /\bminio_data\b/i);
  assert.doesNotMatch(compose, /depends_on:[\s\S]{0,240}\bminio(?:-init)?\b/i);
});

test("local MinIO remains available only through explicit local-minio profile", () => {
  const localCompose = readRepoFile("docker-compose.local.yml");

  assert.match(localCompose, /^\s{2}minio:\n\s+image:\s+minio\/minio:/m);
  assert.match(localCompose, /^\s{2}minio-init:\n\s+image:\s+minio\/mc:/m);
  assert.match(localCompose, /profiles:\n\s+- local-minio/);
  assert.match(localCompose, /^\s{2}minio_data:/m);
});

test("production deploy commands target only production services", () => {
  for (const filePath of ["ops/deploy/deploy.yml", "ops/deploy/deploy-standby.yml"]) {
    const playbook = readRepoFile(filePath);

    assert.match(playbook, /docker compose --profile worker build backend worker frontend/);
    assert.match(playbook, /docker compose --profile worker up -d --no-build redis backend worker frontend/);
    assert.doesNotMatch(playbook, /docker compose --profile worker up -d --no-build\s*(?:\n|$)/);
    assert.match(playbook, /Assert MinIO containers are not running in production/);
    assert.match(playbook, /failed_when:\s+production_minio_runtime\.stdout \| length > 0/);
  }
});

test("London no-active-MinIO evidence guard remains present", () => {
  const truthTable = readRepoFile("scripts/dr/check-three-region-truth-table.mjs");
  const rollbackTests = readRepoFile("scripts/tests/route53-regional-rollback.test.mjs");

  assert.match(truthTable, /activeMinioContainers/);
  assert.match(truthTable, /activeMinioProcesses/);
  assert.match(truthTable, /backendStorageDefaultCredentials/);
  assert.match(rollbackTests, /London SSH evidence passes with no MinIO and default-credentials readiness/);
});
