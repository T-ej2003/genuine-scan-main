import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { assertBackendRecoveryWorkflowGraph, disposablePostgresConnection, verifyDisposablePostgresVersion } from "../aws/certify-production-backend-release-gate.mjs";
import { ciImageReference, readApprovedImages } from "../lib/container-image-identity.mjs";

const workflow = yaml.load(fs.readFileSync(new URL("../../.github/workflows/release-gate.yml", import.meta.url), "utf8"));
const copy = () => structuredClone(workflow);

test("backend recovery certification accepts the actual protected workflow", () => {
  assert.equal(assertBackendRecoveryWorkflowGraph(copy()), true);
});

for (const [name, change] of [
  ["concurrent production writers", (gate) => { gate.concurrency["cancel-in-progress"] = true; }],
  ["missing production environment", (gate) => { gate.jobs["deploy-production-ecs"].environment = "staging"; }],
  ["OIDC removed", (gate) => { delete gate.jobs["deploy-production-ecs"].permissions["id-token"]; }],
  ["wrong AWS account", (gate) => { gate.jobs["deploy-production-ecs"].env.AWS_ACCOUNT_ID_EXPECTED = "000000000000"; }],
  ["mutable PostgreSQL image", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = "postgres:18"; }],
  ["PostgreSQL 17 image", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = "postgres:17"; }],
  ["incorrect PostgreSQL 18 image", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = ciImageReference(readApprovedImages()["postgres-certification"]); }],
  ["different PostgreSQL digest", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = `docker.io/library/postgres@sha256:${"a".repeat(64)}`; }],
  ["malformed PostgreSQL digest", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = "docker.io/library/postgres@sha256:abc"; }],
  ["different PostgreSQL registry", (gate) => { gate.jobs["deploy-production-ecs"].services.postgres.image = gate.jobs["deploy-production-ecs"].services.postgres.image.replace("docker.io", "foreign.example"); }],
  ["different Redis digest", (gate) => { gate.jobs["deploy-production-ecs"].services.redis.image = `docker.io/library/redis@sha256:${"b".repeat(64)}`; }],
  ["mutable Redis tag", (gate) => { gate.jobs["deploy-production-ecs"].services.redis.image = "redis:7"; }],
  ["missing Redis digest", (gate) => { gate.jobs["deploy-production-ecs"].services.redis.image = "docker.io/library/redis"; }],
  ["different Redis repository", (gate) => { gate.jobs["deploy-production-ecs"].services.redis.image = gate.jobs["deploy-production-ecs"].services.redis.image.replace("library/redis", "foreign/redis"); }],
  ["malformed Redis digest", (gate) => { gate.jobs["deploy-production-ecs"].services.redis.image = "docker.io/library/redis@sha256:abc"; }],
  ["RLS certification skipped", (gate) => { gate.jobs["deploy-production-ecs"].steps = gate.jobs["deploy-production-ecs"].steps.filter((step) => step.name !== "Full RLS verification and PostgreSQL 18.4 certification"); }],
  ["RLS certification made conditional", (gate) => { gate.jobs["deploy-production-ecs"].steps.find((step) => step.name === "Full RLS verification and PostgreSQL 18.4 certification").if = "${{ false }}"; }],
  ["component commit before smoke", (gate) => { const steps = gate.jobs["deploy-production-ecs"].steps;
    const commit = steps.findIndex((step) => step.name === "Commit authenticated backend recovery component state");
    const smoke = steps.findIndex((step) => step.name === "Verify backend health");
    [steps[commit], steps[smoke]] = [steps[smoke], steps[commit]]; }],
  ["green lane disabled", (gate) => { gate.jobs["deploy-production-ecs"].steps.find((step) => step.name === "Execute governed green backend health recovery with verified Terraform source").if = "${{ false }}"; }],
]) test(`backend recovery certification rejects ${name}`, () => {
  const gate = copy(); change(gate);
  assert.throws(() => assertBackendRecoveryWorkflowGraph(gate));
});

for (const host of ["localhost", "127.0.0.1", "[::1]"]) test(`disposable database accepts exact ${host} endpoint`, () => {
  const url = `postgresql://cert_admin@${host}:5432/mscqr_full_rls_admin`;
  const canonicalUrl = url.replace("@localhost:", "@127.0.0.1:");
  const connection = disposablePostgresConnection(url, {
    PGHOST: "remote.example", PGHOSTADDR: "10.0.0.2", PGPORT: "9999", PGSERVICE: "prod",
    PGSERVICEFILE: "/tmp/prod.conf", PGOPTIONS: "-c search_path=unsafe", PGPASSFILE: "/tmp/pass",
    DATABASE_URL: "postgresql://remote.example/prod", OTHER_DATABASE_URL: "postgresql://remote.example/prod",
    MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL: "postgresql://remote.example/prod",
    MSCQR_FULL_RLS_CERTIFICATION_ADMIN_URL: "postgresql://remote.example/prod",
    PATH: "/usr/bin",
  });
  assert.equal(connection.url, canonicalUrl);
  assert.deepEqual(connection.env, { PATH: "/usr/bin" });
  verifyDisposablePostgresVersion(connection, (command, args, options) => {
    assert.equal(command, "psql");
    assert.deepEqual(args, [canonicalUrl, "-X", "-Atqc", "SHOW server_version"]);
    assert.deepEqual(options.env, { PATH: "/usr/bin" });
    return "18.4 (Debian 18.4-1)\n";
  });
});

for (const url of [
  "postgresql://cert_admin@remote.example:5432/cert_db",
  "postgresql://cert_admin@localhost:5432/cert_db?hostaddr=10.0.0.2",
  "postgresql://cert_admin@localhost:5432/cert_db?host=remote",
  "postgresql://cert_admin@localhost:5432/cert_db?host=localhost&host=remote",
  "postgresql://cert_admin@localhost:5432/cert_db?%68ostaddr=10.0.0.2",
  "postgresql://cert_admin@localhost:5432/cert_db?host=%2Ftmp",
  "postgresql://cert_admin@localhost:5432/cert_db?service=prod",
  "postgresql://cert_admin@localhost:5432/cert_db?servicefile=%2Ftmp%2Fprod.conf",
  "postgresql://cert_admin@localhost:5432/cert_db?sslmode=disable",
  "postgresql://cert_admin@/cert_db?host=/tmp",
  "postgresql://cert_admin@localhost/cert_db",
  "postgresql://cert_admin@localhost:0/cert_db",
  "postgresql://cert_admin@localhost:65536/cert_db",
  "postgresql://cert_admin@127.1:5432/cert_db",
  (() => { const url = new URL("postgresql://cert_admin@localhost:5432/cert_db"); url.password = "fixture-only"; return url.href; })(),
  "postgresql://cert_admin@localhost:5432/cert_db#fragment",
  "postgresql://cert_admin@localhost:5432/cert_db/extra",
  "postgresql://cert_admin@localhost:5432/cert_db%2Fother",
  "postgresql://cert_admin@localhost:5432/customer_data",
  "not a URL",
]) test(`disposable database rejects routing ambiguity: ${url.split("?")[0]}`, () => {
  assert.throws(() => disposablePostgresConnection(url), /Disposable PostgreSQL|Admin database name/);
});

test("disposable database rejects connection failure and PostgreSQL version drift", () => {
  const connection = disposablePostgresConnection("postgresql://cert_admin@127.0.0.1:5432/mscqr_full_rls_admin");
  assert.throws(() => verifyDisposablePostgresVersion(connection, () => { throw new Error("connection refused"); }), /connection refused/);
  assert.throws(() => verifyDisposablePostgresVersion(connection, () => "17.7"), /PostgreSQL 18.4/);
});
