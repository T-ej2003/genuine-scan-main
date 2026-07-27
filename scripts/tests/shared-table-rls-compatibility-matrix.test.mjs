import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { scanSharedTableAccesses } from "../lib/shared-table-rls-compatibility-scanner.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const matrixPath = path.join(repoRoot, "documents/security/mscqr_shared_table_rls_compatibility_matrix_2026-07-15.json");
const matrix = JSON.parse(fs.readFileSync(matrixPath, "utf8"));
const operations = matrix.operations;
const byId = new Map(operations.map((row) => [row.id, row]));
const commands = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "UPSERT", "COUNT", "RAW_SQL"]);
const scopes = new Set(["self", "same-licensee", "same-organization", "manufacturer-link", "platform-wide", "pre-auth", "unknown"]);
const surfaces = new Set(["http", "worker", "startup", "cli", "background-job", "internal"]);
const stages = new Set(["pre-auth", "password-verified", "mfa-bootstrap", "fully-authenticated", "system"]);
const contexts = new Set(["transaction-local", "none", "unknown"]);
const outcomes = new Set(["allowed", "denied", "partially-allowed", "unknown"]);
const risks = new Set(["blocking", "high", "medium", "low"]);
const remediations = new Set(["repository-wrapper", "transaction-context", "security-definer-boundary", "new-policy", "retire-operation", "system-role-design", "none"]);

test("deterministic scanner coverage is exhaustive for direct delegates and shared-table raw SQL", () => {
  const discovered = scanSharedTableAccesses(repoRoot);
  assert(discovered.length > 150, "scanner scope unexpectedly collapsed");
  for (const access of discovered) {
    const row = byId.get(access.id);
    assert(row, `matrix missing ${access.sourceFile}:${access.line} ${access.table}.${access.method}`);
    assert.equal(row.table, access.table);
    assert.equal(row.operation, access.operation);
    assert(row.evidence.some((item) => item.includes(`${access.sourceFile}:${access.line}:`)), `${row.id} lacks source evidence`);
  }
  const scannerIds = new Set(discovered.map((row) => row.id));
  const designedBoundaryIds = new Set(["shared-auth-lookup-password-user", "shared-auth-record-password-failure"]);
  for (const row of operations) assert(scannerIds.has(row.id) || designedBoundaryIds.has(row.id), `unexplained matrix row ${row.id}`);
});

test("every matrix row has a real source and valid closed vocabulary", () => {
  assert.equal(byId.size, operations.length, "matrix ids must be unique");
  for (const row of operations) {
    assert(fs.existsSync(path.join(repoRoot, row.sourceFile)), `${row.id} source file is missing`);
    assert(Number.isInteger(row.line) && row.line > 0, `${row.id} line is invalid`);
    assert(commands.has(row.operation), `${row.id} command is invalid`);
    assert(scopes.has(row.scope), `${row.id} scope is invalid`);
    assert(surfaces.has(row.executionSurface), `${row.id} execution surface is invalid`);
    assert(stages.has(row.authenticationStage), `${row.id} authentication stage is invalid`);
    assert(contexts.has(row.currentRlsContext), `${row.id} context is invalid`);
    assert(outcomes.has(row.currentPolicyOutcome), `${row.id} policy outcome is invalid`);
    assert(risks.has(row.compatibilityRisk), `${row.id} risk is invalid`);
    assert(remediations.has(row.requiredRemediation), `${row.id} remediation is invalid`);
    assert(Array.isArray(row.contextFieldsRequired) && Array.isArray(row.evidence) && row.evidence.length > 0, `${row.id} evidence is incomplete`);
  }
});

test("pre-auth, mutation, allowed, and background classifications fail closed", () => {
  for (const row of operations.filter((candidate) => candidate.authenticationStage === "pre-auth")) {
    assert(row.requiredRemediation, `${row.id} pre-auth remediation is absent`);
    if (row.currentPolicyOutcome === "allowed") {
      assert(row.operation === "RAW_SQL" || row.currentRlsContext === "transaction-local");
      assert.match(row.evidence.join(" "), /SECURITY DEFINER|actor-self User predicate/);
    } else {
      assert.equal(row.requiredRemediation, "security-definer-boundary", `${row.id} pre-auth raw-table access needs a named function boundary`);
    }
  }
  for (const row of operations.filter((candidate) => ["INSERT", "DELETE"].includes(candidate.operation))) {
    assert.equal(row.compatibilityRisk, "blocking", `${row.id} mutation cannot be authorized by this review`);
    assert.notEqual(row.currentPolicyOutcome, "allowed", `${row.id} mutation was incorrectly allowed`);
  }
  for (const row of operations.filter((candidate) => candidate.operation === "UPDATE" && candidate.scope !== "self" && candidate.serviceFunction !== "loginWithPassword")) {
    assert.equal(row.compatibilityRisk, "blocking", `${row.id} cross-user/admin update must remain blocking`);
    assert.notEqual(row.currentPolicyOutcome, "allowed", `${row.id} cross-user/admin update was incorrectly allowed`);
  }
  for (const row of operations.filter((candidate) => candidate.currentPolicyOutcome === "allowed")) {
    assert(row.currentRlsContext === "transaction-local" || /SECURITY DEFINER/.test(row.evidence.join(" ")), `${row.id} lacks policy/context proof`);
  }
  for (const row of operations.filter((candidate) => ["background-job", "worker"].includes(candidate.executionSurface))) {
    assert.equal(row.authenticationStage, "system");
    assert.equal(row.requiredRole, "not yet designed");
    assert.equal(row.requiredRemediation, "system-role-design");
  }
});

test("shared apply remains blocked and absent from automatic execution", () => {
  const applyPath = "documents/security/mscqr_staging_rls_shared_batch_phase_apply_2026-07-15.sql";
  const apply = fs.readFileSync(path.join(repoRoot, applyPath), "utf8");
  const transaction = apply.indexOf("BEGIN;");
  assert(apply.indexOf("Shared batch RLS apply blocked") > -1);
  assert(apply.indexOf("Shared batch RLS apply blocked") < transaction);
  for (const root of ["backend/prisma/migrations", ".github/workflows"]) {
    const walk = (directory) => {
      for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
        const target = path.join(directory, entry.name);
        if (entry.isDirectory()) walk(target);
        else assert(!fs.readFileSync(target, "utf8").includes(path.basename(applyPath)), `${target} must not execute shared apply`);
      }
    };
    walk(path.join(repoRoot, root));
  }
});
