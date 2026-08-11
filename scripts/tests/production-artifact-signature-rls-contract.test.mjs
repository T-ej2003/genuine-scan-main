import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync("backend/src/services/artifactSigningService.ts", "utf8");
const boundary = readFileSync("backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql", "utf8");
const generated = readFileSync("scripts/rls/sql/generated/20-context-helpers.sql", "utf8");

test("artifact crypto and persisted RLS identifiers are distinct and canonical", () => {
  assert.match(source, /ARTIFACT_ALGORITHM\s*=\s*"Ed25519"/);
  assert.match(source, /ARTIFACT_PERSISTED_SIGNATURE_ALGORITHM\s*=\s*"ed25519"/);
  for (const sql of [boundary, generated]) {
    assert.match(sql, /p_result->>'signatureAlgorithm' NOT IN \('ed25519','hmac-sha256'\)/);
    assert.doesNotMatch(sql, /p_result->>'signatureAlgorithm' NOT IN \([^)]*Ed25519/);
  }
});

test("unexpected artifact algorithm spellings remain rejected by the RLS allowlist", () => {
  const accepted = boundary.match(/p_result->>'signatureAlgorithm' NOT IN \(([^)]+)\)/)?.[1] || "";
  assert.match(accepted, /'ed25519'/);
  assert.match(accepted, /'hmac-sha256'/);
  assert.doesNotMatch(accepted, /'Ed25519'/);
  assert.doesNotMatch(accepted, /'ED25519'/);
});
