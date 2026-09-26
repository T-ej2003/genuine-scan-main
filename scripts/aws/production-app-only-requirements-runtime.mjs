import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

export function appOnlyRequirementIdentity(name, row) {
  return name === "routines" ? `${row.schema}.${row.name}(${row.arguments})`
    : name === "policies" ? `${row.table}.${row.name}` : row.name;
}

export function compactAppOnlyRequirements(requirements) {
  return { requirementsSha256: requirements.requirementsSha256,
    objects: Object.fromEntries(Object.entries(requirements.objects).map(([name, rows]) => [name, {
      identities: rows.map((row) => row.identity), sha256: canonicalSha256(rows),
    }])) };
}

export function compareCompactAppOnlyRequirements(catalogue, requirements) {
  const results = {};
  for (const name of ["routines", "tables", "policies", "schemas", "roles"]) {
    const expected = requirements.objects[name], observed = catalogue[name];
    assert.ok(Array.isArray(observed));
    const rows = new Map(observed.map((row) => [appOnlyRequirementIdentity(name, row), canonicalSha256(row)]));
    assert.equal(rows.size, observed.length, "Duplicate catalogue identity");
    const selected = expected.identities.map((identity) => ({ identity, sha256: rows.get(identity) ?? null }));
    results[name] = canonicalSha256(selected) === expected.sha256 ? "COMPATIBLE" : "INCOMPATIBLE";
  }
  const tables = new Set(requirements.objects.tables.identities);
  const policies = new Set(requirements.objects.policies.identities);
  if (catalogue.policies.some((row) => tables.has(row.table) && !policies.has(appOnlyRequirementIdentity("policies", row)))) results.policies = "INCOMPATIBLE";
  return { DATABASE_SCHEMA: results.tables === "COMPATIBLE" && results.schemas === "COMPATIBLE" ? "COMPATIBLE" : "INCOMPATIBLE",
    RLS_FUNCTIONS: results.routines, RLS_POLICIES: results.policies,
    RLS_GRANTS: Object.values(results).every((value) => value === "COMPATIBLE") ? "COMPATIBLE" : "UNPROVEN",
    RLS_FORCE_STATUS: results.tables === "COMPATIBLE" ? "COMPATIBLE" : "UNPROVEN",
    GENERATED_RLS_CONTRACT: Object.values(results).every((value) => value === "COMPATIBLE") ? "COMPATIBLE" : "UNPROVEN" };
}
