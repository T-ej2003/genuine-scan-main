import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { calculateCleanRoomSourceContract } from "../rls/lib/clean-room-source-contract.mjs";
import { appOnlyRequirementIdentity, compactAppOnlyRequirements, compareCompactAppOnlyRequirements } from "./production-app-only-requirements-runtime.mjs";
export { appOnlyRequirementIdentity, compactAppOnlyRequirements, compareCompactAppOnlyRequirements } from "./production-app-only-requirements-runtime.mjs";

// Called only after canonical production-package certification in an isolated
// disposable PostgreSQL database. A live catalogue must NEVER become its own
// expected state. Workflow provenance is authenticated separately by consumers.
export function createAppOnlyRequirements({ repositoryRoot, sourceSha, candidateSourceSha, catalogue, packageChecksums }) {
  for (const sha of [sourceSha, candidateSourceSha]) assert.match(sha || "", /^[a-f0-9]{40}$/);
  const contract = calculateCleanRoomSourceContract(repositoryRoot);
  const body = { schemaVersion: 1, kind: "APP_ONLY_CANONICAL_DATABASE_REQUIREMENTS", sourceSha, candidateSourceSha,
    sourceContractSha256: contract.sourceContractSha256, migrationSetDigest: contract.migrationSetDigest,
    canonicalPackageChecksumsSha256: canonicalSha256(packageChecksums),
    // Row hashes keep fixed task-definition inputs compact while retaining exact
    // function bodies, schema ownership, ACLs, constraints and policy semantics.
    objects: Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"].map((name) => {
      assert.ok(Array.isArray(catalogue[name]) && catalogue[name].length > 0, `Missing canonical ${name}`);
      const rows = catalogue[name].map((row) => ({ identity: appOnlyRequirementIdentity(name, row), sha256: canonicalSha256(row) }));
      assert.equal(new Set(rows.map((row) => row.identity)).size, rows.length, "Duplicate canonical requirement");
      return [name, rows.sort((a, b) => a.identity.localeCompare(b.identity))];
    })) };
  return { ...body, requirementsSha256: canonicalSha256(body) };
}

export function assertAppOnlyRequirements(requirements, { sourceSha, candidateSourceSha, repositoryRoot }) {
  const { requirementsSha256, ...body } = requirements;
  assert.equal(requirementsSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "APP_ONLY_CANONICAL_DATABASE_REQUIREMENTS");
  assert.equal(body.sourceSha, sourceSha); assert.equal(body.candidateSourceSha, candidateSourceSha);
  const contract = calculateCleanRoomSourceContract(repositoryRoot);
  assert.equal(body.sourceContractSha256, contract.sourceContractSha256);
  assert.equal(body.migrationSetDigest, contract.migrationSetDigest);
  assert.match(body.canonicalPackageChecksumsSha256 || "", /^[a-f0-9]{64}$/);
  assert.deepEqual(Object.keys(body.objects || {}).sort(), ["policies", "roles", "routines", "schemas", "tables"]);
  for (const rows of Object.values(body.objects)) {
    assert.ok(Array.isArray(rows) && rows.length > 0 && rows.length <= 2000);
    assert.equal(new Set(rows.map((row) => row.identity)).size, rows.length);
    for (const row of rows) {
      assert.deepEqual(Object.keys(row).sort(), ["identity", "sha256"]);
      assert.ok(typeof row.identity === "string" && row.identity.length > 0 && row.identity.length <= 4096);
      assert.match(row.sha256 || "", /^[a-f0-9]{64}$/);
    }
  }
  return requirements;
}

export function compareAppOnlyRequirements(catalogue, requirements) {
  return compareCompactAppOnlyRequirements(catalogue, compactAppOnlyRequirements(requirements));
}
