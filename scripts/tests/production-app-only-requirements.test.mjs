import test from "node:test";
import assert from "node:assert/strict";
import { createAppOnlyRequirements, assertAppOnlyRequirements, compareAppOnlyRequirements, compactAppOnlyRequirements, compareCompactAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { execFileSync } from "node:child_process";
import { assertAppOnlyCandidateAncestor } from "../aws/produce-production-app-only-requirements.mjs";

const context = { repositoryRoot: process.cwd(), sourceSha: "a".repeat(40), candidateSourceSha: "b".repeat(40) };
const fixture = () => ({ routines: [{ schema: "app_auth", name: "test", arguments: "value text", definition: "fixed", grants: [] }],
  tables: [{ name: "Example", rls: true, forced: true, columns: [], grants: [] }],
  policies: [{ table: "Example", name: "isolation", using: "false", check: "false" }], schemas: [{ name: "app_auth", owner: "fixed", grants: [] }],
  roles: [{ name: "mscqr_prd_rls_phase2_app", superuser: false, inherit: false, memberships: [], members: [] }] });
const requirements = (catalogue) => createAppOnlyRequirements({ ...context, catalogue, packageChecksums: { immutable: "fixture" } });
test("canonical requirements bind source, schema/migration contract and exact catalogue rows", () => {
  const catalogue = fixture(), expected = requirements(catalogue);
  assert.equal(assertAppOnlyRequirements(expected, context), expected);
  assert.ok(Object.values(compareAppOnlyRequirements(catalogue, expected)).every((v) => v === "COMPATIBLE"));
  for (const collection of Object.keys(catalogue)) {
    const bad = structuredClone(catalogue); bad[collection][0].extra = "substituted";
    assert.notEqual(compareAppOnlyRequirements(bad, expected).GENERATED_RLS_CONTRACT, "COMPATIBLE");
  }
});
test("candidate source stays distinct and only an actual protected-source ancestor is accepted", () => {
  const sourceSha = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  const candidateSourceSha = execFileSync("git", ["rev-parse", "HEAD^"], { encoding: "utf8" }).trim();
  assert.equal(assertAppOnlyCandidateAncestor({ sourceSha, candidateSourceSha }), true);
  const sourceRequirements = createAppOnlyRequirements({ ...context, sourceSha, candidateSourceSha: sourceSha, catalogue: fixture(), packageChecksums: { immutable: "fixture" } });
  const ancestorRequirements = createAppOnlyRequirements({ ...context, sourceSha, candidateSourceSha, catalogue: fixture(), packageChecksums: { immutable: "fixture" } });
  assert.equal(ancestorRequirements.sourceSha, sourceSha); assert.equal(ancestorRequirements.candidateSourceSha, candidateSourceSha);
  assert.notEqual(ancestorRequirements.requirementsSha256, sourceRequirements.requirementsSha256);
  assert.throws(() => assertAppOnlyRequirements(ancestorRequirements, { ...context, sourceSha, candidateSourceSha: sourceSha }));
  assert.throws(() => assertAppOnlyCandidateAncestor({ sourceSha, candidateSourceSha: "f".repeat(40) }));
});
test("wrong source, original contract replacement and hash substitution fail", () => {
  const original = requirements(fixture());
  for (const field of ["sourceSha", "candidateSourceSha", "sourceContractSha256", "migrationSetDigest"]) {
    const bad = structuredClone(original); bad[field] = "c".repeat(bad[field].length);
    const { requirementsSha256: omitted, ...body } = bad;
    assert.ok(omitted); bad.requirementsSha256 = canonicalSha256(body);
    assert.throws(() => assertAppOnlyRequirements(bad, context));
  }
  const bad = structuredClone(original); bad.objects.tables[0].sha256 = "d".repeat(64);
  assert.throws(() => assertAppOnlyRequirements(bad, context));
});
test("additional permissive policy is incompatible even with all expected rows present", () => {
  const observed = fixture(), expected = requirements(observed);
  observed.policies.push({ table: "Example", name: "bypass", using: "true" });
  assert.equal(compareAppOnlyRequirements(observed, expected).RLS_POLICIES, "INCOMPATIBLE");
});
test("compact task requirements retain exact identity sets and every full row hash", () => {
  const catalogue = fixture(), original = requirements(catalogue), compact = compactAppOnlyRequirements(original);
  assert.deepEqual(compareCompactAppOnlyRequirements(catalogue, compact), compareAppOnlyRequirements(catalogue, original));
  assert.equal(compact.requirementsSha256, original.requirementsSha256);
  for (const name of Object.keys(compact.objects)) {
    const changed = structuredClone(compact); changed.objects[name].identities[0] = "substituted";
    assert.notEqual(compareCompactAppOnlyRequirements(catalogue, changed).GENERATED_RLS_CONTRACT, "COMPATIBLE");
    const changedHash = structuredClone(compact); changedHash.objects[name].sha256 = "f".repeat(64);
    assert.notEqual(compareCompactAppOnlyRequirements(catalogue, changedHash).GENERATED_RLS_CONTRACT, "COMPATIBLE");
  }
});
