import { catalogueAfterPrinting } from "./production-printing-release-boundary.mjs";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { B03_DELTA_OBJECTS, classifyB03Catalogue } from "./production-b03-catalogue-diagnostic.mjs";
import { NAMED_SQL_FUNCTION_CONTRACTS } from "../rls/lib/named-sql-function-contracts.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const productionRole = (sql) => sql.replaceAll("mscqr_rls_cert_", "mscqr_prd_rls_phase2_");
const functionName = (identity) => /^app_rls\.([a-z0-9_]+)\(/.exec(identity)?.[1];
const sqlFile = (relativePath, repositoryRoot) => fs.readFileSync(path.join(repositoryRoot, relativePath), "utf8");

// C02 session grants belong to its separately governed installation, never B03.
export function selectB03GrantDelta(changedGrants) {
  const sessionContract = NAMED_SQL_FUNCTION_CONTRACTS.find(({ name }) => name === "printing_connector_session");
  const sessionGrants = new Set(sessionContract.security.ownerPrivileges
    .filter(([table]) => table === "PrinterAgentSession")
    .map(([table, privilege, columns]) => `GRANT ${privilege} (${columns.map((column) => `"${column}"`).join(", ")}) ON TABLE public."${table}" TO "mscqr_prd_rls_phase2_auth_owner";`));
  return changedGrants.filter((grant) => !sessionGrants.has(grant));
}

function functionStatement(source, name) {
  const marker = `CREATE OR REPLACE FUNCTION app_rls.${name}(`;
  const start = source.indexOf(marker), end = source.indexOf("\n$fn$;", start);
  assert.ok(start >= 0 && end > start && source.indexOf(marker, start + marker.length) < 0, `Ambiguous B03 routine ${name}`);
  return productionRole(source.slice(start, end + 6));
}

function policyStatement(source, table, name) {
  const lines = source.split("\n");
  const matches = lines.flatMap((line, index) => line.startsWith(`CREATE POLICY "${name}" ON public."${table}" `) ? [index] : []);
  assert.equal(matches.length, 1, `Ambiguous B03 policy ${table}.${name}`);
  const index = matches[0];
  assert.ok(lines[index + 1]?.startsWith(`COMMENT ON POLICY "${name}" ON public."${table}" IS `));
  return [productionRole(lines[index]), productionRole(lines[index + 1])];
}

// The old/new requirements are authenticated by the governed artifact reader;
// this package contains DDL only for identities explicitly allowed above.
export function buildB03DeltaPackage({ predecessor, successor, repositoryRoot = root } = {}) {
  assert.equal(predecessor?.sourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
  assert.match(successor?.sourceSha || "", /^[a-f0-9]{40}$/);
  const oldRows = catalogueAfterPrinting({ predecessor, successor, b03Objects: B03_DELTA_OBJECTS }), newRows = successor.objects;
  const synthetic = { schemaVersion: 1, kind: "PRODUCTION_RLS_CATALOGUE_PROBE", sourceSha: successor.sourceSha,
    candidateSourceSha: successor.sourceSha, requirementsSha256: successor.requirementsSha256,
    probeImageDigest: `sha256:${"0".repeat(64)}`, applicationImageDigest: `sha256:${"0".repeat(64)}`,
    databaseRole: "mscqr_prod_rls_canary_read", catalogue: oldRows };
  synthetic.evidenceSha256 = canonicalSha256(synthetic);
  const diagnostic = classifyB03Catalogue({ probe: synthetic,
    probeIdentity: { sourceSha: successor.sourceSha, probeImageDigest: synthetic.probeImageDigest,
      applicationImageDigest: synthetic.applicationImageDigest }, predecessor, successor });
  assert.equal(diagnostic.differences.length, 18);
  assert.ok(diagnostic.differences.every(({ liveState }) => liveState === "PREDECESSOR"));
  for (const collection of ["routines", "tables", "policies"]) {
    assert.deepEqual(diagnostic.differences.filter((row) => row.collection === collection).map((row) => row.identity).sort(),
      [...B03_DELTA_OBJECTS[collection]].sort());
  }
  const functions = sqlFile("scripts/rls/sql/generated/20-context-helpers.sql", repositoryRoot);
  const policies = sqlFile("scripts/rls/sql/generated/30-policies.sql", repositoryRoot);
  const grants = sqlFile("scripts/rls/sql/generated/21-runtime-grants.sql", repositoryRoot);
  const mutations = [];
  for (const identity of B03_DELTA_OBJECTS.routines) {
    const name = functionName(identity); assert.ok(name);
    mutations.push({ owner: "auth", sql: functionStatement(functions, name) });
  }
  for (const identity of B03_DELTA_OBJECTS.routines.filter((value) => !predecessor.objects.routines.some((row) => row.identity === value))) {
    const name = functionName(identity);
    const signature = `${name}(${identity.slice(identity.indexOf("(") + 1, -1).split(", ").map((argument) => argument.replace(/^p_[a-z0-9_]+ /, "")).join(",")})`;
    mutations.push({ owner: "auth", sql: `REVOKE ALL ON FUNCTION app_rls.${signature} FROM PUBLIC` });
    const grant = functions.split("\n").filter((line) => line.startsWith(`GRANT EXECUTE ON FUNCTION app_rls.${signature} TO `));
    assert.equal(grant.length, 1, `Missing B03 EXECUTE grant ${name}`);
    mutations.push({ owner: "auth", sql: productionRole(grant[0]) });
  }
  const oldGrants = new Set(execFileSync("git", ["show", `${predecessor.sourceSha}:scripts/rls/sql/generated/21-runtime-grants.sql`],
    { cwd: repositoryRoot, encoding: "utf8" }).split("\n").map(productionRole));
  const newGrants = selectB03GrantDelta(grants.split("\n").filter((line) => line.startsWith("GRANT ")).map(productionRole).filter((line) => !oldGrants.has(line)));
  assert.equal(newGrants.length, 5, "B03 table grant delta changed");
  assert.deepEqual(newGrants.map((line) => /^GRANT (INSERT|SELECT|UPDATE) \(.+\) ON TABLE public\."([^"]+)"/.exec(line)?.[2]).sort(),
    ["Licensee", "Notification", "SupportIssueReport", "SupportIssueReport", "SupportIssueReport"].sort());
  // Licensee(name,prefix) was already granted by the predecessor's broader exact column ACL.
  for (const sql of newGrants.filter((line) => !line.includes('ON TABLE public."Licensee"'))) mutations.push({ owner: "schema", sql: productionRole(sql) });
  for (const identity of B03_DELTA_OBJECTS.policies) {
    const separator = identity.indexOf("."); const table = identity.slice(0, separator), name = identity.slice(separator + 1);
    if (predecessor.objects.policies.some((row) => row.identity === identity))
      mutations.push({ owner: "schema", sql: `DROP POLICY "${name}" ON public."${table}"` });
    for (const sql of policyStatement(policies, table, name)) mutations.push({ owner: "schema", sql });
  }
  const catalogueDigests = (objects) => Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"]
    .map((name) => [name, canonicalSha256(objects[name])]));
  const body = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_PACKAGE", predecessorSourceSha: predecessor.sourceSha,
    sourceSha: successor.sourceSha, predecessorRequirementsSha256: predecessor.requirementsSha256,
    successorRequirementsSha256: successor.requirementsSha256,
    predecessorCatalogue: catalogueDigests(oldRows), successorCatalogue: catalogueDigests(successor.objects), mutations };
  return Object.freeze({ ...body, packageSha256: canonicalSha256(body) });
}
