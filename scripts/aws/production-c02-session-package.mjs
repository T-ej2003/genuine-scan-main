import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const certPrefix = "mscqr_rls_cert_";
const productionPrefix = "mscqr_prd_rls_phase2_";
const functionName = "printing_connector_session";
const policyNames = ["select", "insert", "update"].map((suffix) => `printing_lifecycle_printeragentsession_${suffix}`);
export const C02_SESSION_POLICY_DIGESTS = Object.freeze({
  printing_lifecycle_printeragentsession_insert: "b78bbd15b05c261a07dcaa0ba070f630758d9f3122649294e4fb6569b985ff7a",
  printing_lifecycle_printeragentsession_select: "e799b9179ad2d9faff7a59acd1b8b5cfe4d5b26074353cf5b7d03e6fa0e5144b",
  printing_lifecycle_printeragentsession_update: "9e2603c7b218ff4017557882cb3a369461c4cdf9c69ce50027b6f3778d6047b1",
});
const certificationPolicyDigests = Object.freeze({
  printing_lifecycle_printeragentsession_insert: "8d7feff3b85e5e515198ec2952f9da1892eb9d57c46b052bde3454f6d6e062c7",
  printing_lifecycle_printeragentsession_select: "caa723efbfec408c342c6df3b4677818fc19a742c34e19d425cfd923d8c801ec",
  printing_lifecycle_printeragentsession_update: "6acf53434b36cd11fd09f25c3d768e3a7bf612905175f46097b4065c06fc8be8",
});
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const read = (repositoryRoot, name) => fs.readFileSync(path.join(repositoryRoot, name), "utf8").replaceAll("\r\n", "\n").replaceAll(productionPrefix, certPrefix);
const selectedRole = (sql, rolePrefix) => sql.replaceAll(certPrefix, rolePrefix);

const functionSql = (source, rolePrefix) => {
  const marker = `CREATE OR REPLACE FUNCTION app_rls.${functionName}(`;
  const start = source.indexOf(marker);
  const end = source.indexOf("\n$fn$;", start);
  assert.ok(start >= 0 && end > start && source.indexOf(marker, start + marker.length) < 0);
  return selectedRole(source.slice(start, end + 6), rolePrefix);
};

export function buildC02SessionPrerequisitePackage({ sourceSha, repositoryRoot = root, rolePrefix = productionPrefix } = {}) {
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/);
  assert.ok([productionPrefix, certPrefix].includes(rolePrefix));
  const canonical = read(repositoryRoot, "backend/src/rls-waves/session-c/c02/printingLifecycle.sql");
  const generated = read(repositoryRoot, "scripts/rls/sql/generated/20-context-helpers.sql");
  const definition = functionSql(canonical, rolePrefix).replaceAll("{{APP_ROLE}}", `'${rolePrefix}app'`);
  assert.equal(definition, functionSql(generated, rolePrefix), "Generated C02 session function differs from canonical source");
  const grantSource = read(repositoryRoot, "scripts/rls/sql/generated/21-runtime-grants.sql");
  const tableGrants = grantSource.split("\n").filter((line) =>
    /^GRANT (?:SELECT|INSERT|UPDATE) \(.+\) ON TABLE public\."PrinterAgentSession" TO "mscqr_rls_cert_auth_owner";$/.test(line))
    .map((sql) => selectedRole(sql, rolePrefix));
  assert.equal(tableGrants.length, 3, "C02 requires exactly three column-scoped session grants");
  assert.deepEqual(tableGrants.map((line) => /^GRANT (SELECT|INSERT|UPDATE)/.exec(line)?.[1]), ["SELECT", "INSERT", "UPDATE"]);
  const policies = read(repositoryRoot, "scripts/rls/sql/generated/30-policies.sql").split("\n");
  const policySql = policyNames.flatMap((name) => {
    const matches = policies.flatMap((line, index) => line.startsWith(`CREATE POLICY "${name}" ON public."PrinterAgentSession" `) ? [index] : []);
    assert.equal(matches.length, 1, `C02 policy ${name} is absent or ambiguous`);
    const index = matches[0];
    assert.ok(policies[index + 1]?.startsWith(`COMMENT ON POLICY "${name}" ON public."PrinterAgentSession" IS `));
    return [selectedRole(policies[index], rolePrefix), selectedRole(policies[index + 1], rolePrefix)];
  });
  const executeGrant = `GRANT EXECUTE ON FUNCTION app_rls.${functionName}(text,text,text,jsonb) TO "${rolePrefix}app"`;
  assert.ok(generated.includes(`GRANT EXECUTE ON FUNCTION app_rls.${functionName}(text,text,text,jsonb) TO "${certPrefix}app";`));
  const migration = read(repositoryRoot, "backend/prisma/migrations/20261028210000_printer_agent_session_sequence/migration.sql");
  assert.match(migration, /ADD COLUMN "lastMessageSeq" INTEGER NOT NULL DEFAULT 0/);
  const body = { schemaVersion: 1, kind: "PRODUCTION_C02_SESSION_PREREQUISITE", sourceSha,
    migrationSha256: sha256(migration), functionBodySha256: sha256(definition.slice(definition.indexOf("AS $fn$") + 7, definition.lastIndexOf("$fn$;"))),
    rolePrefix, definition, tableGrants, policySql, executeGrant, policyNames,
    policyDigests: rolePrefix === productionPrefix ? C02_SESSION_POLICY_DIGESTS : certificationPolicyDigests };
  return Object.freeze({ ...body, packageSha256: canonicalSha256(body) });
}
