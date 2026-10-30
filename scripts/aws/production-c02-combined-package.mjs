import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { B03_DELTA_OBJECTS } from "./production-b03-catalogue-diagnostic.mjs";
import { catalogueAfterPrinting, PRINTING_RELEASE_NAMES } from "./production-printing-release-boundary.mjs";
import { buildC02SessionPrerequisitePackage } from "./production-c02-session-package.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const digests = objects => Object.fromEntries(Object.entries(objects).map(([key, rows]) => [key, canonicalSha256(rows)]));

export function buildC02CombinedPackage({ sourceSha, predecessor, successor, repositoryRoot = root }) {
  assert.equal(predecessor.sourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
  assert.equal(successor.sourceSha, sourceSha);
  const after = catalogueAfterPrinting({ predecessor, successor, b03Objects: B03_DELTA_OBJECTS });
  const read = relative => fs.readFileSync(path.join(repositoryRoot, relative), "utf8");
  const canonical = read("backend/src/rls-waves/session-c/c02/printingLifecycle.sql");
  const generated = read("scripts/rls/sql/generated/20-context-helpers.sql");
  const extract = (source, name) => {
    const marker = `CREATE OR REPLACE FUNCTION app_rls.${name}(`;
    const start = source.indexOf(marker), end = source.indexOf("\n$fn$;", start);
    assert.ok(start >= 0 && end > start && source.indexOf(marker, start + marker.length) < 0);
    return source.slice(start, end + 6).replaceAll("mscqr_rls_cert_", "mscqr_prd_rls_phase2_")
      .replaceAll("{{APP_ROLE}}", "'mscqr_prd_rls_phase2_app'").replaceAll("{{WORKER_ROLE}}", "'mscqr_prd_rls_phase2_worker'");
  };
  const definitions = PRINTING_RELEASE_NAMES.filter(name => name !== "printing_connector_session").map(name => {
    const sql = extract(canonical, name);
    assert.equal(sql, extract(generated, name));
    return { name, sql };
  });
  const policies = read("scripts/rls/sql/generated/30-policies.sql").split("\n");
  const policySql = ["Printer.printing_lifecycle_printer_update", "PrinterRegistration.printing_lifecycle_printerregistration_update"]
    .flatMap(identity => {
      const [table, name] = identity.split(".");
      const matches = policies.flatMap((sql, i) => sql.startsWith(`CREATE POLICY "${name}" ON public."${table}" `) ? [i] : []);
      assert.equal(matches.length, 1);
      const index = matches[0];
      assert.ok(policies[index + 1].startsWith(`COMMENT ON POLICY "${name}" ON public."${table}" IS `));
      assert.ok(predecessor.objects.policies.some(row => row.identity === identity));
      return [`DROP POLICY "${name}" ON public."${table}"`, policies[index], policies[index + 1]]
        .map(sql => sql.replaceAll("mscqr_rls_cert_", "mscqr_prd_rls_phase2_"));
    });
  const migrationSql = read("backend/prisma/migrations/20261028210000_printer_agent_session_sequence/migration.sql").trim();
  assert.equal(migrationSql, 'ALTER TABLE "PrinterAgentSession"\n  ADD COLUMN "lastMessageSeq" INTEGER NOT NULL DEFAULT 0;');
  const body = { schemaVersion: 2, kind: "PRODUCTION_C02_COMBINED_PREREQUISITE", sourceSha,
    sessionPackage: buildC02SessionPrerequisitePackage({ sourceSha, repositoryRoot }),
    predecessorRequirementsSha256: predecessor.requirementsSha256, successorRequirementsSha256: successor.requirementsSha256,
    predecessorCatalogue: digests(predecessor.objects), successorCatalogue: digests(after), finalCatalogue: digests(successor.objects),
    migrationSql, definitions, policySql };
  return { ...body, packageSha256: canonicalSha256(body) };
}
