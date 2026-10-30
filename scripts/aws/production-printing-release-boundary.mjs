import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { NAMED_SQL_FUNCTION_CONTRACTS } from "../rls/lib/named-sql-function-contracts.mjs";

export const PRINTING_RELEASE_NAMES = Object.freeze(["printing_connector_event", "printing_connector_identity",
  "printing_connector_session", "printing_create_job", "printing_readiness", "printing_reissue_request", "printing_test_label_job"]);
export const PRINTING_RELEASE_OBJECTS = Object.freeze({
  routines: PRINTING_RELEASE_NAMES.map(name => {
    const contract = NAMED_SQL_FUNCTION_CONTRACTS.find(c => c.name === name);
    assert.equal(contract.definitionStatus, "production-reviewed");
    return `app_rls.${name}(${contract.identityArguments})`;
  }),
  tables: ["PrinterAgentSession"],
  policies: ["Printer.printing_lifecycle_printer_update", "PrinterRegistration.printing_lifecycle_printerregistration_update",
    ...["select", "insert", "update"].map(command => `PrinterAgentSession.printing_lifecycle_printeragentsession_${command}`)],
  schemas: [], roles: [],
});
const collections = ["routines", "tables", "policies", "schemas", "roles"];

// Artifact provenance is authenticated by the caller. Keep both original
// artifacts immutable while deriving the exact C02-before-B03 boundary.
export function catalogueAfterPrinting({ predecessor, successor, b03Objects }) {
  for (const requirements of [predecessor, successor]) {
    const { requirementsSha256, ...body } = requirements;
    assert.equal(requirementsSha256, canonicalSha256(body));
    assert.equal(requirements.sourceSha, requirements.candidateSourceSha);
    assert.deepEqual(Object.keys(requirements.objects).sort(), [...collections].sort());
  }
  const result = {};
  for (const collection of collections) {
    const index = requirements => {
      const rows = requirements.objects[collection];
      assert.ok(Array.isArray(rows) && rows.length <= 2000);
      const indexed = new Map();
      for (const row of rows) {
        assert.match(row.identity, /^.{1,4096}$/s);
        assert.match(row.sha256, /^[a-f0-9]{64}$/);
        assert.ok(!indexed.has(row.identity), "Duplicate catalogue identity");
        indexed.set(row.identity, row);
      }
      return indexed;
    };
    const old = index(predecessor), current = index(successor);
    const b03 = new Set(b03Objects[collection] || []), printing = new Set(PRINTING_RELEASE_OBJECTS[collection]);
    result[collection] = [];
    for (const identity of new Set([...old.keys(), ...current.keys()])) {
      const before = old.get(identity), after = current.get(identity);
      if (printing.has(identity)) assert.ok(after, `Printing successor object is missing: ${identity}`);
      if (before?.sha256 !== after?.sha256) {
        assert.ok(b03.has(identity) || printing.has(identity), `Unreviewed release delta: ${collection}.${identity}`);
      }
      const chosen = b03.has(identity) ? before : after;
      if (chosen) result[collection].push(chosen);
    }
    result[collection].sort((a, b) => a.identity.localeCompare(b.identity));
  }
  return result;
}
