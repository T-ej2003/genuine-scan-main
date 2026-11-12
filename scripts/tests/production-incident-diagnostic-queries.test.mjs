import assert from "node:assert/strict";
import { INCIDENT_DATABASE, INCIDENT_QUERIES, INCIDENT_ROLE, INCIDENT_SCOPE, INCIDENT_SOURCE_SHA } from "../../backend/scripts/production-incident-diagnostic-queries.mjs";

assert.equal(INCIDENT_SOURCE_SHA, "7407b80b7919ca88f53e4a6d05596701fe00d0e0");
assert.equal(INCIDENT_DATABASE, "mscqr_production_rls_green_phase2");
assert.equal(INCIDENT_ROLE, "mscqr_prod_rls_canary_read");
assert.equal(Object.keys(INCIDENT_QUERIES).length, 11);
for (const [name, query] of Object.entries(INCIDENT_QUERIES)) {
  assert.match(query, /^SELECT\s/i, `${name} must be a read`);
  assert.doesNotMatch(query, /;|\b(?:INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|TRUNCATE|FOR\s+UPDATE|FOR\s+SHARE)\b/i, `${name} must contain one nonlocking statement`);
  if (name !== "identity") assert.match(query, /\bLIMIT\s+\d+\s*$/i, `${name} must bound returned rows`);
  assert.doesNotMatch(query, /tokenHash|sessionCapabilityHash|\bcode\b|description|screenshot|password|secret|metadata\s+AS/i, `${name} must not return sensitive columns`);
}
for (const name of ["printJobs", "printEvents", "batch", "qrCounts"]) assert.ok(INCIDENT_QUERIES[name].includes(INCIDENT_SCOPE.batchId));
for (const name of ["printJobs", "printEvents", "sessions", "support"]) assert.ok(INCIDENT_QUERIES[name].includes(INCIDENT_SCOPE.manufacturerId));
assert.ok(INCIDENT_QUERIES.testLabel.includes(INCIDENT_SCOPE.testPrinterId));
assert.ok(INCIDENT_QUERIES.testLabelAudit.includes(INCIDENT_SCOPE.testPrinterId));
console.log("fixed incident diagnostic query contract passed");
