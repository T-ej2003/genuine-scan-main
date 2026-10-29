import assert from "node:assert/strict";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { APP_ONLY_VERIFIER } from "./production-app-only-policy.mjs";

const collections = ["routines", "tables", "policies", "schemas", "roles"];
export const B03_DELTA_OBJECTS = Object.freeze({
  routines: [
    "app_rls.b03_claim_support_response_emails(p_attempted_at timestamp without time zone, p_batch_size integer)",
    "app_rls.b03_complete_support_response_email(p_notification_id text, p_claim_token text, p_status text, p_error_code text, p_provider_message_id text)",
    "app_rls.b03_create_support_issue_report(p_licensee_id text, p_organization_id text, p_title text, p_description text, p_source_path text, p_page_url text, p_auto_detected boolean, p_screenshot_path text, p_screenshot_mime text, p_screenshot_size integer, p_diagnostics jsonb, p_ip_hash text, p_request_id text)",
    "app_rls.b03_list_support_issue_reports(p_limit integer, p_offset integer, p_licensee_id text, p_actor_licensee_id text, p_actor_organization_id text, p_request_id text)",
    "app_rls.b03_respond_support_issue_report(p_report_id text, p_message text, p_status text, p_ip_hash text, p_request_id text)",
    "app_rls.b03_support_issue_screenshot_access(p_file_name text, p_actor_licensee_id text, p_actor_organization_id text, p_request_id text)",
    "app_rls.complete_security_event_outbox(p_job_id text, p_payload_digest text, p_attempted_at timestamp without time zone, p_sink_event_id text)",
    "app_rls.refresh_inventory_status_rollups(p_request_id text)",
  ],
  tables: ["Notification", "SupportIssueReport"],
  policies: [
    "AuditLogOutbox.b03_authenticated_auditlogoutbox_insert",
    "Notification.b03_authenticated_notification_insert",
    "Notification.b03_authenticated_notification_select",
    "Notification.b03_authenticated_notification_update",
    "SupportIssueReport.b03_authenticated_supportissuereport_insert",
    "SupportIssueReport.b03_authenticated_supportissuereport_select",
    "SupportIssueReport.b03_authenticated_supportissuereport_update",
    "User.b03_authenticated_user_select",
  ],
  schemas: [], roles: [],
});

const rows = (value, collection) => {
  const list = value?.[collection];
  assert.ok(Array.isArray(list) && list.length <= 2000, `Invalid ${collection} catalogue`);
  const result = new Map();
  for (const row of list) {
    assert.match(row.identity || "", /^.{1,4096}$/s);
    assert.match(row.sha256 || "", /^[a-f0-9]{64}$/);
    assert.ok(!result.has(row.identity), `Duplicate ${collection} identity`);
    result.set(row.identity, row.sha256);
  }
  return result;
};

// The inputs must be independently authenticated GitHub requirements artifacts.
// This emits only bounded identities and row hashes; it never emits definitions.
export function classifyB03Catalogue({ probe, probeIdentity, predecessor, successor }) {
  const { requirementsSha256: oldHash, ...oldBody } = predecessor || {};
  const { requirementsSha256: newHash, ...newBody } = successor || {};
  assert.equal(oldHash, canonicalSha256(oldBody), "Predecessor requirements are invalid");
  assert.equal(newHash, canonicalSha256(newBody), "Successor requirements are invalid");
  assert.equal(predecessor.sourceSha, predecessor.candidateSourceSha);
  assert.equal(successor.sourceSha, successor.candidateSourceSha);
  assert.notEqual(predecessor.sourceSha, successor.sourceSha);
  assert.equal(probeIdentity?.sourceSha, successor.sourceSha);
  const { evidenceSha256, ...probeBody } = probe || {};
  assert.equal(evidenceSha256, canonicalSha256(probeBody), "Probe evidence is invalid");
  assert.equal(probe.schemaVersion, 1);
  assert.equal(probe.kind, "PRODUCTION_RLS_CATALOGUE_PROBE");
  assert.equal(probe.sourceSha, successor.sourceSha);
  assert.equal(probe.candidateSourceSha, successor.candidateSourceSha);
  assert.equal(probe.requirementsSha256, newHash);
  assert.equal(probe.probeImageDigest, probeIdentity.probeImageDigest);
  assert.equal(probe.applicationImageDigest, probeIdentity.applicationImageDigest);
  assert.equal(probe.databaseRole, APP_ONLY_VERIFIER.databaseRole);
  assert.deepEqual(Object.keys(predecessor.objects).sort(), [...collections].sort());
  assert.deepEqual(Object.keys(successor.objects).sort(), [...collections].sort());
  const differences = [];
  for (const collection of collections) {
    const oldRows = rows(predecessor.objects, collection);
    const newRows = rows(successor.objects, collection);
    const liveRows = rows(probe.catalogue, collection);
    const allow = new Set(B03_DELTA_OBJECTS[collection]);
    for (const identity of new Set([...oldRows.keys(), ...newRows.keys(), ...liveRows.keys()])) {
      const before = oldRows.get(identity), after = newRows.get(identity), observed = liveRows.get(identity);
      if (before === after) {
        assert.equal(observed, before, `Unexpected ${collection} catalogue drift: ${identity}`);
        continue;
      }
      assert.ok(allow.has(identity), `Unapproved ${collection} delta: ${identity}`);
      assert.ok(observed === before || observed === after, `Unknown ${collection} predecessor: ${identity}`);
      differences.push({ collection, identity, predecessorSha256: before || null, successorSha256: after || null,
        liveState: observed === before ? "PREDECESSOR" : "SUCCESSOR" });
    }
  }
  assert.ok(differences.length > 0 && differences.length <= 18, "B03 delta is absent or unbounded");
  return Object.freeze({ schemaVersion: 1, kind: "BOUNDED_B03_CATALOGUE_DIAGNOSTIC", sourceSha: successor.sourceSha,
    predecessorSourceSha: predecessor.sourceSha, probeEvidenceSha256: evidenceSha256,
    predecessorRequirementsSha256: oldHash, successorRequirementsSha256: newHash,
    differences: differences.sort((a, b) => `${a.collection}.${a.identity}`.localeCompare(`${b.collection}.${b.identity}`)) });
}
