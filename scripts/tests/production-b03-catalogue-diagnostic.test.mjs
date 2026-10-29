import test from "node:test";
import assert from "node:assert/strict";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { classifyB03Catalogue } from "../aws/production-b03-catalogue-diagnostic.mjs";

const oldSha = "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec";
const newSha = "4".repeat(40);
const digest = `sha256:${"a".repeat(64)}`;
const routine = "app_rls.b03_create_support_issue_report(p_licensee_id text, p_organization_id text, p_title text, p_description text, p_source_path text, p_page_url text, p_auto_detected boolean, p_screenshot_path text, p_screenshot_mime text, p_screenshot_size integer, p_diagnostics jsonb, p_ip_hash text, p_request_id text)";
const row = (identity, sha256) => ({ identity, sha256 });
const requirements = (sourceSha, routines) => {
  const body = { schemaVersion: 1, kind: "APP_ONLY_CANONICAL_DATABASE_REQUIREMENTS", sourceSha, candidateSourceSha: sourceSha,
    objects: { routines, tables: [], policies: [], schemas: [], roles: [] } };
  return { ...body, requirementsSha256: canonicalSha256(body) };
};
const evidence = (successor, routines) => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_CATALOGUE_PROBE", sourceSha: newSha, candidateSourceSha: newSha,
    requirementsSha256: successor.requirementsSha256, probeImageDigest: digest, applicationImageDigest: digest,
    databaseRole: "mscqr_prod_rls_canary_read", catalogue: { routines, tables: [], policies: [], schemas: [], roles: [] } };
  return { ...body, evidenceSha256: canonicalSha256(body) };
};
const old = requirements(oldSha, [row("app_rls.stable()", "1".repeat(64))]);
const next = requirements(newSha, [row("app_rls.stable()", "1".repeat(64)), row(routine, "2".repeat(64))]);
const identity = { sourceSha: newSha, probeImageDigest: digest, applicationImageDigest: digest };
const classify = (probe, predecessor = old, successor = next) => classifyB03Catalogue({ probe, probeIdentity: identity, predecessor, successor });

test("bounded B03 diagnostic accepts authenticated predecessor and partial successor", () => {
  const before = classify(evidence(next, old.objects.routines));
  assert.deepEqual(before.differences.map(({ identity, liveState }) => [identity, liveState]), [[routine, "PREDECESSOR"]]);
  const after = classify(evidence(next, next.objects.routines));
  assert.equal(after.differences[0].liveState, "SUCCESSOR");
  assert.ok(!JSON.stringify(before).includes("CREATE OR REPLACE"));
});

test("bounded B03 diagnostic rejects unrelated and unknown catalogue drift", () => {
  assert.throws(() => classify(evidence(next, [row("app_rls.stable()", "9".repeat(64))])), /Unexpected routines catalogue drift/);
  assert.throws(() => classify(evidence(next, [...old.objects.routines, row("app_rls.unknown()", "3".repeat(64))])), /Unexpected routines catalogue drift/);
  const changed = requirements(newSha, [...next.objects.routines, row("app_rls.unapproved()", "3".repeat(64))]);
  assert.throws(() => classify(evidence(changed, old.objects.routines), old, changed), /Unapproved routines delta/);
});

test("bounded B03 diagnostic rejects altered evidence and source bindings", () => {
  const valid = evidence(next, old.objects.routines);
  assert.throws(() => classify({ ...valid, databaseRole: "postgres" }), /Probe evidence is invalid/);
  assert.throws(() => classify(evidence(next, old.objects.routines), old, { ...next, sourceSha: oldSha }), /Successor requirements are invalid/);
});
