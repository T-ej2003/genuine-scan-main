# Session C C03 integration seams

Coordination SHA: `22bfdb0cfd19d7b435b1390611b452a419923f9f`

This document records the global SQL and integration-owner work that C03 cannot own. The C03 application code fails closed when a required function or caller context is absent. Session A must review these contracts, install the functions in the generated GREEN package, and update the named integration call sites before merging Session C.

> **Security prerequisite resolved:** commit `4add7de` supplies the durable
> opaque authenticated-session proof. The capability-bearing C03 boundaries
> reverify it with `app_auth.require_authenticated_session`; generic caller GUCs
> are no longer C03 authority. The original threat analysis is retained in
> [`C03_TRUSTED_ACTOR_CONTEXT_PREREQUISITE.md`](./C03_TRUSTED_ACTOR_CONTEXT_PREREQUISITE.md).

## Authenticated actor and resource scope

All functions below execute only for the authenticated application identity. They re-read an active `User`, active parent `Licensee` and active `Organization`, verify the installed user ID and role rather than trusting token strings, enforce the requested assurance and allowlisted purpose, and return exactly one row or no row.

```sql
app_rls.c03_revalidate_actor_scope(
  target_licensee_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
) RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)

app_rls.c03_revalidate_incident_actor_scope(
  incident_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
) RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)

app_rls.c03_revalidate_policy_rule_actor_scope(
  policy_rule_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
) RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)

app_rls.c03_revalidate_compliance_pack_job_actor_scope(
  compliance_pack_job_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
) RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)

app_rls.c03_revalidate_incident_evidence_actor_scope(
  incident_evidence_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
) RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)

app_rls.c03_revalidate_sensitive_approval_actor_scope(
  approval_id text,
  allowed_roles_json jsonb,
  minimum_assurance text,
  purpose_code text
) RETURNS TABLE(user_id text, role text, organization_id text, licensee_id text)
```

Resource functions derive scope from the authoritative resource-parent chain. A route selector, filename, storage key, JWT role or JWT tenant claim is never resource authority. Blank, malformed, missing, foreign, disabled, stale-role, stale-membership and inactive-parent cases return no row.

## Policy administration

```sql
app_rls.c03_create_policy_rule(input jsonb) RETURNS jsonb
app_rls.c03_update_policy_rule(policy_rule_id text, patch jsonb) RETURNS jsonb
```

The create function takes licensee, organization and actor attribution only from installed canonical context. It permits only `name`, `description`, `ruleType`, `isActive`, `threshold`, `windowMinutes`, `severity`, `autoCreateIncident`, `incidentSeverity`, `incidentPriority` and `actionConfig`. The update function locks the row, rejects ownership-column changes, applies the same mutable-column allowlist, and is replay-safe under `app.request_id`. Audit and security outbox writes occur in the caller transaction through the Session C transactional audit primitive. Both functions return the existing PolicyRule JSON shape without unrelated user or tenant projections.

## Governance flags and retention

```sql
app_rls.c03_upsert_tenant_feature_flag(key text, enabled boolean, config jsonb) RETURNS jsonb
app_rls.c03_get_or_create_retention_policy() RETURNS jsonb
app_rls.c03_update_retention_policy(patch jsonb) RETURNS jsonb
app_rls.c03_run_retention_lifecycle(mode text, approval_id text) RETURNS jsonb
app_rls.c03_build_incident_evidence_audit_snapshot(incident_id text) RETURNS jsonb
app_rls.c03_generate_compliance_report(from_at timestamptz, to_at timestamptz) RETURNS jsonb
```

All scope and actor attribution come from canonical context. The feature-flag and retention functions lock the existing row, reject ownership or attribution input, use the exact mutable-column allowlist and write audit and outbox rows in the caller transaction. Retention `APPLY` requires a valid approved maker-checker request and deletes fingerprints, evidence rows and the retention job atomically. It returns storage keys only in the private `storageKeysToDelete` field; application code performs file cleanup after commit and removes that field before serialization. Missing protected tables are errors, never ephemeral success.

The evidence snapshot function joins from the authorized Incident and returns only the reviewed incident, event, evidence, fingerprint, handoff and support fields needed by the existing archive. Audit attribution commits with the snapshot read; file loading and ZIP serialization happen after commit. The compliance report function requires one active canonical licensee and returns aggregate/report data only for that scope and date window; platform-global reporting is denied.

Compliance pack state uses explicit two-phase database transitions around external artifact construction:

```sql
app_rls.c03_start_compliance_pack_job(capability text, purpose text, request_id text, licensee_id text, trigger_type text, from_at timestamptz, to_at timestamptz) RETURNS jsonb
app_rls.c03_complete_compliance_pack_job(capability text, purpose text, request_id text, job_id text, result jsonb) RETURNS jsonb
app_rls.c03_fail_compliance_pack_job(capability text, purpose text, request_id text, job_id text, error_code text) RETURNS jsonb
app_rls.c03_get_compliance_pack_job(capability text, purpose text, request_id text, job_id text) RETURNS jsonb
app_rls.c03_complete_compliance_pack_rebuild(capability text, purpose text, request_id text, job_id text, result jsonb) RETURNS jsonb
app_rls.c03_get_incident_evidence_file_by_storage_key(capability text, purpose text, request_id text, storage_key text) RETURNS jsonb
```

Start returns the locked job plus its canonical report snapshot. Artifact signing and storage occur after that commit. Complete and fail derive the job scope, lock it and compare-and-set `RUNNING` to one terminal state with audit and outbox. Rebuild reads a canonical job/report snapshot and compare-and-sets the final artifact metadata. Raw exception text is not persisted. A restricted scheduled-worker claim function is still required from the integration owner; the human application identity cannot run scheduled jobs.

## Incident-bound alert authorization

The frozen contract requires a durable, expiring incident authorization, but the current schema and route have no such product state. Session A owns the product/global artifact and the integration owner must propagate its opaque ID as `x-incident-authorization-id`.

```sql
app_rls.c03_list_ir_alerts(
  incident_authorization_id text,
  incident_id text,
  licensee_id text,
  filters jsonb,
  row_limit integer,
  row_offset integer
) RETURNS TABLE(
  id text,
  licensee_id text,
  alert_type text,
  severity text,
  message text,
  score integer,
  policy_rule_id text,
  incident_id text,
  batch_id text,
  qr_code_id text,
  manufacturer_id text,
  acknowledged_at timestamptz,
  created_at timestamptz,
  total_count bigint
)

app_rls.c03_link_ir_alert_incident(
  incident_authorization_id text,
  alert_id text,
  incident_id text,
  reason text,
  idempotency_key text
) RETURNS TABLE(id text, licensee_id text, incident_id text)
```

The list function requires step-up assurance, a matching active authorization and incident, a 31-day ceiling, and at most 100 rows. Filters only narrow. The link function locks both rows, requires the same active licensee and authorization, performs an unlinked-to-linked compare-and-set, and treats an identical idempotency key as deterministic replay. Acknowledgement, unlinking, reassignment and mixed patches are denied.

## Restricted pre-auth identities

The public report-concern route cannot install a human actor. Session A must provide a restricted pre-auth identity and a security-definer function that validates the QR proof and derives the incident licensee. The function must not accept caller role, organization, licensee or manufacturer scope.

```sql
app_rls.c03_create_public_incident_report(
  qr_proof text,
  report_payload jsonb,
  request_id text,
  idempotency_key text
) RETURNS jsonb
```

The return object must contain the existing incident response fields. The function creates the incident, initial event, evidence metadata, immutable attribution, audit and outbox atomically. File/object writes remain staged outside the transaction and are published only after commit.

Public verification policy evaluation requires a separate restricted identity and QR-derived function:

```sql
app_rls.c03_evaluate_verification_policy(
  qr_proof text,
  verification_event_id text,
  request_id text
) RETURNS jsonb
```

It derives QR, batch, manufacturer and licensee from the proof, reads only allowlisted active rules, and atomically applies deduplicated alerts/incidents/QR state. Caller tenant fields are ignored and forged scope is denied.

## Purpose-specific incident detail

The current IR detail response contains restricted contact, internal-note, location and evidence fields that are not in the ordinary Incident projection. C03 will call a reviewed function rather than add direct grants:

```sql
app_rls.c03_get_ir_incident_detail(
  incident_id text,
  incident_authorization_id text
) RETURNS jsonb
```

The function enforces a matching unexpired authorization and purpose, returns the existing response keys with only the frozen per-purpose columns, and never returns raw credential, token, device fingerprint or unrelated tenant data.

## Sensitive approval caller seam

`approvalController.ts`, `qrController.ts` and `printerController.ts` are integration-owner-only for Session C. They currently pass copied user/role/scope fields to `sensitiveActionApprovalService`; this is not sufficient authority. Each call must also pass the original authenticated claims object and immutable request ID. The exact service input addition is:

```ts
securityContext: {
  user: AuthenticatedSessionClaims;
  requestId: string;
}
```

Missing security context fails before database access. The database functions are:

```sql
app_rls.c03_create_sensitive_action_approval(input jsonb) RETURNS jsonb
app_rls.c03_list_sensitive_action_approvals(status text, row_limit integer, row_offset integer) RETURNS SETOF jsonb
app_rls.c03_approve_sensitive_action_approval(approval_id text, review_note text) RETURNS jsonb
app_rls.c03_reject_sensitive_action_approval(approval_id text, review_note text) RETURNS jsonb
```

They derive maker/checker identity and tenant scope from canonical context, lock the request, enforce expiry and distinct maker/checker, use compare-and-set lifecycle transitions, execute the allowlisted action in the same transaction, and atomically write immutable audit and outbox rows. Payload, request IP hash and user-agent hash are never returned by list.

## Evidence required from Session A

Session A must provide function owner/search-path hardening, revoke PUBLIC, exact runtime grants, `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, positive and negative PostgreSQL 18 probes, and proof that the restricted runtime roles cannot access underlying protected tables directly. Integration evidence must include missing/blank/malformed/foreign/stale/disabled/wrong-role/wrong-assurance denials and replay/concurrency results for every mutation function.
