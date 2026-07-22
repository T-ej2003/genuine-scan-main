# C03 trusted actor context prerequisite

## Status

Resolved locally by the database-verifiable authenticated-session capability in
commit `4add7de` and the capability-bearing C03 boundaries in
`backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql`.

The original threat analysis below is retained because it explains why the
legacy GUC installer remains unavailable to the runtime role. The production
path now presents the server-held `aq_db_session` capability to
`app_auth.require_authenticated_session`; PostgreSQL derives the live user and
scope before any C03 protected-table access. Caller-set `app.*` values are not
authority.

## Implemented contract

- HTTP callers use `withC03ActorTransaction`, `withC03ResourceTransaction`, or
  `withC03PlatformTransaction`; each requires the raw server-side capability.
- The six public C03 repository operations reverify that capability in their
  exact SQL boundary. `c03_revalidate_compliance_pack_job_actor_scope` is the
  capability-derived resource revalidation boundary.
- Internal C03 helpers are owned by the dedicated NOLOGIN auth function owner,
  receive no runtime EXECUTE grant, and install only transaction-local values
  derived from the verified session.
- Exact owner column privileges, operation policies, PUBLIC revocations,
  runtime EXECUTE grants, rollback definitions, catalog assertions and
  checksums are generated from `named-sql-function-contracts.mjs`.
- `c03AuthenticatedBoundariesPostgres18.test.js` and the C03 clean-room family
  certify forged-GUC denial, direct-table denial, lifecycle concurrency,
  rollback and function-owner invariants on PostgreSQL 18.

The scheduled job path remains deliberately fail closed until the separately
reviewed `identity-scheduled-job` durable claim boundary is implemented. It
does not reuse or impersonate an end-user capability.

## Historical prerequisite analysis

Before commit `4add7de`, no generated package, migration, historical production
definition, PostgreSQL JWT verifier, signed-context verifier, or durable
authenticated-session authority was available. The recovery report classified
the six functions as `no definition found`; it classified the only reusable
authenticated actor function, `app_rls.revalidate_authenticated_actor`, as
fixture-only.

## Evidence matrix

| Function | Production caller | Current signature | Return shape expected by the repository | Candidate resource scope | Why implementation is blocked |
| --- | --- | --- | --- | --- | --- |
| `app_rls.c03_start_compliance_pack_job` | `c03CompliancePackRepository.ts:startCompliancePackJobInTransaction` | `(trigger_type text, from_at timestamptz, to_at timestamptz)` | JSON object with `job` and `report` | caller-selected licensee from the C03 actor boundary | The function receives no authenticated proof; `trigger_type` and period only locate work. |
| `app_rls.c03_complete_compliance_pack_job` | `c03CompliancePackRepository.ts:completeCompliancePackJobInTransaction` | `(job_id text, result jsonb)` | JSON job object | `CompliancePackJob.id` | The job ID locates a row but cannot establish actor or tenant authority. |
| `app_rls.c03_fail_compliance_pack_job` | `c03CompliancePackRepository.ts:failCompliancePackJobInTransaction` | `(job_id text, error_code text)` | JSON job object | `CompliancePackJob.id` | The error code and job ID cannot establish actor or tenant authority. |
| `app_rls.c03_get_compliance_pack_job` | `c03CompliancePackRepository.ts:loadCompliancePackJobInTransaction` | `(job_id text)` | JSON object with `job` and `report` | `CompliancePackJob.id` | A read selector is not an authenticated capability. |
| `app_rls.c03_complete_compliance_pack_rebuild` | `c03CompliancePackRepository.ts:completeCompliancePackRebuildInTransaction` | `(job_id text, result jsonb)` | JSON job object | `CompliancePackJob.id` | The artifact metadata must be checked against the job, but it does not authenticate the caller. |
| `app_rls.c03_get_incident_evidence_file_by_storage_key` | `c03IncidentRepository.ts:loadIncidentEvidenceFileInTransaction` | `(storage_key text)` | JSON evidence metadata object | `IncidentEvidence.storageKey` through `Incident.licenseeId` | A storage key is intentionally only a lookup candidate and must never be authority. |
| `app_rls.c03_revalidate_compliance_pack_job_actor_scope` | `c03ActorBoundary.ts:withC03ResourceTransaction` | `(compliance_pack_job_id text, allowed_roles_json jsonb, minimum_assurance text, purpose_code text)` | one actor row or no row | `CompliancePackJob.licenseeId` | It reads `current_setting('app.*')`; it validates claimed values against rows but cannot prove who installed them. |

The actual state machine evidence is still usable once a trusted actor proof is
available: `CompliancePackJob.status` has only `RUNNING`, `COMPLETED`, and
`FAILED`; the service starts a row in one transaction, writes the artifact
outside that transaction, then completes or fails it in a separate transaction.
The download path reads a completed job and may rebuild missing artifact bytes.
The current scheduler deliberately rejects `SCHEDULED` execution before the
database call, so no scheduled-worker behavior may be inferred or implemented
from it.

## Demonstrated contradiction

The clean-room package creates `app_rls.install_actor_context(...)` as a
`SECURITY INVOKER` function. It accepts user ID, role, organization, licensee,
manufacturer, assurance, request ID, and purpose as scalar caller inputs, then
writes them directly with transaction-local `set_config`. The package then
grants `EXECUTE ON ALL FUNCTIONS IN SCHEMA app_rls` to the authenticated
application role, with no exception for `install_actor_context`.

`withCanonicalDbContext` has the same property in application code: after
TypeScript shape validation it writes each caller-provided context field with
`set_config`. `c03_revalidate_actor_scope` and every C03 resource helper read
those values using `current_setting('app.*')`. Re-reading `User`, `Licensee`,
and `Organization` protects against stale rows, but not against the application
role setting the fields to a different active user and matching scope before
calling a C03 function.

The HTTP middleware does verify an HS256 access JWT, but it does so only in
Node (`verifyAccessToken`). The verified JWT is not passed to PostgreSQL; its
secret is loaded only from application environment configuration. PostgreSQL
has no checked-in verifier or independently provisioned verification key.

Therefore a C03 `SECURITY DEFINER` owner policy that combines `current_user`
with the existing GUCs would still authorize a forged application-role
transaction. A function owner, FORCE RLS, narrower grants, or another
row-derived predicate cannot repair that missing proof: each sees the same
caller-controlled values.

## Rejected unsafe alternatives

1. **Use the current `app.*` values with more row checks.** This only proves
   that the forged identity currently exists; it does not bind the caller to
   it.
2. **Authorize only by `current_user` or a C03 function-owner role.** All
   authenticated requests share the runtime database identity. This would turn
   the role into a tenant-wide bypass.
3. **Accept user, organization, licensee, job, or storage identifiers as new
   function arguments.** These are selectors, not authority, and would violate
   the reviewed C03 integration seam.
4. **Treat `RefreshToken.id` / JWT `sessionId` as a database bearer proof.**
   Current C03 callers do not pass a signed token or an opaque, database-verified
   capability. The only proposed revalidation function is fixture-only, so
   promoting the identifier alone would create a new unaudited bearer primitive.
5. **Copy fixture SQL or install a PostgreSQL JWT extension.** Fixtures are not
   production schema authority; no extension, key lifecycle, or deployment
   contract exists in the repository.

## Decision that resolved the prerequisite

The selected proof is the durable opaque database session capability delivered
in the encrypted HttpOnly `aq_db_session` cookie. Its implementation supplies:

1. how a verified access session is represented to PostgreSQL without trusting
   caller-set GUCs;
2. key/capability provisioning, rotation, revocation, and rollback ownership;
3. exact runtime function arguments and replay/expiry semantics;
4. an owner-only transaction-local binding installed before every protected
   access; and
5. PostgreSQL 18 probes proving arbitrary app GUCs and forged identifiers do
   not authorize rows.

PostgreSQL JWT verification was rejected. Only the SHA-256 hash of the opaque
capability is durable; the raw value remains in the trusted application/cookie
boundary and is never written to reports, audit payloads or database rows.

## Consequence

C03 SQL, owner grants, FORCE-RLS policies and exact contracts are now generated
from the reviewed source described above. The legacy generic installer remains
present only as a denied catalog object for older unmigrated families; C03 code
does not call it and the application role cannot execute it.
