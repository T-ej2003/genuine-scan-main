# Canonical production receipt reads

Stage-B and Full-RLS receipt readers use one shared bounded, fully paginated S3 read contract. AccessDenied alone never establishes absence. If a GET is denied, authenticated complete listing of the exact key prefix can establish absence; a listed exact key preserves the denial. Listing errors, incomplete/replayed pagination and unexpected keys fail closed. Required receipt reads still reject authenticated absence.

The workspace policy grants receipt-prefix ListBucket on the state bucket and receipt-prefix GetObject/ListBucket on the Full-RLS artifacts bucket. It adds no write/delete authority. The permission manifest tests both namespaces and rejects unrelated listing. The canonical policy installer must converge this approved policy before production recovery; changing source does not change live IAM.

This correction does not repeat registration, alter a receipt or execute production recovery. Existing immutable transaction provenance and independently approved mutation contracts remain authoritative.

## Validation and review

The final local correction passes the focused receipt/security tests, the Stage-B control-plane suite (1,412 passes, two existing skips), permission preflight (154), additional affected regressions (173), artifact contracts (23), OSV security tests (81), generated RLS verification (24), and capability/dependency closure. Workflow YAML validation covers 95 workflows. Disposable PostgreSQL 18 certification passes for the durable-outbox and Startex QR application paths, with rollback verified and no managed-role/database residue. No production database was accessed. Tests explicitly reject the reported `internal/` namespace, another valid release SHA, unrelated modes, missing/stale role tags, session-tag-enabled trust, and self-tag mutation. Full-RLS rejects a changed source or stale binding before invoking a task. AccessDenied and incomplete listing remain fail-closed.

Historical FinalApplyWrite hash/document assertions and the frontend workflow-text assertion reproduce on exact protected main. They remain unchanged. The receipt-policy simulation is updated only for its added mode resources and authenticated tag context. Local validation does not prove live IAM convergence or authorize production recovery. The current acceptance is retained byte-for-byte pending authorization of the final prospective reviewed-input hash; the raw finding remains visible and expiry remains 2026-11-02.

## Exact release authority

Forty IAM `?` wildcards do not validate hexadecimal SHA identity. Full-RLS read resources and listing prefixes now substitute only `aws:PrincipalTag/MSCQRReceiptReleaseSha`. An independent administrative convergence binds that tag on the existing release-deployer role to the exact current protected-main release. `node scripts/aws/production-receipt-read.mjs` prepares the target from the existing clean/fresh protected-main checker, with no source overrides or AWS writes. The output is a target for existing governance, never authorization by itself. A new ordinary release requires exact tag convergence, not source edits.

The release role is explicitly denied TagRole/UntagRole on itself. Its existing canonical MFA/OIDC trust grants no TagSession, so governed callers cannot override this administrative tag with session tags; no new identity, STS flow, profile, key or MFA mechanism is introduced. Before S3 reads, the shared reader authenticates the exact role, canonical trust and exact tag value. Full-RLS checks clean current-main identity and this authority before the first task invocation. Missing/stale tags, noncanonical trust, duplicates or source substitution fail closed. Administrative/root intervention remains out of band, not part of the routine automation guarantee.

The six hosted failures were duplicate push/PR executions of three jobs with one shared stale generated RLS source-contract root cause. Canonical generation refreshes the derived package after receipt-controller security inputs change. No SQL business capability, acceptance scope or production database is changed by local generation.

## Receipt trust source-binding closure

The receipt boundary binds these repository inputs into the canonical clean-room source contract:

| Input | Receipt security responsibility |
| --- | --- |
| `scripts/aws/production-receipt-read.mjs` | Exact role/tag checks, location validation, complete pagination and authenticated absence. |
| `scripts/aws/production-green-stage-b-contract.mjs` | Exact account, artifact bucket and canonical receipt modes. |
| `scripts/aws/stage-b-terraform-backend-contract.mjs` | State receipt namespace, binding-tag identity and exact-release IAM read/list policy. |
| `scripts/aws/stage-b-deployment-identity.mjs` | Fresh protected-main identity, ancestry, canonical repository and clean checkout. |
| `scripts/aws/production-release-oidc-contract.mjs` | Exact role identity and canonical trust excluding caller-controlled TagSession. |
| `scripts/aws/iam-policy-document.mjs` | Trust-document parsing before exact canonical comparison. |

The last three were previously unbound. Disposable-fixture proof reproduced unchanged source hashes after materially weakening their decisions. Regression coverage now modifies each dependency, verifies a changed source hash and runs the actual package verifier to reject stale generated evidence. A fixture trust change that permits TagSession is explicitly covered. Canonical generation alone updates derived SQL/checksums; no production resource or database is touched.

The backend contract also imports artifact-file helpers for unrelated backup/private-file operations. Those functions do not participate in the receipt namespace, identity or absence decisions and are not added merely because they are imported. The OIDC module's YAML/workflow helpers likewise do not participate in its exact trust classifier. No additional unbound repository dependency was found on the receipt trust call paths.
