# RDS subscription projection recovery review

This change addresses the confirmed Amazon RDS PostgreSQL 18 grant-option failure for `pg_subscription.subconninfo`. The failed transaction left both `mscqr_prod_subscription_observer` and `app_rls.production_security_subscription_inventory()` absent. It does not authorize production execution.

The approved DBA must use `mscqr_prod_admin` on `mscqr_production_rls_green_phase2` through the existing governed private DBA route. Before any write, run the exact read-only [preflight](production-rds-subscription-projection-preflight.sql) and require `RDS_SUBSCRIPTION_PREFLIGHT_PASS`. The preflight checks the full function body's catalogue reads, the existing canary identity, absence of the observer and function, RDS catalogue ownership, and absence of direct canary access. It never selects or logs `subconninfo`. An unexpected state stops the operation.

Approve the exact SHA-256 of [remediation SQL](production-rds-subscription-projection-remediation.sql), `9354a386d933f8f19e83a1ecc983de835d39862f4145fba080bbb7e1d6dc9865`, independently of verifier approval. On the authorized DBA connection, from the protected checkout with the approved file hash, execute:

```sh
shasum -a 256 documents/ops/iam/production-rds-subscription-projection-preflight.sql documents/ops/iam/production-rds-subscription-projection-remediation.sql
psql -X -v ON_ERROR_STOP=1 -f documents/ops/iam/production-rds-subscription-projection-preflight.sql
psql -X -v ON_ERROR_STOP=1 -f documents/ops/iam/production-rds-subscription-projection-remediation.sql
```

The connection is supplied only by the approved private DBA route; do not put a password or URL in a command or log. The remediation is one transaction. It creates only the exact zero-argument `SECURITY DEFINER` function with the existing body hash `ba305e220456f461a9099f8fc1c05e01ca3d96240d4c41536739a0af59830447`, revokes default `PUBLIC EXECUTE`, and grants `EXECUTE` only to the existing canary. It makes no role, catalogue grant, RLS, policy, table, or subscription change. All preconditions and metadata/ACL postconditions must pass before commit. Failure rolls back the transaction.

After commit, independently read back the function owner, body hash, return type, `search_path`, volatility, exact EXECUTE ACL, and direct canary catalogue denial. Execute the projection as the restricted canary and retain only names, non-secret configuration and connection-info digests. Persist the approved execution receipt and readback before rerunning the corrected source-bound verifier. The verifier module is copied into the backend image, so this source change requires a new authenticated image and requirements artifact; previous images cannot certify the new owner contract. Rerun the existing verifier workflow only after the database readback passes. Release Gate remains blocked until the verifier returns PASS.

If the transaction fails, verify that the function remains absent; do not retry against an unexplained partial state. After a successful commit, rollback requires separate DBA approval: in one transaction, first authenticate the exact owner and body hash and inspect dependencies, then revoke the canary's `EXECUTE`, drop only this function, and verify the predecessor absence. Do not revoke `mscqr_prod_admin` catalogue privileges or run the broad Phase 4 rollback.

CTO recommendation: keep this SQL and its signed production readback in the existing release evidence store beyond ECS/CloudWatch retention, so a later verifier retry can prove the database predecessor without repeating DBA changes.
