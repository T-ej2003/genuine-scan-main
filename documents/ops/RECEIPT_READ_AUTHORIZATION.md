# Canonical production receipt reads

Stage-B and Full-RLS receipt readers use one shared bounded, fully paginated S3 read contract. AccessDenied alone never establishes absence. If a GET is denied, authenticated complete listing of the exact key prefix can establish absence; a listed exact key preserves the denial. Listing errors, incomplete/replayed pagination and unexpected keys fail closed. Required receipt reads still reject authenticated absence.

The workspace policy grants receipt-prefix ListBucket on the state bucket and receipt-prefix GetObject/ListBucket on the Full-RLS artifacts bucket. It adds no write/delete authority. The permission manifest tests both namespaces and rejects unrelated listing. The canonical policy installer must converge this approved policy before production recovery; changing source does not change live IAM.

This correction does not repeat registration, alter a receipt or execute production recovery. Existing immutable transaction provenance and independently approved mutation contracts remain authoritative.

## Local validation

The Stage-B control-plane suite passes 1,412 tests with two existing skips. The focused receipt/backend/Full-RLS tests pass 45 tests; receipt plus OSV security tests pass 126 tests; permission/artifact/workflow checks pass 179 tests. Capability and dependency-closure generation converge with zero missing or unmapped capabilities. The focused security review found no unresolved receipt-scope, pagination or denial-to-absence defect.

Two additional IAM reconciliation assertions (the FinalApplyWrite historical hash and frontend workflow text) reproduce unchanged on exact protected main `aabb6af4343ebd007cb8c9c889a7f8851e0ac256`. Those assertions are retained. Source validation does not prove live IAM convergence or authorize production recovery. The security owner authorized the exact reviewed-input transition to `6f6ee4996a203907914fb24ddd900384f4167b742ad14209d2561f7bcff424dd`. The canonical runtime gate passes with the finding visible and scope/security conclusion unchanged; expiry remains 2026-11-02.
