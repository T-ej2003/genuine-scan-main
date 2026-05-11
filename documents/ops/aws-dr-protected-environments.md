# AWS DR Protected Environments and OIDC Plan

Last updated: 2026-05-11

This plan enables manual GitHub Actions apply operations for DR while preserving the MSCQR rule that destructive or public traffic-moving actions require explicit operator approval.

## Protected GitHub Environments

Create these GitHub Environments and require reviewers for each:

- `dr-dns-cutover`
- `dr-dns-rollback`
- `dr-db-restore`
- `dr-object-storage-write-test`
- `dr-standby-db-test`
- `dr-recovery-cleanup`

Recommended environment controls:

- Require at least one incident commander or infrastructure owner reviewer.
- Prevent self-review where GitHub plan support allows it.
- Limit deployment branches to `main`, `aws-dr-finish`, and approved release branches during rollout.
- Store only role ARNs as environment variables. Do not store production secrets in these environments.

## Environment Variables

Set these environment-scoped variables:

- `DR_DNS_CUTOVER_ROLE_TO_ASSUME` on `dr-dns-cutover`.
- `DR_DNS_ROLLBACK_ROLE_TO_ASSUME` on `dr-dns-rollback`.
- `DR_DB_RESTORE_ROLE_TO_ASSUME` on `dr-db-restore`.
- `DR_OBJECT_STORAGE_WRITE_TEST_ROLE_TO_ASSUME` on `dr-object-storage-write-test`.
- `DR_RECOVERY_CLEANUP_ROLE_TO_ASSUME` on `dr-recovery-cleanup`.

The workflow uses GitHub OIDC through `aws-actions/configure-aws-credentials@v4`. Long-lived AWS access keys are not required.

## Manual Apply Workflow

Use:

```text
.github/workflows/aws-dr-apply.yml
```

Supported operations:

- `apply-route53-change`
- `apply-route53-rollback`
- `apply-db-restore-approved`
- `apply-cross-region-snapshot-copy-approved`
- `apply-region-local-db-restore-approved`
- `object-storage-write-test-approved`
- `cleanup-recovery-db-approved`

Each operation requires both:

- GitHub Environment reviewer approval.
- The exact confirmation phrase for that operation.

## Approval Phrases

- DNS cutover: `I_APPROVE_MANUAL_DNS_CUTOVER`
- DNS rollback: `I_APPROVE_MANUAL_DNS_ROLLBACK`
- DB restore: `I_APPROVE_DB_RESTORE_TO_RECOVERY_TARGET`
- Cross-region snapshot copy: `I_APPROVE_CROSS_REGION_SNAPSHOT_COPY`
- Region-local DB restore: `I_APPROVE_REGION_LOCAL_DB_RESTORE`
- Object storage write test: `I_APPROVE_OBJECT_STORAGE_WRITE_TEST`
- Delete generated object storage test object: `I_APPROVE_DELETE_DR_TEST_OBJECT`
- Recovery DB cleanup: `I_APPROVE_RECOVERY_DB_CLEANUP`
- Skip final recovery DB cleanup snapshot: `I_APPROVE_SKIP_FINAL_SNAPSHOT`

## Immutable Evidence

The apply workflow writes logs under `artifacts/dr/`, generates `artifacts/dr/sha256-manifest.txt`, and uploads evidence with `actions/upload-artifact@v4`.

Artifact v4 uploads are immutable for the workflow run. Retention is set to 90 days. Incident commanders should copy the artifact URL into the incident record.

## IAM Templates

Least-privilege templates live in:

```text
ops/aws/iam/dr/
```

Templates:

- `github-oidc-trust-policy.template.json`
- `route53-dns-cutover-policy.template.json`
- `route53-dns-rollback-policy.template.json`
- `rds-restore-recovery-target-policy.template.json`
- `recovery-cleanup-policy.template.json`
- `object-storage-write-test-policy.template.json`
- `dr-explicit-deny-guardrail-policy.template.json`

Replace placeholders such as `<AWS_ACCOUNT_ID>`, `<GITHUB_ORG>`, `<GITHUB_REPO>`, `<HOSTED_ZONE_ID>`, `<NORMALIZED_RECORD_NAME>`, `<TARGET_REGION>`, and `<BUCKET_NAME>` before applying in AWS.

## Safety Notes

- The safe operations workflow still does not expose mutation operations.
- The apply workflow is manual-only.
- No health check triggers DNS movement.
- DNS cutover and rollback call the local gated scripts.
- DB restore creates only a new recovery target and does not modify the primary DB.
- Snapshot copy and region-local restore are manual-only and protected by `dr-db-restore`.
- Recovery DB cleanup is isolated behind `dr-recovery-cleanup` and must never target production identifiers.
- Object storage write testing writes only under `dr-tests/<timestamp>/`.
- Bucket deletion, DB deletion, DB failover, recursive object deletion, Docker prune, and MinIO decommission remain out of scope.
