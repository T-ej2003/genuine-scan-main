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
- `dr-alb-entrypoint-apply`
- `dr-regional-readiness`
- `dr-hardening-apply`

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
- Preferred: `AWS_DR_RECOVERY_CLEANUP_ROLE_ARN` on `dr-recovery-cleanup`.
- Backward-compatible: `DR_RECOVERY_CLEANUP_ROLE_TO_ASSUME` on `dr-recovery-cleanup`.
- Preferred: `AWS_DR_ALB_APPLY_ROLE_ARN` on `dr-alb-entrypoint-apply`.
- Backward-compatible: `DR_ALB_APPLY_ROLE_TO_ASSUME` on `dr-alb-entrypoint-apply`.
- Preferred: `AWS_DR_REGIONAL_READINESS_ROLE_ARN` on `dr-regional-readiness`.
- Backward-compatible: `DR_REGIONAL_READINESS_ROLE_TO_ASSUME` on `dr-regional-readiness`.
- Preferred: `AWS_DR_HARDENING_APPLY_ROLE_ARN` on `dr-hardening-apply`.
- Backward-compatible: `DR_HARDENING_APPLY_ROLE_TO_ASSUME` on `dr-hardening-apply`.

The workflow uses GitHub OIDC through `aws-actions/configure-aws-credentials@v4`. Long-lived AWS access keys are not required.

## Manual Apply Workflows

Use focused manual workflows instead of the old combined apply workflow:

```text
.github/workflows/aws-dr-dns-apply.yml
.github/workflows/aws-dr-snapshot-apply.yml
.github/workflows/aws-dr-db-apply.yml
.github/workflows/aws-dr-cleanup-apply.yml
.github/workflows/aws-dr-object-storage-apply.yml
.github/workflows/aws-dr-alb-apply.yml
.github/workflows/aws-dr-hardening-apply.yml
```

Read-only scaling and reliability evidence uses:

```text
.github/workflows/aws-dr-regional-readiness.yml
```

Supported operations:

- `apply-route53-change`
- `apply-route53-rollback`
- `apply-db-restore-approved`
- `apply-cross-region-snapshot-copy-approved`
- `apply-region-local-db-restore-approved`
- `object-storage-write-test-approved`
- `cleanup-recovery-db-approved`
- `aws-regional-alb-inventory`
- `generate-regional-alb-plan`
- `apply-regional-alb-entrypoint-approved`
- `generate-route53-regional-test-records`
- `generate-route53-alb-cutover-plan`
- `apply-cloudwatch-alarms`
- `apply-alb-access-logs`
- `apply-waf-count-mode`
- `generate-asg-apply-plan`
- `apply-asg-launch-template-approved`
- `verify-hardening-state`

Readiness-only operations:

- `verify-regional-alb-health`
- `regional-capacity-inventory`
- `generate-regional-cloudwatch-alarm-plan`
- `generate-alb-access-log-plan`
- `generate-waf-plan`
- `generate-asg-launch-template-plan`

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
- Copied DR snapshot cleanup: `I_APPROVE_DR_SNAPSHOT_CLEANUP`
- Regional ALB entrypoint apply: `I_APPROVE_REGIONAL_ALB_ENTRYPOINT_APPLY`
- CloudWatch alarm apply: `I_APPROVE_CLOUDWATCH_ALARM_APPLY`
- ALB access log apply: `I_APPROVE_ALB_ACCESS_LOGS_APPLY`
- WAF COUNT-mode apply: `I_APPROVE_WAF_COUNT_MODE_APPLY`
- Regional ASG create and attach: `I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH`

## Immutable Evidence

The apply workflows write logs under `artifacts/dr/`, generate `artifacts/dr/sha256-manifest.txt`, and upload evidence with `actions/upload-artifact@v4`.

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
- `alb-entrypoint-apply-policy.template.json`
- `regional-readiness-policy.template.json`
- `hardening-apply-policy.template.json`
- `asg-web-instance-profile-policy.template.json`
- `dr-explicit-deny-guardrail-policy.template.json`

Replace placeholders such as `<AWS_ACCOUNT_ID>`, `<GITHUB_ORG>`, `<GITHUB_REPO>`, `<HOSTED_ZONE_ID>`, `<NORMALIZED_RECORD_NAME>`, `<TARGET_REGION>`, and `<BUCKET_NAME>` before applying in AWS.

## Safety Notes

- The safe operations workflow still does not expose mutation operations.
- The apply workflows are manual-only and each has fewer than 25 `workflow_dispatch` inputs.
- No health check triggers DNS movement.
- DNS cutover and rollback call the local gated scripts.
- DB restore creates only a new recovery target and does not modify the primary DB.
- Snapshot copy and region-local restore are manual-only and protected by `dr-db-restore`.
- Recovery DB and copied snapshot cleanup are isolated behind `dr-recovery-cleanup`, require a reviewer, should be restricted to `main`, and must never target production identifiers.
- Object storage write testing writes only under `dr-tests/<timestamp>/`.
- Regional ALB entrypoint apply creates or reuses ALB/ACM/target group resources, selects one public IGW-routed ALB subnet per Availability Zone, may call `set-subnets` to correct an existing ALB subnet set, may UPSERT ACM validation CNAMEs, and does not cut over public DNS.
- Regional readiness is read/plan-only. It gathers ALB/target/EC2/CloudWatch evidence and generates alarm, access-log, WAF, and ASG plans without enabling those services.
- Hardening apply is manual-only and protected by `dr-hardening-apply`. CloudWatch alarms, ALB access logs, and WAF COUNT mode are staged before any ASG apply. ASG apply is the highest-risk hardening step and must not be run while `documents/ops/aws-asg-multi-instance-readiness.md` says `ASG_STATUS=BLOCKED`.
- Current app scaling gate: ASG_STATUS=BLOCKED. Before using `I_APPROVE_REGIONAL_ASG_CREATE_AND_ATTACH`, review `documents/ops/aws-asg-multi-instance-readiness.md`, `documents/ops/aws-asg-multi-instance-readiness.checklist.json`, and a fresh `node scripts/dr/check-asg-multi-instance-readiness.mjs` result.
- Bucket deletion, DB deletion, DB failover, recursive object deletion, Docker prune, and MinIO decommission remain out of scope.
