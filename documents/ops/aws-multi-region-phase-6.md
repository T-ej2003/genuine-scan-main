# AWS Multi-Region Phase 6: Object Storage DR Hardening

Last updated: 2026-05-11

## Summary

Phase 6 documents object storage disaster recovery hardening for MSCQR. It is documentation and safe checklists only.

## Goal

Make sure a selected standby region can read required objects and, after database recovery plus write gate approval, safely write new objects without data loss or split-brain behavior.

## Current Known State From Public Health

The public health output showed production object storage configured and ready. This is health-output evidence, not secret disclosure.

| Field | Observed value |
| --- | --- |
| Bucket | `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an` |
| Region | `eu-west-2` |
| Endpoint | `null` |
| Mode | `default-credentials` |
| Ready | `true` |

## Object Storage Recovery Options

| Option | Description | Current recommendation |
| --- | --- | --- |
| Continue using approved central S3 bucket from standby | Standby app reads/writes to the approved bucket if IAM/network policy allows. | Verify read access first. |
| Restore/copy required objects to regional bucket | Copy only required objects to selected region after approval. | Consider only after DB recovery is proven. |
| Future S3 Cross-Region Replication | Automated replication configured later after validation. | Future option, not Phase 6 implementation. |
| MinIO intentionally retained | Keep current MinIO containers/data if used by the deployment. | Do not decommission as part of Phase 6. |

## Verify Read Path

- Identify a safe non-sensitive test object.
- Verify standby app IAM role or credential source.
- Verify bucket policy allows intended read path.
- Verify backend can read required assets.
- Verify logs show no access denied or endpoint errors.

## Verify Upload/Write Path

Run write verification only after:

- Database recovery is approved.
- Write gate is approved.
- Test object naming avoids production collision.
- Cleanup owner is assigned.

Do not delete production objects during write verification.

## Bucket Policy/IAM Checks

- Confirm standby app role or credential source.
- Confirm least-privilege bucket access.
- Confirm encryption/KMS permissions.
- Confirm region-specific access from Mumbai.
- Confirm region-specific access from Cape Town.
- Confirm logs/audit trails are available.

## App Environment Checks

- `OBJECT_STORAGE_BUCKET` points to approved bucket.
- `OBJECT_STORAGE_REGION` or `AWS_REGION` matches the approved plan.
- `OBJECT_STORAGE_ENDPOINT` is blank for native S3 default-credentials mode.
- Static access keys are not copied into docs.
- Credential source is recorded without secret values.

## Rollback Plan

- Preserve objects and evidence.
- Stop write tests if any object/database linkage fails.
- Do not delete buckets.
- Do not delete production objects.
- Keep test object cleanup separate from incident evidence retention.
- Reconcile object references with database rows if writes occurred.

## Completion Checklist

- [ ] Current storage inventory completed.
- [ ] Read path verified from Mumbai.
- [ ] Read path verified from Cape Town.
- [ ] Write path checklist approved but not run until DB recovery gate passes.
- [ ] IAM/bucket policy reviewed.
- [ ] Rollback/reconciliation owner assigned.
- [ ] Replication option recommendation recorded.

## Explicit Exclusions

- No MinIO decommission.
- No destructive object deletion.
- No bucket deletion.
- No automatic failover.
- No active-active writes.
- No object storage migration implementation in Phase 6.
