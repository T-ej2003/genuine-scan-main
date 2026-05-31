# AWS Multi-Region Phase C: MinIO Decommission / S3 Proof

Last updated: 2026-05-31

## Summary

Phase C proves MSCQR production and ASG DR paths no longer depend on MinIO. It is a safe evidence phase: inventory current MinIO references, prove S3/default-credentials read readiness, optionally prove write readiness only after write gate approval, and prepare a MinIO archival plan.

Do not delete MinIO data automatically. Do not mutate AWS from this document. Do not change production DNS. Do not start Phase D automatic failover.

## Current Roadmap Status

- Phase A DB recovery: complete by operator evidence and approval.
- Phase B controlled Route 53 cutover: complete for Mumbai production.
- Phase C MinIO decommission / S3 proof: active.
- Phase D automatic failover: blocked until Phase C is complete and separately approved.

## Current Known S3 State From Existing Evidence

The public health output previously showed production object storage configured and ready. This is health-output evidence, not secret disclosure.

| Field | Observed value |
| --- | --- |
| Bucket | `mscqr-prod-aps1-artifacts-368992683803-ap-south-1` |
| Region | `ap-south-1` |
| Endpoint | `null` |
| Mode | `default-credentials` |
| Ready | `true` |

ASG web-node expectations are stricter than generic object-storage support:

- `docker-compose.asg-web.yml` contains only `backend` and `frontend`.
- `OBJECT_STORAGE_BUCKET` and `OBJECT_STORAGE_REGION` or `AWS_REGION` are required.
- `OBJECT_STORAGE_ENDPOINT`, `OBJECT_STORAGE_ACCESS_KEY`, and `OBJECT_STORAGE_SECRET_KEY` must be empty.
- `OBJECT_STORAGE_FORCE_PATH_STYLE` must be unset or `false`.
- The ASG web backend runs inside Docker on EC2.
- The ASG web instance profile is the desired S3 credential source through the AWS SDK default provider chain.
- Static AWS keys are forbidden in ASG web mode.
- IMDSv2 remains required with `MetadataOptions.HttpTokens=required` and `MetadataOptions.HttpEndpoint=enabled`.
- `MetadataOptions.HttpPutResponseHopLimit=2` is required so the containerized backend can receive IMDSv2 credential responses from the EC2 instance profile.
- `scripts/dr/bootstrap-asg-web-node.sh` rejects non-empty object-storage endpoint/static credential SSM values and does not print the values.
- Local development MinIO remains allowed only in `docker-compose.yml`.

## Phase C Completion Criteria

- MinIO usage inventory is reviewed and classified.
- ASG/production docs no longer recommend MinIO for DR steady state.
- Local guardrail check passes:

```bash
npm run check:minio-decommission-readiness
```

- Mumbai production/ASG object storage evidence proves S3/default-credentials read readiness.
- Optional write-path proof is either explicitly approved and captured or explicitly deferred.
- MinIO data archival plan is approved before any MinIO retirement action.
- Rollback owner and evidence location are recorded.
- Phase D remains blocked until this checklist is complete.

## Explicit Exclusions

- No automatic failover.
- No Route 53 failover routing.
- No production DNS mutation.
- No AWS mutation from this runbook.
- No secret changes or secret disclosure.
- No MinIO data deletion, volume deletion, or bucket deletion.
- No object storage migration write test without write gate approval.

Detailed operator steps live in [Phase C MinIO decommission / S3 proof runbook](object-storage-recovery/minio-decommission-s3-proof-runbook.md).
