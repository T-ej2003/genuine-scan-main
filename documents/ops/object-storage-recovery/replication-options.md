# Object Storage Replication Options

Last updated: 2026-05-11

## Comparison

| Option | Description | Benefits | Risks/Cost | Recommendation |
| --- | --- | --- | --- | --- |
| No replication, central bucket access | Standby regions access the approved current bucket. | Simple current-stage validation. | Cross-region latency and dependency on central bucket. | Recommended first: verify standby read access. |
| Manual copy | Copy required objects during recovery. | Operator-controlled. | Slower RTO, easy to miss objects. | Use only for scoped recovery if documented. |
| S3 Cross-Region Replication | AWS-managed replication to regional buckets. | Better regional readiness. | Requires policy/KMS/versioning design and testing. | Future option after DB recovery and manual cutover are proven. |
| Future dedicated regional buckets | App uses region-local bucket after cutover. | Clear regional isolation. | More app/env and reconciliation complexity. | Later phase only. |
| MinIO retained | Keep existing MinIO data/containers where intentionally used. | Avoids risky cleanup. | Not a long-term DR substitute by itself. | Retain until a separate approved migration exists. |

## Current Recommendation

For the current stage, verify standby read access first. Do not migrate object storage until database recovery and manual cutover are proven.

## Decision Inputs

- RTO target.
- RPO target.
- Object count and size.
- KMS/encryption posture.
- Application object reference patterns.
- Database recovery design.
- Compliance retention needs.
