# Current Object Storage Inventory Template

Last updated: 2026-05-31

The observed bucket below came from public health output and is not a secret.

| Field | Value |
| --- | --- |
| Storage provider | AWS S3 for production/ASG DR; MinIO only for local development or preserved legacy data |
| Bucket name | `mscqr-prod-aps1-artifacts-368992683803-ap-south-1` |
| Region | `ap-south-1` |
| Endpoint | `null` for observed production default-credentials mode |
| Access mode | `default-credentials` |
| IAM role/user | `mscqr-asg-web-role-aps1` through `mscqr-asg-web-instance-profile-aps1` |
| IMDS posture | `HttpTokens=required`, `HttpEndpoint=enabled`, `HttpPutResponseHopLimit=2` required for Dockerized ASG backend |
| Encryption |  |
| Lifecycle rules |  |
| Replication status | None / manual copy / S3 CRR / unknown |
| Backup/copy status |  |
| Mumbai access status |  |
| Cape Town access status |  |
| Last verified date |  |
| Owner |  |

## Review Checklist

- [ ] Bucket/endpoint confirmed.
- [ ] Credential source identified without secret values.
- [ ] `OBJECT_STORAGE_ENDPOINT` confirmed empty for production/ASG DR.
- [ ] Static object-storage credentials confirmed empty for production/ASG DR.
- [ ] Mumbai read access verified.
- [ ] Cape Town read access verified.
- [ ] Write gate process documented.
- [ ] MinIO data archive/snapshot owner assigned before any retirement action.
- [ ] Rollback/reconciliation owner identified.
