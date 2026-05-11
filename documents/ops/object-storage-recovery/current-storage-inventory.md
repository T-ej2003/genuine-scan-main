# Current Object Storage Inventory Template

Last updated: 2026-05-11

The observed bucket below came from public health output and is not a secret.

| Field | Value |
| --- | --- |
| Storage provider | AWS S3 / compatible endpoint / MinIO |
| Bucket name | `mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an` |
| Region | `eu-west-2` |
| Endpoint | `null` for observed production default-credentials mode |
| Access mode | `default-credentials` |
| IAM role/user | `REPLACE_WITH_ROLE_OR_USER_NAME_ONLY` |
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
- [ ] Mumbai read access verified.
- [ ] Cape Town read access verified.
- [ ] Write gate process documented.
- [ ] Rollback/reconciliation owner identified.
