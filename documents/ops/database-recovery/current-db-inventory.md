# Current Database Inventory Template

Last updated: 2026-05-11

Do not record passwords, full database URLs with credentials, private keys, or customer data in this inventory.

| Field | Value |
| --- | --- |
| DB engine |  |
| AWS account |  |
| Primary region | `eu-west-2` |
| Instance/cluster identifier | `REPLACE_WITH_DB_IDENTIFIER` |
| Endpoint | `REPLACE_WITH_DB_ENDPOINT_NO_PASSWORD` |
| Port | 5432 |
| Database name | `REPLACE_WITH_DATABASE_NAME` |
| Backup method | Automated backup / manual snapshot / other |
| Snapshot schedule |  |
| Retention period |  |
| Encryption/KMS status |  |
| Subnet notes |  |
| Security group notes |  |
| Connection source from Mumbai |  |
| Connection source from Cape Town |  |
| Owner |  |
| Last verified date |  |

## Inventory Review Checklist

- [ ] Primary database identifier confirmed.
- [ ] Backup method confirmed.
- [ ] Encryption/KMS access confirmed.
- [ ] Restore target regions confirmed.
- [ ] Mumbai app-to-DB route documented.
- [ ] Cape Town app-to-DB route documented.
- [ ] Owner and last verified date recorded.
