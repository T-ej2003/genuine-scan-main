# Object Storage Recovery Pack

Last updated: 2026-05-31

## Purpose

This is the Phase C MinIO decommission / S3 proof pack for MSCQR multi-region disaster recovery. It helps operators prove production and ASG DR paths use S3/default credentials while preserving local development MinIO and all MinIO data.

## Documents

- [Phase C overview](../aws-multi-region-phase-6.md)
- [Phase C MinIO decommission / S3 proof runbook](minio-decommission-s3-proof-runbook.md)
- [Current storage inventory](current-storage-inventory.md)
- [Read path checklist](read-path-checklist.md)
- [Write path checklist](write-path-checklist.md)
- [Replication options](replication-options.md)
- [Rollback and reconciliation](rollback-and-reconciliation.md)

## Safety Rules

- Do not record access keys, secret keys, tokens, or private credentials.
- Do not delete buckets.
- Do not delete production objects.
- Do not delete MinIO data automatically.
- Do not recommend MinIO for production/ASG DR steady state.
- Complete read-path proof before any decommission approval.
- Do not run write tests until database recovery and write gate approval are complete.
- Do not start automatic failover; Phase D remains blocked until Phase C is complete.
