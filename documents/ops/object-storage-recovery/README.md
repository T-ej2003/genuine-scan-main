# Object Storage Recovery Pack

Last updated: 2026-05-11

## Purpose

This is the Phase 6 object storage recovery pack for MSCQR multi-region disaster recovery. It helps operators verify object read/write readiness safely after database recovery planning.

## Documents

- [Phase 6 overview](../aws-multi-region-phase-6.md)
- [Current storage inventory](current-storage-inventory.md)
- [Read path checklist](read-path-checklist.md)
- [Write path checklist](write-path-checklist.md)
- [Replication options](replication-options.md)
- [Rollback and reconciliation](rollback-and-reconciliation.md)

## Safety Rules

- Do not record access keys, secret keys, tokens, or private credentials.
- Do not delete buckets.
- Do not delete production objects.
- Do not decommission MinIO.
- Do not run write tests until database recovery and write gate approval are complete.
