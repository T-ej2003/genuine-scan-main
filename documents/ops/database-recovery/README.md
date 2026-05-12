# Database Recovery Pack

Last updated: 2026-05-11

## Purpose

This is the Phase 5 database recovery pack for MSCQR multi-region disaster recovery. It gives operators safe templates and checklists for restoring or selecting an approved recovered database endpoint before any real DNS cutover.

The current recovery direction is region-local: Mumbai standby should use an `ap-south-1` recovered DB, and Cape Town standby should use an `af-south-1` recovered DB. Do not make standby apps depend on private London RDS reachability.

## Documents

- [Phase 5 overview](../aws-multi-region-phase-5.md)
- [Current DB inventory](current-db-inventory.md)
- [Backup and snapshot checklist](backup-snapshot-checklist.md)
- [Restore runbook](restore-runbook.md)
- [Regional connectivity checklist](regional-connectivity-checklist.md)
- [RPO measurement template](rpo-measurement-template.md)
- [Rollback and reconciliation](rollback-and-reconciliation.md)

## Safety Rules

- Do not record secrets, tokens, private keys, database passwords, or raw database URLs.
- Do not run destructive database commands as part of this pack.
- Do not wipe, drop, truncate, or delete recovered data during drills.
- Do not allow writes until the write gate is approved.
- Do not move production DNS until app, database, object storage, TLS, rollback, and write gate are approved.
- Test database recovery before any real DNS cutover.

## Automation Sequence

1. Collect topology: `scripts/dr/aws-dr-topology-inventory.sh`.
2. Generate snapshot copy plan: `scripts/dr/generate-cross-region-snapshot-copy-plan.sh`.
3. Copy snapshot only through `AWS DR Snapshot Apply` with `I_APPROVE_CROSS_REGION_SNAPSHOT_COPY`.
4. Restore region-local DB only through `AWS DR DB Apply` with `I_APPROVE_REGION_LOCAL_DB_RESTORE`.
5. Check target DB readiness: `scripts/dr/target-region-db-readiness.sh`.
6. Diagnose standby-to-DB network path: `scripts/dr/diagnose-standby-db-network.sh`.
7. Cut over one standby app with `scripts/dr/test-standby-recovered-db.sh`.
8. Roll back the standby env with `scripts/dr/rollback-standby-db-env.sh`.
9. Cleanup recovery DB only through `AWS DR Cleanup Apply` with `I_APPROVE_RECOVERY_DB_CLEANUP`.
10. Cleanup copied manual DR snapshot only through `AWS DR Cleanup Apply` with `I_APPROVE_DR_SNAPSHOT_CLEANUP`.
