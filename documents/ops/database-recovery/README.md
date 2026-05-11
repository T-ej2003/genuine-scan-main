# Database Recovery Pack

Last updated: 2026-05-11

## Purpose

This is the Phase 5 database recovery pack for MSCQR multi-region disaster recovery. It gives operators safe templates and checklists for restoring or selecting an approved recovered database endpoint before any real DNS cutover.

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
