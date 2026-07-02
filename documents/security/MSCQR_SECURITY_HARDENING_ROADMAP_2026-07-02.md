# MSCQR Security Hardening Roadmap

Date: 2026-07-02
Audience: engineering, security, and operations reviewers.
Scope: public-safe roadmap. This document avoids private infrastructure topology, account secrets, internal inventories, and sensitive endpoint details.

## Current Principle

MSCQR should keep app-layer authorization in place while adding stronger infrastructure and database controls. Security improvements should be rolled out route by route, with evidence, rollback plans, and monitoring before scale testing.

## Roadmap Items

### 1. Route-by-Route Database-Enforced RLS

Continue replacing application-only tenant checks with database-enforced row level security one route at a time.

Requirements:

- Keep existing application authorization checks after RLS is added.
- Use false-by-default route flags during staging validation.
- Prove positive and negative tenant isolation cases per route.
- Capture query shape, latency, and rollback evidence before broadening.
- Avoid production/global/table RLS enablement until the route-specific evidence is approved.

Recommendation:

- Treat RLS as a defense-in-depth control, not a replacement for service authorization. The strongest design is app authorization plus database policy plus telemetry that proves both are active.

### 2. Managed QR Signing and Key Custody

Move fully to managed QR signing or KMS/HSM-backed signing when budget allows, preserving key-version evidence for verification and audit.

Requirements:

- Maintain key version identifiers in QR verification evidence.
- Keep signing keys out of application logs, build artifacts, and operator terminals.
- Define rotation and rollback procedures before migration.
- Preserve compatibility for already-issued QR codes.

Recommendation:

- Prioritize KMS-backed signing for operational maturity. HSM-backed signing is stronger but should be justified by compliance needs, throughput, and cost.

### 3. Dependency Risk Scoring in CI

Add automated dependency-risk scoring to CI in addition to dependency-audit failure.

Requirements:

- Score new and changed dependencies by maintenance health, license risk, known vulnerabilities, transitive reach, and install script behavior.
- Require reviewer acknowledgement for high-risk additions.
- Keep emergency security patch flow fast while still recording evidence.

Recommendation:

- A binary audit gate catches known CVEs but misses supply-chain risk. Add risk scoring before the dependency graph becomes too large to govern manually.

### 4. Connector Endpoint Abuse Detection

Add connector abuse detection beyond static rate limits.

Signals:

- Impossible heartbeat velocity.
- Repeated invalid session hello attempts.
- Printer registration churn.
- Suspicious claim/fail loops.
- Repeated attestation or fingerprint mismatches.
- Unusual task polling patterns relative to assigned printer or tenant.

Requirements:

- Keep detection tenant-aware without leaking tenant identifiers into public logs.
- Add structured security events with redacted identifiers.
- Add alert thresholds and investigation runbooks before enforcing automated lockouts.

Recommendation:

- Start with detection and evidence. Automated blocking should follow only after false-positive review because connector outages can directly affect manufacturer operations.

### 5. Backup, Restore, and Disaster Recovery Evidence

Formalize backup/restore and disaster recovery drills with evidence for Postgres, Redis persistence assumptions, and object storage recovery.

Requirements:

- Prove Postgres restore into an isolated environment on a recurring schedule.
- Document Redis/Valkey persistence assumptions and acceptable data loss for cache/session classes.
- Prove object storage recovery for representative artifacts.
- Record RTO, RPO, operator, timestamps, commands, and verification checks.

Recommendation:

- A backup is not a control until restore evidence exists. Schedule small restore drills first, then grow into full incident tabletop exercises.

### 6. Staging and Production Health Dashboards

Add staging and production health dashboards before scale testing.

Requirements:

- Track ALB 4xx/5xx, target health, ECS desired versus running tasks, task restarts, backend health latency, RDS CPU/connections/storage/memory, Redis CPU/memory/evictions/connections, security event volume, and estimated monthly cost.
- Gate scale tests on dashboard readiness.
- Tie alarms to runbooks, not just notification channels.

Recommendation:

- Build staging dashboards first and promote proven patterns to production. Avoid copying untested alarms into production where they create alert fatigue.

### 7. Controlled Operator Access

Keep ECS Exec and similar shell access break-glass only.

Requirements:

- Require explicit role assumption, ticket or approval ID, command pre-approval, and post-command log review.
- Encrypt and retain session logs.
- Alert on unexpected `ExecuteCommand` events.
- Prefer repeatable jobs over interactive commands.

Recommendation:

- Operator shell access is useful during staging bring-up but should shrink over time. The scalable operating model is auditable jobs, migrations, dashboards, and runbooks.

## Near-Term Priority

1. Finish controlled staging ECS Exec logging and operator policy review before any future staging apply.
2. Add staging health dashboard and `ExecuteCommand` event alerting.
3. Run staging RLS validation only against approved routes with redacted evidence.
4. Add dependency-risk scoring as a CI advisory gate, then promote it to a required gate after baseline tuning.
5. Plan the managed QR signing migration with explicit key-version evidence and backward compatibility.

## Non-Goals

- This roadmap does not publish private infrastructure topology.
- This roadmap does not authorize production database changes.
- This roadmap does not enable production/global/table RLS.
- This roadmap does not replace app-layer authorization.
- This roadmap does not grant broad operator or administrator access.
