# Full-Database RLS Production Blue/Green Replication Runbook

Status: plan only. Production access and deployment are prohibited in this programme run.

## Authority

Production may use only the exact staging-proven source commit, image digests, Prisma migration inventory, SQL package, role marker, catalog expectations and cleanup checksum. Production approval is separate from merge and staging approval.

## Topology and data precondition

- Blue is the current production database and task-definition set. It remains untouched.
- Green is a separate encrypted PostgreSQL 18 RDS instance or cluster with a fresh template0-derived database and no application objects or managed roles.
- All package roles are new on green. Existing blue roles/ACLs are irrelevant and are neither inspected for restoration nor modified.
- This zero-based procedure is valid only while there is no required onboarded customer data to migrate. If that fact changes, stop and obtain a reviewed data-migration/cutover contract; do not improvise dual writes or destructive cleanup.

## Preconditions

1. Staging completed all 428 workflow dispositions, full soak, performance gate, blue/green rollback rehearsal and clean rebuild using the exact candidate artifacts.
2. The final system review has zero P0-P2 findings and staging exposed no new unresolved correctness or security defect.
3. Production green topology, administrator capability, KMS/encryption, backups/PITR, monitoring, task definitions, secret separation and broker audit are independently approved.
4. Incident commander, database operator, security checker and application rollback owner are named for the window.
5. The no-required-data assertion and rollback write-acceptance threshold are machine-verifiable.

## Green build and certification

Run the same five checksum-bound phases proven in staging: `admin-bootstrap.sql`, restricted zero-based Prisma migration, `admin-ownership.sql`, `runtime-policy.sql`, and `verification.sql`. No phase targets blue. No runtime task uses the administrator, migration identity or either NOLOGIN owner.

Before traffic, run safe production-environment smoke checks that create no customer data, exact catalog/role/privilege verification, pool/reconnect checks and performance comparisons. Match the reviewed commit, image and SQL checksums byte-for-byte.

## Traffic switch

Switch only the exact approved task definitions and secret versions to green, with bounded weighted traffic and immediate alarms for supported-workflow failures, RLS denials, cross-scope anomalies, connection saturation and latency regression. Do not weaken policies or bypass RLS to recover a failing workflow.

Blue remains the rollback target. If a rollback criterion trips before required data is accepted, stop/disconnect green, switch tasks to blue, prove blue health, destroy the green database and drop only exact package-marked roles. If required data may have been accepted, stop the automated rollback and invoke the approved incident/data-reconciliation procedure.

## Evidence

Record immutable activation ID, operator and checker identities, timestamps, blue and green infrastructure identifiers, source/image/package/cleanup checksums, catalog and role snapshots, workflow results, performance/soak results, traffic weights and rollback readiness. Exclude endpoints, credentials, tokens, request bodies and customer row data.

No production command in this runbook is authorized until the user separately approves production replication.
