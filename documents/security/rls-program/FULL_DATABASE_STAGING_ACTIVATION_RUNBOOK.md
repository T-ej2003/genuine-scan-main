# Full-Database RLS Staging Blue/Green Activation Runbook

Status: written only; activation remains blocked. The current staging database has not been accessed or modified by this foundation work.

## Topology

- **Blue rollback target:** the current staging database and current task definitions, unchanged.
- **Green candidate:** a separate encrypted PostgreSQL 18 RDS instance or cluster with a fresh template0-derived `staging-rls` database.
- **Role namespace:** green is isolated because PostgreSQL roles are cluster-wide and all managed roles must be newly package-created.
- **Traffic rule:** no application task points to green until the complete supported-workflow staging certification passes.

An in-place conversion of blue is prohibited.

## Blocking gates

Do not create or mutate green until all of these are true:

1. all 428 workflows have one exact final disposition and every supported workflow is application-path certified locally;
2. the final system review has zero unresolved P0-P2 findings;
3. source, image, Prisma migration, SQL package and cleanup checksums are frozen;
4. the green RDS administrator's real non-superuser capabilities are proven through a checksum-bound private executor;
5. exact runtime, pre-auth, worker, scheduled, operator and migration credentials are separately provisionable and absent from blue tasks;
6. the clean-room PostgreSQL 18 certification, failure cleanup and blue-fingerprint proof are green;
7. safe synthetic fixtures, performance limits, soak duration, cutover criteria and rollback criteria are approved.

The existing blue database-role executor is not a full-RLS executor. Its full-RLS modes fail closed before any database call and must not be repurposed.

## Green preflight

Record the source commit, image digests, package/source/cleanup checksums, green RDS ARN and endpoint hash, database name, encryption/KMS state, PostgreSQL version, subnet/security groups, backup settings, administrator identity, operator identity and timestamp. Never record a credential or raw endpoint in repository evidence.

Preflight must refuse before mutation if any managed role, application object, migration ledger row, grant, policy, membership or default ACL exists, if green naming/topology differs, if traffic is already enabled, or if any production endpoint/secret is present.

## Checksum-bound green build

1. `admin-bootstrap.sql`: the green administrator repeats clean-room preflight and creates the exact package-marked roles.
2. `migration.sql` plus the ordered Prisma inventory: only the restricted green migration identity applies migrations from zero.
3. `admin-ownership.sql`: the green administrator transfers the exact post-migration objects to package-created NOLOGIN owners and removes temporary authority in the same transaction.
4. `runtime-policy.sql`: the green administrator installs exact context/functions, column grants, defaults, policies and all 75 FORCE targets.
5. `verification.sql`: exact bidirectional catalog verification and restricted-identity probes.

No running application, worker or scheduled task may receive an administrator, owner or migration credential.

## Certification before traffic

Deploy RLS-aware images as zero-traffic green tasks and run all 428 staging workflow dispositions through safe fixtures, including authentication, MFA, public/proof, tenant/platform/manufacturer, batch/QR/printing/release, workers/outbox, governance/incidents, administration, operator and startup paths. Run negative cross-scope, stale-membership, blank-context, replay, concurrency, lease, pool/reconnect, query-plan, load and soak tests. Preserve the existing HTTP/business contracts.

Only after every supported workflow and catalog check passes may the operator switch the exact ECS task definitions/secrets and ALB routing to green. Record before/after task definitions, desired counts, target health and connection pools. Blue remains available and read-only as the rollback target during the agreed window.

## Rollback rehearsal

Use only declared disposable staging fixtures so the no-required-data condition is provable. Stop/disconnect green tasks, switch traffic to blue, verify blue behavior, drop the green database from its maintenance database, drop only exact package-marked roles, prove zero residue and blue checksum stability, then rebuild the identical green candidate and rerun critical certification. Follow `FULL_DATABASE_RLS_ROLLBACK_RUNBOOK.md`.

## CTO recommendation

Use weighted ALB target-group switching with an explicit write-acceptance metric, connection-drain alarm and cross-tenant denial counter. Keep green pool capacity isolated from blue so soak traffic cannot exhaust the rollback target.
