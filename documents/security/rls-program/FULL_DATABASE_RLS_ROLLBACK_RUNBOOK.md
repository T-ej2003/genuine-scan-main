# Full-Database RLS Clean-Room Rollback Runbook

Status: locally implemented; staging and production execution are not authorized.

## Deployment boundary

Full-database RLS is installed only on a fresh green PostgreSQL instance or cluster. The current blue database, its objects, roles, ACLs, owners, policies and task definitions are never altered by this package. Because PostgreSQL roles are cluster-wide, green must be isolated from blue unless every managed role name is demonstrably absent; the approved staging and production model uses isolated green infrastructure.

There is no in-place restoration package. A failed green candidate is destroyed.

## Rollback prerequisites

Before cleanup, the operator must prove all of the following:

1. every application, worker, scheduled and operator consumer of green is stopped or disconnected;
2. traffic is on blue, or the exact task-definition switch back to blue has completed;
3. no required business data was accepted by green; staging validation fixtures must be declared disposable;
4. the target database name, deployment ID, source-contract checksum and package role marker match the activation record;
5. the target is green, never the current blue database;
6. the maintenance administrator has `DROP DATABASE`/`CREATEDB` and exact role cleanup authority without true PostgreSQL `SUPERUSER`.

If required data may exist, stop. Do not drop green and do not improvise data migration.

## Exact rollback sequence

1. Freeze green writes and terminate only connections to the recorded green database.
2. Switch or confirm application task definitions and secrets point to blue.
3. Re-run the no-required-data check and record its evidence.
4. Connect to the recorded maintenance database, not green, and drop only the exact green database.
5. Run `clean-room-cleanup.sql`, which includes `90-clean-room-role-cleanup.sql`.
6. Cleanup must refuse unless green is absent and every managed role has the exact package marker. It then drops only those package-created roles in dependency-safe order.
7. Verify the green database count and managed-role residue count are both zero, blue's fingerprint is unchanged, and blue application smoke tests pass.

`DROP OWNED`, arbitrary role cleanup, object-level owner reversal and legacy ACL/default-ACL reconstruction are prohibited.

## Failure behavior

Each package phase is transactional. A phase error cannot be treated as success. If database destruction succeeds but role cleanup fails, keep traffic on blue and retry only the checksum-bound role cleanup after re-proving green is absent and every role marker is exact. An unexpected role, marker, database or active consumer is a blocking incident.

## Disposable proof

`scripts/rls/certify-full-database.mjs` creates a fresh database, applies Prisma migrations from zero, installs the exact package, injects failures at every package-created stage, destroys the candidate and proves zero database or managed-role residue. It also fingerprints a separate blue sentinel before and after every refusal/failure path. This mechanical proof does not certify application workflows or authorize staging.

## CTO recommendation

Keep green on a separate encrypted RDS instance with deletion protection disabled only during the controlled pre-traffic build window, then enable deletion protection before traffic. Emit an immutable write-acceptance counter from the application and database so the no-required-data rollback precondition is machine-verifiable rather than an operator judgment.
