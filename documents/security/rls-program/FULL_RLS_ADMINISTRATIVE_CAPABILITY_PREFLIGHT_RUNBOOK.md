# Full-RLS Clean-Room Administrative Capability Preflight

Status: PostgreSQL 18 semantics are implemented locally; staging green execution is not yet performed or authorized.

## Purpose

The administrative executor is a deployment-only green-cluster identity. It is never used by the application. On AWS RDS it need not be true PostgreSQL `SUPERUSER`; preflight proves behavior instead of assuming capability from role labels.

The current blue staging database and its executor are out of scope. Full-RLS modes on the existing blue executor are locked out before database access.

## Required executor capabilities

The green administrator must be bound to the exact environment, database, package/source checksums and private executor image. It must be able to:

- create and drop the fresh green database from a maintenance database;
- create, comment, alter and drop the exact managed roles;
- grant and revoke PostgreSQL 18 membership options needed by the package;
- assume the restricted migration identity and package-created NOLOGIN owners only during reviewed administrative phases;
- transfer exact post-Prisma objects and schemas;
- create exact schemas, functions, grants, default ACLs and policies and enable/FORCE RLS;
- read the catalogs used by exact verification;
- terminate only recorded green connections during cleanup.

It must be `NOBYPASSRLS` and must not be present in any runtime task. Retrieved credentials exist only for the audited deployment session and are removed from the executor environment afterward.

## Clean-room refusal contract

Before creating a role or application object, `00-preflight.sql` requires:

1. the exact green database/environment/deployment/administrator binding;
2. a template0-clean application catalog with no Prisma migration ledger;
3. all managed roles absent cluster-wide;
4. no application schema, table, enum, sequence, routine, policy, publication or subscription;
5. no unexpected direct database/schema grants, memberships or default ACLs;
6. traffic disabled and source/package hashes current.

`10-roles.sql` repeats the same preflight inline so direct invocation cannot bypass it. Every later mutating phase requires the exact package marker, prior phase and source checksum. A missing or drifted prerequisite refuses before mutation.

## Package split

| Phase | Executor | Capability boundary |
| --- | --- | --- |
| `admin-bootstrap.sql` | Green administrator | Clean-room refusal and new managed roles only |
| Prisma migration via `migration.sql` | Restricted migration identity | Migrations from zero; no role/policy/owner authority |
| `admin-ownership.sql` | Green administrator | Exact object transfer and temporary membership revocation |
| `runtime-policy.sql` | Green administrator | Exact helpers, grants, defaults, policies and FORCE RLS |
| `verification.sql` | Read-only behavior of green administrator plus restricted probes | Bidirectional expected catalog comparison |
| `clean-room-cleanup.sql` | Green maintenance administrator after database drop | Drop only exact package-marked roles |

## Local PostgreSQL 18 proof

`scripts/rls/certify-full-database.mjs` uses a non-superuser administrative shape on loopback PostgreSQL 18. It proves direct-phase refusal, zero-based migrations, role/ownership/policy installation, exact catalog verification, tamper detection, injected failure cleanup, green database destruction, marked-role cleanup and unchanged blue sentinel state. Connection strings and row values are excluded from evidence.

This local result proves PostgreSQL semantics only. It does not prove the future RDS identity, broker, task definition, image digest, secret, network or encryption posture.

## Future staging evidence

The future green executor receipt must bind the AWS account/region, green RDS ARN and endpoint hash, PostgreSQL version, encrypted storage/KMS, private subnets/security groups, executor task definition and digest-pinned image, broker code/revision, secret ARN, exact command/mode/checksums, operator identity, timestamps, exit status and sanitized PostgreSQL receipt. No database URL, password, endpoint, token, request body or row data may be committed.

Any mismatch or missing receipt blocks green creation. It never authorizes a blue database query.

## CTO recommendation

Implement the future green executor as a short-lived private task launched only through a checksum-bound broker, with CloudTrail/EventBridge alerts on task launch, secret retrieval, role creation and database deletion. Keep launch authority separate from review/checker authority.
