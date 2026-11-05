# d15b79e offline release verification package

Source: `d15b79e4779d64be4c6c7ec905caea1e91d410f2`. This package is preparation only. It grants no production authority and has not been run against production.

## Fixed executor preparation (2026-11-05)

The isolated `infra/d15-catalog-readback-executor` branch adds a fixed-command Docker target, runtime, pinned checker KMS public key, RDS regional CA bundle, and hostile tests. The runtime accepts no SQL or command arguments, hashes the exact D15 SQL before connecting, validates a short-lived checker-KMS-signed authorization, restricts the connection to the named database/role/host with `verify-full` TLS, and emits bounded catalog chunks with integrity metadata. The receipt verifier reconstructs evidence only from the ordered audit stream and rejects forged or stale receipts. This is offline source preparation, not a deployed private route or production receipt.

Deployment still requires a reviewed dedicated `mscqr_prod_d15_catalog_read` login and credential, restricted ECS task/execution roles, task definition without ECS Exec or mutable overrides, private network access, restricted CloudWatch audit retention, exact launcher/broker IAM boundary, and checker-signed receipt from authenticated ECS/CloudWatch/CloudTrail readback. These resources do not currently exist. The owner ruled out Terraform source changes. Do not provision overlapping resources using ad hoc AWS CLI. Establish an approved non-Terraform ownership/review path before any deployment. The admin credential, emergency DBA task, and fixed RLS canary are excluded.

The fixed SQL proves catalog and migration-ledger visibility only. The comparator also needs an independently authenticated migration/rollback receipt containing the 57 applied Prisma migration records. Do not infer this receipt from the executor output. No image was published, task registered or run, or production SQL executed.

The proposed non-Terraform ownership and private launcher route is in [D15 fixed readback ownership proposal](iam/D15_FIXED_READBACK_OWNERSHIP_PROPOSAL.md). It is a review proposal and grants no production execution authority.

## Database evidence

Expected source contract: `53fe3f041a8d20760caa68898a5de03fffe95eb7d51d72449ac93b96824622ef`.
Expected migration set: `44d992d15d512f410966173b42298d299c34692a874b9cb0eda6fca707d620a5`.
Pinned expected catalog digest: `c96c74b68d15f3eda0bf06ae9fffeb1963cc24fe410f479bfc24aeadd3c1db38`.

The accountable production DBA must approve a restricted catalog-read identity and a reviewed execution environment. The existing fixed read-only canary cannot run this query. From that approved identity only:

```sh
psql -X -qAt -v ON_ERROR_STOP=1 -f scripts/aws/read-production-printing-catalog.sql > catalog-evidence.json
```

The DBA must first establish the approved restricted connection through the existing credential provider; no production catalog identity is presumed here. Required visibility is `pg_proc`, `pg_policy`, `pg_class`, `pg_attribute`, `pg_namespace`, `pg_roles`, and the catalog ACL functions, with readable `_prisma_migrations` and `mscqr_rls_install.state` ledgers. Do not print a connection URL, use an unrestricted SQL shell, or run this command before DBA authorization. A nonzero `psql` result, permission denial, truncated JSON, or missing receipt is `UNVERIFIED`, never absence. The query uses `BEGIN READ ONLY` and reads only catalog metadata; it never reads customer rows. Review the resulting function definitions before wider distribution because catalog text is operational evidence.

`scripts/aws/d15-expected-schema.json` was generated from the exact-source package installed on the repository-pinned PostgreSQL **18.4** image. `build-d15-expected-catalog.mjs` checked all 305 managed `app_*` function identities against generated SQL, all 384 policy identities and 78 FORCE RLS targets against the checked-in expected-catalog snapshot, and included 81 tables, nine managed roles, four managed schemas, normalized function definitions and SHA-256 hashes, owners, ACLs, effective grants, 57 Prisma migration identifiers/checksums, and the printing rollback SQL digest. The source-installed catalog capture is retained as a test fixture. The full repository package certification passed on the canonical disposable harness. An earlier run with a manually created `postgres` superuser failed its exact `subscription_conninfo_acl` grantor check because the approved harness uses `mscqr_p2_test`; another run omitted the harness TLS setup. Neither run changed the source SQL or expected-schema manifest.

The DBA's separately approved receipt must bind the exact source SHA, source contract, migration set, production database and catalog identity, approval reference, catalog evidence SHA-256 (canonical JSON), all 57 migration identifiers/checksums with `state: "applied"`, rollback SQL SHA-256, `rollbackCompatibility: "verified"`, and a nonempty rollback evidence reference. If an object is missing and a migration is approved, the receipt must also contain `approvedMigrationDeltaSha256`, computed over the sorted missing-object identifiers. The accountable owner must authenticate and verify the receipt under the existing governance process before running the comparator. A matching untrusted JSON receipt can be forged; this comparator is not a signature verifier or deployment approval.

```sh
node scripts/aws/compare-production-printing-catalog.mjs scripts/aws/d15-expected-schema.json catalog-evidence.json verified-migration-receipt.json
```

`COMPATIBLE` means the complete pinned object inventory, effective grants, and supplied receipt fields match; it is not deployment approval or a tenant-isolation runtime test. `MIGRATION_REQUIRED` means a source-required object or migration identifier is visibly absent **and** its exact delta is approved in the authenticated receipt. `INCOMPATIBLE` means a present object, unexpected object, or applied migration contradicts the source. `UNVERIFIED` means evidence, authority, visibility, receipt, or delta approval is incomplete. Review predecessor-backend compatibility before authorizing any SQL application.

## Direct release authority

The exact-source normal deployment run `42049258251` classified the change `SECURITY_INFRASTRUCTURE`. The current normal lane therefore cannot deploy this SHA. `publish-ecs-images.yml` and `deploy-ecs-service.sh` provide technical commands, but no independently approved direct exception for this source was found. The accountable production release/governance owner must identify a current policy permitting the alternative and provide an exact-source authorization, or state that the stronger lane is mandatory. Do not alter the classifier or split the required SQL from the release to make it pass.

The authorization request must bind the source SHA, backend and worker impact, no frontend source impact since the current backend image, printing SQL and migration digest above, current backend `:39` and frontend `:23`, previous immutable digests, approved replacement digests, database migration/rollback order, connector scope, rotation state, independent checker, KMS verification, expiry, and ALB/runtime smoke evidence. No signature, approval ID, or validity window is invented here.

## Connector

The signed `2026.10.29.1` artifact came from workflow run `40974330682` at `9fbec4ddecbe29f4adbc5a820238180d882b203f`. Current source still declares `2026.10.29.1`, but its connector runtime and Windows packaging changed after that run. The existing workflow requires `connector_release_version` to equal the source version and `maintenance_api_origin` to be an approved HTTPS origin. `build_verify_only` does not publish, but still requires `production-signing` approval. No repository rule establishes the next version automatically; the connector release owner must select a new monotonic version and review the source version change before a new signed artifact. Verify installed-version upgrade, protocol `local-agent-direct-v2`, maintenance fence, ACK/replay behavior, legacy rollback, and actual Windows signature before publication. Do not overwrite the old version artifact or raise the minimum version before a verified successor exists.

## Offline checks performed

- The catalog SQL ran in `BEGIN READ ONLY` against the repository-pinned PostgreSQL **18.4** image and returned the expected empty lists on a fresh database. It also captured the source-installed package used by the manifest.
- Full package certification passed on the canonical disposable harness after `npm run test:p2:db:up` and `node scripts/p2-test-db-tls.mjs`, using `MSCQR_PRODUCTION_PACKAGE_POSTGRES18_TEST=true` and `MSCQR_PRODUCTION_PACKAGE_POSTGRES18_ADMIN_URL=postgresql://mscqr_p2_test@127.0.0.1:55432/mscqr_p2_admin_test`. The harness provides the expected `mscqr_p2_test` catalog grantor and TLS. Do not treat a run under a different superuser as equivalent evidence.
- Failure diagnosis: `documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql` executes `GRANT SELECT (subconninfo) ON pg_catalog.pg_subscription TO mscqr_prod_subscription_observer`. The verifier reads `pg_attribute.attacl` through `aclexplode` and accepts one non-grantable `SELECT` for that observer from `rdsadmin`, `mscqr_prod_admin`, or `mscqr_p2_test`. The noncanonical disposable run returned `[{"grantee":"mscqr_prod_subscription_observer","grantor":"postgres","grantable":false,"privilege":"SELECT"}]`, so the verifier correctly rejected it. Canonical fixture setup uses `mscqr_p2_test`; no assertion, grant, RLS rule, or approved SQL definition was relaxed.
- `node --test scripts/tests/compare-production-printing-catalog.test.mjs` passed, including incomplete, tampered, wrong-source, duplicate, unexpected-grant, policy, FORCE RLS, and migration cases.
- No production database query, image publication, ECS update, connector signing, or migration was performed.
