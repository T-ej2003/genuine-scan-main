# Production security rebaseline inventory

This source-owned PR1 path inventories security metadata; it cannot apply SQL or authorize deployment. It is independent of historical B01 predecessor, successor, task outcome, execution identity, and receipt eligibility.

## Artifacts and data flow

The protected-main producer builds the canonical package in disposable PostgreSQL 18, then collects it with the same normalized catalogue collector used by the fixed production read-only task. The canonical inventory binds protected-main SHA, clean-room source contract, migration set, package checksums, collector version, and catalogue digest.

The production task runs `REPEATABLE READ, READ ONLY`. Its complete catalogue is gzip-compressed and encrypted to an ephemeral local RSA public key before CloudWatch transport. The private key is never sent to AWS. Canonical, live, and diff files are created outside the checkout with mode `0600`; normal output contains only identities of the source/artifacts, collection/category counts, and digests.

The shared security collector includes all non-system roles (including their attributes, comments, safe settings, direct membership edges with grantor identity, and relevant ownership/grantee references), global and schema-specific default ACLs, non-system non-extension-owned functions, procedures, aggregates, and window routines in user schemas, and relation kinds `r`, `p`, `v`, `m`, and `f`; sequences are collected separately. Aggregate behavior is represented by a digest of its normalized `pg_aggregate` definition because PostgreSQL does not support `pg_get_functiondef` for aggregates. Generated array types are excluded because PostgreSQL rejects independent ACL changes on array types; their element-type ACLs are collected. The system boundary is PostgreSQL-reserved `pg_*` plus exact documented AWS RDS predefined roles, including `rdstopmgr`; arbitrary `rds_*` names are not excluded. The exact `mscqr_p2_test` and `certification-administrator` roles are omitted only from the canonical disposable PG18 harness target and remain unexpected in live collection. Indexes and TOAST relations have no separately managed application ACL boundary and are excluded. Operator inventory records direct memberships and the effective recursive role-membership closure, honoring both per-membership `INHERIT` and each role's `INHERIT` attribute. Unallowlisted roles and memberships become hard-stop diff objects; a global default ACL granting PUBLIC also blocks plan construction. The CloudWatch reader accepts the result only after its authenticated terminal record binds the complete encrypted chunk count and transport digest; incomplete ingestion times out without launching another task.

Example operator shape (do not run without separate production authorization):

```sh
node scripts/aws/probe-production-rls-catalogue.mjs \
  --source-sha "$PROTECTED_MAIN_SHA" \
  --requirements-reference "$REQUIREMENTS_REFERENCE" \
  --security-rebaseline-reference "$CANONICAL_REFERENCE" \
  --security-rebaseline-canonical-out "$PRIVATE_CANONICAL_PATH" \
  --security-rebaseline-live-out "$PRIVATE_LIVE_PATH" \
  --aws-profile mscqr-production-root

node scripts/aws/compare-production-security-rebaseline.mjs \
  --source-sha "$PROTECTED_MAIN_SHA" \
  --live "$PRIVATE_LIVE_PATH" \
  --canonical "$PRIVATE_CANONICAL_PATH" \
  --out "$PRIVATE_DIFF_PATH"
```

The comparison hard-stops on unexpected business objects, schemas, or roles. Its closed categories cannot express business DML, `DROP TABLE`, or `DROP SCHEMA`.

## Required follow-up

PR2 may be designed only after a reviewed live artifact and diff exist. It must bind their digests, collector version, source SHA, source-contract digest, migration digest, and a fresh available RDS snapshot. It must remain incapable of business-data mutation and must verify a fresh read-only catalogue after one controlled apply.
