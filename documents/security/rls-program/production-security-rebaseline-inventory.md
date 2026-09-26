# Production security rebaseline inventory

This source-owned PR1 path inventories security metadata; it cannot apply SQL or authorize deployment. It is independent of historical B01 predecessor, successor, task outcome, execution identity, and receipt eligibility.

## Artifacts and data flow

The protected-main producer builds the canonical package in disposable PostgreSQL 18, then collects it with the same normalized catalogue collector used by the fixed production read-only task. The canonical inventory binds protected-main SHA, clean-room source contract, migration set, package checksums, collector version, and catalogue digest.

Identity fields remain distinct: `protectedMainSha` is the exact current canonical source; `candidateSourceSha` is the candidate image source accepted by the requirements workflow only when it is the protected SHA or an authenticated ancestor; `appOnlyRequirementsSha256` binds both identities and the catalogue. Canonical and live inventory artifacts retain both SHAs, and comparison requires them to match. The read-only task executes the fixed image module `scripts/aws/production-rls-catalogue-probe-runtime.mjs`; its bounded JSON environment value is parsed and schema-validated as data. The task builder does not serialize functions or generate JavaScript.

The app-only compatibility verifier follows the same code/data boundary: its image contains `scripts/aws/production-app-only-verifier-runtime.mjs`, while its ECS command carries only bounded compressed JSON data. That payload binds the protected source SHA, the independently authenticated candidate source SHA, the complete requirements hash, and a versioned verification-contract digest. Candidate ancestry remains validated by the requirements producer; neither runtime substitutes protected main for a distinct candidate.

The production task runs `REPEATABLE READ, READ ONLY`. Its complete catalogue is gzip-compressed and encrypted to an ephemeral local RSA public key before CloudWatch transport. The private key is never sent to AWS. Canonical, live, and diff files are created outside the checkout with mode `0600`; normal output contains only identities of the source/artifacts, collection/category counts, and digests.

The versioned shared security collector includes all non-system roles (including authentication expiry, connection limits, comments, safe settings, direct membership edges with grantor identity, and relevant ownership/grantee references), global and schema-specific default ACLs, parameter ACLs, installed extensions, non-system non-extension-owned functions, procedures, aggregates, and window routines in user schemas, and relation kinds `r`, `p`, `v`, `m`, and `f`; sequences are collected separately with owner, ACL, and sequence parameters. Extension identity contains name, version, schema, relocatability, and owner. Any extension drift blocks plan construction. The current canonical target permits only provider-managed `plpgsql` in `pg_catalog`; those extension-owned members are inside the explicit system boundary, while every other extension is a blocker before its members can be considered safe.

Independently mutable attachment surfaces are collected separately: publication options plus table/schema membership, published columns and row filters; enabled and disabled subscription identity/options from the public safe columns of `pg_subscription` without its connection string; persistent replication-slot identity; database-global settings and security labels as domain-separated digests; user-schema operators/casts; procedural languages; foreign-data wrappers, servers, user mappings, and foreign tables. Foreign option values never enter the catalogue: only option names and domain-separated SHA-256 digests are retained, and a masked user mapping fails closed. Binding, constraint-trigger, or parameter-ACL drift blocks planning. The only canonical environment translation maps the authenticated `mscqr_p2_test` grantor on exact source-generated SET-only phase-2 memberships to production's `rdsadmin` semantic grantor. Live grantors are never translated, and every other canonical grantor fails closed. The same exact translation applies to the source-required `plpgsql` extension and language owner/default ACL in `pg_catalog`; no arbitrary owner or role-name rewriting is allowed.

View and materialized-view rows include `pg_get_viewdef(..., false)` output and security-relevant view options. Non-internal triggers on security-relevant relations include enablement, function identity, and `pg_get_triggerdef(..., false)`. Internal constraint triggers use a stable constraint/relation/function/type identity and retain enablement without backend-local trigger names or OIDs. Non-`_RETURN` rewrite rules are collected with canonical definitions; database event triggers retain owner, event, tags, enablement, and function identity. Any rule or event-trigger drift blocks plan construction. Partition-constraint parents use stable schema/relation/constraint identities, never backend-local OIDs. Types include ownership, ACL grantor, base/domain/enum metadata, and constraints. Every security-inventory ACL expansion retains grantor as well as PUBLIC/grantee, privilege, and grantability. Aggregate behavior is represented by a digest of its normalized `pg_aggregate` definition because PostgreSQL does not support `pg_get_functiondef` for aggregates. Generated array types are excluded because PostgreSQL rejects independent ACL changes on array types; their element-type ACLs are collected. The system boundary is PostgreSQL-reserved `pg_*` plus exact documented AWS RDS predefined roles, including `rdstopmgr`; arbitrary `rds_*` names are not excluded. The exact `mscqr_p2_test` and `certification-administrator` roles are omitted only from the canonical disposable PG18 harness target and remain unexpected in live collection. Indexes and TOAST relations have no separately managed application ACL boundary and are excluded. Operator inventory records direct memberships and the effective recursive role-membership closure, honoring both per-membership `INHERIT` and each role's `INHERIT` attribute. Unallowlisted roles and memberships become hard-stop diff objects; extension, binding, trigger, rule, event-trigger drift, and a global default ACL granting PUBLIC also block plan construction. The CloudWatch reader accepts the result only after its authenticated terminal record binds the complete encrypted chunk count and transport digest; incomplete ingestion times out without launching another task.

## Collector coverage contract

The executable `SECURITY_REBASELINE_COVERAGE` table binds each security surface to its real PostgreSQL catalogue, raw collector collection, and normalized diff collection. Tests assert that this table stays connected to both ends of the pipeline; the PG18 integration test supplies real rows for the behavioral surfaces.

## Required database prerequisite

The fixed read-only task does not provision database objects. Before its first live inventory, the dedicated read-only canary and its restricted `production_security_subscription_inventory()` projection must already have been installed and authenticated by the separately reviewed `documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql` procedure. That DBA operation is a distinct, explicitly authorized provisioning change; it is not run by this PR, the inventory command below, or the ECS task. Follow that procedure's hidden credential prompt and rotation rules. The inventory collector verifies the observer's exact NOLOGIN privileges, the complete `pg_subscription.subconninfo` ACL (only the observer may hold non-grantable SELECT, from an approved provisioning principal), projection owner/body/search path/ACL, and canary invocation grant before calling it; if any prerequisite is absent or differs, collection fails closed before returning an inventory. Do not treat that failure as an empty subscription inventory or proceed to comparison.

Example operator shape (do not run without separate production authorization):

```sh
node scripts/aws/probe-production-rls-catalogue.mjs \
  --source-sha "$PROTECTED_MAIN_SHA" \
  --candidate-source-sha "$CANDIDATE_SOURCE_SHA" \
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
