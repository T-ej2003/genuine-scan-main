# B01 prerequisite to normal backend deployment bridge

This bridge preserves four identities. `0f7ae1a70eec588ef4fdcb2b53e9f42e831c4414` is the immutable origin of the reviewed #567 RLS delta. `e1c16977e9fdce7a19dc267ba3c816ef4ff14597` is the reviewed #568 bridge merge. `69e71ab21c847d27f8a76795a6de6f623313c8ad` is the reviewed live-predecessor correction. The deployment source is the exact protected-main merge SHA of the narrow runtime-evidence correction that immediately follows it. Executable diff attestations cover all three ranges and reject application, authentication, RLS, schema, MFA, session, invitation, business, or unclassified changes.

The local production operator runs the source-bound B01 prerequisite command from the exact protected-main checkout. Before task registration it requires the stable revision-19 service, its immutable task-definition identity and security-relevant runtime shape, and the backend image digest's unique source tag `945692f49c6d262b0a54b9b8e4240ef4c21688eb`. That Node runtime image contains the production dependencies used by the separately injected, fixed, and read-back executor command; live service environment, roles, and commands are not inherited. The executor accepts only the seven reviewed catalogue mutations, authenticates the complete relevant database predecessor before its first mutation, applies them in one serializable transaction, authenticates the successor, and emits a 30-minute receipt. A converged successor emits a zero-write receipt. Any other catalogue state fails before mutation.

The predecessor and successor identities cover every B01 policy's schema, table, command, permissiveness, roles, comment, and PostgreSQL 18 canonical `USING` and `WITH CHECK` deparse hashes. They also cover the two changed functions' signatures, bodies, owners, execution properties and ACLs; the owner/pre-auth role security attributes; and the relevant `AuditLogOutbox` ownership, table ACL, payload-column ACL, forced-RLS state, and role-switch capability. The compact policy-state file is generated from the canonical package on disposable PostgreSQL 18 and the certification test requires exact equality with a freshly collected catalogue.

The receipt binds both semantic SHAs, predecessor and successor identities, package and migration digests, executor bytes, the complete CloudTrail RunTask request, stopped ECS task evidence, production environment, result, timestamp, and bridge patch digest. CloudTrail must match the source-built cluster, task definition, launch type, count, execute-command setting, client token, network configuration, and contain no overrides or extra request fields except AWS's observed false `dryrun` and `enableECSManagedTags` defaults. DescribeTasks may contain only AWS's observed inert materialization: an empty override object, empty arrays, or one name-only override for the expected container. The existing Normal Production Deployment workflow accepts the receipt only while its deployment SHA is still current protected main. It re-reads the stopped executor task and task definition using the existing normal-deployer read permissions, then runs the existing backend image, approval, OIDC, ECS, rollback, health, and smoke implementation. The security classifier remains unchanged and frontend deployment is excluded.

The #567 database change is additive for revision 19: existing refresh operations retain their contracts; the new finalization operation, grant, and narrowly bound policy are unused by the old backend. Therefore applying RLS first is backward-compatible. Application rollback does not roll RLS backward.

After this bridge is merged, execution starts only from a clean checkout whose `HEAD` and `origin/main` are the exact bridge merge SHA. A separately authorized operator runs:

```sh
node scripts/aws/apply-production-b01-prerequisite.mjs \
  --deployment-source-sha "$(git rev-parse HEAD)" \
  --aws-profile <approved-root-profile> \
  --receipt-out <new-private-receipt-path>
```

The command fails before SQL writes unless revision 19 and the exact #567 RLS predecessor are live. Failures emit only an allowlisted stage and sanitized code; raw exceptions and secrets are never logged. After it reports `APPLIED` or `ALREADY_CONVERGED`, the operator base64-encodes that new private receipt and dispatches `Normal Production Deployment` from the same still-current protected-main SHA with `baseline=false` and `b01_prerequisite_receipt_base64` set. The workflow requires the existing `production-normal-deploy` approval and rejects an expired receipt or any later main advance.

Do not rerun an ambiguous executor failure. After separate authorization, reconcile the durable catalogue first with the fixed source-owned read-only entry point:

```sh
node scripts/aws/probe-production-b01-prerequisite.mjs \
  --deployment-source-sha "$(git rev-parse HEAD)" \
  --aws-profile <approved-root-profile>
```

The registered task definition fixes the read-only command; RunTask supplies no overrides. The process executes the same canonical collector and classifier as the mutation executor inside one PostgreSQL `READ ONLY` transaction, reports only `PREDECESSOR`, `SUCCESSOR`, `PARTIAL`, or `UNKNOWN` plus bounded identities/invariants, and exits without a mutation path.
