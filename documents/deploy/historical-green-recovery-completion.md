# Historical green backend recovery completion

## Scope

This continuation closes an existing, successfully executed green backend recovery. It never registers a task definition, starts a task, claims a new ECS dispatch, or calls `ecs:UpdateService`. The original S3 operation ID is the transaction key. The only permitted production writes are the existing conditional S3 update/recovery completion records and the existing DynamoDB component-state compare-and-swap.

For incident `CHG-20261025-008`, the original Release Gate run `40248378928` on source `d785aa7f1e154f37c0dc621082e3f6c46d5d5aec` claimed operation `10d4eb81a0b0ff5f1858bba685d01c41bf0f3826b28b3c67b84279a1896152c8`. CloudTrail event `af14fafb-126c-468b-9dee-616c955a0f1b` records the successful update to task definition `:37`. The protected-main merge after the update prevents the ordinary outage lane from closing that historical claim.

## Governed entry point

After merge and a separately authorized Terraform policy convergence, dispatch `.github/workflows/complete-historical-green-backend-recovery.yml` on protected `main` with the original operation, run, source, ticket, predecessor/target ARNs, digest, CloudTrail event and component generation. The `production-normal-deploy` environment requires a fresh actual GitHub reviewer approval. Its OIDC identity assumes the existing normal-deployer role. Do not dispatch the ordinary backend-health-recovery Release Gate again.

The normal-deployer policy adds only regional `cloudtrail:LookupEvents` read access. Its existing exact-prefix S3 conditional write, ECS readback, ALB readback and exact-key DynamoDB CAS permissions remain unchanged. No IAM apply is part of this PR; live policy must match the reviewed source before the completion command can run.

This workflow joins the shared `production-deploy` concurrency group with cancellation disabled. It cannot overlap a Release Gate or web activation run. The command also rechecks the exact deployment ID, service configuration, task and ALB health, public readiness, approval, and component predecessor immediately before the DynamoDB CAS. External AWS principals are outside GitHub's concurrency lock, so there is no atomic transaction spanning ECS and DynamoDB; a drift readback fails closed.

## Verification and transaction sequence

1. Authenticate current protected main and prove the original source is its ancestor. Authenticate the original GitHub run and exact operation identity.
2. Read the original S3 predecessor, registration, signed handoff, UpdateService intent/dispatch and both historical phase authorization records. Verify their original source, image, ticket, run, task definition, component generation and S3 commit-time relationships. Reauthenticate the signed image and six-domain database artifact **at each original dispatch time**.
3. After fresh protected-environment approval, verify the actual normal-deployer principal and exact live IAM policy. Bind the CloudTrail event to the S3 dispatch window, role, ECS cluster/service, target task definition and live deployment ID.
4. Read the current service, task definition, two healthy tasks, exact image digest, two healthy ALB targets, public readiness, database readiness and generation-1 predecessor component state.
5. Reuse `journalEcsServiceUpdate` only on its previously claimed target branch. The supplied update callback throws unconditionally. The existing journal writes or adopts the exact native update completion with conditional S3 semantics.
6. Recheck live health and component state, then write or adopt the existing recovery completion schema with the actual reconciliation time. The S3 object commit time provides the native completion-record timestamp. Do not backdate either record.
7. Recheck health and fresh approval immediately before the existing DynamoDB CAS. The existing component commit authenticates the S3 records and live ECS snapshot, then conditionally advances generation 1 to 2. Readback must match the exact task definition, digest and source. A lost response is handled by re-reading the exact journal and component state on a later approved continuation.

A missing or conflicting S3 claim, unrelated CloudTrail event, service drift, unhealthy task/ALB, stale approval, or changed component predecessor stops before any new completion write. Two concurrent continuations can race on an immutable S3 completion; the loser fails closed and may authenticate the winner's exact result on a later run. The original historical authorization is evaluated at its S3 dispatch time; current health and the fresh independent approval are evaluated at continuation time.

## Operational limit

CloudTrail event-history lookup and GitHub artifact retention are time bounded. If either original source of evidence is unavailable, this workflow fails closed; it does not infer success from current ECS task counts. The work remains a journal/component-state reconciliation until a governed evidence-preserving alternative is reviewed. Production execution is intentionally outside this PR.
