# Green backend recovery role handoff

The green candidate backend recovery uses the existing Release Gate and its S3
coordinator journal. The `production` job authenticates the source, image,
database, runtime and operator approval. It registers the exact candidate under
the release-deployer role, then records an immutable handoff under the journal's
`green-backend-recovery/prepare/` prefix. It does **not** claim or call
`ecs:UpdateService`.

The dependent `production-normal-deploy` job assumes the existing normal-deployer
role through that environment's OIDC trust. It authenticates the handoff and
the completed task registration, rechecks live ECS and component state, and
claims `BACKEND:UPDATE:DISPATCH` under the same journal's `execute/` prefix
immediately before the single native service update. A lost update response is
reconciled against the exact live service; an unresolved outcome blocks replay.
Smoke verification precedes the final component-state compare-and-swap.

The normal role gains `s3:GetObject` on this recovery prefix, scoped
`s3:ListBucket`, and conditional `s3:PutObject` only on `execute/`. It cannot
write `prepare/`. Existing OIDC trust and ECS grants remain unchanged. The
reviewed policy lives in
`infra/aws/terraform/production-component-deployment-state/normal-deployer-policy.json`;
the existing guarded normal-deployer policy convergence installs it after
separate production authorization. The Terraform component-state module does
not itself write IAM documents.

The denied update from run 40227843406 used the earlier flat journal key.
Its dispatch is never replayed. Task definition `:35` belongs to the earlier
source and authorization. A successor release may reuse a completed
registration only if its exact source, image, candidate fingerprint and durable
registration receipt match; otherwise preparation registers a new revision.

Before any successor dispatch, authenticate protected main, a new source-bound
ticket and image, current runtime evidence, fresh six-domain database verdict,
fresh operator approval, exact ECS predecessor, and the normal role's live IAM
policy. If either protected environment approval is delayed until evidence
expires, stop and renew only that evidence through its authorized producer.
After the reviewed policy is installed, use the governed Release Gate
`backend-health-recovery` mode; do not use a direct ECS CLI update.
