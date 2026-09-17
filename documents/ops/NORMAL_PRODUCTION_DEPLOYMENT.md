# Normal production deployment

Routine application releases use .github/workflows/production-deploy.yml.
Merging a reviewed change to main starts the workflow; the protected
production environment supplies the required approval, GitHub OIDC supplies
the fixed deployer session, and the workflow classifies, publishes immutable
SHA-tagged images, deploys affected ECS services, waits for stable healthy
tasks, and runs the authenticated application smoke suite inside each
affected service's rollback boundary.

The workflow is intentionally limited to NORMAL_APPLICATION changes. Its
classification is derived from the changed paths in the protected-main
commit. IAM, RLS, network, KMS, authentication, migration, recovery, and
ambiguous changes fail closed and remain on the stronger reviewed
SECURITY_INFRASTRUCTURE or EMERGENCY_RECOVERY lanes. A caller cannot
select a release class.

Backend and frontend deployment use fixed account, region, cluster, service,
family, task-role, execution-role, and container contracts. Images are
referenced by the digest returned by the immutable ECR publication step.
Predecessor capture and ECS service CAS prevent deploying over concurrent
state. A failed service rollout, health gate, or authenticated smoke gate rolls
that service back to the exact captured predecessor; the ECS deployment
circuit-breaker remains the last-resort service rollback boundary.

Compatible database migrations and function changes are not currently in the
normal lane: they are classified as infrastructure/security work and must use
the governed database release path before dependent application activation.
For G06 this includes printing_readiness, printing_create_job, and
printing_connector_identity.

The worker service remains absent by reviewed production topology. Worker
changes are not silently deployed as backend changes; they fail closed to the
infrastructure lane until a worker service contract exists.

The older Stage-B evidence, KMS, and recovery machinery remains available for
security/infrastructure and emergency/recovery operations. It is not required
for an ordinary application release. No production credentials, image tags,
task definitions, rollback targets, or evidence documents are supplied by a
caller.

Required production environment values for the authenticated smoke are the
PRODUCTION_SMOKE_LOGIN_EMAIL, PRODUCTION_SMOKE_LOGIN_PASSWORD, and
reviewed MFA/verification secrets. Missing smoke credentials fail the release
gate; they are never replaced by a degraded or unauthenticated result.

## Operator procedure

1. Merge the reviewed application PR to main.
2. Approve the protected production environment if GitHub requests it.
3. Monitor Normal Production Deployment.
4. Treat a failed classification or gate as a routed security/recovery
   operation, not as permission to edit the normal workflow inputs.
5. Confirm the workflow's deployment, health, smoke, and rollback results.

No Codex session, hand-built evidence JSON, manual digest copying, temporary
DBA task, Stage-B recovery authorization, or physical printer acceptance is
part of this routine path. Physical printer acceptance remains a separate
post-release G06 acceptance test.
