# Production Green Stage B infrastructure runbook

1. Obtain an MFA-backed non-root production release-deployer session and initialise the dedicated encrypted S3 backend with `use_lockfile=true`; select workspace `production`.
2. Build the reviewed broker package with `node scripts/aws/package-production-green-stage-b-broker.mjs`. Put its absolute path plus only Stage A output IDs/ARNs, approved secret ARNs, release/package digests, and approved image digests in an untracked tfvars file.
3. Run the plan wrapper. Approve only create/update operations for Stage B task definitions, roles/policies, log groups, task SG, replay table, broker/version/alias, and the alias-qualified Lambda permission. Reject all destroys and all service, traffic, database, secret-value, or tag image changes.
4. After explicit change approval, apply the reviewed saved plan. Verify task-definition revisions, role ARNs, log groups, SG bindings, replay table, broker `reviewed` alias, secret references by ARN only, and exact image digests. Do not run a task or update a service.
5. Infrastructure rollback is limited to a separately reviewed Terraform change that removes only unused Stage B control-plane resources; never destroy a live task definition, secret, database, or service as rollback.
