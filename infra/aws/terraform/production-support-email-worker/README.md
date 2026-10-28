# Production support email worker

This root owns only the support email worker task, ECS service, and the execution
role's permission to read the existing SMTP secret. It reuses the Stage B worker
task template, cluster, roles, log group, private subnets, and application security
group. The service starts with `desired_count = 0`; a running task can send
already queued customer email.

Before planning or activation:

1. Verify the current protected-main SHA and the worker publisher's successful
   exact-head run. Set `source_sha` to that SHA and `worker_image` to the immutable
   ECR digest published by that run.
2. Verify the image with the existing `scripts/aws/verify-release-artifacts.sh`
   using `COSIGN_CERT_IDENTITY_REGEXP` for
   `publish-ecs-images.yml@refs/heads/main`. Check the provenance predicate's
   source SHA and image digest against the two Terraform inputs.
3. Authenticate the live B03 catalogue and worker role grants through the
   governed read-only probe. Confirm SMTP configuration and network egress
   without reading the secret value.
4. Use a reviewed Terraform plan with this root's remote state lock. Inspect
   the saved plan before applying. Keep count zero
   until the B03 functions, queued-email safety, and runtime source are verified.

The execution role gains only `secretsmanager:GetSecretValue` on the existing
SMTP password secret. The task role and its database identity are unchanged.
Activation with count one starts only the support response email outbox loop;
other background workers stay inactive.
