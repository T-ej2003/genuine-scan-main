# AWS ASG Rolling Deploy Policy

Last updated: 2026-05-15

ASG_STATUS=CONDITIONALLY_READY

This document defines the approved rolling deploy and instance refresh contract for MSCQR ASG web nodes. It does not create ASGs, change Route 53, mutate RDS or application S3 data, or claim that live rollout has already been tested.

## Scope

- Applies only to ASG web nodes running `docker compose -f docker-compose.asg-web.yml up -d --build backend frontend`.
- Applies to Mumbai and Cape Town regional ALB target groups.
- Assumes singleton workers remain outside the web ASG.
- Production DNS must remain on London EC2 during ASG rollout validation.

## Policy Values

Source of truth: `documents/ops/aws-asg-rolling-deploy-policy.checklist.json`

- ALB target group deregistration delay: 60 seconds.
- ASG health check type: `ELB`.
- ASG health check grace period: 180 seconds.
- ASG default instance warmup: 180 seconds.
- Instance refresh minimum healthy percentage: 100.
- Instance refresh maximum healthy percentage if supported: 150.
- Instance refresh checkpoints: 50 percent and 100 percent.
- Instance refresh checkpoint wait: 300 seconds.
- Initial ASG capacity for first production-safe rollout: `min=2 desired=2 max=4`.
- Required healthy target count after ASG apply and after each replacement step: at least 2.

## Required Alarms

Before, during, and after refresh, the following CloudWatch alarms must remain green for the target region:

- ALB 5XX
- target 5XX
- target response time
- unhealthy hosts

The machine-readable policy stores region-specific placeholder names for Mumbai and Cape Town. Before a real apply, operators must provide the reviewed concrete alarm names to the apply path.

## Smoke Tests

Every rollout batch and replacement step must pass:

- `GET /healthz`
- `GET /api/health/ready`
- target group healthy count is at least 2
- ALB 5XX alarm remains `OK`
- target 5XX alarm remains `OK`
- target response time alarm remains `OK`

`/healthz` is shallow liveness only. `/api/health/ready` must confirm `database.ready=true`, `redis.configured=true`, `redis.ready=true`, `objectStorage.configured=true`, and `objectStorage.ready=true`.

## Go/No-Go Checklist

- Production DNS still points to London EC2.
- Regional test hostname is healthy before the rollout starts.
- `node scripts/dr/check-asg-multi-instance-readiness.mjs` passes.
- `scripts/dr/bootstrap-asg-web-node.sh` is the launch-template bootstrap path.
- `RUN_BACKGROUND_WORKERS=false`, `RUN_DB_MIGRATIONS_ON_START=false`, and `COMPLIANCE_PACK_SCHEDULER_ENABLED=false` remain forced.
- Regional Redis and regional S3/default-credential object storage are green through readiness.
- CloudWatch alarms are green before the first attach and before each refresh checkpoint decision.
- The previous launch template version remains available for rollback.

No-go if any required alarm is red, any smoke test fails, or target group healthy count cannot stay at 2 or above.

## Manual Rollback

If rollout health degrades:

1. Stop the rollout by canceling the active instance refresh.
2. Keep production DNS unchanged.
3. Revert the ASG to the previous launch template version if the new launch template is implicated.
4. Restore healthy capacity before terminating or deregistering any new unhealthy instance.
5. Re-run `GET /healthz`, `GET /api/health/ready`, and target-health checks.
6. Capture CloudWatch alarm state, target health, launch template version, and smoke-test evidence.

Rollback criteria:

- any new target fails `/healthz`
- any new target fails `/api/health/ready`
- target group healthy count drops below 2
- ALB 5XX or target 5XX alarms enter `ALARM`
- target response time alarm enters `ALARM`
- operator smoke tests fail on the regional test hostname

## Replacement-Instance Drill

This is the remaining live go/no-go after repo hardening.

1. Create and attach the regional ASG with `min=2 desired=2 max=4` and no production DNS cutover.
2. Wait for at least 2 healthy targets on the regional ALB target group.
3. Run the smoke tests on the regional test hostname:
   `https://dr-mumbai.mscqr.com/healthz` or `https://dr-capetown.mscqr.com/healthz`
   `https://dr-mumbai.mscqr.com/api/health/ready` or `https://dr-capetown.mscqr.com/api/health/ready`
4. Start a one-instance replacement step, either through instance refresh with the documented checkpoints or by a controlled single-instance replacement without decrementing desired capacity.
5. Confirm the new instance reaches healthy target state and both health endpoints pass.
6. Confirm CloudWatch alarms remain green and target response time stays within the approved baseline.
7. Record artifacts under `artifacts/dr/` and link them in the incident or rollout record.

This drill is successful only when healthy target count returns to at least 2 after replacement and no rollback criteria fire.

## Operator Rule

Do not perform production DNS cutover during ASG rollout validation. The purpose of the first ASG rollout is to prove launch-template bootstrap, healthy replacement, and rollback safety behind the regional ALB only.
