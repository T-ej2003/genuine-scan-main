# MSCQR Staging Smoke Test Runbook

Date: 2026-07-08
Scope: read-only staging smoke evidence after the first healthy ECS deployment.

This runbook does not authorize Terraform apply, AWS mutation, deployment,
production database access, production/global/table RLS enablement, runtime
secret rotation, or manual AWS Console edits.

Use a staging-only AWS profile and region:

```sh
set +x
export AWS_PROFILE="<staging-provisioning-or-readonly-profile>"
export AWS_REGION="eu-west-2"
export MSCQR_STAGING_ALB_HEALTH_URL="http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health"
```

Never use `mscqr.com`, `www.mscqr.com`, production DBs, production Redis, or
production Secrets Manager values for staging smoke evidence.

## 1. Confirm AWS Identity

```sh
npm run check:staging-aws-identity
```

Expected: JSON with `allowed: true`, `region: "eu-west-2"`, and a
staging/provisioning role classification. Root, production-looking, non-role,
wrong-account, and wrong-region identities must stop the run.

## 2. ECS Service Steady State

```sh
aws ecs describe-services \
  --region "$AWS_REGION" \
  --cluster mscqr-staging-euw2-main \
  --services mscqr-staging-backend-service-euw2 \
  --query 'services[0].{status:status,desired:desiredCount,running:runningCount,pending:pendingCount,rollout:deployments[0].rolloutState,taskDefinition:taskDefinition}' \
  --output json
```

Expected for the current baseline: `status` is `ACTIVE`, desired is `1`,
running is `1`, pending is `0`, and rollout is stable.

## 3. Target Health

```sh
TARGET_GROUP_ARN="$(aws elbv2 describe-target-groups \
  --region "$AWS_REGION" \
  --names mscqr-stg-backend-tg-euw2 \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text)"

aws elbv2 describe-target-health \
  --region "$AWS_REGION" \
  --target-group-arn "$TARGET_GROUP_ARN" \
  --query 'TargetHealthDescriptions[].{target:Target.Id,port:Target.Port,state:TargetHealth.State,reason:TargetHealth.Reason}' \
  --output json
```

Expected: at least one target is `healthy` on port `4000`. Record any
`draining` targets during deployments; they should clear after rollout.

## 4. ALB Health

```sh
curl -fsS "$MSCQR_STAGING_ALB_HEALTH_URL"
```

Expected current payload:

```json
{"status":"ok","release":{"name":"mscqr-backend","version":"1.0.0","gitSha":"unknown","shortGitSha":"unknown","environment":"staging"}}
```

`gitSha: "unknown"` is an accepted current staging gap, not the target state.
Future staging deploys should expose the immutable commit SHA in this payload.

## 5. Recent Backend Logs

```sh
aws logs tail /ecs/mscqr-staging-backend \
  --region "$AWS_REGION" \
  --since 30m \
  --format short
```

Evidence rules:

- Do not paste credentials, tokens, full `DATABASE_URL`, full `REDIS_URL`, raw
  Secrets Manager values, private subnet IDs, private security group IDs, or
  Terraform state into documents or tickets.
- If logs contain secret-shaped values, stop and open a redaction bug before
  sharing evidence.

## 6. Runtime Secret Sync Dry Run

```sh
npm run check:staging-runtime-secret-sync
```

Expected: safe JSON only, `validationOnly: true`, `mutatesAws: false`, and
redacted URL previews. This does not rotate or update staging secrets.

## 7. Remote Terraform Zero-Diff Check

Generate plan evidence only through the wrapper:

```sh
set +x
MSCQR_STAGING_TERRAFORM_PLAN_ENABLED=true \
MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM=MSCQR_GENERATE_STAGING_PLAN_ONLY \
npm run plan:staging-terraform
```

Then check the generated redacted summary:

```sh
npm run check:staging-private-inputs -- --strict
node scripts/check-staging-terraform-drift-summary.mjs ".terraform-plans/staging/<summary>.summary.json"
```

Expected after remote state migration: add `0`, change `0`, destroy `0`.
Plan binaries, text plans, private tfvars, state backups, and `.terraform/`
directories must remain ignored and uncommitted.

## 8. Hardening Posture Check

```sh
npm run check:staging-hardening-posture -- --alb-health-url "$MSCQR_STAGING_ALB_HEALTH_URL"
```

Expected current staging gaps:

- `redis_transit_encryption_disabled`
- `redis_auth_not_configured`
- `rds_storage_unencrypted`
- `ecs_temporary_world_open_egress`
- `alb_http_only`

Expected current risk level:

```json
"riskLevel": "needs-hardening-before-shared-use"
```

This check is read-only. It must print `rawSecretValuesPrinted: false` and
`mutatesAws: false`.

## 9. Evidence Packet

For each smoke-test pass, keep a short evidence note with:

- UTC timestamp and operator.
- AWS profile alias only, not access keys or credentials.
- ECS service steady-state JSON.
- Target-health JSON.
- ALB `/health` status and sanitized payload.
- Backend log summary with no raw secrets.
- Runtime secret sync dry-run status.
- Terraform zero-diff summary status.
- Hardening posture check status and gap codes.

## CTO Recommendations

- Make this runbook the preflight and postflight for every staging hardening
  change. That gives the team a consistent regression signal as infrastructure
  moves from launch posture to shared-use posture.
- Promote the hardening posture checker into scheduled read-only CI once AWS
  OIDC credentials are stable. Human-only smoke evidence is useful, but
  scheduled drift detection scales better.
- Fix release metadata before using staging for broader acceptance testing.
  Unknown commit evidence slows incident response and rollback decisions.
