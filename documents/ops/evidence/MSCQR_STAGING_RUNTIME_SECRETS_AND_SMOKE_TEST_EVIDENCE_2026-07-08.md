# MSCQR Staging Runtime Secrets Sync and Smoke Test Evidence

Date: 2026-07-08  
Environment: staging  
AWS region: eu-west-2  
Scope: staging only  
Production impact: none  

## 1. Summary

MSCQR staging runtime secrets were synced from the staging RDS and Redis/Valkey endpoints.

After the secret sync, the staging ECS backend service was force redeployed. The backend then passed smoke testing through the staging ALB.

This evidence is staging-only. It does not validate production and does not enable RLS.

## 2. Pass/Fail Summary

| Check | Result |
|---|---|
| Runtime secret sync dry run | Passed |
| DATABASE_URL secret updated | Passed |
| REDIS_URL secret updated | Passed |
| Raw secrets printed | No |
| ECS forced redeploy | Passed |
| ECS service stable | Passed |
| ALB target health | Passed |
| Public health endpoint | Passed |
| Backend CloudWatch logs | Passed |
| Production DB used | No |
| Terraform apply run | No |
| RLS enabled | No |

## 3. Runtime Secrets Sync Evidence

Secrets updated:

| Secret | Status |
|---|---|
| mscqr/staging/database-url | Updated |
| mscqr/staging/redis-url | Updated |

Database evidence:

| Field | Value |
|---|---|
| DB identifier | mscqr-staging-db |
| DB host | mscqr-staging-db.c3ewey6o6mq5.eu-west-2.rds.amazonaws.com |
| DB port | 5432 |
| DB name | mscqr_staging |
| DB username | mscqr_staging_admin |
| Password source | rds-managed-master-user-secret |
| SSL mode | require |

Redis/Valkey evidence:

| Field | Value |
|---|---|
| Replication group | mscqr-staging-redis-euw2 |
| Host | mscqr-staging-redis-euw2.mwntvg.ng.0001.euw2.cache.amazonaws.com |
| Port | 6379 |
| Redis AUTH configured | false |
| Transit encryption | Follow-up hardening item |

Secret safety:

| Check | Result |
|---|---|
| Full DATABASE_URL printed | No |
| Full REDIS_URL printed | No |
| Passwords printed | No |
| Token/secret strings printed | No |

## 4. ECS Redeploy Evidence

Cluster: mscqr-staging-euw2-main  
Service: mscqr-staging-backend-service-euw2  

Final ECS service state:

| Field | Value |
|---|---|
| Status | ACTIVE |
| Desired | 1 |
| Running | 1 |
| Pending | 0 |
| Task definition | arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-backend:1 |

Deployment evidence:

- Service reached steady state.
- Deployment completed.
- Old task drained and stopped.
- New running task remained healthy.

## 5. ALB Target Health Evidence

Initial target health after redeploy:

| Target | Port | State | Reason |
|---|---:|---|---|
| 10.0.144.65 | 4000 | healthy | none |
| 10.0.165.11 | 4000 | draining | Target.DeregistrationInProgress |

Final target health:

| Target | Port | State | Reason |
|---|---:|---|---|
| 10.0.144.65 | 4000 | healthy | none |

Result: passed.

## 6. Public Health Endpoint Evidence

Command used:

    curl -i http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health

Result:

    HTTP/1.1 200 OK

Response body:

    {
      "status": "ok",
      "timestamp": "2026-07-08T22:05:15.072Z",
      "release": {
        "name": "mscqr-backend",
        "version": "1.0.0",
        "gitSha": "unknown",
        "shortGitSha": "unknown",
        "environment": "staging"
      }
    }

Observed security headers:

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: no-referrer
- X-Permitted-Cross-Domain-Policies: none
- Permissions-Policy: geolocation=(), camera=(), microphone=()
- Cross-Origin-Opener-Policy: same-origin
- Cross-Origin-Resource-Policy: same-site
- RateLimit headers present

Result: passed.

## 7. CloudWatch Log Evidence

Log group:

    /ecs/mscqr-staging-backend

Observed startup evidence:

- Server running on http://localhost:4000
- API available at http://localhost:4000/api
- Health check at http://localhost:4000/health
- Latency summary at http://localhost:4000/health/latency
- Background workers disabled for this HTTP process

Observed QR signing evidence:

- QR signing profile ready
- mode: ed25519
- provider: env
- legacyHmacFallback: false

Observed health log pattern:

- method: GET
- path: /health/live
- status: 200
- release: mscqr-backend@1.0.0

Result: passed.

## 8. Non-Blocking Findings

| Finding | Severity | Follow-up |
|---|---:|---|
| Redis AUTH is not configured | Medium | Redis AUTH/TLS hardening |
| Redis transit encryption is not enabled | Medium | Redis AUTH/TLS hardening |
| SMTP is not configured | Medium | Configure staging SMTP or explicitly disable email flows in staging |
| Release gitSha is unknown | Low | Fix release metadata injection in ECS task definition or build pipeline |

## 9. Commands Used

Runtime secret dry run:

    npm run check:staging-runtime-secret-sync

Runtime secret sync:

    MSCQR_STAGING_SECRET_SYNC_ENABLED=true \
    MSCQR_STAGING_SECRET_SYNC_CONFIRM=MSCQR_UPDATE_STAGING_RUNTIME_SECRETS \
    node scripts/sync-staging-runtime-secrets.mjs --sync-secrets

ECS redeploy:

    MSCQR_STAGING_ECS_REDEPLOY_ENABLED=true \
    MSCQR_STAGING_ECS_REDEPLOY_CONFIRM=MSCQR_FORCE_STAGING_ECS_REDEPLOY \
    node scripts/sync-staging-runtime-secrets.mjs --force-ecs-redeploy

Wait for service stable:

    aws ecs wait services-stable \
      --cluster mscqr-staging-euw2-main \
      --services mscqr-staging-backend-service-euw2

Check ECS service:

    aws ecs describe-services \
      --cluster mscqr-staging-euw2-main \
      --services mscqr-staging-backend-service-euw2 \
      --query 'services[0].{Status:status,Desired:desiredCount,Running:runningCount,Pending:pendingCount,TaskDefinition:taskDefinition,Events:events[0:5].message}' \
      --output json

Check target health:

    aws elbv2 describe-target-health \
      --target-group-arn arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-stg-backend-tg-euw2/a877f5fab1abba80 \
      --query 'TargetHealthDescriptions[].{Target:Target.Id,Port:Target.Port,State:TargetHealth.State,Reason:TargetHealth.Reason}' \
      --output json

Check public health endpoint:

    curl -i http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health

Tail backend logs:

    aws logs tail /ecs/mscqr-staging-backend \
      --since 20m \
      --format short

## 10. Conclusion

Staging runtime secret sync and smoke testing passed.

The staging backend is reachable through the ALB, target health is clean, ECS is stable, and CloudWatch logs show successful health checks.

This does not approve production rollout. The next planned task is staging RLS validation planning.
