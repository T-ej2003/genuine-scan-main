# MSCQR Staging Health Dashboard Plan

Date: 2026-07-02
Scope: plan-only staging dashboard and alarm design for the staging API stack.

This document defines the observability baseline required before staging scale tests or repeated ECS Exec usage. It does not create dashboards, alarms, deployments, or AWS resources.

## Objectives

- Prove that the staging API can be operated without shell-first debugging.
- Detect infrastructure, application, and security regressions before route-by-route RLS rollout expands.
- Keep the dashboard public-safe by documenting metric classes and thresholds without exposing private topology or secret values.
- Make every future staging apply easier to review by tying metrics to rollback and approval gates.

## Proposed Dashboard Sections

### ALB

- Metric: `HTTPCode_ELB_5XX_Count`
  - Alarm: any sustained non-zero value over 5 minutes.
  - Action: stop rollout, review target health and backend logs.
- Metric: `HTTPCode_Target_5XX_Count`
  - Alarm: more than a low single-digit count over 5 minutes during validation.
  - Action: compare with backend error logs and RLS collector results.
- Metric: `HTTPCode_Target_4XX_Count`
  - Alarm: unusual increase versus validation baseline.
  - Action: inspect auth, CIDR, collector configuration, and route flags.
- Metric: `HealthyHostCount` and `UnHealthyHostCount`
  - Alarm: healthy hosts below desired running task count, or any unhealthy host sustained over 2 checks.
  - Action: block scale test and inspect ECS service events.
- Metric: `TargetResponseTime`
  - Alarm: p95 above the approved staging threshold for 10 minutes.
  - Action: compare backend health latency, RDS CPU/connections, and Redis metrics.

### ECS Service

- Metric: desired task count versus running task count.
  - Alarm: running tasks below desired tasks for more than one deployment interval.
  - Action: review ECS events, image pull errors, security group reachability, and task health.
- Metric: task stop count and restart frequency.
  - Alarm: more than one unexpected stop in a validation window.
  - Action: inspect stopped task reason and backend logs.
- Metric: CPU and memory utilization.
  - Alarm: sustained high utilization before scale tests.
  - Action: capture baseline and decide whether task sizing or query tuning is needed.
- Metric: ECS Exec usage events from CloudTrail.
  - Alarm: any `ecs:ExecuteCommand` event without a matching approval ID.
  - Action: security review and access revocation if unapproved.

### Backend Health

- Metric: `/health/live` latency and status.
  - Alarm: non-2xx or latency above staging threshold for 5 minutes.
  - Action: rollback recent infrastructure change or disable staged validation flags.
- Metric: `/health/ready` latency and dependency status when exposed safely.
  - Alarm: dependency failure or high latency.
  - Action: inspect RDS, Redis, and object storage reachability.
- Metric: structured application error count.
  - Alarm: increase during seed or collector runs.
  - Action: attach log excerpts with secrets redacted.

### RDS Postgres

- Metric: CPU utilization.
  - Alarm: sustained high CPU during collector or seed activity.
  - Action: capture query evidence and review RLS/index plan before expanding routes.
- Metric: database connections.
  - Alarm: connection count near configured limit or unexpected spikes.
  - Action: inspect pool settings and task restarts.
- Metric: free storage space.
  - Alarm: below approved staging minimum.
  - Action: stop scale test and review retention/storage settings.
- Metric: freeable memory.
  - Alarm: sustained low memory.
  - Action: review instance class and query shape.
- Metric: read/write latency.
  - Alarm: sustained latency above baseline.
  - Action: compare with RLS collector timing and app logs.

### Redis or Valkey

- Metric: CPU utilization.
  - Alarm: sustained high CPU.
  - Action: inspect session, rate-limit, and cache usage patterns.
- Metric: memory usage percentage and freeable memory.
  - Alarm: memory pressure or unexpected growth.
  - Action: verify TTLs and key cardinality.
- Metric: evictions.
  - Alarm: any eviction during controlled validation.
  - Action: block scale proof until cache sizing or TTL policy is understood.
- Metric: current connections and new connections.
  - Alarm: unexpected spikes.
  - Action: inspect task restarts, client pooling, and connection leaks.

### RLS Collector and Seed Evidence

- Metric: staging RLS collector success/failure count.
  - Source: `scripts/collect-rls-staging-validation-evidence.mjs` evidence output or CI wrapper.
  - Alarm: any failed approved route, host guard failure, redirect warning, or redaction failure.
  - Action: no-go for staged RLS expansion.
- Metric: staging validation seed success/failure.
  - Source: `npm --prefix backend run test:staging-rls-validation-seed` and controlled seed task evidence.
  - Alarm: any failed seed precondition or non-staging guard failure.
  - Action: do not run collector against incomplete fixtures.

### Cost Guardrail

- Metric: estimated monthly staging cost.
  - Source: budget alert or Cost Explorer review.
  - Alarm: forecast above approved monthly staging budget.
  - Action: reduce desired count, pause scale tests, or downsize staging-only resources after evidence is captured.
- Metric: CloudWatch Logs ingestion and retention.
  - Alarm: unexpected ingestion spike after ECS Exec or load testing.
  - Action: review command output and log verbosity.

## Implementation Sequence

1. Add CloudWatch dashboard and alarms only after staging Terraform apply approval based on an attached, human-reviewed plan.
2. Keep dashboard resources in the staging Terraform root or a dedicated observability module with staging-only name guards.
3. Wire CloudTrail `ecs:ExecuteCommand` events to an EventBridge rule and notification target before broadening operator access.
4. Add CI or scheduled evidence collection for the RLS collector and seed script after the staging endpoint exists.
5. Add a monthly budget alarm with a low staging threshold before load or scale testing.

## CTO Recommendations

- Make the dashboard a release gate, not a passive status page. Route-by-route RLS expansion should require green ALB, ECS, RDS, Redis, collector, and seed status.
- Prefer structured custom metrics from the backend for collector and seed outcomes. Log scraping is acceptable for the first pass but becomes brittle as validation grows.
- Add service-level objectives for staging health before production scale proof. Without thresholds, dashboards become screenshots instead of operational controls.
