# MSCQR Staging Security Hardening Backlog

Date: 2026-07-08
Scope: staging-only hardening plan and non-mutating evidence checks after the
first healthy staging API launch.

This document does not authorize Terraform apply, AWS mutation, deployment,
production database access, production/global/table RLS enablement, runtime
secret rotation, or manual console edits.

## Current Baseline

- ECS service `mscqr-staging-backend-service-euw2` is active with desired `1`,
  running `1`, and pending `0`.
- Staging target group has a healthy backend target on port `4000`.
- ALB health endpoint currently returns HTTP `200` at
  `http://mscqr-stg-alb-euw2-1729860344.eu-west-2.elb.amazonaws.com/health`.
- Health payload currently reports `environment: staging`, but release
  `gitSha` and `shortGitSha` are `unknown`.
- Staging runtime `DATABASE_URL` and `REDIS_URL` Secrets Manager values were
  synced from RDS and Redis endpoints, and ECS was redeployed after sync.
- Terraform state is on the staging S3 backend with S3 lockfile locking, and
  the latest reviewed plan evidence was zero-diff.
- Redis/Valkey currently has `TransitEncryptionEnabled=false`,
  `AtRestEncryptionEnabled=true`, and no detected AUTH.
- RDS currently has `StorageEncrypted=false`.
- ECS currently has temporary outbound `0.0.0.0/0`.

Production impact: none. These checks and docs are staging-only and do not
touch production resources.

## Immediate No-Risk Work

Implemented now:

- Add `scripts/check-staging-hardening-posture.mjs` as a read-only JSON posture
  checker.
- Add `npm run check:staging-hardening-posture`.
- Add tests that prove staging identity/profile guards, secret redaction,
  expected current hardening gaps, JSON output shape, and no AWS mutation calls.
- Document the smoke-test evidence set required while hardening work remains
  open.

The posture checker reads AWS state only. It uses `sts:GetCallerIdentity`,
`Describe*` style calls, `secretsmanager:GetSecretValue` for the staging Redis
URL shape only, and an optional HTTP GET to the reviewed staging ALB health URL.
It never prints secret values.

## Redis AUTH/TLS Hardening

Current gap:

- `TransitEncryptionEnabled=false`.
- Redis AUTH is not detected from the replication group configuration or the
  staging `mscqr/staging/redis-url` shape.

Required future state:

- In-transit encryption enabled.
- Runtime URL uses `rediss://`.
- AUTH or Valkey ACL user group configured without committing auth material.
- Backend Redis client has an explicit TLS mode validation path.
- Separate Terraform plan proves whether the change is in-place or replacement.

Do not apply this in the current PR. ElastiCache encryption/auth changes can be
replacement-sensitive, and auth tokens can become Terraform-state-sensitive if
managed directly. Use
`documents/ops/MSCQR_STAGING_REDIS_AUTH_TLS_HARDENING_PLAN_2026-07-08.md` as the
specific design starting point.

## RDS Encryption Posture

Current gap:

- `StorageEncrypted=false`.

Required future state:

- Encrypted staging database storage.
- Snapshot/restore or blue-green cutover plan reviewed before implementation.
- Clear rollback and data-copy validation evidence.

Do not toggle this directly on the existing instance. For RDS, storage
encryption is usually handled through snapshot restore or replacement-style
flows. Treat the future work as a controlled data migration, not a small inline
Terraform edit.

## ECS Outbound Tightening

Current gap:

- ECS security group has temporary egress to `0.0.0.0/0`.

Required future state:

- Preserve service health while replacing broad egress with explicit routes.
- Prefer VPC endpoints for ECR API, ECR Docker, Secrets Manager, CloudWatch
  Logs, STS, SSM Messages, KMS, and S3 where practical.
- Where endpoints are not enough, constrain outbound through NAT-specific
  routes, prefix lists, or reviewed CIDRs.
- Keep DB and Redis paths security-group-referenced, not world-routed.

Do not remove the broad egress until the endpoint/NAT path is proven with an
ECS deployment, backend logs, and `/health` evidence. Breaking ECR, Secrets
Manager, or CloudWatch Logs access can leave staging unable to start or prove
itself healthy.

## ALB HTTPS/TLS Listener

Current gap:

- Staging ALB is HTTP-only.

Required future state:

- ACM certificate for the reviewed staging hostname.
- HTTPS listener on `443`.
- HTTP listener redirects to HTTPS once smoke tests confirm the redirect path.
- Operator CIDR restrictions remain in place until a public staging policy is
  intentionally approved.

Do not point staging evidence at `mscqr.com` or `www.mscqr.com`. Those are
production hostnames.

## Release Metadata Fix

Current gap:

- Health payload reports `gitSha: "unknown"` and `shortGitSha: "unknown"`.

Required future state:

- Backend image build passes immutable git SHA metadata into the runtime.
- `/health` and release smoke evidence expose the deployed commit without
  exposing secrets or private infrastructure values.
- CI should fail when a staging image intended for deployment lacks release
  metadata.

This is operationally important because hardening evidence should identify the
exact deployed build, not just the service state.

## CloudWatch Alarms and Log Retention

Current posture:

- Backend and ECS Exec log groups have Terraform-managed retention settings.

Required future alarms:

- ALB target group unhealthy host count.
- ECS service running count below desired count.
- ECS deployment rollback or circuit breaker events.
- Backend log error-rate signal.
- RDS CPU, storage, connection count, and freeable memory.
- Redis CPU, memory pressure, evictions, and connection count.

Required future evidence:

- Alarm ARNs and thresholds are documented.
- Log retention remains finite and staging-specific.
- No alarm routes notify production incident channels unless explicitly
  approved.

## Staged Smoke-Test Evidence Requirements

For every hardening step, collect evidence before and after the change:

- ECS service steady state: desired, running, pending, rollout state.
- Target health: healthy and draining target counts.
- ALB `/health` HTTP status and sanitized payload.
- Recent backend logs without raw credentials, tokens, or service URLs.
- Runtime secret sync dry-run evidence with redacted URL previews.
- Remote Terraform zero-diff plan summary before the next mutation window.
- `npm run check:staging-hardening-posture` JSON output.

Keep plan files, state files, private tfvars, credentials, and ignored backup
artifacts out of git.

## Manual AWS Console Warnings

Do not make manual AWS Console changes for these items:

- Do not enable Redis TLS/AUTH in the console.
- Do not modify the RDS instance encryption posture in the console.
- Do not delete or tighten ECS egress in the console.
- Do not add ALB HTTPS listeners, certificates, or redirect rules in the
  console.
- Do not rotate or edit `mscqr/staging/database-url` or
  `mscqr/staging/redis-url` manually.
- Do not edit Terraform-managed security groups, target groups, ECS services,
  RDS, Redis, ALB, IAM roles, KMS keys, log groups, or S3 buckets manually.

Any manual console drift must be treated as an incident for the staging
Terraform control plane. Record it, stop applies, and reconcile through a
reviewed plan.

## Future Implementation Order

1. Keep smoke testing running and collect posture evidence.
2. Fix release metadata so health evidence carries a real git SHA.
3. Add CloudWatch alarms for health and rollback detection.
4. Add ALB HTTPS on a staging hostname and confirm `/health` over TLS.
5. Design Redis AUTH/TLS with no committed token and no unreviewed state-secret
   exposure.
6. Plan RDS encrypted replacement or snapshot/restore as a data migration.
7. Replace ECS broad egress after endpoint/NAT dependencies are proven.

## CTO Recommendations

- Treat staging as a rehearsal for production change control: every hardening
  step should have before/after evidence, rollback criteria, and a zero-diff
  Terraform baseline before the next step begins.
- Prioritize release metadata and alarms before replacement-sensitive
  infrastructure changes. Without observability, the team cannot safely
  distinguish a good hardening rollout from a silent service regression.
- For scalability, prefer private AWS service endpoints and explicit egress
  contracts over broad NAT egress. That makes future multi-environment
  deployments easier to audit and cheaper to reason about.
- Keep Redis auth material out of Terraform code and avoid putting long-lived
  secrets into Terraform state unless state access has been reviewed as
  credential-bearing access.
- Handle RDS encryption through a migration-grade plan with backup, restore,
  validation, and cutover evidence. Do not treat it as a simple flag flip on a
  live database.
