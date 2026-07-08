# MSCQR Staging Redis AUTH and TLS Hardening Plan

Date: 2026-07-08
Scope: non-mutating follow-up plan for staging Valkey/Redis AUTH and in-transit
TLS after Terraform remote state is migrated and verified.

This hardening is intentionally not applied in PR #105. PR #105 must preserve a
zero-diff Terraform plan after state migration. Changing the ElastiCache
replication group now would mix app-resource mutation with state migration and
could make the required `add=0`, `change=0`, `destroy=0` verification
impossible to interpret.

## Required Design

- Enable in-transit encryption for `aws_elasticache_replication_group.staging`.
- Use Redis AUTH or Valkey ACL users without committing the auth token.
- Store the runtime Redis URL only in `mscqr/staging/redis-url`.
- Use `rediss://` once TLS is enabled.
- Confirm the backend Redis client validates TLS settings through environment
  configuration before the Terraform change is applied.
- Generate a human-reviewed plan that has no destroy actions and explicitly
  documents whether ElastiCache can update in place or requires replacement.

## State-Safety Requirement

Terraform state may contain sensitive ElastiCache auth material if `auth_token`
is passed directly to Terraform. Prefer an AWS-managed secret or user-group
pattern that avoids putting long-lived Redis credentials into Terraform state.
If Terraform must manage a token, treat the remote state bucket as sensitive
credential-bearing infrastructure and require additional access review before
the change.

## Readiness Gate

Do not mark staging long-lived or shared until:

- remote Terraform state migration is complete;
- a fresh post-migration plan shows `add=0`, `change=0`, `destroy=0`;
- CloudTrail data event audit coverage exists for the state bucket;
- Redis AUTH/TLS design has a reviewed rollback path;
- a separate PR implements the Redis change with targeted tests and a reviewed
  plan.
