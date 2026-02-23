# Rollback Runbook

Use this when a production deployment introduces regressions, outages, or security concerns.

## Immediate actions
1. Pause further rollouts.
2. Capture logs and incident notes.
3. Identify last known good release (commit SHA or image tag).

## Rollback options

### Option A: Container/image rollback (preferred)
1. Re-deploy the prior image tag used in production.
2. Confirm the rollback is active by hitting `/version` and checking the `gitSha`.

### Option B: Git revert and redeploy
1. Revert the release commit(s) on `main`.
2. Re-run the deployment pipeline.
3. Confirm `/version` reports the previous `gitSha`.

## Database considerations
- If new migrations are not backwards compatible, restore from backup or apply a corrective migration.
- Validate core queries (login, scan, audit log retrieval) after rollback.

## Verification checklist
- `/healthz` returns `status: ok`.
- `/health/db` returns `database: reachable`.
- Auth flows, scan endpoints, and admin dashboards load without errors.
- Error logs are stable (no new spikes).
