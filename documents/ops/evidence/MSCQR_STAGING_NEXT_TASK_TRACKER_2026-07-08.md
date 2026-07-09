# MSCQR Staging Next Task Tracker

Date: 2026-07-08  
Scope: staging only  

## Completed

| Step | Status |
|---|---|
| 1. Staging runtime secrets sync | Complete |
| 2. Staging smoke test | Complete |

## Evidence Stored

Evidence document:

    documents/ops/evidence/MSCQR_STAGING_RUNTIME_SECRETS_AND_SMOKE_TEST_EVIDENCE_2026-07-08.md

## Next Task

The next task is:

    3. RLS validation on staging

Safe RLS candidate endpoints:

    GET /api/qr/batches
    GET /api/qr/batches/:id/allocation-map
    GET /api/manufacturer/printers

## Do Not Start Yet

Do not start these until RLS validation is planned and explicitly approved:

    4. Staging hardening PR
    5. Production RLS rollout plan

## Hardening Backlog Captured During Smoke Test

| Item | Reason |
|---|---|
| Redis AUTH/TLS | Redis AUTH is false and transit encryption is false |
| RDS encryption posture | Needs separate review before long-lived or shared staging |
| ECS outbound tightening | Temporary outbound is currently expected |
| SMTP setup | Emails will fail until SMTP secrets are configured |
| Release metadata | gitSha is currently unknown in staging health response |
