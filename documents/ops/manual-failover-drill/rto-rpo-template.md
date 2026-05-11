# Manual Failover RTO/RPO Template

Last updated: 2026-05-11

## Drill Metadata

| Field | Value |
| --- | --- |
| Drill date | 2026-05-11 |
| Target standby region | Mumbai and Cape Town |
| Incident commander | Àbhîram .K |
| App operator | Àbhîram .K |
| Database operator | Not tested in this app-only drill |
| Storage operator | Not tested independently in this app-only drill |
| Starting git commit | 6fa84f3 |
| Standby deployed git commit | 6fa84f3 |
| Drill type | Technical rehearsal, app deploy and health check only |

## Mumbai Drill Timeline

| Event | UTC Time | Evidence Link/Note |
| --- | --- | --- |
| Drill started | 2026-05-11 10:39:31 UTC | Mumbai deploy started at 11:39:31 BST |
| Primary outage confirmed or simulated | Not simulated | App-only standby deploy drill |
| Incident declared | Not applicable | Drill only |
| Write freeze or maintenance mode decision | Not tested | Required before real failover |
| Backup/snapshot selected | Not tested | DB restore not included in this drill |
| Database restore started | Not tested | DB restore not included in this drill |
| Database restore completed | Not tested | DB restore not included in this drill |
| Object storage read verified | Not independently tested | MinIO container remained healthy |
| Standby env update completed | Not changed | Existing standby env used |
| App restart started | 2026-05-11 10:39:31 UTC | Deploy command started |
| App restart completed | 2026-05-11 10:41:57 UTC | Deploy completed |
| `/healthz` passed | 2026-05-11 10:43:54 UTC | Health check passed |
| `/api/health/ready` passed | 2026-05-11 10:43:54 UTC | Health check passed |
| Core journeys verified | Not tested | Health endpoints only |
| Manual DNS change approved, if applicable | Not applicable | No DNS cutover in Phase 3 |
| Manual DNS change completed, if applicable | Not applicable | No DNS cutover in Phase 3 |
| Monitoring stable | Not tested | Manual health check only |
| Drill ended | 2026-05-11 10:43:54 UTC | Mumbai health check completed |

## Cape Town Drill Timeline

| Event | UTC Time | Evidence Link/Note |
| --- | --- | --- |
| Drill started | 2026-05-11 10:45:25 UTC | Cape Town deploy started at 11:45:25 BST |
| Primary outage confirmed or simulated | Not simulated | App-only standby deploy drill |
| Incident declared | Not applicable | Drill only |
| Write freeze or maintenance mode decision | Not tested | Required before real failover |
| Backup/snapshot selected | Not tested | DB restore not included in this drill |
| Database restore started | Not tested | DB restore not included in this drill |
| Database restore completed | Not tested | DB restore not included in this drill |
| Object storage read verified | Not independently tested | MinIO container remained healthy |
| Standby env update completed | Not changed | Existing standby env used |
| App restart started | 2026-05-11 10:45:25 UTC | Deploy command started |
| App restart completed | 2026-05-11 10:47:54 UTC | Deploy completed |
| `/healthz` passed | 2026-05-11 10:49:20 UTC | Health check passed |
| `/api/health/ready` passed | 2026-05-11 10:49:20 UTC | Health check passed |
| Core journeys verified | Not tested | Health endpoints only |
| Manual DNS change approved, if applicable | Not applicable | No DNS cutover in Phase 3 |
| Manual DNS change completed, if applicable | Not applicable | No DNS cutover in Phase 3 |
| Monitoring stable | Not tested | Manual health check only |
| Drill ended | 2026-05-11 10:49:20 UTC | Cape Town health check completed |

## RTO Measurement

| Metric | Value |
| --- | --- |
| Mumbai RTO start time | 2026-05-11 10:39:31 UTC |
| Mumbai RTO end time | 2026-05-11 10:43:54 UTC |
| Mumbai measured app-only RTO | 4 minutes 23 seconds |
| Cape Town RTO start time | 2026-05-11 10:45:25 UTC |
| Cape Town RTO end time | 2026-05-11 10:49:20 UTC |
| Cape Town measured app-only RTO | 3 minutes 55 seconds |
| Target RTO | Not defined yet |
| Pass/fail | Partial pass: app deploy and health checks passed, full failover not tested |

RTO starts when the outage is confirmed or simulated and ends when the selected standby region passes health checks and core journey verification. This drill measured app deploy plus health check time only.

## RPO Measurement

| Metric | Value |
| --- | --- |
| Latest usable backup/snapshot time | Not tested |
| Last confirmed successful write before outage/freeze | Not tested |
| Estimated data loss window | Unknown until DB backup/snapshot process is verified |
| Final measured RPO | Not measured |
| Target RPO | Not defined yet |
| Pass/fail | Not tested |

RPO is the maximum expected data loss window from the latest usable recovery point to outage or write-freeze time. This app-only drill did not restore or validate the database.

## Core Journey Verification

| Journey | Result | Evidence/Note |
| --- | --- | --- |
| Public homepage loads | Not tested | Add in next drill |
| Public verify entry loads | Not tested | Add in next drill |
| Backend ready endpoint passes | Passed | `/api/health/ready` passed in both Mumbai and Cape Town |
| Login page loads | Not tested | Add in next drill |
| Admin dashboard loads for test account, if approved | Not tested | Requires approved test account |
| QR verification read path works, if approved | Not tested | Add in next drill if safe |
| Write path remains frozen or explicitly approved | Not tested | Required before real failover |

## Docker Service Health

### Mumbai

| Service | Result |
| --- | --- |
| genuine-scan-backend | Healthy |
| genuine-scan-frontend | Healthy |
| genuine-scan-worker | Running |
| genuine-scan-redis | Healthy, intentionally untouched |
| genuine-scan-minio | Healthy, intentionally untouched |

### Cape Town

| Service | Result |
| --- | --- |
| genuine-scan-backend | Healthy |
| genuine-scan-frontend | Healthy |
| genuine-scan-worker | Running |
| genuine-scan-redis | Healthy, intentionally untouched |
| genuine-scan-minio | Healthy, intentionally untouched |

## Outcome

| Field | Value |
| --- | --- |
| Drill result | Partial pass |
| Primary blocker | Database restore, object storage verification, core journey checks, DNS cutover, and write-freeze were not tested |
| Follow-up owner | Àbhîram .K |
| Follow-up due date | Before Phase 4 DNS cutover work |

## Notes

- Do not record secrets here.
- Do not record private keys, database passwords, tokens, or raw customer data.
- Link to approved evidence locations instead of embedding sensitive output.
- Mumbai standby app deploy passed on commit `6fa84f3`.
- Cape Town standby app deploy passed on commit `6fa84f3`.
- Mumbai health checks passed for `/healthz` and `/api/health/ready`.
- Cape Town health checks passed for `/healthz` and `/api/health/ready`.
- This drill did not test database restore.
- This drill did not independently verify object storage recovery.
- This drill did not perform DNS cutover.
- This drill did not implement automatic failover.
- This drill did not add Route 53 failover routing.
- This drill did not add active-active database writes.
- This drill did not clean up or decommission MinIO.