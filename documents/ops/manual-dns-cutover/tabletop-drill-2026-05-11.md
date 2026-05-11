# Phase 4 Manual DNS Cutover Tabletop Drill

Last updated: 2026-05-11

## Summary

This was a tabletop-only Phase 4 DNS cutover drill for MSCQR.

No production DNS record was changed.
No Route 53 automation was added.
No automatic failover was added.
No active-active database logic was added.
No MinIO cleanup or decommissioning was performed.

## Drill Type

| Field | Value |
| --- | --- |
| Drill type | Tabletop / dry run |
| Production DNS changed | No |
| Target regions reviewed | Mumbai and Cape Town |
| Operator | Àbhîram .K |
| Repository | genuine-scan-main |
| Branch | main |

## Target Region Review

| Region | Status |
| --- | --- |
| Mumbai | Reviewed as standby target |
| Cape Town | Reviewed as standby target |

## Standby Health Check Evidence

Command used:

```bash
scripts/health-check-regions.sh standby
Result

| Region | Health result | Commit | Notes |
| --- | --- | --- |
| Mumbai | Passed | ac1d8ee | /healthz and /api/health/ready passed. Docker services healthy/running. No DNS change. |
| Cape Town | Passed | ac1d8ee | /healthz and /api/health/ready passed. Docker services healthy/running. No DNS change. |

DNS Provider and Record Inventory
Field	Value
DNS provider identified	Pending console confirmation
DNS console/account identified	Pending console confirmation
Production hostname	www.mscqr.com

Apex hostname	mscqr.com
Current www record value	www.mscqr.com -> mscqr.com -> 13.135.108.69
Current apex record value	mscqr.com -> 13.135.108.69
Current TTL	Pending DNS console verification
Rollback value captured	13.135.108.69 from DNS lookup, pending console confirmation
Target standby value	Pending approval
Proposed TTL	Pending
DNS Lookup Evidence

Command used:

dig +short www.mscqr.com
dig +short mscqr.com

Result captured on 2026-05-11 at 12:26:43 BST:

DNS CHECK START: Mon 11 May 2026 12:26:43 BST
www.mscqr.com:
mscqr.com.
13.135.108.69
mscqr.com:
13.135.108.69
DNS CHECK FINISH: Mon 11 May 2026 12:26:43 BST
Public Production Health Evidence

Commands used:

curl -fsS https://www.mscqr.com/healthz
curl -fsS https://www.mscqr.com/api/health/ready

Result captured on 2026-05-11 at 12:27:01 BST:

PUBLIC HEALTH CHECK START: Mon 11 May 2026 12:27:01 BST
ok

{"success":true,"status":"ready","uptimeSec":1073,"timestamp":"2026-05-11T11:27:01.830Z","ms":36,"release":{"environment":"production"},"dependencies":{"database":{"configured":true,"ready":true},"redis":{"configured":true,"ready":true},"objectStorage":{"configured":true,"ready":true,"bucket":"mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an","region":"eu-west-2","endpoint":null,"mode":"default-credentials"}}}
PUBLIC HEALTH CHECK FINISH: Mon 11 May 2026 12:27:01 BST
Roles Review
Role	Owner	Status
Incident commander	Àbhîram .K	Identified for drill
DNS operator	Àbhîram .K	Needs DNS console access confirmation before real cutover
App operator	Àbhîram .K	Identified
Database operator	Pending	Required before real cutover
Storage operator	Pending	Required before real cutover
Security reviewer	Pending	Required before real cutover
Communications owner	Pending	Required before real cutover
Pre-Cutover Checklist Review
Item	Tabletop Status
Phase 3 drill evidence reviewed	Done
Target region selected	Not selected, both Mumbai and Cape Town reviewed
Target app health checks pass	Passed
Target database recovery state approved	Not done
Target object storage read path verified	Not done for standby target
Write freeze or maintenance mode documented	Not done
TLS/certificate posture approved	Pending
Current DNS values captured	Captured via DNS lookup, pending DNS console confirmation
Rollback DNS values captured	Captured via DNS lookup as 13.135.108.69, pending DNS console confirmation
DNS TTL reviewed	Pending DNS console verification
Monitoring owner assigned	Pending
Rollback Decision Gate Review

Rollback would be required if:

Production hostname fails health checks after DNS propagation.
TLS is invalid or browsers reject the production hostname.
Core user journeys fail.
Recovered database state is rejected.
Object storage read path fails.
Error rate exceeds the incident commander threshold.
Security reviewer rejects the posture.

Tabletop result: rollback logic reviewed, but not tested with real DNS movement.

Evidence Capture
Evidence	Status
Approval timestamp	Tabletop only
Target region	Mumbai and Cape Town reviewed
Deployed commit	ac1d8ee
Current DNS values	www.mscqr.com -> mscqr.com -> 13.135.108.69; mscqr.com -> 13.135.108.69
New DNS values	Not applicable, no DNS change
TTL values	Pending DNS console verification
Health check responses	Mumbai and Cape Town standby health checks passed
Core journey results	Not tested
Logs and alarm snapshots	Not captured
RTO/RPO worksheet	Existing Phase 3 app-only drill recorded
Rollback evidence	Not applicable, no DNS change
Blockers Before Real DNS Cutover
 Confirm DNS provider and access.
 Capture current DNS record values from authoritative DNS console.
 Capture current TTL values.
 Confirm rollback DNS values in DNS console.
 Confirm TLS/certificate readiness for production hostname on standby target.
 Complete database recovery plan and test.
 Verify object storage read path from target standby region.
 Define write-freeze or maintenance-mode process.
 Assign database operator.
 Assign storage operator.
 Assign security reviewer.
 Assign communications owner.
 Test core user journeys safely.
Outcome
Field	Value
Drill result	Partial pass
Reason	Phase 4 procedure reviewed and read-only checks passed, but real DNS movement was not performed
Production DNS changed	No
Safe to proceed to real DNS cutover	No, database, storage, TLS, DNS rollback, and role gaps remain
Notes

This tabletop confirms the manual DNS cutover process is documented and current production DNS/health can be observed safely.

MSCQR should not perform a real production DNS cutover until database recovery, object storage, TLS, rollback, and operator ownership are verified.
