# MSCQR Regional Failover Runbook v1

Last updated: 2026-06-01

Purpose: provide an operator-safe manual failover process for moving MSCQR production service from London to Mumbai or Cape Town when London cannot safely serve traffic.

This runbook reflects the current architecture:

- Mumbai (`ap-south-1`) is current production for `www.mscqr.com`.
- Cape Town (`af-south-1`) is the next Africa DNS readiness target after ASG health reached healthy state.
- London (`eu-west-2`) needs audit/rebuild after Cape Town DNS readiness and is not changed in this pass.
- There is no active-active multi-write topology.
- DNS cutover is manual and must be treated as a controlled incident action.
- Object storage steady state is region-local S3 through EC2 IAM role credentials: blank endpoint, blank static keys, `OBJECT_STORAGE_FORCE_PATH_STYLE=false`.

## Region Roles

| Region | Role | App health endpoint | RDS identifier | S3 artifacts bucket |
| --- | --- | --- | --- | --- |
| Mumbai / `ap-south-1` | Current production | `https://www.mscqr.com/api/health/ready` | `mscqr-prod-db-aps1` | `mscqr-prod-aps1-artifacts-ACCOUNT_ID-ap-south-1` |
| Cape Town / `af-south-1` | Africa DNS readiness target | `http://mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com/healthz` | `mscqr-prod-db-afs1` | `mscqr-prod-afs1-artifacts-ACCOUNT_ID-af-south-1` |
| London / `eu-west-2` | Pending audit/rebuild | Audit before use | `mscqr-prod-db` | `mscqr-prod-euw2-artifacts-ACCOUNT_ID-eu-west-2` |

## Prerequisites

1. AWS operator access can read EC2, RDS, S3, and CloudWatch in all three regions.
2. The regional drift checker is available from the repo:

```bash
npm run ops:regional-drift -- --out-dir reports/regional-drift
```

3. Optional runtime inspection is available from an operator workstation with EC2 Instance Connect and SSH:

```bash
npm run ops:regional-drift -- --ssh --out-dir reports/regional-drift-ssh
```

4. At least one recent manual RDS snapshot exists for the target standby region.
5. Target region EC2, RDS, S3 bucket, IAM role, and CloudWatch alarms exist.
6. DNS/TLS ownership is available to the incident commander or release engineer.

## Trigger Conditions

Consider failover only when one or more are true:

1. London `/api/health/ready` is failing or degraded and cannot be remediated quickly.
2. London RDS is unavailable, corrupted, or isolated from the app.
3. London EC2 host is unavailable or cannot be recovered within the incident objective.
4. London networking, DNS, or TLS path is unavailable.
5. Security incident response requires isolating London.

Do not fail over for a cosmetic UI issue, isolated user support issue, or transient alarm that clears before operator validation.

## Pre-Failover Decision Gate

1. Name one incident commander.
2. Freeze non-incident deploys.
3. Capture current evidence:

```bash
npm run ops:regional-drift -- --out-dir reports/pre-failover-$(date -u +%Y%m%dT%H%M%SZ) --no-fail
```

4. Confirm London cannot safely remain active.
5. Pick exactly one target. For the current safe DR step, only Cape Town Africa DNS readiness is in scope.
6. Confirm the target has:
   - Ready health passing.
   - Object storage ready with the target region-local bucket.
   - RDS endpoint aligned to the target region.
   - Alarms present.
   - Recent manual snapshot.
   - Super-admin bootstrap disabled.
   - No production object-storage dependency on MinIO/static keys.

If the target region has a FAIL finding, stop unless the incident commander explicitly accepts the risk and documents why.

## Failover: London to Mumbai

1. Run target verification:

```bash
npm run ops:regional-drift -- --out-dir reports/failover-mumbai-precheck --no-fail
curl -fsS https://mumbai-standby.example.internal/api/health/ready
```

2. Confirm Mumbai app config:
   - `AWS_REGION=ap-south-1`
   - `OBJECT_STORAGE_REGION=ap-south-1`
   - `OBJECT_STORAGE_BUCKET=mscqr-prod-aps1-artifacts-ACCOUNT_ID-ap-south-1`
   - `OBJECT_STORAGE_ENDPOINT=`
   - `OBJECT_STORAGE_ACCESS_KEY=`
   - `OBJECT_STORAGE_SECRET_KEY=`
   - `OBJECT_STORAGE_FORCE_PATH_STYLE=false`

3. Confirm Mumbai RDS is the configured database. Do not point Mumbai at London RDS.
4. Confirm no write traffic is still intentionally being sent to London.
5. Lower DNS TTL if not already low.
6. Decide TLS approach:
   - Preferred: complete certificate binding for the production hostname in Mumbai before public cutover.
   - Emergency: use a controlled temporary hostname only if customer-facing impact and security posture are explicitly accepted.
7. Update DNS to route production traffic to Mumbai.
8. Validate after cutover:

```bash
curl -fsS https://www.mscqr.com/api/health/ready
curl -fsS https://www.mscqr.com/api/health/live
npm run verify:staging-smoke
```

9. Watch CloudWatch alarms and backend logs for at least 30 minutes.
10. Declare Mumbai active only after health, smoke, auth, verification, controlled print, and support flows are validated.

## Failover: London to Cape Town

1. Run target verification:

```bash
npm run ops:regional-drift -- --out-dir reports/failover-capetown-precheck --no-fail
curl -fsS https://capetown-standby.example.internal/api/health/ready
```

2. Confirm Cape Town app config:
   - `AWS_REGION=af-south-1`
   - `OBJECT_STORAGE_REGION=af-south-1`
   - `OBJECT_STORAGE_BUCKET=mscqr-prod-afs1-artifacts-ACCOUNT_ID-af-south-1`
   - `OBJECT_STORAGE_ENDPOINT=`
   - `OBJECT_STORAGE_ACCESS_KEY=`
   - `OBJECT_STORAGE_SECRET_KEY=`
   - `OBJECT_STORAGE_FORCE_PATH_STYLE=false`

3. Confirm Cape Town RDS is the configured database. Do not point Cape Town at London RDS.
4. Confirm no write traffic is still intentionally being sent to London.
5. Lower DNS TTL if not already low.
6. Decide TLS approach using the same decision gate as Mumbai.
7. Update DNS to route production traffic to Cape Town.
8. Validate after cutover:

```bash
curl -fsS https://www.mscqr.com/api/health/ready
curl -fsS https://www.mscqr.com/api/health/live
npm run verify:staging-smoke
```

9. Watch CloudWatch alarms and backend logs for at least 30 minutes.
10. Declare Cape Town active only after health, smoke, auth, verification, controlled print, and support flows are validated.

## Africa Routing: Mumbai Default To Cape Town Africa

This is the current planning path. It is not a full failover and it is not automatic failover.

1. Capture clean Cape Town ASG evidence:

```bash
TARGET_REGION_GROUP=capetown \
AWS_REGION=af-south-1 \
ASG_NAME=mscqr-capetown-dr-asg \
TARGET_GROUP_ARN=arn:aws:elasticloadbalancing:af-south-1:368992683803:targetgroup/mscqr-capetown-frontend-tg/a9b43fd2d346e26d \
ALB_DNS_NAME=mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com \
ALB_HTTP_HEALTHZ_URL=http://mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com/healthz \
npm run ops:asg-health-evidence
```

2. Generate the Africa DNS plan only:

```bash
AFRICA_ALB_DNS_NAME=mscqr-capetown-alb-1730011881.af-south-1.elb.amazonaws.com \
AFRICA_ALB_HOSTED_ZONE_ID=Z268VQBMOI5EKX \
DEFAULT_ALB_DNS_NAME=mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com \
DEFAULT_ALB_HOSTED_ZONE_ID=ZP97RAFLXTNZK \
CURRENT_GLOBAL_ALB_DNS_NAME=mscqr-mumbai-alb-1249752376.ap-south-1.elb.amazonaws.com \
CURRENT_GLOBAL_ALB_HOSTED_ZONE_ID=ZP97RAFLXTNZK \
npm run ops:route53-africa-dns-plan
```

3. Review the proposed cutover and rollback batches. Do not apply Route 53 changes from this runbook.
4. Confirm raw ALB HTTPS certificate mismatch is ignored as expected; use real domain records for DNS/TLS validation.

## Validation Checklist After Cutover

1. `https://www.mscqr.com/api/health/ready` returns HTTP 200 JSON.
2. Health dependency status is ready or intentionally unconfigured.
3. Object storage bucket and region match the active region.
4. Object storage mode is `default-credentials`.
5. Object storage endpoint is blank.
6. Public `/verify` flow loads and can submit a safe test lookup.
7. Super Admin can log in with expected MFA/session behavior.
8. Manufacturer and Licensee Admin flows load without permission regression.
9. Controlled print page loads and does not point to stale region dependencies.
10. Support queue is reachable.
11. CloudWatch alarms are visible for the active region.
12. Incident evidence is saved in the incident folder.

## Rollback Sequence

Rollback only if the new active region is failing and London is confirmed safe enough to resume.

1. Freeze writes if possible.
2. Capture drift and health evidence from both regions.
3. Confirm London RDS and S3 are healthy and current enough for rollback.
4. Repoint DNS back to London.
5. Validate:

```bash
curl -fsS https://www.mscqr.com/api/health/ready
npm run verify:staging-smoke
npm run ops:regional-drift -- --out-dir reports/post-rollback --no-fail
```

6. Keep the failed standby isolated until root cause is understood.

## Evidence Capture Requirements

Capture:

- Regional drift JSON and Markdown reports.
- `/health/ready` responses before and after cutover.
- CloudWatch alarm screenshots or exported alarm state.
- RDS snapshot identifiers and creation times.
- DNS records before and after cutover.
- Timeline of decisions and operator names.
- Customer/support impact notes.

Do not paste secrets, full database URLs, JWT secrets, QR signing secrets, SMTP passwords, or raw `.env` files into incident channels.

## Communication Checklist

1. Incident commander announces failover consideration.
2. Release engineer announces deploy freeze.
3. Operations owner confirms target region readiness.
4. Security owner confirms no emergency auth/bootstrap weakening.
5. Support owner prepares customer-facing language if needed.
6. Incident commander announces cutover start.
7. Incident commander announces cutover validation result.
8. Post-incident review is scheduled before closing the incident.

## Do Not Do

- Do not point a standby app at the wrong region database.
- Do not reintroduce MinIO/static-key object storage as steady-state production mode.
- Do not enable super-admin bootstrap in steady state.
- Do not reuse the production hostname in a standby region before DNS/TLS is intentionally cut over.
- Do not accept HTML from an API health check.
- Do not treat a warm standby as active-active multi-write.
- Do not skip evidence capture because the site appears healthy.
- Do not commit secrets, generated storage state, or raw environment files while operating the incident.

## Post-Incident Actions

1. Complete the tabletop record or incident report.
2. File remediation work for every WARN/FAIL finding that was accepted during cutover.
3. Refresh manual snapshots after the environment stabilizes.
4. Review CloudWatch alarm routing and on-call ownership.
5. Confirm DNS/TLS automation gaps are tracked for Phase 1B.
6. Run:

```bash
npm run ops:regional-drift -- --ssh --out-dir reports/post-incident-regional-drift
```
