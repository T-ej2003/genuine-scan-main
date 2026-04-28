# AWS / Operations / Reliability Audit

## Ops readiness checklist

### Environment and configuration

- [ ] Production, staging, and development environments are clearly separated
- [ ] Production secrets are managed outside source control and have named rotation owners
- [ ] Production URLs, callback URLs, and CORS origins are current
- [ ] SSL/TLS certificates are valid and auto-renew behavior is confirmed

### Data protection

- [ ] Database backup schedule is confirmed in AWS
- [ ] Backup retention period is confirmed
- [ ] Latest successful backup timestamp is recorded
- [ ] Restore drill has been performed and timed
- [ ] Object storage versioning and lifecycle are confirmed
- [ ] Bucket encryption and public-access-block settings are confirmed

### Monitoring and alerting

- [ ] Application health checks are live and externally verifiable
- [ ] CloudWatch or equivalent dashboards exist for API, DB, queue, and auth issues
- [ ] Alert destinations are configured and tested
- [ ] Error tracking ownership is assigned
- [ ] Cron/job visibility exists for background tasks

### Release and rollback

- [ ] Release candidate gate passes on target build
- [ ] Deployment operator checklist is current
- [ ] Rollback runbook has been rehearsed
- [ ] Release version tagging and evidence capture are current

### Support and incident response

- [ ] Primary/secondary on-call contacts are assigned
- [ ] Severity matrix is agreed
- [ ] Customer communication owner is assigned
- [ ] Support queue and incident queue are monitored during launch week

## What is already good from repo evidence

- Backup/restore DR runbook exists
- Premium launch incident runbook exists
- Security baseline doc exists
- Deployment audit checklist exists
- Rollback doc exists
- Release smoke tests and release candidate gate docs exist
- CI workflows include substantial validation and security scanning

## What still needs confirmation outside the repo

- actual AWS backup policy and retention configuration
- actual restore test evidence
- actual object storage lifecycle/versioning settings
- actual alarm targets and escalation routing
- actual domain/SSL renewal posture
- actual cron/background visibility and failure alerts
- actual secret rotation history

## Rollback runbook

### Trigger conditions

- Release smoke test failure with customer impact
- Authentication failure spike
- Verification failure spike
- Connector download integrity or installer trust failure
- Severe data integrity or migration issue

### Rollback steps

1. Freeze new deploys.
2. Declare incident owner and communications owner.
3. Capture current version, config hash, and affected surfaces.
4. Revert to last known good application version.
5. Apply config rollback if the issue is environment-driven.
6. Validate:
- public verify flow
- operator login
- dashboard load
- QR/batch access
- printer/connector entry points
7. Communicate rollback status internally.
8. If customer-facing impact exists, send approved customer update.
9. Preserve logs and metrics for root-cause analysis.

### Evidence to keep

- version rolled back from and to
- exact timestamp
- approver
- post-rollback smoke results
- incident ticket reference

## Incident response starter runbook

### Severity guide

- `SEV-1`: full outage, auth failure across users, restore-needed data event, major security event
- `SEV-2`: degraded verification, onboarding blocked, printing broadly failing, major customer impact
- `SEV-3`: partial feature issue, workaround exists, limited-customer impact
- `SEV-4`: cosmetic or low-risk issue

### First 30 minutes

1. Assign incident commander.
2. Assign communications lead.
3. Identify affected roles and surfaces.
4. Freeze risky deploys and migrations.
5. Pull current logs, metrics, alerts, and recent release notes.
6. Decide whether rollback is faster than hotfix.
7. Open incident record with timestamps.

### First customer communication should answer

- what is impacted
- who is impacted
- current mitigation
- next update time

### Post-incident

- root cause
- impact window
- data exposure or integrity assessment
- corrective actions
- owner and due date for each action

## Backup / restore verification checklist

- [ ] Latest backup inventory exported
- [ ] Restore target environment prepared
- [ ] Restore run completed successfully
- [ ] Application can start after restore
- [ ] Authentication works after restore
- [ ] Public verification works after restore
- [ ] Key admin data is present and consistent after restore
- [ ] RTO and RPO measured and recorded
- [ ] Restore run approved by named owner
- [ ] Follow-up gaps captured in backlog

## CTO recommendations for stronger operations maturity

1. Add a one-page red/amber/green launch dashboard with auth health, verify health, backup freshness, alert status, and connector distribution status.
2. Add release evidence automation that captures build hash, migration status, smoke results, and approver into one immutable artifact.
3. Add synthetic monitoring for public verify, operator login, and connector download integrity.
4. Add environment drift checks so staging and production config divergence is visible before launch.
