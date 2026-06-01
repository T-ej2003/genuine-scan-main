# AWS Multi-Region Phase 4: Controlled Manual DNS Cutover Plan

Last updated: 2026-06-01

## Summary

Phase 4 documents a controlled manual DNS cutover process for moving MSCQR public traffic from London to a selected standby region after Phase 3 manual failover has been proven.

This is a plan and operator checklist only. It does not implement DNS automation, Route 53 failover routing, automatic failover, active-active database writes, or MinIO cleanup.

The target outcome is a low-surprise manual cutover with named approvals, known rollback, recorded RTO/RPO impact, and clear evidence.

Current roadmap note: Phase B controlled Route 53 cutover is complete for Mumbai production by operator evidence. Cape Town ASG has reached healthy state and is pending clean final evidence plus Africa DNS plan review only. Phase C S3/default-credentials proof is complete for Mumbai and still pending clean Cape Town proof after DNS/evidence. Phase D automatic failover remains blocked until London, Mumbai, and Cape Town are standardized and no-MinIO/S3 proof is green in all three regions.

## Entry Criteria

Do not start Phase 4 until these are true:

- Phase 2 standby deployment is repeatable for Mumbai and Cape Town.
- Phase 3 manual recovery drill has passed at least once for the target region.
- RTO/RPO measurements are recorded.
- Database recovery path for the selected target is approved.
- Object storage access for the selected target is verified.
- App health checks pass in the selected target:
  - `/healthz`
  - `/api/health/ready`
- Core read journeys pass in the selected target.
- Write freeze or maintenance-mode decision is documented.
- TLS/certificate plan for the production hostname is approved.
- DNS owner and rollback owner are named.

## Explicit Exclusions

- No DNS automation.
- No Route 53 failover routing.
- No unapproved Route 53 geolocation apply.
- No health-check-driven DNS switching.
- No automatic failover.
- No active-active writes.
- No database replication implementation.
- No object storage migration.
- No MinIO cleanup or decommission.
- No destructive Docker cleanup.

## Roles

| Role | Owner | Responsibility |
| --- | --- | --- |
| Incident commander |  | Approves cutover, rollback, and customer impact decisions. |
| DNS operator |  | Performs manual DNS change in the approved console/provider. |
| App operator |  | Deploys and verifies standby app health. |
| Database operator |  | Confirms recovered database state and write gate. |
| Storage operator |  | Confirms object storage access. |
| Security reviewer |  | Confirms TLS, secrets handling, and auth posture. |
| Communications owner |  | Coordinates internal/customer updates and timestamps. |

## DNS Record Inventory Template

Complete before any change.

| Field | Value |
| --- | --- |
| Production hostname | `www.mscqr.com` |
| Apex hostname, if used | `mscqr.com` |
| Current DNS provider/account |  |
| Hosted zone / DNS zone |  |
| Current record type | A / AAAA / CNAME / ALIAS |
| Current record value |  |
| Current TTL |  |
| Target standby region | Mumbai / Cape Town |
| Target record type | A / AAAA / CNAME / ALIAS |
| Target record value |  |
| Proposed TTL |  |
| Previous value captured by |  |
| Rollback value confirmed by |  |

Do not record private credentials, tokens, or secrets in this table.

## Pre-Cutover Checklist

- [ ] Incident commander approved Phase 4 cutover window.
- [ ] Phase 3 drill evidence reviewed.
- [ ] Target region selected: Mumbai / Cape Town.
- [ ] Latest target deployment commit recorded.
- [ ] Target app health checks pass.
- [ ] Target database recovery state approved.
- [ ] Target object storage read path verified.
- [ ] Write freeze or maintenance mode is active, or risk is explicitly accepted.
- [ ] TLS/certificate posture for production hostname approved.
- [ ] Current DNS values captured.
- [ ] Rollback DNS values captured.
- [ ] DNS TTL reviewed and lowered in advance when this is a planned drill.
- [ ] Support/communications owner prepared status update.
- [ ] Monitoring owner watching logs, metrics, and alarms.

## Verification Commands

These commands observe state. They do not change DNS.

Check local deploy state:

```bash
cd /Users/abhiramteja/Downloads/genuine-scan-main
git status --short --branch
scripts/health-check-regions.sh standby
```

Check the selected standby directly by region:

```bash
scripts/health-check-regions.sh mumbai
scripts/health-check-regions.sh capetown
```

Capture current DNS resolution:

```bash
dig +short www.mscqr.com
dig +short mscqr.com
```

Capture public production health before and after cutover:

```bash
curl -fsS https://www.mscqr.com/api/health/ready
curl -fsS https://www.mscqr.com/healthz
```

If `dig` is unavailable on the operator workstation, use the approved DNS console or another approved DNS lookup tool and record the result.

Cape Town Africa DNS readiness uses a plan-only geolocation generator. It must preserve Mumbai as the default/global route and route only Africa (`AF`) to Cape Town after approval:

```bash
npm run ops:route53-africa-dns-plan
```

Do not apply the generated JSON from this phase document. Use it only as reviewed input for a later protected DNS apply.

## Manual DNS Cutover Procedure

This procedure is intentionally manual. Do not add scripts or infrastructure automation for this phase.

1. Confirm incident commander approval.
2. Confirm write freeze or maintenance-mode decision.
3. Confirm target standby health checks pass.
4. Confirm database and object storage gates are approved.
5. Open the approved DNS provider console.
6. Locate the production DNS record.
7. Screenshot or export the current record value and TTL.
8. Update the record to the approved target standby value.
9. Save the change manually.
10. Record the exact change time in the RTO/RPO template.
11. Observe DNS propagation from at least two networks or resolvers.
12. Verify production hostname health.
13. Verify core user journeys.
14. Monitor logs, metrics, and support channels.
15. Declare cutover complete only after validation passes.

## Post-Cutover Validation

- [ ] `www.mscqr.com` resolves to the approved target.
- [ ] `mscqr.com`, if used, resolves or redirects as expected.
- [ ] TLS certificate is valid for the production hostname.
- [ ] `https://www.mscqr.com/api/health/ready` returns success.
- [ ] `https://www.mscqr.com/healthz` returns success.
- [ ] Public verify entry loads.
- [ ] Login page loads.
- [ ] Super Admin login is tested only if approved.
- [ ] QR verification read path works with a safe test case.
- [ ] Write path remains frozen unless explicitly approved.
- [ ] Backend, frontend, and worker logs show no cutover-specific error spike.
- [ ] Support owner confirms no unexpected customer-impact pattern.

## Rollback Decision Gate

Rollback if one or more are true:

- Production hostname fails health checks after DNS propagation.
- TLS is invalid or browsers reject the production hostname.
- Core user journeys fail.
- Recovered database state is rejected.
- Object storage read path fails.
- Error rate exceeds the incident commander threshold.
- Security reviewer rejects the posture.

## Manual DNS Rollback Procedure

1. Incident commander approves rollback.
2. DNS operator restores the previous DNS record value manually.
3. Record rollback start time.
4. Verify DNS resolution returns to the previous value.
5. Verify London health only if London was approved as safe to resume.
6. Keep target standby logs and recovered data for investigation.
7. Do not destroy restored databases, buckets, volumes, or MinIO data.
8. Record rollback end time and validation result.

## Evidence Capture

Save these artifacts in the incident or drill evidence folder:

- Approval timestamp and approver.
- Target region.
- Deployed commit.
- Current DNS values before cutover.
- New DNS values after cutover.
- TTL values before and after cutover.
- Health check responses.
- Core journey results.
- Logs and alarm snapshots.
- RTO/RPO worksheet.
- Rollback evidence, if rollback occurs.
- Follow-up actions and owners.

## Planned Drill Variant

For a planned drill where real public DNS movement is approved:

1. Lower TTL ahead of the drill window.
2. Confirm certificate readiness before the window.
3. Run Phase 3 app/database/object-storage validation first.
4. Perform manual DNS cutover.
5. Measure propagation and customer-visible readiness.
6. Roll back manually to London or keep the target active only if explicitly approved.
7. Restore normal TTL after the drill.

For a planned drill where public DNS movement is not approved:

1. Do not modify production DNS.
2. Use DNS lookup records, screenshots, and a dry-run checklist review.
3. Validate target app by direct region URL/IP only.
4. Record that the DNS step was tabletop-only.

## Completion Criteria

Phase 4 is complete when:

- At least one controlled manual DNS cutover drill is completed or tabletop-approved.
- Rollback path is documented and tested or tabletop-approved.
- RTO/RPO impact of DNS propagation is measured or estimated.
- TLS readiness gaps are resolved or tracked.
- Follow-up items have owners and dates.
- No automatic failover or DNS automation was introduced.

## Future Phases

## Next Phase

- [Phase 5 database recovery strategy](aws-multi-region-phase-5.md)
- [Database recovery pack](database-recovery/README.md)

Phase 5 should prove snapshot/backup restore, recovered endpoint approval, app connectivity, schema compatibility, and write gate approval before any real production DNS cutover.

## Later Phases

- [Phase C MinIO decommission / S3 proof](aws-multi-region-phase-6.md)
- [Final multi-region disaster recovery runbook](aws-multi-region-disaster-recovery-runbook.md)
