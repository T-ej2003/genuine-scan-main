# Premium Launch Evidence Pack Requirements

All items below are required before premium-client launch approval.

## 1) CI gate evidence

- Green run link for `Release Candidate Gate / rc-trust-critical`
- Green run link for `Release Candidate Gate / rc-staging-smoke`
- `release-checklist-artifact` JSON from the same run

## 2) Staging smoke evidence

- Uploaded `staging-smoke-log` artifact
- Verified smoke configuration (all required staging vars/secrets set)
- Authentication, verify, print, incident, and evidence retrieval checks passed

## 3) Provenance backfill evidence

- `audit-artifacts/provenance/backfill-dryrun-<timestamp>.json`
- `audit-artifacts/provenance/backfill-exec-<timestamp>.json`
- Review note confirming unknown historical labels were not upgraded without governed evidence

## 4) Secret rotation evidence

- `.security/rotation-evidence.json` updated with:
  - approver and operator identities
  - linked deploy SHAs
  - cleanup state fields
- Cleanup confirmation when rotation window closes (no `*_PREVIOUS` values in production)

## 5) Observability/alert evidence

- CloudWatch metric filters applied from `docs/observability/cloudwatch/verification-trust-metric-filters.json`
- CloudWatch alarms applied from `docs/observability/cloudwatch/verification-trust-alarms.json`
- Test-fire proof for:
  - replay spike alert
  - break-glass usage alert
  - signing fallback alert

## 6) Incident drill evidence

Documented drill notes with owner and timestamp for:

1. Replay spike / changed-context cluster
2. Break-glass misuse spike
3. Signer misconfiguration
4. Legacy provenance anomaly
5. Challenge completion failures

## 7) Final sign-off

- Engineering sign-off
- Security sign-off
- Operations/on-call sign-off
- Product/CTO release approval

