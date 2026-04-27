# MSCQR Regional Failover Tabletop Record

Use this template to document one tabletop run. Keep the completed record internally shareable: do not include plaintext secrets, raw `.env` files, full database URLs, JWT secrets, QR signing secrets, SMTP passwords, or customer personal data.

## Exercise Metadata

- Date:
- Start time:
- End time:
- Facilitator:
- Scribe:
- Scenario:
- Regions exercised:
- Production changes made: No / Yes

## Participants

| Name | Role | Team | Present for full exercise? |
| --- | --- | --- | --- |
|  | Incident Commander |  |  |
|  | Release Engineer |  |  |
|  | AWS Operator |  |  |
|  | Security Owner |  |  |
|  | Support Lead |  |  |
|  | Scribe |  |  |

## Baseline Evidence

| Evidence | Location or Summary | Owner |
| --- | --- | --- |
| Regional drift Markdown report |  |  |
| Regional drift JSON report |  |  |
| Health check outputs |  |  |
| CloudWatch alarm review |  |  |
| Snapshot review |  |  |
| DNS/TLS review |  |  |

## Scenario Summary

Describe the incident condition used for the exercise:

-

## Decisions Made

| Time | Decision | Decision owner | Evidence used | Accepted risk |
| --- | --- | --- | --- | --- |
|  |  |  |  |  |

## Validation Checkpoints

| Checkpoint | Expected result | Actual result | Pass/Warn/Fail | Notes |
| --- | --- | --- | --- | --- |
| London health reviewed | JSON health status known |  |  |  |
| Mumbai readiness reviewed | Drift findings understood |  |  |  |
| Cape Town readiness reviewed | Drift findings understood |  |  |  |
| Target DB regionality confirmed | Target app uses target-region RDS |  |  |  |
| Target S3 regionality confirmed | Target app uses target-region S3 |  |  |  |
| Object storage mode confirmed | Default credentials / IAM mode |  |  |  |
| Super-admin bootstrap checked | Disabled |  |  |  |
| DNS/TLS owner identified | Named owner and path |  |  |  |
| Rollback trigger defined | Concrete signal named |  |  |  |
| Support communication ready | Owner and message outline |  |  |  |

## Gaps Found

| Gap | Severity | Impact | Recommended remediation | Owner | Due date |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

## Action Items

| Action item | Owner | Due date | Status |
| --- | --- | --- | --- |
|  |  |  |  |

## What Worked

-

## What Was Confusing

-

## Follow-Up Evidence Needed

-

## Final Exercise Outcome

- Success / Partial / Failed:
- Reason:
- Next tabletop target date:
