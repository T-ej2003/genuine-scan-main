# MSCQR Manual Failover Tabletop Exercise

Purpose: rehearse the manual failover process for MSCQR’s current three-region architecture without changing live DNS, databases, or production traffic.

Architecture under exercise:

- London (`eu-west-2`) is active production.
- Mumbai (`ap-south-1`) and Cape Town (`af-south-1`) are warm standby.
- Failover is manual.
- DNS/TLS cutover is not fully automated.
- Object storage must remain region-local S3 through IAM-role/default-credentials mode.

## Participants

| Role | Responsibilities |
| --- | --- |
| Incident Commander | Owns decisions, timeline, and go/no-go calls. |
| Release Engineer | Runs repo checks, drift checker, smoke tests, and captures command evidence. |
| AWS Operator | Reviews EC2/RDS/S3/CloudWatch, snapshots, DNS, and TLS readiness. |
| Security Owner | Ensures no auth, bootstrap, credential, or secret-handling guardrail is weakened. |
| Support Lead | Tracks customer impact, support queue, and communication readiness. |
| Scribe | Maintains the tabletop record and action items. |

## Scenario Overview

London starts as active production. At 10:00 UTC, the London application begins returning degraded `/api/health/ready` responses and CloudWatch alarms fire for the active stack. The team must decide whether to keep London active, fail over to Mumbai, fail over to Cape Town, or stop for additional evidence.

No real DNS updates are made during tabletop unless the exercise is explicitly promoted to a supervised production drill.

## Assumptions

1. Operators can access AWS read-only APIs for all three regions.
2. The repo checkout is available and dependencies are installed.
3. No one will enable super-admin bootstrap or introduce static S3 credentials.
4. Mumbai and Cape Town remain warm standby, not active-active write targets.
5. Public standby endpoints may use IP-based HTTP health until DNS/TLS cutover work is completed.

## Pre-Exercise Setup

1. Open the runbook: `documents/ops/REGIONAL_FAILOVER_RUNBOOK.md`.
2. Open the record template: `documents/ops/REGIONAL_FAILOVER_TABLETOP_RECORD.md`.
3. Run:

```bash
npm run ops:regional-drift -- --out-dir reports/tabletop-baseline --no-fail
```

4. Optional deeper runtime check:

```bash
npm run ops:regional-drift -- --ssh --out-dir reports/tabletop-baseline-ssh --no-fail
```

5. Confirm no generated reports or credentials will be committed.

## Inject Timeline

| Time | Inject | Expected Decisions |
| --- | --- | --- |
| T+00 | London `/api/health/ready` becomes degraded. | Declare incident commander, freeze deploys, start evidence capture. |
| T+05 | London RDS alarms fire. | Decide whether London can be remediated or failover should be considered. |
| T+10 | Mumbai drift report has PASS except DNS/TLS is manual. | Decide if Mumbai is the preferred target and document DNS/TLS plan. |
| T+15 | Cape Town health is checked as an alternate. | Compare Mumbai and Cape Town readiness; choose one target only. |
| T+20 | Object storage check shows endpoint must stay blank. | Confirm no MinIO/static-key rollback path will be used for production traffic. |
| T+25 | Support reports customer verification failures increasing. | Prepare support and customer communication language. |
| T+30 | Incident commander requests cutover readiness. | Complete go/no-go checklist and name rollback criteria. |
| T+40 | Simulated DNS cutover completed. | Run validation checklist and smoke-test plan. |
| T+50 | Post-cutover support ticket appears. | Verify support queue ownership and evidence capture. |
| T+60 | Exercise ends. | Record gaps, action items, owners, and due dates. |

## Questions and Prompts

1. What evidence proves London is unsafe to keep active?
2. Which target region is most ready and why?
3. What would block failover even if London is degraded?
4. How do we prove the target app is not pointing at London RDS?
5. How do we prove object storage is native S3 IAM mode and not MinIO/static-key mode?
6. Who owns DNS and TLS cutover?
7. What customer-facing language is accurate without overclaiming?
8. What exact signal would trigger rollback?
9. What evidence must be captured before closing the incident?

## Validation Checkpoints

Use these checkpoints during the exercise:

```bash
npm run ops:regional-drift -- --out-dir reports/tabletop-checkpoint --no-fail
curl -fsS https://www.mscqr.com/api/health/ready
curl -fsS http://15.206.45.108/api/health/ready
curl -fsS http://15.240.28.113/api/health/ready
```

Expected validations:

- Health responses are JSON, never frontend HTML.
- Object storage bucket and region match each region.
- Object storage endpoint is blank.
- Object storage mode is `default-credentials`.
- RDS endpoints are region-local.
- Alarms exist.
- Manual snapshots are recent enough for the exercise window.
- Super-admin bootstrap remains disabled.

## Success Criteria

The tabletop is successful if:

1. The team makes a target-region decision using evidence, not intuition.
2. The team identifies DNS/TLS as a controlled cutover gate.
3. No participant proposes static S3 keys, MinIO steady-state mode, or super-admin bootstrap as a normal recovery shortcut.
4. The validation checklist is executable by the release engineer.
5. Gaps are recorded with owners and due dates.

## Failure Criteria

The tabletop fails if:

1. The team cannot identify an incident commander.
2. The target region cannot be selected because evidence is missing.
3. Operators cannot explain which database and S3 bucket the target region uses.
4. DNS/TLS decision ownership is unclear.
5. The exercise ends without action items.

## Follow-Up Capture

Use `documents/ops/REGIONAL_FAILOVER_TABLETOP_RECORD.md` for every exercise run. Store completed records in the incident/evidence location chosen by operations, not in the repo unless the record is intentionally sanitized for internal documentation.
