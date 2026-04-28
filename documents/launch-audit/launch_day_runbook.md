# Launch Day Runbook

## Before deployment

1. Confirm all `P0` items in `manual_verification_tracker.md` are complete.
2. Confirm clean migration replay has passed.
3. Confirm final approved release candidate version.
4. Confirm owner matrix is populated.
5. Confirm support and incident contacts are staffed.
6. Review `deployment_operator_checklist.md` and `rollback_rehearsal_checklist.md`.

## Release sequence

1. Record the version/build being deployed.
2. Capture release evidence using `release_evidence_template.md`.
3. Execute deployment using the approved operator checklist.
4. Run smoke tests immediately after deployment:
- public landing page
- public verify landing
- operator login
- dashboard
- connector download
- support issue submission path
5. Review alarms and logs for 15 minutes before declaring success.

## If something goes wrong

1. Stop further deploy activity.
2. Assign incident commander.
3. Decide rollback vs hotfix.
4. If rolling back, follow the rollback rehearsal checklist and capture timings.
5. Send internal update and customer update if required.
