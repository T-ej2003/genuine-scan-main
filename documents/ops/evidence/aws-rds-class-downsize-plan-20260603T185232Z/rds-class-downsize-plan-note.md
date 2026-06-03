# AWS RDS class downsize plan

## DB instance

`mscqr-prod-db`

## Original target

`db.t4g.small`

## Result

Blocked.

The RDS `describe-valid-db-instance-modifications` response did not return `db.t4g.small` as a valid target class. The mutation must not be run from this plan.

## Snapshot

A manual pre-change snapshot was created and waited to completion:

`mscqr-prod-db-pre-class-downsize-20260603t185232z`

## Next action

Do not mutate RDS until valid class discovery confirms an allowed smaller class. If no smaller class is valid, skip RDS and move to EC2/ASG standby footprint.
