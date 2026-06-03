# AWS EC2 frontend resize

## Instance

`i-024ec40bcbdb30035` / `mscqr-prod_london`

## Change

`t3.medium` -> `t3.small`

## AMI backup

`ami-0fe5ba33e4407c12f`

## Reason

14-day CPU max average was low and the frontend instance was oversized for current traffic.

## Downtime

This was an in-place stop/resize/start operation and caused temporary frontend downtime while the single frontend target restarted.

## Rollback

Use `rollback-resize-to-t3-medium.sh` if target health, app response, or traffic performance degrades.
