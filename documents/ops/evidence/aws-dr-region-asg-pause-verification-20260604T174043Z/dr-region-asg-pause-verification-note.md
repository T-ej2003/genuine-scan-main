# DR ASG pause verification

This evidence directory corrects the earlier ASG pause evidence run where some Python snippets failed because environment variables were not exported.

## Verified intent

Mumbai and Cape Town DR Auto Scaling Groups are paused for cost control while London remains active.

## Pause model

- ASG min size: 0
- ASG desired capacity: 0
- ASG instance count: 0
- Launch process suspended

## What remains intact

- Auto Scaling Groups
- Launch templates
- ALBs
- Target groups
- RDS
- ElastiCache
- VPC networking
- Security groups
- AMIs/snapshots

## Resume

Use the generated per-region resume scripts when DR should be re-enabled around July second week. Re-sync application/database/object state before treating DR as live again.

## Do not do

Do not manually stop ASG-managed instances while desired capacity is above zero. ASG will recreate them.
