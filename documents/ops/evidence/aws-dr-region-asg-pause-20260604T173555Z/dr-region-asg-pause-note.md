# DR region ASG pause

Mumbai and Cape Town DR Auto Scaling Groups were paused to stop automatic replacement of standby EC2 instances while London remains the active operating region.

## Intent

Pause DR compute cost until planned reactivation around July second week.

## Scope

This pauses ASG-managed EC2 compute only.

It does not delete:
- Auto Scaling Groups
- Launch templates
- ALBs
- Target groups
- RDS
- ElastiCache
- VPCs
- Security groups
- AMIs/snapshots
- Route53 records

## Resume

Use the generated per-region resume scripts after deciding to re-enable DR. Re-sync data/application state before treating either region as live DR again.

## Important

Do not manually stop ASG-managed instances. ASG desired capacity must be controlled first.
