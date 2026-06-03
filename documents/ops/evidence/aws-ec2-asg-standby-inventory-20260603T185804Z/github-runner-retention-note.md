# GitHub runner retention decision

## Instance

`i-0628b4a4a06f6e4d3` / `mscqr-github-actions-runner`

## Decision

Do not stop or terminate this instance during the current cost optimization pass.

## Reason

The instance supports GitHub Actions workflows and may be required for monitoring, automatic DR, failover, and operational automation.

## Cost decision

Keep running until workflows are moved to GitHub-hosted runners, EventBridge/Lambda, ECS scheduled tasks, or another managed automation path.

## Next EC2 optimization target

Resize the live frontend instance `i-024ec40bcbdb30035` from `t3.medium` to `t3.small` after creating an AMI backup.
