# AWS No-Touch Resources

Date: 2026-06-03

These resources must not be deleted, stopped, resized, reduced, released, detached, or modified without a separate explicit approval record.

## GitHub Runner Retained

- `i-0628b4a4a06f6e4d3` / `mscqr-github-actions-runner`.
- Reason: supports GitHub Actions workflows, monitoring, automatic DR, failover, and operational automation.
- Evidence: `documents/ops/evidence/aws-ec2-asg-standby-inventory-20260603T185804Z/github-runner-retention-note.md`.

## RDS Instances Blocked

Do not modify RDS class from the current state unless `describe-valid-db-instance-modifications` returns a specific target and a maintenance/rollback plan is approved.

| Region | DB | Current class | Reason |
| --- | --- | --- | --- |
| London `eu-west-2` | `mscqr-prod-db` | `db.t4g.medium` | Valid-modification API returned no smaller class. |
| Mumbai `ap-south-1` | `mscqr-prod-db-aps1` | `db.t4g.medium` | Valid-modification API returned no smaller class. |
| Cape Town `af-south-1` | `mscqr-prod-db-afs1` | `db.t4g.small` | Valid-modification API returned no smaller class. |

## DR ASGs Not Reduced

- `mscqr-mumbai-dr-asg`: min 2, desired 2, max 4.
- `mscqr-capetown-dr-asg`: min 2, desired 2, max 4.
- Reason: reducing these changes DR readiness and must be tied to explicit RTO/RPO policy.

## AMIs and Snapshots Needed for Rollback

- London frontend resize AMI: `ami-0fe5ba33e4407c12f`.
- London frontend resize evidence and rollback script: `documents/ops/evidence/aws-ec2-frontend-resize-20260603T190354Z/`.
- RDS pre-change snapshot evidence: `documents/ops/evidence/aws-rds-class-downsize-plan-20260603T185232Z/`.
- Any snapshot or AMI referenced in evidence directories must be retained until an owner signs off that rollback evidence has expired.

## Current Intentional Single Points of Failure

- London now has one NAT gateway, `nat-0be609dfc6ce97dc3`, after cost-driven consolidation.
- London ElastiCache was reduced to one node after replica removal.
- London frontend EC2 was resized in place and remains a cost-optimized capacity choice.

These are accepted cost tradeoffs, not recommended end-state HA architecture. Revisit them when budget permits.

## Other No-Touch Classes

- Active ALBs/NLBs, listeners, target groups, and Route 53 production records.
- Attached EIPs and ENIs.
- Production RDS backups, manual snapshots, DB parameter/subnet/security groups.
- Object storage, IAM roles/policies, Secrets Manager, WAF, CloudWatch alarms/logs, and release workflow resources.
- Any resource that appears in rollback, DR, or evidence hash manifests.

## Safe Review Only

Future changes require:

- New timestamped inventory.
- Evidence hashes.
- Cost impact.
- Security and DR impact.
- Rollback path.
- Manual approval.

CTO recommendation: the next improvement is to replace no-touch tribal knowledge with policy-as-code keep rules that fail CI if a cleanup plan tries to touch protected resources.
