# MSCQR AWS Final Setup Audit

Date: 2026-06-03

No AWS infrastructure was mutated during this documentation pass.

## Executive Summary

MSCQR is now in a safer cost posture than the start of the June 3 cleanup pass. The biggest completed savings were London NAT consolidation, old NAT EIP release, London frontend EC2 resize, London ElastiCache replica removal, and Mumbai ElastiCache node downsize while preserving HA. RDS downsizing was intentionally blocked because AWS `describe-valid-db-instance-modifications` did not return an approved smaller class, even where smaller classes were orderable.

The remaining environment is still production and DR sensitive. Do not delete or reduce live ALBs, target groups, RDS databases, DR ASGs, attached EIPs, attached volumes, snapshots/AMIs used for rollback, or the GitHub runner without a separate owner-approved change record.

## Per-Region Architecture Summary

### London / `eu-west-2`

- Production frontend EC2: `mscqr-prod_london` resized from `t3.medium` to `t3.small`.
- Production RDS: `mscqr-prod-db`, PostgreSQL 18.3, `db.t4g.medium`, single-AZ, private, encrypted, 20 GiB gp3.
- ElastiCache: `mscqr-redis-euw2-primary` was reduced from two nodes to one node after earlier evidence; final evidence shows one primary member.
- ALB/target group remain active for Europe traffic.
- NAT topology intentionally collapsed from two NAT gateways to one survivor NAT, `nat-0be609dfc6ce97dc3`.
- Old NAT EIP allocation `eipalloc-0d5bae537b16aece4` was released only after the NAT was deleted, route references were empty, and HTTPS checks stayed healthy.
- Current intentional single points of failure: one NAT gateway and one resized frontend EC2 target. This is a cost decision, not an HA improvement.

### Mumbai / `ap-south-1`

- Regional cleanup inventory found three running EC2 instances, one ALB, one target group, one RDS instance, one ElastiCache replication group with two cache clusters, one DR ASG, three associated EIPs, no idle EIPs, no unattached EBS volumes, no NAT gateways, and no VPC endpoints.
- RDS: `mscqr-prod-db-aps1`, PostgreSQL 18.3, `db.t4g.medium`, single-AZ, private, 20 GiB gp3.
- ElastiCache: `mscqr-redis-aps1-primary` was downsized from two `cache.t4g.medium` nodes to two `cache.t4g.small` nodes while preserving automatic failover and Multi-AZ.
- DR ASG: `mscqr-mumbai-dr-asg`, min 2, desired 2, max 4. Do not reduce without explicit DR RTO/RPO policy.

### Cape Town / `af-south-1`

- Regional cleanup inventory found three running EC2 instances, one ALB, one target group, one RDS instance, one ElastiCache replication group with two cache clusters, one DR ASG, three associated EIPs, no idle EIPs, no unattached EBS volumes, no NAT gateways, and no VPC endpoints.
- RDS: `mscqr-prod-db-afs1`, PostgreSQL 18.3, `db.t4g.small`, single-AZ, private, 20 GiB gp3.
- ElastiCache: `mscqr-redis-afs1-primary`, two `cache.t3.micro` nodes, automatic failover and Multi-AZ enabled. Evidence found no lower valid practical class.
- DR ASG: `mscqr-capetown-dr-asg`, min 2, desired 2, max 4. Do not reduce without explicit DR policy.

## What Was Changed

- London NAT route tables were migrated so all private route tables use survivor NAT `nat-0be609dfc6ce97dc3`.
- London retiring NAT `nat-0a51226e1f9190b2e` was deleted after verification.
- London old NAT EIP `eipalloc-0d5bae537b16aece4` was released after it was idle/unassociated.
- London frontend EC2 `i-024ec40bcbdb30035` was resized from `t3.medium` to `t3.small` after AMI backup `ami-0fe5ba33e4407c12f`.
- London ElastiCache replica was removed, reducing the replication group from two nodes to one.
- Mumbai ElastiCache was downsized from two `cache.t4g.medium` nodes to two `cache.t4g.small` nodes with automatic failover and Multi-AZ preserved.

## What Was Intentionally Not Changed

- RDS instances were not modified because AWS did not return valid smaller modification targets.
- Cape Town ElastiCache was not downsized because it is already at two `cache.t3.micro` nodes.
- Mumbai and Cape Town DR ASGs were not reduced.
- GitHub runner `i-0628b4a4a06f6e4d3` was retained for workflows, monitoring, and DR automation.
- Active ALBs, target groups, Route 53 policy, production DBs, backups, snapshots, IAM roles, and object storage posture were not changed.

## Cost Optimization Actions Completed

| Area | Result |
| --- | --- |
| NAT/VPC | London NAT count reduced from two to one; old NAT EIP released. |
| EC2 | London frontend resized from `t3.medium` to `t3.small`. |
| ElastiCache London | Replica removed; one-node lower-cost posture accepted. |
| ElastiCache Mumbai | Node class reduced to `cache.t4g.small` while keeping HA. |
| Cleanup inventory | Mumbai/Cape Town read-only evidence shows no obvious idle EIPs, unattached volumes, stopped EC2, empty target groups, or unreferenced NATs. |

## Blocked Optimizations

- London RDS: blocked by valid-modification API. Orderable classes existed, but `describe-valid-db-instance-modifications` returned no valid `DBInstanceClass` targets.
- Mumbai RDS: blocked by valid-modification API. Smaller classes were orderable, but no valid modification targets were returned.
- Cape Town RDS: blocked by valid-modification API. Smaller classes were orderable, but no valid modification targets were returned.
- Cape Town ElastiCache: no lower practical valid class than two `cache.t3.micro` nodes while preserving HA.
- DR ASG cost reduction: blocked by business policy, not technical limitation. RTO/RPO and regional failover capacity must be approved first.

## Security Posture Notes

- Evidence was sanitized previously and gitleaks was made clean after fingerprint ignores.
- The regional inventory playbook uses read-only AWS CLI calls and does not call Secrets Manager `GetSecretValue`.
- Do not commit `.env`, raw credentials, AWS client tokens, private keys, or unredacted console exports.
- RDS instances are private and storage encrypted in the captured summaries.
- ElastiCache evidence records transit and at-rest encryption for London; keep TLS and security group scoping as hard requirements.
- The GitHub runner should remain patched and monitored because it is retained as an operational dependency.

## DR Posture Notes

- Mumbai and Cape Town DR ASGs remain at min 2, desired 2, max 4.
- Automatic failover and Multi-AZ were preserved for Mumbai ElastiCache.
- Cape Town ElastiCache remains two-node HA.
- London NAT consolidation intentionally reduces AZ-isolated egress. This is a cost tradeoff and should be revisited when budget allows.
- Do not reduce DR ASGs or delete rollback AMIs/snapshots until RTO/RPO policy and restore evidence are approved.

## Evidence Directory Index

| Directory | Purpose |
| --- | --- |
| `documents/ops/evidence/aws-cost-nat-billing-review-20260603T172924Z/` | NAT billing and initial dependency review. |
| `documents/ops/evidence/aws-first-cleanup-deletion-pass-20260603T174823Z/` | Early cost screenshots, CSVs, deletion plan, hashes. |
| `documents/ops/evidence/aws-eip-review-20260603T181001Z/` | Regional Elastic IP association review. |
| `documents/ops/evidence/aws-nat-redesign-plan-20260603T182442Z/` | London one-NAT migration plan and rollback logic. |
| `documents/ops/evidence/aws-nat-route-migration-20260603T182733Z/` | London route table migration evidence. |
| `documents/ops/evidence/aws-nat-post-migration-verification-20260603T182912Z/` | Post-migration HTTPS, target health, and ALB checks. |
| `documents/ops/evidence/aws-nat-gateway-deletion-20260603T183219Z/` | NAT deletion evidence. |
| `documents/ops/evidence/aws-nat-deletion-final-state-20260603T183435Z/` | Deleted NAT and idle EIP final-state check. |
| `documents/ops/evidence/aws-old-nat-eip-release-20260603T183725Z/` | Old NAT EIP release evidence. |
| `documents/ops/evidence/aws-elasticache-rightsize-inventory-20260603T184059Z/` | London ElastiCache topology and metrics. |
| `documents/ops/evidence/aws-elasticache-replica-removal-20260603T184352Z/` | London ElastiCache replica removal evidence. |
| `documents/ops/evidence/aws-rds-rightsize-inventory-20260603T185100Z/` | London RDS topology and metrics. |
| `documents/ops/evidence/aws-rds-class-downsize-plan-20260603T185232Z/` | London RDS class downsize block and snapshot evidence. |
| `documents/ops/evidence/aws-ec2-asg-standby-inventory-20260603T185804Z/` | EC2/ASG inventory and GitHub runner retention. |
| `documents/ops/evidence/aws-ec2-frontend-resize-20260603T190354Z/` | London frontend resize and rollback script. |
| `documents/ops/evidence/aws-ec2-frontend-resize-followup-20260603T193519Z/` | Follow-up resize verification. |
| `documents/ops/evidence/aws-ec2-frontend-resize-ami-final-20260603T193712Z/` | Final AMI/resize verification. |
| `documents/ops/evidence/aws-regional-cleanup-mumbai-20260603T195128Z/` | Mumbai read-only cleanup inventory. |
| `documents/ops/evidence/aws-regional-cleanup-capetown-20260603T195128Z/` | Cape Town read-only cleanup inventory. |
| `documents/ops/evidence/aws-elasticache-rightsize-mumbai-20260603T195548Z/` | Mumbai ElastiCache right-size evidence. |
| `documents/ops/evidence/aws-elasticache-rightsize-capetown-20260603T195631Z/` | Cape Town ElastiCache right-size evidence. |
| `documents/ops/evidence/aws-elasticache-mumbai-node-downsize-plan-20260603T200446Z/` | Mumbai node downsize plan. |
| `documents/ops/evidence/aws-elasticache-mumbai-node-downsize-20260603T200545Z/` | Mumbai node downsize completion evidence. |
| `documents/ops/evidence/aws-elasticache-capetown-node-downsize-plan-20260603T202447Z/` | Cape Town no-lower-class decision. |
| `documents/ops/evidence/aws-rds-mumbai-class-downsize-plan-20260603T202624Z/` | Mumbai RDS valid-modification block. |
| `documents/ops/evidence/aws-rds-capetown-class-downsize-plan-20260603T202910Z/` | Cape Town RDS valid-modification block. |

## Rollback Evidence/Scripts Index

- London NAT rollback plan: `documents/ops/evidence/aws-nat-redesign-plan-20260603T182442Z/06-proposed-one-nat-migration-plan.md`.
- London frontend resize rollback script: `documents/ops/evidence/aws-ec2-frontend-resize-20260603T190354Z/rollback-resize-to-t3-medium.sh`.
- London frontend AMI backup: `documents/ops/evidence/aws-ec2-frontend-resize-20260603T190354Z/AMI_ID.txt`.
- RDS pre-change snapshot evidence: `documents/ops/evidence/aws-rds-class-downsize-plan-20260603T185232Z/`.
- Per-directory `SHA256SUMS.txt` files preserve evidence integrity.

## Final Do Not Delete List

- GitHub runner `i-0628b4a4a06f6e4d3`.
- All production RDS instances and DB snapshots until restore policy is explicit.
- Mumbai and Cape Town DR ASGs.
- Active ALBs, listeners, target groups, and Route 53 production records.
- Attached EIPs and ENIs.
- AMI `ami-0fe5ba33e4407c12f` and any snapshots backing resize rollback.
- S3/object-storage, IAM, Secrets Manager, WAF, and monitoring resources without separate service-owner approval.
- Remaining London NAT `nat-0be609dfc6ce97dc3`.

## Remaining Safe Next Steps

1. Rerun read-only inventory monthly and after every infrastructure change.
2. Add VPC endpoints analysis for S3, ECR, SSM, CloudWatch Logs, EC2Messages, and SSMMessages before considering further NAT changes.
3. Recheck RDS valid modification targets in a maintenance window; do not rely on orderable classes alone.
4. Review London single-NAT and one-node cache posture against required availability targets.
5. Build a formal DR capacity policy before reducing Mumbai/Cape Town ASGs.
6. CTO recommendation: the next best development is automated read-only Cost Explorer plus CloudWatch evidence capture, not mutation automation.
