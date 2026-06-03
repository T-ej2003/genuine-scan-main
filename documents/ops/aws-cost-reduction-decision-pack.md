# MSCQR AWS Cost Reduction Decision Pack

Last updated: 2026-06-03

No AWS mutation was performed. This is a planning and evidence document only.

## Evidence Used

- Cost deep-dive evidence: `/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Deep-Dive-20260603T130145Z`
- Latest analyzer report: `/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Optimization-Reports/20260603T130148Z/cost-optimization-report.md`
- Latest analyzer report JSON: `/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Optimization-Reports/20260603T130148Z/cost-optimization-report.json`
- Screenshot and CSV evidence: `/Users/abhiramteja/Downloads/genuine-scan-main/artifacts/aws-cleanup-inventory/`

Key evidence:

- Forecast: about `$931.60/month`.
- Safe target ceiling for below GBP 600 including taxes: about `$700-$730/month`.
- Required reduction: about `$201-$231/month`.
- Latest all-services CSV total: `$1,476.19`, with RDS `$499.58`, ElastiCache `$344.18`, Tax `$246.03`, EC2-Instances `$168.25`, EC2-Other `$102.94`, ELB `$46.33`, VPC `$41.27`.
- Wider service CSV total: `$1,706.21`, with RDS `$578.23`, ElastiCache `$371.43`, Tax `$284.36`, EC2-Instances `$183.34`, EC2-Other `$137.36`, ELB `$54.19`, VPC `$50.55`.
- ElastiCache usage type CSV: EUW2 `cache.r7g.large` `$186.37`, AFS1 `cache.t3.medium` `$59.17`, APS3 `cache.t4g.medium` `$58.97`, EUW2 `cache.t4g.medium` `$38.76`.
- EC2-Other usage type CSV: EUW2 NAT gateway hours `$79.10`, EBS volume usage about `$18.49`, regional data transfer about `$5.23`.
- VPC usage type CSV: public IPv4 in-use addresses total about `$41.27`.

## A. Executive Decision

The GBP 600/month target is achievable, but not by random legacy cleanup. The plan needs a controlled reduction of the major recurring drivers. The first optimization pass should target:

1. ElastiCache node class/count/topology.
2. RDS instance class and DR posture.
3. NAT/VPC plus EC2-Other breakdown.

Estimated savings range from the first three workstreams is `$130-$450/month` before tax effects. A realistic approval-gated goal is `$200-$250/month`, which should bring the forecast toward the `$700-$730/month` ceiling if metrics support right-sizing.

Blocked by missing metrics:

- ElastiCache CPU, memory, evictions, connections, network, replication role, and app dependency.
- RDS CPU, free memory, connections, storage, IOPS, latency, backup posture, and latest snapshot.
- NAT route table dependencies, NAT bytes, private subnet egress needs, public IPv4 ownership, EBS attachment and snapshot recovery purpose.

## B. Prioritized Action Table

| Priority | Service | Candidate action | Estimated monthly saving range | Risk | Required proof | Approval level | Rollback path | Status |
| ---: | --- | --- | ---: | --- | --- | --- | --- | --- |
| 1 | ElastiCache | Metrics-backed node class/count/topology review, especially EUW2 `cache.r7g.large` and multi-region cache footprint | `$60-$180` | High | Node type/count, CPU, memory, evictions, connections, network bytes, replication role, snapshots, app dependency | CTO + production owner + ops | Revert to previous node class/topology; validate app health and cache warm-up | Ready for console metric review |
| 2 | RDS | Metrics-backed instance class and DR DB posture review | `$50-$180` | High | DB class, Multi-AZ, CPU, memory, connections, storage, IOPS, latency, backup retention, latest snapshot, restore path | CTO + data owner + ops | Revert DB class or restore from verified snapshot in approved maintenance window | Ready for console metric review |
| 3 | NAT/VPC + EC2-Other | Review EUW2 NAT gateway hours, public IPv4, EBS volume usage, regional transfer | `$20-$90` | High | NAT route tables, private subnet egress, NAT bytes/hours, endpoint alternatives, public IPv4 owners, EBS attachment/snapshot proof | CTO + network owner + ops | Restore previous route table and NAT topology; reattach/restore EBS from approved backup | Ready for dependency review |
| 4 | EC2-Instances | Review ASG, GitHub runner, production/DR footprint after metrics | `$20-$70` | Medium to High | CPU, network, disk, ASG desired/min/max, release gate dependency, runner queue | CTO + release owner + ops | Restore prior ASG desired capacity or instance class | Not first pass |
| 5 | ELB | Review orphan target groups only; keep active ALBs | `$0-$10` | Medium | Listener association, target health, ASG references, Route 53 aliases | Ops + CTO | Recreate target group/listener attachment from captured config | Not first pass |
| 6 | CloudWatch/WAF/Secrets/ECR/S3 lifecycle | Small-service hygiene only after big drivers | `$5-$30` | Low to Medium | Retention, lifecycle, access-last-used, workflow references, owner approval | Service owner + ops | Revert retention/lifecycle settings from captured config | Not first pass |

## C. First 3 Actions Only

### Action 1: ElastiCache Metrics-Backed Right-Size/Topology Review

Decision objective: determine whether cache node classes, node count, or regional cache topology can be reduced without affecting QR verification, auth/session behavior, rate limiting, release safety, or DR.

Evidence pressure:

- ElastiCache observed cost is `$344.18-$371.43`.
- Usage type CSV shows EUW2 `cache.r7g.large` alone at `$186.37`.
- Other material node usage: AFS1 `cache.t3.medium` `$59.17`, APS3 `cache.t4g.medium` `$58.97`, EUW2 `cache.t4g.medium` `$38.76`.

### Action 2: RDS Metrics-Backed Right-Size/DR Posture Review

Decision objective: determine whether RDS instance classes, Multi-AZ posture, regional DB roles, or restore-test resources can be adjusted safely.

Evidence pressure:

- RDS observed cost is `$499.58-$578.23`.
- RDS is the largest service driver before tax.
- Latest evidence pack includes RDS usage screenshot/CSV evidence but does not include the full per-region DB inventory JSON in this latest folder, so the decision gate must use console metrics and DB inventory before any proposal.

### Action 3: NAT/VPC + EC2-Other Breakdown Review

Decision objective: determine whether EUW2 NAT gateway hours, public IPv4 allocation, EBS usage, and regional transfer can be reduced safely without breaking private subnet egress, deployments, health checks, object storage access, or rollback.

Evidence pressure:

- EC2-Other observed cost is `$102.94-$137.36`.
- VPC observed cost is `$41.27-$50.55`.
- EC2-Other usage type CSV shows EUW2 NAT gateway hours at `$79.10`.
- VPC usage type CSV shows public IPv4 in-use charges around `$41.27`.

## D. Console Click-by-Click for First 3 Actions

### ElastiCache

1. Open AWS Console > ElastiCache.
2. Select each region in scope: `eu-west-2`, `ap-south-1`, `af-south-1`.
3. Open Redis OSS / Valkey clusters.
4. Capture screenshots of cluster ID, node type, node count, status, engine, replication group, snapshot retention, subnet group, security groups, encryption settings.
5. Open Monitoring for each cluster.
6. Capture CPU utilization, database memory usage percentage, evictions, current connections, network bytes in/out, cache hits/misses if present.
7. Compare EUW2 `cache.r7g.large` and regional `t3/t4g.medium` usage with actual utilization.
8. Record app dependency: session store, rate limiting, queues, verification cache, or transient-only cache.

### RDS

1. Open AWS Console > RDS > Databases.
2. Select each MSCQR DB by region.
3. Capture DB identifier, class, engine/version, status, Multi-AZ, allocated storage, storage type, encryption, deletion protection, backup retention, latest automated backup, latest manual snapshot.
4. Open Monitoring.
5. Capture CPU utilization, freeable memory, database connections, read/write IOPS, read/write latency, storage free space, burst/credit metrics if relevant.
6. Open Snapshots.
7. Capture latest snapshot timestamp, snapshot ARN/ID, source DB, status, and restore requirement.
8. Confirm whether each DB is primary, DR, or restore-test.

### VPC/NAT/EC2-Other

1. Open AWS Console > VPC > NAT gateways.
2. Select `eu-west-2` first because EC2-Other usage shows EUW2 NAT gateway hours at `$79.10`.
3. Capture NAT gateway ID, state, VPC, subnet, public IP, route table associations, bytes processed metric, creation time, tags.
4. Open VPC > Route tables.
5. Capture private subnet routes pointing to NAT gateways.
6. Open VPC > Endpoints.
7. Capture existing endpoints and missing endpoint candidates for high-volume private egress.
8. Open EC2 > Network Interfaces / Elastic IPs.
9. Capture public IPv4 associations and owners.
10. Open EC2 > Volumes and Snapshots.
11. Capture EBS volume ID, size, type, attachment state, instance ID, age, encryption, snapshot source, and owner/recovery purpose.

## E. Decision Gates

### Action 1: ElastiCache

Green-light conditions:

- CPU and memory utilization are consistently low across peak windows.
- Evictions are zero or explainable.
- Connections and network traffic are comfortably below node limits.
- App dependency confirms cache can tolerate planned class/topology change.
- Previous node class/topology and rollback procedure are documented.

Red-light conditions:

- High memory pressure, evictions, saturated CPU, high connection count, or unknown app dependency.
- Cache participates in critical auth/session/rate-limit path without tested fallback.
- No rollback or warm-up plan.

Required screenshots:

- Cluster overview, node type/count, replication group, monitoring graphs, snapshot settings.

Required rollback plan:

- Restore previous node class/topology and verify application health, cache warm-up, and error rates.

What not to touch:

- Do not delete clusters.
- Do not change production cache topology.
- Do not alter security groups, subnet groups, encryption, auth, or replication without a separate approved change.

### Action 2: RDS

Green-light conditions:

- CPU, memory, IOPS, latency, storage, and connections show sustained headroom.
- DB role is confirmed: primary, DR, or restore-test.
- Latest backup/snapshot is valid and restore path is documented.
- Maintenance window and rollback plan are approved.

Red-light conditions:

- High or spiky CPU, low free memory, high latency, storage pressure, heavy connections, missing backups, unclear DB role.
- No restore test or rollback owner.

Required screenshots:

- DB configuration, Multi-AZ, storage, backups, latest snapshot, CloudWatch metrics.

Required rollback plan:

- Revert DB class or restore from verified snapshot during approved maintenance window.

What not to touch:

- No RDS deletion.
- No RDS snapshot deletion.
- No backup retention reduction.
- No production DB stop, resize, or modify in this pass.

### Action 3: NAT/VPC + EC2-Other

Green-light conditions:

- NAT route table dependencies are fully mapped.
- NAT traffic is low or has clear endpoint alternatives.
- Public IPv4 owners are identified.
- EBS volumes/snapshots have owner, recovery purpose, and backup status.
- Rollback route plan is documented.

Red-light conditions:

- Unknown private subnet egress.
- NAT used by deploys, health checks, package pulls, object storage flows, or rollback path without alternative.
- Unknown public IP owners.
- EBS snapshot or volume may be recovery evidence.

Required screenshots:

- NAT gateway overview, route tables, NAT bytes/hours, VPC endpoints, public IPv4 associations, EBS volume/snapshot details.

Required rollback plan:

- Restore previous route table targets, NAT topology, public IP associations, and EBS attachment/restore path as applicable.

What not to touch:

- Do not delete NAT gateways.
- Do not change route tables.
- Do not release public IPs.
- Do not delete EBS volumes or snapshots.

## F. Not Today

- No RDS deletion.
- No RDS snapshot deletion.
- No S3 bucket deletion.
- No Route 53 deletion or change.
- No active ALB deletion.
- No IAM role deletion.
- No production EC2 stop or terminate.
- No ElastiCache deletion.
- No NAT deletion.
- No EBS deletion.
- No security group, subnet, listener, ASG, or release workflow mutation.

## G. Approval Template

Use this before any future AWS change:

```text
Cost action title:
Service:
Region:
Resource ID/ARN:
Current monthly cost evidence:
Expected monthly saving:
Owner:
Business justification:
Console screenshots attached:
Metrics reviewed:
Backup/snapshot confirmed:
Rollback path:
Maintenance window:
Production impact assessment:
DR/failover impact assessment:
Security impact assessment:
Manual approver:
Approval timestamp:
Post-action verification plan:
```

## H. Final Recommendation

Continue with console metric review now. Ask Amazon Q only after the operator has captured service-specific metrics for ElastiCache, RDS, and NAT/VPC; then use it for focused right-sizing explanations per service. Do not implement automation yet. Automation should wait until there is a manually approved, repeatable policy with rollback evidence.

CTO recommendation: the first real savings decision should be ElastiCache, followed by RDS, then NAT/VPC plus EC2-Other. Random legacy cleanup is not the path to the GBP 600/month target.
