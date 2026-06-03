# MSCQR AWS Cost Optimization Review

Last updated: 2026-06-03

This document describes the read-only AWS cost optimization analyzer and review workflow. It turns local Cost Explorer exports, usage-type deep dives, AWS inventory JSON, screenshots, and legacy cleanup classifications into a conservative cost reduction plan.

No AWS mutation was performed.

## Purpose

The current AWS forecast is about `$931.60/month`. The business target is below GBP 600 including taxes, so the working AWS ceiling is about `$700-$730/month`, preferably lower before tax. The required reduction is roughly `$200-$250/month`.

The safe path is not random legacy deletion. The realistic path is:

1. Metrics-backed RDS right-sizing and DR database posture review.
2. Metrics-backed ElastiCache right-sizing and regional cache topology review.
3. EC2, ASG, and GitHub runner footprint review.
4. NAT, VPC, and public IPv4 cost review.
5. EBS volume and snapshot lifecycle review.
6. Small services cleanup only after the big drivers are controlled.

Analysis first, console proof second, approval third, mutation last.

## Evidence Collection

Preferred deep-dive pack:

```bash
/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Deep-Dive-20260603T121634Z
/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Deep-Dive-20260603T121634Z.tar.gz
```

The analyzer supports:

- Cost Explorer service CSV exports.
- Cost Explorer usage-type JSON for RDS, ElastiCache, EC2-Other, and VPC.
- Per-region RDS DB and manual snapshot inventory.
- Per-region ElastiCache cluster inventory.
- Per-region EC2, EBS volume, EBS snapshot, and NAT gateway inventory.
- Optional screenshot directories.
- Existing legacy cleanup `classified-resources.json` files under repo artifacts or ops evidence.

Recommended evidence capture before each review:

1. Cost Explorer grouped by Service for current month and last 30 days.
2. Cost Explorer grouped by Usage type for RDS, ElastiCache, EC2-Other, VPC, and EC2 Compute.
3. RDS database metrics: CPU, free memory, connections, storage, IOPS, latency, backup retention, latest snapshot.
4. ElastiCache metrics: CPU, memory, evictions, current connections, network bytes, replication role, snapshots.
5. EC2/ASG metrics: CPU, network, disk, public IPv4, launch template, desired/min/max, release dependency.
6. NAT/VPC proof: route tables, private subnet egress, NAT bytes/hours, endpoint alternatives, rollback route plan.
7. EBS proof: attachment state, volume source, snapshot source, owner, age, recovery purpose.
8. S3/ECR/CloudWatch proof: lifecycle state, object/image/log age, retention, owner, app dependency.

## Commands

Analyze the latest deep-dive directory:

```bash
npm_config_script_shell=/bin/sh npm run ops:cost-optimization -- \
  --evidence-dir /Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Deep-Dive-20260603T121634Z \
  --screenshots-dir /Users/abhiramteja/Downloads/aws-cleanup-inventory
```

Analyze the latest deep-dive archive:

```bash
npm_config_script_shell=/bin/sh npm run ops:cost-optimization -- \
  --archive /Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Deep-Dive-20260603T121634Z.tar.gz
```

If no input is supplied, the analyzer checks the known deep-dive folder, then the earlier optimization evidence folder, then matching Downloads evidence directories.

## Outputs

Each run writes the same report pack to both locations:

- `artifacts/aws-cost-optimization/<UTC_STAMP>/`
- `/Users/abhiramteja/Downloads/MSCQR-AWS-Cost-Optimization-Reports/<UTC_STAMP>/`

Report pack contents:

- `cost-optimization-report.md`
- `cost-optimization-report.json`
- `cost-optimization-summary.txt`
- `proposed-console-review-checklist.md`
- `cost-action-register.tsv`
- `SHA256SUMS.txt`

Do not stage generated report packs unless a later task explicitly asks to preserve a baseline artifact in git.

## Action Categories

Every candidate uses one of these categories:

- `KEEP`: production or required infrastructure.
- `OBSERVE_ONLY`: informational finding only.
- `REVIEW_REQUIRED`: needs human review before any proposal.
- `CANDIDATE_RIGHTSIZE_AFTER_METRICS`: possible future size or topology change after metrics and approval.
- `CANDIDATE_STOP_AFTER_APPROVAL`: reversible future stop only after proof and approval.
- `CANDIDATE_DELETE_AFTER_BACKUP_AND_APPROVAL`: future cleanup only with backup, restore path, console proof, and approval.
- `NEVER_DELETE_WITHOUT_BACKUP`: blocked unless backup/restore evidence and owner decision exist.
- `BLOCKED_UNTIL_MORE_EVIDENCE`: no recommendation until missing evidence is collected.

There are no automatic deletion candidates. Even cleanup candidates require screenshot evidence, resource ID/ARN, cost proof, owner decision, rollback path, backup confirmation, and explicit manual approval in a separate future pass.

## Forbidden

The analyzer must not:

- Call AWS APIs.
- Change Route 53.
- Change RDS, ElastiCache, EC2, ALB, ASG, IAM, S3, EBS, NAT, WAF, CloudWatch, Secrets Manager, or billing resources.
- Stop, resize, scale, detach, deregister, modify, apply, or remove anything.
- Touch secrets.
- Break the Route 53 three-region policy: Africa AF to Cape Town ALB, Europe EU to London ALB, default/global to Mumbai ALB.
- Reintroduce production MinIO.
- Change S3 production object storage mode.
- Change Release Train / Release Gate behavior.
- Make the automatic failover monitor mutating.

## Console Review Protocol

Cost Explorer:

1. Open AWS Console > Billing and Cost Management > Cost Explorer.
2. Set current month and last 30 days.
3. Group by Service, then Usage type for top services.
4. Export CSV and capture screenshots.

RDS:

1. Open AWS Console > RDS > Databases.
2. Select each MSCQR DB by region and identifier.
3. Capture class, engine, Multi-AZ, storage, backup retention, deletion protection, CPU, free memory, connections, IOPS, latency, and latest snapshot.
4. Confirm restore path and owner approval before any right-size proposal.

ElastiCache:

1. Open AWS Console > ElastiCache > clusters.
2. Capture cluster ID, node type/count, engine, status, replication group, snapshot retention, CPU, memory, evictions, connections, and network bytes.
3. Confirm app dependency and failover behavior before any topology or class proposal.

EC2 / ASG:

1. Open AWS Console > EC2 > Instances and Auto Scaling Groups.
2. Capture instance ID, name, state, class, launch time, public IPv4, instance profile, ASG desired/min/max, launch template, and target groups.
3. Separate production nodes, DR nodes, ASG nodes, GitHub runner, and unknown nodes.

VPC / NAT:

1. Open AWS Console > VPC > NAT gateways and Route tables.
2. Capture NAT ID, region, state, VPC, subnet, public IP, private subnet routes, egress requirements, and NAT bytes/hours.
3. Compare VPC endpoint alternatives before any future network proposal.

ELB / Target groups:

1. Open AWS Console > EC2 > Load Balancers and Target Groups.
2. Capture DNS name, listeners, rules, target health, ASG references, tags, and Route 53 aliases.
3. Keep ALBs serving Africa AF, Europe EU, and default/global policy.

S3 / ECR / CloudWatch / WAF / Secrets:

1. Capture lifecycle state, object count, image age, stored log bytes, retention, WAF associations, and access evidence.
2. Review only after owner approval and rollback plan.

## Approval Requirements

Before any future mutation, create a separate approval record with:

- Screenshot.
- Resource ARN or ID.
- Current cost evidence.
- Owner decision.
- Rollback or restore path.
- Backup confirmation.
- Explicit manual approval.
- Post-action verification plan.

This keeps cost reduction aligned with production safety, DR readiness, QR signing integrity, object storage safety, DNS correctness, release rollback, and MSCQR customer trust.
