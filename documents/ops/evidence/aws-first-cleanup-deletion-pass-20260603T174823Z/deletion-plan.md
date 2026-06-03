# MSCQR AWS First Cleanup Deletion Pass

## Scope

Goal: start deleting only low-blast-radius legacy/unwanted AWS resources after visual console confirmation.

## Approved first-pass deletion candidates

1. Lightsail unused static IPs
2. Lightsail obsolete snapshots after confirming they are not required restore points
3. Orphan ELB target groups after confirming no load balancer/listener/ASG dependency

## Explicitly not approved in this pass

- NAT gateways
- Route tables
- RDS databases
- RDS snapshots
- ElastiCache clusters
- Production ALBs
- Route 53 production records
- S3 production buckets
- IAM deploy roles
- EC2 production instances
- ASGs

## NAT decision

NAT deletion is blocked because current console evidence shows private route tables still route 0.0.0.0/0 to NAT gateways. Deleting NAT before route redesign can blackhole private subnet outbound traffic.

## Required deletion evidence per resource

For every deletion:
- Screenshot before deletion
- Resource ID / ARN
- Region
- Console page showing detached/unused/orphan status
- Deletion confirmation screenshot
- Post-delete list screenshot
- Notes on rollback/recreate path
