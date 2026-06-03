# MSCQR AWS NAT / Billing Review Evidence

## Current evidence

June AWS bill PDF shows:
- Billing period: Jun 1 - Jun 30, 2026
- Date printed: Jun 3, 2026
- Estimated grand total: USD 64.70
- Highest service spend: Elastic Compute Cloud, USD 19.86
- Highest AWS Region spend: EU London, USD 19.67
- London EC2 NAT Gateway charge: USD 4.70 from 94 NAT Gateway hours and 0 GB data processed

## Console NAT evidence

Observed in AWS Console, region eu-west-2:

1. NAT gateway:
   - NAT gateway ID: nat-0a51226e1f9190b2e
   - Name: mscqr-prod-euw2-nat-public2-eu-west-2b
   - State: Available
   - Connectivity: Public
   - Public IPv4: 35.179.203.86
   - Private IPv4: 10.0.29.131
   - Subnet: subnet-028957bce09fae0c0 / mscqr-prod-euw2-public-b
   - VPC: vpc-09825a6dc884b486a / mscqr-prod-euw2
   - Created: Apr 17, 2026

2. NAT gateway:
   - NAT gateway ID: nat-0be609dfc6ce97dc3
   - Name: mscqr-prod-euw2-nat-public1-eu-west-2a
   - State: Available
   - Connectivity: Public
   - Public IPv4: 3.9.15.121
   - Private IPv4: 10.0.4.219
   - Subnet: subnet-0756dbd09eb4ece7f / mscqr-prod-euw2-public-a
   - VPC: vpc-09825a6dc884b486a / mscqr-prod-euw2
   - Created: Apr 17, 2026

## Decision

Do not delete NAT gateways yet.

Next required evidence:
- Route tables in eu-west-2
- Which private subnets route 0.0.0.0/0 to each NAT gateway
- Which EC2/RDS/ElastiCache resources live in those private subnets
- Whether backend/runner/deploy path requires outbound internet from private subnets
- Rollback path and downtime impact

## Current status

NAT is a valid cost optimization candidate, but not deletion-approved.
