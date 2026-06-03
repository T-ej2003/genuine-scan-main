# AWS London NAT redesign plan

## Current finding

- Region: `eu-west-2`
- Current state: `2 available NAT gateways`
- Candidate action: collapse London from `2 NAT gateways` to `1 NAT gateway`
- Safety status: `PLAN ONLY / NO MUTATION IN THIS COMMIT`

## Available NAT gateways

- `nat-0a51226e1f9190b2e` `mscqr-prod-euw2-nat-public2-eu-west-2b`
  - AZ: `eu-west-2b`
  - Public subnet: `subnet-028957bce09fae0c0` `mscqr-prod-euw2-public=b`
  - Public IP: `35.179.203.86`
  - Allocation ID: `eipalloc-0d5bae537b16aece4`
- `nat-0be609dfc6ce97dc3` `mscqr-prod-euw2-nat-public1-eu-west-2a`
  - AZ: `eu-west-2a`
  - Public subnet: `subnet-0756dbd09eb4ece7f` `mscqr-prod-euw2-public=a`
  - Public IP: `3.9.15.121`
  - Allocation ID: `eipalloc-0d048b9168225c496`

## Route-table references

### `nat-0a51226e1f9190b2e` `mscqr-prod-euw2-nat-public2-eu-west-2b`

- Route table: `rtb-08944319a1a049253` `mscqr-prod-euw2-rtb-private4-eu-west-2b`
  - Associated subnet IDs: `subnet-043b12b3099be82f9`
  - Associated subnet names: `mscqr-prod-euw2-data-b`
- Route table: `rtb-0bd0293e2aca23c60` `mscqr-prod-euw2-rtb-private2-eu-west-2b`
  - Associated subnet IDs: `subnet-068d949017bd2ce45`
  - Associated subnet names: `mscqr-prod-euw2-app-b`

### `nat-0be609dfc6ce97dc3` `mscqr-prod-euw2-nat-public1-eu-west-2a`

- Route table: `rtb-0450c9c858725c61c` `mscqr-prod-euw2-rtb-private3-eu-west-2a`
  - Associated subnet IDs: `subnet-07e0a76e3a5241138`
  - Associated subnet names: `mscqr-prod-euw2-app-a`
- Route table: `rtb-068f3e23f2e21ec4f` `mscqr-prod-euw2-rtb-private1-eu-west-2a`
  - Associated subnet IDs: `subnet-0c18d5d4c2a24a41a`
  - Associated subnet names: `mscqr-prod-euw2-data-a`

## Concrete observed route dependencies

```text
nat-0a51226e1f9190b2e -> rtb-08944319a1a049253 mscqr-prod-euw2-rtb-private4-eu-west-2b -> mscqr-prod-euw2-data-b
nat-0a51226e1f9190b2e -> rtb-0bd0293e2aca23c60 mscqr-prod-euw2-rtb-private2-eu-west-2b -> mscqr-prod-euw2-app-b
nat-0be609dfc6ce97dc3 -> rtb-0450c9c858725c61c mscqr-prod-euw2-rtb-private3-eu-west-2a -> mscqr-prod-euw2-app-a
nat-0be609dfc6ce97dc3 -> rtb-068f3e23f2e21ec4f mscqr-prod-euw2-rtb-private1-eu-west-2a -> mscqr-prod-euw2-data-a
```

## Safer default recommendation

Keep `nat-0be609dfc6ce97dc3` in `eu-west-2a` and move the two `eu-west-2b` private route tables to it.

Reason:

- It is already serving `app-a` and `data-a`.
- Collapsing to one NAT is a cost optimization, not an availability optimization.
- This creates cross-AZ dependency for `app-b` and `data-b`; acceptable only if lower cost is currently more important than AZ-isolated egress.

Alternative:


Keep `nat-0a51226e1f9190b2e` in `eu-west-2b` and move the two `eu-west-2a` private route tables to it.

## Mutation phase: keep NAT A, retire NAT B

This option keeps `nat-0be609dfc6ce97dc3` and retires `nat-0a51226e1f9190b2e`.

```bash
REGION=eu-west-2
SURVIVOR_NAT_ID=nat-0be609dfc6ce97dc3
RETIRING_NAT_ID=nat-0a51226e1f9190b2e

# Move eu-west-2b app private route table to survivor NAT
aws ec2 replace-route \
  --region "$REGION" \
  --route-table-id rtb-0bd0293e2aca23c60 \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id "$SURVIVOR_NAT_ID"

# Move eu-west-2b data private route table to survivor NAT
aws ec2 replace-route \
  --region "$REGION" \
  --route-table-id rtb-08944319a1a049253 \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id "$SURVIVOR_NAT_ID"

# Verify routes
aws ec2 describe-route-tables \
  --region "$REGION" \
  --route-table-ids rtb-0bd0293e2aca23c60 rtb-08944319a1a049253 \
  --query 'RouteTables[].{RouteTableId:RouteTableId,Name:Tags[?Key==`Name`]|[0].Value,Routes:Routes[?DestinationCidrBlock==`0.0.0.0/0`]}' \
  --output table

# Only after application egress verification succeeds:
# aws ec2 delete-nat-gateway \
#   --region "$REGION" \
#   --nat-gateway-id "$RETIRING_NAT_ID"
```

## Rollback for keep NAT A option

```bash
REGION=eu-west-2
ORIGINAL_B_NAT_ID=nat-0a51226e1f9190b2e

aws ec2 replace-route \
  --region "$REGION" \
  --route-table-id rtb-0bd0293e2aca23c60 \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id "$ORIGINAL_B_NAT_ID"

aws ec2 replace-route \
  --region "$REGION" \
  --route-table-id rtb-08944319a1a049253 \
  --destination-cidr-block 0.0.0.0/0 \
  --nat-gateway-id "$ORIGINAL_B_NAT_ID"
```

## Required verification before NAT deletion

- ECS/app task/container outbound HTTPS succeeds.
- Application can reach required external APIs.
- S3 path still uses gateway endpoint route where applicable.
- No increase in 5xx from ALB/app after route migration.
- CloudWatch NAT metrics show traffic only on survivor NAT after migration.

## Explicit unsafe action

Do not run `delete-nat-gateway` before route replacement and egress verification.
