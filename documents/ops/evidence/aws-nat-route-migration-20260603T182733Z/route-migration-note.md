# AWS NAT route migration

## Change

Moved eu-west-2b private route tables from NAT B to NAT A.

## Survivor NAT

`nat-0be609dfc6ce97dc3`

## Retiring NAT candidate

`nat-0a51226e1f9190b2e`

## Changed route tables

- `rtb-08944319a1a049253` / `mscqr-prod-euw2-rtb-private4-eu-west-2b` / `data-b`
- `rtb-0bd0293e2aca23c60` / `mscqr-prod-euw2-rtb-private2-eu-west-2b` / `app-b`

## Not done yet

The retiring NAT Gateway was not deleted in this step.

## Required before deletion

- Verify app still serves production traffic.
- Verify outbound HTTPS from private app workload succeeds.
- Verify no increase in ALB/app 5xx.
- Verify no route-table references remain for `nat-0a51226e1f9190b2e`.
- Preserve rollback script before deleting the NAT.
