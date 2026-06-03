# AWS NAT post-migration verification

## Change already completed

The eu-west-2b private route tables were moved from NAT B to NAT A.

## Survivor NAT

`nat-0be609dfc6ce97dc3`

## Retiring NAT candidate

`nat-0a51226e1f9190b2e`

## Verified

- External HTTPS returned HTTP/2 200 for https://www.mscqr.com.
- Target group `mscqr-frontend-tg-euw2` has healthy target state.
- ALB `mscqr-alb-euw2` is active.
- Retiring NAT route references must remain empty before deletion.

## Still not done

NAT B deletion is not included in this verification evidence.
