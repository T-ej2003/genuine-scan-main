# AWS NAT Gateway deletion

## Deleted NAT Gateway

`nat-0a51226e1f9190b2e`

## Survivor NAT Gateway

`nat-0be609dfc6ce97dc3`

## Reason

London NAT Gateway topology was collapsed from two NAT gateways to one NAT gateway after route migration and verification.

## Pre-delete safety checks

- Retiring NAT route references were empty.
- All four private route tables used survivor NAT.
- External HTTPS check returned HTTP/2 200 before deletion.
- Target group health was healthy before deletion.
- ALB 5xx metric query returned no datapoints in the verification window.

## Post-delete checks

Captured in this evidence directory.

## Important

The NAT Gateway was deleted. The EIP allocation formerly attached to it should be checked after AWS finishes deleting the NAT Gateway. Do not manually release anything until the EIP is confirmed idle/unassociated.
