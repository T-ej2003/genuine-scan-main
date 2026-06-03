# AWS old NAT EIP release

## Released EIP allocation

`eipalloc-0d5bae537b16aece4`

## Public IP

`35.179.203.86`

## Former NAT Gateway

`nat-0a51226e1f9190b2e`

## Survivor NAT Gateway

`nat-0be609dfc6ce97dc3`

## Safety checks before release

- Former NAT Gateway was deleted.
- EIP had no AssociationId.
- EIP had no NetworkInterfaceId.
- Retired NAT had zero route-table references.
- Application external HTTPS check remained healthy.

## Expected post-release lookup

A lookup by the released allocation ID may fail because the allocation no longer exists.
