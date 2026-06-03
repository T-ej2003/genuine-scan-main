# AWS NAT deletion final state check

## Retired NAT

`nat-0a51226e1f9190b2e`

## Survivor NAT

`nat-0be609dfc6ce97dc3`

## Old NAT EIP allocation

`eipalloc-0d5bae537b16aece4`

## Purpose

Verify NAT Gateway deletion has fully settled before considering old EIP release.

## Rule

Do not release the old NAT EIP unless:

- retired NAT is `deleted` or no longer returned,
- old EIP has no `AssociationId`,
- old EIP has no `NetworkInterfaceId`,
- retired NAT has zero route references,
- external HTTPS still works.
