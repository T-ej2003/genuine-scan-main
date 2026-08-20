# MSCQR Stage-B CURRENT/DEPOSED Identity Contract

## Scope

Stage-B Terraform plan and prior-state consumers must distinguish a CURRENT
resource instance from a DEPOSED instance even when both share one Terraform
address.

## Canonical identities

- CURRENT: Terraform resource address plus the current state role; it must
  not carry a deposed identity.
- DEPOSED: Terraform resource address plus the exact lowercase eight-character
  hexadecimal deposed key (`deposed_key` on the observed prior-state resource,
  `deposed` on plan resource changes).
- Mutation authorization uses the repository mutation-instance identity,
  including address, current/deposed identity, and action sequence.

## Consumer rules

The reference-audit predecessor map is CURRENT-only. It validates and skips
prior-state DEPOSED entries before building the address map, so a deposed
revision cannot overwrite a current predecessor. DEPOSED plan entries remain
in the separately validated cleanup and mutation-instance multisets.

Address-only maps are permitted only after the input has been proven
CURRENT-only or for a canonical resource-address allowlist. Mixed CURRENT /
DEPOSED collections require mutation-instance identity.

Fresh-image partial-apply recovery has exactly two valid cleanup topologies:
`LEGACY_RESIDUE` contains all 11 reviewed DEPOSED cleanups, while
`ALREADY_RECONCILED` contains none. Both require the same 12 CURRENT
task-definition replacements and three broker updates. Plan capture and
approval use the shared numeric census only after the plan's exact
mutation-instance set has passed structural validation; partial cleanup sets
and any unrelated mutation remain fail closed.

## Evidence

The reference-audit regression covers both reviewed cleanup topologies through
classification, capture, validation, and approval, plus reversed input order,
partial cleanup counts, malformed deposed keys, and duplicate deposed
identities.
