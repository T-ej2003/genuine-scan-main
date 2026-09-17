# Component deployment-state installation

This is source-only work in progress. Do not activate infrastructure from an
unmerged checkpoint. First-bootstrap execution and isolated Terraform execution
must pass their final gates before this installation procedure is operational.
Historical development findings live in [the review log](../../../../documents/ops/COMPONENT_INSTALLATION_REVIEW.md); they are not
alternative supported commands. Recovery provenance is in `RECOVERY.md`.

## Ownership

| Owner | Exact scope |
| --- | --- |
| Initial identity bootstrap | Narrow permanent session identities, fixed broker execution role/policy, exact broker package/configuration and published versions |
| Guarded broker | Two component roles and three inline policies; source-owned trust/policy documents only |
| Terraform | `aws_dynamodb_table.component_deployment_state` only |
| Normal controller | Explicit approval authentication, scoped session issuance, fixed broker invocation |
| Cleanup controller | Fresh weaker cleanup session, durable archive discovery, exact readback and closure |

The component IAM targets are `mscqr-production-normal-deployer`,
`mscqr-production-component-state-bootstrap`, and only
`MSCQRProductionComponentStateTerminalWriter` on the existing
`mscqr-production-release-deployer`. No Terraform-managed IAM resources remain.
The existing release role's other legitimate policies are not owned here.

IAM resource scoping does not constrain replacement policy/trust bytes. Therefore
the Terraform executor never receives IAM document-writing authority. The broker
derives all such bytes from its protected-source package. The normal installer
cannot replace broker code/configuration/authority or pass its execution role.
The broker cannot modify its own authority. Future `BROKER_CHANGE` and
`IDENTITY_CHANGE` transitions require separate governance; initial bootstrap is
not a generic updater.

## Authoritative remote state

`state-backend-contract.json` fixes:

- Account: `368992683803`; region: `eu-west-2`; workspace: `default`.
- Existing S3 bucket: `mscqr-production-terraform-state-368992683803-eu-west-2`.
- Unique state key: `mscqr/production/component-deployment-state/terraform.tfstate`.
- Encryption enabled; native S3 locking with `use_lockfile = true`.
- Lock: exact state key plus `.tflock`.
- Write-once apply reservation: exact state key plus `.initial-activation-attempt`.

Absence of state before the authorized first installation is expected. Terraform
creates its first remote state through that governed operation; no operator
manually creates/imports state. Subsequent ownership belongs exclusively to this
remote backend. No local production state, state-key reuse, force state push,
state deletion, arbitrary workspace, or force unlock is supported. An ambiguous
first apply must be reconciled through separately reviewed recovery, not repeated.

## Solo-operator approval

MSCQR currently has one authorized operator/reviewer: User `T-ej2003`, GitHub ID
`183396573`. Each component approval environment requires that exact identity,
`prevent_self_review=false`, `can_admins_bypass=false`, and only branch `main`.
There is no automatic self-authorization and no independent second reviewer.
This exception does not change Stage-A/Stage-B or other governance domains.

The separate installation environment is
`production-component-infrastructure-install-permission`. Initial identity
bootstrap uses `production-component-installation-identity-bootstrap`.
The normal deployment, component-state bootstrap and table-activation environments
retain their exact contracts. Never broaden an OIDC subject to bypass approval.

## Normal IAM installation after trust-anchor bootstrap

Use a clean current protected-main checkout after merge. Dispatch the exact
`authorize-component-iam-installation.yml` workflow with `source_sha` and a UUIDv4
`transition_id`. T-ej2003 explicitly approves its environment request. The fixed
reusable publisher authenticates source and approval before acquiring OIDC
credentials, then invokes only broker version 3 to archive the authorization.
Record the successful first-attempt run ID.

Future operator commands, after prerequisites are installed and verified:

```sh
node scripts/aws/component-iam-installation.mjs install APPROVED_RUN_ID TRANSITION_UUID
node scripts/aws/component-iam-installation.mjs inspect APPROVED_RUN_ID TRANSITION_UUID
node scripts/aws/component-iam-installation.mjs close TRANSITION_UUID
```

These are the only normal-controller modes. `activate`, `recover`, `renew`,
`prepare-table` and `apply-table` administrator routes have been deleted. There
is no root/default-profile or release-deployer mutation adapter in this controller.

Installation authenticates the completed publisher run, explicit reviewer,
environment, exact source and audit archive before MFA issuance. It then obtains
a 900-second human session and exact installation-role session. The broker
independently checks its durable archive, signed STS caller proof, unique
MFA-backed CloudTrail issuance and actual AWS expiration before its exact writes.
Local JSON and an assumed-role ARN alone are never sufficient.

## Interruption and closure

The fixed broker classifies exact live IAM as ABSENT/EXPECTED/DIFFERENT. It never
overwrites DIFFERENT state. Ambiguous responses resolve through readback; retries
do not blindly repeat IAM mutations. A verified installation must still match live
state on idempotent continuation.

The durable session record is coordination, not credential authority. Replacement
requires authenticated old STS expiry plus the source-defined safety margin,
fresh approval, a new session issued after fencing, live reconciliation and CAS.
No lease-age, PID, host-death or unsigned-marker takeover exists. A failed CLI
does not imply the previous session is expired. Do not immediately issue another
controller expecting it to take ownership.

Fresh approval for the same source/transition goes through the same authorization
workflow and installation command. The broker retains authenticated approval
lineage, finishes only missing exact writes, and cannot reopen a closed transition.
Source changes require new governance, hashes and approvals; they never inherit
an old transition silently.

Cleanup requires only the transition ID and a fresh exact cleanup-role session.
Broker version 2 exposes read-only `CLEANUP_CONTEXT` at its fixed evidence location
to discover the original source and authorization hash. No retained GitHub artifact
or caller-selected file/key is required. `CLOSE` still authenticates signed human
session proof and live IAM before writing durable closure. It does not delete the
permanent bootstrap identities, fixed broker, component roles or table, and cannot
reinstall or modify IAM. STS expiration removes the old controller's usable
credentials; closure fences the broker transition permanently.

## Remaining table and deployment boundaries

Table preparation/application remains separately governed by exact protected SHA,
backend/workspace identity, authenticated IAM receipt and exact saved-plan SHA256.
A regenerated plan cannot reuse approval. The replacement isolated executor is
required before production use; the recovered host-local Terraform implementation
is not an approved execution path and is being removed.

After verified infrastructure installation, component-state bootstrap is a separate
explicitly approved operation. Creating a table is not bootstrapping its contents.
Normal-deployer OIDC/read-only preflight and accumulated-release classification
follow; installation never dispatches an application deployment. Security/database
changes cannot be routed through the normal application lane to bypass their gates.

CTO recommendation: preserve this small ownership split and durable evidence. Do
not add a reusable privileged installer framework. Add future identity/broker
changes only as separately reviewed transitions when actually needed.
