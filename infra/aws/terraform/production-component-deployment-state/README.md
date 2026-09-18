# Component deployment-state installation

This is source-only work in progress. Do not activate infrastructure from an
unmerged checkpoint. First-bootstrap execution and isolated Terraform execution
must pass their final gates before this installation procedure is operational.
Historical development findings live in [the review log](../../../../documents/ops/COMPONENT_INSTALLATION_REVIEW.md); they are not
alternative supported commands. Recovery provenance is in [the recovery record](../../../../documents/ops/COMPONENT_INSTALLATION_RECOVERY.md).

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

## Exceptional first identity bootstrap

After merge, use clean protected main and dispatch
`authorize-component-installation-identity-bootstrap.yml` with the exact source
SHA and a new UUIDv4 transition. T-ej2003 must approve its dedicated environment.
The workflow only builds source-bound approval evidence; it has no AWS credentials.
After its first-attempt run succeeds, the separately reviewed bootstrap command is:

```sh
node scripts/aws/component-identity-bootstrap-cli.mjs execute APPROVED_RUN_ID TRANSITION_UUID
```

The command reauthenticates GitHub approval and the deterministic broker package
before loading the existing exact administrator. This is the explicitly approved
first-bootstrap exception, **not an IAM policy restriction on root**. Its adapter
performs only the fixed source transaction. Administrative credentials remain in
that process's SDK clients and are not returned, archived, forwarded to Terraform
or Lambda, or used by the normal controllers.

Fresh hidden MFA authenticates the exact bootstrap operator through the existing
release role solely as human provenance. Signed STS identity and unique CloudTrail
issuance bind its 900-second expiry to the approved bootstrap. Root
`GetSessionToken` is not used. The non-secret human proof is archived with the
fixed CAS bootstrap record. The five exact execution identities and three fixed
broker versions must pass complete readback before closure.

An existing or incomplete reservation is never stolen based on elapsed time.
Ambiguous accepted writes are read back within the owning transaction; a crashed
administrative transaction remains fail-closed and requires separately reviewed
reconciliation. Human-session expiry is not claimed to revoke root authority.
Do not delete its journal or replay initial bootstrap to update existing targets.

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
A regenerated plan cannot reuse approval. The activation entry point now invokes
only the credential-isolated container runner; the host Terraform/root-profile
adapter has been removed. After the IAM installation is verified, create a fresh
owner-only directory outside the checkout and use:

```sh
node scripts/aws/component-infrastructure-activation.mjs prepare PRIVATE_DIRECTORY TRANSITION_UUID
```

Preparation authenticates all three deployment environments, current protected
source, the closed durable IAM authorization/receipt and live IAM documents, absent remote state/history,
and absent table. Hidden MFA issues the scoped Terraform session. Terraform runs
with no network namespace access or host credential mounts; a fixed TLS relay
permits only the required AWS endpoints. The reviewed Terraform/provider downloads
are hash checked, the committed provider lock is read-only, and no host plugin
cache or CLI override is accepted.

The historical IAM approval may have expired before preparation. Its fixed AWS
archive and closure remain provenance, never mutation authority: broker version 1
discovers the exact transition, requires a fully verified closure and receipt,
then authenticates the fresh scoped Terraform session. Closure continues to reject
`INSTALL`, `INSPECT`, and installation-session proof. Terraform apply still needs
its separate fresh environment-gated saved-plan approval. Saved-plan freshness is
measured from GitHub's authenticated successful-run completion (`updated_at`), not
workflow dispatch time; the completion timestamp is re-read unchanged with the run.

Review the saved `activation.tfplan`, `preparation.json` and returned hashes.
Dispatch `authorize-component-infrastructure-activation.yml` with their exact
source, plan and preparation hashes, then explicitly approve its environment.
Only a separately authorized apply execution may run:

```sh
node scripts/aws/component-infrastructure-activation.mjs apply PRIVATE_DIRECTORY ACTIVATION_APPROVAL_RUN_ID
```

Apply obtains a fresh scoped session and reauthenticates the exact GitHub approval,
source, plan, backend and live IAM receipt at the isolated pre-apply barrier.
A conditional write reserves the fixed activation-attempt object before the
exact saved plan may execute. Ambiguous reservation or apply is not retried.
The executor verifies a no-change readback plan before reporting success. No
credentials are written to the plan directory, evidence or child environment.

After verified infrastructure installation, component-state bootstrap is a separate
explicitly approved operation. Creating a table is not bootstrapping its contents.
Normal-deployer OIDC/read-only preflight and accumulated-release classification
follow; installation never dispatches an application deployment. Security/database
changes cannot be routed through the normal application lane to bypass their gates.

CTO recommendation: preserve this small ownership split and durable evidence. Do
not add a reusable privileged installer framework. Add future identity/broker
changes only as separately reviewed transitions when actually needed.
