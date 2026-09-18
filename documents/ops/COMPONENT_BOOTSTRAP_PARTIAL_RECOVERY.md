# Component identity bootstrap partial recovery

## Purpose and incident boundary

This runbook covers only the fail-closed production bootstrap incident created
from protected main `adf2eda47b5e32dc3222adb060a9b6fd832189a1`, GitHub run
`35329458948`, and transition
`bb793961-e6bc-4618-932a-0ea2cc8b05ad`. It is not a reusable broker updater,
ordinary bootstrap replay, component IAM installation, or Terraform procedure.

The durable journal remains `BOOTSTRAP_EXECUTING`. The five source-owned IAM
identities and the broker execution role are exact. The broker function exists
with the historical deterministic package at `$LATEST`, no published versions,
no resource policy, and incomplete concurrency/runtime finalization. The
failure was caused by treating an omitted `FunctionName` in AWS's empty
`GetFunctionCodeSigningConfig` response as drift even though the exact function
was independently bound by the request and complete Lambda readback.

The recovery performs one reviewed old-package to new-package transition. Its
only code mutation is `UpdateFunctionCode` on
`mscqr-production-component-iam-installer`, with `Publish=false`, the
authenticated historical `RevisionId`, and deterministic ZIP bytes built from
the new protected source. No caller supplies a function, ZIP, hash, revision,
version, policy, role, or evidence key.

## Required GitHub environment

Create `production-component-installation-identity-bootstrap-recovery` with
exactly one required User reviewer, `T-ej2003` (`183396573`),
`prevent_self_review=false`, `can_admins_bypass=false`, and one custom branch
policy for `main`. Teams, additional reviewers, wildcards, tags, all-branch or
protected-branch-only selection are invalid.

## Governed recovery sequence

1. Wait until this recovery source is merged and the exact protected-main SHA
   is green. Do not execute from a PR branch.
2. Reauthenticate the unchanged live incident read-only. A different role,
   policy, journal ETag, package, revision, configuration, resource policy, or
   version fails closed.
3. Generate a fresh UUID and dispatch
   `.github/workflows/authorize-component-installation-identity-bootstrap-recovery.yml`
   on that exact protected-main SHA with `source_sha` and `transition_id`.
4. Explicitly approve the environment request as `T-ej2003`. The workflow has
   no AWS credentials and emits one digest-authenticated authorization artifact.
5. After the run succeeds, execute from a clean checkout of the same protected
   main:

   ```text
   node scripts/aws/component-bootstrap-partial-recovery-cli.mjs execute <run-id> <recovery-transition-id>
   ```

6. Complete the hidden MFA prompt. The CLI authenticates the GitHub run,
   environment, artifact, source, package, historical incident and approval
   before loading exceptional recovery authority.
7. The controller conditionally claims the existing journal, authenticates all
   five identities and the old broker, writes the corrected package once,
   waits for exact `$LATEST` readback, and only then finalizes concurrency,
   runtime management and versions `1`, `2`, and `3`.
8. Closure uses CAS on the existing journal and records both historical and
   recovery provenance. An ambiguous response is resolved by exact live
   readback. Never retry with ad-hoc AWS CLI commands.

If a controller is lost after reserving recovery, its approval cannot be
reused. A replacement waits until both the recorded approval and human session
have expired plus the source-owned safety margin, obtains a fresh environment
approval and MFA session for the same recovery transition, and CAS-transfers
the journal to a new owner. A live owner or losing CAS contender performs no
further Lambda write. The closure retains the complete authorization/owner
lineage.

After closure, ordinary bootstrap and the recovery authorization are
non-replayable. Component IAM installation remains a separate governed step and
must not start before exact bootstrap closure.

## Effective trust anchor after recovery

The closed journal retains the original bootstrap fields as immutable incident
lineage. A broker built from the recovery source must therefore authenticate
both lineages: the original source, authorization, transition, package and
manifest first; then the complete `RECOVERY_CLOSED` record. The recovery's
source, package and manifest become the effective *predecessor* binding only
when its state, operation list, partial-state digest, authorization lineage,
final versions and identity readback are all exact. Any present-but-invalid
recovery metadata fails closed; the broker never falls back to the historical
binding. A later broker package is not implicitly accepted by this recovery
record: it must be bound by its own governed `BROKER_CHANGE` transition.

This check is shared by every fixed broker entry point, including authorization
archive, installation, cleanup context and Terraform provenance.

## Post-merge deployment boundary

This recovery is closed and cannot update broker code again. A separately
governed `BROKER_CHANGE` controller now provides the only post-bootstrap code
path: merge the successor source, configure the exact protected environment,
obtain fresh explicit approval, then run the documented source-owned CLI. It
binds the immutable recovered predecessor and exact replacement
package/configuration/version state. Source merge alone does not alter the
deployed broker; do not rerun bootstrap or recovery to deploy a successor.

During that change, invocation routing remains exact: a caller tries the
predecessor entry only and reaches the successor entry only after AWS denies
that predecessor version. The broker then authenticates the effective closed
trust anchor. Durable installation receipts from the predecessor remain
readable only when their source, package and manifest match the authenticated
predecessor triple; they are history, never fresh IAM-mutation authority. New
authorizations must bind the successor package and manifest.

The broker resolves that authenticated predecessor consistently for an existing
installation's expired-session renewal, cleanup closure and read-only Terraform
provenance. A predecessor authorization can never call `INSTALL` after the
change: that mutation path requires a fresh successor-bound authorization and
the current protected-main fence. Terraform's saved-plan approval remains a
separate current-source authorization. Before a renewed installation proceeds,
the broker CAS-migrates its durable IAM ledger only after exact predecessor
authorization, source and document bindings and live readback all match.
Its session proof carries the verified historical installation source only to
bind the durable IAM receipt.

## Evidence and redaction

Diagnostics may retain hashes, ARNs, configuration values, version inventory,
journal state and ETag. They must drop `GetFunction.Code.Location` and any value
containing `X-Amz-Credential`, `X-Amz-Signature`, or
`X-Amz-Security-Token`. Credentials, MFA codes, session tokens and presigned
package URLs are never durable evidence.

## Safety and future changes

The recovery capability contains no IAM mutation, `iam:PassRole`,
`CreateFunction`, `DeleteFunction`, resource-policy mutation, or arbitrary
Lambda target. Normal installation, cleanup, Terraform, the broker and normal
deployment identities retain no broker-update authority. Any future broker
change requires the separately governed `BROKER_CHANGE` transition; this
incident recovery cannot become that mechanism.

CTO recommendation: after recovery closure, retain this contract as immutable
incident history and require a new source contract for any future Lambda code
change. Add operational alerting on unexpected broker versions, resource
policies and code/config hashes so drift is detected before the next production
transition.
