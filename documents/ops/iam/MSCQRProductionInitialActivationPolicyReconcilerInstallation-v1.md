# Initial-activation reconciler installation contract

`PRODUCTION_INITIAL_ACTIVATION_POLICY_RECONCILER_INSTALLATION` is the
purpose-bound, source-only bridge for installing the Terraform root introduced
by PR #451. It accepts only a clean protected-main checkout, the exact isolated
Terraform root/backend, an absent or exact partial predecessor, and a saved
plan containing the three reviewed role/policy/attachment addresses.

Preparation is read-only. A separate GitHub `production` environment approval
binds the source, preparation digest, state predecessor, backend, administrator
identity, exact resources, and mutation limits. The local executor resolves the
authorization artifact from the exact successful GitHub workflow run and
attempt, verifies its GitHub artifact digest and independently rechecks the
production approval evidence; a caller-supplied local authorization file is not
authorization provenance. It then applies the exact saved plan once with the
existing `mscqr-production-root` administrator profile, and then requires the
canonical read-only verifier to pass. Ambiguous apply outcomes are never
retried blindly; exact-complete replay performs zero apply.

The plan validator is regression-tested with Terraform 1.15.8 and the locked
AWS provider using local-only, refresh-disabled plans for absent, all three safe
partial, and exact-complete states. Every plan must contain the three reviewed
resources; `create` is actionable, while `no-op` is still fully authenticated
but counts as zero mutation. Role and policy paths, descriptions, tags, trust,
permissions, session duration, permissions-boundary absence, provider identity,
and the attachment's exact configuration references are source-bound.
The rendered configuration must also contain exactly the canonical AWS provider
with the production account allowlist and region, the three resources must all
use that unaliased provider, and their complete configuration must match the
reviewed root. Provisioners, alternate profiles, assumed roles, endpoints,
aliases, extra outputs, and additional configuration are rejected. Terraform
commands receive the repository's sanitized named-profile environment, so
ambient session credentials or endpoint redirects cannot override the
authenticated administrator profile.
Before planning or applying, predecessor discovery enumerates the reserved
customer-managed policy name across every IAM path and page. A role-only
partial state is accepted only when the exact role has no managed or inline
policies; a noncanonical same-named policy or any surviving role capability is
unexpected and fails closed. Terraform's complete, possibly colored
`No state file was found!` diagnostic is the sole state-pull error classified
as first-install absence; every other backend failure remains fatal.
Backend initialization uses only supported `terraform init` options; native
state locking remains enabled on the saved-plan apply with a bounded timeout.
The authorization workflow passes dispatcher and prior-step values through
step environment variables; no caller-controlled GitHub expression is
interpolated directly into its shell program.

This contract does not install the live role in source development, grant the
runtime role self-installation capability, mutate the InitialActivationLifecycle
target policy, reopen Stage A, or change PR #448.
