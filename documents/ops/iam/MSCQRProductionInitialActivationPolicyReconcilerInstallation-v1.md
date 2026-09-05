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

This contract does not install the live role in source development, grant the
runtime role self-installation capability, mutate the InitialActivationLifecycle
target policy, reopen Stage A, or change PR #448.
