# Initial-activation reconciler installation bootstrap

This bounded bridge has depth one. An independently approved local
`mscqr-production-root` session may create only the exact GitHub OIDC bootstrap
role and its one exact inline policy. The role then runs the already-reviewed
InitialActivation reconciler Terraform root inside the dedicated protected
`production-initial-activation-reconciler-bootstrap` environment and shared
`production-deploy` concurrency group. This dedicated environment is used only
by the bootstrap workflow, so its immutable GitHub OIDC subject cannot be
minted by unrelated production jobs.

The bootstrap role is not an administrator. Its IAM writes are limited to the
exact reconciler role, exact reconciler managed policy, and their exact
attachment. Its S3 access is limited to that root's state and native lockfile.
It cannot change itself, assume another role, modify Stage A or Stage B, publish
images, or call `CreatePolicyVersion` on the target lifecycle policy.

The root transition is convergent: `CreateRole` is followed by exact readback;
an ambiguous create never advances. The only resumable partial state is the
exact role without its inline policy. `PutRolePolicy` always writes the same
source-hashed document and is the final root mutation, so an ambiguous response
is resolved only by exact readback. Unexpected trust, tags, boundaries,
attachments, or inline policies fail closed.

The role remains narrowly available for authenticated recovery runs. Removing
it would require another privileged transition and provides no security gain
while production environment approval, protected source binding, the shared
workflow queue, exact Terraform state locking, and plan validation remain
mandatory.

After this source is merged, dispatch
`authorize-production-initial-activation-policy-reconciler-bootstrap.yml` for
the exact protected-main SHA. The independently authenticated local root
executor then consumes only that run and attempt:

```text
npm run production:initial-activation-reconciler:bootstrap -- --execute \
  --source-sha <protected-main-sha> \
  --authorization-workflow-run-id <run-id> \
  --authorization-workflow-run-attempt <attempt> \
  --admin-profile mscqr-production-root \
  --result <new-private-result-path>
```

The command requires a clean protected-main checkout, downloads and verifies
the exact GitHub artifact and approval evidence, preflights the result path,
authenticates root, and writes the final exact-topology result. It never runs
Terraform or installs the #451 resources itself.
