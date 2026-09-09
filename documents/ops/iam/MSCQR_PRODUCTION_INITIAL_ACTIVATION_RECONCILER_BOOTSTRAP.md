# Initial-activation reconciler installation bootstrap

This bounded bridge has depth one. An authorized human-approved local
`mscqr-production-root` session may create only the exact GitHub OIDC bootstrap
role and its one exact inline policy. The role then runs the already-reviewed
InitialActivation reconciler Terraform root inside the dedicated protected
`production-initial-activation-reconciler-bootstrap` environment and shared
`production-deploy` concurrency group. This dedicated environment is used only
by the bootstrap workflow, so its immutable GitHub OIDC subject cannot be
minted by unrelated production jobs.

The bootstrap role is not an administrator. Its IAM writes are limited to the
exact reconciler role, exact reconciler managed policy, their exact attachment,
and the exact target-policy `CreatePolicyVersion` required by the separately
governed reconciler upgrade. Its S3 access is limited to that root's state and
native lockfile. It cannot change itself, assume another role, modify Stage A
or Stage B, or publish images.

The root transition is convergent: `CreateRole` is followed by exact readback;
an ambiguous create never advances. The only resumable partial state is the
exact role without its inline policy. `PutRolePolicy` always writes the same
source-hashed document and is the final root mutation, so an ambiguous response
is resolved only by exact readback. Unexpected trust, tags, boundaries,
attachments, or inline policies fail closed.

MSCQR currently operates with one authorized production operator, so the
dedicated environment intentionally permits self-review
(`prevent_self_review=false`). Approval is still real GitHub environment
approval bound to the exact run, source, and operation; locally fabricated
approval is rejected.

The role remains narrowly available for authenticated recovery runs. Removing
it would require another privileged transition and provides no security gain
while production environment approval, protected source binding, the shared
workflow queue, exact Terraform state locking, and plan validation remain
mandatory.

## Prepare and authorize

Start from an exact, clean protected-main checkout. Preparation is a local,
root-authenticated read-only step; authorization is a separate GitHub
protected-environment approval step. Neither performs an IAM mutation.

```sh
git fetch origin main
test -z "$(git status --porcelain=v1 --untracked-files=all)"
source_sha="$(git rev-parse HEAD)"
test "$source_sha" = "$(git rev-parse origin/main)"
workdir="$(mktemp -d /private/tmp/mscqr-bootstrap-preparation.XXXXXX)"
chmod 700 "$workdir"

npm run production:initial-activation-reconciler:bootstrap -- --prepare \
  --source-sha "$source_sha" \
  --admin-profile mscqr-production-root \
  --output "$workdir/preparation.json"

preparation_sha256="$(node -e 'const fs=require("fs"),crypto=require("crypto"); process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"))' "$workdir/preparation.json")"
preparation_base64="$(base64 < "$workdir/preparation.json" | tr -d '\n')"

gh workflow run authorize-production-initial-activation-policy-reconciler-bootstrap.yml \
  --ref main \
  -f source_sha="$source_sha" \
  -f preparation_base64="$preparation_base64" \
  -f preparation_sha256="$preparation_sha256"
```

`preparation_sha256` is the SHA-256 digest of the exact original preparation
bytes. `preparation_base64` encodes those same bytes without changing them;
the workflow decodes, hashes, and revalidates the bound preparation before it
creates its authorization artifact. Wait for the required protected-environment
human approval and successful authorization job. Do not execute the installer
from this step.

## Execute after authorization

The independently authenticated local root executor consumes only the approved
run and attempt:

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
