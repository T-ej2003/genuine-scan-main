# Stage B generated-artifact contract

Every production Stage B evidence directory is outside the checkout, owned by the
current operator, non-symlinked, and mode `0700`. Every sensitive generated file is a
regular non-symlinked file owned by the current operator and mode `0600`.

The contract inventory is generated from
`scripts/aws/stage-b-artifact-contract.mjs`:

```sh
npm run stage-b:artifact-contract:generate
npm run stage-b:artifact-contract:verify
```

The generated inventory currently covers 24 artifacts from image evidence through
post-apply observations; every entry has a producer, consumer set, path, mode,
symlink, atomic-write, overwrite, and hash-binding contract.

Terraform may create its data directory and backend metadata with permissive modes.
The release preflight normalizes only the reviewed `TF_DATA_DIR` and
`terraform.tfstate`, then re-stat checks both before reporting `backendReady=true`.
Downstream consumers only validate; they never repair permissions.

All plan, refresh, audit, permission, image, state, handoff, tfvars, and broker
artifacts are external to the repository, hash-bound, and written without implicit
overwrite. The local contract test exercises real temporary filesystem behavior and
uses injected command seams, so it performs no AWS or Terraform-state operation.
