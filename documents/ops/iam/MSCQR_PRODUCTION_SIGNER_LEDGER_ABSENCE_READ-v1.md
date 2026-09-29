# Signer ledger first-read repair

The live immutable component broker versions 13/14/15 already have exact-object `s3:GetObject` and `s3:PutObject` access to `mscqr/production/component-deployment-state/signer-policy-transition.json`. The first `SIGNER_AUTHORIZE` reads that object before creating it. S3 returns AccessDenied for an absent key when the caller lacks bucket listing, so the broker cannot distinguish absence from an unauthorized read.

The broker inline policy is part of the authenticated closed 13/14/15 lineage. This repair leaves that policy, all Lambda versions, all signer authorization code, and the absent ledger untouched. It adds one resource-policy statement to the existing production state bucket: `s3:ListBucket` for `mscqr-production-component-iam-provisioner`, conditioned on `s3:prefix` equal to the single signer ledger key. Existing bucket-policy statements are retained byte-for-byte at the JSON value level. The fixed transition accepts only the authenticated policy in `MSCQRProductionStateBucketSignerLedgerPredecessor-v1.json` and its one-statement successor.

After this change is merged, use a clean isolated worktree at the exact protected-main SHA. Install root and broker-package dependencies from their lockfiles. The read-only preparation is:

```sh
node scripts/aws/production-signer-ledger-absence-reconciliation.mjs prepare
```

Require `live=EXACT_PREDECESSOR`, the exact bucket, role, key and successor digest. Dispatch `.github/workflows/authorize-production-signer-ledger-absence.yml` with only its required `source_sha` input, using that protected-main SHA. Approve the existing `production` environment. The workflow archives a fixed, source-bound authorization with the actual approval history. Once it succeeds, the interactive root-MFA executor is:

```sh
node scripts/aws/production-signer-ledger-absence-reconciliation.mjs execute RUN_ID RUN_ATTEMPT
```

The executor rechecks protected main, the workflow artifact and its digest, approval freshness, the exact live policy, root-MFA identity, and the exact successor before a single `PutBucketPolicy`. Readback must return `CONVERGED` and the successor digest. An already converged policy returns `ALREADY_CONVERGED` without a write. Unexpected policy state or readback fails closed; preserve evidence and inspect live state before any retry. Do not replay failed signer authorization run 36510174203. Obtain a fresh signer authorization only after this bucket-policy readback succeeds.

The bucket-policy grant contains no `GetObject`, `PutObject`, `DeleteObject`, wildcard key or bucket-wide listing permission. AWS does not support `lambda:SourceFunctionArn` in a resource-based policy, so the principal is the exact existing broker execution role and the permitted prefix is the exact ledger key. The existing IAM policy still limits the object read and write to the broker function.
