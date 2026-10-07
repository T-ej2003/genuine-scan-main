# Terminal policy adoption reachability revalidation

Date: 2026-10-07 UTC. This is a fingerprint refresh for the existing
`braces@3.0.3` non-runtime review, not a new finding acceptance.

The executable/build-input fingerprint is now
`837f680d50f7a9b203cb91a7b497717ae8d7bc29d02af17a06ae1e1072a2d2ba`. Only
PR #637 follow-up changed only Stage-B AWS control-plane validation and focused tests. The changed runtime
scripts authenticate and compare release metadata, KMS signatures, S3 receipts,
DynamoDB ownership, IAM policy state and Terraform state; they do not import
frontend build tooling, evaluate content globs, or enter the browser bundle.
The frontend source, dependency manifests/locks, Tailwind/Vite configuration,
Docker packaging and runtime code are unchanged.

A fresh canonical browser-closure build transformed 3,993 modules into 96
chunks and authenticated 3,993 module identities against the lockfile. The
existing raw OSV scan still reports exactly one finding:
`GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`, HIGH, `braces@3.0.3`, dev dependency.
The finding remains confined to trusted build-time Tailwind glob expansion;
these Stage-B scripts add no runtime import or attacker-controlled pattern.

Only the existing reachability input hash changed. Advisory, package/version,
scope, rationale, owner, and exclusive expiry `2026-11-02` are unchanged.
