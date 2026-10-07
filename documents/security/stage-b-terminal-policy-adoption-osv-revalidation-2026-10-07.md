# Terminal policy adoption reachability revalidation

Date: 2026-10-07 UTC. This is a fingerprint refresh for the existing
`braces@3.0.3` non-runtime review, not a new finding acceptance.

The executable/build-input fingerprint is now
`837f680d50f7a9b203cb91a7b497717ae8d7bc29d02af17a06ae1e1072a2d2ba`. PR #637
follow-up changed only Stage-B AWS control-plane validation and focused tests.
The changed runtime scripts authenticate and compare release metadata, KMS
signatures, S3 receipts, DynamoDB ownership, IAM policy state and Terraform
state; they do not import frontend build tooling, evaluate content globs, or
enter the browser bundle.
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

## Receipt-bound adoption PR input refresh

The receipt-bound Stage-B adoption source change updates the same input
fingerprint to
`ff011494708c2949ae2ebe78deb10a709d967e4fa99442afc0453e774de05bef`.
The canonical browser-closure build completed again (3,993 modules, 96 chunks,
204 runtime packages) and still excludes `braces@3.0.3`. A fresh unfiltered
OSV Scanner 2.6.0 source report again contains exactly the same single HIGH
finding: `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`, `braces@3.0.3`, dev-only,
unpatched. The existing acceptance remains unchanged apart from its input
fingerprint: scope, rationale, owner, and expiry `2026-11-02` are preserved.
