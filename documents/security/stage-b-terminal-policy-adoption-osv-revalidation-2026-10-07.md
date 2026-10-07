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

The three exact-head review corrections update the fingerprint to
`838538ddc496668d36f116cc3bba49878df1e63a5aedfaeba3e0b38815ad05db`.
They change only Stage-B receipt verification and tests; dependency manifests,
locks, frontend sources, and build configuration remain unchanged. The prior
unfiltered scanner report still contains the same one `braces@3.0.3` advisory;
the canonical runtime check is rerun against the amended executable-input
fingerprint before push. Acceptance scope and expiry are unchanged.

The downstream publication-to-cutover lifecycle corrections update the
fingerprint to
`a29e47ed72fa56865a1cfd62520525fcbdcee5f52b72320bd43b17150d417900`.
They preserve receipt-bound checker disclosure and prerequisite authentication
through the exact publication, cutover, reconciliation, and matching recovery
phases. No dependency, frontend, build configuration, advisory, acceptance
scope, or expiry changed.
