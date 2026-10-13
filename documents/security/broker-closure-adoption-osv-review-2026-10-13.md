# Broker closure adoption reachability review

The Release Train change adds a source-bound locator for an independently
completed broker closure. The hosted coordinator authenticates the existing
signed terminal receipt, live Lambda/IAM/Terraform state, historical ECS
registrations and current protected-main tooling before persisting an adoption
record. It performs no ECS registration, IAM policy write, Lambda publication,
alias update or Terraform apply. The normal coordinator path is unchanged.

On 2026-10-13, the repository's unfiltered, recursive, no-resolve OSV Scanner
2.6.0 procedure reported only dev-only `braces@3.0.3`
(`GHSA-vfj7-8cjw-p6xm`, `CVE-2026-93687`). The report SHA-256 was
`f5c5699bc6cc5bf6d99d31e3b58c011124b5498fdbe18e88bcfc24a6cb6a525a`.
The canonical browser closure contained 204 packages and excluded `braces`.
The final reviewed executable/build-input SHA-256 is
`6c3bdb57d2a1f2499c668bedbc64132308451e4b83b1c26f01548bd912976972`.
The final change imports the canonical protected-checkout and tooling-tree
verifiers into the hosted closure callback, verifies closure-tooling ancestry
when protected main advances, and regenerates the full-RLS package bound to
the Release Train workflow source. The second unfiltered OSV scan produced the
same report SHA-256 shown above; canonical browser closure was rerun.
Runtime packaging checks passed. No application source, dependency lockfile,
frontend content glob, Dockerfile or runtime packaging rule changed. The
existing frontend-build-only acceptance retains its owner, scope and
2026-11-02 expiry. CI must independently repeat the scan and reachability
check on the final head.
