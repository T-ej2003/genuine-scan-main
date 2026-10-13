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
The reviewed executable/build-input SHA-256 is
`79709c4112f877c58640f9de5bc6b140162e2b1082dd00630db4b4ac21946f17`.
Runtime packaging checks passed. No application source, dependency lockfile,
frontend content glob, Dockerfile or runtime packaging rule changed. The
existing frontend-build-only acceptance retains its owner, scope and
2026-11-02 expiry. CI must independently repeat the scan and reachability
check on the final head.
