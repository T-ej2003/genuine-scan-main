# Coordinator dependency bootstrap: reachability revalidation

The existing composite installs the unchanged backend lockfile before startup,
with lifecycle scripts disabled. The new test reproduces root-only module-loading
failure and verifies real coordinator import after backend packages are available.
No application source, lockfile, runtime packaging, Terraform or RLS contract changes.

A fresh unfiltered OSV Scanner2.6.0 recursive/no-resolve scan returned report
SHA256 e7f8a33f732774b0883f0e4a381b366bb3ae1bf916f31d4064b2af83298ec476.
The sole finding remains HIGH unpatched braces3.0.3,
GHSA-vfj7-8cjw-p6xm / CVE-2026-93687, in frontend build dependencies.
Canonical runtime packaging, browser closure and finding enforcement passed:
204 browser packages, no braces; backend/worker locks and Nginx runtime exclude it.
Reviewed executable-input hash:
b4f400122ef1aea0931fcd2e352744fdbd47c10d7efcea589dbc9a81d90e3212.

Only the existing acceptance input binding advances. Owner, scope, rationale,
creation date, runtime exclusions and exclusive2026-11-02 expiry are unchanged.
No finding is hidden or policy weakened. Private evidence is retained under
/private/tmp/mscqr-current-release-e8e1047/startup-correction-osv/.
No production workflow or mutation was executed during this correction.

The current-source ticket documentation regression was included in this fresh
unfiltered scan and browser/runtime review. It changes no executable release
behavior; acceptance scope and expiry remain unchanged.
