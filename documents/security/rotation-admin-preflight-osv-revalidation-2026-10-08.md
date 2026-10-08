# Rotation administrator preflight OSV revalidation

Date: 2026-10-08 UTC. After the governed-policy preflight correction and its
review finding were resolved, the final executable/build-input fingerprint was
`1eb67d34a6ebea4af555f05d369bcc80503917c31927da290af1e827f7c2dda1`.
The changed executable inputs are the Stage-B IAM policy reader, normal
activation policy identity, and their regression tests. Dependency lockfiles,
application/runtime code, and the reviewed Tailwind content globs did not
change.

The canonical OSV Scanner 2.6.0 binary has SHA-256
`98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4`.
Its fresh unfiltered source report has SHA-256
`aa880ef712ccf47bd71fce0cc1f9b701f8c1c188d68d0593f7ced8eebf6a17a0`
and reports one finding: HIGH `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`,
`braces@3.0.3` in the root development dependency. The report is retained at
`/private/tmp/mscqr-rotation-preflight-osv.odCQoq/osv-source.json` for this
local review; the tracked acceptance records only the reviewed input hash.

`node scripts/check-osv-runtime.mjs` rebuilt the canonical production browser
closure from those exact inputs and passed. It found 204 browser packages and
no `braces@3.0.3` in the browser closure; the backend lockfile also has no
`braces` instance. Backend/worker and Nginx runtime packaging checks passed.
The change does not create a production runtime execution path for the affected
build-only package or allow production users to control its build-time glob
patterns. The existing time-bounded non-runtime acceptance retains its owner,
advisory, scope, rationale, and exclusive 2026-11-02 expiry; only the reviewed
input fingerprint was updated. No production mutation occurred during this
revalidation.
