# Publication recovery reachability revalidation — 2026-10-09

The Stage-B executable, test, and package-script changes invalidate the prior executable-input fingerprint. A fresh OSV 2.6.0 scan found only the existing frontend build dependency `braces@3.0.3` (GHSA-vfj7-8cjw-p6xm). Scanner SHA-256: `98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4`. Unfiltered report SHA-256: `2cfec8508571945ec1443f6baa31963a9210bf78e1fe7c30c27320bdc3fe26f2`.

Fresh production browser compilation and closure inspection covered 204 packages and excluded braces. Backend lockfile and existing worker/server runtime packaging checks also exclude it. The sole locked braces instance remains development-only. This correction changes no dependency lockfiles, Tailwind content patterns, application inputs, or runtime packaging; it introduces no attacker-controlled build pattern. The existing non-runtime conclusion therefore remains valid.

Canonical reviewed executable-input fingerprint: `c392fbd9b39dc79560f658d5c8f79e4c66c8d3bb043dfff6c0869dbba7f8bab2`. Only that fingerprint changes in the acceptance record; owner, advisory, rationale, and exclusive expiry remain unchanged. Validate with `node scripts/check-osv-runtime.mjs <unfiltered-osv-report.json>`.

The administrator-report recovery binding correction was re-reviewed against this final fingerprint; the freshly rebuilt browser closure still excludes braces.
