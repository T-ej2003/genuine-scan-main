# Production release coordinator OSV reachability revalidation

Date: 2026-10-08 UTC. The PR A executable/build inputs were frozen after the
coordinator, hosted Release Train, Stage-B, required security guardrail, workflow, dependency,
Terraform, and RLS validation passed. The canonical
`reachabilityInputsSha256(process.cwd())` is
`46e3c5597d9b527dedd5c47b609f92e621a3629c6bfcb5b26a258def4ea249a5`.
This final fingerprint includes the native recovery-boundary correction,
authenticated journal-recovered approval timeout, and a distinct exact
authorization for state-only closure after completed alias CAS. The source
scan was rerun after executable inputs and deterministic interruption tests
were frozen.

The unfiltered OSV Scanner 2.6.0 source scan used binary SHA-256
`98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4`.
Its report SHA-256 is
`13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`.
The report contains one finding: HIGH `GHSA-vfj7-8cjw-p6xm` /
`CVE-2026-93687`, `braces@3.0.3`, in the root npm development dependency.

The canonical `scripts/check-osv-runtime.mjs` gate rebuilt the production
browser closure from these exact inputs: 3,993 modules, 96 chunks, 204 browser
packages. `braces@3.0.3` was absent. The backend lockfile contains no `braces`.
The gate passed and its browser-closure report SHA-256 is
`df8d3fa8109dfbb5d28eedf7bd4df25b9c16b9750009fed5f42469b105d9b7d1`.
The new coordinator and workflow code orchestrate production operations; they
do not add a browser or backend runtime import of the affected build package or
an attacker-controlled input to its Tailwind content-glob use.

The existing time-bounded non-runtime acceptance is bound to the fingerprint
above. Its advisory, package/version, scope, rationale, owner, creation date,
execution claims, and exclusive expiry `2026-11-02` are unchanged. Earlier
fingerprints in historical evidence describe earlier source trees only. No
production operation was performed during this revalidation.

The broader local `verify:guardrails:source` command stops at
`check:branch-secret-diff` because the earlier committed, signed registration
test evidence contains Secrets Manager ARN references. This recovery change did
not alter that evidence; `check:security-guardrails` passed.
