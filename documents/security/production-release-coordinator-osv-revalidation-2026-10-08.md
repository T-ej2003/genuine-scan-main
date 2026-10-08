# Production release coordinator OSV reachability revalidation

Date: 2026-10-08 UTC. The PR A executable/build inputs were frozen after the
coordinator, hosted Release Train, Stage-B, security, workflow, dependency,
Terraform, and RLS validation passed. The canonical
`reachabilityInputsSha256(process.cwd())` is
`41a4615ff64cec08c6b92aec2c061d3e7b9fc6a06b6dbf333345443b8227175c`.
This final fingerprint includes the native recovery-boundary correction for
coordinator restart, exact pre-intent reservation readback, and deterministic
interruption tests across registration, policy, publication, alias CAS and
terminal reconciliation. The source scan was rerun after executable inputs
were frozen. The final follow-up also records timed-out protected approval
children as consumed rounds without changing the preparation or source.

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
`8b19e28ca8ec52db6b4d2b868e24170af0188126fef00e461b9cb1644a341cd4`.
The new coordinator and workflow code orchestrate production operations; they
do not add a browser or backend runtime import of the affected build package or
an attacker-controlled input to its Tailwind content-glob use.

The existing time-bounded non-runtime acceptance is bound to the fingerprint
above. Its advisory, package/version, scope, rationale, owner, creation date,
execution claims, and exclusive expiry `2026-11-02` are unchanged. Earlier
fingerprints in historical evidence describe earlier source trees only. No
production operation was performed during this revalidation.
