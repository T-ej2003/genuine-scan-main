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

The post-publication Terraform-state authentication correction updates the
fingerprint to
`02f90c67d940c2e0c5c09142aaadca356f8e15adc22425b3d500015f3d4747e8`.
It preserves the exact state captured by the durable adoption receipt while
accepting only a strictly newer serial on the same lineage after the governed
publication apply. No dependency, advisory, acceptance scope, or expiry
changed.

The historical policy tooling-tree recomputation updates the fingerprint to
`c570635d7a4de415ccfcb86af96c0343e01129e31c2277de3a993175ef2deb63`.
It adds only source-to-tree authentication at receipt-bound handoff creation
and consumption. The accepted finding and expiry remain unchanged.

The earlier PR #640 WorkspaceState policy-capacity review was historically
bound to `8d18bc437e1b2af948109498dc1196003ba18d3de0d2fe443e075a8b324873e1`.
That digest is superseded and is not the final executable/build-input review.

## Historical PR #640 input revalidation (superseded)

Date: 2026-10-08 UTC. After hostile review and final relevant tests, the
implementation was frozen. The canonical `reachabilityInputsSha256(process.cwd())`
result was `56358825a3f222b8161f16aa87a72d59a651797881ef183574e7fb229d9826af`.
An unfiltered OSV Scanner 2.6.0 source scan produced the same finding set as the
previous report: one HIGH dev-only `braces@3.0.3` finding,
`GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`. The fresh canonical browser-closure
build transformed 3,993 modules into 96 chunks and resolved 204 packages;
`braces@3.0.3` was absent. The exact hosted OSV/runtime gate passed against
that fresh report and fingerprint.

Only `reachability.inputsSha256` changed in the acceptance. Advisory identity,
package/version, scope, rationale, owner, creation date, execution claims, and
exclusive expiry `2026-11-02` are unchanged. The current acceptance and this
final revalidation record both bind the digest above.

## Historical PR #640 continuation recovery revalidation (superseded)

Date: 2026-10-08 UTC. After the WorkspaceState continuation and restart
recovery implementation was frozen and its required local test gates passed,
the canonical `reachabilityInputsSha256(process.cwd())` result was
`8c8980f2318590552657955caabffb50d5268ca513a673eddf1bd4d71f0fee56`. A fresh
unfiltered OSV Scanner 2.6.0 source scan found exactly one HIGH finding:
`GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`, `braces@3.0.3`, in the root
development dependency lockfile. The fresh canonical browser-closure build
transformed 3,993 modules into 96 chunks and resolved 204 packages;
`braces@3.0.3` was absent. The exact hosted OSV/runtime gate passed against
these frozen inputs. The existing acceptance remains limited to this advisory
and its existing scope, rationale, owner, and expiry `2026-11-02`; no
reachability or expiry claim was broadened.

## Historical PR #640 delete-retry recovery revalidation (superseded)

Date: 2026-10-08 UTC. After the exact-head review correction for deletion
retry recovery was implemented, the implementation was frozen and the
required local suites passed. The canonical `reachabilityInputsSha256(process.cwd())`
result was `7ea49721e3dfd4cad4bd00ce492a54de0036886e46fcf99e37b94998c443023c`.
A fresh unfiltered OSV Scanner 2.6.0 scan again found exactly the existing HIGH
`braces@3.0.3` development-only advisory `GHSA-vfj7-8cjw-p6xm` /
`CVE-2026-93687`. The fresh browser/runtime gate transformed 3,993 modules into
96 chunks and resolved 204 packages; `braces@3.0.3` was absent, and the gate
passed. The acceptance remains bound only to that existing advisory and keeps
its prior scope, rationale, owner, and expiry `2026-11-02`.

## Historical PR #640 compact-continuation revalidation (superseded)

Date: 2026-10-08 UTC. After the compact continuation transport and separately
bound base-preparation handling were frozen, all required Stage-B, IAM,
capability/dependency, security, workflow, and RLS gates passed. The canonical
`reachabilityInputsSha256(process.cwd())` result is
`03c57c88519d75bf6633928329a119cacb0824361801b4f92e4cc264a03b8645`.
Unfiltered OSV Scanner 2.6.0 report
`/private/tmp/mscqr-pr640-osv.9KXqm9/osv-source.json` contains the existing
single HIGH `braces@3.0.3` dev-only finding, `GHSA-vfj7-8cjw-p6xm` /
`CVE-2026-93687`. The canonical browser closure built 3,993 modules into 96
chunks and resolved 204 packages; `braces@3.0.3` is absent. The exact
`check-osv-runtime.mjs` gate passed on this report and the final fingerprint.
The acceptance continues to use the existing advisory, package/version,
scope, rationale, owner, creation date, execution claims, and expiry
`2026-11-02`.

## Historical PR #640 pre-delete no-write recovery revalidation (superseded)

Date: 2026-10-08 UTC. After the final pre-delete no-write journal disposition
and contradiction classification were implemented and all required
source/test gates passed, the
canonical `reachabilityInputsSha256(process.cwd())` result is
`8b300f5dd7868d2349737ef63b5b21319ea4426c4beb8fa53ab3120b59f4afa6`. A fresh
unfiltered OSV Scanner 2.6.0 scan at
`/private/tmp/mscqr-pr640-osv-final-fbf0c050/osv-source.json` found the same
single HIGH development-only `braces@3.0.3` finding,
`GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`. The fresh canonical browser closure
at `/private/tmp/mscqr-pr640-osv-final-fbf0c050/browser-runtime-closure.json`
transformed 3,993 modules into 96 chunks and resolved 204 packages;
`braces@3.0.3` is absent. The existing non-runtime acceptance remains limited
to this advisory and retains its prior scope, rationale, owner, creation date,
execution claims, and expiry `2026-11-02`.

## Current final PR #640 adopter-bound continuation revalidation

Date: 2026-10-08 UTC. After validating adopter-bound attempt, prewrite-proof,
and completion journal bindings, the frozen executable/build fingerprint is
`28fa19e652f9e9146423bc723229fe9a43ffbfdbee5857a800a91d0040d7de06`. The
fresh unfiltered OSV Scanner 2.6.0 report at
`/private/tmp/mscqr-pr640-osv-final-YxjONK/osv-source.json` contains the same
single HIGH dev-only `braces@3.0.3` finding, `GHSA-vfj7-8cjw-p6xm` /
`CVE-2026-93687`. A fresh canonical browser closure at
`/private/tmp/mscqr-pr640-osv-final-YxjONK/browser-runtime-closure.json`
transformed 3,993 modules into 96 chunks and resolved 204 packages;
`braces@3.0.3` is absent. The existing acceptance retains its advisory,
package/version, scope, rationale, owner, creation date, execution claims, and
exclusive expiry `2026-11-02`.

## Current pre-publication registration predecessor PR revalidation

Date: 2026-10-08 UTC. After the Stage-B pre-publication predecessor change was
frozen at candidate commit `cb98c7264a9950e47750e8ac383168d5fd805f1a`, the
canonical `reachabilityInputsSha256(process.cwd())` result was
`96c7d730a92855c313cd02e17cf633cde57f2c5b53bb110e3170ccc08b0ff506`. A fresh
unfiltered OSV Scanner 2.6.0 scan found the same single HIGH development-only
finding, `braces@3.0.3`, `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687` (report SHA256
`13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`). The
canonical browser closure built 3,993 modules into 96 chunks and resolved 204
packages; `braces@3.0.3` was absent. The exact OSV runtime gate passed against
the frozen inputs. The acceptance remains limited to the same advisory and
retains its scope, rationale, owner, creation date, execution claims, and
exclusive expiry `2026-11-02`.

## Historical PR #641 predecessor-authentication revalidation

Date: 2026-10-08 UTC. The frozen executable/build inputs at candidate commit
`d7d3355c2f32bab082855bd34b9b5edd1893948e` have canonical
`reachabilityInputsSha256` `2219ce92d55b2bb0537b143214639684ffc7255a94d21db67437c2b0ee1e46c3`.
A fresh unfiltered OSV Scanner 2.6.0 scan (binary SHA256
`98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4`, report
SHA256 `13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`)
found the existing HIGH development-only `braces@3.0.3` advisory
`GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`. The canonical browser closure for
the same fingerprint transformed 3,993 modules into 96 chunks and resolved
204 packages; `braces@3.0.3` is absent. The backend lockfile also remains free
of this package, and the scan identifies the finding only in the root npm
development dependency group. The accepted advisory identity, scope,
rationale, owner, creation date, execution claims, and expiry `2026-11-02`
remain unchanged.

## Historical PR #641 predecessor-recovery and policy-chain revalidation

Date: 2026-10-08 UTC. After freezing the recovery source-identity and mixed
policy-chain corrections at code commit
`3757b62cba7cb9d424fdddbcc5973241a256fa9c`, the canonical
`reachabilityInputsSha256(process.cwd())` result is
`699b53c1d0ce2f8730aff07bd0d31eb93c77bd171cd4fd24f0f9aa7f9295bfa3`. A fresh
unfiltered OSV Scanner 2.6.0 scan found the same HIGH development-only
`braces@3.0.3` finding, `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687` (report
SHA256 `13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`).
The canonical browser closure transformed 3,993 modules into 96 chunks and
resolved 204 packages; `braces@3.0.3` is absent. The backend lockfile remains
free of the package and the scan identifies it only in the root npm
development dependency group. The acceptance remains limited to the same
advisory and retains its scope, rationale, owner, creation date, execution
claims, and expiry `2026-11-02`. The canonical OSV runtime gate passed against
these frozen inputs.

## Historical PR #641 mixed-policy-disclosure revalidation

Date: 2026-10-08 UTC. After freezing the mixed schema-3 registration plus
receipt-bound policy authorization-disclosure correction at code commit
`e2969fb74d1da298d4848b3fa5109e6eb764fbd6`, the canonical
`reachabilityInputsSha256(process.cwd())` result is
`28dec8eed24fefda423b87237c83da485e0d5bf2353433ed76547df0f60dbd78`. A fresh
unfiltered OSV Scanner 2.6.0 scan found the same HIGH development-only
`braces@3.0.3` finding, `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687` (report
SHA256 `13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`).
The canonical browser closure transformed 3,993 modules into 96 chunks and
resolved 204 packages; `braces@3.0.3` is absent. The backend lockfile remains
free of this package, and the scan identifies it only in the root npm
development dependency group. The acceptance retains the same advisory,
scope, rationale, owner, creation date, execution claims, and expiry
`2026-11-02`. The canonical OSV runtime gate passed against these frozen
inputs.


## Historical PR #641 final correctness revalidation

Date: 2026-10-08 UTC. Implementation is frozen after the retained-predecessor
versus current-successor recovery correction and mandatory schema-3 policy
evidence correction. The canonical `reachabilityInputsSha256(process.cwd())`
is `1994ac89449f703a84dada3c6106fe16fd51c5bbcf5df0ab5ef78fc62ce5e5a4`.
The full Stage-B suite passed (1,584 passed, zero failed, two skipped), and
focused public-CLI omission, signing/verification, retained predecessor and
advanced-successor recovery tests passed. Capability/dependency closure,
security guardrails, RLS package verification and its 24 tests, workflow
validation and production dependency audit passed before revalidation.

A new unfiltered OSV Scanner 2.6.0 scan of these frozen inputs produced report
SHA256 `13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`.
The canonical runtime gate rebuilt the production browser closure and passed:
204 browser packages, with `braces@3.0.3` absent. The backend lockfile contains
no `braces`; the affected instance remains a root npm development dependency.
The existing HIGH `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687` acceptance remains
non-runtime under the canonical reachability checks. Its advisory identity,
scope, rationale, owner, creation date, execution claims and expiry
`2026-11-02` are unchanged. The acceptance and this current revalidation bind
the same final fingerprint. Earlier fingerprints in this document describe
historical validation inputs only. No production operation was performed.

## Current PR #641 complete policy-evidence handoff revalidation

Date: 2026-10-08 UTC. Implementation is frozen after preserving the mandatory
receipt-bound policy through registration preparation, execution, recovery and
serialized handoff, and authenticating it during subsequent policy preparation
and signing. The public-operation regression also exercises the real KMS
transport boundary for the full authorization disclosure. The canonical
`reachabilityInputsSha256(process.cwd())` is `97b5977f01b696c3b0c28f51f41f0cd99c1be2048dbf1493af72fe10a3898910`.
The focused suite passed (562 passed, zero failed, two skipped), and the full
Stage-B suite passed (1,585 passed, zero failed, two skipped). Capability and
dependency closure, security guardrails, RLS verification and its 24 tests,
workflow validation and production dependency audit passed.

A fresh unfiltered OSV Scanner 2.6.0 scan of the frozen inputs produced report
SHA256 `13c369975a7f9749fe59755af2c4e0c252d7c2d433f31fcf2ff58483aee2a24f`.
The canonical runtime gate rebuilt the production browser closure and passed:
204 browser packages, with `braces@3.0.3` absent. The backend lockfile remains
free of this package; the affected root npm instance is development-only.
The HIGH `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687` acceptance remains non-runtime
under the canonical checks. Advisory identity, scope, rationale, owner,
creation date, execution claims and expiry `2026-11-02` are unchanged.
Acceptance and this current evidence bind the same final fingerprint.
Earlier fingerprints are historical only. No production operation occurred.
