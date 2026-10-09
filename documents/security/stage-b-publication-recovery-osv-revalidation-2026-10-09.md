# Publication recovery reachability revalidation — 2026-10-09

The Stage-B executable, test, and package-script changes invalidate the prior executable-input fingerprint. A fresh OSV 2.6.0 scan found only the existing frontend build dependency `braces@3.0.3` (GHSA-vfj7-8cjw-p6xm). Scanner SHA-256: `98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4`. Unfiltered report SHA-256: `2cfec8508571945ec1443f6baa31963a9210bf78e1fe7c30c27320bdc3fe26f2`.

Fresh production browser compilation and closure inspection covered 204 packages and excluded braces. Backend lockfile and existing worker/server runtime packaging checks also exclude it. The sole locked braces instance remains development-only. This correction changes no dependency lockfiles, Tailwind content patterns, application inputs, or runtime packaging; it introduces no attacker-controlled build pattern. The existing non-runtime conclusion therefore remains valid.

Canonical reviewed executable-input fingerprint: `5e4da0b61fe8035e642c7fa640f250f7f137888d43146b50a54dc1ae3b4f1311`. Only that fingerprint changes in the acceptance record; owner, advisory, rationale, and exclusive expiry remain unchanged. Validate with `node scripts/check-osv-runtime.mjs <unfiltered-osv-report.json>`.

The administrator-report recovery binding correction was re-reviewed against this final fingerprint; the freshly rebuilt browser closure still excludes braces.

Original-release approval recovery now reads authenticated historical task templates and carries their hashes through approval evidence and preparation. The public-operation regression uses different original and descendant templates and verifies that the original contracts remain bound throughout publication, cutover, closure and approval. No runtime dependencies or build patterns changed.

Recovery readiness also materializes the original committed checksum bytes, checks their digests against the authenticated broker configuration, and supplies them through the existing tfvars generator checksum-file input. The descendant checkout cannot substitute its contracts.

The complete original-renderer and two-identity rotation-bootstrap correction was independently revalidated: the fresh browser closure still contains 204 packages and excludes braces. Runtime packaging remains unchanged; acceptance expiry is not extended.

PR #648 integration revalidation: the combined executable/build inputs have fingerprint `df59e415f27cd189104e7cdcf813cf00dae16d796eb52581ab109fa40ddaa665`. A fresh unfiltered OSV scan of both lockfiles reports only GHSA-vfj7-8cjw-p6xm in `braces@3.0.3`. The canonical browser rebuild inspects 204 packages and excludes braces; independent backend/worker lockfile and Nginx/runtime packaging checks remain satisfied. No dependency versions, application build patterns, advisory ownership or acceptance expiry were changed. The supported runtime gate passed. The registry/parser changes are inherited unchanged from reviewed protected main; recovery fixture edits introduce no attacker-controlled compilation pattern.
