# Completed-inventory KMS transport reachability review

The production adoption correction changes only the Stage B inventory adoption producer, its four evidence readers, and focused tests. It selects AWS KMS SHA-256 `DIGEST` for canonical signed messages over 4,096 bytes and preserves `RAW` for smaller historical messages. It adds no dependency, browser import, build pattern, Dockerfile, container image, or application runtime path. The signed payload and approval checks are unchanged.

OSV Scanner 2.6.0 scanned the current lock graph without suppression and reported only the existing `braces@3.0.3` / `GHSA-vfj7-8cjw-p6xm` finding. The canonical production browser closure compiled 3,993 modules, 204 packages and 96 chunks; `braces` was absent. Runtime image packaging passed. The finding remains limited to the trusted frontend build toolchain; its owner, scope, expiry, and attacker-control decision are unchanged. The exact-head hosted Deployment Audit must repeat the scan and closure.

The acceptance fingerprint is regenerated with `reachabilityInputsSha256(process.cwd())` after this review. This review does not authorize any production signing, inventory adoption, or deployment.
