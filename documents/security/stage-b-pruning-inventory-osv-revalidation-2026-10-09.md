# Pruning inventory producer revalidation

The native pruning producer now uses the existing inventory normalizer before binding the saved plan. Only AWS response ordering and CreateDate metadata are removed; version IDs, default identity, policy ARN and the existing verifier remain unchanged. Focused native-producer regression coverage rejects actual inventory changes. The completed production registration is not replayed by this correction.

The executor/test change moves the broad executable-input fingerprint from `2e513d612fa13230947c52488547e871097c2f2c196c91bf278b186612a3a60a` to `fe9c7190b817ef7b9710613ab8dab787f56c3043f8ba42a86bc2d3f6f7f7cf7e`. OSV Scanner 2.6.0 scanned all five manifests without dependency filtering; report SHA-256: `d665fce06a88ea2a93637bb634c2e4677958a912243a6b24fcd43e063223ec18`. The existing HIGH unpatched GHSA-vfj7-8cjw-p6xm / CVE-2026-93687 for braces@3.0.3 remains visible.

Canonical buildBrowserClosure, assertRuntimePackaging and enforceRuntimeFindings passed before updating acceptance. The browser closure contains 204 packages and no braces. Runtime packaging, dependency locks and production-controlled build patterns are unchanged. Only the reviewed fingerprint changes; acceptance scope, rationale, owner and exclusive 2026-11-02 expiry remain unchanged. No production mutation occurred.
