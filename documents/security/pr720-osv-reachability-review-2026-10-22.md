# PR #720 OSV reachability review — 22 October 2026

The previous exact-head Deployment Audit completed canonical browser compilation, then rejected the stale source-input fingerprint. The protected source and this PR change production workflow, coordinator and trusted-terminal scripts, tests, and generated RLS source seals. They do not change frontend application source, dependency locks, build content patterns, backend runtime source, or runtime container packaging.

The local canonical browser closure on the reviewed tree compiled 3,993 modules and 204 packages with no `braces` package. The frontend lock retains `braces@3.0.3` as a development-only dependency; the backend lock contains none. The existing accepted advisory, owner, non-runtime execution classification, attacker-input decision, and exclusive 2026-11-02 expiry are unchanged.

`reachabilityInputsSha256(process.cwd())` for this reviewed executable tree is `f4a983c604645862ded919f341cfeabe590c6ca15a033bb8aa671778af2fa00c`. The acceptance record is rebound only to that hash after the bridge authorization-wait correction. Exact-head hosted unfiltered scanning and browser closure must pass before merge. Any further executable edit requires a new fingerprint and review. This review authorizes no production signing or deployment.
