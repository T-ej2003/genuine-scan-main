# PR #720 hostile security review — 22 October 2026

This review covers the trusted-terminal bridge at commit `52265068f574d23dae36c37be7c0bf4c840a9ff1`. It uses source inspection and non-production tests; no production cutover or KMS Sign was run. **The PR is not ready to merge or deploy.**

## Blocking findings

1. **Native Stage B completion is not independently authenticated.** `run-hosted-production-release-bridge.mjs:44` intentionally requires a verifier that its CLI does not supply. `run-production-release-terminal-bridge.mjs:208-221` persists readiness and the three earlier signature artifacts, but no separately authorized checker signature over the final verifier-owned native outcomes. `production-cutover-control-plane.mjs:416-440` records readiness stage references and returns richer in-process results; a stage reference or terminal completion flag is not an authoritative AWS result. The interactive verifier session is process scoped. The approved contract change must add a fresh, one-use post-cutover checker authorization and signed result, plus hosted KMS verification and authoritative AWS readbacks for MFA issuance, inventory, Terraform, Secrets Manager, task registration, and prepared overlap. Until then, the line 44 guard must remain.
2. **Partial Release Gate runs have no safe continuation.** `run-hosted-production-release-bridge.mjs:145-212` pins one overlap and one normal child run. It can reuse a failed normal run only when the deployment job, receipts, smoke and live state all prove completion. If that run stops after any earlier mutation, the same child is read again and fails; there is no per-transition continuation. New dispatch based on GitHub failure would risk repeating RLS, ECS, frontend or component-state writes. Each transition needs a durable claim, exact native result, readback classifier, and Gate entry point that skips authenticated completed steps.
3. **Secrets Manager writes lack a durable native version result.** `production-artifact-signing-secrets-adapter.mjs:46-54` discards the `PutSecretValue` response and returns only a secret reference. A lost response can mean that a version was committed. Recovery must bind an immutable request token or version ID and compare the exact secret/version by read-only AWS observation; an absent CLI response must remain `OUTCOME_UNKNOWN`.

## Corrected finding on this head

The previous Codex review found that polling ended after 30 minutes even when a native Sign was dispatched. The parent now observes the exact authorization round for a bounded five-hour interval and stops at request expiry when no Sign for that round exists. A Sign from a previous round cannot extend a newer request. Focused tests cover late Sign completion, expiry, and cross-round dispatch. The native signing journal still refuses to repeat a Sign whose response was lost.

## Release decision

Keep the PR draft and fail closed. A new post-cutover checker signature must have its own explicit approval binding and one-use claim; the existing pre-cutover signatures cannot prove later mutations. The release-deployer's regional `cloudtrail:LookupEvents` permission and the authoritative event shapes must be verified before hosted native verification is enabled. The external release-deployer role is not owned by the Stage A Terraform module, so a source change alone cannot establish live permission. A later approved production IAM action would be a separate Phase 3 prerequisite, not part of this PR's test run.

No root, checker, MFA, 900-second root TTL, protected environment, OIDC, or disabled conditional-lane boundary was relaxed.
