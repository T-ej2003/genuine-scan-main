# PR #718 OSV reachability review

The exact source change modifies only the production-disabled Stage B conditional tooling, one protected workflow input, tests and operations documentation. It does not change dependency locks, application source, Tailwind content globs, Vite configuration, Dockerfiles or runtime packaging. No new tool imports `braces` or accepts production-user build patterns.

Hosted Deployment Audit run `39654976632` at head `f40a71b7bc30aaac2b290b439e60263625c22dd1` retained the unfiltered OSV report in artifact `12372465667`. Its only finding is the existing development-only `braces@3.0.3` advisory `GHSA-vfj7-8cjw-p6xm` / `CVE-2026-93687`. The canonical browser build completed; the audit stopped at the strict source-input fingerprint, as expected after the tooling change. This was a failed audit, not a runtime clearance.

After reviewing the exact changed files and unchanged browser/build boundary, `reachabilityInputsSha256(process.cwd())` is `17c5b29ad17bb35ac28dc10600ebc1cdddf111d503444b2b61fc46d280be14b5`. The existing acceptance is rebound to that exact input tree. Its advisory, dev-only scope, owner, expiry on 2026-11-02, four non-runtime execution decisions and attacker-input decision are unchanged. Final-head hosted unfiltered scanning and canonical browser closure must pass before merge; new findings require a separate review.

The 81 local OSV policy tests passed. A local full closure run built the browser but stopped because this sparse worktree resolves `micromark-factory-destination` through a sibling checkout's `node_modules`; that is not a clean-install result. The final-head hosted Deployment Audit remains the acceptance check.
