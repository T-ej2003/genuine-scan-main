# Completed inventory adoption reachability review

The changed executable inputs are the local production cutover bootstrap,
operator, inventory adapter, and adoption proof reader/producer, plus their
regression tests and required CI registration. No application source,
dependency lockfile, Tailwind content pattern, Dockerfile, or production
runtime package path changed. The retained unfiltered OSV Scanner 2.6.0 report
still identifies only `braces@3.0.3` (`GHSA-vfj7-8cjw-p6xm`) in the root
development dependency. It is used for trusted frontend compilation, while
the application build globs exclude the changed `scripts` files. Production
users cannot supply those globs. The backend lockfile contains no affected
package and the frontend runtime image copies only compiled assets.

The existing time-bounded acceptance retains its exact package, advisory,
owner, scope, execution decisions, and 2026-11-02 expiry. The reviewed
executable-input fingerprint is recorded in
`documents/security/osv-non-runtime-acceptance.json`. Exact-head CI must run
a fresh unfiltered OSV scan and canonical browser closure before merge. Local
canonical closure could not complete in the isolated worktree because its
low-disk dependency symlink resolves outside the worktree and fails the
lockfile-relative-path check; no browser-runtime result is claimed locally.
