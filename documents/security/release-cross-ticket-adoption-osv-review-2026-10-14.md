# Cross-ticket registration adoption: OSV reachability review

The correction changes only the checksum-bound release evidence transport, hosted
predecessor receipt selection, its regression tests, CI registration and operations
documentation. It does not change frontend source, Tailwind content globs,
dependency locks or runtime image packaging.

OSV Scanner 2.6.0 ran recursively without filtering against this exact worktree.
Its sole finding is the existing development dependency `braces@3.0.3`
(`GHSA-vfj7-8cjw-p6xm`, `CVE-2026-93687`). The canonical production browser
closure compiled 3,993 modules and contains 204 packages; `braces` is absent.
The canonical runtime packaging check passed. The existing acceptance still has
owner `@T-ej2003`, frontend-build-only scope and exclusive 2026-11-02 expiry.
Only its reviewed executable-input SHA-256 changed to
`0d6f5b6d1ede0af64bcbff294b97ef9d172cc23e159c568de06670e4c0cec654`.
The unfiltered report and browser closure evidence are retained privately in
`/private/tmp/mscqr-v15-state-review/osv-cross-ticket*.json` and must be
revalidated independently by required CI on the final PR head.
