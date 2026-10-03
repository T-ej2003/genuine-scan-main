# Deployment Audit production runtime boundary

## Corrected authority

A package's `dev` group is classification input, not browser runtime authority.
The previous blanket OSV override was unsafe: Vite can bundle an imported
`devDependency` into JavaScript served by Nginx. Removing runtime node_modules
does not remove that JavaScript. The blanket configuration is deleted.

Deployment Audit installs locked frontend dependencies, records the unfiltered
OSV v2.6.0 recursive source report using `--config=/dev/null` to prevent
implicit directory-level exemptions, and invokes:

```sh
node scripts/check-osv-runtime.mjs audit-artifacts/osv-source.json
```

This invokes the real production Vite configuration in production build mode,
using a newly created output directory. The build census collects resolved module
identities and all output chunks through native plugin hooks, including a separate
worker-build hook. Package identities are checked against installed metadata and
the lockfile. Dynamic and lazy chunks are included. Existing worker plugins are
preserved. No source map, package-name grep, or emitted chunk name is used to infer
absence of a dependency. Missing/failed builds, external/unresolved imports,
unattributed executable public assets or inline/external HTML scripts, incomplete
finding identities, and lock/install mismatches fail closed.

A development npm finding may be non-blocking only for the two canonical root or
backend lockfiles, while server packaging still prunes dev dependencies and a
fresh browser graph proves the package absent. Positive browser evidence wins over
`dev` classification. Normal dependencies remain blocking under the existing
conservative source policy even if tree-shaken. Nested lockfiles and other
unestablished runtime closures remain blocking. No package/advisory ignore or
severity reduction exists. Unfiltered findings remain in the existing audit
artifact alongside fresh browser evidence.

Current evidence: `braces@3.0.3` is reachable through Tailwind compilation tooling,
not application imports. The production browser build census contains 204 package
identities and does not include braces. Canonical backend/worker packaging prunes
the development closure. The current finding is therefore build-only, not patched
or waived. Runtime vulnerabilities in frontend, backend, worker and transitive
closures still fail. A manifest change alone cannot authorize browser exclusion.

## Stage B failure

At `3dc00f24`, Stage B image-impact validation failed on the newly added unknown
`.security/osv-production.toml`. This was introduced by the OSV patch, not the
historical-runtime implementation. Deleting that unsafe configuration removes the
new unknown path from the net protected-main diff. Manifest and lockfile changes
remain frontend image-affecting; the regression requires new images/publication.
No image-impact or release-authority assertion is weakened.

## Pre-push hostile review

All cases below must pass before pushing. Behavioral fixtures build actual browser
output, using a generic vulnerable fixture package and generic advisory metadata.

| Attack | Expected | Observed | Result |
|---|---|---|---|
| Dev package imported in application | Block | Fresh graph includes package; gate rejects | PASS |
| Transitive browser dependency | Block | Parent fixture resolves vulnerable child | PASS |
| Manifest disagrees with bundle | Bundle wins | Dev classification cannot override graph | PASS |
| Dynamic import | Block | Dynamic fixture captured | PASS |
| Lazy chunk | Block | Lazy fixture captured | PASS |
| Browser worker | Block | Worker-specific hook captures package | PASS |
| PostCSS execution | Distinguish build from browser | Real build-only plugin executes; graph excludes it | PASS |
| Backend transitive runtime | Block | Runtime finding rejected | PASS |
| Worker runtime | Block | Shared pruned runtime closure enforced | PASS |
| Move dependency to dev alone | Require runtime proof | Imported dev fixture rejected | PASS |
| Missing browser evidence | Block | Missing/empty evidence rejected | PASS |
| Build failure | Block | Unresolved build cannot return evidence | PASS |
| Stale dist | Ignore stale output | Fresh isolated build fails despite stale dist fixture | PASS |
| Source maps/chunk names | No authority | Renamed/no-map chunk fixture still rejected | PASS |
| OSV group overrides runtime | Forbidden | Positive runtime wins | PASS |
| Advisory in dev and runtime | Block | Mixed-closure report rejected | PASS |
| Nested lockfile | Fail closed | Unestablished closure rejected | PASS |
| Medium/runtime findings | Preserve policy | Existing blocking behavior retained | PASS |
| CI differs from local | Same gate | Workflow invokes tested script and locked build | PASS |
| Config missing for nested lock | No filtering config | Unfiltered report consumed | PASS |
| OSV directory config scoping | No trust exemption | No dev override remains | PASS |
| Image-impact drift | Require publication | Manifest/lock regression requires fresh images | PASS |
| Incorrect frontend payload | Block packaging drift | Canonical static-output packaging contract checked | PASS |
| Text-only tests | Insufficient | Actual Vite builds and gate decisions exercised | PASS |
| Additional reasonable P1 routes | Fail unknowns | External, variable import, raw asset, lock mismatch rejected | PASS |

Recommendation: continue tracking the unfiltered development findings and use
compatible upstream fixes when available. A future packaging or bundler change must
re-establish runtime attribution; it must not restore manifest-only exemptions.
