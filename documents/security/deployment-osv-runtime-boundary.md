# Deployment Audit OSV runtime boundary

Deployment Audit previously ran `./osv-scanner --recursive --no-resolve .`.
That is a source/lockfile scan, not a production-image scan. It blocked the release
on an unpatched development-only `braces` finding after the production dependency
audit already established that the dependency was outside the runtime closure.

The production source gate now runs:

```sh
./osv-scanner --recursive --no-resolve --config=.security/osv-production.toml .
```

The policy uses OSV's official npm `dev` package-group override. It contains no
package name, advisory ID, version exception, or severity threshold. Scanner
v2.6.0 is pinned so the tested grouping and exit-code behavior are reproducible.
Runtime findings retain the existing blocking behavior, including when the same
advisory occurs in both development and runtime dependency closures.

Before filtering, Deployment Audit runs the packaging contract and actual scanner
fixture tests. Current frontend runtime images contain static build output in
Nginx, not builder node_modules. Backend and worker use the backend runtime stage
with dependencies pruned using `--omit=dev`. Removing pruning or copying frontend
node_modules into runtime fails the contract. A future packaging change must
re-establish the runtime boundary; moving a dependency in the manifest alone is
not sufficient authority to filter runtime exposure.

An unfiltered JSON source report remains in the existing uploaded audit artifact.
Its findings exit code is non-blocking for reporting only; scanner errors remain
blocking. The filtered gate remains mandatory. The production npm audit and
existing container/security checks are unchanged. Build/dev vulnerabilities remain
security debt, not patched or waived vulnerabilities.

Validation: the real OSV v2.6.0 recursive command passes this repository. Focused
fixtures cover dev-only, frontend/backend/worker runtime, transitive runtime,
mixed dev/runtime, unfiltered visibility, and runtime-packaging regression. No
historical-runtime, Stage B, worker, printing, or production resources change.

Recommendation: keep the unfiltered artifact visible during routine dependency
maintenance and resolve build-tool vulnerabilities when a compatible upstream fix
exists. Do not treat development classification as a substitute for verifying
changed production packaging.
