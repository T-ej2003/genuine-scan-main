# Stage-B refresh-only policy closure

Terraform may omit `resource_changes` from refresh-only plan JSON when it has
no planned resource actions. The broker closure validator now treats an absent
property as an empty action list while continuing to validate any supplied
array and the exact broker policy drift/target. The state-only refresh plan is
still validated and applied from its saved bytes; the policy API mutation is
not replayed.

The production executable-input fingerprint is
`d883d19492a18a81a5d4427a992ddcce2e75d4866bd6c5e2591c6e6af6eaea0c`. The
canonical browser build did not include `braces@3.0.3`; the existing
build-only acceptance for GHSA-vfj7-8cjw-p6xm / CVE-2026-93687 remains limited
to the dev dependency and expires 2026-11-02. Only its reachability input hash
was refreshed.

Focused validation:

- `node --test scripts/tests/stage-b-release-prerequisites.test.mjs`
- `node --test scripts/tests/stage-b-staged-broker-executor.test.mjs`
- `node scripts/check-osv-runtime.mjs <unfiltered-osv-report.json>`

The incident-shaped test omits `resource_changes`, authenticates the exact
policy drift, and proves the executor applies only the validated saved
refresh-only plan. Malformed arrays, unexpected changes, and wrong policy
state remain rejected.
